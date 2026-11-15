use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use image::AnimationDecoder;
use image::codecs::gif::GifDecoder;
use rodio::buffer::SamplesBuffer;
use rodio::{Decoder, OutputStream, OutputStreamHandle, Sink, Source};

use super::{
    AudioPlayerBackend, AudioSession, AudioStatus, DecodedImageAsset, DecodedImageFrame,
    DecodedVideoFrame, ImageDecoderBackend, VideoDecoderBackend, VideoSession, VideoStatus,
};

pub struct StandardImageBackend;

impl ImageDecoderBackend for StandardImageBackend {
    fn decode(&self, bytes: &[u8], file_name: &str) -> Result<DecodedImageAsset, String> {
        let is_gif = file_name.to_ascii_lowercase().ends_with(".gif")
            || bytes.starts_with(b"GIF87a")
            || bytes.starts_with(b"GIF89a");

        if is_gif
            && let Ok(decoder) = GifDecoder::new(Cursor::new(bytes))
            && let Ok(raw_frames) = decoder.into_frames().collect_frames()
            && !raw_frames.is_empty()
        {
            let frame_count = raw_frames.len();
            let frames = raw_frames
                .into_iter()
                .map(|f| {
                    let (numer, denom) = f.delay().numer_denom_ms();
                    let delay_ms = if denom > 0 {
                        (numer / denom).max(20)
                    } else {
                        80
                    };
                    let buf = f.into_buffer();
                    DecodedImageFrame {
                        width: buf.width(),
                        height: buf.height(),
                        rgba: buf.into_raw(),
                        delay_ms,
                    }
                })
                .collect();

            return Ok(DecodedImageAsset {
                frames,
                format_label: if frame_count > 1 {
                    format!("Animated GIF ({frame_count} frames)")
                } else {
                    "GIF".to_string()
                },
            });
        }

        let fmt_label = image::guess_format(bytes)
            .map(|f| format!("{f:?}"))
            .unwrap_or_else(|_| "Image".to_string());

        let img = image::load_from_memory(bytes)
            .map_err(|e| format!("Failed decoding image in memory: {e}"))?;
        let rgba = img.to_rgba8();

        Ok(DecodedImageAsset {
            frames: vec![DecodedImageFrame {
                width: rgba.width(),
                height: rgba.height(),
                rgba: rgba.into_raw(),
                delay_ms: 0,
            }],
            format_label: fmt_label,
        })
    }
}

pub struct RodioAudioBackend;

struct DecodedPcmTrack {
    channels: u16,
    sample_rate: u32,
    samples: Arc<Vec<i16>>,
    duration_ms: u64,
    waveform_bars: [f32; 32],
    backend_name: String,
}

fn decode_audio_track_in_memory(
    bytes: Arc<[u8]>,
    file_name: &str,
) -> Result<DecodedPcmTrack, String> {
    // 1. On Windows, prefer Windows Media Foundation PCM decoding on an isolated MTA worker thread.
    //    This natively supports MP3, M4A/AAC, WAV, FLAC, WMA, and MP4/MOV/MKV audio tracks without
    //    hitting rodio 0.19's Symphonia ReadSeekSource `byte_len() -> None` SeekError panic.
    #[cfg(target_os = "windows")]
    {
        if let Ok((channels, sample_rate, pcm, reported_dur_ms)) =
            win_mf::decode_audio_pcm_in_memory(bytes.clone(), file_name)
        {
            let ch = channels.max(1);
            let sr = sample_rate.max(1);
            let computed_ms =
                ((pcm.len() as u128 * 1000) / (sr as u128 * ch as u128)) as u64;
            let duration_ms = reported_dur_ms.unwrap_or(computed_ms).max(computed_ms);
            let waveform_bars = compute_waveform_from_i16(&pcm);
            return Ok(DecodedPcmTrack {
                channels: ch,
                sample_rate: sr,
                samples: Arc::new(pcm),
                duration_ms,
                waveform_bars,
                backend_name: "Windows Media Foundation + Rodio (In-Memory PCM)".to_string(),
            });
        }
    }

    // 2. Fallback to Rodio / Symphonia wrapped in `catch_unwind` so internal symphonia decoder
    //    panics (such as `symphonia.rs:44` unreachable SeekError) never crash the application.
    let bytes_for_fallback = bytes.clone();
    let fallback_res = catch_unwind(AssertUnwindSafe(move || -> Result<DecodedPcmTrack, String> {
        let decoder = Decoder::new(Cursor::new(bytes_for_fallback))
            .map_err(|e| format!("Failed decoding audio stream in memory: {e}"))?;
        let ch = decoder.channels().max(1);
        let sr = decoder.sample_rate().max(1);
        let samples: Vec<i16> = decoder.collect();
        if samples.is_empty() {
            return Err("Audio stream decoded 0 PCM samples".to_string());
        }
        let duration_ms = ((samples.len() as u128 * 1000) / (sr as u128 * ch as u128)) as u64;
        let waveform_bars = compute_waveform_from_i16(&samples);
        Ok(DecodedPcmTrack {
            channels: ch,
            sample_rate: sr,
            samples: Arc::new(samples),
            duration_ms,
            waveform_bars,
            backend_name: "Rodio / Symphonia (In-Memory PCM)".to_string(),
        })
    }));

    match fallback_res {
        Ok(res) => res,
        Err(_) => Err(format!(
            "Unsupported or non-seekable audio container in '{file_name}'"
        )),
    }
}

struct ActiveRodioSession {
    _stream: OutputStream,
    stream_handle: OutputStreamHandle,
    sink: Sink,
    track: DecodedPcmTrack,
    volume: f32,
    muted: bool,
    accumulated_ms: u64,
    last_resume: Option<Instant>,
}

impl ActiveRodioSession {
    fn append_from_ms(&mut self, start_ms: u64) {
        let ch = self.track.channels.max(1) as usize;
        let sr = self.track.sample_rate.max(1) as u128;
        let frame_offset = ((start_ms as u128 * sr) / 1000) as usize;
        let raw_sample_offset = frame_offset.saturating_mul(ch).min(self.track.samples.len());
        let aligned_offset = raw_sample_offset - (raw_sample_offset % ch);

        let slice = if aligned_offset < self.track.samples.len() {
            self.track.samples[aligned_offset..].to_vec()
        } else {
            Vec::new()
        };

        if !slice.is_empty() {
            let source = SamplesBuffer::new(
                self.track.channels.max(1),
                self.track.sample_rate.max(1),
                slice,
            );
            self.sink.append(source);
        }
    }

    fn rebuild_sink_at(&mut self, start_ms: u64, play_immediately: bool) {
        self.sink.stop();
        if let Ok(new_sink) = Sink::try_new(&self.stream_handle) {
            self.sink = new_sink;
            let eff_vol = if self.muted { 0.0 } else { self.volume };
            self.sink.set_volume(eff_vol);
            self.append_from_ms(start_ms);
            if play_immediately {
                self.sink.play();
                self.last_resume = Some(Instant::now());
            } else {
                self.sink.pause();
                self.last_resume = None;
            }
        }
        self.accumulated_ms = start_ms.min(self.track.duration_ms);
    }

    fn current_elapsed_ms(&self) -> u64 {
        let live = self
            .last_resume
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);
        self.accumulated_ms
            .saturating_add(live)
            .min(self.track.duration_ms)
    }
}

impl AudioSession for ActiveRodioSession {
    fn play(&mut self) {
        if self.sink.empty() {
            self.rebuild_sink_at(0, true);
            return;
        }
        self.sink.play();
        if self.last_resume.is_none() {
            self.last_resume = Some(Instant::now());
        }
    }

    fn pause(&mut self) {
        self.sink.pause();
        if let Some(t) = self.last_resume.take() {
            self.accumulated_ms = self
                .accumulated_ms
                .saturating_add(t.elapsed().as_millis() as u64)
                .min(self.track.duration_ms);
        }
    }

    fn stop(&mut self) {
        self.rebuild_sink_at(0, false);
    }

    fn seek_ms(&mut self, pos_ms: u64) {
        let was_playing = !self.sink.is_paused() && !self.sink.empty();
        let clamped = pos_ms.min(self.track.duration_ms);
        self.rebuild_sink_at(clamped, was_playing);
    }

    fn set_volume(&mut self, volume: f32) {
        self.volume = volume.clamp(0.0, 1.5);
        if !self.muted {
            self.sink.set_volume(self.volume);
        }
    }

    fn set_muted(&mut self, muted: bool) {
        self.muted = muted;
        self.sink.set_volume(if muted { 0.0 } else { self.volume });
    }

    fn status(&mut self) -> AudioStatus {
        if self.sink.empty() && self.last_resume.is_some() {
            if let Some(t) = self.last_resume.take() {
                self.accumulated_ms = self
                    .accumulated_ms
                    .saturating_add(t.elapsed().as_millis() as u64)
                    .min(self.track.duration_ms);
            }
        }
        let is_playing = !self.sink.is_paused() && !self.sink.empty();
        AudioStatus {
            is_playing,
            elapsed_ms: self.current_elapsed_ms(),
            duration_ms: Some(self.track.duration_ms),
            volume: self.volume,
            muted: self.muted,
            waveform_bars: self.track.waveform_bars,
            backend_name: self.track.backend_name.clone(),
        }
    }
}

fn compute_waveform_from_i16(samples: &[i16]) -> [f32; 32] {
    let mut bars = [0.08f32; 32];
    if samples.is_empty() {
        return bars;
    }
    let chunk_len = (samples.len() / 32).max(1);
    for (i, bar) in bars.iter_mut().enumerate() {
        let start = i * chunk_len;
        if start >= samples.len() {
            break;
        }
        let end = (start + chunk_len).min(samples.len());
        let slice = &samples[start..end];
        let step = (slice.len() / 256).max(1);
        let mut sum_sq = 0.0f64;
        let mut count = 0usize;
        for s in slice.iter().step_by(step) {
            let norm = (*s as f64) / 32768.0;
            sum_sq += norm * norm;
            count += 1;
        }
        if count > 0 {
            let rms = (sum_sq / count as f64).sqrt() as f32;
            *bar = (rms * 2.2).clamp(0.08, 1.0);
        }
    }
    bars
}

impl AudioPlayerBackend for RodioAudioBackend {
    fn open_memory(&self, bytes: Arc<[u8]>, file_name: &str) -> Result<Box<dyn AudioSession>, String> {
        let track = decode_audio_track_in_memory(bytes, file_name)?;

        let (stream, stream_handle) = catch_unwind(|| OutputStream::try_default())
            .map_err(|_| "Audio output stream initialization panicked".to_string())?
            .map_err(|e| format!("Failed opening system audio output device: {e}"))?;
        let sink = Sink::try_new(&stream_handle)
            .map_err(|e| format!("Failed creating audio sink: {e}"))?;

        let mut session = ActiveRodioSession {
            _stream: stream,
            stream_handle,
            sink,
            track,
            volume: 0.85,
            muted: false,
            accumulated_ms: 0,
            last_resume: Some(Instant::now()),
        };

        session.sink.set_volume(session.volume);
        session.append_from_ms(0);
        session.sink.play();

        Ok(Box::new(session))
    }
}

pub struct PlatformVideoBackend;

impl VideoDecoderBackend for PlatformVideoBackend {
    fn open_memory(&self, bytes: Arc<[u8]>, file_name: &str) -> Result<Box<dyn VideoSession>, String> {
        #[cfg(target_os = "windows")]
        {
            win_mf::WindowsMfVideoSession::open(bytes, file_name)
                .map(|s| Box::new(s) as Box<dyn VideoSession>)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (bytes, file_name);
            Err("No native video decoder backend registered for this OS yet (implement VideoDecoderBackend).".to_string())
        }
    }
}

#[cfg(target_os = "windows")]
mod win_mf {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::ptr::null_mut;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::thread;
    use std::time::{Duration, Instant};

    use windows::Win32::Media::MediaFoundation::{
        IMFAttributes, IMFByteStream, IMFMediaBuffer, IMFMediaType, IMFSample, IMFSourceReader,
        MF_API_VERSION, MF_BYTESTREAM_CONTENT_TYPE, MF_BYTESTREAM_ORIGIN_NAME,
        MF_MT_AUDIO_BITS_PER_SAMPLE, MF_MT_AUDIO_NUM_CHANNELS, MF_MT_AUDIO_SAMPLES_PER_SECOND,
        MF_MT_DEFAULT_STRIDE, MF_MT_FRAME_SIZE, MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE, MF_PD_DURATION,
        MF_SDK_VERSION, MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING,
        MF_SOURCE_READER_FIRST_AUDIO_STREAM, MF_SOURCE_READER_FIRST_VIDEO_STREAM,
        MF_SOURCE_READER_MEDIASOURCE, MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED,
        MF_SOURCE_READERF_ENDOFSTREAM, MF_SOURCE_READERF_ERROR, MFAudioFormat_PCM,
        MFCreateAttributes, MFCreateMFByteStreamOnStream, MFCreateMediaType,
        MFCreateSourceReaderFromByteStream, MFMediaType_Audio, MFMediaType_Video, MFSTARTUP_FULL,
        MFStartup, MFVideoFormat_RGB32,
    };
    use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};
    use windows::Win32::UI::Shell::SHCreateMemStream;
    use windows::core::{GUID, HSTRING, Interface};

    use super::{
        AudioPlayerBackend, AudioSession, DecodedVideoFrame, RodioAudioBackend, VideoSession,
        VideoStatus,
    };

    pub const MF_VERSION_COMBINED: u32 = (MF_SDK_VERSION << 16) | MF_API_VERSION;

    fn guess_mime_type(file_name: &str, bytes: &[u8]) -> Option<&'static str> {
        let lower = file_name.to_ascii_lowercase();
        let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or_default();
        match ext {
            "mp4" | "m4v" => return Some("video/mp4"),
            "mov" => return Some("video/quicktime"),
            "mkv" => return Some("video/x-matroska"),
            "webm" => return Some("video/webm"),
            "avi" => return Some("video/x-msvideo"),
            "wmv" => return Some("video/x-ms-wmv"),
            "mp3" => return Some("audio/mpeg"),
            "m4a" | "aac" => return Some("audio/mp4"),
            "wav" => return Some("audio/wav"),
            "flac" => return Some("audio/flac"),
            "wma" => return Some("audio/x-ms-wma"),
            "ogg" | "oga" | "opus" => return Some("audio/ogg"),
            _ => {}
        }
        if bytes.len() > 12 && &bytes[4..8] == b"ftyp" {
            return Some("video/mp4");
        }
        if bytes.starts_with(b"ID3") {
            return Some("audio/mpeg");
        }
        if bytes.starts_with(b"fLaC") {
            return Some("audio/flac");
        }
        if bytes.len() > 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE" {
            return Some("audio/wav");
        }
        None
    }

    /// Creates an in-memory `IMFSourceReader`.
    /// Must always be called on an MTA worker thread so `SHCreateMemStream` lives in the same
    /// Multi-Threaded Apartment as Media Foundation's workqueue threads.
    fn create_in_memory_source_reader(
        bytes: &[u8],
        file_name: &str,
    ) -> Result<IMFSourceReader, String> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            MFStartup(MF_VERSION_COMBINED, MFSTARTUP_FULL)
                .map_err(|e| format!("MFStartup failed: {e}"))?;

            let mem_stream = SHCreateMemStream(Some(bytes)).ok_or_else(|| {
                "SHCreateMemStream failed to allocate in-memory IStream".to_string()
            })?;

            let byte_stream: IMFByteStream = MFCreateMFByteStreamOnStream(&mem_stream)
                .map_err(|e| format!("MFCreateMFByteStreamOnStream failed: {e}"))?;

            if let Ok(bs_attrs) = byte_stream.cast::<IMFAttributes>() {
                let clean_name = file_name
                    .rsplit_once(['/', '\\'])
                    .map(|(_, n)| n)
                    .unwrap_or(file_name);
                let _ = bs_attrs.SetString(&MF_BYTESTREAM_ORIGIN_NAME, &HSTRING::from(clean_name));
                if let Some(mime) = guess_mime_type(clean_name, bytes) {
                    let _ = bs_attrs.SetString(&MF_BYTESTREAM_CONTENT_TYPE, &HSTRING::from(mime));
                }
            }

            let mut reader_attrs: Option<IMFAttributes> = None;
            MFCreateAttributes(&mut reader_attrs, 2)
                .map_err(|e| format!("MFCreateAttributes failed: {e}"))?;
            if let Some(ref attrs) = reader_attrs {
                let _ = attrs.SetUINT32(&MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, 1);
            }

            MFCreateSourceReaderFromByteStream(&byte_stream, reader_attrs.as_ref()).map_err(|e| {
                format!("MFCreateSourceReaderFromByteStream failed for '{file_name}': {e}")
            })
        }
    }

    fn query_duration_ms(reader: &IMFSourceReader) -> Option<u64> {
        unsafe {
            let prop = reader
                .GetPresentationAttribute(MF_SOURCE_READER_MEDIASOURCE.0 as u32, &MF_PD_DURATION)
                .ok()?;
            let raw_bytes: &[u8] = std::slice::from_raw_parts(
                (&prop as *const _) as *const u8,
                std::mem::size_of_val(&prop),
            );
            let vt = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
            if vt == 21 || vt == 20 {
                let hns = u64::from_le_bytes(raw_bytes[8..16].try_into().ok()?);
                return Some(hns / 10_000);
            }
            None
        }
    }

    /// Decodes an audio stream in memory on a dedicated MTA worker thread so it never deadlocks
    /// with `winit`'s STA GUI thread.
    pub fn decode_audio_pcm_in_memory(
        bytes: Arc<[u8]>,
        file_name: &str,
    ) -> Result<(u16, u32, Vec<i16>, Option<u64>), String> {
        let fname = file_name.to_string();
        let handle = thread::spawn(move || {
            let res = catch_unwind(AssertUnwindSafe(|| {
                decode_audio_pcm_on_mta(&bytes, &fname)
            }));
            match res {
                Ok(inner) => inner,
                Err(_) => Err("Media Foundation audio decoder panicked".to_string()),
            }
        });

        handle
            .join()
            .map_err(|_| "Media Foundation audio worker thread failed".to_string())?
    }

    fn decode_audio_pcm_on_mta(
        bytes: &[u8],
        file_name: &str,
    ) -> Result<(u16, u32, Vec<i16>, Option<u64>), String> {
        unsafe {
            let reader = create_in_memory_source_reader(bytes, file_name)?;
            let stream_idx = MF_SOURCE_READER_FIRST_AUDIO_STREAM.0 as u32;

            let pcm_type: IMFMediaType =
                MFCreateMediaType().map_err(|e| format!("MFCreateMediaType failed: {e}"))?;
            pcm_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio)
                .map_err(|e| format!("SetGUID MajorType failed: {e}"))?;
            pcm_type
                .SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_PCM)
                .map_err(|e| format!("SetGUID Subtype PCM failed: {e}"))?;
            let _ = pcm_type.SetUINT32(&MF_MT_AUDIO_BITS_PER_SAMPLE, 16);

            reader
                .SetCurrentMediaType(stream_idx, None, &pcm_type)
                .map_err(|e| format!("SetCurrentMediaType(Audio PCM) failed: {e}"))?;

            let actual_type = reader
                .GetCurrentMediaType(stream_idx)
                .map_err(|e| format!("GetCurrentMediaType(Audio) failed: {e}"))?;
            let channels = actual_type
                .GetUINT32(&MF_MT_AUDIO_NUM_CHANNELS)
                .unwrap_or(2)
                .max(1) as u16;
            let sample_rate = actual_type
                .GetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND)
                .unwrap_or(44100)
                .max(1);
            let duration_ms = query_duration_ms(&reader);

            let mut pcm_samples = Vec::new();
            let eos_or_err =
                (MF_SOURCE_READERF_ENDOFSTREAM.0 | MF_SOURCE_READERF_ERROR.0) as u32;

            loop {
                let mut flags: u32 = 0;
                let mut sample: Option<IMFSample> = None;
                reader
                    .ReadSample(
                        stream_idx,
                        0,
                        None,
                        Some(&mut flags),
                        None,
                        Some(&mut sample),
                    )
                    .map_err(|e| format!("ReadSample(Audio) failed: {e}"))?;

                if (flags & eos_or_err) != 0 {
                    break;
                }
                let Some(sample) = sample else {
                    if flags != 0 {
                        continue;
                    }
                    break;
                };
                let Ok(buffer): Result<IMFMediaBuffer, _> = sample.ConvertToContiguousBuffer()
                else {
                    continue;
                };
                let mut ptr: *mut u8 = null_mut();
                let mut cur_len: u32 = 0;
                if buffer.Lock(&mut ptr, None, Some(&mut cur_len)).is_ok() {
                    if !ptr.is_null() && cur_len >= 2 {
                        let byte_slice = std::slice::from_raw_parts(ptr, cur_len as usize);
                        for chunk in byte_slice.chunks_exact(2) {
                            pcm_samples.push(i16::from_le_bytes([chunk[0], chunk[1]]));
                        }
                    }
                    let _ = buffer.Unlock();
                }
            }

            if pcm_samples.is_empty() {
                return Err("No PCM audio samples decoded from media stream".to_string());
            }

            Ok((channels, sample_rate, pcm_samples, duration_ms))
        }
    }

    pub struct WindowsMfVideoSession {
        frame_rx: Receiver<DecodedVideoFrame>,
        latest_frame: Option<DecodedVideoFrame>,
        audio_session: Option<Box<dyn AudioSession>>,
        is_playing: Arc<AtomicBool>,
        stop_signal: Arc<AtomicBool>,
        restart_signal: Arc<AtomicBool>,
        seek_requested: Arc<AtomicBool>,
        seek_target_ms: Arc<AtomicU64>,
        position_ms: Arc<AtomicU64>,
        duration_ms: Option<u64>,
        width: Arc<AtomicU32>,
        height: Arc<AtomicU32>,
        finished: Arc<AtomicBool>,
        volume: f32,
        muted: bool,
    }

    impl WindowsMfVideoSession {
        pub fn open(bytes: Arc<[u8]>, file_name: &str) -> Result<Self, String> {
            let (frame_tx, frame_rx): (SyncSender<DecodedVideoFrame>, Receiver<DecodedVideoFrame>) =
                sync_channel(3);
            let (init_tx, init_rx) = sync_channel::<Result<(u32, u32, Option<u64>), String>>(1);

            let is_playing = Arc::new(AtomicBool::new(true));
            let stop_signal = Arc::new(AtomicBool::new(false));
            let restart_signal = Arc::new(AtomicBool::new(false));
            let seek_requested = Arc::new(AtomicBool::new(false));
            let seek_target_ms = Arc::new(AtomicU64::new(0));
            let position_ms = Arc::new(AtomicU64::new(0));
            let width = Arc::new(AtomicU32::new(0));
            let height = Arc::new(AtomicU32::new(0));
            let finished = Arc::new(AtomicBool::new(false));

            let thread_bytes = bytes.clone();
            let thread_playing = is_playing.clone();
            let thread_stop = stop_signal.clone();
            let thread_restart = restart_signal.clone();
            let thread_seek_req = seek_requested.clone();
            let thread_seek_target = seek_target_ms.clone();
            let thread_pos = position_ms.clone();
            let thread_w = width.clone();
            let thread_h = height.clone();
            let thread_fin = finished.clone();
            let fname = file_name.to_string();

            // Spawn the video worker on an MTA thread first so COM / Media Foundation never
            // touches the winit STA GUI thread.
            thread::spawn(move || {
                let _ = catch_unwind(AssertUnwindSafe(move || {
                    video_worker_loop(
                        thread_bytes,
                        fname,
                        init_tx,
                        frame_tx,
                        thread_playing,
                        thread_stop,
                        thread_restart,
                        thread_seek_req,
                        thread_seek_target,
                        thread_pos,
                        thread_w,
                        thread_h,
                        thread_fin,
                    );
                }));
            });

            let (init_w, init_h, mut duration_ms) = init_rx
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "Timed out initializing Media Foundation video decoder".to_string())??;

            width.store(init_w, Ordering::Relaxed);
            height.store(init_h, Ordering::Relaxed);

            // Open optional synchronized in-memory audio track (safe if video has no audio stream)
            let mut audio_session = RodioAudioBackend.open_memory(bytes, file_name).ok();
            if duration_ms.is_none()
                && let Some(ref mut audio) = audio_session
            {
                duration_ms = audio.status().duration_ms;
            }

            Ok(Self {
                frame_rx,
                latest_frame: None,
                audio_session,
                is_playing,
                stop_signal,
                restart_signal,
                seek_requested,
                seek_target_ms,
                position_ms,
                duration_ms,
                width,
                height,
                finished,
                volume: 0.85,
                muted: false,
            })
        }
    }

    unsafe fn seek_source_reader_ms(reader: &IMFSourceReader, target_ms: u64) -> bool {
        unsafe {
            let mut prop = std::mem::zeroed();
            let raw: &mut [u8] = std::slice::from_raw_parts_mut(
                (&mut prop as *mut _) as *mut u8,
                std::mem::size_of_val(&prop),
            );
            raw[0..2].copy_from_slice(&20u16.to_le_bytes()); // VT_I8 = 20 (100-ns units)
            let hns = (target_ms as i64).saturating_mul(10_000);
            raw[8..16].copy_from_slice(&hns.to_le_bytes());

            let _ = reader.Flush(MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32);
            reader.SetCurrentPosition(&GUID::zeroed(), &prop).is_ok()
        }
    }

    fn configure_video_reader(
        bytes: &[u8],
        file_name: &str,
    ) -> Result<(IMFSourceReader, u32, u32, i32, Option<u64>), String> {
        unsafe {
            let reader = create_in_memory_source_reader(bytes, file_name)?;
            let v_idx = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;
            let out_type: IMFMediaType =
                MFCreateMediaType().map_err(|e| format!("MFCreateMediaType failed: {e}"))?;
            out_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .map_err(|e| format!("SetGUID Video failed: {e}"))?;
            out_type
                .SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_RGB32)
                .map_err(|e| format!("SetGUID RGB32 failed: {e}"))?;
            reader
                .SetCurrentMediaType(v_idx, None, &out_type)
                .map_err(|e| format!("Media Foundation could not configure RGB32 video decoder: {e}"))?;

            let current = reader
                .GetCurrentMediaType(v_idx)
                .map_err(|e| format!("GetCurrentMediaType(Video) failed: {e}"))?;
            let packed = current.GetUINT64(&MF_MT_FRAME_SIZE).unwrap_or(0);
            let w = (packed >> 32) as u32;
            let h = (packed & 0xFFFF_FFFF) as u32;
            let s = current
                .GetUINT32(&MF_MT_DEFAULT_STRIDE)
                .map(|v| v as i32)
                .unwrap_or((w * 4) as i32);
            let dur = query_duration_ms(&reader);
            Ok((reader, w, h, s, dur))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn video_worker_loop(
        bytes: Arc<[u8]>,
        file_name: String,
        init_tx: SyncSender<Result<(u32, u32, Option<u64>), String>>,
        frame_tx: SyncSender<DecodedVideoFrame>,
        is_playing: Arc<AtomicBool>,
        stop_signal: Arc<AtomicBool>,
        restart_signal: Arc<AtomicBool>,
        seek_requested: Arc<AtomicBool>,
        seek_target_ms: Arc<AtomicU64>,
        position_ms: Arc<AtomicU64>,
        width_out: Arc<AtomicU32>,
        height_out: Arc<AtomicU32>,
        finished: Arc<AtomicBool>,
    ) {
        let mut first_pass = true;
        let v_idx = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;
        let eos_or_err = (MF_SOURCE_READERF_ENDOFSTREAM.0 | MF_SOURCE_READERF_ERROR.0) as u32;

        'outer: loop {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }

            let (reader, mut width, mut height, mut stride, dur) =
                match configure_video_reader(&bytes, &file_name) {
                    Ok(tuple) => tuple,
                    Err(e) => {
                        if first_pass {
                            let _ = init_tx.send(Err(e));
                        }
                        break;
                    }
                };

            if first_pass {
                first_pass = false;
                let _ = init_tx.send(Ok((width, height, dur)));
            }

            width_out.store(width, Ordering::Relaxed);
            height_out.store(height, Ordering::Relaxed);
            finished.store(false, Ordering::Relaxed);

            let mut force_decode_one_frame = false;
            if seek_requested.swap(false, Ordering::Relaxed) {
                let target_ms = seek_target_ms.load(Ordering::Relaxed);
                let _ = unsafe { seek_source_reader_ms(&reader, target_ms) };
                position_ms.store(target_ms, Ordering::Relaxed);
                force_decode_one_frame = true;
            } else {
                position_ms.store(0, Ordering::Relaxed);
            }

            let mut wall_anchor: Option<Instant> = None;
            let mut media_anchor_ms: u64 = 0;

            loop {
                if stop_signal.load(Ordering::Relaxed) {
                    break 'outer;
                }
                if restart_signal.swap(false, Ordering::Relaxed) {
                    continue 'outer;
                }
                if seek_requested.swap(false, Ordering::Relaxed) {
                    let target_ms = seek_target_ms.load(Ordering::Relaxed);
                    if unsafe { seek_source_reader_ms(&reader, target_ms) } {
                        position_ms.store(target_ms, Ordering::Relaxed);
                        finished.store(false, Ordering::Relaxed);
                        wall_anchor = None;
                        force_decode_one_frame = true;
                    } else {
                        seek_requested.store(true, Ordering::Relaxed);
                        continue 'outer;
                    }
                }
                if !is_playing.load(Ordering::Relaxed) && !force_decode_one_frame {
                    wall_anchor = None;
                    thread::sleep(Duration::from_millis(15));
                    continue;
                }

                let mut flags: u32 = 0;
                let mut timestamp_hns: i64 = 0;
                let mut sample: Option<IMFSample> = None;

                let read_ok = unsafe {
                    reader.ReadSample(
                        v_idx,
                        0,
                        None,
                        Some(&mut flags),
                        Some(&mut timestamp_hns),
                        Some(&mut sample),
                    )
                };
                if read_ok.is_err() {
                    break;
                }

                if (flags & (MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED.0 as u32)) != 0 {
                    unsafe {
                        if let Ok(current) = reader.GetCurrentMediaType(v_idx) {
                            let packed = current.GetUINT64(&MF_MT_FRAME_SIZE).unwrap_or(0);
                            width = (packed >> 32) as u32;
                            height = (packed & 0xFFFF_FFFF) as u32;
                            stride = current
                                .GetUINT32(&MF_MT_DEFAULT_STRIDE)
                                .map(|v| v as i32)
                                .unwrap_or((width * 4) as i32);
                            width_out.store(width, Ordering::Relaxed);
                            height_out.store(height, Ordering::Relaxed);
                        }
                    }
                }

                if (flags & eos_or_err) != 0 {
                    finished.store(true, Ordering::Relaxed);
                    is_playing.store(false, Ordering::Relaxed);
                    while !stop_signal.load(Ordering::Relaxed) {
                        if restart_signal.swap(false, Ordering::Relaxed)
                            || seek_requested.load(Ordering::Relaxed)
                        {
                            continue 'outer;
                        }
                        thread::sleep(Duration::from_millis(25));
                    }
                    break 'outer;
                }

                let Some(sample) = sample else {
                    if flags != 0 {
                        continue;
                    }
                    break;
                };

                let frame_ts_ms = (timestamp_hns.max(0) as u64) / 10_000;
                position_ms.store(frame_ts_ms, Ordering::Relaxed);

                if !force_decode_one_frame {
                    // Pace video decoding to real-time presentation timestamp
                    match wall_anchor {
                        None => {
                            wall_anchor = Some(Instant::now());
                            media_anchor_ms = frame_ts_ms;
                        }
                        Some(anchor) => {
                            let media_delta = frame_ts_ms.saturating_sub(media_anchor_ms);
                            let wall_delta = anchor.elapsed().as_millis() as u64;
                            if media_delta > wall_delta {
                                let sleep_ms = (media_delta - wall_delta).min(250);
                                thread::sleep(Duration::from_millis(sleep_ms));
                            }
                        }
                    }
                }
                force_decode_one_frame = false;

                let rgba = unsafe { extract_rgba_from_sample(&sample, width, height, stride) };
                if let Some(rgba) = rgba {
                    let _ = frame_tx.try_send(DecodedVideoFrame {
                        width,
                        height,
                        rgba,
                        timestamp_ms: frame_ts_ms,
                    });
                }
            }
        }
    }

    unsafe fn extract_rgba_from_sample(
        sample: &IMFSample,
        width: u32,
        height: u32,
        stride: i32,
    ) -> Option<Vec<u8>> {
        if width == 0 || height == 0 {
            return None;
        }
        let buffer: IMFMediaBuffer = unsafe { sample.ConvertToContiguousBuffer().ok()? };
        let mut data_ptr: *mut u8 = null_mut();
        let mut cur_len: u32 = 0;
        unsafe { buffer.Lock(&mut data_ptr, None, Some(&mut cur_len)).ok()? };
        if data_ptr.is_null() || cur_len == 0 {
            let _ = unsafe { buffer.Unlock() };
            return None;
        }

        let w = width as usize;
        let h = height as usize;
        let abs_stride = if stride == 0 {
            w * 4
        } else {
            stride.unsigned_abs() as usize
        };
        let bottom_up = stride < 0;

        let src = unsafe { std::slice::from_raw_parts(data_ptr, cur_len as usize) };
        let mut rgba = vec![0u8; w * h * 4];

        for y in 0..h {
            let src_row_idx = if bottom_up { h - 1 - y } else { y };
            let src_row_start = src_row_idx.saturating_mul(abs_stride);
            let dst_row_start = y * w * 4;

            for x in 0..w {
                let s_i = src_row_start + x * 4;
                let d_i = dst_row_start + x * 4;
                if s_i + 3 < src.len() {
                    rgba[d_i] = src[s_i + 2];     // R
                    rgba[d_i + 1] = src[s_i + 1]; // G
                    rgba[d_i + 2] = src[s_i];     // B
                    rgba[d_i + 3] = 255;          // A
                }
            }
        }

        let _ = unsafe { buffer.Unlock() };
        Some(rgba)
    }

    impl Drop for WindowsMfVideoSession {
        fn drop(&mut self) {
            self.stop_signal.store(true, Ordering::Relaxed);
            if let Some(ref mut audio) = self.audio_session {
                audio.stop();
            }
        }
    }

    impl VideoSession for WindowsMfVideoSession {
        fn play(&mut self) {
            if self.finished.load(Ordering::Relaxed) {
                self.restart();
                return;
            }
            self.is_playing.store(true, Ordering::Relaxed);
            if let Some(ref mut audio) = self.audio_session {
                audio.play();
            }
        }

        fn pause(&mut self) {
            self.is_playing.store(false, Ordering::Relaxed);
            if let Some(ref mut audio) = self.audio_session {
                audio.pause();
            }
        }

        fn restart(&mut self) {
            self.finished.store(false, Ordering::Relaxed);
            self.is_playing.store(true, Ordering::Relaxed);
            self.position_ms.store(0, Ordering::Relaxed);
            self.restart_signal.store(true, Ordering::Relaxed);
            if let Some(ref mut audio) = self.audio_session {
                audio.stop();
                audio.play();
            }
        }

        fn seek_ms(&mut self, pos_ms: u64) {
            let clamped = match self.duration_ms {
                Some(d) if d > 0 => pos_ms.min(d),
                _ => pos_ms,
            };
            self.finished.store(false, Ordering::Relaxed);
            self.position_ms.store(clamped, Ordering::Relaxed);
            self.seek_target_ms.store(clamped, Ordering::Relaxed);
            self.seek_requested.store(true, Ordering::Relaxed);
            if let Some(ref mut audio) = self.audio_session {
                audio.seek_ms(clamped);
            }
        }

        fn set_volume(&mut self, volume: f32) {
            self.volume = volume.clamp(0.0, 1.5);
            if let Some(ref mut audio) = self.audio_session {
                audio.set_volume(self.volume);
            }
        }

        fn set_muted(&mut self, muted: bool) {
            self.muted = muted;
            if let Some(ref mut audio) = self.audio_session {
                audio.set_muted(muted);
            }
        }

        fn poll_frame(&mut self) -> Option<DecodedVideoFrame> {
            while let Ok(frame) = self.frame_rx.try_recv() {
                self.latest_frame = Some(frame);
            }
            self.latest_frame.clone()
        }

        fn status(&self) -> VideoStatus {
            VideoStatus {
                is_playing: self.is_playing.load(Ordering::Relaxed),
                position_ms: self.position_ms.load(Ordering::Relaxed),
                duration_ms: self.duration_ms,
                width: self.width.load(Ordering::Relaxed),
                height: self.height.load(Ordering::Relaxed),
                volume: self.volume,
                muted: self.muted,
                finished: self.finished.load(Ordering::Relaxed),
                backend_name: "Windows Media Foundation (In-Memory Stream)".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use windows::Win32::Media::MediaFoundation::{
        IMFAttributes, IMFByteStream, IMFMediaBuffer, IMFMediaType, IMFSample, IMFSinkWriter,
        MF_BYTESTREAM_CONTENT_TYPE, MF_BYTESTREAM_ORIGIN_NAME, MF_MT_AVG_BITRATE,
        MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
        MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE, MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS,
        MF_TRANSCODE_CONTAINERTYPE, MFCreateAttributes, MFCreateMFByteStreamOnStream,
        MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample, MFCreateSinkWriterFromURL,
        MFMediaType_Video, MFSTARTUP_FULL, MFStartup, MFTranscodeContainerType_MPEG4,
        MFVideoFormat_H264, MFVideoFormat_RGB32, MFVideoInterlace_Progressive,
    };
    use windows::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED, CoInitializeEx, IStream, STATFLAG_NONAME,
        STREAM_SEEK_SET,
    };
    use windows::Win32::UI::Shell::SHCreateMemStream;
    use windows::core::{HSTRING, Interface};

    use super::{AudioPlayerBackend, PlatformVideoBackend, RodioAudioBackend, VideoDecoderBackend};

    #[test]
    fn test_sta_thread_audio_and_video() {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            println!("STA CoInitializeEx hr = {hr:?}");
        }

        let wav = make_test_wav();
        let mf_res = super::decode_audio_track_in_memory(Arc::from(wav), "test.wav");
        assert!(mf_res.is_ok(), "Expected WAV audio decode in memory to succeed");
        let track = mf_res.unwrap();
        assert_eq!(track.channels, 1);
        assert_eq!(track.sample_rate, 8000);
        assert_eq!(track.samples.len(), 800);

        // Verify that passing an MP4 container to RodioAudioBackend never panics (even when
        // Symphonia's ReadSeekSource would have triggered a SeekError panic).
        let mp4_bytes = make_test_mp4();
        println!("Generated MP4 bytes: {} B", mp4_bytes.len());
        let _ = RodioAudioBackend.open_memory(Arc::from(mp4_bytes.clone()), "sample.mp4");

        let video_res = PlatformVideoBackend.open_memory(Arc::from(mp4_bytes), "sample.mp4");
        match video_res {
            Ok(mut session) => {
                let mut got_frame = None;
                for _ in 0..80 {
                    if let Some(f) = session.poll_frame() {
                        got_frame = Some(f);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                let f = got_frame.expect("Expected at least one decoded video frame from MP4");
                println!(
                    "Decoded MP4 frame: {}x{} ({} bytes RGBA)",
                    f.width,
                    f.height,
                    f.rgba.len()
                );
                assert_eq!(f.width, 64);
                assert_eq!(f.height, 64);

                // Test seeking video while paused
                session.pause();
                session.seek_ms(66);
                std::thread::sleep(std::time::Duration::from_millis(60));
                let after_seek = session.poll_frame();
                assert!(after_seek.is_some(), "Expected video frame after seeking while paused");
            }
            Err(e) => panic!("PlatformVideoBackend.open_memory failed: {e}"),
        }
    }

    fn make_test_wav() -> Vec<u8> {
        let sample_rate = 8000u32;
        let num_samples = 800u32; // 0.1s
        let data_size = num_samples * 2;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&(36 + data_size).to_le_bytes());
        buf.extend_from_slice(b"WAVEfmt ");
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // PCM
        buf.extend_from_slice(&1u16.to_le_bytes()); // 1 channel
        buf.extend_from_slice(&sample_rate.to_le_bytes());
        buf.extend_from_slice(&(sample_rate * 2).to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&16u16.to_le_bytes());
        buf.extend_from_slice(b"data");
        buf.extend_from_slice(&data_size.to_le_bytes());
        for i in 0..num_samples {
            let sample = ((i as f32 * 0.1).sin() * 4000.0) as i16;
            buf.extend_from_slice(&sample.to_le_bytes());
        }
        buf
    }

    fn make_test_mp4() -> Vec<u8> {
        std::thread::spawn(|| unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            MFStartup(super::win_mf::MF_VERSION_COMBINED, MFSTARTUP_FULL).unwrap();

            let mem_stream: IStream = SHCreateMemStream(None).unwrap();
            let byte_stream: IMFByteStream = MFCreateMFByteStreamOnStream(&mem_stream).unwrap();
            if let Ok(bs_attrs) = byte_stream.cast::<IMFAttributes>() {
                let _ = bs_attrs.SetString(&MF_BYTESTREAM_ORIGIN_NAME, &HSTRING::from("sample.mp4"));
                let _ = bs_attrs.SetString(&MF_BYTESTREAM_CONTENT_TYPE, &HSTRING::from("video/mp4"));
            }

            let mut sw_attrs: Option<IMFAttributes> = None;
            MFCreateAttributes(&mut sw_attrs, 2).unwrap();
            if let Some(ref a) = sw_attrs {
                let _ = a.SetGUID(&MF_TRANSCODE_CONTAINERTYPE, &MFTranscodeContainerType_MPEG4);
                let _ = a.SetUINT32(&MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS, 1);
            }

            let writer: IMFSinkWriter =
                MFCreateSinkWriterFromURL(&HSTRING::from(".mp4"), &byte_stream, sw_attrs.as_ref())
                    .unwrap();

            let width = 64u32;
            let height = 64u32;
            let frame_size = ((width as u64) << 32) | (height as u64);
            let fps_packed = (30u64 << 32) | 1u64;
            let par_packed = (1u64 << 32) | 1u64;

            let out_type: IMFMediaType = MFCreateMediaType().unwrap();
            out_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).unwrap();
            out_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264).unwrap();
            out_type.SetUINT32(&MF_MT_AVG_BITRATE, 400_000).unwrap();
            out_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .unwrap();
            out_type.SetUINT64(&MF_MT_FRAME_SIZE, frame_size).unwrap();
            out_type.SetUINT64(&MF_MT_FRAME_RATE, fps_packed).unwrap();
            out_type
                .SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, par_packed)
                .unwrap();

            let stream_index = writer.AddStream(&out_type).unwrap();

            let in_type: IMFMediaType = MFCreateMediaType().unwrap();
            in_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).unwrap();
            in_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_RGB32).unwrap();
            in_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .unwrap();
            in_type.SetUINT64(&MF_MT_FRAME_SIZE, frame_size).unwrap();
            in_type.SetUINT64(&MF_MT_FRAME_RATE, fps_packed).unwrap();
            in_type
                .SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, par_packed)
                .unwrap();

            writer.SetInputMediaType(stream_index, &in_type, None).unwrap();
            writer.BeginWriting().unwrap();

            let frame_bytes = (width * height * 4) as u32;
            let dur_hns = 333_333i64;
            for i in 0..5i64 {
                let buf: IMFMediaBuffer = MFCreateMemoryBuffer(frame_bytes).unwrap();
                let mut ptr = std::ptr::null_mut();
                buf.Lock(&mut ptr, None, None).unwrap();
                let slice = std::slice::from_raw_parts_mut(ptr, frame_bytes as usize);
                for px in slice.chunks_exact_mut(4) {
                    px[0] = 40;
                    px[1] = 120;
                    px[2] = 220;
                    px[3] = 255;
                }
                buf.Unlock().unwrap();
                buf.SetCurrentLength(frame_bytes).unwrap();

                let sample: IMFSample = MFCreateSample().unwrap();
                sample.AddBuffer(&buf).unwrap();
                sample.SetSampleTime(i * dur_hns).unwrap();
                sample.SetSampleDuration(dur_hns).unwrap();
                writer.WriteSample(stream_index, &sample).unwrap();
            }

            writer.Finalize().unwrap();

            let mut stat = std::mem::zeroed();
            mem_stream.Stat(&mut stat, STATFLAG_NONAME).unwrap();
            let total_len = stat.cbSize as usize;
            mem_stream.Seek(0, STREAM_SEEK_SET, None).unwrap();
            let mut out = vec![0u8; total_len];
            let mut read = 0u32;
            let _ = mem_stream.Read(out.as_mut_ptr() as *mut _, total_len as u32, Some(&mut read));
            out
        })
        .join()
        .unwrap()
    }
}

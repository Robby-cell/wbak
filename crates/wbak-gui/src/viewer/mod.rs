#[cfg(feature = "media-viewer")]
pub mod backends;

use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Text,
    Image,
    Audio,
    Video,
    Binary,
}

impl MediaKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "Text / Code",
            Self::Image => "Photo / Image",
            Self::Audio => "Music / Audio",
            Self::Video => "Video",
            Self::Binary => "Binary / Hex",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Text => "📄",
            Self::Image => "🖼",
            Self::Audio => "🎵",
            Self::Video => "🎬",
            Self::Binary => "🔢",
        }
    }
}

/// Classifies a file's content type from its logical path and in-memory byte header.
pub fn classify_media_kind(logical_path: &str, bytes: &[u8]) -> MediaKind {
    let lower = logical_path.to_ascii_lowercase();
    let ext = lower
        .rsplit_once('.')
        .map(|(_, e)| e)
        .unwrap_or_default();

    match ext {
        "png" | "jpg" | "jpeg" | "webp" | "bmp" | "ico" | "tiff" | "tif" => {
            return MediaKind::Image;
        }
        "gif" => {
            return MediaKind::Image;
        }
        "mp3" | "wav" | "flac" | "ogg" | "oga" | "m4a" | "aac" | "opus" | "wma" => {
            return MediaKind::Audio;
        }
        "mp4" | "mkv" | "webm" | "mov" | "avi" | "wmv" | "m4v" => {
            return MediaKind::Video;
        }
        "txt" | "md" | "rs" | "toml" | "json" | "yaml" | "yml" | "xml" | "html" | "css" | "js"
        | "ts" | "tsx" | "jsx" | "py" | "c" | "cpp" | "cc" | "h" | "hpp" | "cs" | "go" | "java"
        | "sh" | "ps1" | "bat" | "cmd" | "ini" | "cfg" | "conf" | "log" | "csv" | "sql"
        | "gitignore" | "wbakignore" | "gitconfig" | "pub" | "pem" | "key" => {
            if decode_text_preview(bytes).is_some() {
                return MediaKind::Text;
            }
        }
        _ => {}
    }

    // Magic byte sniffing for extensionless files
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xFF\xD8\xFF")
        || bytes.starts_with(b"GIF87a")
        || bytes.starts_with(b"GIF89a")
        || (bytes.len() > 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
    {
        return MediaKind::Image;
    }

    if bytes.starts_with(b"ID3")
        || bytes.starts_with(b"fLaC")
        || bytes.starts_with(b"OggS")
        || (bytes.len() > 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE")
    {
        return MediaKind::Audio;
    }

    if bytes.len() > 12 && &bytes[4..8] == b"ftyp" {
        return MediaKind::Video;
    }

    if decode_text_preview(bytes).is_some() {
        MediaKind::Text
    } else {
        MediaKind::Binary
    }
}

/// Attempts to decode an in-memory byte slice as UTF-8 or UTF-16 (LE/BE BOM) text.
pub fn decode_text_preview(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }

    // Check UTF-16 LE BOM
    if bytes.starts_with(&[0xFF, 0xFE]) && bytes.len() % 2 == 0 {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&u16s).ok();
    }

    // Check UTF-16 BE BOM
    if bytes.starts_with(&[0xFE, 0xFF]) && bytes.len() % 2 == 0 {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&u16s).ok();
    }

    // Reject binary files containing null bytes in the first 8 KB
    let probe_len = bytes.len().min(8192);
    if bytes[..probe_len].contains(&0) {
        return None;
    }

    std::str::from_utf8(bytes).ok().map(ToOwned::to_owned)
}

#[derive(Debug, Clone)]
pub struct DecodedImageFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
    pub delay_ms: u32,
}

#[derive(Debug, Clone)]
pub struct DecodedImageAsset {
    pub frames: Vec<DecodedImageFrame>,
    pub format_label: String,
}

/// Platform-agnostic trait for decoding in-memory image/photo assets (including animated frames).
pub trait ImageDecoderBackend: Send + Sync {
    fn decode(&self, bytes: &[u8], file_name: &str) -> Result<DecodedImageAsset, String>;
}

#[derive(Debug, Clone)]
pub struct AudioStatus {
    pub is_playing: bool,
    pub elapsed_ms: u64,
    pub duration_ms: Option<u64>,
    pub volume: f32,
    pub muted: bool,
    pub waveform_bars: [f32; 32],
    pub backend_name: String,
}

/// Platform-agnostic active audio playback session backed by in-memory bytes.
pub trait AudioSession {
    fn play(&mut self);
    fn pause(&mut self);
    fn stop(&mut self);
    fn seek_ms(&mut self, pos_ms: u64);
    fn set_volume(&mut self, volume: f32);
    fn set_muted(&mut self, muted: bool);
    fn status(&mut self) -> AudioStatus;
}

/// Platform-agnostic factory for creating in-memory audio sessions.
pub trait AudioPlayerBackend: Send + Sync {
    fn open_memory(&self, bytes: Arc<[u8]>, file_name: &str) -> Result<Box<dyn AudioSession>, String>;
}

#[derive(Debug, Clone)]
pub struct DecodedVideoFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone)]
pub struct VideoStatus {
    pub is_playing: bool,
    pub position_ms: u64,
    pub duration_ms: Option<u64>,
    pub width: u32,
    pub height: u32,
    pub volume: f32,
    pub muted: bool,
    pub finished: bool,
    pub backend_name: String,
}

/// Platform-agnostic active video playback session backed by in-memory bytes.
pub trait VideoSession {
    fn play(&mut self);
    fn pause(&mut self);
    fn restart(&mut self);
    fn seek_ms(&mut self, pos_ms: u64);
    fn set_volume(&mut self, volume: f32);
    fn set_muted(&mut self, muted: bool);
    fn poll_frame(&mut self) -> Option<DecodedVideoFrame>;
    fn status(&self) -> VideoStatus;
}

/// Platform-agnostic factory for creating in-memory video playback sessions.
pub trait VideoDecoderBackend: Send + Sync {
    fn open_memory(&self, bytes: Arc<[u8]>, file_name: &str) -> Result<Box<dyn VideoSession>, String>;
}

#[cfg(not(feature = "media-viewer"))]
struct UnsupportedImageBackend;
#[cfg(not(feature = "media-viewer"))]
impl ImageDecoderBackend for UnsupportedImageBackend {
    fn decode(&self, _bytes: &[u8], _file_name: &str) -> Result<DecodedImageAsset, String> {
        Err("Image viewer feature ('media-viewer') is not enabled in this build.".to_string())
    }
}

#[cfg(not(feature = "media-viewer"))]
struct UnsupportedAudioBackend;
#[cfg(not(feature = "media-viewer"))]
impl AudioPlayerBackend for UnsupportedAudioBackend {
    fn open_memory(&self, _bytes: Arc<[u8]>, _file_name: &str) -> Result<Box<dyn AudioSession>, String> {
        Err("Audio player feature ('media-viewer') is not enabled in this build.".to_string())
    }
}

#[cfg(not(feature = "media-viewer"))]
struct UnsupportedVideoBackend;
#[cfg(not(feature = "media-viewer"))]
impl VideoDecoderBackend for UnsupportedVideoBackend {
    fn open_memory(&self, _bytes: Arc<[u8]>, _file_name: &str) -> Result<Box<dyn VideoSession>, String> {
        Err("Video player feature ('media-viewer') is not enabled in this build.".to_string())
    }
}

/// Registry of pluggable platform media backends.
/// Can be extended on Windows, Linux, macOS, or Web without changing GUI or domain code.
#[derive(Clone)]
pub struct MediaBackendRegistry {
    pub image: Arc<dyn ImageDecoderBackend>,
    pub audio: Arc<dyn AudioPlayerBackend>,
    pub video: Arc<dyn VideoDecoderBackend>,
}

impl MediaBackendRegistry {
    pub fn default_for_platform() -> Self {
        #[cfg(feature = "media-viewer")]
        {
            Self {
                image: Arc::new(backends::StandardImageBackend),
                audio: Arc::new(backends::RodioAudioBackend),
                video: Arc::new(backends::PlatformVideoBackend),
            }
        }
        #[cfg(not(feature = "media-viewer"))]
        {
            Self {
                image: Arc::new(UnsupportedImageBackend),
                audio: Arc::new(UnsupportedAudioBackend),
                video: Arc::new(UnsupportedVideoBackend),
            }
        }
    }

    pub fn with_custom_backends(
        image: Arc<dyn ImageDecoderBackend>,
        audio: Arc<dyn AudioPlayerBackend>,
        video: Arc<dyn VideoDecoderBackend>,
    ) -> Self {
        Self {
            image,
            audio,
            video,
        }
    }
}

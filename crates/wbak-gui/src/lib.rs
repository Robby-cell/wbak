pub mod app;
pub mod viewer;
pub mod viewer_panel;

use anyhow::{Result, anyhow};

use wbak_app::WbakApplication;

pub use app::*;

pub fn launch_gui(app: WbakApplication) -> Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("wbak — Windows Backup & Reproducible Environment Tool")
            .with_inner_size([1080.0, 720.0])
            .with_min_inner_size([800.0, 540.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "wbak",
        native_options,
        Box::new(move |_cc| Ok(Box::new(WbakGuiApp::new(app)))),
    )
    .map_err(|e| anyhow!("GUI error: {e}"))
}

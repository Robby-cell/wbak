pub mod app;

use anyhow::{anyhow, Result};

use wbak_app::WbakApplication;

pub use app::*;

pub fn launch_gui(app: WbakApplication) -> Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("wbak — Windows Backup & Reproducible Environment Tool")
            .with_inner_size([980.0, 680.0])
            .with_min_inner_size([760.0, 520.0]),
        ..Default::default()
    };

    eframe::run_native(
        "wbak",
        native_options,
        Box::new(move |_cc| Ok(Box::new(WbakGuiApp::new(app)))),
    )
    .map_err(|e| anyhow!("GUI error: {e}"))
}

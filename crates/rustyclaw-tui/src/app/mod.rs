mod app;
mod handlers;
mod state;

pub use app::App;
pub use state::SharedState;

use anyhow::Result;
use rustyclaw_core::config::Config;

pub fn create_app(config: Config) -> Result<App> {
    App::new(config)
}

pub fn create_app_with_password(config: Config, password: String) -> Result<App> {
    App::with_password(config, password)
}

pub fn create_app_locked(config: Config) -> Result<App> {
    App::new_locked(config)
}

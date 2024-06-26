pub mod util;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use crate::windows::*;

#[cfg(target_os = "windows")]
pub use retour;

#[cfg(target_os = "windows")]
pub use anyhow;

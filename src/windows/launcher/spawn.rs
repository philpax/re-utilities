use anyhow::Context;
use std::path::{Path, PathBuf};

use dll_syringe::process::OwnedProcess;
use windows::{core::HSTRING, Win32::System::Threading};

pub fn arbitrary_process(
    game_path: &Path,
    executable_path: &Path,
    env_vars: impl Iterator<Item = (String, String)>,
) -> anyhow::Result<OwnedProcess> {
    use std::os::windows::prelude::FromRawHandle;

    let startup_info = Threading::STARTUPINFOW::default();
    let mut process_info = Threading::PROCESS_INFORMATION::default();

    let environment: Vec<u16> = std::env::vars()
        .chain(env_vars)
        .fold(String::new(), |a, (k, v)| format!("{}{}={}\0", a, k, v))
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let application_name = HSTRING::from(executable_path.as_os_str());
        let current_directory = HSTRING::from(game_path.as_os_str());
        Threading::CreateProcessW(
            &application_name,
            windows::core::PWSTR::null(),
            std::ptr::null(),
            std::ptr::null(),
            false,
            Threading::CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr() as _,
            &current_directory,
            &startup_info,
            &mut process_info,
        )
        .as_bool()
        .then(|| OwnedProcess::from_raw_handle(process_info.hProcess.0 as _))
        .context("failed to spawn process")
    }
}

pub fn steam_process(
    app_id: u32,
    executable_path_builder: impl Fn(&Path) -> PathBuf + Copy,
) -> anyhow::Result<OwnedProcess> {
    let app_id = app_id.to_string();
    let game_path = game_scanner::steam::find(&app_id)?
        .path
        .context("failed to locate app")?;
    let executable_path = executable_path_builder(&game_path);

    let env_vars = ["SteamGameId", "SteamAppId"]
        .iter()
        .map(|s| (s.to_string(), app_id.clone()));

    arbitrary_process(&game_path, &executable_path, env_vars)
}

pub fn egs_process(
    app_id: &str,
    executable_path_builder: impl Fn(&Path) -> PathBuf + Copy,
) -> anyhow::Result<OwnedProcess> {
    let game_path = game_scanner::epicgames::find(app_id)?
        .path
        .context("failed to locate app")?;
    let executable_path = executable_path_builder(&game_path);

    // TODO: Make this actually work. Turns out EGS requires you to pass in
    // an authentication token via the parameters, ughhhhh:
    // https://github.com/derrod/legendary/blob/d7360eef3e2ed5816da5549d71d5bce57e129df3/legendary/core.py#L662
    arbitrary_process(&game_path, &executable_path, std::iter::empty())
}

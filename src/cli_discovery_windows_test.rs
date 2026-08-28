#![cfg(windows)]

use crate::orchestrator::which_on_path_in;
use tempfile::tempdir;

#[test]
fn test_which_on_path_finds_executable_with_extension_on_windows() {
    let temp = tempdir().unwrap();
    let fake_claude_exe = temp.path().join("claude.exe");
    std::fs::write(&fake_claude_exe, "fake binary content").unwrap();

    let path_var = Some(temp.path().as_os_str().to_os_string());
    let found = which_on_path_in("claude", path_var);

    assert!(
        found.is_some(),
        "which_on_path_in(\"claude\") must locate `claude.exe` on PATH on Windows, but got None"
    );
    let found_path = found.unwrap();
    assert!(
        found_path.to_ascii_lowercase().ends_with("claude.exe"),
        "expected found path to end with claude.exe, got {found_path}"
    );
}

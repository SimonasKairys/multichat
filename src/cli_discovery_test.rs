use crate::orchestrator::{which_on_path, which_on_path_in};
use std::path::Path;
use tempfile::tempdir;

#[test]
fn which_on_path_in_finds_an_exact_executable_name() {
    let temp = tempdir().unwrap();
    let executable = temp.path().join("simon-test-tool");
    std::fs::write(&executable, "fake binary content").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
    }

    let found = which_on_path_in(
        "simon-test-tool",
        Some(temp.path().as_os_str().to_os_string()),
    );

    assert_eq!(
        found.as_deref(),
        Some(executable.to_string_lossy().as_ref())
    );
}

#[test]
fn which_on_path_in_returns_none_when_the_executable_is_absent() {
    let temp = tempdir().unwrap();
    assert_eq!(
        which_on_path_in(
            "missing-simon-test-tool",
            Some(temp.path().as_os_str().to_os_string())
        ),
        None
    );
}

#[test]
fn which_on_path_in_rejects_an_empty_executable_name() {
    let temp = tempdir().unwrap();
    assert_eq!(
        which_on_path_in("", Some(temp.path().as_os_str().to_os_string())),
        None
    );
}

#[test]
fn which_on_path_returns_a_real_executable_from_the_process_path() {
    let found = which_on_path("cargo").expect("cargo must be on PATH while running cargo tests");
    assert!(
        Path::new(&found).is_file(),
        "resolved cargo path is not a file: {found}"
    );
}

#[cfg(windows)]
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

#[cfg(windows)]
#[test]
fn which_on_path_prefers_pathext_match_over_extensionless_npm_shim_on_windows() {
    // npm installs three shims side by side: an extensionless POSIX `claude` script
    // (for Git Bash), `claude.cmd`, and `claude.ps1`. `CreateProcess` cannot run the
    // POSIX script, so discovery must hand back the `.cmd` even though the bare file
    // matches the name exactly.
    let temp = tempdir().unwrap();
    std::fs::write(
        temp.path().join("claude"),
        "#!/bin/sh\nexec node claude.js \"$@\"\n",
    )
    .unwrap();
    std::fs::write(
        temp.path().join("claude.cmd"),
        "@echo off\r\nnode claude.js %*\r\n",
    )
    .unwrap();

    let found = which_on_path_in("claude", Some(temp.path().as_os_str().to_os_string()))
        .expect("discovery must find the shim pair");
    assert!(
        found.to_ascii_lowercase().ends_with("claude.cmd"),
        "expected the spawnable claude.cmd, got the unspawnable {found}"
    );
}

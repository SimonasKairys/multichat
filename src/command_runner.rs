//! Bounded argv-only execution for commander-requested proofs.
//!
//! A command may only be run with an isolated task copy as its working directory.
//! `current_dir` is not a kernel sandbox: trusted project code can still open absolute
//! paths, create sockets, or spawn other programs. The safeguards here instead close
//! the model-controlled surfaces Simon can enforce without adding a container
//! runtime: no shell, a small program/subcommand allowlist, no absolute or parent-path
//! arguments, a cleared environment with task-local home/temp/cache directories,
//! capped output, a wall-clock timeout, and process-group termination on Unix.

use anyhow::{Context, Result, anyhow};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::process::Command;

use crate::isolation::{CopyQuota, validate_copy_root, wait_for_copy_quota_violation};

pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const OUTPUT_BYTES_PER_STREAM: usize = 16 * 1024;
const MAX_ARGS: usize = 64;
const MAX_ARG_CHARS: usize = 512;
const MAX_ARGV_CHARS: usize = 4 * 1024;

const ALLOWED_CARGO_SUBCOMMANDS: &[&str] = &[
    "test", "check", "build", "clippy", "fmt", "nextest", "mutants", "doc",
];
const ALLOWED_GO_SUBCOMMANDS: &[&str] = &["test", "build", "vet", "fmt"];
const ALLOWED_DENO_SUBCOMMANDS: &[&str] = &["test", "check", "fmt", "lint"];
const ALLOWED_SCRIPT_NAMES: &[&str] = &["test", "check", "lint", "build", "typecheck", "fmt"];
const ALLOWED_MAKE_TARGETS: &[&str] = &["test", "check", "lint", "build", "fmt", "clippy"];

#[derive(Debug, Clone)]
pub struct ValidatedCommand {
    pub argv: Vec<String>,
    program: PathBuf,
    child_path: OsString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// `None` means the command was killed by the wall-clock or copy-resource limit.
    pub exit_code: Option<i32>,
    pub resource_limit: Option<String>,
    pub output: String,
    pub output_chars: usize,
}

struct ProcessGroupGuard {
    pid: Option<u32>,
}

impl ProcessGroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid }
    }

    fn terminate(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.pid {
            let _ = crate::security::kill_process_group(pid);
        }
        self.pid = None;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Validates a model-provided argv and pins its executable to an absolute path.
pub fn validate_command(
    argv: &[String],
    task_root: &Path,
    main_project_root: &Path,
) -> Result<ValidatedCommand> {
    if argv.is_empty() {
        return Err(anyhow!("command argv is empty"));
    }
    if argv.len() > MAX_ARGS {
        return Err(anyhow!(
            "command has {} arguments, over the {MAX_ARGS}-argument limit",
            argv.len()
        ));
    }

    let mut total_chars = 0usize;
    for arg in argv {
        let chars = arg.chars().count();
        if chars > MAX_ARG_CHARS {
            return Err(anyhow!(
                "one command argument is {chars} characters, over the {MAX_ARG_CHARS}-character limit"
            ));
        }
        total_chars = total_chars.saturating_add(chars);
    }
    if total_chars > MAX_ARGV_CHARS {
        return Err(anyhow!(
            "command argv is {total_chars} characters, over the {MAX_ARGV_CHARS}-character limit"
        ));
    }

    let program = argv[0].trim();
    if program.is_empty() {
        return Err(anyhow!("command program is empty"));
    }
    if Path::new(program).components().count() != 1 {
        return Err(anyhow!(
            "command program `{program}` must be a bare allowlisted name, not a path"
        ));
    }

    validate_program_policy(program, &argv[1..])?;
    for arg in &argv[1..] {
        validate_argument(arg)?;
    }

    let safe_path = safe_path(&[task_root, main_project_root]);
    let program_path = resolve_program(program, &safe_path)
        .ok_or_else(|| anyhow!("allowlisted command `{program}` was not found on PATH"))?;

    Ok(ValidatedCommand {
        argv: argv.to_vec(),
        program: program_path,
        child_path: std::env::join_paths(safe_path)
            .context("could not construct a safe child PATH")?,
    })
}

fn validate_program_policy(program: &str, args: &[String]) -> Result<()> {
    let program = program.to_ascii_lowercase();
    let first = args.first().map(String::as_str);

    match program.as_str() {
        "cargo" => require_subcommand("cargo", first, ALLOWED_CARGO_SUBCOMMANDS),
        "go" => require_subcommand("go", first, ALLOWED_GO_SUBCOMMANDS),
        "pytest" => Ok(()),
        "python" | "python3" => {
            if args.len() >= 2
                && args[0] == "-m"
                && matches!(args[1].as_str(), "pytest" | "unittest")
            {
                Ok(())
            } else {
                Err(anyhow!(
                    "`{program}` is limited to `-m pytest` or `-m unittest`"
                ))
            }
        }
        "node" => {
            if first == Some("--test") {
                Ok(())
            } else {
                Err(anyhow!("`node` is limited to its `--test` runner"))
            }
        }
        "npm" | "pnpm" => validate_package_runner(&program, args),
        "yarn" => {
            if matches!(first, Some(name) if ALLOWED_SCRIPT_NAMES.contains(&name))
                || (first == Some("run")
                    && matches!(args.get(1).map(String::as_str), Some(name) if ALLOWED_SCRIPT_NAMES.contains(&name)))
            {
                Ok(())
            } else {
                Err(anyhow!(
                    "`yarn` is limited to test/check/lint/build/typecheck/fmt scripts"
                ))
            }
        }
        "make" | "just" => {
            if matches!(first, Some(name) if ALLOWED_MAKE_TARGETS.contains(&name)) {
                Ok(())
            } else {
                Err(anyhow!(
                    "`{program}` is limited to test/check/lint/build/fmt/clippy targets"
                ))
            }
        }
        "deno" => require_subcommand("deno", first, ALLOWED_DENO_SUBCOMMANDS),
        "bun" => {
            if first == Some("test") {
                Ok(())
            } else {
                Err(anyhow!("`bun` is limited to `bun test`"))
            }
        }
        _ => Err(anyhow!(
            "`{program}` is not in the commander command allowlist"
        )),
    }
}

fn require_subcommand(program: &str, subcommand: Option<&str>, allowed: &[&str]) -> Result<()> {
    let Some(subcommand) = subcommand else {
        return Err(anyhow!("`{program}` requires an allowlisted subcommand"));
    };
    if allowed.contains(&subcommand) {
        Ok(())
    } else {
        Err(anyhow!(
            "`{program} {subcommand}` is not an allowed command"
        ))
    }
}

fn validate_package_runner(program: &str, args: &[String]) -> Result<()> {
    let first = args.first().map(String::as_str);
    if matches!(first, Some(name) if ALLOWED_SCRIPT_NAMES.contains(&name)) {
        return Ok(());
    }
    if first == Some("run")
        && matches!(args.get(1).map(String::as_str), Some(name) if ALLOWED_SCRIPT_NAMES.contains(&name))
    {
        return Ok(());
    }
    Err(anyhow!(
        "`{program}` is limited to test/check/lint/build/typecheck/fmt scripts"
    ))
}

fn validate_argument(arg: &str) -> Result<()> {
    const SHELL_TOKENS: &[&str] = &[
        "|", "||", "&&", ";", ">", ">>", "<", "<<", "2>&1", "&>", "`",
    ];
    if SHELL_TOKENS.contains(&arg) || arg.contains("$(") || arg.contains("${") {
        return Err(anyhow!(
            "shell operators and substitutions are not supported; use separate argv-only actions"
        ));
    }
    if arg.contains("..") {
        return Err(anyhow!(
            "command argument `{arg}` contains `..`, which could escape the task copy"
        ));
    }

    let path = Path::new(arg);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::RootDir | Component::Prefix(_)))
    {
        return Err(anyhow!(
            "command argument `{arg}` contains an absolute path"
        ));
    }
    Ok(())
}

fn safe_path(excluded_roots: &[&Path]) -> Vec<PathBuf> {
    safe_path_from(std::env::var_os("PATH"), excluded_roots)
}

fn safe_path_from(path: Option<OsString>, excluded_roots: &[&Path]) -> Vec<PathBuf> {
    let excluded_roots: Vec<PathBuf> = excluded_roots
        .iter()
        .filter_map(|root| fs::canonicalize(root).ok())
        .collect();
    path.map(|path| {
        std::env::split_paths(&path)
            .filter(|entry| entry.is_absolute())
            .filter_map(|entry| fs::canonicalize(entry).ok())
            .filter(|entry| !excluded_roots.iter().any(|root| entry.starts_with(root)))
            .collect()
    })
    .unwrap_or_default()
}

fn resolve_program(program: &str, path: &[PathBuf]) -> Option<PathBuf> {
    #[cfg(windows)]
    let candidates: Vec<String> = {
        let has_extension = Path::new(program).extension().is_some();
        if has_extension {
            vec![program.to_string()]
        } else {
            let extensions = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT".into());
            extensions
                .split(';')
                .filter(|ext| !ext.is_empty())
                .map(|ext| format!("{program}{ext}"))
                .collect()
        }
    };
    #[cfg(not(windows))]
    let candidates = vec![program.to_string()];

    for directory in path {
        for candidate in &candidates {
            let joined = directory.join(candidate);
            if is_executable_file(&joined) {
                // Preserve the invoked basename. Rustup-style tool proxies are
                // symlinks to one binary that dispatches from argv[0]; canonicalizing
                // `cargo` to `rustup` would execute the wrong command.
                return Some(joined);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
}

/// Executes a validated command inside `cwd`.
pub async fn execute_command(
    command: &ValidatedCommand,
    cwd: &Path,
    timeout: Duration,
    quota: CopyQuota,
) -> Result<ExecutionResult> {
    let cwd = fs::canonicalize(cwd)
        .with_context(|| format!("task copy {} does not exist", cwd.display()))?;
    if !fs::metadata(&cwd)?.is_dir() {
        return Err(anyhow!("task copy {} is not a directory", cwd.display()));
    }
    let runtime = prepare_runtime(&cwd)?;

    let mut child_command = Command::new(&command.program);
    child_command
        .args(&command.argv[1..])
        .current_dir(&cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .env("PATH", &command.child_path)
        .env("HOME", &runtime.home)
        .env("USERPROFILE", &runtime.home)
        .env("TMPDIR", &runtime.temp)
        .env("TMP", &runtime.temp)
        .env("TEMP", &runtime.temp)
        .env("CARGO_HOME", &runtime.cargo_home)
        .env("CARGO_TARGET_DIR", &runtime.cargo_target)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("NO_COLOR", "1");

    for name in [
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "RUST_BACKTRACE",
        "RUST_LOG",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        if let Some(value) = inherited_non_secret(name) {
            child_command.env(name, value);
        }
    }
    // Windows toolchains cannot work from an empty environment. rustc locates the
    // MSVC linker through vswhere under `ProgramFiles(x86)` and the registry via
    // COM, both of which resolve through these system-installation variables, and
    // process creation itself leans on `SystemRoot` and `ComSpec`. Scrubbing them
    // made every `cargo test` in a task copy die with "linker `link.exe` not
    // found" before the fixture's own tests ever ran. They name machine-wide
    // install locations, not user data — nothing here is a secret.
    #[cfg(windows)]
    for name in [
        "SYSTEMROOT",
        "WINDIR",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATHEXT",
        "PROGRAMFILES",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "PROGRAMDATA",
        "ALLUSERSPROFILE",
        "COMMONPROGRAMFILES",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
    ] {
        if let Some(value) = inherited_non_secret(name) {
            child_command.env(name, value);
        }
    }
    // The child's HOME/USERPROFILE point at the scratch runtime, so a rustup
    // proxy in the child would look for toolchains under the scratch directory
    // and find none. Resolve the parent's real home here — `HOME` on unix,
    // `USERPROFILE` on Windows, where `HOME` is usually not set at all — and
    // hand the proxy its real toolchain store explicitly.
    if std::env::var_os("RUSTUP_HOME").is_none()
        && let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
    {
        let default_rustup = PathBuf::from(home).join(".rustup");
        if default_rustup.is_dir() {
            child_command.env("RUSTUP_HOME", default_rustup);
        }
    }

    #[cfg(unix)]
    {
        child_command.process_group(0);
    }

    let mut child = child_command
        .spawn()
        .with_context(|| format!("failed to spawn `{}`", command.argv[0]))?;
    let child_pid = child.id();
    let mut process_group = ProcessGroupGuard::new(child_pid);
    let stdout = child.stdout.take().expect("stdout was configured as piped");
    let stderr = child.stderr.take().expect("stderr was configured as piped");
    let stdout_task = tokio::spawn(read_tail_capped(stdout, OUTPUT_BYTES_PER_STREAM));
    let stderr_task = tokio::spawn(read_tail_capped(stderr, OUTPUT_BYTES_PER_STREAM));

    enum Completion {
        Exited(std::io::Result<std::process::ExitStatus>),
        Quota(anyhow::Error),
    }

    let completion = tokio::time::timeout(timeout, async {
        tokio::select! {
            status = child.wait() => Completion::Exited(status),
            error = wait_for_copy_quota_violation(&cwd, quota) => Completion::Quota(error),
        }
    })
    .await;
    let (mut exit_code, mut resource_limit, timed_out) = match completion {
        Ok(Completion::Exited(status)) => {
            let code = status
                .context("failed to wait for command")?
                .code()
                .unwrap_or(-1);
            // A test runner must not daemonize helpers that outlive the approved
            // command. The group leader may already be gone; ESRCH is harmless.
            process_group.terminate();
            (Some(code), None, false)
        }
        Ok(Completion::Quota(error)) => {
            process_group.terminate();
            let _ = child.kill().await;
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            (None, Some(error.to_string()), false)
        }
        Err(_) => {
            process_group.terminate();
            let _ = child.kill().await;
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            (None, None, true)
        }
    };
    if resource_limit.is_none()
        && let Err(error) = validate_copy_root(&cwd, quota)
    {
        exit_code = None;
        resource_limit = Some(error.to_string());
    }

    let (stdout_bytes, stdout_truncated) = join_reader(stdout_task).await;
    let (stderr_bytes, stderr_truncated) = join_reader(stderr_task).await;
    let mut output = combine_output(
        &stderr_bytes,
        stderr_truncated,
        &stdout_bytes,
        stdout_truncated,
        timed_out,
    );
    if let Some(reason) = &resource_limit {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(
            "[simon] command stopped because the task copy exceeded its resource limit: ",
        );
        output.push_str(reason);
    }
    let output_chars = output.chars().count();

    Ok(ExecutionResult {
        exit_code,
        resource_limit,
        output,
        output_chars,
    })
}

struct RuntimeDirs {
    home: PathBuf,
    temp: PathBuf,
    cargo_home: PathBuf,
    cargo_target: PathBuf,
}

fn prepare_runtime(cwd: &Path) -> Result<RuntimeDirs> {
    let root = cwd.join(".simon-run");
    ensure_real_directory(&root)?;
    let home = root.join("home");
    let temp = root.join("tmp");
    let cargo_home = root.join("cargo-home");
    let cargo_target = root.join("target");
    for directory in [&home, &temp, &cargo_home, &cargo_target] {
        ensure_real_directory(directory)?;
    }
    Ok(RuntimeDirs {
        home,
        temp,
        cargo_home,
        cargo_target,
    })
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(anyhow!(
                "refusing task runtime directory symlink {}",
                path.display()
            ));
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(anyhow!(
                "task runtime path {} is not a directory",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).with_context(|| format!("failed to create {}", path.display()))?;
        }
        Err(e) => {
            return Err(e).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    Ok(())
}

fn inherited_non_secret(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

async fn read_tail_capped<R: AsyncRead + Unpin>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = VecDeque::with_capacity(cap);
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if read >= cap {
                    kept.clear();
                    kept.extend(&chunk[read - cap..read]);
                    truncated = true;
                    continue;
                }
                let overflow = kept.len().saturating_add(read).saturating_sub(cap);
                if overflow > 0 {
                    kept.drain(..overflow);
                    truncated = true;
                }
                kept.extend(&chunk[..read]);
            }
        }
    }
    (kept.into_iter().collect(), truncated)
}

async fn join_reader(mut task: tokio::task::JoinHandle<(Vec<u8>, bool)>) -> (Vec<u8>, bool) {
    match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => (Vec::new(), false),
        Err(_) => {
            task.abort();
            (Vec::new(), true)
        }
    }
}

fn combine_output(
    stderr: &[u8],
    stderr_truncated: bool,
    stdout: &[u8],
    stdout_truncated: bool,
    timed_out: bool,
) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stdout = String::from_utf8_lossy(stdout);
    let mut output = String::new();
    if timed_out {
        output.push_str("[killed: command exceeded the time limit]\n");
    }
    if !stderr.trim().is_empty() {
        output.push_str("[stderr]\n");
        output.push_str(&stderr);
        if !stderr.ends_with('\n') {
            output.push('\n');
        }
    }
    if !stdout.trim().is_empty() {
        output.push_str("[stdout]\n");
        output.push_str(&stdout);
        if !stdout.ends_with('\n') {
            output.push('\n');
        }
    }
    if stderr_truncated {
        output.push_str("[earlier stderr output truncated]\n");
    }
    if stdout_truncated {
        output.push_str("[earlier stdout output truncated]\n");
    }
    if output.is_empty() {
        output.push_str("(no output)");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn root() -> tempfile::TempDir {
        tempdir().unwrap()
    }

    // Every consumer is a unix-gated executor test; without the matching gate the
    // helper is dead code on Windows and `-D warnings` turns that into a red gate.
    #[cfg(unix)]
    fn generous_quota() -> CopyQuota {
        CopyQuota {
            max_regular_file_bytes: u64::MAX,
            max_bytes: u64::MAX,
            max_entries: usize::MAX,
        }
    }

    #[test]
    fn permits_cargo_test_and_rejects_shells_and_dangerous_subcommands() {
        let root = root();
        let cargo =
            validate_command(&["cargo".into(), "test".into()], root.path(), root.path()).unwrap();
        // `file_stem`, compared case-insensitively: Windows resolution appends a
        // PATHEXT extension whose case follows the PATHEXT entry (`cargo.EXE`),
        // and the basename check must not fail on either count.
        assert!(
            cargo
                .program
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem.eq_ignore_ascii_case("cargo")),
            "rustup-style proxies must keep the invoked cargo basename, got {:?}",
            cargo.program
        );
        assert!(
            validate_command(
                &["bash".into(), "-c".into(), "true".into()],
                root.path(),
                root.path()
            )
            .is_err()
        );
        assert!(
            validate_command(&["cargo".into(), "run".into()], root.path(), root.path()).is_err()
        );
        assert!(
            validate_command(
                &["/usr/bin/cargo".into(), "test".into()],
                root.path(),
                root.path()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_shell_tokens_and_paths_that_escape_the_copy() {
        let root = root();
        for argv in [
            vec!["cargo".into(), "test".into(), "&&".into(), "cargo".into()],
            vec!["cargo".into(), "test".into(), "../../secret".into()],
            vec!["cargo".into(), "test".into(), "/etc/passwd".into()],
            vec!["cargo".into(), "test".into(), "$(id)".into()],
        ] {
            assert!(
                validate_command(&argv, root.path(), root.path()).is_err(),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn safe_path_never_uses_relative_or_project_directories() {
        let root = root();
        let canonical = fs::canonicalize(root.path()).unwrap();
        assert!(
            safe_path(&[root.path()])
                .iter()
                .all(|entry| entry.is_absolute() && !entry.starts_with(&canonical))
        );
    }

    #[test]
    fn safe_path_excludes_both_main_and_task_copy_directories() {
        let temp = tempfile::tempdir().unwrap();
        let main = temp.path().join("main");
        let copy = temp.path().join("copy");
        let trusted = temp.path().join("trusted");
        for directory in [&main, &copy, &trusted] {
            fs::create_dir_all(directory.join("bin")).unwrap();
        }
        let path = std::env::join_paths([main.join("bin"), copy.join("bin"), trusted.join("bin")])
            .unwrap();

        let filtered = safe_path_from(Some(path), &[&main, &copy]);

        assert_eq!(
            filtered,
            vec![fs::canonicalize(trusted.join("bin")).unwrap()]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn executor_records_nonzero_exit_as_evidence() {
        let root = root();
        let command = ValidatedCommand {
            argv: vec!["false".into()],
            program: PathBuf::from("/usr/bin/false"),
            child_path: OsString::from("/usr/bin:/bin"),
        };
        let result = execute_command(
            &command,
            root.path(),
            Duration::from_secs(2),
            generous_quota(),
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, Some(1));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn executor_kills_a_timed_out_process() {
        let root = root();
        let command = ValidatedCommand {
            argv: vec!["sleep".into(), "30".into()],
            program: PathBuf::from("/usr/bin/sleep"),
            child_path: OsString::from("/usr/bin:/bin"),
        };
        let result = execute_command(
            &command,
            root.path(),
            Duration::from_millis(25),
            generous_quota(),
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, None);
        assert!(result.resource_limit.is_none());
        assert!(result.output.contains("exceeded the time limit"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn executor_stops_when_the_task_copy_exceeds_its_quota() {
        let root = root();
        fs::write(root.path().join("large.bin"), [0u8; 16]).unwrap();
        let command = ValidatedCommand {
            argv: vec!["sleep".into(), "30".into()],
            program: PathBuf::from("/usr/bin/sleep"),
            child_path: OsString::from("/usr/bin:/bin"),
        };

        let result = execute_command(
            &command,
            root.path(),
            Duration::from_secs(2),
            CopyQuota {
                max_regular_file_bytes: u64::MAX,
                max_bytes: 8,
                max_entries: 100,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, None);
        assert!(result.resource_limit.is_some());
        assert!(result.output.contains("resource limit"));
    }

    #[tokio::test]
    async fn tail_reader_keeps_the_end_with_a_hard_memory_cap() {
        let data = b"0123456789";
        let (kept, truncated) = read_tail_capped(&data[..], 4).await;
        assert_eq!(kept, b"6789");
        assert!(truncated);
    }
}

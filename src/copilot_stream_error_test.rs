#[cfg(unix)]
use crate::providers::Provider;
#[cfg(unix)]
use crate::providers::local_binary::{CliInvocation, LocalBinaryProvider, StreamDialect};

#[cfg(unix)]
#[tokio::test]
async fn copilot_session_error_surfaces_its_message() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("copilot-error");
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         printf '%s\\n' '{\"type\":\"session.error\",\"data\":{\"message\":\"rate limit exceeded\",\"errorType\":\"model\"}}'\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let provider = LocalBinaryProvider::new(
        "copilot",
        script.to_string_lossy(),
        "copilot",
        temp.path().to_path_buf(),
        CliInvocation {
            dialect: Some(StreamDialect::CopilotJson),
            ..CliInvocation::default()
        },
    )
    .unwrap();

    let error = provider.send(None, "hello").await.unwrap_err().to_string();
    assert!(
        error.contains("rate limit exceeded"),
        "Copilot's session.error message was lost: {error}"
    );
}

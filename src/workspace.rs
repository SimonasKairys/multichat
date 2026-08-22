//! The one place models may write files.
//!
//! `skills.rs` is deliberately read-only: its module doc says so, and that stays
//! true here too — a model that could write a skill file could inject content
//! straight into the system prompt sent to every model for the rest of the session.
//! This module is a *separate* tree from the skills root for exactly that reason.
//! Every write goes through the same traversal-hardening pattern as
//! `SkillsDir::resolve` (reject `..`/absolute/symlink escapes), plus a size cap and a
//! file-count cap so an unbounded model cannot fill the disk. Every successful or
//! failed write is audited by the orchestrator and surfaced in the TUI — the user
//! must be able to see everything a model has written, since this directory is never
//! rendered back into a prompt the way skills are.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Largest file a single write may create or overwrite. Mirrors `skills::MAX_SKILL_BYTES`
/// in spirit — a bound on how much a single filesystem operation can move — but this
/// caps model-authored *output*, not something read back into a prompt, so the number
/// is chosen for "a generous file," not "a generous prompt injection."
const MAX_FILE_BYTES: usize = 256 * 1024;

/// Ceiling on how many files may exist under the workspace root at once. Without this,
/// a model in a long session could write an unbounded number of files — each one
/// individually under `MAX_FILE_BYTES` but unbounded in aggregate. Overwriting an
/// existing file never counts against this cap; it is audited scratch space, not a
/// quota on total bytes ever written.
const MAX_WORKSPACE_FILES: usize = 256;

pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    /// Opens the directory, resolving the root once so later prefix comparisons are
    /// canonical. Mirrors `SkillsDir::new`.
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create workspace directory {}", root.display()))?;
        let root = fs::canonicalize(&root)
            .with_context(|| format!("failed to resolve {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Counts files recursively under `root`. Walked with `file_type()` rather than
    /// `Path::is_file()` so a directory entry that is itself a symlink is counted (or
    /// skipped) by what it *is*, not by following it — the same reasoning `list()` in
    /// `skills.rs` got wrong before `read_description` was hardened to route through
    /// `resolve()`.
    fn count_files(&self) -> usize {
        fn walk(dir: &Path, count: &mut usize) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.filter_map(|e| e.ok()) {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() {
                    walk(&entry.path(), count);
                } else if file_type.is_file() {
                    *count += 1;
                }
            }
        }
        let mut count = 0;
        walk(&self.root, &mut count);
        count
    }

    /// Resolves a model-supplied relative path and writes `content` to it, creating
    /// any parent directories as needed. Returns the resolved absolute path on
    /// success.
    ///
    /// Order matters here, unlike a straight port of `SkillsDir::resolve`:
    /// `fs::canonicalize` fails on a path that doesn't exist yet, but a write target
    /// usually doesn't exist yet, so the *parent* is canonicalised and prefix-checked
    /// instead of the final path itself.
    pub fn write(&self, requested: &str, content: &str) -> Result<PathBuf> {
        if requested.trim().is_empty() {
            return Err(anyhow!("empty workspace path"));
        }

        // Same lexical check as `SkillsDir::resolve`: reject anything that could
        // escape the root before ever touching the filesystem.
        let candidate = Path::new(requested);
        for component in candidate.components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(anyhow!(
                        "workspace path `{requested}` escapes the workspace directory"
                    ));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(anyhow!("workspace path `{requested}` must be relative"));
                }
            }
        }

        if content.len() > MAX_FILE_BYTES {
            return Err(anyhow!(
                "workspace file `{requested}` is {} bytes, over the {MAX_FILE_BYTES}-byte limit",
                content.len()
            ));
        }

        let joined = self.root.join(candidate);

        // Overwriting an existing file never counts against the cap — it is audited
        // scratch space, not a quota on total bytes ever written. Only a write that
        // would create a *new* file is refused once the count is already at the cap.
        if !joined.exists() && self.count_files() >= MAX_WORKSPACE_FILES {
            return Err(anyhow!(
                "workspace already holds {MAX_WORKSPACE_FILES} files, the maximum; \
                 overwrite an existing file instead"
            ));
        }

        let Some(parent) = joined.parent() else {
            return Err(anyhow!("workspace path `{requested}` has no parent"));
        };
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        let resolved_parent = fs::canonicalize(parent)
            .with_context(|| format!("failed to resolve {}", parent.display()))?;
        if !resolved_parent.starts_with(&self.root) {
            return Err(anyhow!(
                "workspace path `{requested}` resolves outside the workspace directory"
            ));
        }

        let Some(file_name) = joined.file_name() else {
            return Err(anyhow!("workspace path `{requested}` has no file name"));
        };
        let resolved = resolved_parent.join(file_name);

        // A symlink at the final path — even one whose parent is legitimately inside
        // the root — could redirect the write outside it. `symlink_metadata` never
        // follows the link, unlike `metadata`, so this actually inspects the link
        // itself rather than its target.
        if let Ok(meta) = fs::symlink_metadata(&resolved)
            && meta.file_type().is_symlink()
        {
            return Err(anyhow!(
                "workspace path `{requested}` is a symlink, refusing to write through it"
            ));
        }

        fs::write(&resolved, content)
            .with_context(|| format!("failed to write workspace file `{requested}`"))?;
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> (tempfile::TempDir, Workspace) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        let w = Workspace::new(root).unwrap();
        (dir, w)
    }

    #[test]
    fn a_write_lands_under_the_workspace_root() {
        let (_guard, w) = workspace();
        let path = w.write("notes.txt", "hello").unwrap();
        assert!(path.starts_with(w.root()));
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
    }

    #[test]
    fn a_subdirectory_is_created_automatically() {
        let (_guard, w) = workspace();
        let path = w.write("nested/deep/notes.txt", "hi").unwrap();
        assert!(path.starts_with(w.root()));
        assert_eq!(fs::read_to_string(&path).unwrap(), "hi");
    }

    #[test]
    fn a_traversal_attempt_surfaces_as_an_error_not_a_crash() {
        let (guard, w) = workspace();
        let err = w.write("../escape.txt", "x").unwrap_err().to_string();
        assert!(err.contains("escapes"), "unexpected error: {err}");
        assert!(!guard.path().join("escape.txt").exists());

        let absolute = if cfg!(windows) {
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        } else {
            "/etc/passwd"
        };
        let err = w.write(absolute, "x").unwrap_err().to_string();
        assert!(err.contains("relative"), "unexpected error: {err}");
    }

    #[test]
    fn an_oversized_write_is_refused() {
        let (_guard, w) = workspace();
        let big = "x".repeat(MAX_FILE_BYTES + 1);
        let err = w.write("big.txt", &big).unwrap_err().to_string();
        assert!(err.contains("limit"), "unexpected error: {err}");
        assert!(!w.root().join("big.txt").exists());
    }

    // Unix-only: `std::os::unix::fs::symlink` has no direct Windows equivalent — see
    // the same gating on the sibling tests in `skills.rs`.
    #[cfg(unix)]
    #[test]
    fn a_symlink_target_is_refused() {
        let (guard, w) = workspace();
        let outside = guard.path().join("outside.txt");
        fs::write(&outside, "original").unwrap();
        std::os::unix::fs::symlink(&outside, w.root().join("link.txt")).unwrap();

        let err = w.write("link.txt", "clobbered").unwrap_err().to_string();
        assert!(err.contains("symlink"), "unexpected error: {err}");
        // The link's target must be untouched — the whole point of the refusal.
        assert_eq!(fs::read_to_string(&outside).unwrap(), "original");
    }

    #[test]
    fn overwriting_an_existing_file_is_allowed() {
        let (_guard, w) = workspace();
        w.write("notes.txt", "first").unwrap();
        let path = w.write("notes.txt", "second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
    }

    #[test]
    fn the_file_count_cap_refuses_new_files_but_allows_overwrites() {
        let (_guard, w) = workspace();
        for i in 0..MAX_WORKSPACE_FILES {
            w.write(&format!("f{i}.txt"), "x").unwrap();
        }
        // Overwriting an already-existing file at the cap must still succeed.
        w.write("f0.txt", "overwritten").unwrap();
        assert_eq!(
            fs::read_to_string(w.root().join("f0.txt")).unwrap(),
            "overwritten"
        );
        // But a brand-new file must be refused once the cap is reached.
        let err = w.write("new.txt", "x").unwrap_err().to_string();
        assert!(err.contains("maximum"), "unexpected error: {err}");
        assert!(!w.root().join("new.txt").exists());
    }
}

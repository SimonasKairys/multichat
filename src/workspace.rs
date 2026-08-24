//! The project folder: the one part of the filesystem models may read, list, and
//! write through simon's own protocol.
//!
//! This used to be a private scratch tree under simon's own data directory; it is now
//! the user's project — whatever folder `simon` was started in, or `--project <dir>`
//! (see `main::resolve_project_root`). That change is why every entry point here still
//! takes a model-supplied *relative* path and never trusts it at face value: the
//! threat model is unchanged even though the root moved. `skills.rs` stays read-only
//! for a different reason (a model that could write a skill file could inject content
//! straight into the system prompt sent to every model for the rest of the session),
//! and remains a *separate* tree from this one.
//!
//! Every access goes through the same traversal-hardening pattern as
//! `SkillsDir::resolve` (reject `..`/absolute/symlink escapes), plus a size cap on
//! reads and writes so a single operation cannot move an unbounded amount of data.
//! There is deliberately no cap on how many files may exist under the root any more —
//! see `write`'s doc comment for why. Every successful or failed access is audited by
//! the orchestrator and surfaced in the TUI — the user must be able to see everything
//! a model has read, listed, or written in their project.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Largest file a single read or write may move. Mirrors `skills::MAX_SKILL_BYTES` in
/// spirit — a bound on how much a single filesystem operation can move — but this
/// caps arbitrary project content, not something curated for a prompt, so the number
/// is chosen for "a generous file," not "a generous prompt injection."
const MAX_FILE_BYTES: usize = 256 * 1024;

/// Ceiling on how many entries a single `list` call returns. A real project directory
/// can hold far more than that; this bounds one filesystem operation's result the same
/// way `MAX_FILE_BYTES` bounds one read or write, not a claim about the directory
/// itself. Truncation is reported, not silent — see `list`.
const MAX_LIST_ENTRIES: usize = 500;

pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    /// Opens `root` — the project folder — resolving it once so later prefix
    /// comparisons are canonical.
    ///
    /// Deliberately does NOT create `root`: the old scratch-space workspace lived
    /// under simon's own data directory, where silently creating it on first use was
    /// harmless and convenient. `root` here is the user's own project folder; silently
    /// creating a directory that doesn't exist there would be surprising, not helpful.
    /// The caller (`main::resolve_project_root`) is expected to have already validated
    /// that `root` exists and is a directory before this is ever called, but this
    /// checks again rather than trusting that — `Workspace::new` is a public
    /// constructor, not something only that one caller can reach.
    pub fn new(root: PathBuf) -> Result<Self> {
        let meta = fs::metadata(&root)
            .with_context(|| format!("project directory {} does not exist", root.display()))?;
        if !meta.is_dir() {
            return Err(anyhow!(
                "project path {} is not a directory",
                root.display()
            ));
        }
        let root = fs::canonicalize(&root)
            .with_context(|| format!("failed to resolve {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Lexical component check shared by every entry point that accepts a
    /// model-supplied relative path: reject empty, `..`, absolute, and drive-prefixed
    /// paths before ever touching the filesystem. Mirrors `SkillsDir::resolve`'s
    /// equivalent loop; `write` below has its own variant of this because it must
    /// tolerate a final path that doesn't exist yet (see that method's doc comment).
    fn reject_traversal(requested: &str) -> Result<()> {
        if requested.trim().is_empty() {
            return Err(anyhow!("empty project path"));
        }
        for component in Path::new(requested).components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(anyhow!(
                        "project path `{requested}` escapes the project folder"
                    ));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(anyhow!("project path `{requested}` must be relative"));
                }
            }
        }
        Ok(())
    }

    /// Resolves a model-supplied relative path that must already exist — the shared
    /// core of `read` and (for a non-root target) `list`. Unlike `write`'s resolution,
    /// this can canonicalize the full path directly rather than working through the
    /// parent, because both callers require the target to already be there.
    fn resolve(&self, requested: &str) -> Result<PathBuf> {
        Self::reject_traversal(requested)?;
        let joined = self.root.join(requested);
        let resolved = fs::canonicalize(&joined)
            .with_context(|| format!("project path `{requested}` not found"))?;
        // Second check: canonicalize follows symlinks, so a link inside the root that
        // points outside it is only caught here, same as `SkillsDir::resolve`.
        if !resolved.starts_with(&self.root) {
            return Err(anyhow!(
                "project path `{requested}` resolves outside the project folder"
            ));
        }
        Ok(resolved)
    }

    /// Reads a project file. `requested` is untrusted model output — the same threat
    /// `SkillsDir::read` was hardened against — so it goes through the same
    /// traversal/symlink-escape checks via `resolve`.
    pub fn read(&self, requested: &str) -> Result<String> {
        let path = self.resolve(requested)?;
        let meta = fs::metadata(&path)
            .with_context(|| format!("failed to read project file `{requested}`"))?;
        if !meta.is_file() {
            return Err(anyhow!("project path `{requested}` is not a file"));
        }
        if meta.len() > MAX_FILE_BYTES as u64 {
            return Err(anyhow!(
                "project file `{requested}` is {} bytes, over the {MAX_FILE_BYTES}-byte limit",
                meta.len()
            ));
        }
        fs::read_to_string(&path)
            .with_context(|| format!("failed to read project file `{requested}`"))
    }

    /// Metadata for an existing project file, so a caller can tell what a write would
    /// replace before making it. Goes through the same `resolve` hardening as `read`,
    /// so a model-supplied path can no more stat something outside the project than it
    /// could read it. A path that does not exist yet is an error, which callers read
    /// as "this write creates a new file".
    pub fn metadata(&self, requested: &str) -> Result<fs::Metadata> {
        let path = self.resolve(requested)?;
        fs::metadata(&path).with_context(|| format!("failed to stat project file `{requested}`"))
    }

    /// Lists one directory's immediate entries — never recursively, so a model must
    /// spend a further `list` call to descend into a subdirectory it saw. `requested`
    /// empty (or `.`) means the project root itself; anything else goes through the
    /// same traversal/symlink-escape checks as `read`.
    ///
    /// Entries are sorted, directories are distinguished with a trailing `/`, and the
    /// result is capped at `MAX_LIST_ENTRIES` with the truncation reported as the
    /// final entry rather than silently cutting the listing short.
    pub fn list(&self, requested: &str) -> Result<Vec<String>> {
        let trimmed = requested.trim();
        let dir = if trimmed.is_empty() || trimmed == "." {
            self.root.clone()
        } else {
            self.resolve(requested)?
        };

        let meta = fs::metadata(&dir)
            .with_context(|| format!("failed to list project directory `{requested}`"))?;
        if !meta.is_dir() {
            return Err(anyhow!("project path `{requested}` is not a directory"));
        }

        let mut entries: Vec<String> = fs::read_dir(&dir)
            .with_context(|| format!("failed to list project directory `{requested}`"))?
            .filter_map(|e| e.ok())
            .filter_map(|entry| {
                // `file_type()` reports what the directory entry itself is, without
                // following a symlink — matters only for the trailing-`/` distinction
                // here, not for escaping the root (this never leaves `dir`, which is
                // already confirmed to be inside `self.root`).
                let file_type = entry.file_type().ok()?;
                let name = entry.file_name().into_string().ok()?;
                Some(if file_type.is_dir() {
                    format!("{name}/")
                } else {
                    name
                })
            })
            .collect();
        entries.sort();

        let total = entries.len();
        if total > MAX_LIST_ENTRIES {
            entries.truncate(MAX_LIST_ENTRIES);
            entries.push(format!(
                "... {} more entries not shown (truncated at {MAX_LIST_ENTRIES})",
                total - MAX_LIST_ENTRIES
            ));
        }
        Ok(entries)
    }

    /// The checks a write must pass that need no filesystem changes to evaluate:
    /// traversal, size, and the `.git` refusal.
    ///
    /// Split out of `write` so a caller can find out that a write is doomed *before*
    /// acting on it — specifically, before asking the user to approve it. Prompting
    /// for a write that would be refused anyway trains the user that their answer does
    /// not matter, and makes a refusal look like the consequence of their approval.
    ///
    /// Deliberately not the whole of `write`'s validation: the symlink and
    /// canonical-prefix checks require creating the parent directory first, and a
    /// check with side effects is not a check. Those stay in `write`, which is still
    /// the only thing standing between a path and the disk — this is an early-out, not
    /// a replacement.
    pub fn precheck(&self, requested: &str, content_len: usize) -> Result<()> {
        Self::reject_traversal(requested)?;
        if content_len > MAX_FILE_BYTES {
            return Err(anyhow!(
                "project file `{requested}` is {content_len} bytes, over the {MAX_FILE_BYTES}-byte limit"
            ));
        }
        Self::reject_git_writes(requested, Path::new(requested))
    }

    /// Refuses any write whose path passes through a `.git` component.
    fn reject_git_writes(requested: &str, candidate: &Path) -> Result<()> {
        if candidate
            .components()
            .any(|c| matches!(c, Component::Normal(name) if name == ".git"))
        {
            return Err(anyhow!(
                "project path `{requested}` would write into `.git`, which is refused"
            ));
        }
        Ok(())
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
        Self::reject_traversal(requested)?;
        let candidate = Path::new(requested);

        if content.len() > MAX_FILE_BYTES {
            return Err(anyhow!(
                "project file `{requested}` is {} bytes, over the {MAX_FILE_BYTES}-byte limit",
                content.len()
            ));
        }

        let joined = self.root.join(candidate);

        let Some(parent) = joined.parent() else {
            return Err(anyhow!("project path `{requested}` has no parent"));
        };

        // `create_dir_all` below will happily create directories through a symlink
        // that escapes the root — e.g. a link `out -> /tmp` committed inside the
        // project, written to as `out/newdir/f.txt`. The write itself is still
        // caught by the prefix check a few lines down, but by the time that check
        // runs, `create_dir_all` has already created `/tmp/newdir` on disk: a
        // directory outside the project the user never approved, even though the
        // file content never lands there. So before creating anything, walk up
        // from `parent` to the deepest ancestor that already exists — the first
        // directory `create_dir_all` would actually touch — and canonicalize
        // *that* (canonicalize requires existence, the same reason `write` checks
        // `parent` rather than `joined` in the first place). If a symlink anywhere
        // on the way redirects that ancestor outside `self.root`, refuse here,
        // before `create_dir_all` ever runs, instead of after.
        let mut anchor = parent;
        while !anchor.exists() {
            let Some(next) = anchor.parent() else {
                // Unreachable in practice: `self.root` itself always exists (`new`
                // checked that), and `parent` is `self.root` joined with more
                // components, so this walk reaches `self.root` and stops before
                // running out of ancestors. A hard error rather than an `unwrap`
                // so a future change to that invariant fails loudly instead of
                // panicking.
                return Err(anyhow!(
                    "project path `{requested}` has no existing ancestor"
                ));
            };
            anchor = next;
        }
        let resolved_anchor = fs::canonicalize(anchor)
            .with_context(|| format!("failed to resolve {}", anchor.display()))?;
        if !resolved_anchor.starts_with(&self.root) {
            return Err(anyhow!(
                "project path `{requested}` resolves outside the project folder"
            ));
        }

        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        let resolved_parent = fs::canonicalize(parent)
            .with_context(|| format!("failed to resolve {}", parent.display()))?;
        if !resolved_parent.starts_with(&self.root) {
            return Err(anyhow!(
                "project path `{requested}` resolves outside the project folder"
            ));
        }

        let Some(file_name) = joined.file_name() else {
            return Err(anyhow!("project path `{requested}` has no file name"));
        };
        let resolved = resolved_parent.join(file_name);

        // A write anywhere inside a `.git` directory can corrupt the repository in
        // ways the user cannot easily undo (rewritten refs, a mangled index, objects
        // overwritten with model-authored garbage), and no legitimate use of this
        // protocol needs one — a model that wants to interact with git has the shell
        // access of a delegated CLI provider for that, not this write path. Checked
        // against the resolved absolute path, not just the lexical `requested`
        // string, so a symlink whose target lands inside `.git` is caught too, not
        // just a request that spells `.git` out directly. Reading `.git` is not
        // special-cased — only a write can corrupt it.
        // `precheck` already ran this against the lexical path, as an early-out so a
        // doomed write is never put to the user for approval. This re-runs it against
        // the RESOLVED path, which is the load-bearing one: it is what catches a
        // symlink whose target lands inside `.git`.
        Self::reject_git_writes(requested, &resolved)?;

        // A symlink at the final path — even one whose parent is legitimately inside
        // the root — could redirect the write outside it. `symlink_metadata` never
        // follows the link, unlike `metadata`, so this actually inspects the link
        // itself rather than its target.
        if let Ok(meta) = fs::symlink_metadata(&resolved)
            && meta.file_type().is_symlink()
        {
            return Err(anyhow!(
                "project path `{requested}` is a symlink, refusing to write through it"
            ));
        }

        fs::write(&resolved, content)
            .with_context(|| format!("failed to write project file `{requested}`"))?;
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The project root is created here rather than by `Workspace::new`, which
    /// deliberately refuses a root that doesn't exist — see its doc comment. `dir` is
    /// returned so callers can also reach the parent, one level *above* the project,
    /// which is what the escape tests need.
    fn workspace() -> (tempfile::TempDir, Workspace) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        fs::create_dir_all(&root).unwrap();
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

    // Unix-only: same reasoning as `a_symlink_target_is_refused` above — this is the
    // directory-escape counterpart, guarding the ancestor walk added ahead of
    // `create_dir_all` in `write`.
    #[cfg(unix)]
    #[test]
    fn a_write_through_a_symlinked_directory_creates_nothing_outside_the_root() {
        let (guard, w) = workspace();
        let outside_dir = guard.path().join("outside");
        fs::create_dir_all(&outside_dir).unwrap();
        std::os::unix::fs::symlink(&outside_dir, w.root().join("link")).unwrap();

        let err = w
            .write("link/newdir/f.txt", "clobbered")
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside"), "unexpected error: {err}");
        // The whole point: `create_dir_all` must never have run against the
        // resolved (outside-the-root) path, so `outside/newdir` must not exist.
        assert!(!outside_dir.join("newdir").exists());
        assert!(!outside_dir.join("newdir").join("f.txt").exists());
    }

    #[test]
    fn overwriting_an_existing_file_is_allowed() {
        let (_guard, w) = workspace();
        w.write("notes.txt", "first").unwrap();
        let path = w.write("notes.txt", "second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
    }
}

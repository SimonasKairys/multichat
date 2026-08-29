//! Read-only shared skills directory.
//!
//! Models may reference files here by name. Every lookup is canonicalised and checked
//! to still live under the skills root, so a crafted name (`../../.ssh/id_rsa`, an
//! absolute path, or a symlink pointing outside) cannot read arbitrary files.

use anyhow::{Context, Result, anyhow};
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

/// Largest skill file that will be loaded into a prompt.
const MAX_SKILL_BYTES: u64 = 256 * 1024;

/// Ceiling on how much of a skill file gets read while hunting for frontmatter.
/// `list_with_descriptions` runs on every `system_prompt()` call — which is every
/// prompt AND every delegation, per the orchestrator — so it must not read whole
/// files (some may be up to `MAX_SKILL_BYTES`, i.e. 256KB, each). Frontmatter is a
/// handful of lines at the very top of the file, so 1KB is generous headroom and
/// keeps this cheap no matter how many skills or how large the files get.
const FRONTMATTER_HEAD_BYTES: usize = 1024;

#[cfg(unix)]
fn regular_file_link_count(meta: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;

    meta.is_file().then(|| meta.nlink())
}

#[cfg(windows)]
fn regular_file_link_count(meta: &fs::Metadata) -> Option<u64> {
    use std::os::windows::fs::MetadataExt as _;

    meta.is_file().then(|| meta.number_of_links())
}

#[cfg(not(any(unix, windows)))]
fn regular_file_link_count(meta: &fs::Metadata) -> Option<u64> {
    meta.is_file().then_some(2)
}

fn reject_multi_linked_regular_file(meta: &fs::Metadata, requested: &str) -> Result<()> {
    if let Some(count) = regular_file_link_count(meta)
        && count > 1
    {
        return Err(anyhow!(
            "skill `{requested}` has {count} hard links, refusing to read a multi-linked file"
        ));
    }
    Ok(())
}

pub struct SkillsDir {
    root: PathBuf,
}

/// A skill's name plus its optional one-line description, for rendering into the
/// system prompt so a model has enough to decide whether the skill is relevant
/// before spending an `ACTION: read_skill(...)` round trip on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillMeta {
    pub name: String,
    pub description: Option<String>,
}

/// Pulls a single-line `description:` value out of optional YAML-style frontmatter:
/// ```text
/// ---
/// name: whatever
/// description: One line saying when this skill applies.
/// ---
/// ```
/// Hand-rolled rather than pulling in a YAML crate — the format supported here is
/// deliberately narrow (one key, one line), so a real parser would be overkill.
/// A file with no frontmatter, or frontmatter with no `description:` line, or
/// frontmatter that never closes within the head we read, all just yield `None` —
/// a skill is still valid without a description; this is metadata, not validation.
fn parse_description(head: &str) -> Option<String> {
    let mut lines = head.lines();
    if lines.next()?.trim() != "---" {
        return None;
    }
    let mut description = None;
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "---" {
            // Closing fence reached.
            return description;
        }
        if let Some(value) = trimmed.strip_prefix("description:") {
            let value = value.trim();
            let unquoted = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value)
                .trim();
            if !unquoted.is_empty() && description.is_none() {
                description = Some(unquoted.to_string());
            }
        }
    }
    // Ran off the end of the head (or the file) without a closing fence. Since we
    // only ever read a bounded head, a real closing fence past that point is
    // indistinguishable from "absent" here — either way there is nothing safe to
    // report, so treat it the same as no frontmatter.
    None
}

impl SkillsDir {
    /// Opens the directory, resolving the root once so later comparisons are canonical.
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create skills directory {}", root.display()))?;
        let root = fs::canonicalize(&root)
            .with_context(|| format!("failed to resolve {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves a model-supplied name to a path inside the skills root.
    ///
    /// Rejects absolute paths, drive prefixes, and any `..` component before touching
    /// the filesystem, then canonicalises and re-checks the prefix to catch symlinks
    /// that escape the root.
    pub fn resolve(&self, requested: &str) -> Result<PathBuf> {
        if requested.trim().is_empty() {
            return Err(anyhow!("empty skill name"));
        }

        let candidate = Path::new(requested);
        for component in candidate.components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(anyhow!(
                        "skill path `{requested}` escapes the skills directory"
                    ));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(anyhow!("skill path `{requested}` must be relative"));
                }
            }
        }

        let joined = self.root.join(candidate);
        let resolved =
            fs::canonicalize(&joined).with_context(|| format!("skill `{requested}` not found"))?;

        // Second check: canonicalize follows symlinks, so a link inside the root that
        // points outside is only caught here.
        if !resolved.starts_with(&self.root) {
            return Err(anyhow!(
                "skill path `{requested}` resolves outside the skills directory"
            ));
        }
        Ok(resolved)
    }

    /// Reads a skill file. Read-only by design — there is no write counterpart.
    pub fn read(&self, requested: &str) -> Result<String> {
        let path = self.resolve(requested)?;
        let meta = fs::metadata(&path)?;
        if !meta.is_file() {
            return Err(anyhow!("skill `{requested}` is not a file"));
        }
        reject_multi_linked_regular_file(&meta, requested)?;
        if meta.len() > MAX_SKILL_BYTES {
            return Err(anyhow!(
                "skill `{requested}` is {} bytes, over the {MAX_SKILL_BYTES}-byte limit",
                meta.len()
            ));
        }
        fs::read_to_string(&path).with_context(|| format!("failed to read skill `{requested}`"))
    }

    /// Lists available skill file names, sorted.
    fn list(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = fs::read_dir(&self.root)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        Ok(names)
    }

    /// Lists skills with their optional frontmatter description, sorted by name.
    ///
    /// A model sees only bare filenames without this — no basis to decide whether a
    /// skill is relevant before spending a round trip reading it. This is what makes
    /// the listing useful for that decision.
    ///
    /// One malformed or unreadable file must not take down the whole listing: a
    /// per-file read failure just yields a `None` description for that file, same as
    /// a file with no frontmatter at all.
    pub fn list_with_descriptions(&self) -> Result<Vec<SkillMeta>> {
        // `list()` already returns names sorted, so the result here is sorted too.
        let metas = self
            .list()?
            .into_iter()
            .map(|name| {
                let description = self.read_description(&name);
                SkillMeta { name, description }
            })
            .collect();
        Ok(metas)
    }

    /// Reads only a bounded head of the file (see `FRONTMATTER_HEAD_BYTES`) and
    /// looks for a description in it. Never errors — any failure (escapes the root,
    /// can't open, can't decode) just means "no description," matching how a file
    /// with no frontmatter is treated.
    fn read_description(&self, name: &str) -> Option<String> {
        // Must go through `resolve()`, not a bare `self.root.join(name)`. `list()`
        // filters entries with `Path::is_file()`, which follows symlinks, so a
        // symlink inside the root pointing outside it (exactly the threat this
        // module's doc comment names) reaches this function too. Without `resolve()`
        // here, that symlink's target would be read and its frontmatter rendered
        // straight into the system prompt sent to every model, including remote
        // ones — even though `read()` already refuses to serve the same file. Both
        // paths must agree on what's inside the root.
        let path = self.resolve(name).ok()?;
        let meta = fs::metadata(&path).ok()?;
        if !meta.is_file() || reject_multi_linked_regular_file(&meta, name).is_err() {
            return None;
        }
        let file = File::open(path).ok()?;
        // `Read::read` is allowed to return a short read even when more data is
        // available (a single syscall hitting a pipe buffer boundary, for example),
        // so one `read` call is not a reliable way to get "the first N bytes" — it
        // could silently return fewer and miss a description that's within the
        // bound. `Read::take(..).read_to_end(..)` keeps reading until either the
        // bound or EOF, so this stays a genuinely bounded read without that gap.
        let mut buf = Vec::new();
        file.take(FRONTMATTER_HEAD_BYTES as u64)
            .read_to_end(&mut buf)
            .ok()?;
        // Lossy decode: the head may cut a multi-byte UTF-8 character in half at the
        // boundary, and this is metadata extraction, not a full read — a mangled
        // trailing character must not turn into a panic.
        let head = String::from_utf8_lossy(&buf);
        parse_description(&head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skills() -> (tempfile::TempDir, SkillsDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("skills");
        let s = SkillsDir::new(root).unwrap();
        (dir, s)
    }

    #[test]
    fn reads_a_skill_inside_the_root() {
        let (_guard, s) = skills();
        fs::write(s.root().join("style.md"), "be terse").unwrap();
        assert_eq!(s.read("style.md").unwrap(), "be terse");
        assert_eq!(s.list().unwrap(), vec!["style.md".to_string()]);
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        let (guard, s) = skills();
        fs::write(guard.path().join("secret.txt"), "private").unwrap();
        let err = s.read("../secret.txt").unwrap_err().to_string();
        assert!(err.contains("escapes"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_deeply_nested_traversal() {
        let (_guard, s) = skills();
        assert!(s.read("a/../../../../etc/passwd").is_err());
    }

    #[test]
    fn rejects_absolute_paths() {
        let (_guard, s) = skills();
        let absolute = if cfg!(windows) {
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        } else {
            "/etc/passwd"
        };
        let err = s.read(absolute).unwrap_err().to_string();
        assert!(err.contains("relative"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_empty_name() {
        let (_guard, s) = skills();
        assert!(s.read("   ").is_err());
    }

    #[test]
    fn missing_skill_is_an_error_not_a_panic() {
        let (_guard, s) = skills();
        assert!(s.read("nope.md").is_err());
    }

    #[test]
    fn oversized_skills_are_refused() {
        let (_guard, s) = skills();
        let big = vec![b'x'; (MAX_SKILL_BYTES + 1) as usize];
        fs::write(s.root().join("big.md"), big).unwrap();
        let err = s.read("big.md").unwrap_err().to_string();
        assert!(err.contains("limit"), "unexpected error: {err}");
    }

    #[test]
    fn test_reproduction_empty_quoted_description_yields_no_description() {
        let (_guard, s) = skills();
        fs::write(
            s.root().join("empty_double.md"),
            "---\ndescription: \"\"\n---\nbody\n",
        )
        .unwrap();
        fs::write(
            s.root().join("empty_single.md"),
            "---\ndescription: ''\n---\nbody\n",
        )
        .unwrap();
        fs::write(
            s.root().join("quoted.md"),
            "---\ndescription: \"Quoted skill description\"\n---\nbody\n",
        )
        .unwrap();
        let metas = s.list_with_descriptions().unwrap();
        let empty_double = metas.iter().find(|m| m.name == "empty_double.md").unwrap();
        assert_eq!(
            empty_double.description, None,
            "empty double-quoted description must be None, not Some(\"\")"
        );
        let empty_single = metas.iter().find(|m| m.name == "empty_single.md").unwrap();
        assert_eq!(
            empty_single.description, None,
            "empty single-quoted description must be None, not Some(\"\")"
        );
        let quoted = metas.iter().find(|m| m.name == "quoted.md").unwrap();
        assert_eq!(
            quoted.description.as_deref(),
            Some("Quoted skill description"),
            "quotes should be stripped from skill description"
        );
    }

    #[test]
    fn a_skill_with_frontmatter_reports_its_description() {
        let (_guard, s) = skills();
        fs::write(
            s.root().join("notes.md"),
            "---\nname: notes\ndescription: One line saying when this applies.\n---\nbody\n",
        )
        .unwrap();
        let metas = s.list_with_descriptions().unwrap();
        assert_eq!(
            metas,
            vec![SkillMeta {
                name: "notes.md".to_string(),
                description: Some("One line saying when this applies.".to_string()),
            }]
        );
    }

    #[test]
    fn a_skill_with_no_frontmatter_is_still_valid_with_no_description() {
        let (_guard, s) = skills();
        fs::write(
            s.root().join("plain.md"),
            "just a body, no frontmatter at all\n",
        )
        .unwrap();
        let metas = s.list_with_descriptions().unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].name, "plain.md");
        assert_eq!(metas[0].description, None);
    }

    #[test]
    fn frontmatter_with_no_description_key_yields_no_description() {
        let (_guard, s) = skills();
        fs::write(s.root().join("bare.md"), "---\nname: bare\n---\nbody\n").unwrap();
        let metas = s.list_with_descriptions().unwrap();
        assert_eq!(metas[0].description, None);
    }

    #[test]
    fn frontmatter_that_never_closes_within_the_head_yields_no_description() {
        // A stray leading "---" with no closing fence (and no description line)
        // anywhere in the bounded head must not be mistaken for a valid block or
        // cause an error — it just means no description was found.
        let (_guard, s) = skills();
        fs::write(
            s.root().join("unclosed.md"),
            "---\nname: unclosed\nno closing fence here\n",
        )
        .unwrap();
        let metas = s.list_with_descriptions().unwrap();
        assert_eq!(metas[0].description, None);
    }

    #[test]
    fn one_malformed_skill_file_does_not_break_the_whole_listing() {
        let (_guard, s) = skills();
        fs::write(s.root().join("bad.md"), "---\ndescription:\n---\nbody\n").unwrap();
        fs::write(
            s.root().join("good.md"),
            "---\ndescription: this one is fine\n---\nbody\n",
        )
        .unwrap();
        let metas = s.list_with_descriptions().unwrap();
        assert_eq!(metas.len(), 2);
        let good = metas.iter().find(|m| m.name == "good.md").unwrap();
        assert_eq!(good.description.as_deref(), Some("this one is fine"));
        let bad = metas.iter().find(|m| m.name == "bad.md").unwrap();
        assert_eq!(bad.description, None);
    }

    #[test]
    fn only_a_bounded_head_is_read_looking_for_frontmatter() {
        // A description far beyond FRONTMATTER_HEAD_BYTES must not be found — proves
        // the read is actually bounded, not just documented as such. This matters
        // because `system_prompt()` calls into this on every prompt and every
        // delegation; reading whole (up to 256KB) files that often would be wasteful.
        let (_guard, s) = skills();
        let padding = "x".repeat(FRONTMATTER_HEAD_BYTES + 100);
        let content = format!("---\n{padding}\ndescription: too far in to be found\n---\n");
        fs::write(s.root().join("huge.md"), &content).unwrap();
        let metas = s.list_with_descriptions().unwrap();
        assert_eq!(metas[0].description, None);
    }

    #[test]
    fn parse_description_ignores_other_frontmatter_keys() {
        // Only `description:` needs to be understood; any other key present before it
        // must be skipped over, not misparsed as the description.
        let text = "---\nname: whatever\nversion: 2\ndescription: the real one\n---\n";
        assert_eq!(parse_description(text), Some("the real one".to_string()));
    }

    #[test]
    fn parse_description_requires_the_opening_fence_on_the_first_line() {
        // Content that merely contains "description:" somewhere, without starting
        // with a "---" frontmatter fence, must not be picked up — that would treat
        // arbitrary skill body text as metadata.
        assert_eq!(
            parse_description("description: not frontmatter\n---\n"),
            None
        );
    }

    // Unix-only: `std::os::unix::fs::symlink` has no direct Windows equivalent
    // (Windows symlinks need elevated privileges / a different API), and this is
    // the only thing under test here — see the `#[cfg(unix)]` tests in
    // `orchestrator.rs` and `providers::local_binary.rs` for the same pattern.
    #[cfg(unix)]
    #[test]
    fn a_symlink_escaping_the_root_leaks_no_description_and_still_fails_to_read() {
        // Regression guard for the bug this fix closes: `list()` filters with
        // `Path::is_file()`, which follows symlinks, so a symlink inside the root
        // pointing outside it was still listed. `read_description` used to join
        // straight onto `self.root` instead of calling `resolve()`, so it happily
        // opened the escaping target and rendered its frontmatter description into
        // the system prompt sent to every model — even though `read()` on the very
        // same name already refused it. The two must agree: `description` here
        // must be `None`, and `read()` must still be `Err`.
        let (guard, s) = skills();
        let outside = guard.path().join("secret.md");
        fs::write(
            &outside,
            "---\nname: secret\ndescription: LEAKED_FROM_OUTSIDE\n---\nbody\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, s.root().join("escape.md")).unwrap();

        let metas = s.list_with_descriptions().unwrap();
        let escape = metas.iter().find(|m| m.name == "escape.md").unwrap();
        assert_eq!(escape.description, None);
        assert!(s.read("escape.md").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_another_file_inside_the_root_still_resolves_its_description() {
        // The guard must reject symlinks that escape the root, not symlinks in
        // general — an in-root symlink is not the threat named in this module's
        // doc comment, so its description should resolve normally.
        let (_guard, s) = skills();
        fs::write(
            s.root().join("real.md"),
            "---\nname: real\ndescription: a real in-root skill\n---\nbody\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(s.root().join("real.md"), s.root().join("alias.md")).unwrap();

        let metas = s.list_with_descriptions().unwrap();
        let alias = metas.iter().find(|m| m.name == "alias.md").unwrap();
        assert_eq!(alias.description.as_deref(), Some("a real in-root skill"));
    }

    #[test]
    fn a_hard_link_escaping_the_root_leaks_no_description_and_fails_to_read() {
        let (guard, s) = skills();
        let outside = guard.path().join("secret.md");
        fs::write(
            &outside,
            "---\nname: secret\ndescription: LEAKED_FROM_OUTSIDE\n---\nbody\n",
        )
        .unwrap();
        fs::hard_link(&outside, s.root().join("escape.md")).unwrap();

        let metas = s.list_with_descriptions().unwrap();
        let escape = metas.iter().find(|m| m.name == "escape.md").unwrap();
        assert_eq!(escape.description, None);

        let err = s.read("escape.md").unwrap_err().to_string();
        assert!(err.contains("hard links"), "unexpected error: {err}");
    }

    #[test]
    fn unclosed_frontmatter_containing_description_yields_no_description() {
        let (_guard, s) = skills();
        fs::write(
            s.root().join("unclosed_with_desc.md"),
            "---\nname: unclosed\ndescription: should not be leaked without closing fence\nbody without fence\n",
        )
        .unwrap();
        let metas = s.list_with_descriptions().unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].name, "unclosed_with_desc.md");
        assert_eq!(
            metas[0].description, None,
            "unclosed frontmatter must not leak description"
        );
    }
}

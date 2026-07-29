//! Read-only shared skills directory.
//!
//! Models may reference files here by name. Every lookup is canonicalised and checked
//! to still live under the skills root, so a crafted name (`../../.ssh/id_rsa`, an
//! absolute path, or a symlink pointing outside) cannot read arbitrary files.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Largest skill file that will be loaded into a prompt.
const MAX_SKILL_BYTES: u64 = 256 * 1024;

pub struct SkillsDir {
    root: PathBuf,
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
        if meta.len() > MAX_SKILL_BYTES {
            return Err(anyhow!(
                "skill `{requested}` is {} bytes, over the {MAX_SKILL_BYTES}-byte limit",
                meta.len()
            ));
        }
        fs::read_to_string(&path).with_context(|| format!("failed to read skill `{requested}`"))
    }

    /// Lists available skill file names, sorted.
    pub fn list(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = fs::read_dir(&self.root)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        Ok(names)
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
}

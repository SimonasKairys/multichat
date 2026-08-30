use anyhow::{Context, Result, anyhow, bail};
use blake2::{Blake2s256, Digest};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationLimits {
    pub max_regular_file_bytes: u64,
    pub max_copied_bytes: u64,
    pub max_entries: usize,
    pub max_total_live_bytes: u64,
    pub max_excluded_paths: usize,
}

impl Default for IsolationLimits {
    fn default() -> Self {
        Self {
            max_regular_file_bytes: 16 * 1024 * 1024,
            max_copied_bytes: 256 * 1024 * 1024,
            max_entries: 50_000,
            max_total_live_bytes: 512 * 1024 * 1024,
            max_excluded_paths: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSummary {
    pub root: PathBuf,
    pub files: usize,
    pub bytes: u64,
    pub excluded_total: usize,
    pub excluded: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyPlan {
    pub writes: Vec<crate::swarm::FileWrite>,
    pub deleted: Vec<String>,
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyQuota {
    pub max_regular_file_bytes: u64,
    pub max_bytes: u64,
    pub max_entries: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CopyUsage {
    bytes: u64,
    entries: usize,
}

#[derive(Debug, Clone)]
struct BaselineEntry {
    digest: [u8; 32],
    len: u64,
    source_path: PathBuf,
}

#[derive(Debug, Clone)]
struct CopyRecord {
    root: PathBuf,
    baseline: BTreeMap<PathBuf, BaselineEntry>,
}

#[derive(Debug)]
pub struct IsolationBroker {
    copies_root: PathBuf,
    session_dir: PathBuf,
    limits: IsolationLimits,
    copies: BTreeMap<String, CopyRecord>,
}

impl IsolationBroker {
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self> {
        Self::build(data_dir.as_ref(), IsolationLimits::default())
    }

    #[cfg(test)]
    pub fn new_with_limits(data_dir: impl AsRef<Path>, limits: IsolationLimits) -> Result<Self> {
        Self::build(data_dir.as_ref(), limits)
    }

    pub fn create_copy(&mut self, task_id: &str, source: &Path) -> Result<SnapshotSummary> {
        if self.copies.contains_key(task_id) {
            bail!("task copy `{task_id}` already exists");
        }
        if task_id.trim().is_empty() {
            bail!("task id cannot be empty");
        }

        let source_root = fs::canonicalize(source)
            .with_context(|| format!("failed to resolve source root {}", source.display()))?;
        if !source_root.is_dir() {
            bail!("source root {} is not a directory", source_root.display());
        }

        self.ensure_session_dir()?;
        let copy_root = self.session_dir.join(task_directory_name(task_id));
        if copy_root.exists() {
            bail!("task copy path {} already exists", copy_root.display());
        }
        fs::create_dir(&copy_root)
            .with_context(|| format!("failed to create task copy {}", copy_root.display()))?;
        restrict_to_owner(&copy_root)?;
        let resolved_copy_root = fs::canonicalize(&copy_root)
            .with_context(|| format!("failed to resolve task copy {}", copy_root.display()))?;

        let mut build = SnapshotBuild {
            files: 0,
            bytes: 0,
            entries: 0,
            excluded: ExcludedPaths::new(self.limits.max_excluded_paths),
            baseline: BTreeMap::new(),
            existing_live_bytes: self.live_bytes()?,
        };

        let result =
            self.copy_directory(&source_root, &source_root, &resolved_copy_root, &mut build);
        match result {
            Ok(()) => {
                let summary = SnapshotSummary {
                    root: resolved_copy_root.clone(),
                    files: build.files,
                    bytes: build.bytes,
                    excluded_total: build.excluded.total(),
                    excluded: build.excluded.finish(),
                };
                self.copies.insert(
                    task_id.to_string(),
                    CopyRecord {
                        root: resolved_copy_root,
                        baseline: build.baseline,
                    },
                );
                Ok(summary)
            }
            Err(err) => {
                let _ = fs::remove_dir_all(&copy_root);
                Err(err)
            }
        }
    }

    pub fn workspace_root(&self, task_id: &str) -> Option<PathBuf> {
        self.copies.get(task_id).map(|record| record.root.clone())
    }

    pub fn contains(&self, task_id: &str) -> bool {
        self.copies.contains_key(task_id)
    }

    pub fn copy_quota(&self, task_id: &str) -> Result<CopyQuota> {
        self.usage_and_quota(task_id).map(|(_, quota)| quota)
    }

    pub fn validate_copy(&self, task_id: &str) -> Result<()> {
        self.usage_and_quota(task_id).map(|_| ())
    }

    pub fn precheck_write(&self, task_id: &str, relative: &Path, new_len: u64) -> Result<()> {
        let record = self
            .copies
            .get(task_id)
            .ok_or_else(|| anyhow!("unknown task copy `{task_id}`"))?;
        let (usage, quota) = self.usage_and_quota(task_id)?;
        if new_len > quota.max_regular_file_bytes {
            bail!(
                "task copy regular file limit would be exceeded ({new_len} bytes, limit {})",
                quota.max_regular_file_bytes
            );
        }
        let target = record.root.join(relative);
        let old_len = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_file() => metadata.len(),
            Ok(_) => 0,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", relative.display()));
            }
        };
        let projected_bytes = usage.bytes.saturating_sub(old_len).saturating_add(new_len);
        if projected_bytes > quota.max_bytes {
            bail!(
                "task copy byte limit would be exceeded (projected {projected_bytes}, limit {})",
                quota.max_bytes
            );
        }

        let added_entries = count_missing_entries(&record.root, relative)?;
        let projected_entries = usage.entries.saturating_add(added_entries);
        if projected_entries > quota.max_entries {
            bail!(
                "task copy entry limit would be exceeded (projected {projected_entries}, limit {})",
                quota.max_entries
            );
        }
        Ok(())
    }

    pub fn plan_apply(&self, task_id: &str, current_main: &Path) -> Result<ApplyPlan> {
        // Validate the entire live tree first, including runtime/cache directories
        // intentionally omitted from the apply diff. The scan below repeats its own
        // limits so growth racing this preflight still fails closed.
        self.validate_copy(task_id)?;
        let record = self
            .copies
            .get(task_id)
            .ok_or_else(|| anyhow!("unknown task copy `{task_id}`"))?;
        let main_root = fs::canonicalize(current_main).with_context(|| {
            format!(
                "failed to resolve current main project root {}",
                current_main.display()
            )
        })?;
        if !main_root.is_dir() {
            bail!(
                "current main root {} is not a directory",
                main_root.display()
            );
        }

        let mut deleted = BTreeSet::new();
        let mut scan = PlanScan {
            baseline: &record.baseline,
            main_root: &main_root,
            state: PlanScanState::default(),
            seen: BTreeSet::new(),
            writes: Vec::new(),
            conflicts: BTreeSet::new(),
        };
        self.scan_copy(&record.root, Path::new(""), &mut scan)?;

        for (relative, baseline) in &record.baseline {
            if scan.seen.contains(relative) {
                continue;
            }
            let main_path = main_root.join(relative);
            if !main_path.exists() {
                continue;
            }
            if matches_baseline(&main_path, baseline)? {
                deleted.insert(relative_to_string(relative));
            } else {
                scan.conflicts.insert(relative_to_string(relative));
            }
        }

        scan.writes
            .sort_by(|left, right| left.path.cmp(&right.path));

        Ok(ApplyPlan {
            writes: scan.writes,
            deleted: deleted.into_iter().collect(),
            conflicts: scan.conflicts.into_iter().collect(),
        })
    }

    pub fn release(&mut self, task_id: &str) -> Result<()> {
        let Some(record) = self.copies.get(task_id) else {
            return Ok(());
        };
        remove_exact_copy(&self.session_dir, &record.root)?;
        self.copies.remove(task_id);
        Ok(())
    }

    pub fn release_all(&mut self) -> Result<()> {
        self.release_all_inner()
    }

    fn build(data_dir: &Path, limits: IsolationLimits) -> Result<Self> {
        if data_dir.as_os_str().is_empty() {
            bail!("data directory cannot be empty");
        }
        fs::create_dir_all(data_dir)
            .with_context(|| format!("failed to create data directory {}", data_dir.display()))?;
        let copies_root = data_dir.join("task-copies");
        fs::create_dir_all(&copies_root)
            .with_context(|| format!("failed to create {}", copies_root.display()))?;
        restrict_to_owner(&copies_root)?;
        let copies_root = fs::canonicalize(&copies_root)
            .with_context(|| format!("failed to resolve {}", copies_root.display()))?;

        let session_dir = create_unique_session_dir(&copies_root)?;
        Ok(Self {
            copies_root,
            session_dir,
            limits,
            copies: BTreeMap::new(),
        })
    }

    fn ensure_session_dir(&mut self) -> Result<()> {
        if self.session_dir.exists() {
            return Ok(());
        }
        self.session_dir = create_unique_session_dir(&self.copies_root)?;
        Ok(())
    }

    fn live_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        for record in self.copies.values() {
            let usage = measure_copy_usage(
                &record.root,
                self.limits.max_regular_file_bytes,
                self.limits.max_copied_bytes,
                self.limits.max_entries,
            )?;
            total = total.saturating_add(usage.bytes);
            if total > self.limits.max_total_live_bytes {
                bail!("total live task-copy storage quota exceeded");
            }
        }
        Ok(total)
    }

    fn usage_and_quota(&self, task_id: &str) -> Result<(CopyUsage, CopyQuota)> {
        if !self.copies.contains_key(task_id) {
            bail!("unknown task copy `{task_id}`");
        }

        let mut target_usage = None;
        let mut other_bytes = 0u64;
        for (id, record) in &self.copies {
            let usage = measure_copy_usage(
                &record.root,
                self.limits.max_regular_file_bytes,
                self.limits.max_copied_bytes,
                self.limits.max_entries,
            )
            .with_context(|| format!("task copy `{id}` exceeds its live storage quota"))?;
            if id == task_id {
                target_usage = Some(usage);
            } else {
                other_bytes = other_bytes.saturating_add(usage.bytes);
            }
        }
        if other_bytes > self.limits.max_total_live_bytes {
            bail!("other live task copies already exceed the total storage quota");
        }
        let quota = CopyQuota {
            max_regular_file_bytes: self.limits.max_regular_file_bytes,
            max_bytes: self
                .limits
                .max_copied_bytes
                .min(self.limits.max_total_live_bytes - other_bytes),
            max_entries: self.limits.max_entries,
        };
        let usage = target_usage.expect("requested copy was checked above");
        if usage.bytes > quota.max_bytes {
            bail!(
                "task copy byte limit exceeded ({} bytes, limit {})",
                usage.bytes,
                quota.max_bytes
            );
        }
        Ok((usage, quota))
    }

    fn copy_directory(
        &self,
        source_root: &Path,
        source_dir: &Path,
        dest_dir: &Path,
        build: &mut SnapshotBuild,
    ) -> Result<()> {
        for entry in sorted_entries(source_dir)? {
            let file_type = entry.file_type().with_context(|| {
                format!("failed to read file type for {}", entry.path().display())
            })?;
            let relative = entry
                .path()
                .strip_prefix(source_root)
                .expect("entry is under source root")
                .to_path_buf();
            let name = entry.file_name();
            let name = name.to_string_lossy();

            if entry.path().starts_with(&self.copies_root) {
                build.excluded.push(&relative, "task-copy storage");
                continue;
            }
            if let Some(reason) = named_exclusion(&name, file_type.is_dir(), file_type.is_file()) {
                build.excluded.push(&relative, reason);
                continue;
            }

            if file_type.is_symlink() {
                build.excluded.push(&relative, "symlink");
                continue;
            }

            if file_type.is_dir() {
                self.reserve_entry(build, &relative, "entry count")?;
                let dest_path = dest_dir.join(&relative);
                fs::create_dir_all(&dest_path)
                    .with_context(|| format!("failed to create {}", dest_path.display()))?;
                restrict_to_owner(&dest_path)?;
                build.entries += 1;
                self.copy_directory(source_root, &entry.path(), dest_dir, build)?;
                continue;
            }

            if !file_type.is_file() {
                build.excluded.push(&relative, "special file");
                continue;
            }

            self.reserve_entry(build, &relative, "entry count")?;
            self.copy_regular_file(source_root, &entry.path(), dest_dir, &relative, build)?;
        }

        Ok(())
    }

    fn reserve_entry(
        &self,
        build: &SnapshotBuild,
        relative: &Path,
        limit_name: &str,
    ) -> Result<()> {
        if build.entries.saturating_add(1) > self.limits.max_entries {
            bail!(
                "{limit_name} limit exceeded while copying {}",
                relative.display()
            );
        }
        Ok(())
    }

    fn copy_regular_file(
        &self,
        source_root: &Path,
        source_path: &Path,
        dest_dir: &Path,
        relative: &Path,
        build: &mut SnapshotBuild,
    ) -> Result<()> {
        let metadata = fs::metadata(source_path)
            .with_context(|| format!("failed to stat {}", source_path.display()))?;
        if metadata.len() > self.limits.max_regular_file_bytes {
            bail!(
                "regular file limit exceeded by {} ({} bytes)",
                relative.display(),
                metadata.len()
            );
        }

        let dest_path = dest_dir.join(relative);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
            restrict_to_owner(parent)?;
        }

        let mut input = fs::File::open(source_path)
            .with_context(|| format!("failed to open {}", source_path.display()))?;
        let mut output = fs::File::create(&dest_path)
            .with_context(|| format!("failed to create {}", dest_path.display()))?;
        let mut hasher = Blake2s256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 8192];
        loop {
            let read = input
                .read(&mut buffer)
                .with_context(|| format!("failed to read {}", source_path.display()))?;
            if read == 0 {
                break;
            }
            copied = copied.saturating_add(read as u64);
            if copied > self.limits.max_regular_file_bytes {
                bail!(
                    "regular file limit exceeded while copying {}",
                    relative.display()
                );
            }
            if build.bytes.saturating_add(copied) > self.limits.max_copied_bytes {
                bail!(
                    "copy byte limit exceeded while copying {}",
                    relative.display()
                );
            }
            if build
                .existing_live_bytes
                .saturating_add(build.bytes)
                .saturating_add(copied)
                > self.limits.max_total_live_bytes
            {
                bail!(
                    "total live copy quota exceeded while copying {}",
                    relative.display()
                );
            }
            output
                .write_all(&buffer[..read])
                .with_context(|| format!("failed to write {}", dest_path.display()))?;
            hasher.update(&buffer[..read]);
        }

        build.entries += 1;
        build.files += 1;
        build.bytes += copied;
        preserve_snapshot_permissions(&dest_path, &metadata)?;
        build.baseline.insert(
            relative.to_path_buf(),
            BaselineEntry {
                digest: hasher.finalize().into(),
                len: copied,
                source_path: source_root.join(relative),
            },
        );
        Ok(())
    }

    fn scan_copy(
        &self,
        copy_root: &Path,
        relative_dir: &Path,
        scan: &mut PlanScan<'_>,
    ) -> Result<()> {
        let current_dir = copy_root.join(relative_dir);
        for entry in sorted_entries(&current_dir)? {
            let path = entry.path();
            let relative = path
                .strip_prefix(copy_root)
                .expect("entry is under copy root")
                .to_path_buf();
            let file_type = entry.file_type().with_context(|| {
                format!("failed to read file type for {}", entry.path().display())
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();

            if file_type.is_symlink() {
                self.reserve_plan_entry(&mut scan.state, &relative)?;
                scan.conflicts.insert(relative_to_string(&relative));
                continue;
            }

            if file_type.is_dir() {
                if name.eq_ignore_ascii_case(".git") || is_runtime_cache_dir(&name) {
                    continue;
                }
                self.reserve_plan_entry(&mut scan.state, &relative)?;
                self.scan_copy(copy_root, &relative, scan)?;
                continue;
            }

            if let Some(_reason) = named_exclusion(&name, false, file_type.is_file()) {
                continue;
            }

            if !file_type.is_file() {
                self.reserve_plan_entry(&mut scan.state, &relative)?;
                scan.conflicts.insert(relative_to_string(&relative));
                continue;
            }

            let metadata = fs::metadata(&path)
                .with_context(|| format!("failed to stat {}", path.display()))?;
            self.reserve_plan_entry(&mut scan.state, &relative)?;
            self.reserve_plan_bytes(&mut scan.state, &relative, metadata.len())?;

            scan.seen.insert(relative.clone());
            let bytes =
                fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
            let digest: [u8; 32] = Blake2s256::digest(&bytes).into();
            let path_string = relative_to_string(&relative);
            let main_path = scan.main_root.join(&relative);
            if main_parent_conflicts(scan.main_root, &relative)? {
                scan.conflicts.insert(path_string);
                continue;
            }

            if let Some(entry) = scan.baseline.get(&relative) {
                if entry.len == bytes.len() as u64 && entry.digest == digest {
                    continue;
                }
                if !matches_baseline(&main_path, entry)? {
                    if regular_file_matches_digest(&main_path, bytes.len() as u64, &digest)? {
                        continue;
                    }
                    scan.conflicts.insert(path_string);
                    continue;
                }
            } else {
                match fs::symlink_metadata(&main_path) {
                    Ok(_)
                        if regular_file_matches_digest(
                            &main_path,
                            bytes.len() as u64,
                            &digest,
                        )? =>
                    {
                        continue;
                    }
                    Ok(_) => {
                        scan.conflicts.insert(path_string);
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to inspect main-project path {}", relative.display())
                        });
                    }
                }
            }

            let content = match String::from_utf8(bytes) {
                Ok(content) => content,
                Err(_) => {
                    scan.conflicts.insert(path_string);
                    continue;
                }
            };
            scan.writes.push(crate::swarm::FileWrite {
                path: path_string,
                content,
            });
        }
        Ok(())
    }

    fn reserve_plan_entry(&self, state: &mut PlanScanState, relative: &Path) -> Result<()> {
        if state.entries.saturating_add(1) > self.limits.max_entries {
            bail!(
                "entry count limit exceeded while scanning {}",
                relative.display()
            );
        }
        state.entries += 1;
        Ok(())
    }

    fn reserve_plan_bytes(
        &self,
        state: &mut PlanScanState,
        relative: &Path,
        file_len: u64,
    ) -> Result<()> {
        if file_len > self.limits.max_regular_file_bytes {
            bail!(
                "regular file limit exceeded while scanning {}",
                relative.display()
            );
        }
        if state.bytes.saturating_add(file_len) > self.limits.max_copied_bytes {
            bail!(
                "copy byte limit exceeded while scanning {}",
                relative.display()
            );
        }
        state.bytes += file_len;
        Ok(())
    }

    fn release_all_inner(&mut self) -> Result<()> {
        let task_ids: Vec<String> = self.copies.keys().cloned().collect();
        for task_id in task_ids {
            self.release(&task_id)?;
        }
        remove_exact_session_dir(&self.copies_root, &self.session_dir)?;
        Ok(())
    }
}

#[derive(Debug)]
struct SnapshotBuild {
    files: usize,
    bytes: u64,
    entries: usize,
    excluded: ExcludedPaths,
    baseline: BTreeMap<PathBuf, BaselineEntry>,
    existing_live_bytes: u64,
}

#[derive(Debug, Default)]
struct PlanScanState {
    entries: usize,
    bytes: u64,
}

#[derive(Debug)]
struct PlanScan<'a> {
    baseline: &'a BTreeMap<PathBuf, BaselineEntry>,
    main_root: &'a Path,
    state: PlanScanState,
    seen: BTreeSet<PathBuf>,
    writes: Vec<crate::swarm::FileWrite>,
    conflicts: BTreeSet<String>,
}

pub fn validate_copy_root(root: &Path, quota: CopyQuota) -> Result<()> {
    measure_copy_usage(
        root,
        quota.max_regular_file_bytes,
        quota.max_bytes,
        quota.max_entries,
    )
    .map(|_| ())
}

pub async fn wait_for_copy_quota_violation(root: &Path, quota: CopyQuota) -> anyhow::Error {
    loop {
        if let Err(error) = validate_copy_root(root, quota) {
            return error;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

fn measure_copy_usage(
    root: &Path,
    max_regular_file_bytes: u64,
    max_bytes: u64,
    max_entries: usize,
) -> Result<CopyUsage> {
    let metadata = fs::metadata(root)
        .with_context(|| format!("failed to inspect task copy {}", root.display()))?;
    if !metadata.is_dir() {
        bail!("task copy root is not a directory");
    }

    fn visit(
        directory: &Path,
        usage: &mut CopyUsage,
        max_regular_file_bytes: u64,
        max_bytes: u64,
        max_entries: usize,
    ) -> Result<()> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to scan task copy {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to scan task copy {}", directory.display())
                    });
                }
            };
            usage.entries = usage.entries.saturating_add(1);
            if usage.entries > max_entries {
                bail!("task copy entry limit exceeded (more than {max_entries} entries)");
            }
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to inspect {}", entry.path().display()));
                }
            };
            if file_type.is_dir() {
                visit(
                    &entry.path(),
                    usage,
                    max_regular_file_bytes,
                    max_bytes,
                    max_entries,
                )?;
            } else if file_type.is_file() {
                let len = match entry.metadata() {
                    Ok(metadata) => metadata.len(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to inspect {}", entry.path().display())
                        });
                    }
                };
                if len > max_regular_file_bytes {
                    bail!(
                        "task copy regular file limit exceeded ({len} bytes, limit {max_regular_file_bytes})"
                    );
                }
                usage.bytes = usage.bytes.saturating_add(len);
                if usage.bytes > max_bytes {
                    bail!("task copy byte limit exceeded (more than {max_bytes} bytes)");
                }
            }
        }
        Ok(())
    }

    let mut usage = CopyUsage::default();
    visit(
        root,
        &mut usage,
        max_regular_file_bytes,
        max_bytes,
        max_entries,
    )?;
    Ok(usage)
}

fn count_missing_entries(root: &Path, relative: &Path) -> Result<usize> {
    let mut current = root.to_path_buf();
    let mut missing = 0usize;
    for component in relative.components() {
        match component {
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("task-copy write path must be relative")
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing = missing.saturating_add(1);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
                bail!(
                    "task-copy write path {} has a parent that is not a directory",
                    relative.display()
                );
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", relative.display()));
            }
        }
    }
    Ok(missing)
}

#[derive(Debug)]
struct ExcludedPaths {
    cap: usize,
    kept: Vec<String>,
    overflow: usize,
    total: usize,
}

impl ExcludedPaths {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            kept: Vec::new(),
            overflow: 0,
            total: 0,
        }
    }

    fn push(&mut self, relative: &Path, reason: &str) {
        self.total = self.total.saturating_add(1);
        let entry = format!("{} ({reason})", relative_to_string(relative));
        if self.cap == 0 {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        if self.kept.len() < self.cap {
            self.kept.push(entry);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    fn finish(mut self) -> Vec<String> {
        if self.overflow == 0 || self.cap == 0 {
            return self.kept;
        }
        if self.kept.len() >= self.cap && self.cap > 1 {
            self.kept.truncate(self.cap - 1);
        } else if self.cap == 1 {
            self.kept.clear();
        }
        self.kept
            .push(format!("... and {} more excluded paths", self.overflow));
        self.kept
    }

    fn total(&self) -> usize {
        self.total
    }
}

fn create_unique_session_dir(copies_root: &Path) -> Result<PathBuf> {
    static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

    for _ in 0..128 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        let seq = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let session_dir = copies_root.join(format!("{pid:x}-{now:x}-{seq:x}"));
        match fs::create_dir(&session_dir) {
            Ok(()) => {
                restrict_to_owner(&session_dir)?;
                return fs::canonicalize(&session_dir).with_context(|| {
                    format!(
                        "failed to resolve session directory {}",
                        session_dir.display()
                    )
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to create {}", session_dir.display()));
            }
        }
    }
    bail!(
        "failed to create a unique task-copy session directory under {}",
        copies_root.display()
    )
}

fn sorted_entries(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(dir).with_context(|| format!("failed to read directory {}", dir.display()))?
    {
        entries.push(entry.with_context(|| format!("failed to list {}", dir.display()))?);
    }
    entries.sort_by(|left, right| {
        left.file_name()
            .to_string_lossy()
            .cmp(&right.file_name().to_string_lossy())
    });
    Ok(entries)
}

fn task_directory_name(task_id: &str) -> String {
    let mut name = String::from("task-");
    let mut sanitized = String::new();
    for ch in task_id.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        sanitized.push_str("unnamed");
    }
    name.push_str(&sanitized);
    name
}

fn relative_to_string(relative: &Path) -> String {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_string()),
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    parts.join("/")
}

fn named_exclusion(name: &str, is_dir: bool, is_file: bool) -> Option<&'static str> {
    if name.eq_ignore_ascii_case(".git") {
        return Some("git metadata");
    }

    let lower = name.to_ascii_lowercase();
    if is_dir && is_runtime_cache_dir(name) {
        return Some("runtime/cache directory");
    }

    if !is_file {
        return None;
    }

    if lower == ".env" {
        return Some("credential file");
    }
    if lower.starts_with(".env.")
        && !matches!(
            lower.as_str(),
            ".env.example" | ".env.sample" | ".env.template"
        )
    {
        return Some("credential file");
    }
    if matches!(
        lower.as_str(),
        ".netrc" | ".npmrc" | ".pypirc" | ".vault-token" | "credentials"
    ) {
        return Some("credential file");
    }
    if lower.starts_with("id_") && !lower.ends_with(".pub") {
        return Some("private key");
    }
    if let Some(extension) = Path::new(name).extension().and_then(OsStr::to_str)
        && matches!(
            extension.to_ascii_lowercase().as_str(),
            "pem" | "key" | "p12" | "pfx" | "p8" | "gpg" | "age"
        )
    {
        return Some("credential file");
    }
    None
}

fn is_runtime_cache_dir(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "target"
            | "node_modules"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | ".next"
            | "dist"
            | "build"
            | ".cache"
            | ".simon-run"
    )
}

fn matches_baseline(path: &Path, baseline: &BaselineEntry) -> Result<bool> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to stat {}", path.display()));
        }
    };
    if !metadata.is_file() || metadata.len() != baseline.len {
        return Ok(false);
    }
    let resolved = match fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to resolve {}", path.display()));
        }
    };
    if resolved != baseline.source_path {
        return Ok(false);
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let digest: [u8; 32] = Blake2s256::digest(&bytes).into();
    Ok(digest == baseline.digest)
}

fn regular_file_matches_digest(
    path: &Path,
    expected_len: u64,
    expected_digest: &[u8; 32],
) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if !metadata.is_file() || metadata.len() != expected_len {
        return Ok(false);
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() as u64 != expected_len {
        return Ok(false);
    }
    let digest: [u8; 32] = Blake2s256::digest(&bytes).into();
    Ok(&digest == expected_digest)
}

fn main_parent_conflicts(main_root: &Path, relative: &Path) -> Result<bool> {
    let joined = main_root.join(relative);
    let Some(mut ancestor) = joined.parent() else {
        return Ok(true);
    };
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                return Ok(metadata.file_type().is_symlink() || !metadata.is_dir());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                let Some(parent) = ancestor.parent() else {
                    return Ok(true);
                };
                ancestor = parent;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect main-project parent {}",
                        ancestor.display()
                    )
                });
            }
        }
    }
}

fn remove_exact_copy(session_dir: &Path, root: &Path) -> Result<()> {
    if !root.starts_with(session_dir) {
        bail!(
            "refusing to remove copy outside session directory: {}",
            root.display()
        );
    }
    match fs::remove_dir_all(root) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", root.display())),
    }
}

fn remove_exact_session_dir(copies_root: &Path, session_dir: &Path) -> Result<()> {
    if !session_dir.starts_with(copies_root) {
        bail!(
            "refusing to remove session directory outside task-copies root: {}",
            session_dir.display()
        );
    }
    match fs::remove_dir(session_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", session_dir.display())),
    }
}

#[cfg(unix)]
fn preserve_snapshot_permissions(dest_path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = fs::Permissions::from_mode(metadata.permissions().mode() & 0o777);
    fs::set_permissions(dest_path, permissions)
        .with_context(|| format!("failed to preserve permissions on {}", dest_path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn preserve_snapshot_permissions(dest_path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let mut permissions = fs::metadata(dest_path)
        .with_context(|| format!("failed to stat {}", dest_path.display()))?
        .permissions();
    permissions.set_readonly(metadata.permissions().readonly());
    fs::set_permissions(dest_path, permissions)
        .with_context(|| format!("failed to preserve permissions on {}", dest_path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_to_owner(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(dir)
        .with_context(|| format!("failed to stat {}", dir.display()))?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(dir, permissions)
        .with_context(|| format!("failed to restrict {}", dir.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_to_owner(_dir: &Path) -> Result<()> {
    Ok(())
}

impl Drop for IsolationBroker {
    fn drop(&mut self) {
        let _ = self.release_all_inner();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn write_bytes(path: &Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn tiny_limits() -> IsolationLimits {
        IsolationLimits {
            max_regular_file_bytes: 128,
            max_copied_bytes: 256,
            max_entries: 64,
            max_total_live_bytes: 512,
            max_excluded_paths: 20,
        }
    }

    #[test]
    fn snapshot_fidelity_preserves_regular_and_untracked_files() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("src/main.rs"), "fn main() {}\n");
        write_file(&source.join("notes.txt"), "dirty but on disk\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();

        assert_eq!(snapshot.files, 2);
        assert_eq!(snapshot.excluded_total, 0);
        assert_eq!(
            fs::read_to_string(snapshot.root.join("src/main.rs")).unwrap(),
            "fn main() {}\n"
        );
        assert_eq!(
            fs::read_to_string(snapshot.root.join("notes.txt")).unwrap(),
            "dirty but on disk\n"
        );
    }

    #[test]
    fn snapshot_excludes_its_own_storage_when_data_lives_under_the_project() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = source.join(".simon");
        write_file(&source.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();

        assert_eq!(
            fs::read_to_string(snapshot.root.join("src/lib.rs")).unwrap(),
            "pub fn value() -> u8 { 1 }\n"
        );
        assert!(
            snapshot
                .excluded
                .iter()
                .any(|entry| entry.contains("task-copy storage"))
        );
        assert!(!snapshot.root.join(".simon/task-copies").exists());
    }

    #[test]
    fn exclusions_are_reported_and_not_copied() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join(".git/HEAD"), "ref: refs/heads/main\n");
        write_file(&source.join("node_modules/pkg/index.js"), "ignored\n");
        write_file(&source.join(".env"), "SECRET=1\n");
        write_file(&source.join(".env.example"), "SAFE=1\n");
        write_file(&source.join("id_rsa"), "private\n");
        write_file(&source.join("creds.pem"), "pem\n");
        write_file(&source.join("keep.txt"), "kept\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();

        assert_eq!(snapshot.excluded_total, 5);
        assert!(snapshot.excluded.iter().any(|line| line.contains(".git")));
        assert!(
            snapshot
                .excluded
                .iter()
                .any(|line| line.contains("node_modules"))
        );
        assert!(snapshot.excluded.iter().any(|line| line.contains(".env")));
        assert!(snapshot.excluded.iter().any(|line| line.contains("id_rsa")));
        assert!(
            snapshot
                .excluded
                .iter()
                .any(|line| line.contains("creds.pem"))
        );
        assert!(!snapshot.root.join(".git").exists());
        assert!(!snapshot.root.join("node_modules").exists());
        assert!(!snapshot.root.join(".env").exists());
        assert!(!snapshot.root.join("id_rsa").exists());
        assert_eq!(
            fs::read_to_string(snapshot.root.join(".env.example")).unwrap(),
            "SAFE=1\n"
        );
        assert_eq!(
            fs::read_to_string(snapshot.root.join("keep.txt")).unwrap(),
            "kept\n"
        );
    }

    #[test]
    fn distinct_tasks_receive_distinct_workspace_roots() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("file.txt"), "shared\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let first = broker.create_copy("1", &source).unwrap();
        let second = broker.create_copy("2", &source).unwrap();

        assert_ne!(first.root, second.root);
        assert_eq!(first.root.parent(), second.root.parent());
    }

    #[test]
    fn excluded_path_reporting_stays_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join(".env"), "one\n");
        write_file(&source.join(".netrc"), "two\n");
        write_file(&source.join("id_rsa"), "three\n");

        let mut limits = tiny_limits();
        limits.max_excluded_paths = 2;
        let mut broker = IsolationBroker::new_with_limits(&data, limits).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();

        assert_eq!(snapshot.excluded.len(), 2);
        assert_eq!(snapshot.excluded_total, 3);
        assert!(snapshot.excluded[1].contains("more excluded paths"));
    }

    #[test]
    fn limit_breach_cleans_the_partial_new_copy() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("a.txt"), &"a".repeat(90));
        write_file(&source.join("b.txt"), &"b".repeat(90));

        let mut limits = tiny_limits();
        limits.max_copied_bytes = 100;
        let mut broker = IsolationBroker::new_with_limits(&data, limits).unwrap();
        let err = broker.create_copy("too-big", &source).unwrap_err();

        assert!(err.to_string().contains("copy byte limit exceeded"));
        assert!(!broker.contains("too-big"));
        assert!(!broker.session_dir.join("task-too-big").exists());
    }

    #[test]
    fn total_quota_failure_preserves_existing_copies() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("a.txt"), &"a".repeat(70));
        write_file(&source.join("b.txt"), &"b".repeat(70));

        let mut limits = tiny_limits();
        limits.max_total_live_bytes = 150;
        let mut broker = IsolationBroker::new_with_limits(&data, limits).unwrap();
        let first = broker.create_copy("one", &source).unwrap();
        let err = broker.create_copy("two", &source).unwrap_err();

        assert!(err.to_string().contains("total live copy quota exceeded"));
        assert!(first.root.exists());
        assert!(broker.contains("one"));
        assert!(!broker.contains("two"));
    }

    #[test]
    fn growth_in_a_live_copy_counts_against_new_copy_creation() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("base.txt"), &"a".repeat(20));

        let mut limits = tiny_limits();
        limits.max_total_live_bytes = 100;
        let mut broker = IsolationBroker::new_with_limits(&data, limits).unwrap();
        let first = broker.create_copy("one", &source).unwrap();
        write_file(&first.root.join("base.txt"), &"b".repeat(90));

        let error = broker.create_copy("two", &source).unwrap_err().to_string();

        assert!(error.contains("total live copy quota exceeded"), "{error}");
        assert!(first.root.exists());
        assert!(broker.contains("one"));
        assert!(!broker.contains("two"));
    }

    #[test]
    fn projected_write_over_copy_quota_is_rejected_before_disk_changes() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("base.txt"), "base\n");

        let mut limits = tiny_limits();
        limits.max_copied_bytes = 32;
        let mut broker = IsolationBroker::new_with_limits(&data, limits).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();

        let error = broker
            .precheck_write("task-1", Path::new("too-large.txt"), 32)
            .unwrap_err()
            .to_string();

        assert!(error.contains("copy byte limit"), "{error}");
        assert!(!snapshot.root.join("too-large.txt").exists());
        assert!(broker.contains("task-1"));
    }

    #[test]
    fn plan_apply_reports_changed_and_new_files() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("a.txt"), "old\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("a.txt"), "new\n");
        write_file(&snapshot.root.join("b.txt"), "fresh\n");

        let plan = broker.plan_apply("task-1", &source).unwrap();
        assert_eq!(
            plan.writes
                .iter()
                .map(|write| write.path.clone())
                .collect::<Vec<_>>(),
            vec!["a.txt".to_string(), "b.txt".to_string()]
        );
        assert!(plan.deleted.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn plan_apply_skips_files_already_written_from_the_same_copy() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("first.txt"), "first base\n");
        write_file(&source.join("second.txt"), "second base\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("first.txt"), "first changed\n");
        write_file(&snapshot.root.join("second.txt"), "second changed\n");
        write_file(&snapshot.root.join("new.txt"), "new content\n");

        write_file(&source.join("first.txt"), "first changed\n");
        write_file(&source.join("new.txt"), "new content\n");

        let plan = broker.plan_apply("task-1", &source).unwrap();

        assert_eq!(
            plan.writes
                .iter()
                .map(|write| write.path.as_str())
                .collect::<Vec<_>>(),
            vec!["second.txt"]
        );
        assert!(plan.deleted.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn plan_apply_reports_deleted_files() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("a.txt"), "keep\n");
        write_file(&source.join("b.txt"), "delete\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        fs::remove_file(snapshot.root.join("b.txt")).unwrap();

        let plan = broker.plan_apply("task-1", &source).unwrap();
        assert_eq!(plan.deleted, vec!["b.txt".to_string()]);
        assert!(plan.writes.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn changed_files_conflict_when_main_has_drifted() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("a.txt"), "base\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("a.txt"), "copy change\n");
        write_file(&source.join("a.txt"), "main drift\n");

        let plan = broker.plan_apply("task-1", &source).unwrap();
        assert!(plan.writes.is_empty());
        assert!(plan.deleted.is_empty());
        assert_eq!(plan.conflicts, vec!["a.txt".to_string()]);
    }

    #[test]
    fn apply_plan_conflicts_when_main_has_a_file_in_a_required_parent_position() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("ok.txt"), "base\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("ok.txt"), "changed\n");
        write_file(&snapshot.root.join("blocked/nested.txt"), "new\n");
        write_file(&source.join("blocked"), "not a directory\n");

        let plan = broker.plan_apply("task-1", &source).unwrap();

        assert_eq!(plan.writes.len(), 1);
        assert_eq!(plan.writes[0].path, "ok.txt");
        assert_eq!(plan.conflicts, vec!["blocked/nested.txt".to_string()]);
    }

    #[test]
    fn new_files_conflict_when_main_now_has_that_path() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("base.txt"), "base\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("new.txt"), "copy version\n");
        write_file(&source.join("new.txt"), "main version\n");

        let plan = broker.plan_apply("task-1", &source).unwrap();
        assert!(plan.writes.is_empty());
        assert!(plan.deleted.is_empty());
        assert_eq!(plan.conflicts, vec!["new.txt".to_string()]);
    }

    #[test]
    fn new_files_conflict_when_main_has_a_file_in_their_parent_chain() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("base.txt"), "base\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("ok.txt"), "safe\n");
        write_file(&snapshot.root.join("blocked/new.txt"), "copy version\n");
        write_file(&source.join("blocked"), "main file\n");

        let plan = broker.plan_apply("task-1", &source).unwrap();

        assert_eq!(
            plan.writes
                .iter()
                .map(|write| write.path.as_str())
                .collect::<Vec<_>>(),
            vec!["ok.txt"]
        );
        assert_eq!(plan.conflicts, vec!["blocked/new.txt".to_string()]);
    }

    #[test]
    fn excluded_runtime_directories_are_ignored_during_plan_generation() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("tracked.txt"), "base\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(
            &snapshot.root.join("node_modules/pkg/index.js"),
            "generated\n",
        );
        write_file(&snapshot.root.join(".cache/tool/state"), "generated\n");

        let plan = broker.plan_apply("task-1", &source).unwrap();
        assert!(plan.writes.is_empty());
        assert!(plan.deleted.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn plan_apply_rejects_files_over_the_regular_file_limit() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("tracked.txt"), "base\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("huge.txt"), &"x".repeat(129));

        let err = broker.plan_apply("task-1", &source).unwrap_err();
        let detail = format!("{err:#}");
        assert!(
            detail.contains("task copy regular file limit exceeded"),
            "{detail}"
        );
        assert_eq!(
            fs::read_to_string(source.join("tracked.txt")).unwrap(),
            "base\n"
        );
    }

    #[test]
    fn plan_apply_rejects_total_bytes_over_the_live_copy_limit() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("tracked.txt"), "base\n");

        let mut limits = tiny_limits();
        limits.max_copied_bytes = 10;
        let mut broker = IsolationBroker::new_with_limits(&data, limits).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("a.txt"), "12345");
        write_file(&snapshot.root.join("b.txt"), "67890");

        let err = broker.plan_apply("task-1", &source).unwrap_err();
        let detail = format!("{err:#}");
        assert!(detail.contains("task copy byte limit exceeded"), "{detail}");
    }

    #[test]
    fn plan_apply_rejects_trees_over_the_entry_limit() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("tracked.txt"), "base\n");

        let mut limits = tiny_limits();
        limits.max_entries = 2;
        let mut broker = IsolationBroker::new_with_limits(&data, limits).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_file(&snapshot.root.join("dir/a.txt"), "a\n");
        write_file(&snapshot.root.join("dir/b.txt"), "b\n");

        let err = broker.plan_apply("task-1", &source).unwrap_err();
        let detail = format!("{err:#}");
        assert!(
            detail.contains("task copy entry limit exceeded"),
            "{detail}"
        );
    }

    #[test]
    fn non_utf8_copy_changes_are_reported_as_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("blob.bin"), "text\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        write_bytes(&snapshot.root.join("blob.bin"), &[0xff, 0xfe, 0xfd]);

        let plan = broker.plan_apply("task-1", &source).unwrap();
        assert!(plan.writes.is_empty());
        assert_eq!(plan.conflicts, vec!["blob.bin".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_created_inside_the_copy_are_reported_as_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("target.txt"), "target\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        std::os::unix::fs::symlink(
            snapshot.root.join("target.txt"),
            snapshot.root.join("link.txt"),
        )
        .unwrap();

        let plan = broker.plan_apply("task-1", &source).unwrap();
        assert!(plan.writes.is_empty());
        assert_eq!(plan.conflicts, vec!["link.txt".to_string()]);
    }

    #[test]
    fn release_and_release_all_only_remove_registered_copy_roots() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("file.txt"), "data\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let first = broker.create_copy("one", &source).unwrap();
        let second = broker.create_copy("two", &source).unwrap();

        broker.release("one").unwrap();
        assert!(!first.root.exists());
        assert!(!broker.contains("one"));
        assert!(second.root.exists());

        broker.release_all().unwrap();
        assert!(!second.root.exists());
        assert!(!broker.contains("two"));
        assert!(!broker.session_dir.exists());
    }

    #[test]
    fn release_all_removes_the_unique_session_directory() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("file.txt"), "data\n");

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        broker.create_copy("task-1", &source).unwrap();
        let session_dir = broker.session_dir.clone();

        broker.release_all().unwrap();

        assert!(!session_dir.exists());
    }

    #[test]
    fn drop_best_effort_releases_registered_paths() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        write_file(&source.join("file.txt"), "data\n");

        let session_dir = {
            let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
            broker.create_copy("task-1", &source).unwrap();
            broker.session_dir.clone()
        };

        assert!(!session_dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn snapshots_preserve_regular_permissions_but_strip_special_bits() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        let readonly = source.join("readonly.txt");
        let script = source.join("script.sh");
        write_file(&readonly, "ro\n");
        write_file(&script, "#!/bin/sh\nexit 0\n");
        fs::set_permissions(&readonly, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o6755)).unwrap();

        let mut broker = IsolationBroker::new_with_limits(&data, tiny_limits()).unwrap();
        let snapshot = broker.create_copy("task-1", &source).unwrap();
        let readonly_mode = fs::metadata(snapshot.root.join("readonly.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        let script_mode = fs::metadata(snapshot.root.join("script.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;

        assert_eq!(readonly_mode, 0o444);
        assert_eq!(script_mode, 0o755);
    }
}

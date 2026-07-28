# Paranoid Security & Shared Context
1. **Shared Skills Dir**: Unified `~/.config/multichat/skills/` accessible by ALL models.
2. **Path Traversal Protection**: Models can only READ this directory. Strict chroot/path validation prevents them from accessing `~/.ssh` or outside files.
3. **Supply Chain Defense**: `Cargo.lock` enforced. `#![forbid(unsafe_code)]` at project level. `cargo-audit` required for CI.
4. **Clipboard Security**: App will clear OS clipboard after a timeout if used.

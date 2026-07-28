# Permissions Policy Update
1. **Default Unlimited**: By default, ALL models have FULL read/write/execute permissions across the system. No read-only limits or path sandboxes are enforced initially.
2. **Opt-in Restrictions**: The user can actively restrict these permissions (e.g., locking down to read-only or a specific chroot folder) when starting the chat session via CLI flags or TUI config.

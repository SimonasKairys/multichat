# Step 5: TUI (corrected)
- ratatui 0.29 / crossterm 0.28, `tokio::select!` over input and the orchestrator event channel.
- **Fixed**: input reaches a model. The previous loop replied `Acknowledged: {msg}` from a hardcoded string and never called a provider.
- `TerminalGuard` restores the terminal on drop, so a panic cannot strand the user in raw mode.
- Per-model attribution, scrolling, busy state.
- Verified: 7 tests.

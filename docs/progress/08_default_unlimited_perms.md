# Permissions Policy (corrected)

The original text ("ALL models have FULL read/write/execute permissions") contradicted
`01`/`05`/`07` and was never built.

**Actual**: models have no filesystem or execution access. The only outward paths are the
read-only, traversal-guarded skills dir and local CLI providers the user configures in
`config.json`. Model output cannot add one.

Future tool execution must be opt-in, never default-allow.

"""WebSocket-only Kripke verification for web_in_c.

kripke: finite graph, BFS, AG/EF/AG EF.
model: one-connection command-boundary product with auth/membership monitors.
products: two-connection shared session/room abstractions and LEAVE diagnostic.
properties: requirements; handoff: JSON/CSV/DOT/test-vector exports.
bmc/liveness: small bounded/progress helpers for the team's verification work.
verify: run checks and C state-machine replay; see README.md.
"""

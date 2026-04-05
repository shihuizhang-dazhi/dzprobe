# Changelog

## 2.0.1 - 2026-04-01
- Fix direct script usage by adding a shebang to `DZProce.py` and documenting executable usage.
- Normalize README examples to use `./DZProce.py` for source-run workflows.
- Add graceful fallback when `colorama` is unavailable so CLI startup does not fail.

## 2.0.0 - 2026-04-01
- Widen terminal output columns for target host and HTTP Server fields to reduce truncation of long values.
- Add regression tests to lock output rendering for long server banners and long domain targets.

## 1.0.0 - 2026-03-30
- First-generation official release.
- Add scan profile presets via `--scan-profile` (`stealth`, `balanced`, `aggressive`, `custom`).
- Add adaptive pacing controls: `--adaptive-pacing`, `--submit-jitter-ms`, `--adaptive-window`.
- Refactor task scheduling to stream target submission with bounded in-flight futures, reducing memory peaks.
- Improve HTTPS-oriented service probing by preferring TLS checks on common TLS ports.
- Normalize placeholder `Server` header values (`none`, `null`, `unknown`) to empty output for clearer reporting.
- Clarify output semantics: separate service classification and probe evidence display.
- Expand `probe_signatures.json` with broader protocol/middleware signatures and tighter low-false-positive patterns.
- Add unit tests for CLI profile presets, adaptive pacing helpers, and probe output regressions.


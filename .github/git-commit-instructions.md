# Git Commit Instructions

Use concise conventional commits when practical, for example `feat: add size rule` or `fix: preserve fingerprint compatibility`.

Keep commits focused by boundary: runtime code with its tests, GOAT Flow setup docs, and generated package artifacts should not be mixed unless the user explicitly asks for a single combined commit. Do not commit `node_modules/`, `dist/`, `.venv/`, or local cache directories.

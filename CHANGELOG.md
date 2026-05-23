# Changelog

All notable changes to `gruff-py`. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Public API pre-1.0.

## [Unreleased]

## [0.1.0] - 2026-05-23

First public release.

- 116 rules across 10 pillars: size, complexity, maintainability, dead-code, naming, documentation, security, sensitive-data, test-quality, design.
- Outputs: text, JSON, HTML, Markdown, GitHub annotations, hotspot, SARIF 2.1.0.
- Local dashboard; `.gruff-py.yaml` / `[tool.gruff-py]` config; PHP-compatible 16-char fingerprints.
- Schemas pinned: `gruff-py.analysis.v1`, `gruff-py.hotspot.v1`, `gruff-py.baseline.v1` (reserved).
- Pre-release false-positive sweep across 9 rules: 425 → 335 findings (-21%) on a 53-file dogfood project.

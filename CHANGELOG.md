# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Dependabot for uv dependencies and GitHub Actions
- CODEOWNERS and this changelog
- Lint checks (flake8, black, isort) now fail CI when they fail

### Changed
- Aligned COPYRIGHT and security-insights metadata with GPLv3+

## [0.9.5.1] - 2026-07-18

### Added
- PyPI Trusted Publishing via tag-triggered GitHub Actions (`v*` tags)
- Developer docs under `docs/` (DEVELOPMENT.md, TESTING.md)

### Changed
- Migrated packaging from requirements.txt/pip to uv (`pyproject.toml` + `uv.lock`)
- Upgraded GitHub Actions to Node.js 24–compatible action versions

### Fixed
- Mocked NVD API responses in unit tests to avoid rate-limit failures

## [0.9.5] - 2026-07-10

### Changed
- Dependency updates (including urllib3 security fixes)

[Unreleased]: https://github.com/vdanen/vex-reader/compare/v0.9.5.1...HEAD
[0.9.5.1]: https://github.com/vdanen/vex-reader/releases/tag/v0.9.5.1
[0.9.5]: https://github.com/vdanen/vex-reader/releases/tag/0.9.5

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.5.2] - 2026-07-18

### Added
- Dependabot for uv dependencies and GitHub Actions
- CODEOWNERS and this changelog
- Lint checks (flake8, black, isort) now fail CI when they fail

### Changed
- Aligned COPYRIGHT and security-insights metadata with GPLv3+
- Formatted codebase with black and isort
- Dependency updates: requests 2.34.2, pytest 9.1.1, black 26.5.1,
  isort 8.0.1, coverage 7.15.2, build 1.5.0, twine 6.2.0
- GitHub Actions updates: ossf/scorecard-action 2.4.3, codeql-action v4

### Fixed
- Incomplete `microsoft.com` URL host check in package parsing (CodeQL);
  parse the hostname instead of using substring matching

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

[Unreleased]: https://github.com/vdanen/vex-reader/compare/v0.9.5.2...HEAD
[0.9.5.2]: https://github.com/vdanen/vex-reader/compare/v0.9.5.1...v0.9.5.2
[0.9.5.1]: https://github.com/vdanen/vex-reader/releases/tag/v0.9.5.1
[0.9.5]: https://github.com/vdanen/vex-reader/releases/tag/0.9.5

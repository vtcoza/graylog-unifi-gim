# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
Semantic Versioning.

## [Unreleased]

### Fixed

- Use Graylog 7-compatible positional arguments for `parse_cef` and wait for
  the installed UDP input before the Docker release gate replays fixtures.

### Planned

- Real gateway fixtures and upgrade/failover/failback parsers.
- Broader UniFi Network 10.x CEF event coverage.

## [0.1.0] - 2026-08-08

### Added

- Mixed CEF and device-syslog parsing pipeline for Graylog Open 7.1.
- GIM field normalization with preserved `UNIFI*` vendor fields.
- Lookup tables, streams, disabled event definitions, and four dashboards.
- Self-contained and assets-only content-pack variants.
- Twelve sanitized parser-signature fixtures and regression tests.
- Docker/Data Node release-gate scaffold and GitHub Actions workflows.

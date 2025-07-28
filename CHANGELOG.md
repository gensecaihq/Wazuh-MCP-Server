# Changelog

## [2.0.0] - Repository Optimization

### Changed
- **Simplified Configuration**: Single `config/wazuh.env` file for all settings
- **Streamlined Scripts**: Consolidated tools into `scripts/` directory
- **Modern Docker Standards**: Using `compose.yml` and `docker compose` commands
- **Cleaner Structure**: Removed duplicate files and unnecessary directories

### Added
- `scripts/configure.sh` - Interactive configuration wizard
- `scripts/quick-start.sh` - One-command deployment
- `scripts/test-server.sh` - Functionality testing
- `scripts/validate-production.sh` - Production readiness checks
- `docs/QUICK_START.md` - 3-step getting started guide
- `PROJECT_STRUCTURE.md` - Clear project organization

### Removed
- Duplicate configuration methods
- `tools/` directory (merged into `scripts/`)
- Unnecessary README files in subdirectories
- Complex environment variable mappings
- Binary artifacts

### Improvements
- Reduced configuration complexity from 20+ variables to 3 required
- Simplified Docker Compose from 100+ lines to 38 lines
- Clear separation between user scripts and source code
- Better documentation organization
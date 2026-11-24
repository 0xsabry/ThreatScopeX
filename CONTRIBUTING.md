# Contributing to ThreatScope

Thank you for your interest in contributing! ThreatScope welcomes contributions from the security community.

## How to Contribute

### Reporting Bugs

- Open an issue with a clear description
- Include the log file type (`.log`, `.txt`, `.evtx`) and Python version
- Attach error tracebacks if applicable

### Adding Detection Rules

1. Fork the repository
2. Add your rule(s) to the `PATTERNS` dictionary in `ThreatscopeX.py` (legacy desktop GUI — 308 rules). Rules for the web application belong in `BUILTIN_PATTERNS` in `core/analyzer.py` (57 patterns).
3. Each rule must include: `patterns`, `severity`, `weight`, `category`, `desc`, `mitre`
4. Add corresponding MITRE technique to `MITRE_DESCRIPTIONS` in `ThreatscopeX.py` if new
5. Validate the rules with the check in `.github/workflows/ci.yml` (it compiles every regex in `PATTERNS` and checks the required fields). There is no separate `validate_threatscope.py` script.
6. Submit a Pull Request

### Adding Sigma Rules

1. Create a `.yml` file in the `sigma_rules/` directory
2. Follow the [Sigma specification](https://github.com/SigmaHQ/sigma)
3. Include `detection.keywords` for pattern matching
4. Submit a Pull Request

### Adding Correlation Rules

1. Add to the `CORRELATION_RULES` list
2. Include: `name`, `requires` (list of rule IDs), `severity`, `score_boost`, `desc`

## Code Style

- Follow PEP 8
- Use descriptive variable names
- Comment complex regex patterns
- Keep new web-application code in the existing package layout (`core/`, `parsers/`, `intel/`, `ai/`, `export/`). The single-file `ThreatscopeX.py` is the legacy desktop GUI only.

## Testing

Before submitting, ensure:

- `python -c "import py_compile; py_compile.compile('ThreatscopeX.py', doraise=True)"` passes
- All regex patterns compile without errors
- GUI launches without errors: `python ThreatscopeX.py`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

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
5. Validate the rules with the test suite (`python -m unittest discover -s tests -v`): `tests/test_legacy.py` compiles every regex in the legacy `PATTERNS` and checks the required fields, and `tests/test_analyzer_patterns.py` does the same for the web application's `BUILTIN_PATTERNS`. There is no separate `validate_threatscope.py` script.
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

Before submitting, install dependencies and run the test suite from the
repository root:

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The suite uses Python's standard `unittest` (no extra test framework) and
covers:

- Current detection patterns: `tests/test_analyzer_patterns.py` validates
  the 57 patterns in `core/analyzer.py` (`BUILTIN_PATTERNS`) — required
  fields and regex compilation.
- Current CLI: `tests/test_cli.py` checks `cli.py --help` and
  `analyze --help`, then runs a real offline analysis of the committed
  sample EVTX with JSON export.
- Flask entry point: `tests/test_flask_app.py` uses Flask's test client
  against the real `app` object (no server is launched).
- Legacy desktop GUI: `tests/test_legacy.py` compiles `ThreatscopeX.py`
  and validates its own 308 legacy rules. These checks are separate and
  do not validate `app.py` or `cli.py`; the Tkinter GUI is never launched.

CI (`.github/workflows/ci.yml`) runs the same checks on Python 3.11–3.15.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

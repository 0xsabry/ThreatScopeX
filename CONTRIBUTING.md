# Contributing to ThreatScope

Thank you for your interest in contributing! ThreatScope welcomes contributions from the security community.

## How to Contribute

### Reporting Bugs

- Open an issue with a clear description
- Include the log file type (`.log`, `.txt`, `.evtx`) and Python version
- Attach error tracebacks if applicable

### Adding Detection Rules

1. Fork the repository
2. Add your rule(s) to the `PATTERNS` dictionary in `0xSABRY_ThreatScope.py`
3. Each rule must include: `patterns`, `severity`, `weight`, `category`, `desc`, `mitre`
4. Add corresponding MITRE technique to `MITRE_DESCRIPTIONS` if new
5. Run the validation script: `python validate_threatscope.py`
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
- Keep all code in a single file for zero-dependency deployment

## Testing

Before submitting, ensure:

- `python -c "import py_compile; py_compile.compile('0xSABRY_ThreatScope.py', doraise=True)"` passes
- All regex patterns compile without errors
- GUI launches without errors: `python 0xSABRY_ThreatScope.py`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

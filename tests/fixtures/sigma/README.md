# Sigma conformance fixtures

Curated rules used by `tests/test_sigma_conformance.py`. The tests distinguish
**parsing/validation compatibility** (does the rule load and validate?) from
**event-matching compatibility** (does it detect the expected event?). Passing
YAML parsing does not imply pySigma matching equivalence.

| Fixture | Validation | Expected matching | Notes |
|---------|------------|-------------------|-------|
| `valid_process_creation.yml` | valid | matches `Image` ending `\cmd.exe` **and** `CommandLine` containing `whoami` | `endswith` + `contains`, standard condition |
| `valid_base64_chain.yml` | valid | matches `CommandLine` containing the base64 of `Invoke-Mimikatz` | `base64|contains`; padding preserved |
| `valid_windash.yml` | valid | matches `CommandLine` with `-encodedcommand` or its slash/dash variants | `windash|contains` |
| `invalid_unsupported_modifier.yml` | invalid | never detects | `fieldref` unsupported (pySigma **accepts**) |
| `invalid_terminal_wide.yml` | invalid | never detects | encoding chain ends in `wide` (pySigma **accepts**) |
| `invalid_re_with_contains.yml` | invalid | never detects | `contains` combined with `re` (pySigma **also rejects**) |

## Intentional deviations from pySigma semantics

Verified against pySigma 1.5.1 and 2.0.1 by
`tests/test_sigma_pysigma_crosscheck.py`:

- **Terminal encoding modifiers** (`|wide`, `|utf16*` as the last modifier) are
  rejected. pySigma applies the transform and matches the transformed value;
  ThreatScopeX requires an explicit matcher (`|contains` or a base64 stage)
  because its default matcher is equality, and a bare transform could never
  match literally.
- **`fieldref` and `expand`** are rejected. pySigma implements them
  (`SigmaFieldReferenceModifier`, `SigmaExpandModifier`); ThreatScopeX has no
  field-reference/placeholder-pipeline support, so it fails closed.
- **`|all` on a scalar value** is rejected. pySigma accepts a single value with
  `all` (treating it as all-of-one); ThreatScopeX requires an explicit list.
- **`base64`** keeps RFC 4648 padding and matches exactly (value-transformation
  semantics) and **`base64offset`** produces the same three byte-alignment
  variants as pySigma (`['Y21k', 'NtZ', 'jbW']` for `cmd`).
- **`windash`** expands only `\B[-/]\b` separators to the same five variants as
  pySigma. pySigma 2.x also rejects values with more than three eligible
  separators; pySigma 1.x expands them without bound. ThreatScopeX rejects such
  rules in both cases (bounded expansion).
- **`utf16|base64` byte-order mark is version-dependent in pySigma.** pySigma
  1.x encodes the `U+FEFF` marker as UTF-8 (`EF BB BF`, base64 `77u/…`);
  pySigma 2.x and ThreatScopeX use the real UTF-16LE BOM bytes (`FF FE`, base64
  `//5…`). ThreatScopeX matches pySigma 2.x.
- **`contains|re` / `startswith|re` / `endswith|re`** are rejected instead of
  silently ignoring one matcher; pySigma raises `SigmaValueError` for the same
  combinations.
- **`re`** runs through the `regex` package with a hard timeout (ReDoS
  protection) and is case-sensitive unless `|re|i` is used.

pySigma is an optional test-only dependency (`requirements-dev.txt`).
`test_sigma_pysigma_crosscheck.py` performs the version-aware parse/semantic
cross-check and is skipped when pySigma is absent.

### What pySigma does *not* verify

pySigma is used here for **rule parsing and modifier/condition semantics only**.
It has no backend-agnostic event-matching API in this environment, so it does
**not** confirm that ThreatScopeX matches (or fails to match) real events. Those
event-matching results remain verified solely by
`tests/test_sigma_conformance.py` and are not claimed to be equivalent to any
pySigma backend.

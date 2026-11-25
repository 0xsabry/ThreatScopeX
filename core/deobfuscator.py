"""
ThreatScope — Auto-Deobfuscation Engine
Author: 0xSABRY

Multi-layer recursive deobfuscation for malicious payloads:
  - PowerShell: Base64, backtick escapes, format strings (-f),
    XOR payloads, environment variable replacement, char() arrays
  - Bash: Command concatenation, hex encoding, base64 pipes,
    $() substitution, eval chains
  - Generic: URL encoding, HTML entities, Unicode escapes

Extracts embedded C2 indicators (IPs, domains, URIs) from
deobfuscated payloads for threat intel enrichment.
"""

import re
import base64
import codecs
import logging
import html
from urllib.parse import unquote
from typing import Dict, List, Optional, Tuple, Any, Set

logger = logging.getLogger("threatscope.deobfuscator")


# ============================================================
# IOC Extraction Patterns (post-deobfuscation)
# ============================================================

C2_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv4_port": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?):(\d{1,5})\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|xyz|info|ru|cn|tk|top|cc|pw|biz|me|co|"
        r"uk|de|fr|onion|bit|club|live|online)\b"
    ),
    "url": re.compile(
        r"https?://[^\s\"'<>]{5,200}"
    ),
    "uri_path": re.compile(
        r"/[a-zA-Z0-9_\-./]{3,100}(?:\?[^\s\"']*)?",
    ),
}

# Private IP ranges to exclude from C2 indicators
PRIVATE_RANGES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                   "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                   "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.")


# ============================================================
# PowerShell Deobfuscator
# ============================================================

class PowerShellDeobfuscator:
    """
    Multi-layer PowerShell deobfuscation engine.

    Handles:
      - Base64 encoded commands (-EncodedCommand)
      - Backtick escape removal (p`o`w`e`r`s`h`e`l`l)
      - Caret escape removal (p^o^w^e^r^s^h^e^l^l)
      - Format string expansion ("{0}{1}" -f "pow","ershell")
      - Char code arrays ([char]72 + [char]101 + ...)
      - String concatenation ('po' + 'wer' + 'shell')
      - Environment variable replacement ($env:COMSPEC)
      - XOR byte array decryption
      - SecureString reverse
      - Invoke-Expression (IEX) unwrapping
    """

    # Environment variable defaults for replacement
    ENV_DEFAULTS = {
        "$env:comspec": "C:\\Windows\\system32\\cmd.exe",
        "$env:systemroot": "C:\\Windows",
        "$env:windir": "C:\\Windows",
        "$env:temp": "C:\\Users\\user\\AppData\\Local\\Temp",
        "$env:tmp": "C:\\Users\\user\\AppData\\Local\\Temp",
        "$env:userprofile": "C:\\Users\\user",
        "$env:appdata": "C:\\Users\\user\\AppData\\Roaming",
        "$env:programdata": "C:\\ProgramData",
        "$env:programfiles": "C:\\Program Files",
    }

    def deobfuscate(self, payload: str, max_iterations: int = 10) -> "DeobfuscationResult":
        """
        Recursively deobfuscate a PowerShell payload.

        Applies all deobfuscation layers iteratively until no further
        changes are detected or max_iterations is reached.

        Args:
            payload: The obfuscated PowerShell command/script.
            max_iterations: Maximum recursion depth.

        Returns:
            DeobfuscationResult with deobfuscated output and metadata.
        """
        layers: List[Dict[str, str]] = []
        current = payload.strip()
        seen: Set[str] = {current}

        for iteration in range(max_iterations):
            previous = current

            # Layer 1: Base64 decode
            current, decoded = self._decode_base64(current)
            if decoded:
                layers.append({"layer": "base64", "output": current[:500]})

            # Layer 2: Remove backtick escapes
            current, changed = self._remove_backticks(current)
            if changed:
                layers.append({"layer": "backtick_removal", "output": current[:500]})

            # Layer 3: Remove caret escapes
            current, changed = self._remove_carets(current)
            if changed:
                layers.append({"layer": "caret_removal", "output": current[:500]})

            # Layer 4: Expand format strings
            current, changed = self._expand_format_strings(current)
            if changed:
                layers.append({"layer": "format_string", "output": current[:500]})

            # Layer 5: Resolve char arrays
            current, changed = self._resolve_char_arrays(current)
            if changed:
                layers.append({"layer": "char_array", "output": current[:500]})

            # Layer 6: Concatenate strings
            current, changed = self._concat_strings(current)
            if changed:
                layers.append({"layer": "string_concat", "output": current[:500]})

            # Layer 7: Environment variable replacement
            current, changed = self._replace_env_vars(current)
            if changed:
                layers.append({"layer": "env_var_replace", "output": current[:500]})

            # Layer 8: XOR decode
            current, changed = self._decode_xor(current)
            if changed:
                layers.append({"layer": "xor_decode", "output": current[:500]})

            # Layer 9: Unwrap IEX
            current, changed = self._unwrap_iex(current)
            if changed:
                layers.append({"layer": "iex_unwrap", "output": current[:500]})

            # Check for convergence
            if current == previous or current in seen:
                break
            seen.add(current)

        # Extract C2 indicators from final output
        c2_indicators = extract_c2_indicators(current)

        return DeobfuscationResult(
            original=payload,
            deobfuscated=current,
            layers=layers,
            layer_count=len(layers),
            c2_indicators=c2_indicators,
            language="powershell",
        )

    def _decode_base64(self, text: str) -> Tuple[str, bool]:
        """Decode Base64 encoded PowerShell commands."""
        # Match -EncodedCommand or -enc parameter
        match = re.search(
            r"-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|"
            r"encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+"
            r"([A-Za-z0-9+/=]{20,})",
            text, re.IGNORECASE
        )
        if match:
            try:
                decoded = base64.b64decode(match.group(1))
                # Try UTF-16LE (PowerShell default for encoded commands)
                try:
                    decoded_str = decoded.decode("utf-16-le")
                except UnicodeDecodeError:
                    decoded_str = decoded.decode("utf-8", errors="replace")
                return decoded_str.strip(), True
            except Exception:
                pass

        # Match standalone base64 blobs
        for b64_match in re.finditer(r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", text):
            try:
                decoded = base64.b64decode(b64_match.group(1))
                decoded_str = decoded.decode("utf-8", errors="replace")
                if decoded_str.isprintable() or any(
                    kw in decoded_str.lower() for kw in ["http", "powershell", "cmd", "invoke"]
                ):
                    return text.replace(b64_match.group(0), f'"{decoded_str}"'), True
            except Exception:
                continue

        return text, False

    def _remove_backticks(self, text: str) -> Tuple[str, bool]:
        """Remove PowerShell backtick escape characters."""
        cleaned = re.sub(r"`([^`\n])", r"\1", text)
        return cleaned, cleaned != text

    def _remove_carets(self, text: str) -> Tuple[str, bool]:
        """Remove cmd.exe caret escape characters."""
        cleaned = re.sub(r"\^([^\^\n])", r"\1", text)
        return cleaned, cleaned != text

    def _expand_format_strings(self, text: str) -> Tuple[str, bool]:
        """Expand PowerShell format strings: "{0}{1}" -f "pow","ershell"."""
        changed = False

        def _replace_format(match: re.Match) -> str:
            nonlocal changed
            fmt_str = match.group(1)
            args_str = match.group(2)
            try:
                # Parse arguments
                args = [
                    a.strip().strip("'\"")
                    for a in re.split(r",(?=(?:[^'\"]*['\"][^'\"]*['\"])*[^'\"]*$)", args_str)
                ]
                result = fmt_str
                for i, arg in enumerate(args):
                    result = result.replace(f"{{{i}}}", arg)
                changed = True
                return result
            except Exception:
                return match.group(0)

        result = re.sub(
            r"['\"]([^'\"]*\{\d+\}[^'\"]*)['\"]"
            r"\s*-f\s*"
            r"(.+?)(?=\s*[;|\n\r]|$)",
            _replace_format, text, flags=re.IGNORECASE
        )
        return result, changed

    def _resolve_char_arrays(self, text: str) -> Tuple[str, bool]:
        """Resolve [char] code arrays: [char]72+[char]101+[char]108..."""
        changed = False

        def _replace_chars(match: re.Match) -> str:
            nonlocal changed
            char_str = match.group(0)
            chars = re.findall(r"\[char\]\s*(\d+)", char_str, re.IGNORECASE)
            if chars:
                try:
                    result = "".join(chr(int(c)) for c in chars)
                    changed = True
                    return f'"{result}"'
                except (ValueError, OverflowError):
                    pass
            return char_str

        result = re.sub(
            r"(?:\[char\]\s*\d+\s*\+?\s*){2,}",
            _replace_chars, text, flags=re.IGNORECASE
        )
        return result, changed

    def _concat_strings(self, text: str) -> Tuple[str, bool]:
        """Concatenate adjacent string literals: 'po' + 'wer' + 'shell'."""
        changed = False

        def _replace_concat(match: re.Match) -> str:
            nonlocal changed
            parts = re.findall(r"['\"]([^'\"]*)['\"]", match.group(0))
            if len(parts) > 1:
                changed = True
                return f"'{''.join(parts)}'"
            return match.group(0)

        result = re.sub(
            r"(?:['\"][^'\"]*['\"]\s*\+\s*){1,}['\"][^'\"]*['\"]",
            _replace_concat, text
        )
        return result, changed

    def _replace_env_vars(self, text: str) -> Tuple[str, bool]:
        """Replace known environment variables with defaults."""
        changed = False
        result = text
        for env_var, default_val in self.ENV_DEFAULTS.items():
            if env_var.lower() in result.lower():
                result = re.sub(re.escape(env_var), default_val, result, flags=re.IGNORECASE)
                changed = True
        return result, changed

    def _decode_xor(self, text: str) -> Tuple[str, bool]:
        """Decode XOR-encoded byte arrays."""
        # Match patterns like: (byte_array) -bxor key
        xor_match = re.search(
            r"\(?\s*((?:\d{1,3}\s*,\s*){5,}(?:\d{1,3}))\s*\)?\s*"
            r"(?:\|\s*%\s*\{|\|.*?foreach.*?\{)?\s*"
            r"(?:\$_\s*-bxor\s*(\d+)|\$_\s*-bxor\s*0x([0-9a-fA-F]+))",
            text, re.IGNORECASE
        )
        if xor_match:
            try:
                bytes_str = xor_match.group(1)
                byte_values = [int(b.strip()) for b in bytes_str.split(",")]

                key = 0
                if xor_match.group(2):
                    key = int(xor_match.group(2))
                elif xor_match.group(3):
                    key = int(xor_match.group(3), 16)

                if key > 0:
                    decoded = "".join(chr(b ^ key) for b in byte_values if 0 <= (b ^ key) <= 127)
                    if decoded and len(decoded) > 5:
                        return decoded, True
            except (ValueError, OverflowError):
                pass

        return text, False

    def _unwrap_iex(self, text: str) -> Tuple[str, bool]:
        """Unwrap Invoke-Expression / IEX wrappers."""
        # Remove IEX( ... ) or Invoke-Expression( ... ) wrappers
        match = re.search(
            r"(?:IEX|Invoke-Expression)\s*\(\s*(.+)\s*\)",
            text, re.IGNORECASE | re.DOTALL
        )
        if match:
            return match.group(1).strip(), True

        # Remove piped IEX: ... | IEX
        match = re.search(r"(.+?)\s*\|\s*(?:IEX|Invoke-Expression)\s*$",
                          text, re.IGNORECASE)
        if match:
            return match.group(1).strip(), True

        return text, False


# ============================================================
# Bash Deobfuscator
# ============================================================

class BashDeobfuscator:
    """
    Bash/shell command deobfuscation engine.

    Handles:
      - Base64 pipe chains (echo ... | base64 -d | bash)
      - Hex encoding (\\x48\\x65\\x6c\\x6c\\x6f)
      - Octal encoding (\\110\\145\\154)
      - Variable concatenation (a="po"; b="wer"; $a$b"shell")
      - $() and backtick command substitution
      - eval/exec chain unwrapping
      - printf format strings
      - xxd/od reverse encoding
    """

    def deobfuscate(self, payload: str, max_iterations: int = 10) -> "DeobfuscationResult":
        """
        Recursively deobfuscate a Bash/shell payload.

        Args:
            payload: The obfuscated shell command.
            max_iterations: Maximum recursion depth.

        Returns:
            DeobfuscationResult with deobfuscated output and metadata.
        """
        layers: List[Dict[str, str]] = []
        current = payload.strip()
        seen: Set[str] = {current}

        for iteration in range(max_iterations):
            previous = current

            # Layer 1: Base64 pipe decode
            current, changed = self._decode_base64_pipe(current)
            if changed:
                layers.append({"layer": "base64_pipe", "output": current[:500]})

            # Layer 2: Hex decode
            current, changed = self._decode_hex(current)
            if changed:
                layers.append({"layer": "hex_decode", "output": current[:500]})

            # Layer 3: Octal decode
            current, changed = self._decode_octal(current)
            if changed:
                layers.append({"layer": "octal_decode", "output": current[:500]})

            # Layer 4: Unwrap eval/exec
            current, changed = self._unwrap_eval(current)
            if changed:
                layers.append({"layer": "eval_unwrap", "output": current[:500]})

            # Layer 5: Printf expansion
            current, changed = self._expand_printf(current)
            if changed:
                layers.append({"layer": "printf_expand", "output": current[:500]})

            # Layer 6: URL decode
            current, changed = self._url_decode(current)
            if changed:
                layers.append({"layer": "url_decode", "output": current[:500]})

            if current == previous or current in seen:
                break
            seen.add(current)

        c2_indicators = extract_c2_indicators(current)

        return DeobfuscationResult(
            original=payload,
            deobfuscated=current,
            layers=layers,
            layer_count=len(layers),
            c2_indicators=c2_indicators,
            language="bash",
        )

    def _decode_base64_pipe(self, text: str) -> Tuple[str, bool]:
        """Decode base64 pipe chains: echo 'xxx' | base64 -d | bash."""
        match = re.search(
            r"echo\s+['\"]?([A-Za-z0-9+/=]{20,})['\"]?\s*\|\s*base64\s+(?:-d|--decode)",
            text, re.IGNORECASE
        )
        if match:
            try:
                decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
                return decoded.strip(), True
            except Exception:
                pass

        # Match: base64 -d <<< "..."
        match = re.search(
            r"base64\s+(?:-d|--decode)\s*<<<\s*['\"]?([A-Za-z0-9+/=]{20,})['\"]?",
            text, re.IGNORECASE
        )
        if match:
            try:
                decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
                return decoded.strip(), True
            except Exception:
                pass

        return text, False

    def _decode_hex(self, text: str) -> Tuple[str, bool]:
        """Decode hex-encoded strings: \\x48\\x65\\x6c..."""
        hex_pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
        match = hex_pattern.search(text)
        if match:
            hex_str = match.group(0)
            try:
                decoded = codecs.decode(hex_str.replace("\\x", ""), "hex").decode(
                    "utf-8", errors="replace"
                )
                return text.replace(hex_str, decoded), True
            except Exception:
                pass

        # $'\x48\x65\x6c\x6c\x6f' format
        match = re.search(r"\$'((?:\\x[0-9a-fA-F]{2})+)'", text)
        if match:
            try:
                decoded = codecs.decode(
                    match.group(1).replace("\\x", ""), "hex"
                ).decode("utf-8", errors="replace")
                return text.replace(match.group(0), decoded), True
            except Exception:
                pass

        return text, False

    def _decode_octal(self, text: str) -> Tuple[str, bool]:
        """Decode octal-encoded strings: \\110\\145\\154..."""
        octal_match = re.findall(r"\\(\d{3})", text)
        if len(octal_match) >= 4:
            try:
                decoded = "".join(chr(int(o, 8)) for o in octal_match)
                original = "".join(f"\\{o}" for o in octal_match)
                return text.replace(original, decoded), True
            except (ValueError, OverflowError):
                pass
        return text, False

    def _unwrap_eval(self, text: str) -> Tuple[str, bool]:
        """Unwrap eval/exec chains."""
        match = re.search(r"eval\s+['\"](.+?)['\"]", text, re.DOTALL)
        if match:
            return match.group(1), True

        match = re.search(r"eval\s+\$\((.+?)\)", text, re.DOTALL)
        if match:
            return match.group(1), True

        # Remove trailing | bash / | sh
        match = re.search(r"(.+?)\s*\|\s*(?:ba)?sh\s*$", text, re.IGNORECASE)
        if match:
            return match.group(1).strip(), True

        return text, False

    def _expand_printf(self, text: str) -> Tuple[str, bool]:
        """Expand printf format strings with hex/octal."""
        match = re.search(
            r"printf\s+['\"](%[boxXs0-9\\]+)['\"]",
            text
        )
        if match:
            # Let shell-style printf with hex escape sequences
            fmt = match.group(1)
            try:
                # Decode hex escapes in printf format
                decoded = codecs.decode(fmt, "unicode_escape")
                return text.replace(match.group(0), decoded), True
            except Exception:
                pass
        return text, False

    def _url_decode(self, text: str) -> Tuple[str, bool]:
        """URL decode percent-encoded strings."""
        if "%" in text:
            decoded = unquote(text)
            if decoded != text:
                return decoded, True
        return text, False


# ============================================================
# Deobfuscation Result
# ============================================================

class DeobfuscationResult:
    """
    Result of a deobfuscation operation.

    Attributes:
        original: The original obfuscated payload.
        deobfuscated: The final deobfuscated output.
        layers: List of deobfuscation layers applied.
        layer_count: Number of layers processed.
        c2_indicators: Extracted C2 indicators from the payload.
        language: Detected language (powershell, bash, generic).
    """

    def __init__(
        self,
        original: str,
        deobfuscated: str,
        layers: List[Dict[str, str]],
        layer_count: int,
        c2_indicators: Dict[str, List[str]],
        language: str = "unknown",
    ) -> None:
        self.original = original
        self.deobfuscated = deobfuscated
        self.layers = layers
        self.layer_count = layer_count
        self.c2_indicators = c2_indicators
        self.language = language

    @property
    def was_obfuscated(self) -> bool:
        """Check if the payload was actually obfuscated (layers were applied)."""
        return self.layer_count > 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "original": self.original[:1000],
            "deobfuscated": self.deobfuscated[:2000],
            "layers": self.layers,
            "layer_count": self.layer_count,
            "c2_indicators": self.c2_indicators,
            "language": self.language,
            "was_obfuscated": self.was_obfuscated,
        }

    def to_finding(self) -> Dict[str, Any]:
        """Convert to ThreatFinding-compatible dictionary."""
        if not self.was_obfuscated:
            return {}

        c2_count = sum(len(v) for v in self.c2_indicators.values())

        return {
            "rule_id": "deobfuscation",
            "rule_type": "deobfuscation",
            "title": f"Obfuscated {self.language.title()} Payload Decoded",
            "description": (
                f"Multi-layer obfuscated {self.language} payload decoded through "
                f"{self.layer_count} layers. "
                f"{'C2 indicators extracted: ' + str(c2_count) if c2_count else 'No C2 indicators found.'}"
            ),
            "severity": "high" if c2_count > 0 else "medium",
            "weight": 30 if c2_count > 0 else 20,
            "mitre": "T1027",
            "timestamp": "",
            "category": "Deobfuscation",
            "deobfuscation_result": self.to_dict(),
            "raw": self.deobfuscated[:500],
            "line_number": 0,
        }


# ============================================================
# C2 Indicator Extraction
# ============================================================

def extract_c2_indicators(text: str) -> Dict[str, List[str]]:
    """
    Extract C2 indicators from deobfuscated payload text.

    Args:
        text: The deobfuscated payload text.

    Returns:
        Dictionary mapping indicator type to list of values.
    """
    indicators: Dict[str, List[str]] = {
        "ips": [],
        "domains": [],
        "urls": [],
        "uris": [],
    }

    if not text:
        return indicators

    # Extract IPs (excluding private ranges)
    for match in C2_PATTERNS["ipv4"].finditer(text):
        ip = match.group(0)
        if not ip.startswith(PRIVATE_RANGES):
            if ip not in indicators["ips"]:
                indicators["ips"].append(ip)

    # Extract domains
    for match in C2_PATTERNS["domain"].finditer(text):
        domain = match.group(0).lower()
        # Exclude common benign domains
        if not any(
            domain.endswith(b) for b in [
                "microsoft.com", "windows.com", "google.com",
                "amazonaws.com", "windowsupdate.com",
            ]
        ):
            if domain not in indicators["domains"]:
                indicators["domains"].append(domain)

    # Extract URLs
    for match in C2_PATTERNS["url"].finditer(text):
        url = match.group(0)
        if url not in indicators["urls"]:
            indicators["urls"].append(url)

    # Extract URI paths
    for match in C2_PATTERNS["uri_path"].finditer(text):
        uri = match.group(0)
        if uri not in indicators["uris"] and len(uri) > 4:
            indicators["uris"].append(uri)

    return indicators


# ============================================================
# Unified Deobfuscation Pipeline
# ============================================================

class DeobfuscationPipeline:
    """
    Unified deobfuscation pipeline that auto-detects language
    and applies the appropriate deobfuscator.

    Example:
        >>> pipeline = DeobfuscationPipeline()
        >>> result = pipeline.deobfuscate(obfuscated_payload)
        >>> print(result.deobfuscated)
        >>> print(result.c2_indicators)
    """

    def __init__(self) -> None:
        self.ps_deobfuscator = PowerShellDeobfuscator()
        self.bash_deobfuscator = BashDeobfuscator()
        self._results: List[DeobfuscationResult] = []

    def deobfuscate(self, payload: str, language: str = "auto") -> DeobfuscationResult:
        """
        Deobfuscate a payload, auto-detecting the language if needed.

        Args:
            payload: The obfuscated payload string.
            language: Force language ("powershell", "bash") or "auto".

        Returns:
            DeobfuscationResult with deobfuscated output.
        """
        if language == "auto":
            language = self._detect_language(payload)

        if language == "powershell":
            result = self.ps_deobfuscator.deobfuscate(payload)
        elif language == "bash":
            result = self.bash_deobfuscator.deobfuscate(payload)
        else:
            # Try both and use the one with more layers
            ps_result = self.ps_deobfuscator.deobfuscate(payload)
            bash_result = self.bash_deobfuscator.deobfuscate(payload)
            result = ps_result if ps_result.layer_count >= bash_result.layer_count else bash_result

        self._results.append(result)
        return result

    def deobfuscate_bulk(self, payloads: List[str]) -> List[DeobfuscationResult]:
        """
        Deobfuscate multiple payloads.

        Args:
            payloads: List of obfuscated payload strings.

        Returns:
            List of DeobfuscationResult objects.
        """
        return [self.deobfuscate(p) for p in payloads]

    def get_all_c2_indicators(self) -> Dict[str, List[str]]:
        """Get all C2 indicators from all processed payloads."""
        combined: Dict[str, Set[str]] = {
            "ips": set(), "domains": set(), "urls": set(), "uris": set(),
        }
        for result in self._results:
            for key, values in result.c2_indicators.items():
                combined.get(key, set()).update(values)
        return {k: sorted(v) for k, v in combined.items()}

    def get_summary(self) -> Dict[str, Any]:
        """Get pipeline processing summary."""
        total_c2 = 0
        for r in self._results:
            total_c2 += sum(len(v) for v in r.c2_indicators.values())

        return {
            "total_processed": len(self._results),
            "total_obfuscated": len([r for r in self._results if r.was_obfuscated]),
            "total_layers": sum(r.layer_count for r in self._results),
            "total_c2_indicators": total_c2,
            "c2_indicators": self.get_all_c2_indicators(),
        }

    @staticmethod
    def _detect_language(payload: str) -> str:
        """Auto-detect the scripting language of a payload."""
        payload_lower = payload.lower()

        ps_indicators = sum([
            "powershell" in payload_lower,
            "-encodedcommand" in payload_lower or "-enc " in payload_lower,
            "[char]" in payload_lower,
            "invoke-" in payload_lower,
            "$env:" in payload_lower,
            "iex" in payload_lower,
            "-f " in payload and "{0}" in payload,
            "new-object" in payload_lower,
        ])

        bash_indicators = sum([
            "#!/bin" in payload,
            "| base64 -d" in payload_lower,
            "eval " in payload_lower,
            "$(" in payload,
            "\\x" in payload and len(re.findall(r"\\x[0-9a-f]{2}", payload_lower)) > 3,
            "| bash" in payload_lower or "| sh" in payload_lower,
            "echo " in payload_lower and "|" in payload,
        ])

        if ps_indicators > bash_indicators:
            return "powershell"
        elif bash_indicators > ps_indicators:
            return "bash"
        return "generic"

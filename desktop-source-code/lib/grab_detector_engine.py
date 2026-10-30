import base64
import binascii
import bisect
import hashlib
import hmac
import importlib.util
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

MAX_UPLOAD_BYTES = int(os.environ.get("GRAB_DETECTOR_MAX_BYTES", str(3 * 1024 * 1024)))
MAX_DEOBFUSCATED_BYTES = 8 * 1024 * 1024
MAX_REQUESTS = int(os.environ.get("GRAB_DETECTOR_MAX_REQUESTS", "100"))
MAX_URLS = 250
MAX_ENCODED = 250
MAX_FINDINGS = 100
MAX_BINARY_STRINGS = 5000
MAX_BODY_CHARS = 8000
MAX_HEADER_VALUE_CHARS = 1200
HOURLY_LIMIT = int(os.environ.get("GRAB_DETECTOR_HOURLY_LIMIT", "30"))
DAILY_LIMIT = int(os.environ.get("GRAB_DETECTOR_DAILY_LIMIT", "100"))
SANDBOX_TIMEOUT_MS = min(25000, max(3000, int(os.environ.get("GRAB_DETECTOR_SANDBOX_TIMEOUT_MS", "15000"))))
SANDBOX_MONTHLY_LIMIT = max(1, int(os.environ.get("GRAB_DETECTOR_SANDBOX_MONTHLY_LIMIT", "500")))
SANDBOX_LUA_BUDGET_MS = min(10000, max(100, int(os.environ.get("GRAB_DETECTOR_LUA_BUDGET_MS", "2500"))))
SANDBOX_EVENT_BUDGET_MS = min(5000, max(100, int(os.environ.get("GRAB_DETECTOR_EVENT_BUDGET_MS", "500"))))
SANDBOX_SIMULATION_BUDGET_MS = min(10000, max(500, int(os.environ.get("GRAB_DETECTOR_SIMULATION_BUDGET_MS", "3000"))))
SANDBOX_MAX_WAIT_CALLS = min(2000, max(20, int(os.environ.get("GRAB_DETECTOR_MAX_WAIT_CALLS", "400"))))
SANDBOX_MAX_VIRTUAL_MS = min(60000, max(100, int(os.environ.get("GRAB_DETECTOR_MAX_VIRTUAL_MS", "5000"))))
SANDBOX_MAX_INSTRUCTIONS = min(50000000, max(100000, int(os.environ.get("GRAB_DETECTOR_MAX_INSTRUCTIONS", "5000000"))))
SANDBOX_RUNTIME_LABEL = "Isolated Lua Runtime"
FREE_PERFORMED_DELAY_SECONDS = min(120, max(0, int(os.environ.get("GRAB_DETECTOR_FREE_DELAY_SECONDS", "120"))))
PREMIUM_SECRET = (os.environ.get("PREMIUM_SECRET") or "").strip()
PREMIUM_TOKEN_TTL_MS = 30 * 24 * 3600 * 1000
SYNTHETIC_LOGIN_INPUT = "RM7_FAKE_TEST_PASSWORD"
SANDBOX_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "grab-detector-sandbox")
SANDBOX_RUNTIME_PATH = os.path.join(SANDBOX_ROOT, "runtime.mjs")
SANDBOX_PRELUDE_PATH = os.path.join(SANDBOX_ROOT, "sandbox-prelude.lua")
SANDBOX_WASMOON_INDEX_PATH = os.path.join(SANDBOX_ROOT, "vendor", "wasmoon", "index.js")
SANDBOX_WASMOON_GLUE_PATH = os.path.join(SANDBOX_ROOT, "vendor", "wasmoon", "glue.wasm")

URL_RE = re.compile(r"https?://[^\s\"'<>\\`]+", re.IGNORECASE)
WEBHOOK_RE = re.compile(
    r"https?://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
    re.IGNORECASE,
)
TELEGRAM_RE = re.compile(
    r"https?://api\.telegram\.org/bot\d+:[A-Za-z0-9_\-]+(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)
TELEGRAM_TOKEN_RE = re.compile(r"\bbot\d{6,}:[A-Za-z0-9_\-]{25,}\b")
REQUIRE_RE = re.compile(r"\brequire\s*(?:\(\s*)?[\"']([^\"']{1,100})[\"']")
LONG_STRING_RE = re.compile(r"\[\[(.*?)\]\]", re.DOTALL)
QUOTED_RE = re.compile(r"(?P<q>[\"'])(?P<s>(?:\\.|(?!\1).){4,40000})(?P=q)")
STRING_CHAR_RE = re.compile(r"\bstring\.char\s*\(([0-9,\s]{1,5000})\)")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
HEX_BLOB_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){8,}$")
SECRET_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-\.=]{24,}$")

SENSITIVE_NAME_RE = re.compile(
    r"(?:(?<![A-Za-z0-9])pass(?![A-Za-z0-9])|token|secret|key|password|passwd|pwd|auth|authorization|cookie|session|webhook|api[_-]?key|access[_-]?token|refresh[_-]?token|signature|license)",
    re.IGNORECASE,
)
SENSITIVE_HEADER_RE = SENSITIVE_NAME_RE

REQUEST_PATTERNS = [
    ("socket.http.request", re.compile(r"\bsocket\.http\.request\s*\(")),
    ("ssl.https.request", re.compile(r"\bssl\.https\.request\s*\(")),
    ("http.request", re.compile(r"(?<![\w.])http\.request\s*\(")),
    ("http.get", re.compile(r"(?<![\w.])http\.get\s*\(")),
    ("http.post", re.compile(r"(?<![\w.])http\.post\s*\(")),
    ("http.put", re.compile(r"(?<![\w.])http\.put\s*\(")),
    ("http.patch", re.compile(r"(?<![\w.])http\.patch\s*\(")),
    ("http.delete", re.compile(r"(?<![\w.])http\.delete\s*\(")),
    ("requests.request", re.compile(r"\brequests\.request\s*\(")),
    ("requests.get", re.compile(r"\brequests\.get\s*\(")),
    ("requests.post", re.compile(r"\brequests\.post\s*\(")),
    ("requests.put", re.compile(r"\brequests\.put\s*\(")),
    ("requests.patch", re.compile(r"\brequests\.patch\s*\(")),
    ("requests.delete", re.compile(r"\brequests\.delete\s*\(")),
    ("performHttpRequest", re.compile(r"\bperformHttpRequest\s*\(")),
    ("httpRequest", re.compile(r"\bhttpRequest\s*\(")),
    ("CreateHttpRequest", re.compile(r"\bCreateHttpRequest\s*\(")),
    ("downloadUrlToFile", re.compile(r"\bdownloadUrlToFile\s*\(")),
    ("monet.httpRequest", re.compile(r"\bmonet\w*\.(?:httpRequest|request|downloadUrlToFile|download)\s*\(")),
    ("socket.connect", re.compile(r"\bsocket\.connect\s*\(")),
    ("tcp.connect", re.compile(r"\.connect\s*\(\s*[\"'][^\"']+[\"']\s*,\s*\d+")),
]

DYNAMIC_LIBRARIES = {
    "socket",
    "socket.http",
    "ssl",
    "ssl.https",
    "ltn12",
    "requests",
    "http",
    "moonloader",
    "lib.moonloader",
    "samp.events",
    "lib.samp.events",
    "monet",
    "monetloader",
}

METHOD_WORDS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

_QUOTA_LOCK = threading.Lock()
_QUOTA_MEMORY = {}
_SANDBOX_SDK = None
_SANDBOX_SDK_ERROR = None
_SANDBOX_MONTH_LOCK = threading.Lock()
_SANDBOX_MONTH_MEMORY = {"key": "", "count": 0}
_DEOB_MODULE = None
_DEOB_ERROR = None


class FileValidationError(ValueError):
    def __init__(self, message, code="INVALID_FILE", status=400):
        super().__init__(message)
        self.code = code
        self.status = status


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def safe_filename(name):
    base = os.path.basename(str(name or "script.lua")).replace("\x00", "")
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")
    if not base:
        base = "script.lua"
    if len(base) > 120:
        stem, ext = os.path.splitext(base)
        base = stem[: 120 - len(ext)] + ext
    return base


def _printable_ratio(text):
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text)


def classify_file(data, filename):
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise FileValidationError("The uploaded file is empty.", "EMPTY_FILE", 400)
    if len(data) > MAX_UPLOAD_BYTES:
        raise FileValidationError("The uploaded file exceeds the size limit.", "FILE_TOO_LARGE", 413)
    data = bytes(data)
    name = safe_filename(filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in (".lua", ".luac"):
        raise FileValidationError("Only .lua and .luac files are supported.", "UNSUPPORTED_FILE_TYPE", 415)

    if data.startswith(b"\x1bLJ"):
        return {
            "kind": "luajit_bytecode",
            "extension": ext,
            "lua_version": "LuaJIT bytecode",
            "source_available": False,
            "static_coverage": "partial",
            "deobfuscation": "ljd",
            "notes": ["LuaJIT bytecode was detected; string extraction is partial and decompilation is attempted only in Performed Scan."],
        }
    if data.startswith(b"\x1bLua"):
        return {
            "kind": "lua_bytecode",
            "extension": ext,
            "lua_version": "Standard Lua bytecode",
            "source_available": False,
            "static_coverage": "partial",
            "deobfuscation": "unsupported",
            "notes": ["Standard Lua bytecode cannot be fully inspected by the current static analyzer; only printable strings are examined."],
        }
    if ext == ".luac":
        return {
            "kind": "unsupported_bytecode",
            "extension": ext,
            "lua_version": "Unknown bytecode",
            "source_available": False,
            "static_coverage": "partial",
            "deobfuscation": "unsupported",
            "notes": ["The .luac file does not have a recognized Lua or LuaJIT bytecode header."],
        }

    if b"\x00" in data[:8192]:
        raise FileValidationError("Binary data in a .lua file is not supported.", "MALFORMED_LUA", 415)
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError:
        raise FileValidationError("The .lua file is not valid UTF-8 text.", "MALFORMED_LUA", 415)
    if _printable_ratio(source) < 0.75:
        raise FileValidationError("The .lua file contains too much non-text data.", "MALFORMED_LUA", 415)
    return {
        "kind": "lua_source",
        "extension": ext,
        "lua_version": "Lua source",
        "source_available": True,
        "static_coverage": "full",
        "deobfuscation": "moonsec",
        "notes": [],
    }


def _line_starts(text):
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return starts


def _line_at(starts, position):
    return bisect.bisect_right(starts, position)


def _line_text(lines, line_number):
    if not line_number or line_number < 1 or line_number > len(lines):
        return ""
    return lines[line_number - 1].strip()[:400]


def _clean_url(raw):
    url = str(raw or "").strip().strip("\"'")
    while url and url[-1] in ".,;:":
        url = url[:-1]
    while url.endswith(")") and url.count(")") > url.count("("):
        url = url[:-1]
    return url


def _secret_like(value):
    value = str(value or "")
    return len(value) >= 24 and bool(SECRET_VALUE_RE.match(value))


def redact_url(raw):
    raw = _clean_url(raw)
    if not raw:
        return ""
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError:
        return _redact_text(raw, 500)
    netloc = parts.netloc.rsplit("@", 1)[-1]
    path = parts.path or ""
    path = re.sub(r"(/api/webhooks/)\d+/[^/?#]+", r"\1[redacted]/[redacted]", path, flags=re.IGNORECASE)
    path = re.sub(r"/bot\d+:[^/?#]+", "/bot[redacted]", path, flags=re.IGNORECASE)
    segments = []
    for segment in path.split("/"):
        segments.append("[redacted]" if _secret_like(segment) else segment)
    path = "/".join(segments)

    query_parts = []
    if parts.query:
        for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            if SENSITIVE_NAME_RE.search(key or "") or _secret_like(value):
                query_parts.append((key, "[redacted]"))
            else:
                query_parts.append((key, value))
    query = "&".join(
        urllib.parse.quote(str(key), safe="") + "=" + urllib.parse.quote(str(value), safe="[]")
        for key, value in query_parts
    )
    fragment = parts.fragment
    if fragment and _secret_like(fragment):
        fragment = "[redacted]"
    return urllib.parse.urlunsplit((parts.scheme, netloc, path, query, fragment))


def _redact_text(text, limit=1000):
    value = str(text or "")[:limit]
    value = WEBHOOK_RE.sub(lambda m: redact_url(m.group(0)), value)
    value = TELEGRAM_RE.sub(lambda m: redact_url(m.group(0)), value)
    value = TELEGRAM_TOKEN_RE.sub("bot[redacted]", value)
    value = re.sub(
        r"(?i)\b(token|secret|key|password|passwd|pwd|authorization|cookie|session|signature)=([^&\s\"']+)",
        lambda m: m.group(1) + "=[redacted]",
        value,
    )
    value = re.sub(
        r"(?i)([\"']?(?:token|secret|key|password|passwd|pwd|authorization|cookie|session|signature)[\"']?\s*[:=]\s*)([\"']?)([^\"',}\s]{1,500})(\2)",
        lambda m: m.group(1) + m.group(2) + "[redacted]" + m.group(4),
        value,
    )
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+", "Bearer [redacted]", value)
    value = re.sub(r"\b[A-Za-z0-9_\-]{40,}\b", "[redacted]", value)
    value = value.replace(SYNTHETIC_LOGIN_INPUT, "[synthetic-login-input]")
    return value


def redact_headers(headers):
    pairs = []
    if isinstance(headers, dict):
        pairs = list(headers.items())
    elif isinstance(headers, list):
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                pairs.append((item[0], item[1]))
    result = {}
    for key, value in pairs[:60]:
        name = str(key or "").strip()[:100]
        if not name:
            continue
        lname = name.lower()
        if SENSITIVE_HEADER_RE.search(lname):
            result[name] = "[redacted]"
        else:
            result[name] = _redact_text(value, MAX_HEADER_VALUE_CHARS)
    return result


def _redact_json_value(value, depth=0):
    if depth > 12:
        return "[redacted]"
    if isinstance(value, dict):
        out = {}
        for key, item in list(value.items())[:80]:
            name = str(key)
            if SENSITIVE_NAME_RE.search(name):
                out[name] = "[redacted]"
            else:
                out[name] = _redact_json_value(item, depth + 1)
        return out
    if isinstance(value, list):
        return [_redact_json_value(item, depth + 1) for item in value[:80]]
    if isinstance(value, str):
        return _redact_text(value, 2000)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _redact_text(value, 500)


def redact_body(body):
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return _redact_json_value(body)
    text = str(body)
    if len(text) > MAX_BODY_CHARS:
        text = text[:MAX_BODY_CHARS]
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return _redact_json_value(json.loads(stripped))
        except Exception:
            pass
    return _redact_text(text, MAX_BODY_CHARS)


def _decode_lua_escapes(value):
    out = bytearray()
    i = 0
    raw = str(value or "")
    while i < len(raw):
        ch = raw[i]
        if ch != "\\" or i + 1 >= len(raw):
            out.extend(ch.encode("utf-8", "replace"))
            i += 1
            continue
        nxt = raw[i + 1]
        if nxt == "x" and i + 3 < len(raw) and re.match(r"[0-9a-fA-F]{2}", raw[i + 2 : i + 4]):
            out.append(int(raw[i + 2 : i + 4], 16))
            i += 4
        elif nxt == "z":
            i += 2
            while i < len(raw) and raw[i].isspace():
                i += 1
        elif nxt == "u" and i + 2 < len(raw) and raw[i + 2] == "{":
            end = raw.find("}", i + 3)
            if end != -1:
                try:
                    out.extend(chr(int(raw[i + 3 : end], 16)).encode("utf-8"))
                    i = end + 1
                    continue
                except Exception:
                    pass
            out.extend(b"\\u")
            i += 2
        elif nxt.isdigit():
            end = i + 1
            while end < len(raw) and end < i + 4 and raw[end].isdigit():
                end += 1
            try:
                out.append(int(raw[i + 1 : end], 10) & 0xFF)
                i = end
            except Exception:
                out.extend(b"\\")
                i += 1
        else:
            mapping = {"n": b"\n", "r": b"\r", "t": b"\t", "a": b"\a", "b": b"\b", "f": b"\f", "v": b"\v", "\\": b"\\", "\"": b"\"", "'": b"'"}
            out.extend(mapping.get(nxt, nxt.encode("utf-8", "replace")))
            i += 2
    return out.decode("utf-8", "replace")


def _decode_base64_candidate(value):
    text = str(value or "").strip()
    if len(text) < 16 or len(text) > 40000 or not BASE64_RE.match(text):
        return None
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(decoded) < 8 or _printable_ratio(decoded) < 0.85:
        return None
    return decoded


def _decode_hex_candidate(value):
    text = str(value or "").strip()
    if len(text) < 16 or len(text) > 40000 or not HEX_BLOB_RE.match(text):
        return None
    try:
        raw = bytes.fromhex(text)
        decoded = raw.decode("utf-8")
    except Exception:
        return None
    if _printable_ratio(decoded) < 0.85:
        return None
    return decoded


def _interesting_decoded(text):
    low = text.lower()
    return (
        URL_RE.search(text) is not None
        or "api/webhooks" in low
        or "api.telegram.org" in low
        or "http.request" in low
        or "socket.http" in low
        or "ssl.https" in low
        or "requests." in low
    )


def _encoded_findings(source, starts, lines):
    findings = []
    seen = set()
    candidates = []
    for match in QUOTED_RE.finditer(source):
        candidates.append((match.group("s"), match.start(), "quoted"))
        if len(candidates) >= 2000:
            break
    if len(candidates) < 2000:
        for match in LONG_STRING_RE.finditer(source):
            candidates.append((match.group(1), match.start(), "long"))
            if len(candidates) >= 2000:
                break
    for match in STRING_CHAR_RE.finditer(source):
        nums = [int(x) for x in re.findall(r"\d+", match.group(1))][:20000]
        if not nums:
            continue
        try:
            decoded = bytes([n for n in nums if 0 <= n <= 255]).decode("utf-8", "replace")
        except Exception:
            continue
        if _interesting_decoded(decoded):
            line = _line_at(starts, match.start())
            key = (line, "string.char", sha256_hex(decoded.encode("utf-8")))
            if key not in seen:
                seen.add(key)
                findings.append({"line": line, "encoding": "string.char", "decoded_preview": _redact_text(decoded, 280), "context": _redact_text(_line_text(lines, line), 220)})
        if len(findings) >= MAX_ENCODED:
            return findings

    for value, position, kind in candidates:
        if len(findings) >= MAX_ENCODED:
            break
        line = _line_at(starts, position)
        decoded = None
        encoding = None
        if "\\x" in value or re.search(r"\\[0-9]{2,3}", value):
            candidate = _decode_lua_escapes(value)
            if _interesting_decoded(candidate):
                decoded = candidate
                encoding = "escaped-string"
        if decoded is None:
            candidate = _decode_base64_candidate(value)
            if candidate and _interesting_decoded(candidate):
                decoded = candidate
                encoding = "base64"
        if decoded is None:
            candidate = _decode_hex_candidate(value)
            if candidate and _interesting_decoded(candidate):
                decoded = candidate
                encoding = "hex"
        if decoded is None:
            continue
        digest = sha256_hex(decoded.encode("utf-8"))
        key = (line, encoding, digest)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "line": line,
                "encoding": encoding,
                "decoded_preview": _redact_text(decoded, 280),
                "context": _redact_text(_line_text(lines, line), 220),
            }
        )
    return findings


def _obfuscation_findings(source, starts):
    low = source[:600000].lower()
    indicators = []

    def add(code, detail, line=None):
        indicators.append({"code": code, "detail": detail, "line": line})

    for name in ("moonsec", "ironbrew", "prometheus", "luraph", "luaobfuscator"):
        pos = low.find(name)
        if pos != -1:
            add("engine-keyword", name, _line_at(starts, pos))
    for keyword in ("loadstring", "load(", "setfenv", "getfenv", "bit32", "string.char", "while true do"):
        pos = low.find(keyword)
        if pos != -1:
            add("dynamic-or-vm-code", keyword, _line_at(starts, pos))
    hex_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", source))
    if hex_count:
        add("escaped-strings", str(hex_count) + " hex escape sequences")
    if re.search(r"[A-Za-z0-9+/]{80,}={0,2}", source):
        add("encoded-blob", "large base64-like blob")
    if len(source) > 20000 and source.count("\n") < 20:
        add("minified", "large source with very few lines")
    if source.count("while ") >= 3 or source.count("repeat ") >= 3:
        add("control-flow", "repeated loops")

    score = min(100, len(indicators) * 14)
    hint = "Unknown"
    if "moonsec" in low:
        hint = "MoonSec"
    elif "ironbrew" in low:
        hint = "IronBrew"
    elif "prometheus" in low:
        hint = "Prometheus"
    elif "luraph" in low:
        hint = "Luraph"
    elif indicators:
        hint = "Obfuscated (unknown engine)"
    return {
        "detected": bool(indicators),
        "score": score,
        "hint": hint,
        "indicators": indicators[:30],
    }


def _infer_method(api, source, start, end):
    low_api = api.lower()
    for method in METHOD_WORDS:
        if low_api.endswith("." + method.lower()):
            return method
    window = source[max(0, start - 200) : min(len(source), end + 500)]
    match = re.search(r"[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']", window, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return "UNKNOWN"


def _record_url(result, raw, line, offset, source_label):
    clean = _clean_url(raw)
    if not clean:
        return
    redacted = redact_url(clean)
    if not redacted:
        return
    try:
        parts = urllib.parse.urlsplit(clean)
        host = parts.hostname or ""
        path = urllib.parse.urlsplit(redacted).path or ""
    except ValueError:
        host = ""
        path = ""
    key = (line, redacted)
    if key in result["_url_keys"] or len(result["urls"]) >= MAX_URLS:
        return
    result["_url_keys"].add(key)
    result["urls"].append(
        {
            "line": line,
            "offset": offset,
            "url": redacted,
            "raw_url": clean,
            "hostname": host,
            "path": path,
            "source": source_label,
        }
    )


def _scan_source_text(source, label="source"):
    starts = _line_starts(source)
    lines = source.splitlines()
    result = {
        "coverage": {
            "read": label,
            "line_numbers": True,
            "partial": False,
            "notes": [],
        },
        "urls": [],
        "discord_webhooks": [],
        "telegram_endpoints": [],
        "request_calls": [],
        "libraries": [],
        "http_methods": [],
        "encoded_strings": [],
        "obfuscation": {"detected": False, "score": 0, "hint": "Unknown", "indicators": []},
        "_url_keys": set(),
    }
    methods = set()
    for match in URL_RE.finditer(source):
        line = _line_at(starts, match.start())
        _record_url(result, match.group(0), line, None, label)
    for match in WEBHOOK_RE.finditer(source):
        line = _line_at(starts, match.start())
        if len(result["discord_webhooks"]) < MAX_FINDINGS:
            result["discord_webhooks"].append(
                {
                    "line": line,
                    "url": redact_url(match.group(0)),
                    "raw_url": _clean_url(match.group(0)),
                    "context": _redact_text(_line_text(lines, line), 220),
                }
            )
        methods.update({"POST", "GET"})
    for match in TELEGRAM_RE.finditer(source):
        line = _line_at(starts, match.start())
        if len(result["telegram_endpoints"]) < MAX_FINDINGS:
            result["telegram_endpoints"].append(
                {
                    "line": line,
                    "url": redact_url(match.group(0)),
                    "raw_url": _clean_url(match.group(0)),
                    "context": _redact_text(_line_text(lines, line), 220),
                }
            )
        methods.add("POST")
    for match in TELEGRAM_TOKEN_RE.finditer(source):
        line = _line_at(starts, match.start())
        if len(result["telegram_endpoints"]) < MAX_FINDINGS:
            result["telegram_endpoints"].append(
                {
                    "line": line,
                    "url": "https://api.telegram.org/bot[redacted]",
                    "raw_url": "https://api.telegram.org/" + match.group(0),
                    "context": _redact_text(_line_text(lines, line), 220),
                }
            )
        methods.add("POST")

    for match in REQUIRE_RE.finditer(source):
        name = match.group(1).strip()
        line = _line_at(starts, match.start())
        if len(result["libraries"]) < MAX_FINDINGS:
            result["libraries"].append(
                {
                    "line": line,
                    "name": name,
                    "dynamic_supported": name in DYNAMIC_LIBRARIES,
                    "context": _redact_text(_line_text(lines, line), 220),
                }
            )

    for api, pattern in REQUEST_PATTERNS:
        if len(result["request_calls"]) >= 150:
            break
        for match in pattern.finditer(source):
            line = _line_at(starts, match.start())
            method = _infer_method(api, source, match.start(), match.end())
            if method != "UNKNOWN":
                methods.add(method)
            nearby = source[match.start() : min(len(source), match.start() + 700)]
            url_match = URL_RE.search(nearby)
            result["request_calls"].append(
                {
                    "line": line,
                    "api": api,
                    "method": method,
                    "url": redact_url(url_match.group(0)) if url_match else None,
                    "raw_url": _clean_url(url_match.group(0)) if url_match else None,
                    "context": _redact_text(_line_text(lines, line), 240),
                }
            )
            if len(result["request_calls"]) >= 150:
                break

    result["http_methods"] = sorted(methods)
    result["encoded_strings"] = _encoded_findings(source, starts, lines)
    result["obfuscation"] = _obfuscation_findings(source, starts)
    if len(result["urls"]) >= MAX_URLS:
        result["coverage"]["notes"].append("URL evidence was capped at " + str(MAX_URLS) + " items.")
    if len(result["discord_webhooks"]) >= MAX_FINDINGS or len(result["telegram_endpoints"]) >= MAX_FINDINGS:
        result["coverage"]["notes"].append("Endpoint evidence was capped at " + str(MAX_FINDINGS) + " items per type.")
    result.pop("_url_keys", None)
    return result


def _extract_printable_strings(data):
    strings = []
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        try:
            text = match.group(0).decode("ascii")
        except UnicodeDecodeError:
            continue
        strings.append((text, match.start()))
        if len(strings) >= MAX_BINARY_STRINGS:
            break
    return strings


def _scan_binary_strings(data, label="bytecode_strings"):
    result = {
        "coverage": {
            "read": label,
            "line_numbers": False,
            "partial": True,
            "notes": ["Source lines are unavailable. Findings come from printable strings embedded in bytecode."],
        },
        "urls": [],
        "discord_webhooks": [],
        "telegram_endpoints": [],
        "request_calls": [],
        "libraries": [],
        "http_methods": [],
        "encoded_strings": [],
        "obfuscation": {"detected": True, "score": 40, "hint": "Bytecode", "indicators": [{"code": "bytecode", "detail": label, "line": None}]},
        "_url_keys": set(),
    }
    methods = set()
    strings = _extract_printable_strings(data)
    for text, offset in strings:
        for match in URL_RE.finditer(text):
            _record_url(result, match.group(0), None, offset, "bytecode_string")
        for match in WEBHOOK_RE.finditer(text):
            if len(result["discord_webhooks"]) < MAX_FINDINGS:
                result["discord_webhooks"].append({"line": None, "offset": offset, "url": redact_url(match.group(0)), "raw_url": _clean_url(match.group(0)), "context": _redact_text(text, 220)})
            methods.update({"POST", "GET"})
        for match in TELEGRAM_RE.finditer(text):
            if len(result["telegram_endpoints"]) < MAX_FINDINGS:
                result["telegram_endpoints"].append({"line": None, "offset": offset, "url": redact_url(match.group(0)), "raw_url": _clean_url(match.group(0)), "context": _redact_text(text, 220)})
            methods.add("POST")
        for api, pattern in REQUEST_PATTERNS:
            if len(result["request_calls"]) >= 150:
                break
            for match in pattern.finditer(text):
                result["request_calls"].append(
                    {
                        "line": None,
                        "offset": offset,
                        "api": api,
                        "method": _infer_method(api, text, match.start(), match.end()),
                        "url": None,
                        "context": _redact_text(text, 240),
                    }
                )
                if len(result["request_calls"]) >= 150:
                    break
    result["http_methods"] = sorted(methods)
    result.pop("_url_keys", None)
    return result


def scan_source(source):
    return _scan_source_text(source, "source")


def _load_deob_engine():
    global _DEOB_MODULE, _DEOB_ERROR
    if _DEOB_MODULE is not None:
        return _DEOB_MODULE
    if _DEOB_ERROR is not None:
        raise RuntimeError(_DEOB_ERROR)
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "api", "lua-deob.py")
    try:
        spec = importlib.util.spec_from_file_location("rm7_lua_deob_engine", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Lua deobfuscation module was not found")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _DEOB_MODULE = module
        return module
    except Exception as exc:
        _DEOB_ERROR = "The existing deobfuscation engine is unavailable: " + str(exc)[:200]
        raise RuntimeError(_DEOB_ERROR)


def verify_session_uid(headers):
    secret = (os.environ.get("SESSION_SECRET") or "").strip()
    if not secret:
        return None
    cookie = headers.get("Cookie") or headers.get("cookie") or ""
    session = re.search(r"rm7_session=([^;]+)", cookie)
    uid_cookie = re.search(r"rm7_uid=([^;]+)", cookie)
    if not session or not uid_cookie or "." not in session.group(1) or "." not in uid_cookie.group(1):
        return None
    token, signature = session.group(1).rsplit(".", 1)
    expected = base64.urlsafe_b64encode(hmac.new(secret.encode(), token.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    if not hmac.compare_digest(expected, signature):
        return None
    uid, uid_signature = uid_cookie.group(1).rsplit(".", 1)
    expected_uid = base64.urlsafe_b64encode(hmac.new(secret.encode(), uid.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    if not hmac.compare_digest(expected_uid, uid_signature):
        return None
    return uid if re.fullmatch(r"\d{17,20}", uid) else None


def verify_premium_token(token):
    try:
        pad = "=" * (-len(token) % 4)
        decoded = base64.urlsafe_b64decode(token + pad).decode()
        parts = decoded.split(":")
        if len(parts) < 3:
            return None
        sig = parts.pop()

        discord_user_id = None
        if (
            len(parts) >= 3
            and re.fullmatch(r"\d{17,20}", parts[-1] or "")
            and re.fullmatch(r"\d{10,17}", parts[-2] or "")
        ):
            discord_user_id = parts.pop()

        ts = parts.pop()
        if not re.fullmatch(r"\d+", ts or ""):
            return None
        key = ":".join(parts)
        if not key:
            return None

        payload = f"{key}:{ts}:{discord_user_id}" if discord_user_id else f"{key}:{ts}"
        if not PREMIUM_SECRET:
            return None
        expected = hmac.new(PREMIUM_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        if int(time.time() * 1000) - int(ts) > PREMIUM_TOKEN_TTL_MS:
            return None
        return {"key": key, "discord_user_id": discord_user_id, "issued_at": int(ts), "legacy": not bool(discord_user_id)}
    except Exception:
        return None


def is_premium_request(headers, uid):
    cookie = headers.get("Cookie") or headers.get("cookie") or ""
    match = re.search(r"premium_token=([^;]+)", cookie)
    token = match.group(1) if match else ""
    authorization = headers.get("Authorization") or headers.get("authorization") or ""
    if not token and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    parsed = verify_premium_token(token) if token else None
    if not parsed:
        return False
    bound_uid = parsed.get("discord_user_id")
    if bound_uid and str(bound_uid) != str(uid):
        return False
    return True


def deobfuscate(data, filename, classification):
    module = None
    try:
        module = _load_deob_engine()
    except Exception as exc:
        return {"status": "unavailable", "engine": None, "detected": "Unknown", "error_code": "DEOBFUSCATOR_UNAVAILABLE", "error": str(exc), "source": None}

    kind = classification.get("kind")
    source_text = None
    if kind == "luajit_bytecode":
        try:
            source_text = module.decompile_bytes(data)
            detected = module.detect_obfuscator_type(source_text)
            engine = "ljd"
        except Exception as exc:
            return {"status": "failed", "engine": "ljd", "detected": "LuaJIT bytecode", "error_code": "DECOMPILATION_FAILED", "error": str(exc)[:300], "source": None}
    elif kind == "lua_source":
        try:
            source_text = data.decode("utf-8")
            detected = module.detect_obfuscator_type(source_text)
        except Exception as exc:
            return {"status": "failed", "engine": None, "detected": "Unknown", "error_code": "DEOBFUSCATION_FAILED", "error": str(exc)[:300], "source": None}
        low = str(detected).lower()
        if "moonsec" in low:
            if not getattr(module, "HAS_MOONSEC_CS", False):
                return {"status": "unavailable", "engine": "moonsec", "detected": detected, "error_code": "DEOBFUSCATOR_BINARY_MISSING", "error": "The MoonSec deobfuscator is not installed on this deployment.", "source": None}
            try:
                source_text = module.run_moonsec_cs(source_text)
                engine = "moonsec"
            except Exception as exc:
                return {"status": "failed", "engine": "moonsec", "detected": detected, "error_code": "DEOBFUSCATION_FAILED", "error": str(exc)[:300], "source": None}
        elif "prometheus" in low or "ironbrew" in low or "luraph" in low:
            return {"status": "skipped", "engine": None, "detected": detected, "error_code": "UNSUPPORTED_OBFUSCATOR", "error": "The detected obfuscator is not supported by the existing deobfuscation engine.", "source": None}
        else:
            return {"status": "skipped", "engine": None, "detected": detected, "error_code": "NO_SUPPORTED_OBFUSCATION", "error": None, "source": None}
    else:
        return {"status": "skipped", "engine": None, "detected": classification.get("lua_version", "Unknown"), "error_code": "UNSUPPORTED_FORMAT", "error": "Deobfuscation is not supported for this file format.", "source": None}

    if not source_text or len(source_text.strip()) < 20:
        return {"status": "failed", "engine": engine, "detected": detected, "error_code": "EMPTY_DEOBFUSCATION_OUTPUT", "error": "The deobfuscator returned no usable source.", "source": None}
    encoded = source_text.encode("utf-8", "replace")
    if len(encoded) > MAX_DEOBFUSCATED_BYTES:
        return {"status": "failed", "engine": engine, "detected": detected, "error_code": "DEOBFUSCATED_OUTPUT_TOO_LARGE", "error": "The deobfuscated output exceeded the size limit.", "source": None}
    return {"status": "completed", "engine": engine, "detected": detected, "error_code": None, "error": None, "source": source_text}


STRONG_CREDENTIAL_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9])pass(?![A-Za-z0-9])|password|passwd|pwd|secret|token|authorization|cookie|session|api[_-]?key|access[_-]?key|refresh[_-]?token|private[_-]?key|license",
    re.IGNORECASE,
)
EXFIL_SINK_HOSTS = {
    "discord.com": "Discord webhook",
    "discordapp.com": "Discord webhook",
    "api.telegram.org": "Telegram bot API",
}


def _clean_field_name(name):
    return re.sub(r"^[^0-9A-Za-z]+|[^0-9A-Za-z]+$", "", str(name or ""))[:60].lower()


def _collect_sensitive_fields(value, depth=0, out=None):
    out = out if out is not None else set()
    if depth > 8 or len(out) >= 20:
        return out
    if isinstance(value, dict):
        for key, item in list(value.items())[:80]:
            name = _clean_field_name(key)
            if name and SENSITIVE_NAME_RE.search(name):
                out.add(name)
            if name in ("name", "field", "label", "key") and isinstance(item, str):
                label = _clean_field_name(item)
                if label and SENSITIVE_NAME_RE.search(label):
                    out.add(label)
            _collect_sensitive_fields(item, depth + 1, out)
    elif isinstance(value, list):
        for item in value[:40]:
            _collect_sensitive_fields(item, depth + 1, out)
    elif isinstance(value, str):
        text = value.strip()
        if len(text) <= 2 * 1024 * 1024:
            if text.startswith("{") or text.startswith("["):
                try:
                    parsed = json.loads(text)
                except Exception:
                    parsed = None
                if parsed is not None:
                    _collect_sensitive_fields(parsed, depth + 1, out)
            for match in re.finditer(r"(?i)(?:^|[&;,\s{\"'])([A-Za-z0-9_.\-]{1,60})\s*[:=]", text):
                name = _clean_field_name(match.group(1))
                if name and SENSITIVE_NAME_RE.search(name):
                    out.add(name)
    return out


def _request_sensitive_fields(url, headers, body):
    fields = set()
    try:
        query = urllib.parse.urlsplit(str(url or "")).query
        for key, _ in urllib.parse.parse_qsl(query, keep_blank_values=True):
            name = _clean_field_name(key)
            if name and SENSITIVE_NAME_RE.search(name):
                fields.add(name)
    except ValueError:
        pass
    if isinstance(headers, dict):
        for name in list(headers.keys())[:60]:
            cleaned = _clean_field_name(name)
            if cleaned and SENSITIVE_NAME_RE.search(cleaned):
                fields.add(cleaned)
    elif isinstance(headers, list):
        for item in headers[:60]:
            if isinstance(item, (list, tuple)) and item:
                cleaned = _clean_field_name(item[0])
                if cleaned and SENSITIVE_NAME_RE.search(cleaned):
                    fields.add(cleaned)
    _collect_sensitive_fields(body, 0, fields)
    return sorted(fields)[:20]


def _request_signature(item):
    body = item.get("body")
    try:
        body_key = json.dumps(body, sort_keys=True, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body or "")
    except Exception:
        body_key = str(body or "")
    return (
        str(item.get("method") or "").upper(),
        str(item.get("raw_url") or item.get("url") or ""),
        body_key[:MAX_BODY_CHARS],
    )


def _dedupe_dynamic_requests(requests):
    deduped = []
    positions = {}
    for item in requests:
        key = _request_signature(item)
        existing_index = positions.get(key)
        if existing_index is not None:
            existing = deduped[existing_index]
            known_engines = set(existing.get("observed_by") or [existing.get("engine") or "mock"])
            if item.get("engine") not in known_engines or len(known_engines) > 1:
                merged = sorted(known_engines | {item.get("engine") or "mock"})
                existing["observed_by"] = merged
                existing["sensitive_fields"] = sorted(set(existing.get("sensitive_fields") or []) | set(item.get("sensitive_fields") or []))[:20]
                existing["credential_like"] = bool(existing.get("credential_like") or item.get("credential_like"))
                existing["synthetic_login_input"] = bool(existing.get("synthetic_login_input") or item.get("synthetic_login_input"))
                if len(str(item.get("body") or "")) > len(str(existing.get("body") or "")):
                    existing["body"] = item.get("body")
                continue
        positions[key] = len(deduped)
        deduped.append(item)
        if len(deduped) >= MAX_REQUESTS:
            break
    for index, item in enumerate(deduped):
        item["number"] = index + 1
    return deduped


def normalize_dynamic_requests(raw_requests):
    requests = []
    for index, item in enumerate((raw_requests or [])[:MAX_REQUESTS]):
        if not isinstance(item, dict):
            continue
        raw_url = str(item.get("url") or "")[:4000]
        raw_headers = item.get("headers")
        raw_body = item.get("body")
        sensitive_fields = _request_sensitive_fields(raw_url, raw_headers, raw_body)
        redacted = redact_url(raw_url)
        hostname = str(item.get("hostname") or "").strip()[:255]
        path_value = ""
        try:
            parts = urllib.parse.urlsplit(redacted)
            hostname = hostname or (parts.hostname or "")[:255]
            path_value = (parts.path or "")[:2000]
        except ValueError:
            path_value = str(item.get("path") or "").strip()[:2000]
        body = redact_body(raw_body)
        payload = item.get("json")
        if payload is None and isinstance(body, (dict, list)):
            payload = body
        engine = str(item.get("capture_engine") or item.get("engine") or "mock")[:40]
        observed_by = item.get("observed_by")
        if not isinstance(observed_by, list):
            observed_by = [engine]
        observed_by = [str(value)[:40] for value in observed_by[:8] if str(value or "").strip()]
        requests.append(
            {
                "number": index + 1,
                "method": str(item.get("method") or "UNKNOWN").upper()[:16],
                "url": redacted,
                "raw_url": _clean_url(raw_url),
                "hostname": hostname,
                "path": path_value,
                "headers": redact_headers(raw_headers),
                "body": body,
                "json_payload": _redact_json_value(payload) if payload is not None else None,
                "api": str(item.get("api") or "unknown")[:80],
                "source": _redact_text(item.get("source"), 120) if item.get("source") else None,
                "event": str(item.get("event") or "")[:80] or None,
                "timestamp": str(item.get("timestamp") or datetime.now(timezone.utc).isoformat())[:40],
                "capture_status": "Observed (not sent)" if item.get("sent") else "Intercepted and blocked (not sent)",
                "engine": engine,
                "observed_by": observed_by,
                "sensitive_fields": sensitive_fields,
                "credential_like": bool(sensitive_fields),
                "synthetic_login_input": bool(item.get("synthetic_login_input")),
                "intercepted": bool(item.get("intercepted", not item.get("sent"))),
                "blocked": bool(item.get("blocked", not item.get("sent"))),
                "sent": bool(item.get("sent")),
            }
        )
    return _dedupe_dynamic_requests(requests)


def normalize_dynamic_metadata(raw_metadata):
    if not isinstance(raw_metadata, dict):
        return {}
    metadata = {}
    for key, value in list(raw_metadata.items())[:40]:
        name = str(key or "").strip()[:80]
        if not name:
            continue
        if isinstance(value, (dict, list)):
            metadata[name] = _redact_json_value(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            metadata[name] = _redact_text(str(value), 500)
        else:
            metadata[name] = _redact_text(str(value), 500)
    return metadata


def normalize_unsupported_api(value):
    text = str(value or "").strip()[:160]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:]{0,119}", text):
        return None
    return text


def normalize_missing_module(value):
    text = str(value or "").strip()[:160]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,159}", text) or ".." in text:
        return None
    return text


def normalize_dynamic_observations(raw_observations):
    observations = []
    for item in (raw_observations or [])[:50]:
        if not isinstance(item, dict):
            continue
        event = str(item.get("event") or "event")[:80]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", event):
            event = "event"
        reason = str(item.get("reason") or "error")[:40]
        if reason not in ("observation_window", "instruction_limit", "lua_timeout", "error", "compile"):
            reason = "error"
        observations.append(
            {
                "event": event,
                "reason": reason,
                "error": _redact_text(item.get("error") or "", 300),
            }
        )
    return observations


def normalize_events_run(raw_events):
    events = []
    for item in (raw_events or [])[:30]:
        name = str(item or "").strip()[:80]
        if name and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", name) and name not in events:
            events.append(name)
    return events


def normalize_runtime_limits(raw_limits):
    if not isinstance(raw_limits, dict):
        return {}
    limits = {}
    for key in ("lua_budget_ms", "event_budget_ms", "simulation_budget_ms", "max_wait_calls", "max_virtual_ms", "max_instructions"):
        try:
            values = int(raw_limits.get(key))
        except Exception:
            continue
        if values > 0:
            limits[key] = values
    if raw_limits.get("network"):
        limits["network"] = str(raw_limits.get("network"))[:40]
    if raw_limits.get("lua_compatibility"):
        limits["lua_compatibility"] = str(raw_limits.get("lua_compatibility"))[:60]
    limits["virtual_clock"] = bool(raw_limits.get("virtual_clock"))
    return limits


def normalize_compatibility(raw_compatibility):
    if not isinstance(raw_compatibility, dict):
        return None
    name = normalize_unsupported_api(raw_compatibility.get("name"))
    code = str(raw_compatibility.get("code") or "LUA_VM_COMPATIBILITY")[:60]
    note = _redact_text(raw_compatibility.get("note") or "", 300)
    if not name and not note:
        return None
    return {"code": code, "name": name, "note": note}


def normalize_simulated_inputs(raw_inputs):
    inputs = []
    for item in (raw_inputs or [])[:20]:
        if not isinstance(item, dict):
            continue
        event = str(item.get("event") or "event")[:80]
        field = str(item.get("field") or "input")[:80]
        kind = str(item.get("kind") or "synthetic")[:40]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", event):
            event = "event"
        inputs.append({"event": event, "field": field, "kind": kind, "synthetic": True})
    return inputs


def public_runtime_label(value):
    text = str(value or "").strip()
    if not text:
        return SANDBOX_RUNTIME_LABEL
    if re.search(r"vercel|wasm|wasmoon", text, re.IGNORECASE):
        return SANDBOX_RUNTIME_LABEL
    return text[:80]


def public_coverage_note(value):
    text = str(value or "")
    text = re.sub(r"Vercel Sandbox", "isolated sandbox", text, flags=re.IGNORECASE)
    text = re.sub(r"\bWASM\b", "Lua runtime", text, flags=re.IGNORECASE)
    text = re.sub(r"\bWasmoon\b", "Lua runtime", text, flags=re.IGNORECASE)
    return text[:300]


def _sandbox_result(status, error_code=None, error=None, requests=None, execution_completed=False, timed_out=False, runtime=None, coverage_notes=None, metadata=None, unsupported_api=None, observations=None, events_run=None, runtime_limits=None, compatibility=None, simulated_inputs=None, missing_module=None):
    return {
        "status": status,
        "error_code": error_code,
        "error": error,
        "requests": list(requests or []),
        "execution_completed": bool(execution_completed),
        "timed_out": bool(timed_out),
        "runtime": public_runtime_label(runtime) if runtime else None,
        "metadata": normalize_dynamic_metadata(metadata),
        "unsupported_api": normalize_unsupported_api(unsupported_api),
        "missing_module": normalize_missing_module(missing_module),
        "compatibility": normalize_compatibility(compatibility),
        "simulated_inputs": normalize_simulated_inputs(simulated_inputs),
        "observations": normalize_dynamic_observations(observations),
        "events_run": normalize_events_run(events_run),
        "runtime_limits": normalize_runtime_limits(runtime_limits),
        "coverage_notes": [public_coverage_note(x) for x in (coverage_notes or [])[:20]],
    }


def _sandbox_assets_available():
    return all(os.path.isfile(path) and os.path.getsize(path) > 0 for path in (
        SANDBOX_RUNTIME_PATH,
        SANDBOX_PRELUDE_PATH,
        SANDBOX_WASMOON_INDEX_PATH,
        SANDBOX_WASMOON_GLUE_PATH,
    ))


def _sandbox_asset_bytes():
    paths = {
        "runtime.mjs": SANDBOX_RUNTIME_PATH,
        "sandbox-prelude.lua": SANDBOX_PRELUDE_PATH,
        "vendor/wasmoon/index.js": SANDBOX_WASMOON_INDEX_PATH,
        "vendor/wasmoon/glue.wasm": SANDBOX_WASMOON_GLUE_PATH,
    }
    assets = {}
    try:
        for name, path in paths.items():
            with open(path, "rb") as handle:
                assets[name] = handle.read()
    except OSError:
        return None
    return assets


def _load_sandbox_sdk():
    global _SANDBOX_SDK, _SANDBOX_SDK_ERROR
    if _SANDBOX_SDK is not None:
        return _SANDBOX_SDK
    if _SANDBOX_SDK_ERROR is not None:
        raise RuntimeError(_SANDBOX_SDK_ERROR)
    try:
        from vercel.sandbox import NetworkPolicy, SandboxApiError, SandboxCredentialsError, SandboxResources, SandboxTimeoutError
        from vercel.sandbox import sync as sync_sandbox

        _SANDBOX_SDK = {
            "sync": sync_sandbox,
            "NetworkPolicy": NetworkPolicy,
            "SandboxResources": SandboxResources,
            "SandboxApiError": SandboxApiError,
            "SandboxCredentialsError": SandboxCredentialsError,
            "SandboxTimeoutError": SandboxTimeoutError,
        }
        return _SANDBOX_SDK
    except Exception as exc:
        _SANDBOX_SDK_ERROR = "The sandbox SDK is unavailable: " + str(exc)[:200]
        raise RuntimeError(_SANDBOX_SDK_ERROR)


def sandbox_available():
    if str(os.environ.get("GRAB_DETECTOR_SANDBOX_DISABLED", "")).strip().lower() in ("1", "true", "yes", "on"):
        return False
    if not _sandbox_assets_available():
        return False
    try:
        _load_sandbox_sdk()
    except Exception:
        return False
    return bool(any((os.environ.get(name) or "").strip() for name in ("VERCEL", "VERCEL_ENV", "VERCEL_OIDC_TOKEN")))


def _sandbox_month_key():
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _sandbox_db_month_used():
    dsn = (os.environ.get("DATABASE_URL") or "").strip()
    if not dsn:
        return None
    try:
        import psycopg2
        conn = psycopg2.connect(_pg_dsn(dsn), connect_timeout=4)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) FROM public.audit_logs "
                    "WHERE event_type = 'service.grab_detector' "
                    "AND status IN ('success', 'info') "
                    "AND details->>'mode' = 'performed' "
                    "AND created_at >= date_trunc('month', now())"
                )
                row = cur.fetchone()
            return int(row[0] or 0)
        finally:
            conn.close()
    except Exception:
        return None


def _sandbox_month_used():
    key = _sandbox_month_key()
    with _SANDBOX_MONTH_LOCK:
        if _SANDBOX_MONTH_MEMORY.get("key") != key:
            _SANDBOX_MONTH_MEMORY["key"] = key
            _SANDBOX_MONTH_MEMORY["count"] = 0
        memory_count = int(_SANDBOX_MONTH_MEMORY.get("count") or 0)
    database_count = _sandbox_db_month_used()
    return max(memory_count, database_count or 0)


def record_sandbox_use():
    key = _sandbox_month_key()
    with _SANDBOX_MONTH_LOCK:
        if _SANDBOX_MONTH_MEMORY.get("key") != key:
            _SANDBOX_MONTH_MEMORY["key"] = key
            _SANDBOX_MONTH_MEMORY["count"] = 0
        _SANDBOX_MONTH_MEMORY["count"] = int(_SANDBOX_MONTH_MEMORY.get("count") or 0) + 1


def _sandbox_error_result(exc):
    status_code = getattr(exc, "status_code", None)
    api_code = str(getattr(exc, "code", "") or "").lower()
    message = str(exc or "").lower()
    sdk = _SANDBOX_SDK or {}
    timeout_types = tuple(
        item for item in (sdk.get("SandboxTimeoutError"),) if isinstance(item, type)
    )
    if status_code in (402, 429) or "quota" in api_code or "quota" in message or "concurrency" in message or "too many" in message:
        return _sandbox_result(
            "unavailable",
            "SANDBOX_QUOTA_EXCEEDED",
            "Sandbox quota or concurrency limit was reached. Try again later.",
            coverage_notes=["The file was not executed because the sandbox quota is exhausted."],
        )
    if status_code in (401, 403) or isinstance(exc, tuple(item for item in (sdk.get("SandboxCredentialsError"),) if isinstance(item, type))):
        return _sandbox_result(
            "unavailable",
            "SANDBOX_AUTH_FAILED",
            "Sandbox authentication is unavailable for this deployment.",
            coverage_notes=["The file was not executed because the sandbox could not authenticate."],
        )
    if timeout_types and isinstance(exc, timeout_types):
        return _sandbox_result(
            "failed",
            "SANDBOX_TIMEOUT",
            "The sandbox did not become ready in time.",
            coverage_notes=["The file was not executed because sandbox setup timed out."],
        )
    return _sandbox_result(
        "unavailable",
        "SANDBOX_UNAVAILABLE",
        "The sandbox could not be started.",
        coverage_notes=["The file was not executed. Static and deobfuscation results remain available."],
    )


def _parse_sandbox_output(stdout):
    captured = []
    final = None
    for line in str(stdout or "").splitlines()[:20000]:
        line = line.strip()
        if not line or len(line) > 256 * 1024:
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "request" and isinstance(event.get("request"), dict):
            captured.append(event["request"])
        elif event.get("type") == "result" and isinstance(event.get("result"), dict):
            final = event["result"]
    return captured, final


def _merge_sandbox_requests(*groups):
    merged = []
    seen = set()
    for group in groups:
        for item in group or []:
            if not isinstance(item, dict):
                continue
            try:
                key = json.dumps(item, sort_keys=True, ensure_ascii=False)
            except Exception:
                key = str(item)
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
            if len(merged) >= MAX_REQUESTS:
                return merged
    return merged


def _read_sandbox_text(box, cwd, name, limit=2 * 1024 * 1024):
    try:
        text = box.fs.read_text(name, cwd=cwd)
    except Exception:
        return ""
    text = str(text or "")
    return text[:limit]


def _read_sandbox_result(box, cwd, name, limit=2 * 1024 * 1024):
    text = _read_sandbox_text(box, cwd, name, limit).strip()
    if not text:
        return None
    try:
        value = json.loads(text)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _sandbox_kill_after(options):
    raw = options.get("sandbox_timeout_ms") or SANDBOX_TIMEOUT_MS
    try:
        timeout_ms = int(raw)
    except Exception:
        timeout_ms = SANDBOX_TIMEOUT_MS
    return min(25.0, max(2.0, timeout_ms / 1000.0))


def _run_sandbox(source, filename, options, sdk, assets):
    timeout = _sandbox_kill_after(options)
    box = None
    started = time.monotonic()
    try:
        box = sdk["sync"].create_sandbox(
            resources=sdk["SandboxResources"](vcpus=1),
            execution_time_limit=min(120.0, timeout + 20.0),
            persistent=False,
            network_policy=sdk["NetworkPolicy"].deny_all(),
            tags={"service": "grab-detector"},
            destroy=False,
        )
        record_sandbox_use()
        box.update_network_policy(sdk["NetworkPolicy"].deny_all())

        cwd = getattr(box, "cwd", None) or "/vercel/sandbox"
        box.fs.mkdir("input", cwd=cwd, recursive=True)
        box.fs.mkdir("vendor/wasmoon", cwd=cwd, recursive=True)
        with box.fs.batch(cwd=cwd) as batch:
            for name, content in assets.items():
                batch.write_bytes(name, content)
            batch.write_text("input/scan.lua", source, encoding="utf-8", errors="replace")

        process = box.run_process(
            "node",
            ["--max-old-space-size=256", "runtime.mjs"],
            cwd=cwd,
            env={
                "GD_MAX_REQUESTS": str(min(MAX_REQUESTS, 500)),
                "GD_MAX_BODY": "8192",
                "GD_SOURCE_PATH": "input/scan.lua",
                "GD_PRELUDE_PATH": "sandbox-prelude.lua",
                "GD_REQUESTS_PATH": "requests.ndjson",
                "GD_RESULT_PATH": "result.json",
                "GD_FILE_NAME": safe_filename(filename),
                "GD_LUA_BUDGET_MS": str(SANDBOX_LUA_BUDGET_MS),
                "GD_EVENT_BUDGET_MS": str(SANDBOX_EVENT_BUDGET_MS),
                "GD_SIMULATION_BUDGET_MS": str(SANDBOX_SIMULATION_BUDGET_MS),
                "GD_MAX_WAIT_CALLS": str(SANDBOX_MAX_WAIT_CALLS),
                "GD_MAX_VIRTUAL_MS": str(SANDBOX_MAX_VIRTUAL_MS),
                "GD_MAX_INSTRUCTIONS": str(SANDBOX_MAX_INSTRUCTIONS),
            },
            kill_after=timeout,
            capture_output=True,
        )
        elapsed = time.monotonic() - started
        stdout = process.stdout or ""
        if len(stdout) > 8 * 1024 * 1024:
            return _sandbox_result(
                "failed",
                "SANDBOX_OUTPUT_TOO_LARGE",
                "The isolated Lua runtime returned too much data.",
                coverage_notes=["The sandbox output was discarded because it exceeded the limit."],
            )

        captured, final = _parse_sandbox_output(stdout)
        file_captured, _ = _parse_sandbox_output(_read_sandbox_text(box, cwd, "requests.ndjson"))
        file_final = _read_sandbox_result(box, cwd, "result.json")
        if final is None and file_final is not None:
            final = file_final
        captured = _merge_sandbox_requests(captured, file_captured)
        timed_out = bool(
            (not final and process.returncode in (137, 143, -9))
            or (not final and elapsed >= max(0.5, timeout - 0.25))
        )
        if not final:
            if timed_out:
                return _sandbox_result(
                    "failed",
                    "EXECUTION_TIMEOUT",
                    "Lua execution exceeded the sandbox time limit.",
                    requests=captured,
                    timed_out=True,
                    runtime=SANDBOX_RUNTIME_LABEL,
                    coverage_notes=[
                        "Execution was stopped at the sandbox timeout.",
                        "Requests captured before the timeout are included.",
                        "A timeout is not proof of safety or maliciousness.",
                    ],
                )
            stderr = _redact_text(process.stderr or "", 200)
            return _sandbox_result(
                "incomplete" if process.returncode == 0 else "failed",
                "SANDBOX_NO_RESULT" if process.returncode == 0 else "SANDBOX_RUNTIME_FAILED",
                "The isolated Lua runtime ended without a complete result.",
                requests=captured,
                runtime=SANDBOX_RUNTIME_LABEL,
                coverage_notes=[
                    "Requests captured before the runtime ended are included.",
                    ("Runtime error: " + stderr) if stderr else "",
                ],
            )

        requests = final.get("requests") if isinstance(final.get("requests"), list) else []
        requests = _merge_sandbox_requests(requests, captured)
        status = str(final.get("status") or "incomplete")
        if status not in ("completed", "incomplete", "failed", "timeout"):
            status = "incomplete"
        final_timed_out = bool(final.get("timed_out"))
        timed_out = timed_out or final_timed_out
        execution_completed = bool(final.get("execution_completed")) and not timed_out
        if status in ("completed", "timeout") and not execution_completed:
            status = "incomplete" if status != "timeout" else "timeout"
        return _sandbox_result(
            status,
            final.get("error_code"),
            _redact_text(final.get("error"), 300) if final.get("error") else None,
            requests=requests,
            execution_completed=execution_completed,
            timed_out=timed_out,
            runtime=str(final.get("runtime") or SANDBOX_RUNTIME_LABEL)[:80],
            coverage_notes=final.get("coverage_notes") or [],
            metadata=final.get("metadata"),
            unsupported_api=final.get("unsupported_api"),
            missing_module=final.get("missing_module"),
            compatibility=final.get("compatibility"),
            simulated_inputs=final.get("simulated_inputs"),
            observations=final.get("observations"),
            events_run=final.get("events_run"),
            runtime_limits=final.get("runtime_limits"),
        )
    finally:
        if box is not None:
            try:
                box.stop()
            except Exception:
                pass
            try:
                box.destroy()
            except Exception:
                pass


def sandbox_scan(source, filename, options=None, sandbox_sdk=None):
    options = options or {}
    source = source if isinstance(source, str) else str(source or "")
    if not source.strip():
        return _sandbox_result(
            "incomplete",
            "EMPTY_SOURCE",
            "No Lua source was provided.",
            coverage_notes=["The file was not executed."],
        )

    source_bytes = source.encode("utf-8", "replace")
    if len(source_bytes) > MAX_UPLOAD_BYTES:
        return _sandbox_result(
            "unavailable",
            "DYNAMIC_INPUT_TOO_LARGE",
            "The source is too large for dynamic analysis.",
            coverage_notes=["The file was not executed because it exceeded the dynamic-analysis input limit."],
        )

    if sandbox_sdk is None:
        if not _sandbox_assets_available():
            return _sandbox_result(
                "unavailable",
                "SANDBOX_ASSETS_MISSING",
                "The isolated Lua runtime is not installed for this deployment.",
                coverage_notes=["The file was not executed."],
            )
        try:
            sdk = _load_sandbox_sdk()
        except Exception:
            return _sandbox_result(
                "unavailable",
                "SANDBOX_SDK_MISSING",
                "The isolated runtime is unavailable for this deployment.",
                coverage_notes=["The file was not executed."],
            )
        if not sandbox_available():
            return _sandbox_result(
                "unavailable",
                "SANDBOX_NOT_CONFIGURED",
                "Dynamic analysis is not configured for this deployment.",
                coverage_notes=["Runtime credentials were not detected. The file was not executed."],
            )
        if _sandbox_month_used() >= SANDBOX_MONTHLY_LIMIT:
            return _sandbox_result(
                "unavailable",
                "SANDBOX_QUOTA_EXCEEDED",
                "The monthly dynamic-analysis quota has been reached.",
                coverage_notes=[
                    "The file was not executed. Static and deobfuscation results remain available.",
                    "Monthly dynamic-analysis limit: " + str(SANDBOX_MONTHLY_LIMIT) + ".",
                ],
            )
    else:
        sdk = sandbox_sdk

    assets = _sandbox_asset_bytes()
    if not assets:
        return _sandbox_result(
            "unavailable",
            "SANDBOX_ASSETS_MISSING",
            "The isolated Lua runtime is not installed for this deployment.",
            coverage_notes=["The file was not executed."],
        )

    try:
        result = _run_sandbox(source, filename, options, sdk, assets)
    except Exception as exc:
        result = _sandbox_error_result(exc)

    if result.get("runtime"):
        notes = list(result.get("coverage_notes") or [])
        notes.append("The isolated runtime was stopped and destroyed immediately after this run.")
        result["coverage_notes"] = [str(x)[:300] for x in notes[:20]]
    return result



def _vt_submit(data, filename, api_key):
    boundary = "----RM7GrabDetector" + hmac.new(api_key.encode(), os.urandom(16), hashlib.sha256).hexdigest()[:24]
    filename = safe_filename(filename)
    body = bytearray()
    body.extend(("--" + boundary + "\r\n").encode())
    body.extend(('Content-Disposition: form-data; name="file"; filename="' + filename + '"\r\n').encode())
    body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
    body.extend(data)
    body.extend(("\r\n--" + boundary + "--\r\n").encode())
    request = urllib.request.Request(
        "https://www.virustotal.com/api/v3/files",
        data=bytes(body),
        method="POST",
        headers={
            "x-apikey": api_key,
            "Content-Type": "multipart/form-data; boundary=" + boundary,
            "User-Agent": "RM7-GrabDetector/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        parsed = json.loads(response.read(512000).decode("utf-8", "replace"))
    analysis_id = ((parsed or {}).get("data") or {}).get("id")
    return {"status": "completed", "found": False, "submitted": True, "analysis_id": str(analysis_id or "")[:200], "stats": None, "error_code": None, "error": None}


def virus_total_lookup(sha256, data, filename, options=None):
    options = options or {}
    key = (os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()
    if not key:
        return {"status": "unavailable", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_NOT_CONFIGURED", "error": "Antivirus reputation lookup is not configured."}
    request = urllib.request.Request(
        "https://www.virustotal.com/api/v3/files/" + urllib.parse.quote(sha256),
        headers={"x-apikey": key, "User-Agent": "RM7-GrabDetector/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            parsed = json.loads(response.read(1024000).decode("utf-8", "replace"))
        attrs = ((parsed or {}).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        safe_stats = {key: int(stats.get(key) or 0) for key in ("malicious", "suspicious", "harmless", "undetected", "timeout") if key in stats}
        last_date = attrs.get("last_analysis_date")
        return {
            "status": "completed",
            "found": True,
            "submitted": False,
            "stats": safe_stats,
            "reputation": attrs.get("reputation"),
            "last_analysis_date": datetime.fromtimestamp(int(last_date), timezone.utc).isoformat() if last_date else None,
            "error_code": None,
            "error": None,
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            if options.get("antivirus_submit") and options.get("antivirus_consent"):
                try:
                    return _vt_submit(data, filename, key)
                except urllib.error.HTTPError as submit_exc:
                    if submit_exc.code == 429:
                        return {"status": "unavailable", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_QUOTA_EXCEEDED", "error": "Antivirus submission quota was exceeded."}
                except Exception:
                    return {"status": "failed", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_SUBMISSION_FAILED", "error": "Antivirus submission failed."}
            return {"status": "completed", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_NOT_FOUND", "error": "No reputation record was found."}
        if exc.code == 401:
            return {"status": "unavailable", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_UNAUTHORIZED", "error": "Antivirus reputation lookup is not authorized."}
        if exc.code == 429:
            return {"status": "unavailable", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_QUOTA_EXCEEDED", "error": "Antivirus reputation query quota was exceeded."}
        return {"status": "failed", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_HTTP_ERROR", "error": "Antivirus reputation lookup failed."}
    except Exception:
        return {"status": "failed", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_UNAVAILABLE", "error": "Antivirus reputation lookup was unavailable."}


def _memory_counts(uid):
    now = time.time()
    with _QUOTA_LOCK:
        entries = [t for t in _QUOTA_MEMORY.get(uid, []) if now - t < 86400]
        if entries:
            _QUOTA_MEMORY[uid] = entries
        else:
            _QUOTA_MEMORY.pop(uid, None)
        return sum(1 for t in entries if now - t < 3600), len(entries)


def record_scan(uid):
    with _QUOTA_LOCK:
        _QUOTA_MEMORY.setdefault(uid, []).append(time.time())


def _pg_dsn(dsn):
    try:
        parts = urllib.parse.urlsplit(dsn)
        if not parts.query:
            return dsn
        drop = {"pgbouncer", "connection_limit", "pool_timeout", "supa"}
        pairs = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if k.lower() not in drop]
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(pairs), parts.fragment))
    except Exception:
        return dsn


def _db_counts(uid):
    dsn = (os.environ.get("DATABASE_URL") or "").strip()
    if not dsn:
        return None
    try:
        import psycopg2
        conn = psycopg2.connect(_pg_dsn(dsn), connect_timeout=4)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT "
                    "count(*) FILTER (WHERE created_at >= now() - interval '1 hour') AS hour_count, "
                    "count(*) FILTER (WHERE created_at >= now() - interval '1 day') AS day_count "
                    "FROM public.audit_logs "
                    "WHERE event_type = 'service.grab_detector' AND discord_user_id = %s "
                    "AND status IN ('success', 'info')",
                    (uid,),
                )
                row = cur.fetchone()
            return int(row[0] or 0), int(row[1] or 0)
        finally:
            conn.close()
    except Exception:
        return None


def check_quota(uid, counter=None, hourly=None, daily=None):
    hourly = HOURLY_LIMIT if hourly is None else int(hourly)
    daily = DAILY_LIMIT if daily is None else int(daily)
    if counter is None:
        memory = _memory_counts(uid)
        database = _db_counts(uid)
        if database:
            hour_count = max(memory[0], database[0])
            day_count = max(memory[1], database[1])
        else:
            hour_count, day_count = memory
    else:
        hour_count, day_count = counter(uid)
    if hour_count >= hourly:
        return {"ok": False, "code": "RATE_LIMITED", "window": "hour", "limit": hourly, "used": hour_count, "retry_after": 3600}
    if day_count >= daily:
        return {"ok": False, "code": "RATE_LIMITED", "window": "day", "limit": daily, "used": day_count, "retry_after": 86400}
    return {"ok": True, "hour_used": hour_count, "day_used": day_count, "hourly_limit": hourly, "daily_limit": daily}


def audit_scan(event_type, status, uid, ip, user_agent, details=None, store_url=None, store_secret=None):
    target = (store_url or os.environ.get("STORE_URL") or "https://YOUR_API_DOMAIN.example/api/store").strip()
    secret = (store_secret or os.environ.get("STORE_SECRET") or "").strip()
    if not secret:
        return False
    entry = {
        "event_type": event_type,
        "service": "grab-detector",
        "status": status,
        "discord_user_id": uid,
        "ip_address": ip,
        "user_agent": str(user_agent or "")[:300],
        "details": _redact_json_value(details or {}),
    }
    body = json.dumps(entry).encode("utf-8")
    request = urllib.request.Request(
        target,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-store-secret": secret, "User-Agent": "RM7-GrabDetector/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=3):
            return True
    except Exception:
        return False


def _request_remote_sink(hostname):
    host = str(hostname or "").strip().lower().strip(".")
    if not host:
        return None
    for known, label in EXFIL_SINK_HOSTS.items():
        if host == known or host.endswith("." + known):
            return label
    return None


def _is_external_request_host(hostname):
    host = str(hostname or "").strip().lower().strip(".")
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return False
    if host.endswith(".local") or host.endswith(".internal"):
        return False
    if re.match(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", host):
        return False
    if host in ("example.com", "example.org", "example.net") or host.endswith(".example"):
        return False
    if re.match(r"^192\.0\.2\.", host):
        return False
    return True


def assess_threat(static, dynamic, classification, mode):
    requests = list((dynamic or {}).get("requests") or [])
    fields = sorted({field for request in requests for field in (request.get("sensitive_fields") or [])})
    strong_fields = [field for field in fields if STRONG_CREDENTIAL_NAME_RE.search(field)]
    login_input = any(
        request.get("synthetic_login_input") or str(request.get("event") or "").lower() == "onsenddialogresponse"
        for request in requests
    ) and bool(strong_fields)
    sinks = []
    external_hosts = []
    for request in requests:
        host = str(request.get("hostname") or "")
        sink = _request_remote_sink(host)
        if sink and sink not in sinks:
            sinks.append(sink)
        if _is_external_request_host(host) and host not in external_hosts:
            external_hosts.append(host)
    has_body = any(
        str(request.get("body") or "").strip() and str(request.get("method") or "").upper() in ("POST", "PUT", "PATCH")
        for request in requests
    )
    obfuscation = static.get("obfuscation") or {}
    obfuscated = bool(obfuscation.get("detected"))
    static_webhooks = list(static.get("discord_webhooks") or [])
    static_telegram = list(static.get("telegram_endpoints") or [])
    static_sink = bool(static_webhooks or static_telegram)
    static_calls = list(static.get("request_calls") or [])
    static_encoded = list(static.get("encoded_strings") or [])

    score = 0
    evidence = []
    if requests:
        delivered = any(bool(request.get("sent")) for request in requests)
        score += 5
        evidence.append(
            "The isolated runtime captured " + str(len(requests)) + " HTTP-style request(s); " +
            ("at least one was observed as sent by a capture mechanism." if delivered else "none were delivered.")
        )
    if has_body:
        score += 10
        evidence.append("At least one captured request carried a request body.")
    if strong_fields:
        score += 40
        evidence.append("Credential-like field names were observed: " + ", ".join(strong_fields[:8]) + ".")
    if login_input:
        score += 20
        evidence.append("Synthetic login input reached a dialog-response handler and was then observed in a captured request.")
    if sinks:
        score += 15
        evidence.append("A captured request targeted a known webhook/bot destination: " + ", ".join(sinks) + ".")
    elif external_hosts:
        score += 5
        evidence.append("A captured request targeted an external host: " + ", ".join(external_hosts[:4]) + ".")
    if obfuscated and (strong_fields or login_input):
        score += 10
        evidence.append("Obfuscation indicators are present alongside credential-like request evidence.")

    if not requests:
        static_score = 0
        if static_sink:
            static_score += 20
            evidence.append("Static inspection found a Discord webhook or Telegram endpoint.")
        if static_sink and static_calls:
            static_score += 5
        if obfuscated and static_calls:
            static_score += 10
            evidence.append("Request APIs and obfuscation indicators appear in the same file.")
        if static_sink and static_encoded:
            static_score += 10
            evidence.append("Encoded strings appear alongside a webhook or bot endpoint.")
        score = min(55, static_score)
        if score:
            evidence.append("Static-only evidence cannot confirm execution or intent.")

    if requests and not sinks and not login_input:
        score = min(score, 55)
    score = max(0, min(100, score))
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 35:
        level = "medium"
    elif score >= 15:
        level = "low"
    else:
        level = "info"

    credential_access = bool(login_input)
    credential_transmission = bool(strong_fields and requests)
    if credential_access and sinks:
        title = "Potential credential exfiltration"
        summary = "The script handled synthetic login input and attempted to transmit credential-like data to a webhook or bot endpoint. The request was intercepted and not delivered."
    elif credential_access:
        title = "Potential credential collection"
        summary = "The script handled synthetic login input and produced a request containing credential-like fields. The destination was not a recognised webhook sink."
    elif credential_transmission:
        title = "Credential-like request data"
        summary = "A captured request contained credential-like fields. Review the destination and event origin before running the file."
    elif sinks:
        title = "Suspicious request destination"
        summary = "A captured or embedded request targets a Discord webhook or Telegram bot endpoint without strong credential evidence."
    elif score >= 15:
        title = "Request pattern needs review"
        summary = "Request indicators were observed, but the evidence does not establish credential access or exfiltration."
    else:
        title = "No strong exfiltration pattern"
        summary = "No credential-to-webhook pattern was observed. This is not a safety verdict."

    if level in ("critical", "high"):
        recommendation = "Do not run this file with real credentials. Treat the captured destination and any embedded secrets as exposed."
    elif level == "medium":
        recommendation = "Review the request origin, destination and field names before running the file. Use only synthetic data in any further test."
    else:
        recommendation = "No strong pattern was identified. Continue to treat the file as untrusted and verify the source."

    return {
        "score": score,
        "level": level,
        "title": title,
        "summary": summary,
        "recommendation": recommendation,
        "reasons": evidence[:12],
        "credential_access": credential_access,
        "credential_transmission": credential_transmission,
        "credential_fields": strong_fields[:10],
        "remote_sinks": sinks[:6],
        "external_hosts": external_hosts[:8],
        "request_count": len(requests),
        "obfuscated": obfuscated,
        "static_only": not bool(requests) and bool(score),
        "dynamic_incomplete": str((dynamic or {}).get("status") or "") in ("incomplete", "failed", "timeout", "unavailable"),
    }


ENVIRONMENT_PATTERNS = (
    (
        "luau_roblox",
        "Roblox / LuaU",
        re.compile(r"\b(?:game\s*:\s*GetService|Instance\.new|WaitForChild|Enum\.|workspace\s*\.|script\.Parent|task\.wait|typeof\s*\()", re.IGNORECASE),
        "Roblox LuaU APIs are not available in the local Lua 5.4 runtime.",
    ),
    (
        "moonloader_samp",
        "MoonLoader / SA-MP",
        re.compile(r"\b(?:moonloader|sampfuncs|sampAddChat|sampSendChat|samp\.|lib\.moonloader|lib\.samp|playerfuncs|memory\.)", re.IGNORECASE),
        "MoonLoader/SA-MP APIs are mocked; game behaviour remains environment-dependent.",
    ),
    (
        "luajit_ffi",
        "LuaJIT / FFI",
        re.compile(r"\b(?:require\s*\(?\s*[\"']ffi[\"']|ffi\s*\.|jit\s*\.)", re.IGNORECASE),
        "LuaJIT FFI and native libraries are never loaded in the isolated runtime.",
    ),
)


def classify_environment(source, classification=None):
    """Best-effort classification of the Lua dialect and host environment.

    This is intentionally conservative: an unknown file is never advertised as
    dynamically executable, and Roblox/LuaU files are static-only because the
    isolated runtime implements Lua 5.4 with MoonLoader/SA-MP mocks, not LuaU.
    """
    classification = classification or {}
    kind = str(classification.get("kind") or "")
    if not source or kind != "lua_source":
        label = "Compiled Lua bytecode" if kind else "Unknown format"
        return {
            "id": "bytecode" if "bytecode" in kind else "unknown",
            "label": label,
            "dynamic_supported": False,
            "source_available": False,
            "note": "Dynamic execution requires Lua source. Static evidence is still reported.",
        }
    for env_id, label, pattern, note in ENVIRONMENT_PATTERNS:
        if pattern.search(source):
            dynamic_supported = env_id == "moonloader_samp"
            return {
                "id": env_id,
                "label": label,
                "dynamic_supported": dynamic_supported,
                "source_available": True,
                "note": note,
            }
    return {
        "id": "generic_lua",
        "label": "Generic Lua 5.x",
        "dynamic_supported": True,
        "source_available": True,
        "note": "No host-specific API family was detected; the isolated Lua 5.4 runtime can run this source with mocks.",
    }


def analyze(data, filename, mode="normal", options=None, dynamic_client=None, antivirus_client=None, quota_counter=None):
    options = options or {}
    filename = safe_filename(filename)
    classification = classify_file(data, filename)
    sha256 = sha256_hex(data)
    source_text = data.decode("utf-8") if classification["kind"] == "lua_source" else None
    environment = classify_environment(source_text, classification)
    if classification["kind"] == "lua_source":
        static = scan_source(source_text)
    else:
        static = _scan_binary_strings(data, classification["kind"])

    stages = {
        "static_analysis": "completed",
        "deobfuscation": "skipped",
        "dynamic_analysis": "skipped",
        "antivirus_lookup": "skipped",
    }
    deob_result = {"status": "skipped", "engine": None, "detected": classification.get("lua_version"), "error_code": None, "error": None, "rescanned": None}
    dynamic_result = {"status": "skipped", "requests": [], "execution_completed": False, "timed_out": False, "runtime": None, "error_code": None, "error": None, "metadata": {}, "unsupported_api": None, "missing_module": None, "compatibility": None, "simulated_inputs": [], "observations": [], "events_run": [], "runtime_limits": {}, "coverage_notes": []}
    antivirus_result = {"status": "skipped", "found": False, "submitted": False, "stats": None, "error_code": None, "error": None}

    if mode == "performed":
        deob_result = deobfuscate(data, filename, classification)
        stages["deobfuscation"] = deob_result["status"]
        if deob_result.get("source"):
            deob_result["rescanned"] = scan_source(deob_result["source"])
        else:
            deob_result["rescanned"] = None
        if deob_result.get("error"):
            deob_result["error"] = _redact_text(deob_result.get("error"), 300)

        dynamic_source = source_text
        dynamic_origin = "original_source"
        if dynamic_source is None and deob_result.get("source"):
            dynamic_source = deob_result["source"]
            dynamic_origin = "deobfuscated_source"
        if not environment.get("dynamic_supported"):
            dynamic_result = {
                "status": "unavailable",
                "requests": [],
                "execution_completed": False,
                "timed_out": False,
                "runtime": None,
                "error_code": "UNSUPPORTED_LUA_ENVIRONMENT",
                "error": environment.get("note") or "This Lua environment is static-only.",
                "coverage_notes": [
                    "The source was inspected statically and was not executed in an incompatible runtime.",
                    "This is a runtime-compatibility limit, not evidence of missing behaviour in the file.",
                ],
            }
        elif dynamic_source is None:
            dynamic_result = {
                "status": "unavailable",
                "requests": [],
                "execution_completed": False,
                "timed_out": False,
                "runtime": None,
                "error_code": "UNSUPPORTED_DYNAMIC_FORMAT",
                "error": "Dynamic execution is only available for supported Lua source.",
                "coverage_notes": ["Bytecode and unsupported formats are not executed."],
            }
        elif dynamic_client is None:
            dynamic_result = sandbox_scan(dynamic_source, filename, options)
        else:
            dynamic_result = dynamic_client(dynamic_source, filename, options)
        dynamic_result["requests"] = normalize_dynamic_requests(dynamic_result.get("requests"))
        dynamic_result["metadata"] = normalize_dynamic_metadata(dynamic_result.get("metadata"))
        dynamic_result["unsupported_api"] = normalize_unsupported_api(dynamic_result.get("unsupported_api"))
        dynamic_result["missing_module"] = normalize_missing_module(dynamic_result.get("missing_module"))
        dynamic_result["compatibility"] = normalize_compatibility(dynamic_result.get("compatibility"))
        dynamic_result["simulated_inputs"] = normalize_simulated_inputs(dynamic_result.get("simulated_inputs"))
        dynamic_result["observations"] = normalize_dynamic_observations(dynamic_result.get("observations"))
        dynamic_result["events_run"] = normalize_events_run(dynamic_result.get("events_run"))
        dynamic_result["runtime_limits"] = normalize_runtime_limits(dynamic_result.get("runtime_limits"))
        if dynamic_result.get("runtime"):
            dynamic_result["runtime"] = public_runtime_label(dynamic_result.get("runtime"))
        if dynamic_result.get("coverage_notes"):
            dynamic_result["coverage_notes"] = [
                public_coverage_note(note) for note in (dynamic_result.get("coverage_notes") or [])[:20]
            ]
        if dynamic_result.get("error"):
            dynamic_result["error"] = _redact_text(dynamic_result.get("error"), 300)
        dynamic_result["input"] = dynamic_origin
        stages["dynamic_analysis"] = dynamic_result["status"]

        if options.get("antivirus", False):
            client = antivirus_client or virus_total_lookup
            try:
                antivirus_result = client(sha256, data, filename, options)
            except Exception:
                antivirus_result = {"status": "failed", "found": False, "submitted": False, "stats": None, "error_code": "ANTIVIRUS_UNAVAILABLE", "error": "Antivirus reputation lookup was unavailable."}
            stages["antivirus_lookup"] = antivirus_result.get("status", "failed")

    limitations = []
    limitations.extend(classification.get("notes") or [])
    if not environment.get("dynamic_supported"):
        limitations.append(environment.get("note") or "This environment cannot be executed by the local runtime.")
    if static["coverage"]["partial"]:
        limitations.append("Static inspection is partial for this file format.")
    if dynamic_result.get("status") in ("unavailable", "failed", "incomplete", "timeout"):
        limitations.append("Dynamic coverage is incomplete. Absence of captured requests is not proof of safety.")
    if dynamic_result.get("observations"):
        limitations.append(
            "Synthetic event delivery was bounded; one or more events stopped at the sandbox budget. Captured evidence is partial."
        )
    if dynamic_result.get("unsupported_api"):
        limitations.append(
            "Dynamic execution stopped at unsupported API '" + str(dynamic_result.get("unsupported_api"))[:120] +
            "'. Requests captured before it and static findings are preserved."
        )
    library_report = dynamic_result.get("library") if isinstance(dynamic_result.get("library"), dict) else {}
    if library_report.get("error"):
        limitations.append("Lua library selection: " + str(library_report.get("error"))[:300])
    if library_report.get("missing_modules"):
        limitations.append(
            "Required Lua module(s) missing from the selected folder: " +
            ", ".join(library_report["missing_modules"][:8]) + "."
        )
    if dynamic_result.get("missing_module"):
        limitations.append(
            "Dynamic execution stopped because Lua module '" + dynamic_result["missing_module"] +
            "' is unavailable or incompatible. Static findings and earlier requests are preserved."
        )
    if dynamic_result.get("compatibility"):
        compatibility = dynamic_result.get("compatibility") or {}
        limitations.append(
            "Lua runtime compatibility issue at upvalue '" + str(compatibility.get("name") or "unknown")[:80] +
            "'. This is not classified as a missing MoonLoader API; requests captured before it are preserved."
        )
    if mode == "performed" and (
        deob_result.get("status") in ("failed", "unavailable")
        or (deob_result.get("status") == "skipped" and deob_result.get("error_code") not in (None, "NO_SUPPORTED_OBFUSCATION"))
    ):
        limitations.append("Deobfuscation did not provide fully inspected source.")
    if not static["urls"] and not dynamic_result.get("requests"):
        limitations.append("No HTTP requests were observed in the inspected content. This does not prove the file is safe.")

    failed_stages = [name for name, value in stages.items() if value in ("failed", "unavailable", "incomplete", "timeout")]
    if deob_result.get("status") == "skipped" and deob_result.get("error_code") == "UNSUPPORTED_OBFUSCATOR":
        failed_stages.append("deobfuscation")
    overall_status = "partial_results" if failed_stages else "completed"
    if stages.get("static_analysis") != "completed":
        overall_status = "failed"

    threat = assess_threat(static, dynamic_result, classification, mode)

    badges = []
    if stages.get("static_analysis") == "completed":
        badges.append({"id": "static_completed", "label": "Static Analysis Completed", "tone": "ok"})
    if dynamic_result.get("requests"):
        badges.append({"id": "requests_captured", "label": "Requests Captured", "tone": "info"})
    elif mode == "performed" and dynamic_result.get("status") == "completed":
        badges.append({"id": "no_requests", "label": "No Requests Observed", "tone": "info"})
    elif mode == "normal" and not static.get("urls") and not static.get("request_calls"):
        badges.append({"id": "no_requests", "label": "No Requests Observed", "tone": "info"})
    if mode == "performed" and dynamic_result.get("status") in ("failed", "unavailable", "incomplete", "timeout"):
        badges.append({"id": "dynamic_incomplete", "label": "Dynamic Execution Incomplete", "tone": "warn"})
    if deob_result.get("status") in ("failed", "unavailable") or (
        deob_result.get("status") == "skipped" and deob_result.get("error_code") == "UNSUPPORTED_OBFUSCATOR"
    ):
        badges.append({"id": "deobfuscation_failed", "label": "Deobfuscation Failed", "tone": "warn"})
    if antivirus_result.get("status") == "unavailable":
        badges.append({"id": "antivirus_unavailable", "label": "Antivirus Reputation Unavailable", "tone": "muted"})
    if classification.get("kind") in ("lua_bytecode", "unsupported_bytecode"):
        badges.append({"id": "unsupported_bytecode", "label": "Unsupported Bytecode", "tone": "warn"})
    if not environment.get("dynamic_supported"):
        badges.append({"id": "static_only_environment", "label": "Static-Only Environment", "tone": "warn"})
    if threat.get("level") in ("critical", "high"):
        badges.append({"id": "credential_exfiltration", "label": threat.get("title") or "Credential Exfiltration Pattern", "tone": "danger"})
    elif threat.get("level") == "medium":
        badges.append({"id": "request_pattern_review", "label": "Suspicious Request Pattern", "tone": "warn"})

    report = {
        "file": {
            "name": filename,
            "size": len(data),
            "sha256": sha256,
            "format": classification,
        },
        "mode": mode,
        "environment": environment,
        "stages": stages,
        "static_analysis": static,
        "deobfuscation": {
            "status": deob_result.get("status"),
            "engine": deob_result.get("engine"),
            "detected": deob_result.get("detected"),
            "error_code": deob_result.get("error_code"),
            "error": deob_result.get("error"),
            "rescanned": deob_result.get("rescanned"),
        },
        "dynamic_analysis": {
            "status": dynamic_result.get("status"),
            "runtime": dynamic_result.get("runtime"),
            "requests": dynamic_result.get("requests") or [],
            "execution_completed": bool(dynamic_result.get("execution_completed")),
            "timed_out": bool(dynamic_result.get("timed_out")),
            "input": dynamic_result.get("input"),
            "error_code": dynamic_result.get("error_code"),
            "error": dynamic_result.get("error"),
            "metadata": dynamic_result.get("metadata") or {},
            "unsupported_api": dynamic_result.get("unsupported_api"),
            "missing_module": dynamic_result.get("missing_module"),
            "library": dynamic_result.get("library") or None,
            "compatibility": dynamic_result.get("compatibility"),
            "simulated_inputs": dynamic_result.get("simulated_inputs") or [],
            "observations": dynamic_result.get("observations") or [],
            "events_run": dynamic_result.get("events_run") or [],
            "runtime_limits": dynamic_result.get("runtime_limits") or {},
            "coverage_notes": dynamic_result.get("coverage_notes") or [],
        },
        "antivirus_lookup": {
            "status": antivirus_result.get("status"),
            "found": bool(antivirus_result.get("found")),
            "submitted": bool(antivirus_result.get("submitted")),
            "stats": antivirus_result.get("stats"),
            "reputation": antivirus_result.get("reputation"),
            "last_analysis_date": antivirus_result.get("last_analysis_date"),
            "error_code": antivirus_result.get("error_code"),
            "error": antivirus_result.get("error"),
        },
        "http_requests_captured": len(dynamic_result.get("requests") or []),
        "static_url_count": len(static.get("urls") or []),
        "threat": threat,
        "overall_status": overall_status,
        "status_badges": badges,
        "limitations": limitations,
    }
    return report

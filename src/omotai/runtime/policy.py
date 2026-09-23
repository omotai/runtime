"""Deterministic policy. Decisions come from facts (scheme, origin, method), never page text."""

import sqlite3
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import unquote, urldefrag, urlsplit

import yaml

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LOCAL_SCHEMES = frozenset({"data", "blob", "about"})  # no network involved


DEFAULT_PORTS = {"http": 80, "https": 443}


def origin_of(url: str) -> str:
    """scheme://host[:port], lowercase host, default port dropped: 'https://a:443' == 'https://a'."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    host = f"[{host}]" if ":" in host else host
    port = p.port
    if port is None or DEFAULT_PORTS.get(p.scheme) == port:
        return f"{p.scheme}://{host}"
    return f"{p.scheme}://{host}:{port}"


def normalize_origin(raw: str) -> str:
    """'HTTP://Portal.TEST:80/x' -> 'http://portal.test'. Only http(s) origins with a host;
    anything else (including an invalid port) raises ValueError."""
    parts = urlsplit(raw.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not a valid http(s) origin: {raw!r}")
    parts.port  # noqa: B018  # raises ValueError on an invalid port
    return origin_of(raw.strip())


def path_segments(path: str) -> tuple[str, ...]:
    """A path as the server is likely to route it: percent-decoded until stable, dot segments
    resolved, empty segments dropped, lowercase (Express and many servers ignore case).
    Errs toward matching: a denial that can be sidestepped by encoding is not a denial."""
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    out: list[str] = []
    for seg in path.lower().replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
        else:
            out.append(seg)
    return tuple(out)


def denied_path(origin: str, path_prefix: str) -> tuple[str, tuple[str, ...]]:
    """One `denied_paths` entry, validated and normalized. Bad config fails at load."""
    if not path_prefix.startswith("/"):
        raise ValueError(f"denied_paths: path_prefix must start with '/': {path_prefix!r}")
    segments = path_segments(path_prefix)
    if not segments:
        raise ValueError(
            "denied_paths: path_prefix '/' would deny the whole origin; "
            "drop it from allowed_origins instead"
        )
    return origin_of(origin), segments


def load_domain_rows() -> list[tuple[str, str]]:
    """(origin, action) rows of the `domains` table. No database file or no table yet means no
    dynamic domains; any other database error is raised, so a deny is never silently dropped."""
    from omotai.dashboard import db

    if not db.DB_PATH.exists():
        return []
    try:
        with closing(db.get_connection()) as conn:
            return conn.execute("SELECT origin, action FROM domains").fetchall()
    except sqlite3.OperationalError as e:
        if "no such table" not in str(e):
            raise
        return []


@dataclass(frozen=True)
class Decision:
    verdict: str  # "allow" | "deny" | "confirm"
    rule: str

    @property
    def allowed(self) -> bool:
        """Only allow. Code that does not know `confirm` therefore treats it as a block."""
        return self.verdict == "allow"

    @property
    def needs_confirm(self) -> bool:
        return self.verdict == "confirm"


def allow(rule: str) -> Decision:
    return Decision("allow", rule)


def deny(rule: str) -> Decision:
    return Decision("deny", rule)


def confirm(rule: str) -> Decision:
    return Decision("confirm", rule)


@dataclass(frozen=True)
class Policy:
    allowed_origins: frozenset[str]
    read_only: bool = True  # writes (non-GET) are denied unless explicitly opened by the runtime
    max_actions: int = 40
    max_seconds: int = 600
    login: dict | None = None  # performed by the runtime, never by the agent
    # (origin, path segments): every request to that origin under that path is denied, any method,
    # even for an allowed origin and inside the login window. Build entries with `denied_path`.
    denied_paths: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # A form submit that read_only would deny waits for a human instead: the runtime opens a write
    # window for that exact (method, URL) only if the operator approves. Needs read_only: true.
    confirm_writes: bool = False
    confirm_timeout_seconds: int = 30  # unanswered = denied
    max_confirmations: int = 3  # per session; more are denied without bothering the operator
    # The origins of the YAML file, before the domains table. `with_domains` starts from them, so
    # a domain removed from the table stops applying. None: `allowed_origins` is the base.
    base_origins: frozenset[str] | None = None

    def __post_init__(self):
        if self.confirm_writes and not self.read_only:
            raise ValueError("confirm_writes needs read_only: true (writes stay denied by default)")
        if self.confirm_timeout_seconds < 1 or self.max_confirmations < 0:
            raise ValueError("confirm_timeout_seconds must be >= 1 and max_confirmations >= 0")

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        origins = set(origin_of(o) for o in raw.get("allowed_origins", []))

        raw["allowed_origins"] = frozenset(origins)
        raw["base_origins"] = frozenset(origins)

        entries = []
        for entry in raw.pop("denied_paths", None) or []:
            if set(entry) != {"origin", "path_prefix"}:
                raise ValueError(f"denied_paths entry needs origin and path_prefix: {entry!r}")
            entries.append(denied_path(entry["origin"], entry["path_prefix"]))
        return cls(**raw, denied_paths=tuple(entries)).with_domains(load_domain_rows())

    def with_domains(self, rows) -> "Policy":
        """The policy with the domains table applied: `allow` adds to the base origins, `deny`
        removes (deny wins over any allow)."""
        base = self.base_origins if self.base_origins is not None else self.allowed_origins
        allowed = {origin_of(o) for o, a in rows if a == "allow"}
        denied = {origin_of(o) for o, a in rows if a == "deny"}
        return replace(
            self, allowed_origins=frozenset((base | allowed) - denied), base_origins=base
        )

    def path_denied(self, url: str) -> bool:
        if not self.denied_paths:
            return False
        origin, segments = origin_of(url), path_segments(urlsplit(url).path)
        return any(o == origin and segments[: len(p)] == p for o, p in self.denied_paths)

    def origin_allowed(self, url: str) -> bool:
        return origin_of(url) in self.allowed_origins

    def check_navigate(self, url: str) -> Decision:
        if urlsplit(url).scheme not in ("http", "https"):
            return deny("scheme_not_allowed")
        if not self.origin_allowed(url):
            return deny("origin_not_allowed")
        return deny("path_denied") if self.path_denied(url) else allow("origin_allowed")

    def check_request(
        self, method: str, url: str, write_ok: frozenset[tuple[str, str]] = frozenset()
    ) -> Decision:
        """Every request the browser makes (documents, images, scripts, fetch), any method."""
        scheme = urlsplit(url).scheme
        if scheme in LOCAL_SCHEMES:
            return allow("local_scheme")
        if scheme not in ("http", "https"):
            return deny("scheme_not_allowed")
        if not self.origin_allowed(url):
            return deny("origin_not_allowed")
        if self.path_denied(url):  # before every allowance, the login window included
            return deny("path_denied")
        if method.upper() in SAFE_METHODS:
            return allow("safe_method")
        if (method.upper(), urldefrag(url)[0]) in write_ok:
            return allow("write_window")
        return deny("read_only") if self.read_only else allow("write_allowed")

"""Deterministic policy. Decisions come from facts (scheme, origin, method), never page text."""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urldefrag, urlsplit

import yaml

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LOCAL_SCHEMES = frozenset({"data", "blob", "about"})  # no network involved


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


@dataclass(frozen=True)
class Decision:
    verdict: str  # "allow" | "deny"
    rule: str

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


def allow(rule: str) -> Decision:
    return Decision("allow", rule)


def deny(rule: str) -> Decision:
    return Decision("deny", rule)


@dataclass(frozen=True)
class Policy:
    allowed_origins: frozenset[str]
    read_only: bool = True  # writes (non-GET) are denied unless explicitly opened by the runtime
    max_actions: int = 40
    max_seconds: int = 600
    login: dict | None = None  # performed by the runtime, never by the agent

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        raw["allowed_origins"] = frozenset(raw["allowed_origins"])
        return cls(**raw)

    def origin_allowed(self, url: str) -> bool:
        return origin_of(url) in self.allowed_origins

    def check_navigate(self, url: str) -> Decision:
        if urlsplit(url).scheme not in ("http", "https"):
            return deny("scheme_not_allowed")
        return allow("origin_allowed") if self.origin_allowed(url) else deny("origin_not_allowed")

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
        if method.upper() in SAFE_METHODS:
            return allow("safe_method")
        if (method.upper(), urldefrag(url)[0]) in write_ok:
            return allow("write_window")
        return deny("read_only") if self.read_only else allow("write_allowed")

from dataclasses import replace

import pytest

from omotai.runtime.policy import Policy, denied_path

P = Policy(allowed_origins=frozenset({"http://portal.test"}))
LOGIN_WRITE = frozenset({("POST", "http://portal.test/login")})


@pytest.mark.parametrize(
    ("method", "url", "verdict", "rule"),
    [
        ("GET", "http://portal.test/orders", "allow", "safe_method"),
        ("GET", "http://evil.test/beacon?x=1", "deny", "origin_not_allowed"),  # img/GET exfil
        ("POST", "http://evil.test/collect", "deny", "origin_not_allowed"),
        ("POST", "http://portal.test/cancel", "deny", "read_only"),
        ("DELETE", "http://portal.test/orders/1", "deny", "read_only"),
        ("GET", "data:text/html,<p>hi</p>", "allow", "local_scheme"),
        ("GET", "file:///c:/secrets.txt", "deny", "scheme_not_allowed"),
        ("GET", "http://portal.test.evil.test/", "deny", "origin_not_allowed"),  # lookalike host
        ("GET", "http://portal.test:8080/", "deny", "origin_not_allowed"),  # other port = origin
    ],
)
def test_request_matrix(method, url, verdict, rule):
    d = P.check_request(method, url)
    assert (d.verdict, d.rule) == (verdict, rule)


def test_write_window_opens_exactly_one_write():
    assert P.check_request("POST", "http://portal.test/login", LOGIN_WRITE).rule == "write_window"
    assert P.check_request("POST", "http://portal.test/login").rule == "read_only"
    assert P.check_request("POST", "http://portal.test/other", LOGIN_WRITE).rule == "read_only"


def test_writes_allowed_when_policy_is_not_read_only():
    p = Policy(allowed_origins=frozenset({"http://portal.test"}), read_only=False)
    assert p.check_request("POST", "http://portal.test/x").rule == "write_allowed"
    assert p.check_request("POST", "http://evil.test/x").rule == "origin_not_allowed"


def test_navigate_only_http_on_allowed_origin():
    assert P.check_navigate("http://portal.test/a").allowed
    assert not P.check_navigate("http://evil.test/a").allowed
    assert P.check_navigate("javascript:alert(1)").rule == "scheme_not_allowed"


def test_load_from_yaml(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("allowed_origins: ['http://a.test']\nmax_actions: 5\n", encoding="utf-8")
    p = Policy.load(f)
    assert "http://a.test" in p.allowed_origins and p.max_actions == 5 and p.read_only


D = Policy(
    allowed_origins=frozenset({"http://portal.test", "http://other.test"}),
    read_only=False,
    denied_paths=(denied_path("http://portal.test", "/socket.io/"),),
)


@pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)  # a path is denied for every method
def test_denied_path_is_denied_for_every_method(method):
    d = D.check_request(method, "http://portal.test/socket.io/?EIO=4&transport=polling")
    assert (d.verdict, d.rule) == ("deny", "path_denied")


@pytest.mark.parametrize(
    "url",
    [
        "http://portal.test/socket.io",  # no trailing slash
        "http://portal.test/socket.io/sub/path",
        "http://portal.test/Socket.IO/",  # Express ignores case
        "http://portal.test//socket.io/",  # empty segment
        "http://portal.test/./socket.io/",
        "http://portal.test/rest/../socket.io/",  # dot segments
        "http://portal.test/socket%2Eio/",  # encoded dot
        "http://portal.test/%73ocket.io/",  # encoded letter
        "http://portal.test/socket.io%2F",  # encoded slash
        "http://portal.test/%2573ocket.io/",  # double-encoded
        "http://PORTAL.test:80/socket.io/",  # same origin, spelled differently
    ],
)
def test_denied_path_cannot_be_sidestepped_by_spelling(url):
    assert D.check_request("GET", url).rule == "path_denied"


@pytest.mark.parametrize(
    "url",
    [
        "http://portal.test/socket.iox",  # segment boundary, not a text prefix
        "http://portal.test/api/socket.io/",  # only a prefix of the path is denied
        "http://portal.test/rest/products",
        "http://other.test/socket.io/",  # another origin is not covered by this entry
    ],
)
def test_paths_outside_the_denial_still_work(url):
    assert D.check_request("GET", url).allowed


def test_denial_wins_over_the_login_window_and_applies_to_navigation():
    login = frozenset({("POST", "http://portal.test/socket.io/login")})
    assert D.check_request("POST", "http://portal.test/socket.io/login", login).rule == (
        "path_denied"
    )
    assert D.check_navigate("http://portal.test/socket.io/").rule == "path_denied"
    assert D.check_navigate("http://portal.test/orders").allowed


def test_denied_paths_load_from_yaml(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text(
        "allowed_origins: [http://localhost:3000]\n"
        "denied_paths:\n"
        "  - {origin: 'http://localhost:3000', path_prefix: /socket.io/}\n",
        encoding="utf-8",
    )
    p = Policy.load(f)
    assert p.check_request("GET", "http://localhost:3000/socket.io/?EIO=4").rule == "path_denied"
    assert p.check_request("GET", "http://localhost:3000/rest/products/search").allowed


@pytest.mark.parametrize(
    ("entry", "why"),
    [
        ("{origin: 'http://a.test', path_prefix: /}", "whole origin"),
        ("{origin: 'http://a.test', path_prefix: socket.io}", "must start with"),
        ("{origin: 'http://a.test'}", "needs origin and path_prefix"),
        (
            "{origin: 'http://a.test', path_prefix: /x/, method: GET}",
            "needs origin and path_prefix",
        ),
    ],
)
def test_bad_denied_paths_config_fails_at_load(tmp_path, entry, why):
    f = tmp_path / "p.yaml"
    f.write_text(
        f"allowed_origins: [http://a.test]\ndenied_paths:\n  - {entry}\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match=why):
        Policy.load(f)


def _domains_db(monkeypatch, tmp_path, rows):
    import sqlite3

    from omotai.dashboard import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "x.db")
    db.init_db()
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.executemany("INSERT INTO domains (origin, action) VALUES (?, ?)", rows)
    return db


def _yaml(tmp_path, origins):
    f = tmp_path / "p.yaml"
    f.write_text("allowed_origins: [" + ", ".join(origins) + "]", encoding="utf-8")
    return f


def test_db_deny_beats_yaml_allow(monkeypatch, tmp_path):
    _domains_db(monkeypatch, tmp_path, [("http://portal.test/", "deny")])
    p = Policy.load(_yaml(tmp_path, ["http://portal.test", "http://cdn.test"]))
    assert p.check_navigate("http://portal.test/orders").rule == "origin_not_allowed"
    assert p.check_navigate("http://cdn.test/a.js").allowed  # other origins untouched


def test_db_allow_adds_origin_and_deny_beats_db_allow(monkeypatch, tmp_path):
    _domains_db(
        monkeypatch,
        tmp_path,
        [
            ("http://new.test", "allow"),
            ("http://both.test", "allow"),
            ("http://both.test/", "deny"),
        ],
    )
    p = Policy.load(_yaml(tmp_path, []))
    assert p.check_navigate("http://new.test/").allowed
    assert not p.check_navigate("http://both.test/").allowed


def test_no_db_or_no_table_means_yaml_only(monkeypatch, tmp_path):
    from omotai.dashboard import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "missing.db")
    assert Policy.load(_yaml(tmp_path, ["http://portal.test"])).origin_allowed("http://portal.test")
    (tmp_path / "empty.db").write_bytes(b"")  # exists, no tables
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "empty.db")
    assert Policy.load(_yaml(tmp_path, ["http://portal.test"])).origin_allowed("http://portal.test")


def test_unreadable_db_fails_the_load_instead_of_dropping_denies(monkeypatch, tmp_path):
    import sqlite3

    from omotai.dashboard import db

    (tmp_path / "junk.db").write_bytes(b"this is not a sqlite file" * 10)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "junk.db")
    with pytest.raises(sqlite3.DatabaseError):
        Policy.load(_yaml(tmp_path, ["http://portal.test"]))


def test_domain_cli_exits_nonzero_on_bad_flags():
    from click.testing import CliRunner

    from omotai.runtime.server import cli

    r = CliRunner()
    assert r.invoke(cli, ["domain", "add", "http://a.test"]).exit_code == 1
    assert r.invoke(cli, ["domain", "add", "http://a.test", "--allow", "--deny"]).exit_code == 1


def test_confirm_verdict_is_not_allowed_and_needs_a_read_only_policy():
    from omotai.runtime.policy import confirm

    d = confirm("write_needs_confirmation")
    assert d.needs_confirm and not d.allowed  # code that ignores `confirm` treats it as a block
    with pytest.raises(ValueError, match="read_only"):
        Policy(allowed_origins=frozenset(), read_only=False, confirm_writes=True)
    with pytest.raises(ValueError, match="confirm_timeout_seconds"):
        Policy(allowed_origins=frozenset(), confirm_writes=True, confirm_timeout_seconds=0)


def test_submit_decision_is_confirm_only_with_confirm_writes(tmp_path):
    from omotai.runtime.audit import Audit
    from omotai.runtime.session import Session

    def decide(policy, form):
        s = Session(policy, Audit(tmp_path / "a.jsonl"))
        facts = {"tag": "button", "type": "submit", "href": None, "form": form}
        return s._decide_act("click", facts)

    post = {"method": "post", "action": "http://portal.test/cancel"}
    origins = frozenset({"http://portal.test"})
    plain = decide(Policy(allowed_origins=origins), post)
    assert (plain.verdict, plain.rule) == ("deny", "read_only_submit")
    asked = decide(Policy(allowed_origins=origins, confirm_writes=True), post)
    assert (asked.verdict, asked.rule) == ("confirm", "write_needs_confirmation")
    # a foreign destination is never worth asking about, and a GET form needs no confirmation
    foreign = {"method": "post", "action": "http://evil.test/collect"}
    assert decide(Policy(allowed_origins=origins, confirm_writes=True), foreign).verdict == "deny"
    get = {"method": "get", "action": "http://portal.test/search"}
    assert decide(Policy(allowed_origins=origins, confirm_writes=True), get).verdict == "allow"


def test_policy_yaml_accepts_the_confirm_fields(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text(
        "allowed_origins: [http://portal.test]\nread_only: true\nconfirm_writes: true\n"
        "confirm_timeout_seconds: 5\nmax_confirmations: 2\n",
        encoding="utf-8",
    )
    p = Policy.load(f)
    assert (p.confirm_writes, p.confirm_timeout_seconds, p.max_confirmations) == (True, 5, 2)


def test_with_domains_starts_from_the_base_every_time():
    base = frozenset({"http://a.test", "http://b.test"})
    p = Policy(allowed_origins=base)
    once = p.with_domains([("http://c.test", "allow"), ("HTTP://B.test:80/", "deny")])
    assert once.allowed_origins == {"http://a.test", "http://c.test"} and once.base_origins == base
    # a removed row stops applying: the next application does not build on the previous one
    assert once.with_domains([]).allowed_origins == base
    assert once.with_domains([("http://c.test", "allow")]).allowed_origins == base | {
        "http://c.test"
    }
    assert p.with_domains([]) == replace(p, base_origins=base)  # no rows: same rules

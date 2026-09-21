import pytest

from omotai_runtime.policy import Policy, denied_path

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
    assert p.allowed_origins == {"http://a.test"} and p.max_actions == 5 and p.read_only


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

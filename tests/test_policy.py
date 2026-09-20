import pytest

from omotai_runtime.policy import Policy

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

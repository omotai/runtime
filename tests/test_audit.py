from omotai.runtime.audit import Audit, verify


def test_chain_verifies_and_survives_reopen(tmp_path):
    path = tmp_path / "a.jsonl"
    a = Audit(path)
    a.log(event="one")
    a.log(event="two", n=2)
    Audit(path).log(event="three")  # reopening continues the same chain
    assert verify(path)


def test_tampering_is_detected(tmp_path):
    path = tmp_path / "a.jsonl"
    a = Audit(path)
    for i in range(3):
        a.log(event="tool", n=i)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[1].replace('"n": 1', '"n": 9'), lines[2]]))
    assert not verify(path)


def test_deleting_a_record_is_detected(tmp_path):
    path = tmp_path / "a.jsonl"
    a = Audit(path)
    for i in range(3):
        a.log(event="tool", n=i)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]))
    assert not verify(path)

import pytest
from fim.cli import main
from fim.core import (compare, has_changes, hash_file, load_baseline,
                      save_baseline, scan)


@pytest.fixture
def tree(tmp_path):
    d = tmp_path / "watched"
    d.mkdir()
    (d / "a.txt").write_text("hello")
    (d / "b.txt").write_text("world")
    (d / "skip.log").write_text("ignore me")
    return d


def test_hash_known_value(tmp_path):
    f = tmp_path / "x"
    f.write_text("abc")
    assert hash_file(str(f)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_exclude(tree):
    files, _ = scan([str(tree)], exclude=["*.log"])
    assert len(files) == 2


def test_detects_all_change_types(tree):
    base, _ = scan([str(tree)])
    (tree / "a.txt").write_text("tampered")
    (tree / "b.txt").unlink()
    (tree / "new.txt").write_text("new")
    cur, _ = scan([str(tree)])
    diff = compare(base, cur)
    assert len(diff["modified"]) == 1
    assert len(diff["deleted"]) == 1
    assert len(diff["added"]) == 1


def test_no_changes(tree):
    base, _ = scan([str(tree)])
    assert not has_changes(compare(base, scan([str(tree)])[0]))


def test_baseline_tamper_detected(tree, tmp_path):
    files, _ = scan([str(tree)])
    bl = tmp_path / "bl.json"
    save_baseline(str(bl), files, [str(tree)], key="secret")
    load_baseline(str(bl), key="secret")
    with pytest.raises(ValueError):
        load_baseline(str(bl), key="wrong")
    bl.write_text(bl.read_text().replace("hash", "hasx", 1))
    with pytest.raises(ValueError):
        load_baseline(str(bl), key="secret")


def test_cli_exit_codes(tree, tmp_path):
    bl, lg = str(tmp_path / "bl.json"), str(tmp_path / "f.log")
    assert main(["init", "-p", str(tree), "-b", bl, "-l", lg]) == 0
    assert main(["check", "-b", bl, "-l", lg]) == 0
    (tree / "a.txt").write_text("evil")
    assert main(["check", "-b", bl, "-l", lg]) == 1

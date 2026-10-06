"""Core logic: hashing, scanning, baseline storage and comparison."""
import hashlib
import hmac
import json
import os
import time
from fnmatch import fnmatch

CHUNK = 65536
SUPPORTED_ALGOS = ("sha256", "sha512", "sha3_256", "blake2b")


def hash_file(path, algo="sha256"):
    """Return the hex digest of a file, read in chunks (safe for big files)."""
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def is_excluded(path, patterns):
    name = os.path.basename(path)
    return any(fnmatch(name, p) or fnmatch(path, p) for p in patterns)


def scan(paths, exclude=(), algo="sha256"):
    """Walk the given files/directories and return ({path: info}, [errors])."""
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"Unsupported algorithm: {algo}")
    files, errors = {}, []

    def record(fp):
        try:
            st = os.stat(fp)
            files[fp] = {
                "hash": hash_file(fp, algo),
                "size": st.st_size,
                "mode": oct(st.st_mode & 0o777),
                "mtime": int(st.st_mtime),
            }
        except (OSError, PermissionError) as exc:
            errors.append(f"{fp}: {exc}")

    for root in paths:
        root = os.path.abspath(root)
        if os.path.isfile(root):
            if not is_excluded(root, exclude):
                record(root)
            continue
        if not os.path.isdir(root):
            errors.append(f"{root}: not found")
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames
                           if not is_excluded(os.path.join(dirpath, d), exclude)]
            for name in filenames:
                fp = os.path.join(dirpath, name)
                if os.path.islink(fp) or is_excluded(fp, exclude):
                    continue
                record(fp)
    return files, errors


def _signature(payload, key=None):
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if key:
        return "hmac-sha256:" + hmac.new(key.encode(), data, hashlib.sha256).hexdigest()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def save_baseline(path, files, paths, algo="sha256", exclude=(), key=None):
    payload = {
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "algorithm": algo,
        "paths": [os.path.abspath(p) for p in paths],
        "exclude": list(exclude),
        "files": files,
    }
    payload["signature"] = _signature(payload, key)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_baseline(path, key=None):
    """Load a baseline and verify its own integrity signature."""
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)
    stored = payload.get("signature", "")
    body = {k: v for k, v in payload.items() if k != "signature"}
    if not hmac.compare_digest(stored, _signature(body, key)):
        raise ValueError("Baseline signature mismatch: baseline file was "
                         "modified, corrupted, or the wrong HMAC key was used.")
    return payload


def compare(baseline_files, current_files):
    """Return dict with added / deleted / modified lists."""
    old, new = set(baseline_files), set(current_files)
    modified = []
    for p in sorted(old & new):
        b, c = baseline_files[p], current_files[p]
        reasons = []
        if b["hash"] != c["hash"]:
            reasons.append("content")
        if b["mode"] != c["mode"]:
            reasons.append(f"permissions {b['mode']} -> {c['mode']}")
        if reasons:
            modified.append({"path": p, "changes": reasons})
    return {
        "added": sorted(new - old),
        "deleted": sorted(old - new),
        "modified": modified,
    }


def has_changes(diff):
    return bool(diff["added"] or diff["deleted"] or diff["modified"])

"""Command-line interface."""
import argparse
import json
import os
import time

from . import __version__
from .alerts import format_report, send_email, setup_logger, write_json_report
from .core import compare, has_changes, load_baseline, save_baseline, scan


def load_config(path):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def build_parser():
    p = argparse.ArgumentParser(prog="fim", description="Automated File Integrity Monitor")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("-c", "--config", help="JSON config file")
        sp.add_argument("-p", "--paths", nargs="+", help="Files/directories to monitor")
        sp.add_argument("-b", "--baseline", help="Baseline file (default: baseline.json)")
        sp.add_argument("-e", "--exclude", nargs="*", help="Glob patterns to ignore")
        sp.add_argument("-a", "--algo", help="sha256 | sha512 | sha3_256 | blake2b")
        sp.add_argument("-l", "--log", help="Log file path")

    for name, hlp in [("init", "Create a new baseline"),
                      ("check", "Compare current state to baseline"),
                      ("update", "Accept current state as the new baseline"),
                      ("monitor", "Continuously check at an interval")]:
        sp = sub.add_parser(name, help=hlp)
        common(sp)
        if name in ("check", "monitor"):
            sp.add_argument("--report", help="Write JSON report to this file")
            sp.add_argument("--email", action="store_true", help="Send e-mail alerts")
        if name == "monitor":
            sp.add_argument("-i", "--interval", type=int, help="Seconds between checks")
    return p


def resolve(args):
    cfg = load_config(args.config)
    return {
        "paths": args.paths or cfg.get("paths"),
        "baseline": args.baseline or cfg.get("baseline", "baseline.json"),
        "exclude": args.exclude if args.exclude is not None else cfg.get("exclude", []),
        "algo": args.algo or cfg.get("algorithm", "sha256"),
        "log": args.log or cfg.get("log_file", "fim.log"),
        "interval": getattr(args, "interval", None) or cfg.get("interval", 60),
        "email": cfg.get("email"),
        "key": os.environ.get("FIM_HMAC_KEY"),
    }


def run_check(s, log, report=None):
    """Run one comparison; log and optionally write a JSON report."""
    base = load_baseline(s["baseline"], s["key"])
    current, errors = scan(base["paths"], base["exclude"], base["algorithm"])
    for e in errors:
        log.warning("Scan error: %s", e)
    diff = compare(base["files"], current)
    if has_changes(diff):
        log.warning("INTEGRITY VIOLATION DETECTED\n%s", format_report(diff))
        if report:
            write_json_report(report, diff)
    else:
        log.info("OK - %d files verified, no changes.", len(current))
    return diff


def alert(s, log, diff):
    if not s["email"]:
        log.warning("--email given but no 'email' section in config.")
        return
    try:
        send_email(s["email"], "[FIM] Integrity violation detected", format_report(diff))
        log.info("Alert e-mail sent.")
    except Exception as exc:  # noqa: BLE001
        log.error("E-mail failed: %s", exc)


def main(argv=None):
    args = build_parser().parse_args(argv)
    s = resolve(args)
    log = setup_logger(s["log"])
    try:
        if args.command in ("init", "update"):
            if not s["paths"]:
                log.error("No paths given (use --paths or a config file).")
                return 2
            files, errors = scan(s["paths"], s["exclude"], s["algo"])
            for e in errors:
                log.warning("Scan error: %s", e)
            save_baseline(s["baseline"], files, s["paths"], s["algo"], s["exclude"], s["key"])
            log.info("Baseline saved to %s (%d files).", s["baseline"], len(files))
            return 0

        if args.command == "check":
            diff = run_check(s, log, args.report)
            if has_changes(diff) and args.email:
                alert(s, log, diff)
            return 1 if has_changes(diff) else 0

        if args.command == "monitor":
            log.info("Monitoring every %ds. Press Ctrl+C to stop.", s["interval"])
            last = None
            try:
                while True:
                    diff = run_check(s, log, args.report)
                    sig = json.dumps(diff, sort_keys=True)
                    if has_changes(diff) and sig != last and args.email:
                        alert(s, log, diff)  # alert only on new/different changes
                    last = sig
                    time.sleep(s["interval"])
            except KeyboardInterrupt:
                log.info("Monitor stopped.")
                return 0
    except (ValueError, FileNotFoundError) as exc:
        log.error("%s", exc)
        return 2
    return 0

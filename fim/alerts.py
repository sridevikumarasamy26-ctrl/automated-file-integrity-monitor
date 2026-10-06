"""Logging, report formatting and e-mail alerts."""
import json
import logging
import smtplib
import time
from email.message import EmailMessage


def setup_logger(logfile=None):
    logger = logging.getLogger("fim")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if logfile:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def format_report(diff):
    lines = []
    for p in diff["added"]:
        lines.append(f"[ADDED]    {p}")
    for p in diff["deleted"]:
        lines.append(f"[DELETED]  {p}")
    for m in diff["modified"]:
        lines.append(f"[MODIFIED] {m['path']} ({', '.join(m['changes'])})")
    return "\n".join(lines) if lines else "No changes detected."


def write_json_report(path, diff):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"), **diff}, f, indent=2)


def send_email(cfg, subject, body):
    """cfg: {host, port, username, password, sender, recipients, use_tls}"""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["sender"]
    msg["To"] = ", ".join(cfg["recipients"])
    msg.set_content(body)
    with smtplib.SMTP(cfg["host"], cfg.get("port", 587), timeout=20) as s:
        if cfg.get("use_tls", True):
            s.starttls()
        if cfg.get("username"):
            s.login(cfg["username"], cfg["password"])
        s.send_message(msg)

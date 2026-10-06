# 🛡️ Automated File Integrity Monitor (FIM)

A lightweight, dependency-free security tool that detects unauthorized changes to
files and directories. It builds a cryptographic baseline of your files and alerts
you when anything is **added, deleted, modified, or has its permissions changed**.

## Features
- SHA-256 / SHA-512 / SHA3-256 / BLAKE2b hashing (chunked, handles large files)
- Detects added, deleted, modified files and permission changes
- **Tamper-proof baseline**: signed with SHA-256, or HMAC if `FIM_HMAC_KEY` is set
- Continuous monitoring mode with de-duplicated alerts
- Logging to console + file, JSON reports, optional e-mail (SMTP) alerts
- Glob-based exclusions, JSON config file
- Exit codes for automation (`0` clean, `1` changes found, `2` error)
- Pure Python standard library, with unit tests

## Requirements
Python 3.8+

## Installation
```bash
git clone https://github.com/<your-username>/file-integrity-monitor.git
cd file-integrity-monitor
```

## Usage
```bash
# 1. Create a baseline of a trusted state
python -m fim init -p /etc /var/www -e "*.log" "*.tmp"

# 2. Check for changes (one-off)
python -m fim check

# 3. Continuous monitoring every 30 seconds with e-mail alerts
python -m fim monitor -i 30 --email -c config.json

# 4. After verifying changes are legitimate, accept them
python -m fim update -p /etc /var/www

# Save a JSON report
python -m fim check --report report.json
```

Using a config file: copy `config.example.json` to `config.json`, edit, then run
`python -m fim init -c config.json`.

### Protect the baseline with a secret key (recommended)
```bash
export FIM_HMAC_KEY="a-long-random-secret"      # Linux/macOS
set FIM_HMAC_KEY=a-long-random-secret           # Windows CMD
```
Without the key, an attacker cannot forge a valid baseline after editing files.

### Run automatically (cron)
```
*/15 * * * * cd /opt/fim && FIM_HMAC_KEY=xxx python -m fim check --email -c config.json
```

## Sample output
```
[WARNING] INTEGRITY VIOLATION DETECTED
[ADDED]    /var/www/shell.php
[DELETED]  /etc/important.conf
[MODIFIED] /etc/passwd (content)
```

## Testing
```bash
pip install -r requirements.txt
pytest -v
```

## Project structure
```
fim/core.py     hashing, scanning, baseline, comparison
fim/alerts.py   logging, reports, e-mail
fim/cli.py      command-line interface
tests/          unit tests
```

## Limitations
This tool detects changes after they happen; it does not prevent them. Store the
baseline on read-only or remote storage for best security. Use only on systems you
own or are authorized to monitor.

## License
MIT

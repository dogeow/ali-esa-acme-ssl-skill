# ali-esa-acme-ssl-skill

[Chinese Documentation](README_zh.md)

OpenClaw skill for **automatic HTTPS certificate issuance/renewal** using **Alibaba Cloud ESA DNS + acme.sh**, with optional automatic installation to Nginx.

## What this skill solves

AI models often resolve to the wrong place: they write records to traditional AliDNS, while the correct target should be ESA DNS. These two DNS systems are independent.

In other words, when a domain is hosted on ESA (`*.atrustdns.com`), DNS-01 validation records must be written to ESA DNS, not traditional AliDNS.

## Environment compatibility

- ✅ Linux hosts (Ubuntu tested)
- ✅ System-level Nginx deployments (LNMP tested)
- ❌ Containerized environments (Docker not supported)
- ❌ Windows/macOS not tested

## Project structure

- `SKILL.md` – Trigger rules and usage guidance for the agent
- `scripts/esa_acme_issue.py` – Automation script
- `scripts/i18n/` – Language files (en.json, zh.json, …) for script output
- `evals/evals.json` – Basic evaluation prompts

## First-time acme.sh setup

```bash
curl https://get.acme.sh | sh
source ~/.bashrc
acme.sh --register-account -m example@example.com
acme.sh --set-default-ca --server letsencrypt
```

## Python dependencies

The script can auto-install dependencies by default. Manual install (optional):

```bash
python3 -m pip install --user aliyun-python-sdk-core aliyun-python-sdk-alidns
```

## Quick start

### 1) Export credentials

```bash
export ALIYUN_AK='YOUR_AK'
export ALIYUN_SK='YOUR_SK'
```

### 2) Single domain

```bash
python3 scripts/esa_acme_issue.py -d test.example.com
```

### 3) Apex + wildcard

```bash
python3 scripts/esa_acme_issue.py -d example.com -d '*.example.com'
```

### 4) With Chinese output

```bash
python3 scripts/esa_acme_issue.py -d example.com --lang zh
```

## Defaults

- Auto-install cert to Nginx by default (disable with `--no-install-cert`)
- `--dns-timeout` default is `600`
- Optional A record management: `--ensure-a-record host=ip` (with authoritative NS propagation verification)
- Overwrite protection: existing A value will NOT be overwritten unless `--confirm-overwrite` is provided

Example:

```bash
python3 scripts/esa_acme_issue.py \
  -d test.example.com \
  --ensure-a-record test.example.com=1.2.3.4
```

## Completion criteria (anti false-positive)

Do not say "DNS record is done" unless both checks pass:

1. ESA `ListRecords` confirms the exact `RecordName + Type + Value`
2. Authoritative NS query (`dig @ns TXT`) returns the expected token

If only CreateRecord API returned success, report it as "request accepted" (not completed).

## Common troubleshooting

- `No TXT record found`: increase `--dns-timeout`, verify authoritative NS propagation
- `InvalidRecordNameSuffix`: domain does not belong to current ESA site suffix

## FAQ

### Q: I set an IP whitelist on AccessKey. What should I check?

A: This is a common cause of "permission"-like failures.

- Ensure the **current egress public IP** of the server is in the whitelist
- If using proxy/NAT, whitelist the **actual outbound NAT IP**, not LAN IP
- Verify IP first:

  ```bash
  curl -s ifconfig.me
  ```

- If whitelist is strict, API calls may fail even when AK/SK and RAM policy are correct
- After changing whitelist, wait a short propagation window and retry

## Security notes

Always remind users of these 1/2/3 before execution:

1. Use least-privilege RAM sub-account keys instead of long-term root keys
2. Prefer STS temporary credentials whenever possible
3. Enable AccessKey IP allowlist for actual outbound NAT IP

- Never hardcode AK/SK in script
- Prefer env vars
- Rotate keys immediately if exposed in chat/logs

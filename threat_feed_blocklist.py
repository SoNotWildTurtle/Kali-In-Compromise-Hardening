#!/usr/bin/env python3
"""threat_feed_blocklist.py - Fetch IP threat feeds and block them with iptables."""
import json
import re
import subprocess
from pathlib import Path
from urllib.request import urlopen

FEED_URLS = [
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
]

STATE_FILE = Path('/var/lib/nn_ids/threat_feed_state.json')
LOG_FILE = Path('/var/log/threat_feed_blocklist.log')


def load_state():
    if STATE_FILE.exists():
        with STATE_FILE.open() as f:
            return json.load(f)
    return {"blocked": []}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open('w') as f:
        json.dump(state, f)


def fetch_ips():
    ips = set()
    pattern = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
    for url in FEED_URLS:
        try:
            with urlopen(url) as resp:
                for line in resp.read().decode().splitlines():
                    match = pattern.search(line)
                    if match:
                        ips.add(match.group(0))
        except Exception as e:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with LOG_FILE.open('a') as f:
                f.write(f"Error fetching {url}: {e}\n")
    return ips


def block_ip(ip):
    if subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
        with LOG_FILE.open('a') as f:
            f.write(f"Blocked {ip}\n")


def main():
    state = load_state()
    ips = fetch_ips()
    for ip in ips:
        if ip not in state['blocked']:
            block_ip(ip)
            state['blocked'].append(ip)
    save_state(state)


if __name__ == '__main__':
    main()

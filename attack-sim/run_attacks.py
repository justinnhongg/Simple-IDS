import argparse
import random
import time
from typing import Iterable, List, Sequence

import os
import requests

DEFAULT_TARGET = "http://localhost:5000"
DEFAULT_BRUTEFORCE_DELAY = 0.2
DEFAULT_SQLI_DELAY = 0.2
DEFAULT_PORTSCAN_DELAY = 0.1

# Allow heavier traffic bursts when demoing without editing code.
BRUTEFORCE_ROUNDS = int(os.environ.get("ATTACK_SIM_BRUTEFORCE_ROUNDS", "3"))
SQLI_ROUNDS = int(os.environ.get("ATTACK_SIM_SQLI_ROUNDS", "3"))
PORTSCAN_ROUNDS = int(os.environ.get("ATTACK_SIM_PORTSCAN_ROUNDS", "3"))
SPOOFED_IPS = [ip.strip() for ip in os.environ.get("ATTACK_SIM_SOURCE_IPS", "").split(",") if ip.strip()]
PRIMARY_BRUTEFORCE_BURST = 5  # align with proxy default threshold
PRIMARY_PORTSCAN_BURST = 10   # align with proxy default threshold


def _post(path: str, payload: dict, ip_hint: str | None) -> None:
    try:
        headers = {"X-Forwarded-For": ip_hint} if ip_hint else {}
        response = requests.post(path, json=payload, headers=headers, timeout=3)
        print(f"POST {path} -> {response.status_code}")
    except requests.RequestException as exc:
        print(f"POST {path} failed: {exc}")


def _get(path: str, ip_hint: str | None) -> None:
    try:
        headers = {"X-Forwarded-For": ip_hint} if ip_hint else {}
        response = requests.get(path, headers=headers, timeout=3)
        print(f"GET {path} -> {response.status_code}")
    except requests.RequestException as exc:
        print(f"GET {path} failed: {exc}")


def _paced_sleep(base_delay: float, pace: float) -> None:
    delay = max(base_delay * pace, 0.0)
    if delay:
        time.sleep(delay)


def simulate_bruteforce(base_url: str, pace: float) -> None:
    print("[Brute Force] Starting password spray against /login")
    base_passwords = ["123456", "password", "letmein", "qwerty", "passw0rd", "password123"]
    passwords: List[str] = []
    for _ in range(max(1, BRUTEFORCE_ROUNDS)):
        passwords.extend(base_passwords)
    for index, password in enumerate(passwords):
        ip_hint = _pick_bruteforce_ip(index)
        _post(
            f"{base_url}/login",
            {
                "username": "admin",
                "password": password,
            },
            ip_hint,
        )
        _paced_sleep(DEFAULT_BRUTEFORCE_DELAY, pace)
    print("[Brute Force] Completed")


def simulate_sql_injection(base_url: str, pace: float) -> None:
    print("[SQL Injection] Sending suspicious search queries")
    base_payloads = [
        "' OR 1=1 --",
        "admin' UNION SELECT password FROM users --",
        "'; DROP TABLE users; --",
    ]
    queries: List[str] = []
    for _ in range(max(1, SQLI_ROUNDS)):
        queries.extend(base_payloads)
    for index, query in enumerate(queries):
        ip_hint = _pick_source_ip(f"{query}-{index}")
        _get(f"{base_url}/search?q={requests.utils.quote(query)}", ip_hint)
        _paced_sleep(DEFAULT_SQLI_DELAY, pace)
    print("[SQL Injection] Completed")


def simulate_port_scan(base_url: str, pace: float) -> None:
    print("[Port Scan] Probing a range of ports")
    ports: List[int] = []
    for _ in range(max(1, PORTSCAN_ROUNDS)):
        ports.extend(random.sample(range(20, 1024), 12))
    for index, port in enumerate(ports):
        ip_hint = _pick_portscan_ip(index)
        _get(f"{base_url}/probe/{port}", ip_hint)
        _paced_sleep(DEFAULT_PORTSCAN_DELAY, pace)
    print("[Port Scan] Completed")


def _pick_source_ip(seed: str) -> str | None:
    if not SPOOFED_IPS:
        return None
    index = abs(hash(seed)) % len(SPOOFED_IPS)
    return SPOOFED_IPS[index]


def _pick_bruteforce_ip(attempt_index: int) -> str | None:
    if not SPOOFED_IPS:
        return None
    if attempt_index < PRIMARY_BRUTEFORCE_BURST:
        return SPOOFED_IPS[0]
    # once we have triggered the alert, rotate through the remaining IPs for colour
    if len(SPOOFED_IPS) == 1:
        return SPOOFED_IPS[0]
    offset = (attempt_index - PRIMARY_BRUTEFORCE_BURST) % (len(SPOOFED_IPS) - 1)
    return SPOOFED_IPS[offset + 1]


def _pick_portscan_ip(probe_index: int) -> str | None:
    if not SPOOFED_IPS:
        return None
    if probe_index < PRIMARY_PORTSCAN_BURST:
        return SPOOFED_IPS[0]
    if len(SPOOFED_IPS) == 1:
        return SPOOFED_IPS[0]
    offset = (probe_index - PRIMARY_PORTSCAN_BURST) % (len(SPOOFED_IPS) - 1)
    return SPOOFED_IPS[offset + 1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Trigger demo attacks against the Simple IDS app")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Base URL for the demo application")
    parser.add_argument(
        "--scenarios",
        nargs="+",
        choices=["bruteforce", "sql", "portscan"],
        help="Specific scenarios to execute (defaults to all)",
    )
    parser.add_argument("--all", action="store_true", help="Run every attack scenario")
    parser.add_argument(
        "--pace",
        type=float,
        default=1.0,
        help="Multiplier for pacing between requests (lower is faster, higher slows the demo)",
    )
    return parser.parse_args()


def run_scenarios(target: str, scenarios: Sequence[str], pace: float) -> List[str]:
    base_url = target.rstrip("/")
    pace_value = pace if pace and pace > 0 else 1.0
    executed: List[str] = []
    for scenario in scenarios:
        if scenario == "bruteforce":
            simulate_bruteforce(base_url, pace_value)
            executed.append("bruteforce")
        elif scenario == "sql":
            simulate_sql_injection(base_url, pace_value)
            executed.append("sql")
        elif scenario == "portscan":
            simulate_port_scan(base_url, pace_value)
            executed.append("portscan")
    return executed


def main() -> None:
    args = parse_args()
    scenarios = args.scenarios or []
    if args.all or not scenarios:
        scenarios = ["bruteforce", "sql", "portscan"]
    executed = run_scenarios(args.target, scenarios, args.pace)
    missing = set(scenarios) - set(executed)
    if missing:
        print(f"Skipped unknown scenarios: {', '.join(sorted(missing))}")
    print("All selected scenarios finished. Check the dashboard for detections.")


if __name__ == "__main__":
    main()

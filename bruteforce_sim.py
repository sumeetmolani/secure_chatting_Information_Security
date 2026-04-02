#!/usr/bin/env python3
"""
bruteforce_sim.py — Brute-force attack simulation + protection demo.

This script demonstrates:
  1. What a dictionary / credential-stuffing attack looks like
  2. That SecureChat's rate-limiting and lockout mechanism stops it
  3. How security events appear in the log file

Usage:
    python bruteforce_sim.py [--url http://localhost:5000] [--target bob]

IMPORTANT: Run against localhost only.  Never use against systems you
           don't own or have explicit written permission to test.
"""

import argparse
import time
import requests

# ─── Common passwords attackers try ──────────────────────────────────────────

COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "letmein",
    "password1", "abc123", "iloveyou", "admin",
    "welcome", "monkey", "login", "pass",
    "master", "dragon", "trustno1", "baseball",
]


def simulate_attack(base_url: str, username: str, delay: float = 0.3):
    """
    Attempt authentication with a list of common passwords.
    Demonstrates that the server locks out after MAX_LOGIN_ATTEMPTS failures.
    """
    print(f"""
╔══════════════════════════════════════════════════════════╗
║      SecureChat — Brute-Force Attack Simulation          ║
╠══════════════════════════════════════════════════════════╣
║  Target  : {username:<46}║
║  Server  : {base_url:<46}║
║  Attempt : dictionary attack ({len(COMMON_PASSWORDS)} common passwords)   ║
╚══════════════════════════════════════════════════════════╝
""")
    endpoint = f"{base_url}/api/auth/login"
    locked   = False

    for i, password in enumerate(COMMON_PASSWORDS, start=1):
        try:
            res  = requests.post(
                endpoint,
                json    = {"username": username, "password": password},
                timeout = 5,
            )
            data = res.json()

            status_icon = "✓" if res.ok else "✗"
            print(f"  [{i:02d}] {status_icon}  password={password!r:20s}  HTTP {res.status_code}"
                  f"  → {data.get('error') or 'SUCCESS!'}")

            if res.ok:
                print(f"\n  ⚠ Authentication succeeded with password: {password!r}")
                print(f"  Token: {data.get('token','')[:40]}…")
                break

            if res.status_code == 429:
                print(f"\n  🛡  LOCKOUT TRIGGERED after {i} attempt(s)!")
                print(f"     {data.get('error','')}")
                locked = True
                break

        except requests.exceptions.ConnectionError:
            print(f"  [ERR] Cannot connect to {endpoint}. Is the server running?")
            break

        time.sleep(delay)

    print()
    if locked:
        print("  ✅  PROTECTION EFFECTIVE — brute-force attack was blocked.")
        print("     Check ../logs/security.log for BRUTE_FORCE_DETECTED events.")
    else:
        print("  ℹ  Attack completed without lockout.")
        print("     Ensure the target user exists on the server to trigger lockout.")


# ─── Rate-limit demonstration ─────────────────────────────────────────────────

def simulate_rate_limit(base_url: str, burst: int = 35):
    """
    Fire many requests quickly to trigger the sliding-window rate limiter.
    """
    print(f"\n╔══════════════════════════════════════════════════════════╗")
    print(f"║      Rate-Limit Simulation ({burst} rapid requests)         ║")
    print(f"╚══════════════════════════════════════════════════════════╝\n")

    endpoint = f"{base_url}/api/health"
    blocked  = 0

    for i in range(1, burst + 1):
        try:
            res = requests.get(endpoint, timeout=3)
            icon = "🛡" if res.status_code == 429 else "✓"
            if res.status_code == 429:
                blocked += 1
            print(f"  [{i:02d}] {icon}  HTTP {res.status_code}")
        except requests.exceptions.ConnectionError:
            print("  [ERR] Connection refused.")
            break

    print(f"\n  Total blocked: {blocked}/{burst}")
    if blocked > 0:
        print("  ✅  Rate limiting is working correctly.")


# ─── Input injection demo (safe simulation) ───────────────────────────────────

def simulate_injection_attempt(base_url: str):
    """
    Send malicious payloads that the server should sanitise and reject.
    """
    print(f"\n╔══════════════════════════════════════════════════════════╗")
    print(f"║      SQL Injection / XSS Payload Simulation             ║")
    print(f"╚══════════════════════════════════════════════════════════╝\n")

    payloads = [
        ("' OR '1'='1",         "SQL injection — always-true clause"),
        ("admin'--",            "SQL injection — comment bypass"),
        ("<script>alert(1)</script>", "XSS — script tag"),
        ("SELECT * FROM users", "SQL keyword in username"),
        ("a" * 200,             "Oversized input (200 chars)"),
    ]

    endpoint = f"{base_url}/api/auth/login"

    for payload, description in payloads:
        try:
            res  = requests.post(
                endpoint,
                json    = {"username": payload, "password": "x"},
                timeout = 5,
            )
            data = res.json()
            blocked = res.status_code in (400, 422)
            icon    = "✅" if blocked else "⚠ "
            print(f"  {icon}  {description}")
            print(f"       Payload  : {payload[:50]!r}")
            print(f"       Response : HTTP {res.status_code} — {data.get('error','ok')}")
            print()
        except requests.exceptions.ConnectionError:
            print("  [ERR] Cannot reach server.")
            break


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureChat attack simulation")
    parser.add_argument("--url",    default="http://localhost:5000", help="Base URL of the server")
    parser.add_argument("--target", default="alice",                help="Username to attack")
    parser.add_argument("--all",    action="store_true",            help="Run all simulations")
    args = parser.parse_args()

    simulate_attack(args.url, args.target)

    if args.all:
        simulate_rate_limit(args.url)
        simulate_injection_attempt(args.url)

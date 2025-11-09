import hashlib
import time
import json
import requests
import os
import sqlite3
import random
from ecdsa.util import sigdecode_der
from ecdsa import SECP256k1

# Stałe
n = SECP256k1.order
DB_FILE = "podatnosci.db"
LAST_BLOCK_FILE = "last_block.txt"

NETWORK = "mainnet"
BLOCKSTREAM_API = {
    "mainnet": "https://blockstream.info/api/",
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

found_r_values = {}  # Do wykrywania podwojonych R
analyzed_addresses = set()

# ✅ **Lista adresów do analizy w pierwszej kolejności**
TARGET_ADDRESSES = [
    "bc1qqqwlm30vy72zqmdwf557t3wjzsvx0jyw28xzul",
    "12HtEGL5U9f9FTEpbbv5pZbwLFdoTzRU5v",
    "1MMxJUZS4noWHKPQmzs6iirQ2Y5Z2nkGAX",
    "bc1qstpzhd7ydxd8qx007yyazgahww3zju6s7y4ere",
    "1Mo1K9JRH5brv7fhoBUqFcpDMmmZjpxZwH",
    "bc1qxckg9zrvprl6zk2l7el9alttf8uxu2ylgkffds",
    "3QbgBh4NHtFKayJnKsyaenyRNccnmcMprZ",
    "bc1qhzggkjlka5uk0ju7qswqrcmrl9xje8q8d95pg9",
    "bc1pyneppttgz7lk7kgzgwec2yv39ddrl6lswh0x59n0peeafkvx2xdq0s490e",
    "1LK9NnkGi8nnuqLXc85YUd8NtfaJ6c7P86",
    "bc1qkylaatpwwvhx6yd84sqlqcflv6ykzmnzr2ehff",
    "bc1qdxcha0utenqjenn7pgpmk0vcehjys80wcpv7g7",
    "1K71YtquGtQ1ZYuCkcXU5mZCbeBvJgmU1F",
    "bc1q23mvj7yephuth0q5g48kjd4e327asuxu4upkzz",
    "bc1q3rfhjghhly3hwt0vdtne5yae9lqln5gs9337p8",
    "18mqzJGxcMFwKtcrprFGtX2tikpjZrZq1k",
]

# === BAZA DANYCH SQLITE ===
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            txid TEXT,
            address TEXT,
            r TEXT,
            s TEXT,
            balance INTEGER
        )"""
    )
    conn.commit()
    conn.close()

def save_vulnerability(vuln):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO vulnerabilities (type, txid, address, r, s, balance) VALUES (?, ?, ?, ?, ?, ?)",
        (
            vuln["type"],
            vuln["txid"],
            vuln["address"],
            vuln.get("r", ""),
            vuln.get("s", ""),
            vuln["balance"],
        ),
    )
    conn.commit()
    conn.close()

# === API FUNKCJE ===
def api_call(endpoint, retries=3, backoff=2):
    url = BLOCKSTREAM_API[NETWORK] + endpoint
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                wait_time = int(response.headers.get("Retry-After", 15))
                print(f"[⏳] API limit! Czekam {wait_time} sek...")
                time.sleep(wait_time)
            elif response.status_code >= 500:
                time.sleep(backoff)
                backoff *= 2
            else:
                return None
        except requests.exceptions.RequestException:
            time.sleep(backoff)
            backoff *= 2
    return None

def get_block_height():
    return api_call("blocks/tip/height")

def get_block_txids(height):
    block_hash = api_call(f"block-height/{height}")
    return api_call(f"block/{block_hash}/txids") if block_hash else []

def get_transaction(txid):
    return api_call(f"tx/{txid}")

def get_address_balance(address):
    data = api_call(f"address/{address}")
    return data["chain_stats"]["funded_txo_sum"] - data["chain_stats"]["spent_txo_sum"] if data else 0

def get_transactions_by_address(address):
    return api_call(f"address/{address}/txs")

def get_mempool_txids():
    return api_call("mempool/txids")

# === ANALIZA TRANSAKCJI ===
def get_address_from_tx(tx):
    for vout in tx.get("vout", []):
        if "scriptpubkey_address" in vout:
            return vout["scriptpubkey_address"]
    return "unknown"

def analyze_transaction(txid):
    print(f"[🔍] Analizuję transakcję: {txid}")
    tx = get_transaction(txid)
    if not tx:
        return

    address = get_address_from_tx(tx)
    balance = get_address_balance(address)

    if balance == 0:
        print(f"[⚠️] Pomijam adres bez salda: {address}")
        return

    for vin in tx.get("vin", []):
        if "witness" in vin and len(vin["witness"]) > 2:
            sig = bytes.fromhex(vin["witness"][1])
            try:
                r, s = sigdecode_der(sig, n)

                if s < n / 2:
                    vuln = {"type": "short-s", "r": hex(r), "s": hex(s), "txid": txid, "address": address, "balance": balance}
                    save_vulnerability(vuln)
                    scan_all_transactions_for_address(address)

                if s > n / 2:
                    vuln = {"type": "high-s", "r": hex(r), "s": hex(s), "txid": txid, "address": address, "balance": balance}
                    save_vulnerability(vuln)

                if r in found_r_values:
                    vuln = {"type": "duplicate-r", "r": hex(r), "txid": txid, "address": address, "balance": balance}
                    save_vulnerability(vuln)
                else:
                    found_r_values[r] = {"txid": txid, "s": s}

                if s < 2**128:
                    vuln = {"type": "weak-k", "r": hex(r), "s": hex(s), "txid": txid, "address": address, "balance": balance}
                    save_vulnerability(vuln)

            except Exception as e:
                print(f"[❌] Błąd dekodowania podpisu: {e}")

def scan_all_transactions_for_address(address):
    if address in analyzed_addresses:
        return
    analyzed_addresses.add(address)

    print(f"[🔄] Skanuję wszystkie transakcje dla adresu: {address}")
    transactions = get_transactions_by_address(address)
    if not transactions:
        return

    for tx in transactions:
        analyze_transaction(tx["txid"])

# === SKANOWANIE BLOKÓW I MEMPOOL ===
def scan_blocks():
    latest_block = get_block_height()
    if latest_block:
        for height in range(latest_block - 5, latest_block + 1):
            print(f"[📡] Analizuję blok: {height}")
            txids = get_block_txids(height)
            if txids:
                for txid in txids:
                    analyze_transaction(txid)

def scan_mempool():
    print("[⚡] Analizuję mempool...")
    txids = get_mempool_txids()
    if txids:
        for txid in txids[:100]:
            analyze_transaction(txid)

# === GŁÓWNA PĘTLA ===
init_db()
print("[🚀] Najpierw analizuję podane adresy...")
for address in TARGET_ADDRESSES:
    scan_all_transactions_for_address(address)

while True:
    scan_blocks()
    scan_mempool()
    time.sleep(random.randint(15, 30))

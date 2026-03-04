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
    "17vChfcmZpww59iyKAeez8fFpq24JR6Y3g",
    "1KibEpRfnQ1tQf8TBtWxF38ycLq8bWhkRj",
    "1FU4BkmfqThM13Yxzpi31mjNHVWF1uFvd8",
    "1CmnWXTAVhoph4uotb6D7ZeqCnRbzpfaD6",
    "12MiQ25t9ujjDLQjxuCmxvZBT9i8BapNPi",
    "1DH8xaCNcuBWyMx7ctQZaF2uTmBbxxrRqv",
    "1P5kXuzSYgPGy3YahB1faJqA8dhwgu2rUo",
    "1BoX9egHAb8q11nQjW9NxpZdkaHmHp9fUx",
    "15jr1atLg28fyLpV6VyGbkikm9PghpiWP8",
    "15txX7JruEvwsKtvREY8Nw8YQ4cmUbp2LB",
    "14UiF84KQy2VovHEx72QJ6nefRSaqE4AK9",
    "1DyCbQ8gsnNXaKcWAAs4NfNwsEmVGXBAKw",
    "14dRBQKx9fFH2UUmV8aPN3JKzGhJF8Yjga",
    "3HTPdK2Apneidn8VnsZtwpc74pK1YZCseo",
    "1K5Znxkr1ifJD3vMSTpR2pSidM9sweRtfT",
    "3Ni7jARs2kYEdoV8MF9JqmJnn8uqGidCQg",
    "168GMChpuoohi6AkuNx67A6AwsoT4EsnK4",
    "1kic7uMoUmkr3ZSf7JbW5VnM9aq4ZPSg8",
    "1BDG7MAXqjJZRRFQYqubBvwG4YKMbwDgGM",
    "17bLXnT7xTnkQcoSfR1M4F8HKq1bU5cTYS",
    "196DBDruG8Sn21FkCvFt2BDF2HGy26kJYv",
    "1C4E9i6uo2uf35SNDohDkgcu5Mui4pdsog",
    "1LgJvVKaxwHZj2CeTLKLwczkwmXDbr4M6i",
    "1fH6NBqpApakJjxW9ncZHJcxDqX2KWAmn",
    "1AnkWYQSBUJ4whyZoep4AUCvz5z1dz8JHm",
    "1N6yvVTkuYrNf8g5hjeu6K4H3841g28jkr",
    "12qyrQcNcjYSnHn2Z21eY7Zxypf8Zqwqq2",
    "18cf3REdFh6Sd5aymLr17i9VQnTuGjn2q1",
    "13MLbAw87MMQgrXMERv6PdYVQKL9RvWUiD",
    "1B3D1i4dY2W1cEA73gMEVPb5cnmvrxM5Ai",
    "14kdqQxgrVGChKj1Rc8Cyu2QuZfyxe9mTR",
    "1EYYnDDSNPNaZdKSscRrnF7kFYSnHgtYCv",
    "1ExCJwGD2VbgWw7YNp1JjYo9Wv4BjJnEFa",
    "1HYb838QBwzAKXrPVN1R7h1xzr8bW1Y5ro",
    "1CVzhHs6ZbSVfm2RfHgHQ3EkknSSqrXNJD",
    "1JSXnDsGVZ9TyRdJUFGjZpd2MEmEXfndrR",
    "14pBSHwW98NcwMUMmiPcex7JYjTK2bhzuU",
    "1BKSw5BdqvnPaiGmZWyA3iKcV1bUDy7DHL",
    "19eKsUt9LiuYPP4DwyiBPxbMLpTCW3QBGb",
    "1DH81XfhW3T5eVYJMqCY2CFaNbXoNaZvXj",
    "14kMiXSykM5YSEb6CxUJ8Bcvy6wUFWMd4v",
    "18vP8YaiYMZUxiJjzixohqkojN1PPerRUz",
    "1DLTNXv3UcWAZHxd41KjHZqQpVFDrkBqsK",
    "1FVUQ9wH6Gf4VRJBdEHwHMrKufkRX1j8m2",
    "1KT19Y5vn9RY3cSbkk9eqGzvrUbfuFo9Vn",
    "18txsLJj6tmenX8w9kd59JB2xgHfBcwqEr",
    "191q7vS2erTVzYPXWd6MyhNDNKA6DKreZx",
    "153zHg2qkopMexdL6Bmr78v7GjrTokeHuw",
    "143f6K16Czm1mg5hVzyuLz86H3ffRCfyBo",
    "1AcUGQtUPLbb3tuqFK6y6ZwWqmxqwC6Cim",
    "14BFdUkGBSLhoscdaPqhcjz2hZbkvmZshn",
    "17kntjBPVSRcNkE3MsYLHFThYm6KEoq1AV",
    "333L3FMWfCgbsGE6nRCXjATpXvM9wbkHJX",
    "1DdeJEL2mssY48C1me9T9R1179t2PFc6xW",
    "116E6KTATShTR3YeiDPAjU8zDAG4Wx4U9Y",
    "1QJmjiAZrapPyLUDUXYsR4YkGb22rvrC7W",
    "1KKfC8GvJEYArpVyu2W4C12YQtSSgrVnX4",
    "1MAYunEgFphkw5JPVCeQPtQCKLK6zyHpRX",
    "1DkmG7bUFYA431468A6iG82zSWMKV14dG1",
    "1BACKUUjgZq7z6cyc1af4ts6RSDD3pGJ6x",
    "11455FbSdg4mu9Q7zBTzeqGS9eTYUfhFdP",
    "1FBLRKNXwYydQ8H4UmVjSDMuLFZk2htdJ3",
    "1G653sE8XgX9e6Y4mUYhUjqzcEfLHLuAY8",
    "18x3kihJmJWRzVnHwD99mpqmyCXWtPNQ58",
    "16VyWP8H45dbsHojYvMDE1cJg55LT5qsUT",
    "1PrSwAFLMcz3NjJFJMhsJki4mSzJxUn2yZ",
    "1LHak7xc5PonNxko7BWaVuvtAoydWjfZtW",
    "1GgkuWkai4ubkwDYiKE4kx3CHYyNXzYWAf",
    "1GDpQUUCDs5yxRaHo3jUmtZJ2Ct2WcxXek",
    "1Gbtq8xypZqYZDEc5HL7j4PAMKFdMH7jPi",
    "1FQtiujCghMbT3cEX42v79EBHE7BV6YL3Z",
    "3HqSum8ggGQL7uQGNsaG273wakDYMrtKFU",
    "1QKmYMgUD6GqHZ8tNAUCkryURPiqAgNRK4",
    "1DR4Za5sU5B9qAWboMkQJV5FQGxmp8PXpz",
    "19hvA8o3zWJi1c1DMXyFjzk9gSPWhcPzLw",
    "1JHqf9d8yTxg5pMRy34pNJrPZxrHVSSxFY",
    "19D1Pzq5zaQ6jbgyUZJM4AHePPBPhhbeuP",
    "1bZv7R1ofPsubFwBGt8pSumbgMY3rXcot",
    "1GgPDxMcTc74LcNLUpdG6bq2RD3krnxBPd",
    "14jzMsnsswA1FcBGRPaNWudeVAMai9mSKd",
    "19MG8wSXT8MYVp3jKT71ZmpGML67EF5L8u",
    "1MLYiAfoZQFSDVfPj5rRHsCDZ6rj9N78T9",
    "1CVkBTd9xvkTcUWv5H2eswqjFKX5b85Sjz",
    "1KSk9d2YXBepcToBFRpCF8teCqj4qHKMS9",
    "16REWdY1GkThdMTjGxk7FJTdSXS77QvmaP",
    "1NkLZUm4q58zNpxqzQyZwtvEirRTEJRty7",
    "16QUqXUk7PkBHSinSfazZKdoV8HjhW2KEL",
    "1JvJzp8EP7RkTg1Wh9uXw6CmVkqjTQAuL3",
    "1JngFW8a66qyBTCKE4LBP4f9td77ZW99xH",
    "12U5ETJFpwbaspCy1yf1RLnwBYRNLVpyGN",
    "1FJZ954ygDrVPfj9usnhoDmYGmQ41N4PuE",
    "13QD7kagAQMjgMhBCSXdTxcisyLBKCvmaS",
    "17HFkFsVjfG4d1zX6XUniktwe33oTNfEkM",
    "1PhpNFw2pT2YkzNYXvtELxtXm98du8Zimw",
    "1JKuGSLoA1kB3cgx9xnGXCvAE8uq4ae5ux",
    "1Pjae4N2UpCcKHF5rnjCsFCtSx1c99jKeC",
    "1JgbW9XZZtwJUoXqU4WEMfqChVtadagHyK",
    "12KUQAHeoCu94Fv5mQu9kxxMStgZgVRioA",
    "1NrVrqijWKnpe7eqed5pcBNY8c4wbPVkyj",
    "1MbSN7ifELcKPqkFfattgywJDkr8wK7BUA",
    "1Hg6X3RgYt88KrMSmQDHjQGY8wqy7QEm2Y",
    "12Sm8CC4GaxJmDyZVqYyC4tsU62nhR4VtV",
    "12pfxQdxVsAGj68WNVbs93KQKHvcqXyanw",
    "14nF4iwEd2aGqr5SdxotNAhvJhKoLz5v7A",
    "188FGQu4yaKEmAaUh5WKvQRCSmJ3rVisNU",
    "1484Q7Cgo8WaSi46wn6FW3vSjdkqQK5Tqx",
    "181qRvJBDrKBPXpiTD9fM1EZAXAV6fPdmi",
    "1MsdPBpDpJeLAES3mSq6jAfj6BquhyGUrE",
    "13vs7HK8hy3bEoM1DZihroLAnmfB8JDQQK",
    "1NbZs3wc9nyr9QnYYL87KHWve97DwouBQG",
    "1Adcor2tGT9QbjjKHQoZuwcj4Gb6LhmUKR",
    "1A5Qa8V2M5Dmw4m8tGA6AfyxG7XSDYdek3",
    "15b3FKgeHUSrPyBRp5oxdxE3APPx4rPDjU",
    "1CejHpbkqn6aDaHwup3soDqDirze6FA8ds",
    "1LPgyk8ugBtvoEa1Fu44RnvQy9xLrShysL",
    "1EtrRzQVM5igRVvTfEcQUd68ampjpnUgWF",
    "1EdrkX7QKQcHhhxUmW6ZgX5Chi16G6jzD2",
    "1EzEqEjtUCkF7MZGmc68T6FG1zLsTE63Yt",
    "3EYSTBQ9vvjySEnWteiPjnDUGJUXABh9hR",
    "1KN83v5UDYoTJDxndiaxUd7fohkRRw2tLB",
    "18UBGbap2cRHQNfkw2FAcVh2DHHZTadyVi",
    "1Drk7EtrYnjfmEtP7LoyKX3BKb8phESEXU",
    "1JMgyRvSqh84rnqWLN5ziQJDEC6BkXnSUj",
    "1MB1EuzvF2qBY2Q3nvjvfvaVTLzghRWYUY",
    "1G5U26w7UedTFg36L1frzXALZ9yQLGSzxQ",
    "1K5ezHQrePjhK3mhyhKcfvbGG6LMbUviWa",
    "1K1QwAjXHf1pHpE9WL2DkpsRknfK7TyxUr",
    "18eZzjvA7uMzqB2VjyYgZYNpBpQoPCLM7u",
    "1B9So3f634P6d8xeVUhyU8sdFhfsqnRxwu",
    "1MRBgyKaHVzCK8o3Z7AsmEyMeHG7djRzVq",
    "1EMH33MHCkbxEC7Rnq5RULpdPM1DJNj9HY",
    "19tLNqcUN8Ayy6h1y8hQcJpNMNGUj53y1X",
    "15Gq5iCMMHXePJ2LgMNzNatLynvj3N7LpU",
    "1Ak1BYJzuPkcECA2dYeZ97uUmX1mWBKSXD",
    "1EmcUqLBgjg7Q1hGr1kCnAzMLnyRRASaqC",
    "1PmESbRyXgxxFHZcfvJMuP5VHoe9rTNMmr",
    "1A2sUipdKt5NDcxmy8VDDa3iePv4hp85x1",
    "15PGooNRbsYuwttb62K8tHwqQhKmfQtL59",
    "1CJ48oLrscrTQZ11rb7h5aa5ZyJfcV7YT6",
    "121wMoid7uJk1MS4hTKuCU6vFDaTeYEDXn",
    "1JyHd7i6CucRSERKmuSjVtQAMfcpPrnCSS",
    "1Dg7N8J7QEdR7AwbL3pjPRvjsBQMJs98Ng",
    "1GjquxxNaopYkbtibfpoUhfX3ZaVyEMFtH",
    "1NfveLvEncJoCV2rwwjjgdxiNqxdSUrMZE",
    "1FcRnRq8RfGnrBAGTLLRMwpp73wrjurhGh",
    "1Pm4g9dxJaGaynYLSGrvA1FHZRRMfN8mvu",
    "199Gh523J7tVLTvWTF8PpdH7B5hypf1wcg",
    "121bb3n5k4M9XzC4Br7zjMxF7WNappTKNA",
    "18zSCbjraW4Xbik5XMfzWd42Ppnz4GVU4p",
    "1AovPKJD5mkF359oju9yJjJC5jMfgnNpUj",
    "1KCRV3RvFfYs6rLquaiZpVnwn2TtA7cU2x",
    "1GEawH4fgeBwXoCk1EjSh4PGLwmTqLgHsv",
    "13KxZ47opoqjgqBHAhUJLccUcqjXU5zpuw",
    "1EnBfs8maJSTjFk43VNnBvXDaMU2tQPoUm",
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


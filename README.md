# Bitcoin Transaction Vulnerability Scanner (English README)

**Purpose:**  
This project is a **proof-of-concept vulnerability scanner** designed to analyze Bitcoin transactions for weak or risky ECDSA signatures. It queries the public **Blockstream API**, decodes signatures from transaction inputs, and looks for signs of *potentially insecure signature parameters* — such as reused nonces, low-entropy values, or non-standard `s` values.  
It is meant **only for educational, defensive, and research purposes** (e.g., for monitoring known or owned addresses). It is **not** an attack tool.

---

## Overview

This script continuously scans recent Bitcoin blocks, the mempool, and a list of target addresses to identify transactions that may exhibit ECDSA weaknesses. Detected vulnerabilities are stored in a local SQLite database for review and further analysis.

Key features:
- Connects to the **Blockstream.info API** (Mainnet).
- Parses ECDSA signatures directly from transaction input data.
- Detects and logs potentially vulnerable signatures:
  - Reused nonce (`duplicate-r`).
  - High or low `s` values (`high-s`, `short-s`).
  - Very small `s` values (`weak-k`, suggesting weak randomness).
- Maintains a local record of analyzed transactions and found issues.
- Can monitor the mempool and latest blocks in real time.
- Allows prioritization of specific target Bitcoin addresses.

---

## How it works

1. **Initialization**  
   - Creates a local SQLite database (`podatnosci.db`) to store results.  
   - Loads a list of preselected Bitcoin addresses (`TARGET_ADDRESSES`) for focused scanning.

2. **Data retrieval (via Blockstream API)**  
   - Queries recent blocks and mempool data using:
     - `/blocks/tip/height` — latest block height.
     - `/block/{height}` and `/block/{block_hash}/txids` — transaction lists.
     - `/tx/{txid}` — transaction details.
     - `/address/{address}` — address information and balance.
   - Handles rate limiting and retry logic automatically.

3. **Signature extraction & analysis**  
   - Extracts ECDSA signatures from transaction `vin.witness` fields.  
   - Decodes the DER-encoded signature to retrieve `r` and `s` values.
   - Applies several heuristic checks:
     - **Short-S:** `s < n/2`
     - **High-S:** `s > n/2`
     - **Duplicate-R:** same `r` reused in different transactions (can indicate nonce reuse).
     - **Weak-K:** `s < 2^128`, implying unusually small `s`.

4. **Result storage**  
   - Detected issues are inserted into the local database with:
     - `type` (e.g. `duplicate-r`, `high-s`)
     - `txid`
     - `address`
     - `r` and `s` (hex-encoded)
     - `balance` at the time of detection

5. **Continuous scanning loop**  
   - Periodically fetches and analyzes the latest blocks and mempool every 15–30 seconds.  
   - Automatically re-analyzes any addresses associated with suspicious transactions.

---

## Vulnerability indicators (simplified)

| Type | Meaning | Possible risk |
|------|----------|----------------|
| `short-s` | Low `s` values | May indicate deterministic or reduced-range nonce |
| `high-s` | Non-canonical signature | Non-standard, could leak pattern info |
| `duplicate-r` | Same `r` reused | Reuse of nonce → **critical private key exposure** |
| `weak-k` | Very small `s` | Suggests extremely weak randomness or nonce bias |

---

## Database structure (`podatnosci.db`)

| Column | Type | Description |
|---------|------|-------------|
| `id` | INTEGER | Auto-increment primary key |
| `type` | TEXT | Vulnerability category |
| `txid` | TEXT | Transaction ID |
| `address` | TEXT | Bitcoin address linked to vulnerability |
| `r` | TEXT | R component of signature |
| `s` | TEXT | S component of signature |
| `balance` | INTEGER | Balance (in satoshis) at detection time |

---

## Ethical & legal notice

This script is intended solely for:
- Monitoring your own or publicly authorized addresses.
- Research on cryptographic implementation quality.
- Academic demonstrations of nonce misuse detection.

**Do not** use it to monitor or extract data for addresses you do not control or have explicit authorization to analyze.  
Interacting with blockchain APIs is legal, but using any identified information for unauthorized access or exploitation is **not**.

---

## Limitations

- The script only flags potential issues — it does **not** recover keys or exploit vulnerabilities.
- False positives are possible; manual verification is needed.
- It depends on third-party APIs (Blockstream), which can impose rate limits or temporary bans.
- Real-time scanning is resource-intensive and may require API key–based solutions for large-scale monitoring.

---

## Defensive recommendations

- Always generate ECDSA nonces deterministically (RFC 6979) or with a strong CSPRNG.
- Verify your Bitcoin wallet or library uses **low-S normalization** to avoid malleable signatures.
- Regularly audit wallet code for randomness quality.
- Avoid reusing nonces or key material between signatures.

---

## Files

- `scanner.py` — main script (API queries, decoding, vulnerability checks).
- `podatnosci.db` — local SQLite database for discovered vulnerabilities.
- `last_block.txt` — optional helper for tracking progress between runs.
- `README.md` — this documentation file.

---

## Example output (terminal)

[🚀] Najpierw analizuję podane adresy...
[🔄] Skanuję wszystkie transakcje dla adresu: bc1qqqwlm30vy72zqmdwf557t3wjzsvx0jyw28xzul
[📡] Analizuję blok: 870401
[🔍] Analizuję transakcję: 7f3a9b...
[⚠️] Znaleziono duplikat R → potencjalny reuse nonce

---

## Final note

This tool demonstrates how *public blockchain data can reveal cryptographic implementation issues*. It should be used only to **improve security**, not to compromise it.  
If you operate a wallet, exchange, or signing service — you can adapt this scanner to automatically audit your transactions and verify that your signing code never produces unsafe or repeated signature components.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr

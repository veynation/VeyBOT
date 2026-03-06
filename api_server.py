"""
VeyBOT License API
Deploy this on Railway (free tier) — https://railway.app

This is the central key validation server.
- Validates license keys from any customer exe
- Watches Polygon for USDC payments
- Issues keys automatically after payment confirmed

Setup:
1. Create free account at railway.app
2. New project → Deploy from GitHub (or paste this file)
3. Set environment variables:
   ADMIN_SECRET = any long random string (your admin password)
   WALLET       = your Polygon wallet address
4. Copy the Railway URL (e.g. https://veybot-api.up.railway.app)
5. Put that URL in veybot.py as API_URL

Requirements (requirements.txt):
flask
requests
"""

import hashlib
import json
import os
import time
import threading
import requests
from flask import Flask, request, jsonify
from pathlib import Path

app = Flask(__name__)

# Allow requests from anywhere (the exe serves on localhost)
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Secret"
    return response

@app.route("/", methods=["GET", "OPTIONS"])
def index():
    return jsonify({"status": "VeyBOT License API", "version": "1.0"})
WALLET       = os.environ.get("WALLET", "").lower()
PRICE_USDC   = int(os.environ.get("PRICE_USDC", "200"))  # in USDC (200 = $200)
DB_FILE      = Path("keys.json")

USDC_POLYGON = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"  # USDC contract on Polygon
POLYGONSCAN  = "https://api.polygonscan.com/api"
POLY_API_KEY = os.environ.get("POLYGONSCAN_API_KEY", "")  # optional, free key from polygonscan.com

# ── DATABASE ──────────────────────────────────────────────────
def load_db():
    try:
        if DB_FILE.exists():
            return json.loads(DB_FILE.read_text())
    except Exception:
        pass
    return {"keys": [], "pending": []}

def save_db(db):
    DB_FILE.write_text(json.dumps(db, indent=2))

def sha256(s):
    return hashlib.sha256(("veybot_key_salt_" + s).encode()).hexdigest()

def make_key():
    import secrets
    raw = secrets.token_hex(8).upper()
    return f"VEYBOT-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"

# ── ROUTES ────────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({"status": "VeyBOT License API", "version": "1.0"})

@app.route("/api/validate", methods=["POST", "OPTIONS"])
def validate():
    if request.method == "OPTIONS":
        return "", 204
    """Called by the exe to validate a license key."""
    data = request.json or {}
    key = data.get("key", "").strip().upper()
    fp  = data.get("fp", "")  # device fingerprint

    if not key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    db = load_db()
    match = next((k for k in db["keys"] if k["key"] == key), None)

    if not match:
        return jsonify({"valid": False, "reason": "Invalid license key"})
    if match["status"] == "revoked":
        return jsonify({"valid": False, "reason": "Key has been revoked"})
    if match.get("expires", 0) > 0 and time.time() * 1000 > match["expires"]:
        return jsonify({"valid": False, "reason": "License expired"})

    # Device fingerprint lock
    if match.get("fp") and match["fp"] != fp:
        return jsonify({"valid": False, "reason": "Key is locked to a different device"})

    # Bind on first use
    if not match.get("fp") and fp:
        match["fp"] = fp
        match["activated_at"] = int(time.time() * 1000)
        match["status"] = "locked"

    match["last_seen"] = int(time.time() * 1000)
    save_db(db)

    return jsonify({
        "valid": True,
        "customer": match.get("customer", "User"),
        "expires": match.get("expires", 0),
    })

@app.route("/api/purchase/init", methods=["POST", "OPTIONS"])
def purchase_init():
    """
    Called when buyer clicks Buy.
    Returns wallet address and creates a pending payment record.
    """
    data = request.json or {}
    email = data.get("email", "").strip()

    # Create a unique payment ID
    import secrets
    payment_id = secrets.token_hex(8)

    db = load_db()
    db["pending"].append({
        "id":         payment_id,
        "email":      email,
        "created_at": int(time.time()),
        "status":     "waiting",
        "key":        None,
    })
    save_db(db)

    return jsonify({
        "payment_id": payment_id,
        "wallet":     WALLET,
        "amount_usdc": PRICE_USDC,
        "network":    "Polygon",
        "token":      "USDC",
    })

@app.route("/api/purchase/check", methods=["POST", "OPTIONS"])
def purchase_check():
    """
    Polls to see if payment has been confirmed.
    Called every few seconds by the browser after buyer sends payment.
    """
    data = request.json or {}
    payment_id = data.get("payment_id", "")
    tx_hash    = data.get("tx_hash", "").strip().lower()

    db = load_db()
    pending = next((p for p in db["pending"] if p["id"] == payment_id), None)

    if not pending:
        return jsonify({"status": "not_found"})

    # Already issued
    if pending["status"] == "confirmed" and pending["key"]:
        return jsonify({"status": "confirmed", "key": pending["key"]})

    # Check if tx_hash provided — verify on chain
    if tx_hash and tx_hash.startswith("0x"):
        confirmed = verify_tx(tx_hash)
        if confirmed:
            # Issue key
            key = make_key()
            key_hash = sha256(key)
            db["keys"].append({
                "key":        key,
                "hash":       key_hash,
                "customer":   pending.get("email") or "Customer",
                "created":    int(time.time() * 1000),
                "expires":    0,
                "status":     "active",
                "fp":         "",
                "tx_hash":    tx_hash,
                "payment_id": payment_id,
            })
            pending["status"] = "confirmed"
            pending["key"]    = key
            save_db(db)
            return jsonify({"status": "confirmed", "key": key})

    # Auto-check recent transactions on wallet
    if not tx_hash:
        found_tx = scan_wallet_for_payment(payment_id, pending["created_at"])
        if found_tx:
            key = make_key()
            key_hash = sha256(key)
            db["keys"].append({
                "key":        key,
                "hash":       key_hash,
                "customer":   pending.get("email") or "Customer",
                "created":    int(time.time() * 1000),
                "expires":    0,
                "status":     "active",
                "fp":         "",
                "tx_hash":    found_tx,
                "payment_id": payment_id,
            })
            pending["status"] = "confirmed"
            pending["key"]    = key
            save_db(db)
            return jsonify({"status": "confirmed", "key": key})

    return jsonify({"status": "waiting"})

def verify_tx(tx_hash):
    """Verify a specific transaction on Polygon."""
    try:
        params = {
            "module":  "transaction",
            "action":  "gettxreceiptstatus",
            "txhash":  tx_hash,
            "apikey":  POLY_API_KEY or "YourApiKeyToken",
        }
        r = requests.get(POLYGONSCAN, params=params, timeout=10)
        data = r.json()
        if data.get("result", {}).get("status") == "1":
            # Also verify it's a USDC transfer to our wallet
            return verify_usdc_transfer(tx_hash)
    except Exception as e:
        print(f"verify_tx error: {e}")
    return False

def verify_usdc_transfer(tx_hash):
    """Check that the tx is a USDC transfer of correct amount to our wallet."""
    try:
        params = {
            "module":    "account",
            "action":    "tokentx",
            "contractaddress": USDC_POLYGON,
            "address":   WALLET,
            "apikey":    POLY_API_KEY or "YourApiKeyToken",
        }
        r = requests.get(POLYGONSCAN, params=params, timeout=10)
        txs = r.json().get("result", [])
        for tx in txs:
            if tx.get("hash", "").lower() == tx_hash.lower():
                # USDC has 6 decimals
                value = int(tx.get("value", 0)) / 1_000_000
                to    = tx.get("to", "").lower()
                if to == WALLET and value >= PRICE_USDC:
                    return True
    except Exception as e:
        print(f"verify_usdc error: {e}")
    return False

def scan_wallet_for_payment(payment_id, since_ts):
    """Scan wallet for recent USDC payment (auto-detect without tx hash)."""
    try:
        params = {
            "module":    "account",
            "action":    "tokentx",
            "contractaddress": USDC_POLYGON,
            "address":   WALLET,
            "startblock": 0,
            "sort":      "desc",
            "apikey":    POLY_API_KEY or "YourApiKeyToken",
        }
        r = requests.get(POLYGONSCAN, params=params, timeout=10)
        txs = r.json().get("result", [])
        db  = load_db()
        used_txs = {k.get("tx_hash") for k in db["keys"]} | \
                   {p.get("tx_hash") for p in db["pending"] if p.get("tx_hash")}

        for tx in txs:
            tx_time = int(tx.get("timeStamp", 0))
            if tx_time < since_ts - 60:
                break
            value = int(tx.get("value", 0)) / 1_000_000
            to    = tx.get("to", "").lower()
            tx_hash = tx.get("hash", "").lower()

            if to == WALLET and value >= PRICE_USDC and tx_hash not in used_txs:
                return tx_hash
    except Exception as e:
        print(f"scan_wallet error: {e}")
    return None

# ── ADMIN ROUTES ─────────────────────────────────────────────

def require_admin():
    secret = request.headers.get("X-Admin-Secret") or request.json.get("secret", "")
    return secret == ADMIN_SECRET

@app.route("/api/admin/keys", methods=["POST"])
def admin_keys():
    if not require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    db = load_db()
    return jsonify({"keys": db["keys"], "pending": db["pending"]})

@app.route("/api/admin/revoke", methods=["POST"])
def admin_revoke():
    if not require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    key  = data.get("key", "")
    db   = load_db()
    match = next((k for k in db["keys"] if k["key"] == key), None)
    if match:
        match["status"] = "revoked"
        save_db(db)
        return jsonify({"ok": True})
    return jsonify({"error": "Key not found"}), 404

@app.route("/api/admin/add_key", methods=["POST"])
def admin_add_key():
    """Manually add a key (for keys generated by admin.py)."""
    if not require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    key  = data.get("key", "")
    if not key:
        return jsonify({"error": "No key"}), 400
    db = load_db()
    db["keys"].append({
        "key":      key,
        "hash":     sha256(key),
        "customer": data.get("customer", "Manual"),
        "created":  int(time.time() * 1000),
        "expires":  data.get("expires", 0),
        "status":   "active",
        "fp":       "",
    })
    save_db(db)
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"VeyBOT License API running on port {port}")
    app.run(host="0.0.0.0", port=port)

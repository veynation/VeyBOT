"""
VeyBOT License API — deploy on Railway (free tier)
https://railway.app

Environment variables to set in Railway:
  ADMIN_SECRET        = any long password
  WALLET              = your Polygon wallet address (lowercase)
  PRICE_USDC          = 200
  POLYGONSCAN_API_KEY = free key from polygonscan.com (optional)
"""

import hashlib, json, os, time, secrets, requests
from flask import Flask, request, jsonify
from pathlib import Path

app = Flask(__name__)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change-this-secret")
WALLET       = os.environ.get("WALLET", "").lower()
PRICE_USDC   = int(os.environ.get("PRICE_USDC", "200"))
POLY_API_KEY = os.environ.get("POLYGONSCAN_API_KEY", "")
DB_FILE      = Path("keys.json")
USDC_POLYGON = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"
POLYGONSCAN  = "https://api.polygonscan.com/api"

# ── CORS ─────────────────────────────────────────────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Secret"
    return response

@app.route("/", methods=["GET", "OPTIONS"])
def index():
    if request.method == "OPTIONS": return "", 204
    return jsonify({"status": "VeyBOT License API", "version": "1.0"})

# ── DATABASE ─────────────────────────────────────────────────
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
    raw = secrets.token_hex(8).upper()
    return f"VEYBOT-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"

# ── VALIDATE ─────────────────────────────────────────────────
@app.route("/api/validate", methods=["POST", "OPTIONS"])
def validate():
    if request.method == "OPTIONS": return "", 204
    data  = request.json or {}
    key   = data.get("key", "").strip().upper()
    fp    = data.get("fp", "")
    if not key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400
    db    = load_db()
    match = next((k for k in db["keys"] if k["key"] == key), None)
    if not match:
        return jsonify({"valid": False, "reason": "Invalid license key"})
    if match["status"] == "revoked":
        return jsonify({"valid": False, "reason": "Key has been revoked"})
    if match.get("expires", 0) > 0 and time.time() * 1000 > match["expires"]:
        return jsonify({"valid": False, "reason": "License expired"})
    if match.get("fp") and match["fp"] != fp:
        return jsonify({"valid": False, "reason": "Key is locked to a different device"})
    if not match.get("fp") and fp:
        match["fp"]           = fp
        match["activated_at"] = int(time.time() * 1000)
        match["status"]       = "locked"
    match["last_seen"] = int(time.time() * 1000)
    save_db(db)
    return jsonify({"valid": True, "customer": match.get("customer", "User"), "expires": match.get("expires", 0)})

# ── PURCHASE ─────────────────────────────────────────────────
@app.route("/api/purchase/init", methods=["POST", "OPTIONS"])
def purchase_init():
    if request.method == "OPTIONS": return "", 204
    data       = request.json or {}
    payment_id = secrets.token_hex(8)
    db         = load_db()
    db["pending"].append({
        "id": payment_id, "email": data.get("email", ""),
        "created_at": int(time.time()), "status": "waiting", "key": None
    })
    save_db(db)
    return jsonify({"payment_id": payment_id, "wallet": WALLET, "amount_usdc": PRICE_USDC, "network": "Polygon", "token": "USDC"})

@app.route("/api/purchase/check", methods=["POST", "OPTIONS"])
def purchase_check():
    if request.method == "OPTIONS": return "", 204
    data       = request.json or {}
    payment_id = data.get("payment_id", "")
    tx_hash    = data.get("tx_hash", "").strip().lower()
    db         = load_db()
    pending    = next((p for p in db["pending"] if p["id"] == payment_id), None)
    if not pending:
        return jsonify({"status": "not_found"})
    if pending["status"] == "confirmed" and pending["key"]:
        return jsonify({"status": "confirmed", "key": pending["key"]})
    confirmed_tx = None
    if tx_hash and tx_hash.startswith("0x"):
        if verify_usdc_transfer(tx_hash):
            confirmed_tx = tx_hash
    if not confirmed_tx:
        confirmed_tx = scan_wallet_for_payment(pending["created_at"], db)
    if confirmed_tx:
        key = make_key()
        db["keys"].append({
            "key": key, "hash": sha256(key),
            "customer": pending.get("email") or "Customer",
            "created": int(time.time() * 1000), "expires": 0,
            "status": "active", "fp": "",
            "tx_hash": confirmed_tx, "payment_id": payment_id
        })
        pending["status"] = "confirmed"
        pending["key"]    = key
        save_db(db)
        return jsonify({"status": "confirmed", "key": key})
    return jsonify({"status": "waiting"})

def verify_usdc_transfer(tx_hash):
    try:
        params = {
            "module": "account", "action": "tokentx",
            "contractaddress": USDC_POLYGON, "address": WALLET,
            "apikey": POLY_API_KEY or "YourApiKeyToken"
        }
        txs = requests.get(POLYGONSCAN, params=params, timeout=10).json().get("result", [])
        for tx in txs:
            if tx.get("hash", "").lower() == tx_hash:
                value = int(tx.get("value", 0)) / 1_000_000
                if tx.get("to", "").lower() == WALLET and value >= PRICE_USDC:
                    return True
    except Exception as e:
        print(f"verify error: {e}")
    return False

def scan_wallet_for_payment(since_ts, db):
    try:
        params = {
            "module": "account", "action": "tokentx",
            "contractaddress": USDC_POLYGON, "address": WALLET,
            "sort": "desc", "apikey": POLY_API_KEY or "YourApiKeyToken"
        }
        txs  = requests.get(POLYGONSCAN, params=params, timeout=10).json().get("result", [])
        used = {k.get("tx_hash") for k in db["keys"]} | {p.get("tx_hash") for p in db["pending"] if p.get("tx_hash")}
        for tx in txs:
            if int(tx.get("timeStamp", 0)) < since_ts - 60:
                break
            value   = int(tx.get("value", 0)) / 1_000_000
            tx_hash = tx.get("hash", "").lower()
            if tx.get("to", "").lower() == WALLET and value >= PRICE_USDC and tx_hash not in used:
                return tx_hash
    except Exception as e:
        print(f"scan error: {e}")
    return None

# ── ADMIN ─────────────────────────────────────────────────────
def require_admin():
    secret = request.headers.get("X-Admin-Secret", "") or (request.json or {}).get("secret", "")
    return secret == ADMIN_SECRET

@app.route("/api/admin/keys", methods=["POST", "OPTIONS"])
def admin_keys():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(): return jsonify({"error": "Unauthorized"}), 401
    db = load_db()
    return jsonify({"keys": db["keys"], "pending": db["pending"]})

@app.route("/api/admin/revoke", methods=["POST", "OPTIONS"])
def admin_revoke():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(): return jsonify({"error": "Unauthorized"}), 401
    key   = (request.json or {}).get("key", "")
    db    = load_db()
    match = next((k for k in db["keys"] if k["key"] == key), None)
    if match:
        match["status"] = "revoked"
        save_db(db)
        return jsonify({"ok": True})
    return jsonify({"error": "Key not found"}), 404

@app.route("/api/admin/add_key", methods=["POST", "OPTIONS"])
def admin_add_key():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(): return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    key  = data.get("key", "")
    if not key: return jsonify({"error": "No key"}), 400
    db = load_db()
    db["keys"].append({
        "key": key, "hash": sha256(key),
        "customer": data.get("customer", "Manual"),
        "created": int(time.time() * 1000),
        "expires": data.get("expires", 0),
        "status": "active", "fp": ""
    })
    save_db(db)
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"VeyBOT License API running on port {port}")
    app.run(host="0.0.0.0", port=port)

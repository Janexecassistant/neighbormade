#!/usr/bin/env python3
"""NeighborMade — Local Handmade Marketplace (Python stdlib, zero deps)"""

import os, sys, json, sqlite3, hashlib, hmac, uuid, time, mimetypes, re, io
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
import base64, struct, secrets

# ── Config ──────────────────────────────────────────────────────────────
PORT = int(os.environ.get("PORT", 8080))
SECRET = os.environ.get("JWT_SECRET", "nm-secret-change-in-prod-" + secrets.token_hex(8))
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
MAX_FILE_MB = 50  # max single file size
ALLOWED_IMG = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
ALLOWED_VID = {".mp4", ".mov", ".webm"}
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Lightweight JWT-like tokens (HMAC-SHA256, stdlib only) ──────────────
def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64d(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def make_token(user_id: int, role: str) -> str:
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64e(json.dumps({
        "sub": user_id, "role": role,
        "exp": int(time.time()) + 86400 * 7
    }).encode())
    sig = _b64e(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def decode_token(tok: str):
    try:
        header, payload, sig = tok.split(".")
        expected = _b64e(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_b64d(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None

# ── Database ────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "neighbormade.db"))

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'buyer',
        location TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS listings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER NOT NULL REFERENCES users(id),
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        price REAL NOT NULL,
        description TEXT NOT NULL,
        icon TEXT DEFAULT '🎁',
        status TEXT DEFAULT 'active',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS listing_media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        media_type TEXT NOT NULL,  -- 'image' or 'video'
        sort_order INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL REFERENCES listings(id),
        reviewer_id INTEGER NOT NULL REFERENCES users(id),
        rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
        text TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        buyer_id INTEGER NOT NULL REFERENCES users(id),
        total REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL REFERENCES orders(id),
        listing_id INTEGER NOT NULL REFERENCES listings(id),
        qty INTEGER DEFAULT 1,
        price REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS threads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        buyer_id INTEGER NOT NULL REFERENCES users(id),
        seller_id INTEGER NOT NULL REFERENCES users(id),
        listing_id INTEGER REFERENCES listings(id),
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id INTEGER NOT NULL REFERENCES threads(id),
        sender_id INTEGER NOT NULL REFERENCES users(id),
        text TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    );
    """)
    # Seed demo data if empty
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        _seed(db)
    db.commit()
    db.close()

def _hash_pw(pw):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}:{h}"

def _check_pw(stored, pw):
    salt, h = stored.split(":")
    return hmac.compare_digest(h, hashlib.sha256((salt + pw).encode()).hexdigest())

def _seed(db):
    sellers = [
        ("Maria Chen", "maria@demo.com", "seller", "Portland, OR", "Handcrafted pottery & ceramics"),
        ("Birch & Silver", "birch@demo.com", "seller", "Seattle, WA", "Handmade jewelry from nature"),
        ("Wicks & Wonders", "wicks@demo.com", "seller", "Bend, OR", "Artisanal soy candles"),
    ]
    for name, email, role, loc, bio in sellers:
        db.execute("INSERT INTO users (name,email,password_hash,role,location,bio) VALUES (?,?,?,?,?,?)",
                   (name, email, _hash_pw("demo1234"), role, loc, bio))
    db.execute("INSERT INTO users (name,email,password_hash,role,location) VALUES (?,?,?,?,?)",
               ("Demo Buyer", "buyer@demo.com", _hash_pw("demo1234"), "buyer", "Portland, OR"))

    demo_listings = [
        (1, "Rustic Herb Planter", "pottery", 34.00, "Hand-thrown stoneware planter, perfect for your kitchen herbs. Each one is unique.", "🏺"),
        (1, "Ocean Wave Mug Set", "pottery", 48.00, "Set of 2 handmade mugs with ocean-inspired blue glaze.", "🏺"),
        (2, "Silver Leaf Pendant", "jewelry", 52.00, "Real preserved leaf dipped in sterling silver. Comes on 18\" chain.", "💍"),
        (2, "Copper Wire Earrings", "jewelry", 28.00, "Lightweight hammered copper wire earrings with natural patina.", "💍"),
        (3, "Lavender Dreams Candle", "candles", 18.00, "Hand-poured soy wax candle with dried lavender buds. Burns 45+ hours.", "🕯️"),
        (3, "Cedar & Smoke Collection", "candles", 42.00, "Set of 3 small candles: cedar, campfire, and pine needle.", "🕯️"),
    ]
    for sid, title, cat, price, desc, icon in demo_listings:
        db.execute("INSERT INTO listings (seller_id,title,category,price,description,icon) VALUES (?,?,?,?,?,?)",
                   (sid, title, cat, price, desc, icon))

# ── Multipart parser (stdlib) ──────────────────────────────────────────
def parse_multipart(body: bytes, content_type: str):
    """Parse multipart/form-data, return (fields_dict, files_list)."""
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[9:].strip('"')
    if not boundary:
        return {}, []

    fields = {}
    files = []
    delimiter = f"--{boundary}".encode()
    parts = body.split(delimiter)

    for part in parts[1:]:
        if part.strip() == b"--" or part.strip() == b"":
            continue
        if b"\r\n\r\n" in part:
            header_data, file_data = part.split(b"\r\n\r\n", 1)
        elif b"\n\n" in part:
            header_data, file_data = part.split(b"\n\n", 1)
        else:
            continue

        # Strip trailing \r\n
        if file_data.endswith(b"\r\n"):
            file_data = file_data[:-2]
        elif file_data.endswith(b"\n"):
            file_data = file_data[:-1]

        headers_str = header_data.decode("utf-8", errors="replace")
        name_match = re.search(r'name="([^"]*)"', headers_str)
        filename_match = re.search(r'filename="([^"]*)"', headers_str)

        if not name_match:
            continue

        field_name = name_match.group(1)

        if filename_match and filename_match.group(1):
            fname = filename_match.group(1)
            ct_match = re.search(r'Content-Type:\s*(\S+)', headers_str, re.IGNORECASE)
            ct = ct_match.group(1) if ct_match else "application/octet-stream"
            files.append({"field": field_name, "filename": fname, "content_type": ct, "data": file_data})
        else:
            val = file_data.decode("utf-8", errors="replace")
            if field_name in fields:
                if isinstance(fields[field_name], list):
                    fields[field_name].append(val)
                else:
                    fields[field_name] = [fields[field_name], val]
            else:
                fields[field_name] = val

    return fields, files

# ── Request Handler ─────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {fmt % args}")

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _json(self, code, data):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, path):
        try:
            with open(path, "rb") as f:
                content = f.read()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._cors()
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self._json(404, {"error": "Not found"})

    def _serve_file(self, path):
        if not os.path.isfile(path):
            self._json(404, {"error": "File not found"})
            return
        mime, _ = mimetypes.guess_type(path)
        mime = mime or "application/octet-stream"
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "public, max-age=86400")
        self._cors()
        self.end_headers()
        self.wfile.write(data)

    def _get_user(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            data = decode_token(auth[7:])
            if data:
                return data
        return None

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _read_json(self):
        return json.loads(self._read_body() or b"{}")

    # ── Routing ──────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._html(200, os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"))
        elif path.startswith("/uploads/"):
            self._serve_file(os.path.join(UPLOAD_DIR, path[9:]))
        elif path == "/api/listings":
            self._get_listings(qs)
        elif re.match(r"/api/listings/\d+$", path):
            self._get_listing(int(path.split("/")[-1]))
        elif re.match(r"/api/sellers/\d+/profile$", path):
            self._get_seller_profile(int(path.split("/")[-2]))
        elif path == "/api/sellers/dashboard/me":
            self._get_dashboard()
        elif path == "/api/messages/threads":
            self._get_threads()
        elif re.match(r"/api/messages/threads/\d+$", path):
            self._get_thread_messages(int(path.split("/")[-1]))
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/auth/signup":
            self._signup()
        elif path == "/api/auth/login":
            self._login()
        elif path == "/api/listings":
            self._create_listing()
        elif re.match(r"/api/listings/\d+/media$", path):
            self._add_media(int(path.split("/")[-2]))
        elif re.match(r"/api/reviews/\d+$", path):
            self._create_review(int(path.split("/")[-1]))
        elif path == "/api/checkout":
            self._checkout()
        elif re.match(r"/api/messages/threads/\d+$", path):
            self._send_message(int(path.split("/")[-1]))
        elif path == "/api/messages/start":
            self._start_thread()
        else:
            self._json(404, {"error": "Not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if re.match(r"/api/listings/\d+/media/\d+$", path):
            parts = path.split("/")
            self._delete_media(int(parts[-3]), int(parts[-1]))
        elif re.match(r"/api/listings/\d+$", path):
            self._delete_listing(int(path.split("/")[-1]))
        else:
            self._json(404, {"error": "Not found"})

    # ── Auth ─────────────────────────────────────────────────────────────
    def _signup(self):
        d = self._read_json()
        name, email, pw = d.get("name","").strip(), d.get("email","").strip().lower(), d.get("password","")
        role = d.get("role", "buyer")
        location = d.get("location", "")
        if not name or not email or len(pw) < 4:
            return self._json(400, {"error": "Name, email, and password (4+ chars) required"})
        db = get_db()
        if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            db.close()
            return self._json(409, {"error": "Email already registered"})
        cur = db.execute("INSERT INTO users (name,email,password_hash,role,location) VALUES (?,?,?,?,?)",
                         (name, email, _hash_pw(pw), role, location))
        uid = cur.lastrowid
        db.commit()
        initials = "".join(w[0].upper() for w in name.split()[:2])
        token = make_token(uid, role)
        db.close()
        self._json(201, {"token": token, "user": {"id": uid, "name": name, "email": email, "role": role, "initials": initials}})

    def _login(self):
        d = self._read_json()
        email, pw = d.get("email","").strip().lower(), d.get("password","")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not _check_pw(row["password_hash"], pw):
            db.close()
            return self._json(401, {"error": "Invalid email or password"})
        initials = "".join(w[0].upper() for w in row["name"].split()[:2])
        token = make_token(row["id"], row["role"])
        db.close()
        self._json(200, {"token": token, "user": {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"], "initials": initials}})

    # ── Listings ─────────────────────────────────────────────────────────
    def _get_listings(self, qs):
        db = get_db()
        sort_map = {"new": "l.created_at DESC", "low": "l.price ASC", "high": "l.price DESC"}
        sort = sort_map.get(qs.get("sort", ["new"])[0], "l.created_at DESC")
        cat = qs.get("category", [None])[0]
        search = qs.get("search", [None])[0]

        sql = """SELECT l.*, u.name as seller_name, u.location as seller_location,
                 (SELECT file_path FROM listing_media WHERE listing_id=l.id AND media_type='image' ORDER BY sort_order LIMIT 1) as thumb,
                 COALESCE((SELECT AVG(rating) FROM reviews WHERE listing_id=l.id),0) as avg_rating,
                 (SELECT COUNT(*) FROM reviews WHERE listing_id=l.id) as review_count
                 FROM listings l JOIN users u ON l.seller_id=u.id WHERE l.status='active'"""
        params = []
        if cat:
            sql += " AND l.category=?"
            params.append(cat)
        if search:
            sql += " AND (l.title LIKE ? OR l.description LIKE ? OR u.name LIKE ?)"
            params += [f"%{search}%"] * 3
        sql += f" ORDER BY {sort}"

        rows = db.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("thumb"):
                d["photo_url"] = "/uploads/" + d["thumb"]
            result.append(d)
        db.close()
        self._json(200, result)

    def _get_listing(self, lid):
        db = get_db()
        row = db.execute("""SELECT l.*, u.name as seller_name, u.location as seller_location,
                           COALESCE((SELECT AVG(rating) FROM reviews WHERE listing_id=l.id),0) as avg_rating
                           FROM listings l JOIN users u ON l.seller_id=u.id WHERE l.id=?""", (lid,)).fetchone()
        if not row:
            db.close()
            return self._json(404, {"error": "Listing not found"})
        d = dict(row)
        # Get all media
        media = db.execute("SELECT * FROM listing_media WHERE listing_id=? ORDER BY sort_order", (lid,)).fetchall()
        d["media"] = [{"id": m["id"], "url": "/uploads/" + m["file_path"], "type": m["media_type"], "sort_order": m["sort_order"]} for m in media]
        if d["media"]:
            d["photo_url"] = d["media"][0]["url"]
        # Get reviews
        revs = db.execute("""SELECT r.*, u.name as reviewer_name FROM reviews r
                            JOIN users u ON r.reviewer_id=u.id WHERE r.listing_id=? ORDER BY r.created_at DESC""", (lid,)).fetchall()
        d["reviews"] = [dict(r) for r in revs]
        db.close()
        self._json(200, d)

    def _create_listing(self):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        if user["role"] != "seller":
            return self._json(403, {"error": "Seller account required"})

        ct = self.headers.get("Content-Type", "")
        body = self._read_body()

        if "multipart" in ct:
            fields, files = parse_multipart(body, ct)
        else:
            fields = json.loads(body or b"{}")
            files = []

        title = fields.get("title", "").strip()
        category = fields.get("category", "").strip()
        price = fields.get("price", "0")
        desc = fields.get("description", "").strip()
        icon = fields.get("icon", "🎁")

        if not title or not category or not desc:
            return self._json(400, {"error": "Title, category, price, and description required"})

        try:
            price = float(price)
        except ValueError:
            return self._json(400, {"error": "Invalid price"})

        db = get_db()
        cur = db.execute("INSERT INTO listings (seller_id,title,category,price,description,icon) VALUES (?,?,?,?,?,?)",
                         (user["sub"], title, category, price, desc, icon))
        lid = cur.lastrowid

        # Save uploaded files
        saved = []
        for f in files:
            if f["field"] in ("photos", "photo", "videos", "video", "media"):
                ext = os.path.splitext(f["filename"])[1].lower()
                if ext in ALLOWED_IMG:
                    mtype = "image"
                elif ext in ALLOWED_VID:
                    mtype = "video"
                else:
                    continue
                if len(f["data"]) > MAX_FILE_MB * 1024 * 1024:
                    continue
                fname = f"{uuid.uuid4().hex}{ext}"
                fpath = os.path.join(UPLOAD_DIR, fname)
                with open(fpath, "wb") as out:
                    out.write(f["data"])
                db.execute("INSERT INTO listing_media (listing_id, file_path, media_type, sort_order) VALUES (?,?,?,?)",
                           (lid, fname, mtype, len(saved)))
                saved.append({"url": f"/uploads/{fname}", "type": mtype})

        db.commit()
        db.close()
        self._json(201, {"id": lid, "title": title, "media": saved})

    def _add_media(self, lid):
        """Add additional media to existing listing."""
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        db = get_db()
        listing = db.execute("SELECT * FROM listings WHERE id=? AND seller_id=?", (lid, user["sub"])).fetchone()
        if not listing:
            db.close()
            return self._json(404, {"error": "Listing not found or not yours"})

        ct = self.headers.get("Content-Type", "")
        body = self._read_body()
        _, files = parse_multipart(body, ct)

        max_order = db.execute("SELECT COALESCE(MAX(sort_order),0) FROM listing_media WHERE listing_id=?", (lid,)).fetchone()[0]
        saved = []
        for f in files:
            ext = os.path.splitext(f["filename"])[1].lower()
            if ext in ALLOWED_IMG:
                mtype = "image"
            elif ext in ALLOWED_VID:
                mtype = "video"
            else:
                continue
            if len(f["data"]) > MAX_FILE_MB * 1024 * 1024:
                continue
            fname = f"{uuid.uuid4().hex}{ext}"
            fpath = os.path.join(UPLOAD_DIR, fname)
            with open(fpath, "wb") as out:
                out.write(f["data"])
            max_order += 1
            db.execute("INSERT INTO listing_media (listing_id, file_path, media_type, sort_order) VALUES (?,?,?,?)",
                       (lid, fname, mtype, max_order))
            saved.append({"url": f"/uploads/{fname}", "type": mtype})

        db.commit()
        db.close()
        self._json(201, {"added": saved})

    def _delete_media(self, lid, mid):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        db = get_db()
        row = db.execute("""SELECT lm.* FROM listing_media lm
                           JOIN listings l ON lm.listing_id=l.id
                           WHERE lm.id=? AND lm.listing_id=? AND l.seller_id=?""",
                        (mid, lid, user["sub"])).fetchone()
        if not row:
            db.close()
            return self._json(404, {"error": "Media not found"})
        # Delete file
        fpath = os.path.join(UPLOAD_DIR, row["file_path"])
        if os.path.isfile(fpath):
            os.remove(fpath)
        db.execute("DELETE FROM listing_media WHERE id=?", (mid,))
        db.commit()
        db.close()
        self._json(200, {"deleted": mid})

    def _delete_listing(self, lid):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        db = get_db()
        listing = db.execute("SELECT * FROM listings WHERE id=? AND seller_id=?", (lid, user["sub"])).fetchone()
        if not listing:
            db.close()
            return self._json(404, {"error": "Listing not found"})
        # Delete media files
        media = db.execute("SELECT file_path FROM listing_media WHERE listing_id=?", (lid,)).fetchall()
        for m in media:
            fpath = os.path.join(UPLOAD_DIR, m["file_path"])
            if os.path.isfile(fpath):
                os.remove(fpath)
        db.execute("DELETE FROM listing_media WHERE listing_id=?", (lid,))
        db.execute("DELETE FROM listings WHERE id=?", (lid,))
        db.commit()
        db.close()
        self._json(200, {"deleted": lid})

    # ── Seller Profile ───────────────────────────────────────────────────
    def _get_seller_profile(self, sid):
        db = get_db()
        u = db.execute("SELECT id,name,email,role,location,bio,created_at FROM users WHERE id=? AND role='seller'", (sid,)).fetchone()
        if not u:
            db.close()
            return self._json(404, {"error": "Seller not found"})
        d = dict(u)
        d["initials"] = "".join(w[0].upper() for w in d["name"].split()[:2])
        listings = db.execute("""SELECT l.*,
                               (SELECT file_path FROM listing_media WHERE listing_id=l.id AND media_type='image' ORDER BY sort_order LIMIT 1) as thumb,
                               COALESCE((SELECT AVG(rating) FROM reviews WHERE listing_id=l.id),0) as avg_rating,
                               (SELECT COUNT(*) FROM reviews WHERE listing_id=l.id) as review_count
                               FROM listings l WHERE l.seller_id=? AND l.status='active'""", (sid,)).fetchall()
        d["listings"] = []
        for l in listings:
            ld = dict(l)
            ld["seller_name"] = d["name"]
            ld["seller_id"] = sid
            if ld.get("thumb"):
                ld["photo_url"] = "/uploads/" + ld["thumb"]
            d["listings"].append(ld)
        d["total_sales"] = db.execute("SELECT COALESCE(SUM(oi.qty),0) FROM order_items oi JOIN listings l ON oi.listing_id=l.id WHERE l.seller_id=?", (sid,)).fetchone()[0]
        avg = db.execute("SELECT AVG(r.rating) FROM reviews r JOIN listings l ON r.listing_id=l.id WHERE l.seller_id=?", (sid,)).fetchone()[0]
        d["avg_rating"] = avg or 0
        d["review_count"] = db.execute("SELECT COUNT(*) FROM reviews r JOIN listings l ON r.listing_id=l.id WHERE l.seller_id=?", (sid,)).fetchone()[0]
        db.close()
        self._json(200, d)

    # ── Dashboard ────────────────────────────────────────────────────────
    def _get_dashboard(self):
        user = self._get_user()
        if not user or user["role"] != "seller":
            return self._json(403, {"error": "Seller login required"})
        db = get_db()
        listings = db.execute("""SELECT l.*,
                               (SELECT file_path FROM listing_media WHERE listing_id=l.id AND media_type='image' ORDER BY sort_order LIMIT 1) as thumb,
                               COALESCE((SELECT SUM(oi.qty) FROM order_items oi WHERE oi.listing_id=l.id),0) as units_sold
                               FROM listings l WHERE l.seller_id=? AND l.status='active'""", (user["sub"],)).fetchall()
        ls = []
        for l in listings:
            ld = dict(l)
            if ld.get("thumb"):
                ld["photo_url"] = "/uploads/" + ld["thumb"]
            ls.append(ld)
        total_earnings = db.execute("""SELECT COALESCE(SUM(oi.price * oi.qty * 0.98),0)
                                      FROM order_items oi JOIN listings l ON oi.listing_id=l.id
                                      WHERE l.seller_id=?""", (user["sub"],)).fetchone()[0]
        total_orders = db.execute("""SELECT COUNT(DISTINCT o.id) FROM orders o
                                    JOIN order_items oi ON o.id=oi.order_id
                                    JOIN listings l ON oi.listing_id=l.id
                                    WHERE l.seller_id=?""", (user["sub"],)).fetchone()[0]
        db.close()
        self._json(200, {"listings": ls, "total_earnings": total_earnings, "total_orders": total_orders})

    # ── Reviews ──────────────────────────────────────────────────────────
    def _create_review(self, lid):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        d = self._read_json()
        rating = d.get("rating", 0)
        text = d.get("text", "").strip()
        if not (1 <= rating <= 5) or not text:
            return self._json(400, {"error": "Rating (1-5) and text required"})
        db = get_db()
        db.execute("INSERT INTO reviews (listing_id, reviewer_id, rating, text) VALUES (?,?,?,?)",
                   (lid, user["sub"], rating, text))
        db.commit()
        db.close()
        self._json(201, {"success": True})

    # ── Checkout ─────────────────────────────────────────────────────────
    def _checkout(self):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        d = self._read_json()
        items = d.get("items", [])
        if not items:
            return self._json(400, {"error": "Cart is empty"})

        db = get_db()
        total = 0
        resolved = []
        for it in items:
            listing = db.execute("SELECT * FROM listings WHERE id=?", (it["listing_id"],)).fetchone()
            if listing:
                qty = it.get("qty", 1)
                total += listing["price"] * qty
                resolved.append((listing["id"], qty, listing["price"]))

        cur = db.execute("INSERT INTO orders (buyer_id, total, status) VALUES (?,?,?)",
                         (user["sub"], total, "completed"))
        oid = cur.lastrowid
        for lid, qty, price in resolved:
            db.execute("INSERT INTO order_items (order_id, listing_id, qty, price) VALUES (?,?,?,?)",
                       (oid, lid, qty, price))
        db.commit()
        db.close()
        # In production, this would redirect to Stripe Checkout
        self._json(200, {"success": True, "order_id": oid, "message": "Order placed! (Stripe integration coming soon)"})

    # ── Messages ─────────────────────────────────────────────────────────
    def _get_threads(self):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        db = get_db()
        threads = db.execute("""SELECT t.*,
                               b.name as buyer_name, s.name as seller_name,
                               l.title as listing_title,
                               (SELECT text FROM messages WHERE thread_id=t.id ORDER BY created_at DESC LIMIT 1) as last_message,
                               (SELECT COUNT(*) FROM messages WHERE thread_id=t.id) as message_count
                               FROM threads t
                               JOIN users b ON t.buyer_id=b.id
                               JOIN users s ON t.seller_id=s.id
                               LEFT JOIN listings l ON t.listing_id=l.id
                               WHERE t.buyer_id=? OR t.seller_id=?
                               ORDER BY t.created_at DESC""", (user["sub"], user["sub"])).fetchall()
        db.close()
        self._json(200, [dict(t) for t in threads])

    def _get_thread_messages(self, tid):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        db = get_db()
        msgs = db.execute("""SELECT m.*, u.name as sender_name FROM messages m
                            JOIN users u ON m.sender_id=u.id WHERE m.thread_id=?
                            ORDER BY m.created_at ASC""", (tid,)).fetchall()
        db.close()
        self._json(200, [dict(m) for m in msgs])

    def _send_message(self, tid):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        d = self._read_json()
        text = d.get("text", "").strip()
        if not text:
            return self._json(400, {"error": "Message text required"})
        db = get_db()
        db.execute("INSERT INTO messages (thread_id, sender_id, text) VALUES (?,?,?)",
                   (tid, user["sub"], text))
        db.commit()
        db.close()
        self._json(201, {"success": True})

    def _start_thread(self):
        user = self._get_user()
        if not user:
            return self._json(401, {"error": "Login required"})
        d = self._read_json()
        seller_id = d.get("seller_id")
        listing_id = d.get("listing_id")
        text = d.get("text", "").strip()
        if not seller_id:
            return self._json(400, {"error": "seller_id required"})
        db = get_db()
        # Check for existing thread
        existing = db.execute("SELECT id FROM threads WHERE buyer_id=? AND seller_id=? AND listing_id=?",
                              (user["sub"], seller_id, listing_id)).fetchone()
        if existing:
            tid = existing["id"]
        else:
            cur = db.execute("INSERT INTO threads (buyer_id, seller_id, listing_id) VALUES (?,?,?)",
                             (user["sub"], seller_id, listing_id))
            tid = cur.lastrowid
        if text:
            db.execute("INSERT INTO messages (thread_id, sender_id, text) VALUES (?,?,?)",
                       (tid, user["sub"], text))
        db.commit()
        db.close()
        self._json(201, {"thread_id": tid})


# ── Main ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print(f"🏪 NeighborMade running on http://0.0.0.0:{PORT}")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()

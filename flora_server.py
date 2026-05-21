"""
FLORA Wellness App — Railway Backend
Flask + SQLite (Railway volume) with JWT auth, Google OAuth, Claude AI integration

Deploy to Railway:
1. Create new Railway project
2. Add this file as flora_server.py
3. Add requirements.txt
4. Set environment variables (see bottom of file)
5. Railway auto-deploys on push
"""

from flask import Flask, request, jsonify, make_response
import sqlite3, hashlib, secrets, json, os, smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
import urllib.request, urllib.parse

app = Flask(__name__)

@app.after_request  
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Claude-Key'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

@app.route('/', methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options_handler(path=''):
    response = make_response()
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Claude-Key'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response, 200

DB_PATH = os.environ.get("DB_PATH", "/data/flora.db")
SECRET   = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
CLAUDE_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
SENDGRID_KEY = os.environ.get("SENDGRID_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "hello@flora-wellness.app")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://your-site.netlify.app")

# ── DATABASE ─────────────────────────────────────────────────────────────────

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name TEXT,
        password_hash TEXT,
        google_id TEXT,
        token TEXT,
        reset_token TEXT,
        reset_expires TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        last_login TEXT
    );

    CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY,
        data TEXT,
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS daily_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        date TEXT,
        data TEXT,
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        date TEXT,
        data TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS labs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        date TEXT,
        data TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        month TEXT,
        content TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        data TEXT,
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    db.commit()
    db.close()

# ── HELPERS ──────────────────────────────────────────────────────────────────

def hash_pw(pw): return hashlib.sha256((pw + SECRET).encode()).hexdigest()
def gen_token(): return secrets.token_urlsafe(32)

def get_user_by_token(token):
    if not token: return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    db.close()
    return dict(user) if user else None

def auth_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        user = get_user_by_token(token)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        return f(user, *args, **kwargs)
    return decorated

def send_email(to, subject, body):
    try:
        if SENDGRID_KEY:
            import urllib.request
            data = json.dumps({
                "personalizations": [{"to": [{"email": to}]}],
                "from": {"email": FROM_EMAIL, "name": "FLORA Wellness"},
                "subject": subject,
                "content": [{"type": "text/plain", "value": body}]
            }).encode()
            req = urllib.request.Request(
                "https://api.sendgrid.com/v3/mail/send",
                data=data,
                headers={"Authorization": f"Bearer {SENDGRID_KEY}", "Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req)
    except Exception as e:
        print(f"Email error: {e}")

# ── AUTH ROUTES ───────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "FLORA API running 🌸", "version": "2.0"})

@app.route("/auth/signup", methods=["POST", "OPTIONS"])
def signup():
    if request.method == "OPTIONS": return "", 204
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    token = gen_token()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (email, name, password_hash, token, last_login) VALUES (?,?,?,?,?)",
            (email, name, hash_pw(password), token, datetime.now().isoformat())
        )
        db.commit()
        user_id = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        db.close()

        # Welcome email
        send_email(email, "Welcome to FLORA 🌸", f"""Hi {name or 'there'}!

Welcome to FLORA — your personalized wellness OS.

Your account is ready. Complete your health questionnaire to get your personalized plan.

Questions? Reply to this email.

The FLORA Team 🌸""")

        return jsonify({"success": True, "token": token, "user": {"id": user_id, "email": email, "name": name}})
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({"error": "An account with this email already exists"}), 400

@app.route("/auth/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS": return "", 204
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or user["password_hash"] != hash_pw(password):
        db.close()
        return jsonify({"error": "Invalid email or password"}), 401

    token = gen_token()
    db.execute("UPDATE users SET token=?, last_login=? WHERE id=?",
               (token, datetime.now().isoformat(), user["id"]))
    db.commit()

    # Load profile
    profile_row = db.execute("SELECT data FROM profiles WHERE user_id=?", (user["id"],)).fetchone()
    profile = json.loads(profile_row["data"]) if profile_row else None
    db.close()

    return jsonify({
        "success": True,
        "token": token,
        "user": {"id": user["id"], "email": email, "name": user["name"]},
        "hasProfile": profile is not None,
        "profile": profile
    })

@app.route("/auth/google", methods=["POST", "OPTIONS"])
def google_auth():
    if request.method == "OPTIONS": return "", 204
    data = request.get_json() or {}
    id_token = data.get("id_token", "")

    # Verify Google token
    try:
        verify_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
        req = urllib.request.Request(verify_url)
        resp = urllib.request.urlopen(req)
        g_data = json.loads(resp.read())

        if g_data.get("aud") != GOOGLE_CLIENT_ID:
            return jsonify({"error": "Invalid Google token"}), 401

        email = g_data.get("email", "").lower()
        name = g_data.get("name", "")
        google_id = g_data.get("sub", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        token = gen_token()

        if user:
            db.execute("UPDATE users SET token=?, last_login=?, google_id=? WHERE id=?",
                      (token, datetime.now().isoformat(), google_id, user["id"]))
            user_id = user["id"]
        else:
            db.execute(
                "INSERT INTO users (email, name, google_id, token, last_login) VALUES (?,?,?,?,?)",
                (email, name, google_id, token, datetime.now().isoformat())
            )
            user_id = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]

        db.commit()
        profile_row = db.execute("SELECT data FROM profiles WHERE user_id=?", (user_id,)).fetchone()
        profile = json.loads(profile_row["data"]) if profile_row else None
        db.close()

        return jsonify({
            "success": True,
            "token": token,
            "user": {"id": user_id, "email": email, "name": name},
            "hasProfile": profile is not None,
            "profile": profile
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/auth/forgot", methods=["POST", "OPTIONS"])
def forgot():
    if request.method == "OPTIONS": return "", 204
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if user:
        reset_token = gen_token()
        expires = (datetime.now() + timedelta(hours=1)).isoformat()
        db.execute("UPDATE users SET reset_token=?, reset_expires=? WHERE id=?",
                  (reset_token, expires, user["id"]))
        db.commit()
        link = f"{FRONTEND_URL}?reset={reset_token}&email={email}"
        send_email(email, "Reset your FLORA password", f"""Hi {user['name'] or 'there'},

Click the link below to reset your password. It expires in 1 hour.

{link}

If you didn't request this, ignore this email.

The FLORA Team 🌸""")
    db.close()
    return jsonify({"success": True})  # Always success to prevent email enumeration

@app.route("/auth/reset", methods=["POST", "OPTIONS"])
def reset_password():
    if request.method == "OPTIONS": return "", 204
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    reset_token = data.get("token", "")
    new_password = data.get("password", "")

    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=? AND reset_token=?", (email, reset_token)).fetchone()
    if not user:
        db.close()
        return jsonify({"error": "Invalid or expired reset link"}), 400

    if datetime.fromisoformat(user["reset_expires"]) < datetime.now():
        db.close()
        return jsonify({"error": "Reset link has expired. Please request a new one."}), 400

    token = gen_token()
    db.execute("UPDATE users SET password_hash=?, token=?, reset_token=NULL, reset_expires=NULL WHERE id=?",
              (hash_pw(new_password), token, user["id"]))
    db.commit()
    db.close()
    return jsonify({"success": True, "token": token})

# ── PROFILE ───────────────────────────────────────────────────────────────────

@app.route("/profile", methods=["GET", "POST", "OPTIONS"])
@auth_required
def profile(user):
    if request.method == "OPTIONS": return "", 204
    db = get_db()

    if request.method == "GET":
        row = db.execute("SELECT data FROM profiles WHERE user_id=?", (user["id"],)).fetchone()
        db.close()
        return jsonify({"profile": json.loads(row["data"]) if row else None})

    data = request.get_json() or {}
    profile_data = json.dumps(data.get("profile", {}))
    existing = db.execute("SELECT user_id FROM profiles WHERE user_id=?", (user["id"],)).fetchone()
    if existing:
        db.execute("UPDATE profiles SET data=?, updated_at=? WHERE user_id=?",
                  (profile_data, datetime.now().isoformat(), user["id"]))
    else:
        db.execute("INSERT INTO profiles (user_id, data) VALUES (?,?)", (user["id"], profile_data))
    # Also update name in users table
    name = data.get("profile", {}).get("name", "")
    if name:
        db.execute("UPDATE users SET name=? WHERE id=?", (name, user["id"]))
    db.commit()
    db.close()
    return jsonify({"success": True})

# ── DAILY LOG ─────────────────────────────────────────────────────────────────

@app.route("/daily", methods=["GET", "POST", "OPTIONS"])
@auth_required
def daily(user):
    if request.method == "OPTIONS": return "", 204
    db = get_db()
    today = datetime.now().strftime("%Y-%m-%d")

    if request.method == "GET":
        date = request.args.get("date", today)
        row = db.execute("SELECT data FROM daily_logs WHERE user_id=? AND date=?",
                        (user["id"], date)).fetchone()
        db.close()
        return jsonify({"log": json.loads(row["data"]) if row else None, "date": date})

    data = request.get_json() or {}
    date = data.get("date", today)
    log_data = json.dumps(data.get("log", {}))
    existing = db.execute("SELECT id FROM daily_logs WHERE user_id=? AND date=?",
                         (user["id"], date)).fetchone()
    if existing:
        db.execute("UPDATE daily_logs SET data=?, updated_at=? WHERE user_id=? AND date=?",
                  (log_data, datetime.now().isoformat(), user["id"], date))
    else:
        db.execute("INSERT INTO daily_logs (user_id, date, data) VALUES (?,?,?)",
                  (user["id"], date, log_data))
    db.commit()
    db.close()
    return jsonify({"success": True})

# ── METRICS ───────────────────────────────────────────────────────────────────

@app.route("/metrics", methods=["GET", "POST", "OPTIONS"])
@auth_required
def metrics(user):
    if request.method == "OPTIONS": return "", 204
    db = get_db()

    if request.method == "GET":
        rows = db.execute("SELECT date, data FROM metrics WHERE user_id=? ORDER BY date DESC LIMIT 50",
                         (user["id"],)).fetchall()
        db.close()
        return jsonify({"metrics": [{"date": r["date"], **json.loads(r["data"])} for r in rows]})

    data = request.get_json() or {}
    entry = data.get("entry", {})
    date = entry.get("date", datetime.now().strftime("%Y-%m-%d"))
    db.execute("INSERT INTO metrics (user_id, date, data) VALUES (?,?,?)",
              (user["id"], date, json.dumps(entry)))
    db.commit()
    db.close()
    return jsonify({"success": True})

# ── LABS ──────────────────────────────────────────────────────────────────────

@app.route("/labs", methods=["GET", "POST", "OPTIONS"])
@auth_required
def labs(user):
    if request.method == "OPTIONS": return "", 204
    db = get_db()

    if request.method == "GET":
        rows = db.execute("SELECT date, data FROM labs WHERE user_id=? ORDER BY date DESC LIMIT 20",
                         (user["id"],)).fetchall()
        db.close()
        return jsonify({"labs": [{"date": r["date"], **json.loads(r["data"])} for r in rows]})

    data = request.get_json() or {}
    entry = data.get("entry", {})
    date = entry.get("date", datetime.now().strftime("%Y-%m-%d"))
    db.execute("INSERT INTO labs (user_id, date, data) VALUES (?,?,?)",
              (user["id"], date, json.dumps(entry)))
    db.commit()
    db.close()
    return jsonify({"success": True})

# ── INVENTORY ─────────────────────────────────────────────────────────────────

@app.route("/inventory", methods=["GET", "POST", "OPTIONS"])
@auth_required
def inventory(user):
    if request.method == "OPTIONS": return "", 204
    db = get_db()

    if request.method == "GET":
        row = db.execute("SELECT data FROM inventory WHERE user_id=?", (user["id"],)).fetchone()
        db.close()
        return jsonify({"inventory": json.loads(row["data"]) if row else []})

    data = request.get_json() or {}
    inv = json.dumps(data.get("inventory", []))
    existing = db.execute("SELECT user_id FROM inventory WHERE user_id=?", (user["id"],)).fetchone()
    if existing:
        db.execute("UPDATE inventory SET data=?, updated_at=? WHERE user_id=?",
                  (inv, datetime.now().isoformat(), user["id"]))
    else:
        db.execute("INSERT INTO inventory (user_id, data) VALUES (?,?)", (user["id"], inv))
    db.commit()
    db.close()
    return jsonify({"success": True})

# ── AI PLAN GENERATION ────────────────────────────────────────────────────────

@app.route("/generate-plan", methods=["POST", "OPTIONS"])
@auth_required
def generate_plan(user):
    if request.method == "OPTIONS": return "", 204

    api_key = request.headers.get("X-Claude-Key") or CLAUDE_KEY
    if not api_key:
        return jsonify({"error": "No Claude API key configured"}), 400

    data = request.get_json() or {}
    profile = data.get("profile", {})
    questionnaire = data.get("questionnaire", {})
    labs_data = data.get("labs", [])
    is_onboarding = data.get("is_onboarding", False)

    # Build prompt
    if is_onboarding:
        prompt = f"""You are FLORA, a compassionate and expert functional medicine wellness AI. 
A new user has just completed their health intake questionnaire. Generate a comprehensive, personalized wellness plan for them.

USER INTAKE:
Name: {questionnaire.get('name', 'User')}
Age: {questionnaire.get('age', 'Unknown')}
Height/Weight: {questionnaire.get('height', '')} / {questionnaire.get('weight', '')} lbs
Goal weight: {questionnaire.get('goalWeight', '')} lbs

PRIMARY HEALTH CONDITIONS: {questionnaire.get('conditions', 'None specified')}
SYMPTOMS EXPERIENCING: {questionnaire.get('symptoms', 'None specified')}
CURRENT MEDICATIONS/SUPPLEMENTS: {questionnaire.get('medications', 'None')}
HORMONE/CYCLE STATUS: {questionnaire.get('hormoneStatus', 'Not specified')}
DIETARY RESTRICTIONS/PREFERENCES: {questionnaire.get('diet', 'None')}
EXERCISE HISTORY & GOALS: {questionnaire.get('exercise', 'Not specified')}
SLEEP & STRESS LEVEL: {questionnaire.get('lifestyle', 'Not specified')}
MAIN WELLNESS GOAL: {questionnaire.get('mainGoal', 'General wellness')}
ANYTHING ELSE: {questionnaire.get('other', '')}

Generate a personalized plan with these sections:
1. YOUR WELLNESS PROFILE — 2-3 sentences summarizing what you understand about their health
2. TOP 3 PRIORITIES — the most important things to focus on first
3. RECOMMENDED SUPPLEMENTS — specific supplements with doses and timing based on their conditions
4. NUTRITION FRAMEWORK — dietary approach tailored to their conditions (no generic advice)
5. EXERCISE PROTOCOL — specific workout recommendations based on their goals and conditions
6. DAILY ROUTINE — morning to evening structure
7. WHAT TO TRACK — key metrics and tests to monitor
8. 30-DAY MILESTONES — realistic expectations for the first month

Be specific, warm, and evidence-based. Reference their specific conditions by name. Keep total response under 600 words."""

    else:
        latest_labs = labs_data[0] if labs_data else {}
        prompt = f"""You are FLORA wellness AI generating a monthly plan update.

USER: {profile.get('name', 'User')}, age {profile.get('age', '')}, {profile.get('conditions', [])}
MEDICATIONS: {profile.get('meds', '')}
LATEST LABS: {json.dumps(latest_labs)}
CYCLE DAY: {data.get('cycleDay', 'Unknown')}
CYCLE PHASE: {data.get('cyclePhase', 'Unknown')}
GOAL: {profile.get('goal', '')}

Generate a focused monthly plan update (250-300 words) covering:
1. TOP 3 PRIORITIES this month based on current phase and labs
2. DIETARY FOCUS for this month  
3. SUPPLEMENT ADJUSTMENTS if any
4. EXERCISE MODIFICATIONS if any
5. WHAT TO WATCH — key indicators for this month

Be specific and reference their actual lab numbers and cycle phase."""

    # Call Claude API
    try:
        req_data = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            },
            method="POST"
        )
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        plan_text = result["content"][0]["text"]

        # Save plan to DB
        db = get_db()
        month = datetime.now().strftime("%Y-%m")
        db.execute("INSERT INTO plans (user_id, month, content) VALUES (?,?,?)",
                  (user["id"], month, plan_text))
        db.commit()
        db.close()

        return jsonify({"success": True, "plan": plan_text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── PLANS HISTORY ─────────────────────────────────────────────────────────────

@app.route("/plans", methods=["GET", "OPTIONS"])
@auth_required
def get_plans(user):
    if request.method == "OPTIONS": return "", 204
    db = get_db()
    rows = db.execute("SELECT month, content, created_at FROM plans WHERE user_id=? ORDER BY created_at DESC LIMIT 12",
                     (user["id"],)).fetchall()
    db.close()
    return jsonify({"plans": [{"month": r["month"], "content": r["content"], "created_at": r["created_at"]} for r in rows]})

# ── START ─────────────────────────────────────────────────────────────────────


@app.route("/seed-user", methods=["POST", "OPTIONS"])
def seed_user():
    if request.method == "OPTIONS": return "", 204
    data = request.get_json() or {}
    if data.get("secret") != os.environ.get("ADMIN_SECRET", "flora_seed_2026"):
        return jsonify({"error": "Unauthorized"}), 401
    email = data.get("email", "")
    if not email: return jsonify({"error": "Email required"}), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user: db.close(); return jsonify({"error": "User not found"}), 404
    user_id = user["id"]
    profile = data.get("profile")
    if profile:
        profile_data = json.dumps(profile)
        existing = db.execute("SELECT user_id FROM profiles WHERE user_id=?", (user_id,)).fetchone()
        if existing: db.execute("UPDATE profiles SET data=?, updated_at=? WHERE user_id=?", (profile_data, datetime.now().isoformat(), user_id))
        else: db.execute("INSERT INTO profiles (user_id, data) VALUES (?,?)", (user_id, profile_data))
    for lab in data.get("labs", []):
        db.execute("INSERT INTO labs (user_id, date, data) VALUES (?,?,?)", (user_id, lab.get("date", datetime.now().strftime("%Y-%m-%d")), json.dumps(lab)))
    for m in data.get("metrics", []):
        db.execute("INSERT INTO metrics (user_id, date, data) VALUES (?,?,?)", (user_id, m.get("date", datetime.now().strftime("%Y-%m-%d")), json.dumps(m)))
    plan = data.get("plan")
    if plan: db.execute("INSERT INTO plans (user_id, month, content) VALUES (?,?,?)", (user_id, datetime.now().strftime("%Y-%m"), plan))
    inventory = data.get("inventory")
    if inventory:
        inv_data = json.dumps(inventory)
        existing = db.execute("SELECT user_id FROM inventory WHERE user_id=?", (user_id,)).fetchone()
        if existing: db.execute("UPDATE inventory SET data=? WHERE user_id=?", (inv_data, user_id))
        else: db.execute("INSERT INTO inventory (user_id, data) VALUES (?,?)", (user_id, inv_data))
    db.commit(); db.close()
    return jsonify({"success": True})



def seed_owner_data():
    """Seed owner data if account exists and has no profile"""
    try:
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", ("ccvilch@gmail.com",)).fetchone()
        if not user:
            db.close()
            return
        user_id = user["id"]
        # Check if profile already exists
        existing = db.execute("SELECT user_id FROM profiles WHERE user_id=?", (user_id,)).fetchone()
        if existing:
            db.close()
            return  # Already seeded
        
        profile = {"name":"","age":33,"height":"5'5","weight":130,"goalWeight":125,"conditions":["Lean PCOS","Hashimoto's thyroiditis (controlled)","Melasma"],"symptoms":["Always feeling cold","Melasma / skin pigmentation","Hair thinning","Unwanted hair growth","Constipation","Crying easily","Weight gain (especially midsection)"],"goal":"Body recomposition (build muscle + lose fat)","meds":"Metformin 500mg twice daily, Semaglutide weekly injection","diet":["No grains or pasta"],"fitnessLevel":"Active — 3-4x/week","exerciseTypes":"Weight training, walking, swimming","workoutTime":"14:00","exerciseGoal":"Body recomposition","periodStart":"","cycleLength":28,"calorieTarget":1450,"proteinTarget":110,"waterTarget":11,"sleep":"7-8 hours","stress":"6","job":"Entrepreneur / high stress","alcohol":"Occasional (1-2x/month)","apiKey":"","onboarded":True}
        
        db.execute("INSERT INTO profiles (user_id, data) VALUES (?,?)", (user_id, json.dumps(profile)))
        
        # Labs
        labs = {"date":"2026-04-13","prog":15.0,"estradiol":134,"tsh":2.75,"ir":4,"ft":"pending","shbg":"pending","crp":0.6,"dheas":787,"hba1c":4.7,"fib4":0.62,"hdl":64,"ldl":89,"triglycerides":63,"apob":79,"alt":16,"ast":19,"ggt":11,"platelet":251,"notes":"Quest Diagnostics Apr 13 2026 Day 22 Fasting Lean PCOS confirmed Fatty liver resolved No insulin resistance"}
        db.execute("INSERT INTO labs (user_id, date, data) VALUES (?,?,?)", (user_id, "2026-04-13", json.dumps(labs)))
        
        # Metrics
        for m in [{"date":"2026-04-01","weight":132,"bf":26,"waist":28,"hip":38,"energy":6,"mood":6},{"date":"2026-05-01","weight":130,"bf":25,"waist":27.2,"hip":37.2,"energy":7,"mood":8},{"date":"2026-05-20","weight":130,"bf":25,"waist":27,"hip":37,"energy":7,"mood":7}]:
            db.execute("INSERT INTO metrics (user_id, date, data) VALUES (?,?,?)", (user_id, m["date"], json.dumps(m)))
        
        # Plan
        plan = "FLORA PERSONALIZED WELLNESS PLAN — May 2026\n\nYOUR WELLNESS PROFILE\nLean PCOS confirmed with Hashimoto's (controlled, TPO <1) and Melasma. April 2026 labs: IR score 4, HbA1c 4.7%, hsCRP 0.6 — no insulin resistance. Fatty liver resolved (FIB-4 0.62). Symptoms driven by estrogen/progesterone imbalance of Lean PCOS, compounded by 14 months Santal 33 + EDITION diffuser exposure (both removed). In the recovery arc.\n\nTOP 3 PRIORITIES\n1. Progesterone support — Vitex + Vitamin C 1000mg + Magnesium + Zinc daily\n2. Anti-androgen — Spearmint tea 2 cups daily (29% testosterone reduction in trials)\n3. Estrogen clearance — Cruciferous veg daily + chia seeds 2 tbsp\n\nSUPPLEMENTS\nMorning: Ovasitol, Vitamin C 1000mg, B6 P5P 50mg, Vitex 400mg, Spearmint 900mg\nDinner: Zinc 30mg, Omega-3 2g\nAfter dinner: Chia seeds 2 tbsp in water\nBedtime: Magnesium Glycinate 300mg, Probiotic 50B CFU\nDaily: 2 Brazil nuts (selenium)\n\nNEXT LABS\nFree Testosterone + SHBG (questhealth.com ~$89)\nDHEA-S + Cortisol (~$99)"
        db.execute("INSERT INTO plans (user_id, month, content) VALUES (?,?,?)", (user_id, "2026-05", plan))
        
        # Inventory
        inventory = [{"name":"Wild Sockeye Salmon","cat":"Protein","qty":2,"unit":"bags","days":14,"emoji":"🐟"},{"name":"Kirkland Greek Yogurt","cat":"Dairy","qty":1,"unit":"tub","days":10,"emoji":"🥛"},{"name":"Kirkland Pasture-Raised Eggs","cat":"Protein","qty":60,"unit":"count","days":21,"emoji":"🥚"},{"name":"Organic Baby Spinach","cat":"Vegetables","qty":2,"unit":"bags","days":7,"emoji":"🥬"},{"name":"Organic Avocados","cat":"Vegetables","qty":8,"unit":"count","days":7,"emoji":"🥑"},{"name":"Organic Black Beans","cat":"Legumes","qty":6,"unit":"cans","days":30,"emoji":"🫘"},{"name":"Organic Chickpeas","cat":"Legumes","qty":6,"unit":"cans","days":30,"emoji":"🫘"},{"name":"Kirkland Dried Lentils","cat":"Legumes","qty":1,"unit":"bag","days":60,"emoji":"🫘"},{"name":"Organic Chia Seeds","cat":"Nuts & Seeds","qty":1,"unit":"bag","days":30,"emoji":"🌱"},{"name":"Organic Pumpkin Seeds","cat":"Nuts & Seeds","qty":1,"unit":"bag","days":21,"emoji":"🎃"},{"name":"Kirkland EVOO","cat":"Oils","qty":1,"unit":"tin","days":60,"emoji":"🫒"},{"name":"Spearmint Tea","cat":"Pantry","qty":2,"unit":"boxes","days":30,"emoji":"🍵"},{"name":"Lindt 85% Dark Chocolate","cat":"Pantry","qty":3,"unit":"bars","days":21,"emoji":"🍫"},{"name":"Wild Planet Tuna","cat":"Protein","qty":6,"unit":"cans","days":30,"emoji":"🐟"},{"name":"Organic Mixed Berries","cat":"Frozen","qty":2,"unit":"bags","days":30,"emoji":"🫐"},{"name":"Ovasitol Powder","cat":"Supplements","qty":1,"unit":"bottle","days":90,"emoji":"💊"}]
        db.execute("INSERT INTO inventory (user_id, data) VALUES (?,?)", (user_id, json.dumps(inventory)))
        
        db.commit()
        db.close()
        print("Owner data seeded successfully")
    except Exception as e:
        print("Seed error:", e)


init_db()
seed_owner_data()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

"""
RAILWAY ENVIRONMENT VARIABLES TO SET:
──────────────────────────────────────
DB_PATH              = /data/flora.db
FLASK_SECRET         = (generate with: python -c "import secrets; print(secrets.token_hex(32))")
ANTHROPIC_API_KEY    = sk-ant-... (optional - users can provide their own)
GOOGLE_CLIENT_ID     = (from Google Cloud Console - for Google sign-in)
GOOGLE_CLIENT_SECRET = (from Google Cloud Console)
SENDGRID_API_KEY     = (for password reset emails - optional)
FROM_EMAIL           = hello@flora-wellness.app
FRONTEND_URL         = https://your-site.netlify.app

RAILWAY VOLUME:
──────────────
Add a Railway volume mounted at /data so the SQLite DB persists between deploys.

START COMMAND:
──────────────
python flora_server.py
"""

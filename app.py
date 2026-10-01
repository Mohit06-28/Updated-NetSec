"""
Network Scanner — Vercel-ready edition
- TCP connect scanner (pure sockets, no scapy/nmap/ping)
- Postgres (Neon/Supabase) or SQLite fallback for local dev
- Session-cookie auth, register without OTP, login with email/phone
- SEO-optimized routes
"""
import os, re, json, socket, secrets
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from functools import wraps

from flask import (Flask, render_template, request, jsonify, redirect,
                   url_for, session, send_from_directory, Response, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__,
            static_folder='public', static_url_path='/static',
            template_folder='templates')
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('FLASK_ENV') == 'production',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    JSON_SORT_KEYS=False,
)

DATABASE_URL = os.getenv('DATABASE_URL')

# ---------------------------------------------------------------- DB helpers
def _is_pg(): return bool(DATABASE_URL)

def _sql(sql: str) -> str:
    return sql.replace('?', '%s') if _is_pg() else sql

def get_db():
    if _is_pg():
        import psycopg2
        from psycopg2.extras import RealDictCursor
        return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    import sqlite3
    conn = sqlite3.connect('network_scanner.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def row_to_dict(r):
    if r is None: return None
    return dict(r)

def init_db():
    idtype = 'SERIAL PRIMARY KEY' if _is_pg() else 'INTEGER PRIMARY KEY AUTOINCREMENT'
    conn = get_db(); cur = conn.cursor()
    for ddl in [
        f'''CREATE TABLE IF NOT EXISTS users (
            id {idtype}, username TEXT UNIQUE, email TEXT UNIQUE, phone TEXT,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP, api_key TEXT UNIQUE)''',
        f'''CREATE TABLE IF NOT EXISTS scan_history (
            id {idtype}, user_id INTEGER, target TEXT NOT NULL, scan_type TEXT,
            start_time TIMESTAMP, end_time TIMESTAMP,
            open_ports INTEGER, total_ports INTEGER, high_risk_count INTEGER DEFAULT 0,
            status TEXT, result_json TEXT)''',
        f'''CREATE TABLE IF NOT EXISTS vulnerability_reports (
            id {idtype}, scan_id INTEGER, host TEXT, port INTEGER,
            vulnerability TEXT, severity TEXT, recommendation TEXT,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''',
        f'''CREATE TABLE IF NOT EXISTS app_ratings (
            id {idtype}, stars INTEGER, comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''',
    ]:
        cur.execute(ddl)
    conn.commit(); cur.close(); conn.close()

# ---------------------------------------------------------------- metadata
PORT_NAMES = {
    20:'FTP-Data',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',68:'DHCP',
    69:'TFTP',80:'HTTP',110:'POP3',111:'RPC',119:'NNTP',123:'NTP',135:'MSRPC',
    137:'NetBIOS',138:'NetBIOS',139:'NetBIOS',143:'IMAP',161:'SNMP',179:'BGP',
    194:'IRC',389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTPS',500:'ISAKMP',514:'Syslog',
    515:'LPD',520:'RIP',587:'SMTP-Sub',636:'LDAPS',993:'IMAPS',995:'POP3S',
    1433:'MSSQL',1521:'Oracle',1723:'PPTP',2049:'NFS',2082:'cPanel',2083:'cPanel-SSL',
    2181:'Zookeeper',3000:'Dev-Server',3306:'MySQL',3389:'RDP',3690:'SVN',4444:'Metasploit',
    5432:'PostgreSQL',5500:'VNC',5601:'Kibana',5900:'VNC',5985:'WinRM',6379:'Redis',
    6667:'IRC',7001:'WebLogic',8000:'HTTP-Alt',8008:'HTTP-Proxy',8080:'HTTP-Proxy',
    8081:'HTTP-Alt',8443:'HTTPS-Alt',8888:'Dev-Server',27017:'MongoDB',
}
PORT_RISK = {
    21:'CRITICAL',23:'CRITICAL',445:'CRITICAL',3389:'CRITICAL',6379:'CRITICAL',
    27017:'CRITICAL',25:'HIGH',5900:'HIGH',3306:'HIGH',5432:'HIGH',
    22:'MEDIUM',80:'MEDIUM',443:'MEDIUM',8080:'MEDIUM',
}
def port_name(p): return PORT_NAMES.get(int(p), f'Port {p}')
def port_risk(p): return PORT_RISK.get(int(p), 'LOW')

def parse_ports(spec: str):
    spec = (spec or '1-1000').strip().lower()
    if spec in ('all', '1-65535', 'full'): return list(range(1, 65536))
    if '-' in spec:
        a, b = spec.split('-', 1)
        return list(range(int(a.strip()), min(int(b.strip()), 65535) + 1))
    if ',' in spec:
        return [int(x.strip()) for x in spec.split(',') if x.strip()]
    if spec.isdigit():
        return [int(spec)]
    return list(range(1, 1001))

# ---------------------------------------------------------------- scanner
def _scan_one(host: str, port: int, timeout: float = 1.0) -> dict:
    """TCP connect scan — works on Vercel serverless."""
    r = {'port': port, 'open': False, 'protocol': 'tcp',
         'service': port_name(port), 'risk': 'LOW', 'banner': ''}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, port)) == 0:
            r['open'] = True
            r['risk'] = port_risk(port)
            # Try a banner grab on web-ish ports only
            if port in (80, 8080, 8000, 8888, 443, 8443):
                try:
                    s.settimeout(1.5)
                    s.send(b'HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n' % host.encode())
                    banner = s.recv(512).decode('utf-8', 'ignore')
                    r['banner'] = banner.strip().split('\n')[0][:200]
                except Exception:
                    pass
        s.close()
    except Exception:
        pass
    return r

def run_scan(host: str, ports: list, threads: int = 100, timeout: float = 1.0):
    results = {}
    threads = max(1, min(threads, 200))  # Vercel concurrency-safe cap
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_scan_one, host, p, timeout): p for p in ports}
        for f in as_completed(futs):
            try: results[futs[f]] = f.result()
            except Exception: pass
    return results

# ---------------------------------------------------------------- auth
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get('user_id'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login_page'))
        return f(*a, **kw)
    return wrapper

def _current_user():
    if not session.get('user_id'): return None
    conn = get_db(); cur = conn.cursor()
    cur.execute(_sql('SELECT * FROM users WHERE id = ?'), (session['user_id'],))
    u = row_to_dict(cur.fetchone()); cur.close(); conn.close()
    return u

# ---------------------------------------------------------------- public pages
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/robots.txt')
def robots():
    return send_from_directory('public', 'robots.txt', mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('public', 'sitemap.xml', mimetype='application/xml')

# ---------------------------------------------------------------- auth pages
@app.route('/register', methods=['GET'])
def register_page():
    if session.get('user_id'): return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET'])
def login_page():
    if session.get('user_id'): return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register_post():
    """Register WITHOUT OTP. Fields: email/phone, password, confirm password."""
    data = request.get_json(silent=True) or request.form
    email = (data.get('email') or '').strip().lower()
    phone = (data.get('phone') or '').strip()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    confirm = data.get('confirm_password') or data.get('confirmPassword') or ''

    # Validate: must have at least email OR phone
    if not email and not phone:
        return jsonify({'error': 'Email or phone is required'}), 400
    if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'error': 'Invalid email format'}), 400
    if phone and not re.match(r'^\+?\d{7,15}$', phone.replace(' ', '').replace('-', '')):
        return jsonify({'error': 'Invalid phone number'}), 400
    if password != confirm:
        return jsonify({'error': 'Passwords do not match'}), 400
    if len(password) < 8 or not re.search(r'[A-Z]', password) \
            or not re.search(r'[a-z]', password) or not re.search(r'\d', password):
        return jsonify({'error': 'Password must be 8+ chars with upper, lower and a number'}), 400
    if username and not re.match(r'^[A-Za-z0-9_]{3,20}$', username):
        return jsonify({'error': 'Username must be 3-20 chars (letters, numbers, _)'}), 400

    conn = get_db(); cur = conn.cursor()
    # uniqueness checks
    if email:
        cur.execute(_sql('SELECT id FROM users WHERE email = ?'), (email,))
        if cur.fetchone(): cur.close(); conn.close(); return jsonify({'error': 'Email already registered'}), 409
    if phone:
        cur.execute(_sql('SELECT id FROM users WHERE phone = ?'), (phone,))
        if cur.fetchone(): cur.close(); conn.close(); return jsonify({'error': 'Phone already registered'}), 409
    if username:
        cur.execute(_sql('SELECT id FROM users WHERE username = ?'), (username,))
        if cur.fetchone(): cur.close(); conn.close(); return jsonify({'error': 'Username taken'}), 409

    api_key = secrets.token_urlsafe(32)
    pw_hash = generate_password_hash(password)
    cur.execute(
        _sql('INSERT INTO users (username, email, phone, password_hash, api_key) '
             'VALUES (?, ?, ?, ?, ?)'),
        (username or (email.split('@')[0] if email else phone), email or None, phone or None, pw_hash, api_key))
    conn.commit()

    # fetch id
    ident = email or phone
    cur.execute(_sql('SELECT * FROM users WHERE email = ? OR phone = ?'), (email or '', phone or ''))
    user = row_to_dict(cur.fetchone())
    cur.close(); conn.close()

    # auto-login
    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user.get('username') or ident
    return jsonify({'success': True, 'redirect': '/dashboard', 'username': session['username']})

@app.route('/login', methods=['POST'])
def login_post():
    data = request.get_json(silent=True) or request.form
    ident = (data.get('identifier') or '').strip()
    password = data.get('password') or ''
    if not ident or not password:
        return jsonify({'error': 'Identifier and password required'}), 400

    conn = get_db(); cur = conn.cursor()
    if '@' in ident:
        cur.execute(_sql('SELECT * FROM users WHERE email = ?'), (ident.lower(),))
    else:
        cur.execute(_sql('SELECT * FROM users WHERE phone = ? OR username = ?'),
                    (ident, ident))
    user = row_to_dict(cur.fetchone())
    if not user or not check_password_hash(user['password_hash'], password):
        cur.close(); conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    cur.execute(_sql('UPDATE users SET last_login = ? WHERE id = ?'),
                (datetime.now(), user['id']))
    conn.commit(); cur.close(); conn.close()

    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user.get('username') or ident
    return jsonify({'success': True, 'redirect': '/dashboard', 'username': session['username']})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ---------------------------------------------------------------- dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('username', 'User'))

@app.route('/scanner')
@login_required
def scanner_page():
    return render_template('dashboard.html', username=session.get('username', 'User'), page='scanner')

@app.route('/reports')
@login_required
def reports_page():
    return render_template('dashboard.html', username=session.get('username', 'User'), page='reports')

# ---------------------------------------------------------------- scan API
@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    # basic sanitization
    if not re.match(r'^[A-Za-z0-9\.\-:_]+$', target):
        return jsonify({'error': 'Invalid target format'}), 400

    try: ports = parse_ports(data.get('port_range', '1-1000'))
    except ValueError: return jsonify({'error': 'Invalid port range'}), 400
    ports = ports[:5000]  # Vercel hard cap
    threads = int(data.get('threads', 100))
    timeout = float(data.get('timeout', 1.0))

    started = datetime.now()
    try:
        results = run_scan(target, ports, threads, timeout)
    except socket.gaierror:
        return jsonify({'error': f'Cannot resolve host: {target}'}), 400

    open_ports = [p for p, i in results.items() if i.get('open')]
    high_risk = [p for p in open_ports if results[p]['risk'] in ('CRITICAL', 'HIGH')]
    ended = datetime.now()

    conn = get_db(); cur = conn.cursor()
    cur.execute(
        _sql('INSERT INTO scan_history (user_id, target, scan_type, start_time, end_time, '
             'open_ports, total_ports, high_risk_count, status, result_json) '
             'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
        (session['user_id'], target, 'tcp', started, ended,
         len(open_ports), len(ports), len(high_risk), 'completed', json.dumps(results)))
    conn.commit()

    # record findings as vulnerabilities for medium+ ports
    cur.execute(_sql('SELECT id FROM scan_history WHERE user_id = ? ORDER BY id DESC LIMIT 1'),
                (session['user_id'],))
    row = cur.fetchone()
    scan_id = row['id'] if row else None
    for p in open_ports:
        risk = results[p]['risk']
        if risk in ('CRITICAL', 'HIGH', 'MEDIUM'):
            cur.execute(
                _sql('INSERT INTO vulnerability_reports (scan_id, host, port, vulnerability, severity, recommendation) '
                     'VALUES (?, ?, ?, ?, ?, ?)'),
                (scan_id, target, p, f"Open {port_name(p)} on port {p}", risk,
                 f"Restrict port {p} via firewall or disable {port_name(p)} if unused."))
    conn.commit(); cur.close(); conn.close()

    return jsonify({
        'success': True, 'scan_id': scan_id, 'target': target,
        'open_ports': len(open_ports), 'total_ports': len(ports),
        'high_risk_count': len(high_risk),
        'alert_triggered': len(high_risk) > 0,
        'results': results,
        'duration_sec': (ended - started).total_seconds(),
    })

@app.route('/api/scan-status/<int:scan_id>')
@login_required
def api_scan_status(scan_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute(_sql('SELECT * FROM scan_history WHERE id = ? AND user_id = ?'),
                (scan_id, session['user_id']))
    scan = row_to_dict(cur.fetchone()); cur.close(); conn.close()
    if not scan: return jsonify({'error': 'Not found'}), 404
    scan['result'] = json.loads(scan['result_json']) if scan.get('result_json') else None
    return jsonify(scan)

@app.route('/api/reports')
@login_required
def api_reports():
    kind = request.args.get('type', 'scans')
    conn = get_db(); cur = conn.cursor()
    if kind == 'scans':
        cur.execute(_sql('SELECT * FROM scan_history WHERE user_id = ? ORDER BY start_time DESC LIMIT 50'),
                    (session['user_id'],))
    elif kind == 'vulnerabilities':
        cur.execute(_sql('''SELECT v.* FROM vulnerability_reports v
                            INNER JOIN scan_history s ON v.scan_id = s.id
                            WHERE s.user_id = ? ORDER BY v.discovered_at DESC LIMIT 100'''),
                    (session['user_id'],))
    else:
        cur.execute(_sql('SELECT * FROM scan_history WHERE user_id = ? LIMIT 1'), (session['user_id'],))
    rows = [row_to_dict(r) for r in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify(rows)

@app.route('/api/public-stats')
def public_stats():
    conn = get_db(); cur = conn.cursor()
    cur.execute(_sql("SELECT COUNT(*) AS c FROM scan_history WHERE status = 'completed'")); scans = cur.fetchone()['c'] or 0
    cur.execute(_sql("SELECT COALESCE(SUM(total_ports), 0) AS c FROM scan_history")); ports = cur.fetchone()['c'] or 0
    cur.execute(_sql("SELECT COUNT(*) AS c FROM vulnerability_reports")); vulns = cur.fetchone()['c'] or 0
    cur.execute(_sql("SELECT COUNT(*) AS c FROM users")); users = cur.fetchone()['c'] or 0
    cur.close(); conn.close()
    return jsonify({'scans_completed': int(scans), 'ports_scanned': int(ports),
                    'vulnerabilities_found': int(vulns), 'happy_users': int(users)})

@app.route('/api/rating', methods=['POST'])
def api_rating():
    d = request.get_json(silent=True) or {}
    stars = int(d.get('stars', 0))
    if not 1 <= stars <= 5: return jsonify({'error': 'Stars must be 1-5'}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute(_sql('INSERT INTO app_ratings (stars, comment) VALUES (?, ?)'),
                (stars, (d.get('comment') or '')[:500]))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'success': True})

# ---------------------------------------------------------------- export report
@app.route('/api/export-report/<int:scan_id>')
@login_required
def api_export(scan_id):
    fmt = request.args.get('format', 'json').lower()
    conn = get_db(); cur = conn.cursor()
    cur.execute(_sql('SELECT * FROM scan_history WHERE id = ? AND user_id = ?'),
                (scan_id, session['user_id']))
    scan = row_to_dict(cur.fetchone())
    cur.close(); conn.close()
    if not scan: return jsonify({'error': 'Not found'}), 404
    results = json.loads(scan['result_json']) if scan.get('result_json') else {}

    if fmt == 'txt':
        lines = [f"Network Security Scan Report",
                 f"Target: {scan['target']}", f"Open ports: {scan['open_ports']}",
                 '', 'Open ports:']
        for p, i in results.items():
            if i.get('open'): lines.append(f"  {p}/tcp  {port_name(p)}  risk={i.get('risk')}")
        return Response('\n'.join(lines), mimetype='text/plain',
                        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.txt'})

    return jsonify({'scan': scan, 'results': results})

# ---------------------------------------------------------------- errors
@app.errorhandler(404)
def nf(e):
    if request.path.startswith('/api/'): return jsonify({'error': 'Not found'}), 404
    return redirect(url_for('index'))

@app.errorhandler(500)
def err(e):
    if request.path.startswith('/api/'): return jsonify({'error': 'Server error'}), 500
    return "Server error", 500

# ---------------------------------------------------------------- boot
try:
    init_db()
except Exception as e:
    print("init_db warning:", e)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
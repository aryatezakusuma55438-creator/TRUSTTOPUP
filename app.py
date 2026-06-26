from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify, send_from_directory, Response
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from config import Config
from translations import get_translator
import db_compat
import sqlite3
import sqlite3 as _sq
import os, time, re, hashlib, secrets, threading, requests, datetime
import smtplib
import logging, sys
from email.mime.text import MIMEText

# ---------- APP LOGGING (visible in Railway/hosting logs via stdout) ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout,
)
applog = logging.getLogger('trusttopup')
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config.from_object(Config)

# ---------- UPLOAD FOLDER ----------
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
def is_valid_ip(ip):
    """Loose IPv4/IPv6 sanity check — good enough to reject garbage input from the block form."""
    if not ip or len(ip) > 64:
        return False
    if _IPV4_RE.match(ip):
        return all(0 <= int(part) <= 255 for part in ip.split('.'))
    if ':' in ip:  # very loose IPv6 check
        return bool(re.match(r'^[0-9a-fA-F:]+$', ip))
    return False

# ---------- ROLE HELPERS ----------
def is_admin_logged_in():
    return bool(session.get('admin'))

def is_owner():
    return session.get('admin_role') == 'owner'

def require_admin():
    """Abort 403 if not logged in as any admin (owner or staff)."""
    if not is_admin_logged_in():
        abort(403)

def require_owner():
    """Abort 403 if not logged in as Owner specifically."""
    if not is_admin_logged_in() or not is_owner():
        abort(403)

# ---------- CSRF ----------
csrf = CSRFProtect(app)

# ---------- GOOGLE OAUTH ----------
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

@app.after_request
def inject_csrf_token(response):
    response.set_cookie(
        'csrf_token', generate_csrf(),
        samesite='Lax',
        secure=app.config['SESSION_COOKIE_SECURE'],
        httponly=True,
    )
    return response

@app.errorhandler(CSRFError)
def csrf_error(e):
    flash('Invalid request (CSRF error). Please try again.', 'error')
    return redirect(request.referrer or url_for('index'))

# ---------- LANGUAGE ----------
@app.context_processor
def inject_translator():
    lang = session.get('lang', 'en')
    theme = session.get('theme', 'default')
    if theme not in ('default', 'simple', 'modern', 'gold'):
        theme = 'default'
    return dict(t=get_translator(lang), current_lang=lang, current_theme=theme)

@app.context_processor
def inject_pending_order_banner():
    """
    Makes a global 'pending_order' variable available to every template, so a
    "you haven't finished your payment" banner can be shown on any page (not
    just the status page). Two sources are checked:
      - Logged-in customers: the most recent waiting_payment order tied to
        their account_id, so this works even from a different browser/device.
      - Guests: any waiting_payment order whose token is still in this
        session (session[f'order_token_{id}']), since guests have no account.
    The customer can dismiss a specific order's banner; the dismissal is
    remembered in session so it doesn't reappear for that same order.
    """
    dismissed = session.get('dismissed_pending_orders', [])
    db = get_db()
    row = None

    user_id = session.get('user_id')
    if user_id:
        row = db.execute(
            "SELECT * FROM orders WHERE account_id=? AND status='waiting_payment' "
            "ORDER BY created_at DESC LIMIT 1",
            (user_id,)
        ).fetchone()

    if not row:
        # Guest fallback: scan this session's own order tokens.
        for key in list(session.keys()):
            if not key.startswith('order_token_'):
                continue
            try:
                oid = int(key.replace('order_token_', ''))
            except ValueError:
                continue
            candidate = db.execute(
                "SELECT * FROM orders WHERE id=? AND token=? AND status='waiting_payment'",
                (oid, session[key])
            ).fetchone()
            if candidate:
                row = candidate
                break

    if not row or row['id'] in dismissed:
        return dict(pending_order=None)

    return dict(pending_order={
        'id': row['id'],
        'token': row['token'],
        'game': row['game'],
        'price': format_rupiah(row['price_int']),
    })

# ---------- SHIELD DB ----------
# Same ephemeral-filesystem concern as the main DATABASE — see config.py comment.
# Set SHIELD_DB_PATH (e.g. /data/shield.db, same Volume as DATABASE_PATH) on Railway
# so manual IP blocks and rate-limit state survive redeploys.
_SHIELD_DB = os.environ.get('SHIELD_DB_PATH') or os.path.join(os.path.dirname(__file__), 'shield.db')

def _shield_init():
    with db_compat.shield_connect(_SHIELD_DB) as db:
        if not db_compat.USE_POSTGRES:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=NORMAL')
        db.execute('CREATE TABLE IF NOT EXISTS req_log (ip TEXT NOT NULL, ts REAL NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS blocked (ip TEXT PRIMARY KEY, until REAL NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS login_fail (ip TEXT NOT NULL, ts REAL NOT NULL)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_req_ip ON req_log(ip)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_req_ts ON req_log(ts)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_loginfail_ip ON login_fail(ip)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_loginfail_ts ON login_fail(ts)')
        db.commit()

_shield_init()

RATE_LIMIT=80; RATE_WINDOW=60; LOGIN_LIMIT=5; LOGIN_WINDOW=300
BLOCK_DURATION=600; DDOS_LIMIT=200; DDOS_BLOCK=3600
TRUSTED_PROXIES={'127.0.0.1'}

def get_ip():
    if request.remote_addr in TRUSTED_PROXIES:
        fwd = request.headers.get('X-Forwarded-For','')
        if fwd: return fwd.split(',')[0].strip()
    return request.remote_addr

def is_blocked(ip):
    with db_compat.shield_connect(_SHIELD_DB) as db:
        db.row_factory = _sq.Row
        row = db.execute('SELECT until FROM blocked WHERE ip=?',(ip,)).fetchone()
        if row:
            if time.time() < row['until']: return True
            db.execute('DELETE FROM blocked WHERE ip=?',(ip,)); db.commit()
    return False

def block_ip(ip,duration):
    with db_compat.shield_connect(_SHIELD_DB) as db:
        db.execute('INSERT OR REPLACE INTO blocked (ip,until) VALUES (?,?)',(ip,time.time()+duration)); db.commit()

def unblock_ip(ip):
    """Remove a manual/automatic IP block. Returns True if a row was actually removed."""
    with db_compat.shield_connect(_SHIELD_DB) as db:
        cur = db.execute('DELETE FROM blocked WHERE ip=?',(ip,)); db.commit()
        return cur.rowcount > 0

def list_blocked_ips():
    """All currently-blocked IPs (auto rate-limit blocks + manual Owner blocks), newest-expiring first."""
    now = time.time()
    with db_compat.shield_connect(_SHIELD_DB) as db:
        db.row_factory = _sq.Row
        db.execute('DELETE FROM blocked WHERE until<?', (now,)); db.commit()
        rows = db.execute('SELECT ip, until FROM blocked ORDER BY until DESC').fetchall()
    out = []
    for r in rows:
        remaining = r['until'] - now
        out.append({
            'ip': r['ip'],
            'until': r['until'],
            'permanent': remaining > 60*60*24*365*5,  # treat 5+ year blocks as "Permanent" in the UI
            'until_label': 'Permanent' if remaining > 60*60*24*365*5
                           else datetime.datetime.fromtimestamp(r['until']).strftime('%Y-%m-%d %H:%M'),
        })
    return out

def check_rate_limit(ip):
    now=time.time()
    with db_compat.shield_connect(_SHIELD_DB) as db:
        db.row_factory=_sq.Row
        db.execute('DELETE FROM req_log WHERE ts<?',(now-RATE_WINDOW,)); db.commit()
        count=db.execute('SELECT COUNT(*) as c FROM req_log WHERE ip=?',(ip,)).fetchone()['c']
        if count>=DDOS_LIMIT: block_ip(ip,DDOS_BLOCK); return False
        if count>=RATE_LIMIT:  block_ip(ip,BLOCK_DURATION); return False
        db.execute('INSERT INTO req_log (ip,ts) VALUES (?,?)',(ip,now)); db.commit()
    return True

def check_login_limit(ip):
    now=time.time()
    with db_compat.shield_connect(_SHIELD_DB) as db:
        db.row_factory=_sq.Row
        db.execute('DELETE FROM login_fail WHERE ts<?',(now-LOGIN_WINDOW,)); db.commit()
        count=db.execute('SELECT COUNT(*) as c FROM login_fail WHERE ip=?',(ip,)).fetchone()['c']
        if count>=LOGIN_LIMIT: block_ip(ip,BLOCK_DURATION); return False,0
        return True,max(0,LOGIN_LIMIT-count)

def record_login_fail(ip):
    with db_compat.shield_connect(_SHIELD_DB) as db:
        db.execute('INSERT INTO login_fail (ip,ts) VALUES (?,?)',(ip,time.time())); db.commit()

def clear_login_fail(ip):
    with db_compat.shield_connect(_SHIELD_DB) as db:
        db.execute('DELETE FROM login_fail WHERE ip=?',(ip,)); db.commit()

def _scheduled_cleanup():
    while True:
        time.sleep(300)
        try:
            with db_compat.shield_connect(_SHIELD_DB) as db:
                now=time.time()
                db.execute('DELETE FROM req_log WHERE ts<?',(now-RATE_WINDOW,))
                db.execute('DELETE FROM login_fail WHERE ts<?',(now-LOGIN_WINDOW,))
                db.execute('DELETE FROM blocked WHERE until<?',(now,))
                db.commit()
        except Exception: pass

threading.Thread(target=_scheduled_cleanup,daemon=True).start()

# ---------- VALID PACKAGES ----------
# VIP-Reseller product codes untuk setiap game
# Format: (diamond_label, price_display, price_int, vip_product_code)
VALID_PACKAGES = {
    'Mobile Legends': [
        {'diamond':'86 Diamond',  'price':'Rp 19.000','price_int':19000, 'vip_code':'mobilelegend-86-diamond'},
        {'diamond':'172 Diamond', 'price':'Rp 38.000','price_int':38000, 'vip_code':'mobilelegend-172-diamond'},
        {'diamond':'257 Diamond', 'price':'Rp 57.000','price_int':57000, 'vip_code':'mobilelegend-257-diamond'},
        {'diamond':'344 Diamond', 'price':'Rp 76.000','price_int':76000, 'vip_code':'mobilelegend-344-diamond'},
        {'diamond':'514 Diamond', 'price':'Rp 112.000','price_int':112000,'vip_code':'mobilelegend-514-diamond'},
    ],
    'Free Fire': [
        {'diamond':'5 Diamonds',   'price':'Rp 853',    'price_int':853,    'vip_code':'FF5-S13'},
        {'diamond':'12 Diamonds',  'price':'Rp 1.727',  'price_int':1727,   'vip_code':'FF12-S13'},
        {'diamond':'50 Diamonds',  'price':'Rp 6.509',  'price_int':6509,   'vip_code':'FF50-S13'},
        {'diamond':'100 Diamonds', 'price':'Rp 13.567', 'price_int':13567,  'vip_code':'FF100-S13'},
        {'diamond':'355 Diamonds', 'price':'Rp 42.666', 'price_int':42666,  'vip_code':'FF355-S13'},
    ],
    'PUBG Mobile': [
        {'diamond':'60 UC',  'price':'Rp 15.000','price_int':15000, 'vip_code':'pubgmobile-60-uc'},
        {'diamond':'120 UC', 'price':'Rp 29.000','price_int':29000, 'vip_code':'pubgmobile-120-uc'},
        {'diamond':'325 UC', 'price':'Rp 75.000','price_int':75000, 'vip_code':'pubgmobile-325-uc'},
        {'diamond':'660 UC', 'price':'Rp 149.000','price_int':149000,'vip_code':'pubgmobile-660-uc'},
    ],
    'Roblox': [
        {'diamond':'400 Robux',  'price':'Rp 55.000','price_int':55000, 'vip_code':'roblox-400-robux'},
        {'diamond':'800 Robux',  'price':'Rp 109.000','price_int':109000,'vip_code':'roblox-800-robux'},
        {'diamond':'1700 Robux', 'price':'Rp 219.000','price_int':219000,'vip_code':'roblox-1700-robux'},
    ],
    'Genshin Impact': [
        {'diamond':'60 Primogem',  'price':'Rp 15.000','price_int':15000, 'vip_code':'genshin-60-genesis'},
        {'diamond':'300 Primogem', 'price':'Rp 75.000','price_int':75000, 'vip_code':'genshin-300-genesis'},
        {'diamond':'980 Primogem', 'price':'Rp 149.000','price_int':149000,'vip_code':'genshin-980-genesis'},
    ],
    'Honkai Star Rail': [
        {'diamond':'60 Stellar Jade',  'price':'Rp 15.000','price_int':15000, 'vip_code':'honkai-60-stellar'},
        {'diamond':'300 Stellar Jade', 'price':'Rp 75.000','price_int':75000, 'vip_code':'honkai-300-stellar'},
        {'diamond':'980 Stellar Jade', 'price':'Rp 149.000','price_int':149000,'vip_code':'honkai-980-stellar'},
    ],
}

VALID_PAYMENTS = {'Dana','QRIS'}
VALID_GAMES    = set(VALID_PACKAGES.keys())

# Status order
STATUS_LABELS = {
    'waiting_payment':     'Waiting for Payment',
    'waiting_verification':'Waiting for Verification',
    'unverified_claim':    'Unverified Claim (No Proof)',
    'processing':          'Processing',
    'completed':           'Completed',
    'cancelled':           'Cancelled',
}

def validate_package(game,diamond,price):
    if game not in VALID_PACKAGES: return False
    for pkg in VALID_PACKAGES[game]:
        if pkg['diamond']==diamond and pkg['price']==price: return True
    return False

def get_price_int(game,diamond):
    if game not in VALID_PACKAGES: return 0
    for pkg in VALID_PACKAGES[game]:
        if pkg['diamond']==diamond: return pkg['price_int']
    return 0

def get_vip_code(game,diamond):
    if game not in VALID_PACKAGES: return ''
    for pkg in VALID_PACKAGES[game]:
        if pkg['diamond']==diamond: return pkg.get('vip_code','')
    return ''

def sanitize(text):
    if not text: return ''
    text=str(text).strip()
    text=re.sub(r'[<>"]','',text)
    return text[:200]

def format_rupiah(amount):
    return 'Rp {:,.0f}'.format(amount).replace(',','.')

# ---------- VIP-RESELLER API ----------
VIP_BASE_URL = 'https://vip-reseller.co.id/api'

# ---------- VIP-RESELLER VIA PROXY VPS ----------
# Railway does NOT talk directly to vip-reseller.co.id. All requests are
# forwarded through the VPS proxy whose IP is whitelisted on VIP-Reseller.
# See PROXY_URL & PROXY_AUTH_TOKEN in config.py / Railway environment variables.

def _proxy_headers():
    return {'X-Proxy-Token': app.config['PROXY_AUTH_TOKEN']}

def vip_order(product_code, target_id, server_id='', ref_id=''):
    """
    Send an order to VIP-Reseller through the proxy VPS.
    Returns: (success: bool, data: dict)
    """
    try:
        proxy_url = app.config['PROXY_URL']
        if not proxy_url:
            app.logger.error('PROXY_URL is not configured in Railway environment')
            return False, {'message': 'VIP-Reseller proxy is not configured'}

        payload = {
            'service': product_code,
            'data_no': target_id,
        }
        if server_id:
            payload['data_zone'] = server_id

        resp = requests.post(
            f'{proxy_url}/order',
            data=payload,
            headers=_proxy_headers(),
            timeout=30,
        )
        data = resp.json()
        app.logger.info(f'Proxy order response (ref_id={ref_id}): {data}')

        if data.get('result') is True:
            return True, data
        else:
            return False, data

    except requests.exceptions.Timeout:
        return False, {'message': 'VIP-Reseller proxy timeout'}
    except Exception as e:
        app.logger.error(f'Proxy order error: {e}')
        return False, {'message': str(e)}

def vip_check_status(trx_id):
    """Check order status through the proxy VPS."""
    try:
        proxy_url = app.config['PROXY_URL']
        if not proxy_url:
            app.logger.error('PROXY_URL is not configured in Railway environment')
            return {}

        resp = requests.get(
            f'{proxy_url}/status',
            params={'trxid': trx_id},
            headers=_proxy_headers(),
            timeout=15,
        )
        return resp.json()
    except Exception as e:
        app.logger.error(f'Proxy check status error: {e}')
        return {}

# ---------- ORDER CONFIRMATION EMAIL ----------
def _build_order_email_html(order):
    """Build the HTML body for the order confirmation email."""
    discount_row = ''
    if order.get('discount_amount', 0) > 0:
        discount_row = f'''
        <tr>
          <td style="padding:6px 0;color:#9ca3af;">Voucher ({order.get('voucher_code','')})</td>
          <td style="padding:6px 0;text-align:right;color:#4ade80;">- {format_rupiah(order['discount_amount'])}</td>
        </tr>'''
    return f'''
    <div style="background:#0a0a14;padding:32px 16px;font-family:Arial,Helvetica,sans-serif;">
      <div style="max-width:480px;margin:0 auto;background:#13131f;border:1px solid #2a2a3d;border-radius:16px;overflow:hidden;">
        <div style="background:linear-gradient(135deg,#7c3aed,#06b6d4);padding:24px 28px;">
          <div style="color:#fff;font-size:1.3rem;font-weight:800;">TrustTop Up</div>
        </div>
        <div style="padding:28px;">
          <div style="color:#4ade80;font-size:1.05rem;font-weight:700;margin-bottom:4px;">Order Completed</div>
          <div style="color:#9ca3af;font-size:0.88rem;margin-bottom:24px;">Your top-up has been delivered successfully.</div>
          <table style="width:100%;font-size:0.9rem;color:#e5e7eb;border-collapse:collapse;">
            <tr><td style="padding:6px 0;color:#9ca3af;">Order ID</td><td style="padding:6px 0;text-align:right;">#{order['id']}</td></tr>
            <tr><td style="padding:6px 0;color:#9ca3af;">Game</td><td style="padding:6px 0;text-align:right;">{order['game']}</td></tr>
            <tr><td style="padding:6px 0;color:#9ca3af;">User ID</td><td style="padding:6px 0;text-align:right;">{order['user_id']}{(' / ' + order['server_id']) if order.get('server_id') else ''}</td></tr>
            <tr><td style="padding:6px 0;color:#9ca3af;">Package</td><td style="padding:6px 0;text-align:right;color:#67e8f9;">{order['diamond']}</td></tr>
            {discount_row}
            <tr><td style="padding:10px 0 6px;color:#9ca3af;border-top:1px solid #2a2a3d;font-weight:700;">Total Paid</td><td style="padding:10px 0 6px;text-align:right;border-top:1px solid #2a2a3d;font-weight:700;color:#fff;">{order['price']}</td></tr>
          </table>
          <div style="margin-top:24px;padding:14px 16px;background:rgba(124,58,237,0.08);border:1px solid rgba(124,58,237,0.2);border-radius:10px;font-size:0.82rem;color:#9ca3af;">
            Transaction ID: <span style="color:#a855f7;font-family:monospace;">{order.get('vip_trx_id') or '-'}</span>
          </div>
          <div style="margin-top:24px;font-size:0.8rem;color:#6b7280;line-height:1.6;">
            Thank you for using TrustTop Up. If you have any questions about this order, please contact our support team and include your Order ID above.
          </div>
        </div>
      </div>
    </div>
    '''

def send_order_email(to_email, order):
    """
    Send the order confirmation email synchronously. Called from a background
    thread by notify_customer_async so it never blocks the admin's request.
    """
    if not to_email:
        return False, 'No email address on this order'

    smtp_user = app.config.get('SMTP_USER', '')
    smtp_pass = app.config.get('SMTP_PASSWORD', '')
    if not smtp_user or not smtp_pass:
        app.logger.warning('SMTP_USER/SMTP_PASSWORD not configured -- skipping order email')
        return False, 'Email is not configured on the server'

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Your TrustTop Up order #{order['id']} is complete"
        msg['From'] = f"{app.config.get('SMTP_FROM_NAME','TrustTop Up')} <{smtp_user}>"
        msg['To'] = to_email
        msg.attach(MIMEText(_build_order_email_html(order), 'html'))

        with smtplib.SMTP(app.config['SMTP_HOST'], app.config['SMTP_PORT'], timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, [to_email], msg.as_string())
        return True, None
    except Exception as e:
        app.logger.error(f'Failed to send order email to {to_email}: {e}')
        return False, str(e)

def notify_customer_async(app_ref, order_id, to_email, order_dict):
    """Send the confirmation email in a background thread and record the result."""
    def _worker():
        with app_ref.app_context():
            ok, err = send_order_email(to_email, order_dict)
            db = get_db()
            if ok:
                db.execute('UPDATE orders SET email_sent=1 WHERE id=?', (order_id,))
                db.commit()
                log_admin('Email Sent', f"Order confirmation email sent to {to_email} for order #{order_id}")
            else:
                log_admin('Email Failed', f"Could not send order email for order #{order_id}: {err}")
    threading.Thread(target=_worker, daemon=True).start()

# ---------- TEMPORARY: TEST SMTP CONFIGURATION ----------
# Admin-only route to verify SMTP_USER/SMTP_PASSWORD work, without needing a
# real VIP-Reseller order. Safe to delete this route once email is confirmed working.
@app.route('/admin/test-email', methods=['GET'])
def admin_test_email():
    if not session.get('admin'): abort(403)
    to_email = request.args.get('to', '').strip()
    if not to_email:
        return jsonify({'status': False, 'message': "Add ?to=youremail@gmail.com to the URL"}), 400

    fake_order = {
        'id': 0,
        'game': 'Test Game',
        'user_id': '000000',
        'server_id': '',
        'diamond': 'Test Package',
        'price': 'Rp 1.000',
        'discount_amount': 0,
        'voucher_code': '',
        'vip_trx_id': 'TEST-TRX-0000',
    }
    ok, err = send_order_email(to_email, fake_order)
    if ok:
        return jsonify({'status': True, 'message': f'Test email sent to {to_email}. Check your inbox (and Spam folder).'})
    else:
        return jsonify({'status': False, 'message': f'Failed to send: {err}'}), 500

# ---------- LOGGING HELPERS ----------
WIB = datetime.timezone(datetime.timedelta(hours=7))
def now_wib():
    return datetime.datetime.now(WIB).strftime('%Y-%m-%d %H:%M:%S')

def log_activity(action, detail='', status_code=200):
    ip = get_ip(); method = request.method; path = request.path
    for attempt in (1, 2):
        try:
            db = get_db()
            db.execute('INSERT INTO activity_log (ip,method,path,action,detail,status_code,created_at) VALUES (?,?,?,?,?,?,?)',
                       (ip, method, path, action, str(detail)[:500], status_code, now_wib()))
            db.commit()
            return
        except Exception as e:
            applog.error(f"log_activity FAILED (attempt {attempt}) action={action!r} ip={ip} db={app.config['DATABASE']!r}: {e!r}")
            if attempt == 1:
                time.sleep(0.2)  # brief pause in case it was a transient 'database is locked'
            else:
                applog.error(f"log_activity GIVING UP after 2 attempts — activity NOT recorded for action={action!r} ip={ip}")

def log_admin(action, detail=''):
    ip = get_ip()
    for attempt in (1, 2):
        try:
            db = get_db()
            db.execute('INSERT INTO admin_log (ip,action,detail,created_at) VALUES (?,?,?,?)',
                       (ip, action, str(detail)[:500], now_wib()))
            db.commit()
            return
        except Exception as e:
            applog.error(f"log_admin FAILED (attempt {attempt}) action={action!r} ip={ip} db={app.config['DATABASE']!r}: {e!r}")
            if attempt == 1:
                time.sleep(0.2)
            else:
                applog.error(f"log_admin GIVING UP after 2 attempts — admin action NOT recorded: {action!r}")

# ---------- SECURITY MIDDLEWARE ----------
@app.before_request
def security_check():
    ip=get_ip()
    if is_blocked(ip): abort(429)
    if not check_rate_limit(ip): abort(429)

@app.after_request
def auto_log_and_headers(response):
    if not request.path.startswith('/static') and not request.path.startswith('/uploads'):
        try:
            ip=get_ip(); method=request.method; path=request.path; status=response.status_code
            action_map={
                '/':'Open Home Page','/game':'Open Games Page','/checkout':'Process Checkout',
                '/status':'Check Order Status','/riwayat':'Check Order History',
                '/reting':'Open/Submit Rating','/kritik':'Open/Submit Critique',
                '/saran':'Open/Submit Suggestion','/report':'Open/Submit Bug Report',
                '/login':'Access Login Page','/logout':'Logout','/admin':'Access Admin Dashboard',
                '/contact':'Open Contact Page','/tentang':'Open About Page',
                '/privacy':'Open Privacy Policy','/syarat':'Open Terms & Conditions',
                '/refund':'Open Refund Policy','/faq':'Open FAQ',
            }
            action=action_map.get(path,f'Access {path}')
            detail=''
            if status==429: detail='Rate limit / IP blocked'
            elif status==403: detail='Access denied (403 Forbidden)'
            elif status==404: detail='Page not found (404)'
            elif path.startswith('/admin') and not session.get('admin'):
                detail='Unauthorized admin access attempt!'
            db=get_db()
            db.execute('INSERT INTO activity_log (ip,method,path,action,detail,status_code,created_at) VALUES (?,?,?,?,?,?,?)',
                       (ip,method,path,detail or action,detail,status,now_wib()))
            db.commit()
        except Exception as e:
            # Previously this failed silently (except Exception: pass), which is exactly why
            # missing customer logs on Railway went unnoticed. Now it's surfaced in stdout
            # so it shows up in `railway logs` / the deployment's log viewer.
            applog.error(f"auto_log_and_headers FAILED to write activity_log for {request.path!r} "
                         f"db={app.config.get('DATABASE')!r}: {e!r}")
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']          = 'DENY'
    response.headers['X-XSS-Protection']         = '1; mode=block'
    response.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Permissions-Policy']        = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy']   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https: blob:; "
        "connect-src 'self'; "
    )
    response.headers.pop('Server', None)
    return response

# ---------- ERROR HANDLERS ----------
@app.errorhandler(429)
def too_many_requests(e): return render_template('429.html'),429
@app.errorhandler(404)
def not_found(e): return render_template('404.html'),404
@app.errorhandler(403)
def forbidden(e): return render_template('403.html'),403

# ---------- MAIN DB ----------
def get_db():
    try:
        db = db_compat.connect(app.config['DATABASE'])
    except Exception as e:
        applog.error(f"get_db: FAILED to open database ({'Postgres' if db_compat.USE_POSTGRES else 'SQLite'} "
                     f"at {app.config['DATABASE']!r}): {e!r}")
        raise
    return db

def init_db():
    with app.app_context():
        db=get_db()
        # Payment proof images: when running on Postgres these are stored
        # IN THE DATABASE (so they survive Railway's ephemeral filesystem
        # being wiped on redeploy). On local SQLite they're stored the
        # same way too, for consistency, but app.py only actually reads
        # from here when db_compat.USE_POSTGRES — locally it still saves
        # to UPLOAD_FOLDER on disk as before, since there's no persistence
        # concern in local development.
        if db_compat.USE_POSTGRES:
            db.execute('''CREATE TABLE IF NOT EXISTS payment_proofs (
                id SERIAL PRIMARY KEY,
                order_id INTEGER NOT NULL,
                filename TEXT UNIQUE NOT NULL,
                content_type TEXT,
                data BYTEA NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        else:
            db.execute('''CREATE TABLE IF NOT EXISTS payment_proofs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                filename TEXT UNIQUE NOT NULL,
                content_type TEXT,
                data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        db.commit()
        # Orders table dengan kolom manual payment
        db.execute('''CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game TEXT NOT NULL,
            user_id TEXT NOT NULL,
            server_id TEXT,
            diamond TEXT NOT NULL,
            price TEXT NOT NULL,
            price_int INTEGER NOT NULL DEFAULT 0,
            payment TEXT NOT NULL,
            status TEXT DEFAULT 'waiting_payment',
            token TEXT NOT NULL,
            payment_proof TEXT,
            vip_product_code TEXT,
            vip_trx_id TEXT,
            vip_status TEXT,
            account_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        # Migrate kolom lama jika DB sudah ada
        for col in [
            'ALTER TABLE orders ADD COLUMN payment_proof TEXT',
            'ALTER TABLE orders ADD COLUMN vip_product_code TEXT',
            'ALTER TABLE orders ADD COLUMN vip_trx_id TEXT',
            'ALTER TABLE orders ADD COLUMN vip_status TEXT',
            'ALTER TABLE orders ADD COLUMN account_id INTEGER',
            'ALTER TABLE orders ADD COLUMN price_int INTEGER NOT NULL DEFAULT 0',
            'ALTER TABLE orders ADD COLUMN voucher_code TEXT',
            'ALTER TABLE orders ADD COLUMN discount_amount INTEGER NOT NULL DEFAULT 0',
            'ALTER TABLE orders ADD COLUMN email TEXT',
            'ALTER TABLE orders ADD COLUMN email_sent INTEGER NOT NULL DEFAULT 0',
        ]:
            try: db.execute(col)
            except Exception: pass

        db.execute('''CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, email TEXT,
            kategori TEXT NOT NULL, deskripsi TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS kritik (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, email TEXT, isi TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS saran (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, email TEXT, isi TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, bintang INTEGER NOT NULL DEFAULT 5,
            isi TEXT NOT NULL, admin_reply TEXT, replied_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, method TEXT, path TEXT, action TEXT,
            detail TEXT, status_code INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS admin_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, action TEXT, detail TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE,
            username TEXT UNIQUE,
            password_hash TEXT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            avatar TEXT,
            is_verified INTEGER NOT NULL DEFAULT 0,
            verify_token TEXT,
            reset_token TEXT,
            reset_token_expiry REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        # Migrate: remove NOT NULL constraint on google_id if old schema
        try:
            db.execute('ALTER TABLE users ADD COLUMN username TEXT')
        except: pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN password_hash TEXT')
        except: pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN phone TEXT')
        except: pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0')
        except: pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN verify_token TEXT')
        except: pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN reset_token TEXT')
        except: pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN reset_token_expiry REAL')
        except: pass

        # Admin users table (multi-account, role-based: owner / staff)
        db.execute('''CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        # Voucher codes (Owner-only management, applied at checkout)
        db.execute('''CREATE TABLE IF NOT EXISTS vouchers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            discount_type TEXT NOT NULL DEFAULT 'percent',
            discount_value INTEGER NOT NULL DEFAULT 0,
            max_uses INTEGER,
            used_count INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.commit()

        # Seed the first Owner account from .env credentials if no admin exists yet.
        # This prevents lockout on first run / migration from the old single-admin system.
        existing_admin_count = db.execute('SELECT COUNT(*) as c FROM admin_users').fetchone()['c']
        if existing_admin_count == 0:
            seed_user = app.config.get('ADMIN_USER', '')
            seed_pass = app.config.get('ADMIN_PASS', '')
            if seed_user and seed_pass:
                db.execute(
                    'INSERT INTO admin_users (username, password, role) VALUES (?,?,?)',
                    (seed_user, seed_pass, 'owner')
                )
                db.commit()
        db.close()

GAMES = [
    {'name':'Mobile Legends', 'slug':'mobile-legends',   'price':'Rp 19.000', 'badge':'POPULAR','image':'ml.jpg',
     'user_label':'User ID', 'user_placeholder':'e.g. 123456789',
     'server_type':'input', 'server_label':'Server ID', 'server_placeholder':'e.g. 1234',
     'currency_label':'Diamond'},
    {'name':'Free Fire', 'slug':'free-fire', 'price':'Rp 15.000', 'badge':'HOT', 'image':'ff.jpg',
     'user_label':'Player ID', 'user_placeholder':'e.g. 123456789',
     'server_type':'none', 'currency_label':'Diamond'},
    {'name':'PUBG Mobile', 'slug':'pubg-mobile', 'price':'Rp 15.000', 'badge':'', 'image':'pubg.jpg',
     'user_label':'Character ID', 'user_placeholder':'e.g. 123456789',
     'server_type':'none', 'currency_label':'UC'},
    {'name':'Roblox', 'slug':'roblox', 'price':'Rp 55.000', 'badge':'', 'image':'Roblox.jpg',
     'user_label':'Roblox Username', 'user_placeholder':'e.g. myusername123',
     'server_type':'none', 'currency_label':'Robux'},
    {'name':'Genshin Impact', 'slug':'genshin-impact', 'price':'Rp 15.000', 'badge':'', 'image':'genshin.jpg',
     'user_label':'UID', 'user_placeholder':'e.g. 812345678',
     'server_type':'select', 'currency_label':'Genesis Crystal'},
    {'name':'Honkai Star Rail', 'slug':'honkai-star-rail', 'price':'Rp 15.000', 'badge':'', 'image':'honkai.jpg',
     'user_label':'UID', 'user_placeholder':'e.g. 812345678',
     'server_type':'select', 'currency_label':'Oneiric Shard'},
]

GAMES_BY_SLUG = {g['slug']: g for g in GAMES}

# ---------- ROUTES ----------
@app.route('/tentang')
def tentang(): return render_template('tentang.html')

@app.route('/privacy')
def privacy(): return render_template('privacy.html')

@app.route('/refund')
def refund(): return render_template('refund.html')

@app.route('/syarat')
def syarat(): return render_template('syarat.html')

@app.route('/faq')
def faq(): return render_template('faq.html')

@app.route('/contact')
def contact(): return render_template('contact.html')

@app.route('/')
def index(): return render_template('index.html', games=GAMES)

@app.route('/game')
def game(): return render_template('game.html', games=GAMES)

# ---------- NEW SINGLE-PAGE TOP UP FLOW (UniPin-style) ----------
@app.route('/topup/<slug>')
def topup_page(slug):
    game_info = GAMES_BY_SLUG.get(slug)
    if not game_info:
        abort(404)
    packages = VALID_PACKAGES.get(game_info['name'], [])
    return render_template('topup.html', game=game_info, packages=packages)

# ---------- CHECKOUT (Manual Payment) ----------
@app.route('/checkout', methods=['GET','POST'])
def checkout():
    if request.method == 'POST':
        game_name = sanitize(request.form.get('game',''))
        user_id   = sanitize(request.form.get('user_id',''))
        server_id = sanitize(request.form.get('server_id',''))
        diamond   = sanitize(request.form.get('diamond',''))
        price     = sanitize(request.form.get('price',''))
        voucher_code = sanitize(request.form.get('voucher_code','')).strip().upper()
        email        = sanitize(request.form.get('email','')).strip()
        # The new /topup/<slug> page already lets the customer pick Dana/QRIS
        # in step 3, so it sends 'payment' directly. The old modal flow (being
        # phased out) doesn't send it yet, so this falls back to Pending and
        # the payment is chosen on the checkout page itself in that case.
        payment = sanitize(request.form.get('payment', '')).strip()
        if payment not in VALID_PAYMENTS:
            payment = 'Pending'

        if not game_name or not user_id or not diamond or not price:
            flash('All fields are required!', 'error')
            return redirect(url_for('index'))

        if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('index'))

        if game_name not in VALID_GAMES: abort(400)
        if not validate_package(game_name, diamond, price): abort(400)

        price_int        = get_price_int(game_name, diamond)
        vip_product_code = get_vip_code(game_name, diamond)
        order_token      = secrets.token_urlsafe(32)
        account_id       = session.get('user_id')

        # Server-side voucher validation. Never trust a discounted price coming
        # from the client -- always recompute here using the authoritative price_int.
        discount_amount = 0
        applied_voucher = None
        db = get_db()
        if voucher_code:
            v = db.execute('SELECT * FROM vouchers WHERE code=?', (voucher_code,)).fetchone()
            voucher_ok = (
                v is not None and v['is_active']
                and (v['max_uses'] is None or v['used_count'] < v['max_uses'])
            )
            if voucher_ok and v['expires_at']:
                try:
                    if datetime.datetime.now() > datetime.datetime.fromisoformat(str(v['expires_at'])):
                        voucher_ok = False
                except ValueError:
                    pass
            if voucher_ok:
                if v['discount_type'] == 'percent':
                    discount_amount = int(price_int * v['discount_value'] / 100)
                else:
                    discount_amount = min(v['discount_value'], price_int)
                applied_voucher = v
            else:
                flash('The voucher code entered is no longer valid and was not applied.', 'error')
                voucher_code = ''

        final_price_int = max(price_int - discount_amount, 0)

        cur = db.execute(
            '''INSERT INTO orders
               (game,user_id,server_id,diamond,price,price_int,payment,
                token,status,vip_product_code,account_id,voucher_code,discount_amount,email)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (game_name,user_id,server_id,diamond,price,final_price_int,
             payment,order_token,'waiting_payment',vip_product_code,account_id,
             voucher_code or None, discount_amount, email or None)
        )
        db.commit()
        order_id = cur.lastrowid

        if applied_voucher:
            db.execute('UPDATE vouchers SET used_count = used_count + 1 WHERE id=?', (applied_voucher['id'],))
            db.commit()
            log_admin('Voucher Used', f"Voucher '{voucher_code}' applied on order #{order_id} (-{format_rupiah(discount_amount)})")

        session[f'order_token_{order_id}'] = order_token

        order = {
            'id': order_id,
            'game': game_name,
            'user_id': user_id,
            'server_id': server_id,
            'diamond': diamond,
            'price': format_rupiah(final_price_int),
            'price_int': final_price_int,
            'original_price_int': price_int,
            'discount_amount': discount_amount,
            'voucher_code': voucher_code,
            'payment': payment,
            'token': order_token,
            'status': 'waiting_payment',
        }
        return render_template('checkout.html',
            order=order,
            dana_number=app.config['DANA_NUMBER'],
            dana_name=app.config['DANA_NAME'],
            qris_image=app.config['QRIS_IMAGE'],
        )
    return redirect(url_for('index'))

# ---------- RESUME AN EXISTING UNPAID ORDER ----------
@app.route('/order/<int:order_id>/continue', methods=['GET'])
def continue_order(order_id):
    """
    Brings the customer back to the payment page for an order they already
    created but haven't paid for yet. Used by the 'Continue Order' button
    shown on the status page for waiting_payment orders.
    """
    token = request.args.get('token', '')
    saved_token = session.get(f'order_token_{order_id}')
    if not saved_token or not secrets.compare_digest(saved_token, token):
        abort(403)

    db  = get_db()
    row = db.execute('SELECT * FROM orders WHERE id=? AND token=?', (order_id, token)).fetchone()
    if not row:
        abort(404)
    if row['status'] != 'waiting_payment':
        flash('This order is no longer waiting for payment.', 'error')
        return redirect(url_for('status', order_id=order_id, token=token))

    order = dict(row)
    order['price'] = format_rupiah(order['price_int'])
    return render_template('checkout.html',
        order=order,
        dana_number=app.config['DANA_NUMBER'],
        dana_name=app.config['DANA_NAME'],
        qris_image=app.config['QRIS_IMAGE'],
    )

# ---------- DISMISS GLOBAL "UNPAID ORDER" BANNER ----------
@app.route('/api/pending-order/<int:order_id>/dismiss', methods=['POST'])
def dismiss_pending_order(order_id):
    """Hides the global unpaid-order banner for this specific order (this session only)."""
    dismissed = session.get('dismissed_pending_orders', [])
    if order_id not in dismissed:
        dismissed.append(order_id)
    session['dismissed_pending_orders'] = dismissed
    return jsonify({'status': True})

# ---------- UPLOAD BUKTI TRANSFER ----------
@app.route('/order/<int:order_id>/upload-proof', methods=['POST'])
def upload_proof(order_id):
    token = request.form.get('token','')
    saved_token = session.get(f'order_token_{order_id}')
    if not saved_token or not secrets.compare_digest(saved_token, token):
        abort(403)

    payment_method = sanitize(request.form.get('payment_method',''))
    if payment_method not in VALID_PAYMENTS:
        flash('Please choose a payment method (Dana or QRIS).', 'error')
        return redirect(url_for('status', order_id=order_id, token=token))

    db  = get_db()
    row = db.execute('SELECT * FROM orders WHERE id=? AND token=?',(order_id,token)).fetchone()
    if not row: abort(404)
    if row['status'] not in ('waiting_payment',):
        flash('Cannot upload proof for this order.', 'error')
        return redirect(url_for('status', order_id=order_id, token=token))

    file = request.files.get('proof')
    if not file or file.filename == '':
        flash('Please select a file to upload.', 'error')
        return redirect(url_for('status', order_id=order_id, token=token))

    if not allowed_file(file.filename):
        flash('File type not allowed. Please upload an image (JPG, PNG, etc).', 'error')
        return redirect(url_for('status', order_id=order_id, token=token))

    ext      = file.filename.rsplit('.',1)[1].lower()
    filename = f'proof_{order_id}_{secrets.token_hex(8)}.{ext}'
    file_bytes = file.read()

    if db_compat.USE_POSTGRES:
        # Stored in the database itself — survives Railway wiping the
        # container's disk on redeploy, unlike a plain saved file would.
        content_type = file.mimetype or 'application/octet-stream'
        db.execute(
            'INSERT INTO payment_proofs (order_id, filename, content_type, data) VALUES (?,?,?,?)',
            (order_id, filename, content_type, file_bytes)
        )
        db.commit()
    else:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'wb') as f:
            f.write(file_bytes)

    db.execute(
        'UPDATE orders SET payment_proof=?, payment=?, status=? WHERE id=?',
        (filename, payment_method, 'waiting_verification', order_id)
    )
    db.commit()
    log_activity('Upload Payment Proof', f'Order #{order_id} uploaded proof ({payment_method}): {filename}')
    flash('Payment proof uploaded! Waiting for admin verification.', 'success')
    return redirect(url_for('status', order_id=order_id, token=token))

# ---------- KONFIRMASI SUDAH BAYAR (tanpa upload) ----------
@app.route('/order/<int:order_id>/confirm-paid', methods=['POST'])
def confirm_paid(order_id):
    token = request.form.get('token','')
    saved_token = session.get(f'order_token_{order_id}')
    if not saved_token or not secrets.compare_digest(saved_token, token):
        abort(403)

    payment_method = sanitize(request.form.get('payment_method',''))
    if payment_method not in VALID_PAYMENTS:
        flash('Please choose a payment method (Dana or QRIS).', 'error')
        return redirect(url_for('status', order_id=order_id, token=token))

    db  = get_db()
    row = db.execute('SELECT * FROM orders WHERE id=? AND token=?',(order_id,token)).fetchone()
    if not row: abort(404)
    if row['status'] != 'waiting_payment':
        flash('Order status cannot be updated.', 'error')
        return redirect(url_for('status', order_id=order_id, token=token))

    db.execute('UPDATE orders SET payment=?, status=? WHERE id=?',(payment_method, 'unverified_claim', order_id))
    db.commit()
    log_activity('Confirm Paid', f'Customer confirmed payment ({payment_method}) for order #{order_id} WITHOUT proof screenshot')
    flash('Payment confirmed (no proof)! This will be verified manually and may take longer.', 'success')
    return redirect(url_for('status', order_id=order_id, token=token))

# ---------- BATALKAN PESANAN (oleh customer) ----------
@app.route('/order/<int:order_id>/cancel', methods=['POST'])
def cancel_order(order_id):
    token = request.form.get('token','')
    saved_token = session.get(f'order_token_{order_id}')
    if not saved_token or not secrets.compare_digest(saved_token, token):
        abort(403)

    db  = get_db()
    row = db.execute('SELECT * FROM orders WHERE id=? AND token=?',(order_id,token)).fetchone()
    if not row: abort(404)
    if row['status'] != 'waiting_payment':
        flash('This order can no longer be cancelled.', 'error')
        return redirect(url_for('status', order_id=order_id, token=token))

    db.execute('UPDATE orders SET status=? WHERE id=?',('cancelled', order_id))
    db.commit()
    log_activity('Order Cancelled', f'Customer cancelled order #{order_id}')
    flash('Order cancelled.', 'success')
    return redirect(url_for('status', order_id=order_id, token=token))

# ---------- STATUS ORDER ----------
@app.route('/status')
def status():
    order_id = sanitize(request.args.get('order_id',''))
    token    = request.args.get('token','')
    order    = None

    if order_id and order_id.isdigit():
        if not token: abort(403)
        db = get_db()
        row = db.execute('SELECT * FROM orders WHERE id=? AND token=?',(order_id,token)).fetchone()
        if row: order = dict(row)
    else:
        abort(403)

    if not order: abort(403)

    is_owner   = bool(session.get(f'order_token_{order["id"]}'))
    status_val = order['status']
    status_label = STATUS_LABELS.get(status_val, status_val.replace('_',' ').title())
    return render_template('status.html',
        status=status_val,
        status_label=status_label,
        order=order,
        is_owner=is_owner,
        status_labels=STATUS_LABELS,
    )

@app.route('/api/order-status/<int:order_id>')
def api_order_status(order_id):
    token=request.args.get('token','')
    saved_token=session.get(f'order_token_{order_id}')
    if not saved_token or not secrets.compare_digest(saved_token,token):
        return jsonify({'error':'forbidden'}),403
    db  = get_db()
    row = db.execute('SELECT status FROM orders WHERE id=? AND token=?',(order_id,token)).fetchone()
    if not row: return jsonify({'error':'not found'}),404
    status_val   = row['status']
    status_label = STATUS_LABELS.get(status_val, status_val)
    return jsonify({'status': status_val, 'label': status_label})

# ---------- SERVE UPLOADED FILES (admin only) ----------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    if not session.get('admin'): abort(403)
    # Validasi filename aman
    safe = secure_filename(filename)
    if safe != filename: abort(400)

    if db_compat.USE_POSTGRES:
        db = get_db()
        row = db.execute('SELECT data, content_type FROM payment_proofs WHERE filename=?', (safe,)).fetchone()
        if not row: abort(404)
        return Response(bytes(row['data']), mimetype=row['content_type'] or 'application/octet-stream')

    return send_from_directory(app.config['UPLOAD_FOLDER'], safe)

# ---------- RIWAYAT ADMIN ----------
@app.route('/riwayat')
def riwayat():
    if not session.get('admin'): return redirect(url_for('admin_login'))
    db   = get_db()
    rows = db.execute('SELECT * FROM orders ORDER BY created_at DESC LIMIT 50').fetchall()
    transactions=[dict(r) for r in rows]
    for t in transactions:
        t['date']=t.get('created_at','')[:10]
        t['status_label'] = STATUS_LABELS.get(t['status'], t['status'])
    return render_template('riwayat.html', transactions=transactions)

# ---------- FEEDBACK ROUTES ----------
@app.route('/report', methods=['GET','POST'])
def report():
    success = False
    if request.method == 'POST':
        name=request.form.get('name','').strip()
        email=request.form.get('email','').strip()
        kategori=request.form.get('kategori','').strip()
        deskripsi=request.form.get('deskripsi','').strip()
        if name and kategori and deskripsi:
            db=get_db()
            db.execute('INSERT INTO reports (name,email,kategori,deskripsi) VALUES (?,?,?,?)',(name,email,kategori,deskripsi))
            db.commit()
            success=True
    return render_template('report.html', success=success)

@app.route('/kritik', methods=['GET','POST'])
def kritik():
    success = False
    if request.method == 'POST':
        name=request.form.get('name','').strip()
        email=request.form.get('email','').strip()
        isi=request.form.get('isi','').strip()
        if name and isi and len(name)>=3 and len(isi)>=10:
            db=get_db()
            db.execute('INSERT INTO kritik (name,email,isi) VALUES (?,?,?)',(name,email,isi))
            db.commit()
            success=True
    return render_template('kritik.html', success=success)

@app.route('/saran', methods=['GET','POST'])
def saran():
    success = False
    if request.method == 'POST':
        name=request.form.get('name','').strip()
        email=request.form.get('email','').strip()
        isi=request.form.get('isi','').strip()
        if name and isi and len(name)>=3 and len(isi)>=10:
            db=get_db()
            db.execute('INSERT INTO saran (name,email,isi) VALUES (?,?,?)',(name,email,isi))
            db.commit()
            success=True
    return render_template('saran.html', success=success)

# ---------- AUTH ROUTES ----------
import re as _re
import secrets as _secrets

def _send_email(to, subject, body_html):
    """Send email helper (reuses existing mail config)."""
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = app.config.get('MAIL_USERNAME','')
        msg['To']      = to
        msg.attach(MIMEText(body_html, 'html'))
        with smtplib.SMTP(app.config.get('MAIL_SERVER','smtp.gmail.com'),
                          app.config.get('MAIL_PORT', 587)) as s:
            s.starttls()
            s.login(app.config.get('MAIL_USERNAME',''),
                    app.config.get('MAIL_PASSWORD',''))
            s.sendmail(msg['From'], [to], msg.as_string())
        return True
    except Exception as e:
        app.logger.error(f'Email send error: {e}')
        return False

@app.route('/login', methods=['GET','POST'])
def login():
    if session.get('user_id'): return redirect(url_for('dashboard'))
    if request.method == 'POST':
        identifier = request.form.get('identifier','').strip()  # username or email
        password   = request.form.get('password','').strip()
        if not identifier or not password:
            flash('Username/email and password are required.', 'error')
            return render_template('login.html')
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE (username=? OR email=?) AND password_hash IS NOT NULL',
            (identifier, identifier)
        ).fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            time.sleep(1)
            flash('Wrong username/email or password.', 'error')
            return render_template('login.html')
        session.clear()
        session['user_id']   = user['id']
        session['user_name'] = user['name']
        session['user_email']= user['email']
        session['user_avatar']= user['avatar'] or ''
        session.permanent = True
        log_activity('Login', f"User '{user['username']}' logged in")
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if session.get('user_id'): return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name     = request.form.get('name','').strip()
        username = request.form.get('username','').strip().lower()
        email    = request.form.get('email','').strip().lower()
        phone    = request.form.get('phone','').strip()
        password = request.form.get('password','').strip()
        confirm  = request.form.get('confirm','').strip()
        # Validation
        if not all([name, username, email, phone, password, confirm]):
            flash('All fields are required.', 'error')
            return render_template('register.html', form=request.form)
        if not _re.match(r'^[a-z0-9_]{3,20}$', username):
            flash('Username must be 3-20 characters, letters/numbers/underscore only.', 'error')
            return render_template('register.html', form=request.form)
        if not _re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email address.', 'error')
            return render_template('register.html', form=request.form)
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html', form=request.form)
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html', form=request.form)
        db = get_db()
        if db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
            flash('Username already taken.', 'error')
            return render_template('register.html', form=request.form)
        if db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
            flash('Email already registered.', 'error')
            return render_template('register.html', form=request.form)
        pw_hash = generate_password_hash(password)
        verify_token = _secrets.token_urlsafe(32)
        db.execute(
            'INSERT INTO users (username,password_hash,name,email,phone,verify_token,is_verified) VALUES (?,?,?,?,?,?,0)',
            (username, pw_hash, name, email, phone, verify_token)
        )
        db.commit()
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        # Send verification email
        verify_url = url_for('verify_email', token=verify_token, _external=True)
        _send_email(email, 'Verify your TrustTop Up account',
            f'''<div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
            <h2 style="color:#a855f7;">TrustTop Up</h2>
            <p>Hi <b>{name}</b>, thanks for registering!</p>
            <p>Click the button below to verify your email:</p>
            <a href="{verify_url}" style="display:inline-block;padding:12px 28px;background:#7c3aed;color:#fff;border-radius:8px;text-decoration:none;font-weight:700;">Verify Email</a>
            <p style="color:#888;font-size:0.85rem;margin-top:16px;">If you didn't create an account, ignore this email.</p>
            </div>''')
        # Auto-login after register
        session.clear()
        session['user_id']    = user['id']
        session['user_name']  = user['name']
        session['user_email'] = user['email']
        session['user_avatar']= ''
        session.permanent = True
        flash('Account created! Please check your email to verify your account.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=request.form)

@app.route('/verify-email/<token>')
def verify_email(token):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE verify_token=?', (token,)).fetchone()
    if not user:
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('login'))
    db.execute('UPDATE users SET is_verified=1, verify_token=NULL WHERE id=?', (user['id'],))
    db.commit()
    flash('Email verified! Your account is fully active.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=? AND password_hash IS NOT NULL', (email,)).fetchone()
        # Always show success msg to prevent email enumeration
        if user:
            token = _secrets.token_urlsafe(32)
            expiry = time.time() + 3600  # 1 hour
            db.execute('UPDATE users SET reset_token=?, reset_token_expiry=? WHERE id=?',
                       (token, expiry, user['id']))
            db.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            _send_email(email, 'Reset your TrustTop Up password',
                f'''<div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
                <h2 style="color:#a855f7;">TrustTop Up</h2>
                <p>Hi <b>{user['name']}</b>,</p>
                <p>Click the button below to reset your password. This link expires in 1 hour.</p>
                <a href="{reset_url}" style="display:inline-block;padding:12px 28px;background:#7c3aed;color:#fff;border-radius:8px;text-decoration:none;font-weight:700;">Reset Password</a>
                <p style="color:#888;font-size:0.85rem;margin-top:16px;">If you didn't request this, ignore this email.</p>
                </div>''')
        flash('If that email is registered, a reset link has been sent.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE reset_token=? AND reset_token_expiry>?',
        (token, time.time())
    ).fetchone()
    if not user:
        flash('Reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password','').strip()
        confirm  = request.form.get('confirm','').strip()
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('reset_password.html', token=token)
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        db.execute('UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expiry=NULL WHERE id=?',
                   (generate_password_hash(password), user['id']))
        db.commit()
        flash('Password reset successfully. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)


@app.route('/bhuahahahaha-owner', methods=['GET','POST'])
def admin_login():
    if session.get('admin'): return redirect(url_for('admin'))
    ip=get_ip()
    if request.method=='POST':
        allowed,remaining=check_login_limit(ip)
        if not allowed:
            flash('Too many login attempts. Please try again in 5 minutes.','error')
            return render_template('admin_login.html')
        username=request.form.get('username','').strip()
        password=request.form.get('password','').strip()
        if not username or not password:
            flash('Username and password are required.','error')
            return render_template('admin_login.html')

        db = get_db()
        row = db.execute('SELECT * FROM admin_users WHERE username=?', (username,)).fetchone()

        if row and check_password_hash(row['password'], password):
            session.clear()
            session['admin']      = True
            session['admin_id']   = row['id']
            session['admin_user'] = row['username']
            session['admin_role'] = row['role']
            session.permanent     = True
            clear_login_fail(ip)
            log_admin('Login Successful', f"{row['role'].capitalize()} '{row['username']}' logged in from IP {ip}")
            return redirect(url_for('admin'))

        record_login_fail(ip)
        _,remaining=check_login_limit(ip)
        log_admin('Login FAILED', f'Wrong credentials from IP {ip}, remaining: {remaining}')
        flash(f'Wrong username or password. Attempts remaining: {remaining}','error')
        time.sleep(1)
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    log_admin('Logout', f"{session.get('admin_role','admin').capitalize()} '{session.get('admin_user','')}' logged out from IP {get_ip()}")
    session.pop('admin', None)
    session.pop('admin_id', None)
    session.pop('admin_user', None)
    session.pop('admin_role', None)
    flash('You have been logged out successfully.','success')
    return redirect(url_for('admin_login'))

# ---------- ADMIN DASHBOARD ----------
@app.route('/admin')
def admin():
    if not session.get('admin'): abort(403)
    db = get_db()
    orders = [dict(r) for r in db.execute('SELECT * FROM orders ORDER BY created_at DESC').fetchall()]
    for o in orders:
        o['status_label'] = STATUS_LABELS.get(o['status'], o['status'])

    total         = len(orders)
    success_count = sum(1 for o in orders if o['status']=='completed')
    pending_count = sum(1 for o in orders if o['status'] in ('waiting_payment','waiting_verification','unverified_claim','processing'))
    failed_count  = sum(1 for o in orders if o['status']=='cancelled')
    revenue_total = sum(o.get('price_int',0) for o in orders if o['status']=='completed')
    stats={
        'total_orders': total,
        'success': success_count,
        'pending': pending_count,
        'failed':  failed_count,
        'revenue': format_rupiah(revenue_total),
        'total_users': db.execute('SELECT COUNT(*) as c FROM users').fetchone()['c'],
    }
    reports  = [dict(r) for r in db.execute('SELECT * FROM reports ORDER BY created_at DESC').fetchall()]
    kritiks  = [dict(r) for r in db.execute('SELECT * FROM kritik ORDER BY created_at DESC').fetchall()]
    sarans   = [dict(r) for r in db.execute('SELECT * FROM saran ORDER BY created_at DESC').fetchall()]
    ratings  = [dict(r) for r in db.execute('SELECT * FROM ratings ORDER BY created_at DESC').fetchall()]
    act_logs = [dict(r) for r in db.execute('SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 500').fetchall()]
    users    = [dict(r) for r in db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()]
    vouchers = [dict(r) for r in db.execute('SELECT * FROM vouchers ORDER BY created_at DESC').fetchall()]

    if is_owner():
        # Owner sees the full dashboard: revenue, admin logs, voucher & staff management
        adm_logs    = [dict(r) for r in db.execute('SELECT * FROM admin_log ORDER BY created_at DESC LIMIT 200').fetchall()]
        admin_users = [dict(r) for r in db.execute("SELECT id, username, role, created_at FROM admin_users ORDER BY created_at ASC").fetchall()]
        blocked_ips = list_blocked_ips()
        return render_template('admin.html',
            orders=orders, stats=stats, reports=reports, kritiks=kritiks,
            sarans=sarans, ratings=ratings, act_logs=act_logs, admin_logs=adm_logs,
            users=users, status_labels=STATUS_LABELS, vouchers=vouchers,
            admin_users=admin_users, is_owner=True, admin_role='owner',
            admin_username=session.get('admin_user',''), blocked_ips=blocked_ips,
        )
    else:
        # Staff sees a restricted dashboard: no revenue figure, no admin logs / staff management
        return render_template('staff_dashboard.html',
            orders=orders, stats=stats, reports=reports, kritiks=kritiks,
            sarans=sarans, ratings=ratings, act_logs=act_logs,
            users=users, status_labels=STATUS_LABELS, vouchers=vouchers,
            is_owner=False, admin_role='staff',
            admin_username=session.get('admin_user',''),
        )

# ---------- OWNER ONLY: STAFF ACCOUNT MANAGEMENT ----------
@app.route('/admin/staff/create', methods=['POST'])
def admin_staff_create():
    require_owner()
    username = request.form.get('username','').strip()
    password = request.form.get('password','').strip()

    if not username or not password:
        flash('Username and password are required.','error')
        return redirect(url_for('admin'))
    if len(password) < 8:
        flash('Password must be at least 8 characters.','error')
        return redirect(url_for('admin'))

    db = get_db()
    existing = db.execute('SELECT id FROM admin_users WHERE username=?', (username,)).fetchone()
    if existing:
        flash(f"Username '{username}' is already taken.",'error')
        return redirect(url_for('admin'))

    db.execute(
        'INSERT INTO admin_users (username, password, role) VALUES (?,?,?)',
        (username, generate_password_hash(password), 'staff')
    )
    db.commit()
    log_admin('Staff Created', f"Owner '{session.get('admin_user')}' created staff account '{username}'")
    flash(f"Staff account '{username}' created successfully.",'success')
    return redirect(url_for('admin'))

@app.route('/admin/staff/<int:staff_id>/delete', methods=['POST'])
def admin_staff_delete(staff_id):
    require_owner()
    db = get_db()
    row = db.execute('SELECT * FROM admin_users WHERE id=?', (staff_id,)).fetchone()
    if not row:
        abort(404)
    if row['role'] == 'owner':
        flash('Cannot delete an Owner account.','error')
        return redirect(url_for('admin'))

    db.execute('DELETE FROM admin_users WHERE id=?', (staff_id,))
    db.commit()
    log_admin('Staff Deleted', f"Owner '{session.get('admin_user')}' deleted staff account '{row['username']}'")
    flash(f"Staff account '{row['username']}' deleted.",'success')
    return redirect(url_for('admin'))

# ---------- OWNER ONLY: IP BLOCKING ----------
_BLOCK_DURATIONS = {
    '1h':   60*60,
    '24h':  60*60*24,
    '7d':   60*60*24*7,
    'permanent': 60*60*24*365*100,  # treated as "Permanent" by list_blocked_ips()
}

@app.route('/admin/ip-block', methods=['POST'])
def admin_ip_block():
    # Backend permission check — this is the real enforcement, independent of any
    # frontend hiding of the button/page. Staff/Admin/Moderator get a 403 even if
    # they discover this URL and POST to it directly.
    require_owner()

    ip       = request.form.get('ip','').strip()
    mode     = request.form.get('duration_mode','preset')
    reason   = sanitize(request.form.get('reason','').strip())

    if not is_valid_ip(ip):
        flash('Please enter a valid IPv4 or IPv6 address.','error')
        return redirect(url_for('admin'))

    if mode == 'manual':
        unit_seconds = {'minutes': 60, 'hours': 60*60, 'days': 60*60*24}
        unit = request.form.get('manual_unit', 'hours')
        try:
            value = int(request.form.get('manual_value', '').strip())
        except (TypeError, ValueError):
            flash('Please enter a valid whole number for the manual duration.', 'error')
            return redirect(url_for('admin'))
        if value <= 0 or unit not in unit_seconds:
            flash('Manual duration must be a positive number with a valid unit.', 'error')
            return redirect(url_for('admin'))
        seconds = value * unit_seconds[unit]
        seconds = min(seconds, _BLOCK_DURATIONS['permanent'])  # cap absurd values at the "permanent" ceiling
        label = f"{value} {unit}"
    else:
        duration = request.form.get('duration', '24h')
        if duration not in _BLOCK_DURATIONS:
            duration = '24h'
        seconds = _BLOCK_DURATIONS[duration]
        label = 'Permanent' if duration == 'permanent' else duration

    block_ip(ip, seconds)
    log_admin('IP Blocked', f"Owner '{session.get('admin_user')}' blocked {ip} ({label})"
                            + (f" — reason: {reason}" if reason else ""))
    flash(f"IP {ip} has been blocked ({label}).", 'success')
    return redirect(url_for('admin'))

@app.route('/admin/ip-unblock', methods=['POST'])
def admin_ip_unblock():
    require_owner()

    ip = request.form.get('ip','').strip()
    if not is_valid_ip(ip):
        flash('Invalid IP address.','error')
        return redirect(url_for('admin'))

    removed = unblock_ip(ip)
    if removed:
        log_admin('IP Unblocked', f"Owner '{session.get('admin_user')}' unblocked {ip}")
        flash(f"IP {ip} has been unblocked.", 'success')
    else:
        flash(f"IP {ip} was not in the blocked list.", 'error')
    return redirect(url_for('admin'))

# ---------- OWNER ONLY: VOUCHER MANAGEMENT ----------
@app.route('/admin/voucher/create', methods=['POST'])
def admin_voucher_create():
    require_owner()
    code = request.form.get('code','').strip().upper()
    discount_type = request.form.get('discount_type','percent').strip()
    discount_value = request.form.get('discount_value','0').strip()
    max_uses = request.form.get('max_uses','').strip()
    expires_at = request.form.get('expires_at','').strip()

    if not code:
        flash('Voucher code is required.','error')
        return redirect(url_for('admin'))
    if discount_type not in ('percent','fixed'):
        flash('Invalid discount type.','error')
        return redirect(url_for('admin'))
    try:
        discount_value = int(discount_value)
        if discount_value <= 0:
            raise ValueError()
        if discount_type == 'percent' and discount_value > 100:
            flash('Percent discount cannot exceed 100.','error')
            return redirect(url_for('admin'))
    except ValueError:
        flash('Discount value must be a positive number.','error')
        return redirect(url_for('admin'))

    max_uses_val = None
    if max_uses:
        try:
            max_uses_val = int(max_uses)
            if max_uses_val <= 0:
                raise ValueError()
        except ValueError:
            flash('Max uses must be a positive number.','error')
            return redirect(url_for('admin'))

    db = get_db()
    existing = db.execute('SELECT id FROM vouchers WHERE code=?', (code,)).fetchone()
    if existing:
        flash(f"Voucher code '{code}' already exists.",'error')
        return redirect(url_for('admin'))

    db.execute(
        '''INSERT INTO vouchers (code, discount_type, discount_value, max_uses, is_active, created_by, expires_at)
           VALUES (?,?,?,?,1,?,?)''',
        (code, discount_type, discount_value, max_uses_val, session.get('admin_user',''), expires_at or None)
    )
    db.commit()
    log_admin('Voucher Created', f"Owner '{session.get('admin_user')}' created voucher '{code}'")
    flash(f"Voucher '{code}' created successfully.",'success')
    return redirect(url_for('admin'))

@app.route('/admin/voucher/<int:voucher_id>/toggle', methods=['POST'])
def admin_voucher_toggle(voucher_id):
    require_owner()
    db = get_db()
    row = db.execute('SELECT * FROM vouchers WHERE id=?', (voucher_id,)).fetchone()
    if not row:
        abort(404)
    new_state = 0 if row['is_active'] else 1
    db.execute('UPDATE vouchers SET is_active=? WHERE id=?', (new_state, voucher_id))
    db.commit()
    log_admin('Voucher Toggled', f"Owner '{session.get('admin_user')}' set voucher '{row['code']}' to {'active' if new_state else 'inactive'}")
    flash(f"Voucher '{row['code']}' is now {'active' if new_state else 'inactive'}.",'success')
    return redirect(url_for('admin'))

@app.route('/admin/voucher/<int:voucher_id>/delete', methods=['POST'])
def admin_voucher_delete(voucher_id):
    require_owner()
    db = get_db()
    row = db.execute('SELECT * FROM vouchers WHERE id=?', (voucher_id,)).fetchone()
    if not row:
        abort(404)
    db.execute('DELETE FROM vouchers WHERE id=?', (voucher_id,))
    db.commit()
    log_admin('Voucher Deleted', f"Owner '{session.get('admin_user')}' deleted voucher '{row['code']}'")
    flash(f"Voucher '{row['code']}' deleted.",'success')
    return redirect(url_for('admin'))

# ---------- PUBLIC: VALIDATE VOUCHER AT CHECKOUT ----------
@app.route('/api/voucher/validate', methods=['POST'])
def validate_voucher():
    """
    Called from the checkout page when the customer enters a voucher code.
    Returns JSON describing whether the code is valid and the resulting discount.
    Does not require login -- any visitor checking out can use a voucher.
    """
    code = (request.json.get('code','') if request.is_json else request.form.get('code','')).strip().upper()
    price_int = request.json.get('price_int',0) if request.is_json else request.form.get('price_int',0)
    try:
        price_int = int(price_int)
    except (TypeError, ValueError):
        price_int = 0

    if not code:
        return jsonify({'valid': False, 'message': 'Please enter a voucher code.'})

    db = get_db()
    row = db.execute('SELECT * FROM vouchers WHERE code=?', (code,)).fetchone()

    if not row:
        return jsonify({'valid': False, 'message': 'Voucher code not found.'})
    if not row['is_active']:
        return jsonify({'valid': False, 'message': 'This voucher is no longer active.'})
    if row['max_uses'] is not None and row['used_count'] >= row['max_uses']:
        return jsonify({'valid': False, 'message': 'This voucher has reached its usage limit.'})
    if row['expires_at']:
        try:
            if datetime.datetime.now() > datetime.datetime.fromisoformat(str(row['expires_at'])):
                return jsonify({'valid': False, 'message': 'This voucher has expired.'})
        except ValueError:
            pass

    if row['discount_type'] == 'percent':
        discount_amount = int(price_int * row['discount_value'] / 100)
    else:
        discount_amount = min(row['discount_value'], price_int)

    final_price = max(price_int - discount_amount, 0)

    return jsonify({
        'valid': True,
        'message': f"Voucher '{code}' applied.",
        'discount_type': row['discount_type'],
        'discount_value': row['discount_value'],
        'discount_amount': discount_amount,
        'final_price': final_price,
    })

# ---------- ADMIN: APPROVE ORDER → PANGGIL VIP-RESELLER ----------
@app.route('/admin/order/<int:order_id>/approve', methods=['POST'])
def admin_approve_order(order_id):
    if not session.get('admin'): abort(403)
    db  = get_db()
    row = db.execute('SELECT * FROM orders WHERE id=?',(order_id,)).fetchone()
    if not row: abort(404)

    orig_status = row['status']
    if orig_status not in ('waiting_verification', 'unverified_claim'):
        flash(f'Order #{order_id} is not waiting for verification.', 'error')
        return redirect(url_for('admin'))

    # Update ke processing dulu
    db.execute('UPDATE orders SET status=? WHERE id=?',('processing', order_id))
    db.commit()
    log_admin('Approve Order', f'Order #{order_id} approved, calling VIP-Reseller API')

    # Panggil VIP-Reseller API
    ref_id = f'TRUST-{order_id}-{secrets.token_hex(4)}'
    success, data = vip_order(
        product_code = row['vip_product_code'],
        target_id    = row['user_id'],
        server_id    = row['server_id'] or '',
        ref_id       = ref_id,
    )

    if success:
        trx_id = data.get('data', {}).get('trxid', '')
        db.execute(
            'UPDATE orders SET status=?,vip_trx_id=?,vip_status=? WHERE id=?',
            ('completed', str(trx_id), 'success', order_id)
        )
        db.commit()
        log_admin('VIP-Reseller Success', f'Order #{order_id} completed, trx_id={trx_id}')
        flash(f'Order #{order_id} approved and processed successfully! TRX ID: {trx_id}', 'success')

        # Notify the customer by email if they provided one at checkout.
        # Sent in a background thread so this request doesn't wait on SMTP.
        if row['email']:
            order_for_email = dict(row)
            order_for_email['status']     = 'completed'
            order_for_email['vip_trx_id'] = str(trx_id)
            notify_customer_async(app, order_id, row['email'], order_for_email)
    else:
        err_msg = data.get('message','Unknown error')
        db.execute(
            'UPDATE orders SET status=?,vip_status=? WHERE id=?',
            (orig_status, f'VIP Error: {err_msg}', order_id)
        )
        db.commit()
        log_admin('VIP-Reseller FAILED', f'Order #{order_id} VIP error: {err_msg}')
        flash(f'Order #{order_id}: VIP-Reseller API failed — {err_msg}. Order reverted to {STATUS_LABELS.get(orig_status, orig_status)}.', 'error')

    return redirect(url_for('admin'))

# ---------- ADMIN: UPDATE STATUS MANUAL ----------
@app.route('/admin/order/<int:order_id>/update', methods=['POST'])
def admin_update_order(order_id):
    if not session.get('admin'): abort(403)
    if session.get('admin_role') != 'owner': abort(403)
    new_status = request.form.get('status','waiting_payment')
    if new_status not in STATUS_LABELS: abort(400)
    db=get_db()
    db.execute('UPDATE orders SET status=? WHERE id=?',(new_status,order_id))
    db.commit()
    log_admin('Update Order Status', f'Order #{order_id} → {new_status} by admin from IP {get_ip()}')
    flash(f'Order #{order_id} status updated to {STATUS_LABELS.get(new_status,new_status)}.','success')
    return redirect(url_for('admin'))

# ---------- ADMIN: CANCEL ORDER ----------
@app.route('/admin/order/<int:order_id>/cancel', methods=['POST'])
def admin_cancel_order(order_id):
    if not session.get('admin'): abort(403)
    db=get_db()
    db.execute('UPDATE orders SET status=? WHERE id=?',('cancelled',order_id))
    db.commit()
    log_admin('Cancel Order', f'Order #{order_id} cancelled by admin')
    flash(f'Order #{order_id} has been cancelled.','success')
    return redirect(url_for('admin'))

# ---------- RETING ----------
@app.route('/reting', methods=['GET','POST'])
def reting():
    success = False
    if request.method == 'POST':
        name=request.form.get('name','').strip()
        bintang=request.form.get('bintang','5').strip()
        isi=request.form.get('isi','').strip()
        try: bintang=max(1,min(5,int(bintang)))
        except Exception: bintang=5
        if name and isi and len(name)>=3 and len(isi)>=10:
            db=get_db()
            db.execute('INSERT INTO ratings (name,bintang,isi) VALUES (?,?,?)',(name,bintang,isi))
            db.commit()
            success=True
    db=get_db()
    all_ratings=[dict(r) for r in db.execute('SELECT * FROM ratings ORDER BY created_at DESC').fetchall()]
    total_ratings=len(all_ratings)
    avg_rating=round(sum(r['bintang'] for r in all_ratings)/total_ratings,1) if total_ratings else 0
    dist={5:0,4:0,3:0,2:0,1:0}
    for r in all_ratings: dist[r['bintang']]=dist.get(r['bintang'],0)+1
    return render_template('reting.html',ratings=all_ratings,total=total_ratings,avg=avg_rating,dist=dist,success=success)

@app.route('/admin/reting/<int:rating_id>/reply', methods=['POST'])
def admin_reply_rating(rating_id):
    if not session.get('admin'): abort(403)
    reply=request.form.get('reply','').strip()
    if reply:
        db=get_db()
        db.execute('UPDATE ratings SET admin_reply=?,replied_at=CURRENT_TIMESTAMP WHERE id=?',(reply,rating_id))
        db.commit()
        log_admin('Reply to Rating', f'Admin replied to rating #{rating_id}')
        flash('Reply saved successfully.','success')
    return redirect(url_for('admin')+'#tab-ratings')

# ---------- GOOGLE LOGIN ----------
@app.route('/login/google')
def login_google():
    return google.authorize_redirect(app.config['GOOGLE_REDIRECT_URI'])

@app.route('/login/google/callback')
def login_google_callback():
    try:
        token=google.authorize_access_token()
        user_info=token.get('userinfo')
        if not user_info:
            flash('Failed to get user info from Google.','error')
            return redirect(url_for('login'))
        google_id=user_info['sub']
        name=user_info.get('name','')
        email=user_info.get('email','')
        avatar=user_info.get('picture','')
        db=get_db()
        user=db.execute('SELECT * FROM users WHERE google_id=?',(google_id,)).fetchone()
        if not user:
            db.execute('INSERT INTO users (google_id,name,email,avatar) VALUES (?,?,?,?)',(google_id,name,email,avatar))
            db.commit()
            user=db.execute('SELECT * FROM users WHERE google_id=?',(google_id,)).fetchone()
        session['user_id']=user['id']
        session['user_name']=user['name']
        session['user_email']=user['email']
        session['user_avatar']=user['avatar']
        session.permanent=True
        log_activity('Google Login',f'{name} ({email}) logged in via Google')
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f'Google OAuth error: {e}')
        flash('Login with Google failed. Please try again.','error')
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'): return redirect(url_for('login'))
    db=get_db()
    orders=[dict(r) for r in db.execute(
        'SELECT * FROM orders WHERE account_id=? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()]
    for o in orders:
        o['status_label'] = STATUS_LABELS.get(o['status'], o['status'])
    return render_template('dashboard.html',
        user_name=session.get('user_name'),
        user_email=session.get('user_email'),
        user_avatar=session.get('user_avatar'),
        orders=orders,
    )

@app.route('/settings')
def settings():
    if not session.get('user_id'): return redirect(url_for('login'))
    db=get_db()
    order_count=db.execute('SELECT COUNT(*) as c FROM orders WHERE account_id=?',(session['user_id'],)).fetchone()['c']
    return render_template('settings.html',
        user_name=session.get('user_name'),
        user_email=session.get('user_email'),
        user_avatar=session.get('user_avatar'),
        order_count=order_count,
        current_lang=session.get('lang','en'),
    )

@app.route('/settings/profile')
def settings_profile():
    if not session.get('user_id'): return redirect(url_for('login'))
    return render_template('profile.html',
        user_name=session.get('user_name'),
        user_email=session.get('user_email'),
        user_avatar=session.get('user_avatar'),
    )

@app.route('/settings/profile/update', methods=['POST'])
def settings_profile_update():
    if not session.get('user_id'): return redirect(url_for('login'))
    lang=session.get('lang','en')
    name=request.form.get('name','').strip()
    if not name:
        flash(get_translator(lang)('flash_profile_name_required'),'error')
        return redirect(url_for('settings_profile'))
    db=get_db()
    db.execute('UPDATE users SET name=? WHERE id=?',(name,session['user_id']))
    db.commit()
    session['user_name']=name
    log_activity('Profile Updated',f'User #{session["user_id"]} updated their display name')
    flash(get_translator(lang)('flash_profile_updated'),'success')
    return redirect(url_for('settings_profile'))

@app.route('/lang/<code>')
def set_language(code):
    if code in ('en', 'id'):
        session['lang'] = code
    dest = request.referrer
    if not dest or not dest.startswith(request.host_url):
        dest = url_for('index')
    return redirect(dest)

@app.route('/settings/language', methods=['POST'])
def settings_language():
    if not session.get('user_id'): return redirect(url_for('login'))
    lang=request.form.get('lang','en')
    if lang not in ('en','id'): lang='en'
    session['lang']=lang
    flash(get_translator(lang)('flash_language_updated'),'success')
    return redirect(url_for('settings'))

@app.route('/settings/theme', methods=['POST'])
def settings_theme():
    if not session.get('user_id'): return redirect(url_for('login'))
    theme = request.form.get('theme', 'default')
    if theme not in ('default', 'simple', 'modern', 'gold'):
        theme = 'default'
    session['theme'] = theme
    lang = session.get('lang', 'en')
    flash(get_translator(lang)('flash_theme_updated'), 'success')
    return redirect(url_for('settings'))

@app.route('/settings/delete-account', methods=['POST'])
def settings_delete_account():
    if not session.get('user_id'): return redirect(url_for('login'))
    confirm=request.form.get('confirm','').strip()
    lang=session.get('lang','en')
    if confirm!='DELETE':
        flash(get_translator(lang)('flash_delete_confirm_required'),'error')
        return redirect(url_for('settings_profile'))
    db=get_db()
    user_id=session['user_id']
    db.execute('UPDATE orders SET account_id=NULL WHERE account_id=?',(user_id,))
    db.execute('DELETE FROM users WHERE id=?',(user_id,))
    db.commit()
    log_activity('Account Deleted',f'User account #{user_id} deleted itself')
    session.pop('user_id',None); session.pop('user_name',None)
    session.pop('user_email',None); session.pop('user_avatar',None)
    flash(get_translator(lang)('flash_account_deleted'),'success')
    return redirect(url_for('index'))

@app.route('/logout/customer')
def logout_customer():
    lang=session.get('lang','en')
    session.pop('user_id',None); session.pop('user_name',None)
    session.pop('user_email',None); session.pop('user_avatar',None)
    flash(get_translator(lang)('flash_logged_out'),'success')
    return redirect(url_for('index'))

# ---------- REAL TIME API ----------
@app.route('/api/admin/stats')
def api_admin_stats():
    if not session.get('admin'): return jsonify({'error':'unauthorized'}),403
    try:
        import psutil
        cpu=psutil.cpu_percent(interval=0.5)
        ram=psutil.virtual_memory().percent
        disk=psutil.disk_usage('/').percent
    except ImportError:
        import random
        cpu=round(random.uniform(20,60),1)
        ram=round(random.uniform(40,75),1)
        disk=round(random.uniform(60,80),1)

    db=get_db()
    orders=[dict(r) for r in db.execute('SELECT * FROM orders ORDER BY created_at DESC').fetchall()]
    for o in orders:
        o['status_label']=STATUS_LABELS.get(o['status'],o['status'])
    total=len(orders)
    success_count=sum(1 for o in orders if o['status']=='completed')
    pending_count=sum(1 for o in orders if o['status'] in ('waiting_payment','waiting_verification','unverified_claim','processing'))
    failed_count =sum(1 for o in orders if o['status']=='cancelled')
    revenue_total=sum(o.get('price_int',0) for o in orders if o['status']=='completed')
    success_rate =round((success_count/total*100),1) if total>0 else 0
    total_users  =db.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']

    # Sparkline 7 hari
    now=datetime.datetime.now(WIB)
    sparklines={'orders':[],'revenue':[],'users':[],'pending':[]}
    for i in range(6,-1,-1):
        day_start=(now-datetime.timedelta(days=i)).replace(hour=0,minute=0,second=0,microsecond=0)
        day_end=day_start.replace(hour=23,minute=59,second=59)
        ds=day_start.strftime('%Y-%m-%d %H:%M:%S')
        de=day_end.strftime('%Y-%m-%d %H:%M:%S')
        day_orders=[o for o in orders if ds<=o.get('created_at','')[:19]<=de]
        sparklines['orders'].append(len(day_orders))
        sparklines['revenue'].append(sum(o.get('price_int',0) for o in day_orders if o['status']=='completed'))
        sparklines['users'].append(0)  # users sparkline placeholder
        sparklines['pending'].append(sum(1 for o in day_orders if o['status'] in ('waiting_payment','waiting_verification','unverified_claim')))

    act_logs =[dict(r) for r in db.execute('SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 8').fetchall()]
    all_logs =[dict(r) for r in db.execute('SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 500').fetchall()]

    stats_payload = {
        'total_orders':total,'total_users':total_users,
        'success':success_count,'pending':pending_count,
        'failed':failed_count,
        'success_rate':success_rate,
        'orders_change':'0',
        'users_change':'0','pending_change':'0',
    }

    response = {
        'stats': stats_payload,
        'sparklines': sparklines,
        'resources':{'cpu':cpu,'ram':ram,'disk':disk},
        'recent_orders':orders[:8],
        'recent_activity':act_logs,
        'all_logs':all_logs,
        'all_orders':orders,
    }

    # Revenue figures and Admin Logs are Owner-only information.
    if is_owner():
        stats_payload['revenue'] = format_rupiah(revenue_total)
        stats_payload['revenue_int'] = revenue_total
        stats_payload['revenue_change'] = '0'
        adm_logs = [dict(r) for r in db.execute('SELECT * FROM admin_log ORDER BY created_at DESC LIMIT 200').fetchall()]
        response['admin_logs'] = adm_logs

    return jsonify(response)

if __name__=='__main__':
    init_db()
    app.run(debug=False,host='0.0.0.0',port=5000)

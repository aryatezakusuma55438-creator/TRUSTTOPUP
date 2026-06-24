import os
import sys

class Config:
    _secret = os.environ.get('SECRET_KEY', '')
    if not _secret:
        print("[ERROR] SECRET_KEY tidak ditemukan di .env!", file=sys.stderr)
        sys.exit(1)
    SECRET_KEY = _secret

    WTF_CSRF_ENABLED    = True
    WTF_CSRF_TIME_LIMIT = 3600
    PERMANENT_SESSION_LIFETIME = 7200

    SESSION_COOKIE_SECURE   = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    DATABASE      = os.path.join(os.path.dirname(__file__), 'database.db')
    ADMIN_USER    = os.environ.get('ADMIN_USER', '')
    ADMIN_PASS    = os.environ.get('ADMIN_PASS', '')
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'instance', 'uploads')
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB untuk bukti transfer

    # Manual Payment Info
    DANA_NUMBER  = os.environ.get('DANA_NUMBER', '082258185709')
    DANA_NAME    = os.environ.get('DANA_NAME', 'TrustTop Up')
    QRIS_IMAGE   = 'qris.png'

    # VIP-Reseller API
    # VIP-Reseller Proxy (VPS) — real VIP-Reseller credentials are NOT stored
    # here, only on the VPS proxy. Railway only needs the proxy URL and token.
    PROXY_URL         = os.environ.get('PROXY_URL', '')          # e.g. http://YOUR_VPS_IP:5000
    PROXY_AUTH_TOKEN  = os.environ.get('PROXY_AUTH_TOKEN', '')

    # Google OAuth
    GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    GOOGLE_REDIRECT_URI  = os.environ.get('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5000/login/google/callback')

    # Outgoing email (order confirmation notifications to customers)
    # For Gmail: use an "App Password", not your normal Gmail password.
    # Generate one at https://myaccount.google.com/apppasswords (requires 2FA enabled).
    SMTP_HOST       = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    SMTP_PORT       = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USER       = os.environ.get('SMTP_USER', '')       # e.g. trusttopup@gmail.com
    SMTP_PASSWORD   = os.environ.get('SMTP_PASSWORD', '')   # Gmail App Password (16 chars)
    SMTP_FROM_NAME  = os.environ.get('SMTP_FROM_NAME', 'TrustTop Up')

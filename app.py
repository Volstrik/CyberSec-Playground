from flask import Flask, render_template, request, jsonify
from tools import (
    password_checker,
    dns_lookup,
    whois_lookup,
    port_scanner,
    hash_generator,
    ssl_checker,
    security_headers,
    url_checker,
)
from tools.validators import check_length
app = Flask(__name__)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
app = Flask(__name__)
import config
from flask_wtf.csrf import CSRFProtect
app.config["SECRET_KEY"] = config.SECRET_KEY
# Explicit session cookie hardening — Flask's defaults are decent, but
# stating these outright removes any ambiguity about intent.
app.config["SESSION_COOKIE_SECURE"] = True      # cookie only sent over HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True     # blocks JS access to the cookie (XSS mitigation)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"    # blocks cross-site cookie leakage while still allowing normal top-level navigation
csrf = CSRFProtect(app)
# Render sits behind one reverse proxy hop — trust exactly one layer of
# X-Forwarded-For so Flask-Limiter sees the real visitor IP, not the proxy's.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
# Reject any request body over 16KB outright — every form on this site
# only needs a few hundred bytes at most.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    # CSP: allows the CDNs you already rely on (Bootstrap, Bootstrap Icons,
    # Google Fonts) while blocking everything else by default.
    response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self';")

    return response
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per hour"],
    storage_uri="memory://",
)

# ── Home ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/password", methods=["GET", "POST"])
def password():
    result = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        result = check_length("password", pwd) or password_checker.analyze(pwd)
    return render_template("password.html", result=result)


@app.route("/url", methods=["GET", "POST"])
@limiter.limit("4 per minute")
def url_checker_route():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "")
        result = check_length("url", url) or url_checker.analyze(url)
    return render_template("url.html", result=result)


@app.route("/whois", methods=["GET", "POST"])
def whois():
    result = None
    if request.method == "POST":
        domain = request.form.get("domain", "")
        result = check_length("domain", domain) or whois_lookup.lookup(domain)
    return render_template("whois.html", result=result)


@app.route("/dns", methods=["GET", "POST"])
def dns():
    result = None
    if request.method == "POST":
        domain = request.form.get("domain", "")
        result = check_length("domain", domain) or dns_lookup.lookup(domain)
    return render_template("dns.html", result=result)


@app.route("/scanner", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def scanner():
    result = None
    if request.method == "POST":
        host = request.form.get("host", "")
        result = check_length("host", host) or port_scanner.scan(host)
    return render_template("scanner.html", result=result)


@app.route("/hash", methods=["GET", "POST"])
def hash_gen():
    result = None
    if request.method == "POST":
        text = request.form.get("text", "")
        result = check_length("text", text) or hash_generator.generate(text)
    return render_template("hash.html", result=result)


@app.route("/ssl", methods=["GET", "POST"])
def ssl():
    result = None
    if request.method == "POST":
        domain = request.form.get("domain", "")
        result = check_length("domain", domain) or ssl_checker.check(domain)
    return render_template("ssl.html", result=result)


@app.route("/headers", methods=["GET", "POST"])
def headers():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "")
        result = check_length("url", url) or security_headers.check(url)
    return render_template("headers.html", result=result)

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("rate_limit.html"), 429
@app.errorhandler(400)
def csrf_error(e):
    return render_template("rate_limit.html"), 400
@app.errorhandler(413)
def request_too_large(e):
    return render_template("rate_limit.html"), 413
if __name__ == "__main__":
    app.run(debug=True)
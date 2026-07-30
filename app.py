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

app = Flask(__name__)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
import config

app.config["SECRET_KEY"] = config.SECRET_KEY
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


# ── Password Strength Analyzer ────────────────────────────────────────────────
@app.route("/password", methods=["GET", "POST"])
def password():
    result = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        result = password_checker.analyze(pwd)
    return render_template("password.html", result=result)


# ── URL Reputation Checker ────────────────────────────────────────────────────
@app.route("/url", methods=["GET", "POST"])
@limiter.limit("4 per minute")
def url_checker_route():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "")
        result = url_checker.analyze(url)
    return render_template("url.html", result=result)


# ── WHOIS Lookup ──────────────────────────────────────────────────────────────
@app.route("/whois", methods=["GET", "POST"])
def whois():
    result = None
    if request.method == "POST":
        domain = request.form.get("domain", "")
        result = whois_lookup.lookup(domain)
    return render_template("whois.html", result=result)


# ── DNS Lookup ────────────────────────────────────────────────────────────────
@app.route("/dns", methods=["GET", "POST"])
def dns():
    result = None
    if request.method == "POST":
        domain = request.form.get("domain", "")
        result = dns_lookup.lookup(domain)
    return render_template("dns.html", result=result)


# ── Port Scanner ──────────────────────────────────────────────────────────────
@app.route("/scanner", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def scanner():
    result = None
    if request.method == "POST":
        host = request.form.get("host", "")
        result = port_scanner.scan(host)
    return render_template("scanner.html", result=result)

# ── Hash Generator ────────────────────────────────────────────────────────────
@app.route("/hash", methods=["GET", "POST"])
def hash_gen():
    result = None
    if request.method == "POST":
        text = request.form.get("text", "")
        result = hash_generator.generate(text)
    return render_template("hash.html", result=result)


# ── SSL Certificate Checker ───────────────────────────────────────────────────
@app.route("/ssl", methods=["GET", "POST"])
def ssl():
    result = None
    if request.method == "POST":
        domain = request.form.get("domain", "")
        result = ssl_checker.check(domain)
    return render_template("ssl.html", result=result)


# ── Security Headers Checker ──────────────────────────────────────────────────
@app.route("/headers", methods=["GET", "POST"])
def headers():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "")
        result = security_headers.check(url)
    return render_template("headers.html", result=result)

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("rate_limit.html"), 429
if __name__ == "__main__":
    app.run(debug=True)
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import re

app = Flask(__name__)

limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

logging.basicConfig(level=logging.INFO, filename="waf_logs.log", format="%(asctime)s - %(message)s")

WHITELIST_IPS = ["127.0.0.1"]  # Permitido
BLACKLIST_IPS = ["192.168.1.100"]  # Bloqueado

# Regras avançadas de proteção
BLOCKED_PATTERNS = [
    r"(\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|EXEC|SLEEP|LOAD_FILE|OUTFILE)\b)",  # SQL Injection
    r"<.*?>",  # Qualquer tag HTML (XSS básico)
    r"(\.\./|\.\./\.\.)",  # Path Traversal
    r"(wget|curl|nc|ncat|scp|ftp)",  # Comandos maliciosos
    r"([\"';]|--|#)",  # Caracteres comuns para ataques
    r"(127\.0\.0\.1|localhost|::1|0\.0\.0\.0)",  # SSRF
    r"(%27|%22|%3C|%3E|%3B)",  # Encoding malicioso
    r"(BENCHMARK|SLEEP|WAITFOR DELAY)",  # Blind SQL Injection
    r"javascript:",  # XSS via javascript:
    r"on\w+\s*=",  # XSS com atributos de evento (onload, onclick, etc.)
]

ALLOWED_HOSTS = ["localhost", "example.com"]

# Função para verificar padrões maliciosos
def is_request_malicious(data):
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False

# Função que regista os logs 
def log_attack(data, reason):
    logging.info(f"Blocked request: {data} | Reason: {reason}")

@app.before_request
def waf_filter():
    client_ip = request.remote_addr

    # Verificação de IPs
    if client_ip in BLACKLIST_IPS:
        log_attack(client_ip, "IP blacklisted")
        return jsonify({"error": "Access Denied", "reason": "IP blacklisted"}), 403

    if WHITELIST_IPS and client_ip not in WHITELIST_IPS:
        log_attack(client_ip, "IP not whitelisted")
        return jsonify({"error": "Access Denied", "reason": "IP not whitelisted"}), 403

    
    if "Host" in request.headers:
        host_header = request.headers["Host"]
        if "malicious.com" in host_header:
            log_attack(host_header, "Invalid Host header")
            return jsonify({"error": "Blocked by WAF", "reason": "Invalid Host header"}), 403

    
    for key, value in request.args.items():
        if is_request_malicious(value):
            log_attack(value, "Malicious query parameter")
            return jsonify({"error": "Blocked by WAF", "reason": "Malicious input detected"}), 403


    if request.data:
        if is_request_malicious(request.data.decode('utf-8', errors='ignore')):
            log_attack(request.data.decode('utf-8', errors='ignore'), "Malicious body data")
            return jsonify({"error": "Blocked by WAF", "reason": "Malicious input detected"}), 403

    
    for header, value in request.headers.items():
        if is_request_malicious(value):
            log_attack(value, "Malicious header")
            return jsonify({"error": "Blocked by WAF", "reason": "Malicious input detected"}), 403


@app.route("/")
@limiter.limit("10 per second")  
def index():
    return jsonify({"message": "Welcome to the enhanced Python WAF!"})

@app.route("/submit", methods=["POST"])
@limiter.limit("5 per second")  
def submit():
    data = request.get_json()
    return jsonify({"message": "Data received!", "data": data})

# Iniciar o servidor
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

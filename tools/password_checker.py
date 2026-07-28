import re
import math

def analyze(password):
    length = len(password)
    checks = {
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digits":    bool(re.search(r"\d", password)),
        "symbols":   bool(re.search(r"[^a-zA-Z0-9]", password)),
    }

    # Character pool size (for entropy calc)
    pool = 0
    if checks["lowercase"]: pool += 26
    if checks["uppercase"]: pool += 26
    if checks["digits"]:    pool += 10
    if checks["symbols"]:   pool += 32

    entropy = round(length * math.log2(pool), 1) if pool else 0

    # Score 0–100
    score = 0
    if length >= 8:  score += 20
    if length >= 12: score += 15
    if length >= 16: score += 10
    if checks["uppercase"]: score += 15
    if checks["lowercase"]: score += 10
    if checks["digits"]:    score += 15
    if checks["symbols"]:   score += 15

    score = min(score, 100)

    # Strength label
    if score < 30:
        label = "Very Weak"
        color = "danger"
    elif score < 50:
        label = "Weak"
        color = "danger"
    elif score < 70:
        label = "Fair"
        color = "warn"
    elif score < 85:
        label = "Strong"
        color = "ok"
    else:
        label = "Very Strong"
        color = "ok"

    # Crack time estimate
    guesses_per_second = 1_000_000_000  # 1 billion (modern GPU)
    combinations = pool ** length if pool else 1
    seconds = combinations / guesses_per_second
    crack_time = format_time(seconds)

    # Suggestions
    suggestions = []
    if length < 12:
        suggestions.append("Use at least 12 characters.")
    if not checks["uppercase"]:
        suggestions.append("Add uppercase letters (A–Z).")
    if not checks["lowercase"]:
        suggestions.append("Add lowercase letters (a–z).")
    if not checks["digits"]:
        suggestions.append("Include numbers (0–9).")
    if not checks["symbols"]:
        suggestions.append("Add symbols like !@#$%.")
    if not suggestions:
        suggestions.append("Good password — consider a password manager to store it safely.")

    return {
        "score":       score,
        "label":       label,
        "color":       color,
        "entropy":     entropy,
        "length":      length,
        "checks":      checks,
        "crack_time":  crack_time,
        "suggestions": suggestions,
    }


def format_time(seconds):
    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds // 86400)} days"
    elif seconds < 3.154e10:
        return f"{int(seconds // 31536000)} years"
    else:
        return "Centuries"
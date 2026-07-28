import hashlib

def generate(text):
    if not text:
        return None

    encoded = text.encode("utf-8")

    return {
        "input":   text,
        "md5":     hashlib.md5(encoded).hexdigest(),
        "sha1":    hashlib.sha1(encoded).hexdigest(),
        "sha256":  hashlib.sha256(encoded).hexdigest(),
        "sha512":  hashlib.sha512(encoded).hexdigest(),
    }
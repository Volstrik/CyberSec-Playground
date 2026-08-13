FIELD_LIMITS = {
    "password": 128,
    "text":     50_000,   # hash generator — generous, hashing is cheap
    "domain":   255,      # max valid DNS hostname length
    "host":     255,
    "url":      2048,     # common practical URL length ceiling
}


def check_length(field_name, value):
    """
    Returns an error dict if the value exceeds the field's limit, else None.
    """
    limit = FIELD_LIMITS.get(field_name)
    if limit is None:
        return None

    if len(value) > limit:
        return {
            "error": f"Input too long — '{field_name}' must be under {limit} characters "
                     f"(received {len(value)})."
        }

    return None
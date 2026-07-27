import jwt
from datetime import datetime, timedelta, timezone
from flask import request, current_app


def create_token(user_id, extra_claims=None):
    """
    Creates a signed JWT for the given user id.

    The token carries:
      - sub: the user's account id (string)
      - iat: issued-at timestamp
      - exp: expiry timestamp, JWT_EXP_HOURS from now (config.py)

    Sign it with the app's JWT_SECRET_KEY (see config.py). Any extra_claims
    passed in (e.g. {"role": "admin"}) are merged into the payload.
    """
    now = datetime.now(timezone.utc)
    exp_hours = current_app.config.get("JWT_EXP_HOURS", 12)

    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(hours=exp_hours),
    }
    if extra_claims:
        payload.update(extra_claims)

    secret = current_app.config["JWT_SECRET_KEY"]
    return jwt.encode(payload, secret, algorithm="HS256")


def _extract_bearer_token():
    """Pulls the raw token string out of 'Authorization: Bearer <token>'."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return None

    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1].strip() or None


def get_user_id():
    """
    Extracts and validates the user id from the 'Authorization: Bearer <token>'
    header.

    The token is a signed JWT (see create_token above) whose 'sub' claim
    holds the user's account id - this replaces the old pattern of sending
    the raw user id itself as the token.

    Returns the user id string, or None if the header is missing, malformed,
    the token has expired, or its signature/claims are invalid.
    """
    token = _extract_bearer_token()
    if not token:
        return None

    secret = current_app.config["JWT_SECRET_KEY"]
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    return payload.get("sub")


def get_token_error():
    """
    Like get_user_id(), but tells you *why* validation failed instead of
    collapsing every case to None. Useful for routes/decorators that want to
    return a clearer error to the frontend (e.g. "token_expired" so the
    client can silently redirect to login vs. show a generic auth error).

    Returns one of: None (token is valid), "missing", "expired", "invalid".
    """
    token = _extract_bearer_token()
    if not token:
        return "missing"

    secret = current_app.config["JWT_SECRET_KEY"]
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.InvalidTokenError:
        return "invalid"

    return None
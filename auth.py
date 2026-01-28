from flask import request, redirect, url_for, abort, current_app
from functools import wraps
import jwt


def decode_jwt(token):
    """Decode and validate JWT token"""
    try:
        return jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=[current_app.config["JWT_ALGORITHM"]],
        )
    except jwt.InvalidTokenError:
        return None


def require_role(role):
    """Decorator to require specific role"""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = request.cookies.get("access_token")
            if not token:
                return redirect(url_for("login"))

            decoded = decode_jwt(token)
            if not decoded or decoded.get("role") != role:
                abort(403)

            return fn(decoded, *args, **kwargs)

        return wrapper

    return decorator

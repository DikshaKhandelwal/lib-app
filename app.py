from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
    abort,
)
import jwt
from datetime import datetime, timedelta
from database import (
    init_db,
    create_user,
    authenticate_user,
    get_user_by_id,
    get_all_books,
    add_book,
    delete_book,
)
from auth import require_role, decode_jwt

app = Flask(__name__)
app.config["SECRET_KEY"] = "library-secret-key-2026"
app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_EXPIRATION_HOURS"] = 1

# Initialize database on startup
init_db()


def get_current_user():
    """Get current user from JWT token in cookie"""
    token = request.cookies.get("access_token")
    if token:
        return decode_jwt(token)
    return None


@app.route("/")
def index():
    """Home page - redirects based on authentication and role"""
    user = get_current_user()
    if user:
        if user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("member_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login page"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = authenticate_user(username, password)
        if user:
            payload = {
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "exp": datetime.utcnow()
                + timedelta(hours=app.config["JWT_EXPIRATION_HOURS"]),
            }
            token = jwt.encode(
                payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
            )

            resp = make_response(
                redirect(
                    url_for(
                        "admin_dashboard"
                        if user["role"] == "admin"
                        else "member_dashboard"
                    )
                )
            )
            resp.set_cookie("access_token", token, httponly=True, samesite="Lax")
            return resp
        else:
            return render_template("login.html", error="Invalid username or password")

    try:
        return render_template("login.html")
    except Exception as e:
        print(f"Error rendering login.html: {e}")
        return f"Error: {e}", 500


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration page"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role", "member")

        if create_user(username, password, role=role):
            return redirect(url_for("login"))
        else:
            return render_template("register.html", error="Username already exists")

    return render_template("register.html")


@app.route("/logout")
def logout():
    """User logout"""
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("access_token")
    return resp


# Admin Routes
@app.route("/admin/dashboard")
@require_role("admin")
def admin_dashboard(decoded):
    """Admin dashboard"""
    return render_template("admin/dashboard.html", user=decoded)


@app.route("/admin/books")
@require_role("admin")
def admin_books(decoded):
    """Admin books - View all books"""
    books = get_all_books()
    return render_template("admin/books.html", user=decoded, books=books)


@app.route("/admin/books/add", methods=["GET", "POST"])
@require_role("admin")
def admin_books_add(decoded):
    """Add a book"""
    if request.method == "POST":
        title = request.form.get("title")
        author = request.form.get("author")
        available = request.form.get("available", 1)

        add_book(title, author, available)
        return redirect(url_for("admin_books"))

    return render_template("admin/books.html", user=decoded)


@app.route("/admin/books/delete/<int:id>", methods=["POST"])
@require_role("admin")
def admin_books_delete(decoded, id):
    """Delete book"""
    delete_book(id)
    return redirect(url_for("admin_books"))


# Member Routes
@app.route("/member/dashboard")
@require_role("member")
def member_dashboard(decoded):
    """Member dashboard"""
    return render_template("member/dashboard.html", user=decoded)


@app.route("/member/books")
@require_role("member")
def member_books(decoded):
    """Member books browsing"""
    books = get_all_books()
    return render_template("member/books.html", user=decoded, books=books)


@app.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden"""
    return render_template("error.html", message="Access Denied"), 403


@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found"""
    return render_template("error.html", message="Page not found"), 404


if __name__ == "__main__":
    app.run(debug=True)

import sqlite3
import bcrypt
from contextlib import contextmanager

DATABASE = "library-management.db"


@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initialize the database with required tables"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password BLOB NOT NULL,
                role TEXT NOT NULL DEFAULT 'member'
            )
        """
        )

        # Books table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                available INTEGER DEFAULT 1
            )
        """
        )

        conn.commit()

        # Create default admin user if not exists
        cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
        if not cursor.fetchone():
            admin_password = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", admin_password, "admin"),
            )
            conn.commit()


# User Management Functions
def create_user(username, password, role="member"):
    """Create a new user"""
    try:
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role),
            )
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False


def authenticate_user(username, password):
    """Authenticate user with username and password"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user["password"]):
            return dict(user)
        return None


def get_user_by_id(user_id):
    """Get user by ID"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None


def get_all_users():
    """Get all users"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role FROM users")
        return [dict(row) for row in cursor.fetchall()]


# Book Management Functions
def add_book(title, author, quantity=1):
    """Add a new book to the library"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO books (title, author, available) VALUES (?, ?, ?)",
                (title, author, quantity),
            )
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False


def get_all_books():
    """Get all books from the library"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM books ORDER BY title")
        return [dict(row) for row in cursor.fetchall()]


def get_book_by_id(book_id):
    """Get book by ID"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM books WHERE id = ?", (book_id,))
        book = cursor.fetchone()
        return dict(book) if book else None


def delete_book(book_id):
    """Delete a book from the library"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM books WHERE id = ?", (book_id,))
        conn.commit()
        return cursor.rowcount > 0

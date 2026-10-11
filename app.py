import os
import sys
import sqlite3
import secrets
import uuid
from datetime import date
from functools import wraps
from getpass import getpass
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_SIZE + (1024 * 1024)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# -------------------- DATABASE --------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def table_columns(conn, table_name):
    return {
        row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    }


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                location TEXT NOT NULL,
                date_lost_found TEXT NOT NULL,
                contact TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('Lost', 'Found', 'Returned')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                college_email TEXT UNIQUE,
                roll_number TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
                is_verified INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CHECK (college_email IS NOT NULL OR roll_number IS NOT NULL)
            )
        """)

        # Safe migrations: add new columns without deleting existing records.
        item_columns = table_columns(conn, "items")
        if "image_filename" not in item_columns:
            conn.execute("ALTER TABLE items ADD COLUMN image_filename TEXT")
        if "moderation_status" not in item_columns:
            # Existing listings stay visible; only new submissions require review.
            conn.execute(
                "ALTER TABLE items ADD COLUMN moderation_status TEXT NOT NULL DEFAULT 'approved'"
            )
        if "user_id" not in item_columns:
            conn.execute("ALTER TABLE items ADD COLUMN user_id INTEGER")


# -------------------- AUTH HELPERS --------------------

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


def verified_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        with get_db() as conn:
            user = conn.execute(
                "SELECT is_verified FROM users WHERE id = ?", (session["user_id"],)
            ).fetchone()

        if user is None:
            session.clear()
            flash("Your account could not be found. Please log in again.", "error")
            return redirect(url_for("login"))
        if not user["is_verified"]:
            flash("Your account is awaiting admin verification.", "error")
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped_view


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        with get_db() as conn:
            user = conn.execute(
                "SELECT role, is_verified FROM users WHERE id = ?", (session["user_id"],)
            ).fetchone()

        if user is None:
            session.clear()
            return redirect(url_for("login"))
        if user["role"] != "admin" or not user["is_verified"]:
            flash("Administrator access is required.", "error")
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped_view


def save_uploaded_image(file_storage):
    """Validate and re-encode an uploaded image; return its generated filename."""
    if not file_storage or not file_storage.filename:
        return None

    # Reject unusually large uploads before decoding them.
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size > MAX_IMAGE_SIZE:
        raise ValueError("Image must be 5 MB or smaller.")
    if size == 0:
        raise ValueError("The selected image file is empty.")

    try:
        with Image.open(file_storage.stream) as image:
            if image.format not in ALLOWED_IMAGE_FORMATS:
                raise ValueError("Use a JPG, PNG, or WebP image.")
            image.verify()

        file_storage.stream.seek(0)
        with Image.open(file_storage.stream) as image:
            image = image.convert("RGB")
            if image.width > 5000 or image.height > 5000:
                raise ValueError("Image dimensions must not exceed 5000 × 5000 pixels.")
            image.thumbnail((1600, 1600))
            filename = f"{uuid.uuid4().hex}.webp"
            output_path = os.path.join(UPLOAD_FOLDER, filename)
            image.save(output_path, format="WEBP", quality=82, method=6)
            return filename
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("The uploaded file is not a valid image.") from exc


def delete_uploaded_image(filename):
    if not filename:
        return
    # Only generated names in our upload directory should be deleted.
    safe_name = os.path.basename(filename)
    path = os.path.join(UPLOAD_FOLDER, safe_name)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        app.logger.exception("Could not delete uploaded image %s", safe_name)


@app.errorhandler(413)
def request_too_large(_error):
    flash("Upload is too large. Please choose an image up to 5 MB.", "error")
    return redirect(request.referrer or url_for("home"))


# -------------------- HOMEPAGE --------------------

@app.route("/")
def home():
    keyword = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    location = request.args.get("location", "").strip()
    status = request.args.get("status", "").strip()

    query = """
        SELECT id, title, description, category, location, date_lost_found,
               contact, status, created_at, image_filename
        FROM items
        WHERE moderation_status = 'approved'
    """
    params = []

    if keyword:
        query += """ AND (
            title LIKE ? COLLATE NOCASE OR description LIKE ? COLLATE NOCASE
            OR category LIKE ? COLLATE NOCASE OR location LIKE ? COLLATE NOCASE
        )"""
        search_term = f"%{keyword}%"
        params.extend([search_term] * 4)

    if category:
        query += " AND category = ?"
        params.append(category)

    if location:
        query += " AND location LIKE ? COLLATE NOCASE"
        params.append(f"%{location}%")

    if status in ("Lost", "Found", "Returned"):
        query += " AND status = ?"
        params.append(status)
    else:
        query += " AND status IN ('Lost', 'Found')"
        status = ""

    query += " ORDER BY created_at DESC"

    with get_db() as conn:
        items = conn.execute(query, params).fetchall()
        categories = conn.execute("""
            SELECT DISTINCT category FROM items
            WHERE moderation_status = 'approved'
            ORDER BY category COLLATE NOCASE
        """).fetchall()

    return render_template(
        "index.html", items=items, categories=categories,
        keyword=keyword, selected_category=category,
        location=location, selected_status=status
    )


# -------------------- REGISTRATION --------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("college_email", "").strip().lower()
        roll_number = request.form.get("roll_number", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or len(full_name) > 100:
            flash("Enter a valid full name.", "error")
        elif not email and not roll_number:
            flash("Enter your college email or roll number.", "error")
        elif len(email) > 254 or len(roll_number) > 50:
            flash("Your email or roll number is too long.", "error")
        elif email and ("@" not in email or "." not in email.rsplit("@", 1)[-1]):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8 or len(password) > 128:
            flash("Password must be between 8 and 128 characters.", "error")
        elif password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
            try:
                with get_db() as conn:
                    conn.execute("""
                        INSERT INTO users (
                            full_name, college_email, roll_number,
                            password_hash, role, is_verified
                        ) VALUES (?, ?, ?, ?, 'student', 0)
                    """, (
                        full_name, email or None, roll_number or None,
                        generate_password_hash(password)
                    ))
                flash("Registration successful. Please wait for admin verification.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email or roll number is already registered.", "error")
            except sqlite3.Error:
                app.logger.exception("Registration database error")
                flash("Registration failed. Please try again.", "error")

    return render_template("register.html")


# -------------------- LOGIN --------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute("""
                SELECT id, full_name, college_email, roll_number,
                       password_hash, role, is_verified
                FROM users
                WHERE lower(college_email) = lower(?) OR roll_number = ?
            """, (identifier, identifier)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid email/roll number or password.", "error")
        elif not user["is_verified"]:
            flash("Your account is not verified yet. Please contact your campus admin.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["full_name"]
            session["role"] = user["role"]
            flash("Welcome back!", "success")
            return redirect(url_for("home"))

    return render_template("login.html")


# -------------------- LOGOUT --------------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# -------------------- ADMIN: VERIFY USERS --------------------

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        user_id = request.form.get("user_id", "").strip()
        action = request.form.get("action", "").strip()
        if not user_id.isdigit() or action not in ("approve", "reject"):
            flash("Invalid moderation request.", "error")
            return redirect(url_for("admin_users"))

        with get_db() as conn:
            target = conn.execute(
                "SELECT id, role FROM users WHERE id = ?", (int(user_id),)
            ).fetchone()
            if target is None or target["role"] != "student":
                flash("Student account not found.", "error")
            elif action == "approve":
                conn.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (int(user_id),))
                flash("Student account approved.", "success")
            else:
                conn.execute(
                    "DELETE FROM users WHERE id = ? AND role = 'student' AND is_verified = 0",
                    (int(user_id),)
                )
                flash("Pending student account rejected.", "success")
        return redirect(url_for("admin_users"))

    with get_db() as conn:
        pending_users = conn.execute("""
            SELECT id, full_name, college_email, roll_number, created_at
            FROM users WHERE role = 'student' AND is_verified = 0
            ORDER BY created_at ASC
        """).fetchall()
    return render_template("admin_users.html", pending_users=pending_users)


# -------------------- ADMIN: REVIEW ITEM REPORTS --------------------

@app.route("/admin/items", methods=["GET", "POST"])
@admin_required
def admin_items():
    if request.method == "POST":
        item_id = request.form.get("item_id", "").strip()
        action = request.form.get("action", "").strip()
        if not item_id.isdigit() or action not in ("approve", "reject"):
            flash("Invalid item moderation request.", "error")
            return redirect(url_for("admin_items"))

        image_to_delete = None
        with get_db() as conn:
            item = conn.execute(
                "SELECT id, image_filename FROM items WHERE id = ? AND moderation_status = 'pending'",
                (int(item_id),)
            ).fetchone()
            if item is None:
                flash("Pending report not found. It may already have been reviewed.", "error")
            elif action == "approve":
                conn.execute(
                    "UPDATE items SET moderation_status = 'approved' WHERE id = ?",
                    (int(item_id),)
                )
                flash("Item report approved and published.", "success")
            else:
                image_to_delete = item["image_filename"]
                conn.execute("DELETE FROM items WHERE id = ?", (int(item_id),))
                flash("Item report rejected and removed.", "success")

        if image_to_delete:
            delete_uploaded_image(image_to_delete)
        return redirect(url_for("admin_items"))

    with get_db() as conn:
        pending_items = conn.execute("""
            SELECT id, title, description, category, location, date_lost_found,
                   contact, status, created_at, image_filename, user_id
            FROM items WHERE moderation_status = 'pending'
            ORDER BY created_at ASC
        """).fetchall()
    return render_template("admin_items.html", pending_items=pending_items)


# -------------------- LOST / FOUND REPORTS --------------------

@app.route("/report/<status>", methods=["GET", "POST"])
@verified_required
def report(status):
    if status.lower() not in ("lost", "found"):
        return "Invalid report type.", 404
    status = status.capitalize()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip()
        location = request.form.get("location", "").strip()
        item_date = request.form.get("date_lost_found", "").strip()
        contact = request.form.get("contact", "").strip()
        image_file = request.files.get("image")

        if not all([title, description, category, location, item_date, contact]):
            flash("All fields except the photo are required.", "error")
            return render_template("report.html", status=status), 400
        if len(title) > 100 or len(description) > 1000 or len(category) > 50:
            flash("Please shorten the item name, description, or category.", "error")
            return render_template("report.html", status=status), 400
        if len(location) > 150 or len(contact) > 100:
            flash("Location or contact information is too long.", "error")
            return render_template("report.html", status=status), 400
        try:
            parsed_date = date.fromisoformat(item_date)
            if parsed_date > date.today():
                raise ValueError
        except ValueError:
            flash("Enter a valid date that is not in the future.", "error")
            return render_template("report.html", status=status), 400

        image_filename = None
        try:
            if image_file and image_file.filename:
                # secure_filename is used as a basic filename sanity check; the stored name is random.
                if not secure_filename(image_file.filename):
                    raise ValueError("Please choose a valid image filename.")
                image_filename = save_uploaded_image(image_file)

            with get_db() as conn:
                conn.execute("""
                    INSERT INTO items (
                        title, description, category, location, date_lost_found,
                        contact, status, image_filename, moderation_status, user_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                """, (
                    title, description, category, location, item_date, contact,
                    status, image_filename, session["user_id"]
                ))

            flash("Your report has been submitted for admin review.", "success")
            return redirect(url_for("home"))
        except ValueError as exc:
            if image_filename:
                delete_uploaded_image(image_filename)
            flash(str(exc), "error")
            return render_template("report.html", status=status), 400
        except sqlite3.Error:
            if image_filename:
                delete_uploaded_image(image_filename)
            app.logger.exception("Item report database error")
            flash("Unable to save your report. Please try again.", "error")

    return render_template("report.html", status=status)


# -------------------- CREATE FIRST ADMIN --------------------

def create_admin():
    print("Create the first Campus Lost & Found administrator.")
    full_name = input("Admin full name: ").strip()
    email = input("College email (press Enter to skip): ").strip().lower()
    roll_number = input("Roll number (press Enter to skip): ").strip()

    if not full_name or not (email or roll_number):
        print("A name and at least one identifier are required.")
        return
    password = getpass("Admin password (minimum 8 characters): ")
    confirm = getpass("Confirm password: ")
    if len(password) < 8 or len(password) > 128 or password != confirm:
        print("Passwords must match and contain 8-128 characters.")
        return

    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO users (
                    full_name, college_email, roll_number,
                    password_hash, role, is_verified
                ) VALUES (?, ?, ?, ?, 'admin', 1)
            """, (
                full_name, email or None, roll_number or None,
                generate_password_hash(password)
            ))
        print("Admin account created. You can now log in.")
    except sqlite3.IntegrityError:
        print("That email or roll number is already registered.")
    except sqlite3.Error:
        print("Could not create the admin account.")
        app.logger.exception("Admin creation error")


if __name__ == "__main__":
    init_db()
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin()
    else:
        app.run(debug=True)

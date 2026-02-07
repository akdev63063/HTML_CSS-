from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity, set_access_cookies, get_jwt
)
import config
import os
import json

# Configure Flask to find templates and static files in parent directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))
static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static'))
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['JWT_SECRET_KEY'] = config.JWT_SECRET_KEY
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

jwt = JWTManager(app)

# Load users from JSON file instead of hardcoding
USERS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), 'users.json'))

def load_users():
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('users', [])
    except FileNotFoundError:
        return []

def get_user(username, password):
    for u in load_users():
        if u.get('username') == username and u.get('password') == password:
            return u
    return None

def user_exists(username):
    """Check if username already exists."""
    for u in load_users():
        if u.get('username') == username:
            return True
    return False

def save_user(username, password, role='user'):
    """Add new user to users.json."""
    try:
        users = load_users()
        users.append({
            "username": username,
            "password": password,
            "role": role
        })
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump({"users": users}, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving user: {e}")
        return False

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = get_user(username, password)
        if user:
            role = user.get('role', 'user')
            token = create_access_token(identity=username, additional_claims={"role": role})
            resp = redirect(url_for('admin' if role == 'admin' else 'dashboard'))
            set_access_cookies(resp, token)
            return resp
        else:
            return "Invalid Credentials"

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Validation
        if not username or not password:
            return render_template("signup.html", error="Username and password are required")
        
        if len(username) < 3:
            return render_template("signup.html", error="Username must be at least 3 characters")
        
        if len(password) < 4:
            return render_template("signup.html", error="Password must be at least 4 characters")
        
        if password != confirm_password:
            return render_template("signup.html", error="Passwords do not match")
        
        if user_exists(username):
            return render_template("signup.html", error="Username already exists")
        
        # Save new user
        if save_user(username, password):
            return redirect(url_for('login'))
        else:
            return render_template("signup.html", error="Error creating account. Please try again")
    
    return render_template("signup.html")


@app.route("/dashboard", methods=["GET", "POST"])
@jwt_required()
def dashboard():
    # Log request method/path for debugging
    print(f"Request to {request.path} with method {request.method}")
    user = get_jwt_identity()
    return render_template("dashboard.html", user=user)


@app.route('/admin', methods=["GET", "POST"])
@jwt_required()
def admin():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return "Forbidden", 403
    user = get_jwt_identity()
    return render_template('admin_dashboard.html', user=user)


@app.route('/logout', methods=["GET"])
def logout():
    """Clear JWT cookie and redirect to login"""
    resp = redirect(url_for('login'))
    resp.delete_cookie('access_token_cookie')
    return resp


if __name__ == "__main__":
    app.run(debug=True)

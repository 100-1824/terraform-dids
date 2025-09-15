from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from threading import Thread, Event
from datetime import datetime, timedelta
from scapy.all import sniff, conf, IP, TCP, UDP
from bson.objectid import ObjectId
import netifaces
import logging
import random
import time
from collections import defaultdict
import os
import re
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/dids_dashboard"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Admin credentials
app.config['ADMIN_USERNAME'] = "admin"
app.config['ADMIN_PASSWORD'] = bcrypt.generate_password_hash("SecureAdmin123!").decode('utf-8')

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# Data storage
traffic_data = []
signature_detections = []
stats = {
    'total_packets': 0,
    'protocol_dist': defaultdict(int),
    'top_talkers': defaultdict(int),
    'threats_blocked': 0
}
capture_event = Event()
capture_active = True

# Threat signatures
THREAT_SIGNATURES = {
    'ET MALWARE': {'port': 4444, 'pattern': b'\x90\x90\x90'},
    'ET SCAN': {'port_range': (1, 1024)},
    'ET TROJAN': {'ip': '192.168.1.100'}
}

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.full_name = user_data.get("full_name", ""),
        self.email = user_data.get("email", ""),
        self.role = user_data.get("role", "user"),
        self.active = user_data.get("active", True)

class Admin(UserMixin):
    def __init__(self):
        self.id = "admin"
        self.username = app.config['ADMIN_USERNAME']
        self.role = "admin"
        self.active = True
        self.full_name = "Administrator"

@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin":
        return Admin()
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Admin access required", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_active_interface():
    try:
        gw = netifaces.gateways()['default'][netifaces.AF_INET]
        return gw[1]
    except Exception:
        return 'eth0'

def log_threat(signature, src, dst):
    action = 'blocked' if random.random() > 0.3 else 'alert'
    detection = {
        'timestamp': datetime.now().isoformat(),
        'signature': signature,
        'source': src,
        'destination': dst,
        'action': action
    }
    signature_detections.append(detection)
    if action == 'blocked':
        stats['threats_blocked'] += 1
    logging.warning(f"Threat {action}: {signature} from {src} to {dst}")

def analyze_packet(pkt):
    if IP not in pkt:
        return None
    
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt.sprintf("%IP.proto%")
    size = len(pkt)

    stats['total_packets'] += 1
    stats['protocol_dist'][proto] += 1
    stats['top_talkers'][src] += size

    if TCP in pkt:
        for name, sig in THREAT_SIGNATURES.items():
            if 'port' in sig and pkt[TCP].dport == sig['port']:
                log_threat(name, src, dst)
            if 'pattern' in sig and sig['pattern'] in bytes(pkt[TCP].payload):
                log_threat(name, src, dst)
    elif UDP in pkt:
        for name, sig in THREAT_SIGNATURES.items():
            if 'port_range' in sig and sig['port_range'][0] <= pkt[UDP].dport <= sig['port_range'][1]:
                log_threat(name, src, dst)
            if 'ip' in sig and (src == sig['ip'] or dst == sig['ip']):
                log_threat(name, src, dst)

    return {
        'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
        'source': src,
        'destination': dst,
        'protocol': proto,
        'size': size
    }

def capture_packets():
    interface = get_active_interface()
    logging.info(f"Starting packet capture on {interface}")
    sniff(
        iface=interface,
        prn=lambda p: _store_packet(analyze_packet(p)),
        store=False,
        stop_filter=lambda p: capture_event.is_set()
    )

def _store_packet(record):
    if record:
        traffic_data.append(record)
        if len(traffic_data) > 1000:
            traffic_data.pop(0)

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    return True, ""

@app.route('/')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('index.html')

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = list(mongo.db.users.find())
    return render_template('admin.html', users=users)

@app.route('/admin/delete-user/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    try:
        result = mongo.db.users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count > 0:
            flash("User deleted successfully", "success")
        else:
            flash("User not found", "error")
    except Exception as e:
        app.logger.error(f"Error deleting user: {e}")
        flash("Error deleting user", "error")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle-user/<user_id>', methods=['POST'])
@admin_required
def toggle_user(user_id):
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if user:
            new_status = not user.get('active', True)
            mongo.db.users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'active': new_status}}
            )
            status = "activated" if new_status else "deactivated"
            flash(f"User {status} successfully", "success")
        else:
            flash("User not found", "error")
    except Exception as e:
        app.logger.error(f"Error toggling user status: {e}")
        flash("Error updating user status", "error")
    return redirect(url_for('admin_dashboard'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([current_password, new_password, confirm_password]):
            flash("All fields are required", "error")
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return redirect(url_for('change_password'))

        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, "error")
            return redirect(url_for('change_password'))

        try:
            if current_user.role == 'admin':
                if not bcrypt.check_password_hash(app.config['ADMIN_PASSWORD'], current_password):
                    flash("Current password is incorrect", "error")
                    return redirect(url_for('change_password'))
                app.config['ADMIN_PASSWORD'] = bcrypt.generate_password_hash(new_password).decode('utf-8')
            else:
                user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
                if not bcrypt.check_password_hash(user_data["password"], current_password):
                    flash("Current password is incorrect", "error")
                    return redirect(url_for('change_password'))
                mongo.db.users.update_one(
                    {"_id": ObjectId(current_user.id)},
                    {"$set": {"password": bcrypt.generate_password_hash(new_password).decode('utf-8')}}
                )

            flash("Password changed successfully", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            app.logger.error(f"Password change error: {e}")
            flash("Error changing password", "error")

    return render_template('change_password.html')

@app.route('/api/current_user')
@login_required
def api_current_user():
    return jsonify({
        'name': current_user.full_name if hasattr(current_user, 'full_name') else current_user.username,
        'username': current_user.username,
        'role': current_user.role
    })

@app.route('/api/traffic')
@login_required
def api_traffic():
    return jsonify(traffic_data[-100:])

@app.route('/api/stats')
@login_required
def api_stats():
    now = datetime.now()
    pps = sum(1 for p in traffic_data if now - datetime.strptime(p['timestamp'], "%H:%M:%S.%f") < timedelta(seconds=1))
    return jsonify({
        'pps': pps,
        'total_packets': stats['total_packets'],
        'threats_blocked': stats['threats_blocked'],
        'protocols': dict(stats['protocol_dist']),
        'top_talkers': dict(sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:5])
    })

@app.route('/api/threats')
@login_required
def api_threats():
    return jsonify(signature_detections[-20:])

@app.route('/api/capture/status')
@login_required
def capture_status():
    return jsonify({'active': capture_active})

@app.route('/api/capture/toggle', methods=['POST'])
@login_required
def toggle_capture():
    global capture_active
    capture_active = not capture_active
    return jsonify({'success': True, 'active': capture_active})

@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip().lower()

        if not full_name:
            flash("Full name is required", "error")
            return redirect(url_for("register"))
        if not username:
            flash("Username is required", "error")
            return redirect(url_for("register"))
        if not password:
            flash("Password is required", "error")
            return redirect(url_for("register"))
            
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))
            
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, "error")
            return redirect(url_for("register"))
            
        if mongo.db.users.find_one({"username": username}):
            flash("Username already exists", "error")
            return redirect(url_for("register"))
            
        if email:
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                flash("Invalid email address", "error")
                return redirect(url_for("register"))
            if mongo.db.users.find_one({"email": email}):
                flash("Email already registered", "error")
                return redirect(url_for("register"))

        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user_data = {
                "full_name": full_name,
                "username": username,
                "password": hashed_password,
                "email": email,
                "role": "user",
                "active": True,
                "created_at": datetime.now()
            }
            result = mongo.db.users.insert_one(user_data)
            
            if result.inserted_id:
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            else:
                flash("Failed to create user account", "error")
                return redirect(url_for("register"))
                
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            flash("An error occurred during registration", "error")
            return redirect(url_for("register"))
            
    return render_template("registration.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
        
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        remember = request.form.get("remember", "off") == "on"
        
        # Check for admin login
        if username == app.config['ADMIN_USERNAME']:
            if bcrypt.check_password_hash(app.config['ADMIN_PASSWORD'], password):
                admin = Admin()
                login_user(admin, remember=remember)
                flash("Admin login successful!", "success")
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Invalid admin password", "error")
                return redirect(url_for('login'))
        
        # Regular user login
        user_data = mongo.db.users.find_one({"username": username})
        
        if user_data:
            if not user_data.get('active', True):
                flash("This account is disabled", "error")
            elif bcrypt.check_password_hash(user_data["password"], password):
                user = User(user_data)
                login_user(user, remember=remember)
                flash("Login successful!", "success")
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for("dashboard"))
            else:
                flash("Invalid password", "error")
        else:
            flash("Username not found", "error")
        
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for("login"))

@app.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if email:
            user = mongo.db.users.find_one({"email": email})
            if user:
                flash("If this email exists, you'll receive a password reset link", "info")
            else:
                flash("If this email exists, you'll receive a password reset link", "info")
            return redirect(url_for("login"))
    
    return render_template("forgot_password.html")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Thread(target=capture_packets, daemon=True).start()
    app.run(host='0.0.0.0', port=8000, debug=True, use_reloader=False)
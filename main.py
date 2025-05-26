# main.py
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, send_file
import os
import json
import uuid
import hashlib
import datetime
import mimetypes
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = 'uploads'
USER_DATA = 'user_data'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(USER_DATA, exist_ok=True)
os.makedirs(os.path.join(USER_DATA, 'users'), exist_ok=True)
os.makedirs(os.path.join(USER_DATA, 'sessions'), exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Kennwort#123"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bitte melde dich an, um fortzufahren', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def save_user(username, password):
    user_id = str(uuid.uuid4())
    user_data = {
        'id': user_id,
        'username': username,
        'password_hash': hash_password(password),
        'created_at': datetime.datetime.now().isoformat()
    }

    with open(os.path.join(USER_DATA, 'users', f"{username}.json"), 'w') as f:
        json.dump(user_data, f)

    return user_id

def get_user(username):
    try:
        with open(os.path.join(USER_DATA, 'users', f"{username}.json"), 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def get_user_files(user_id):
    user_upload_dir = os.path.join(UPLOAD_FOLDER, user_id)
    if not os.path.exists(user_upload_dir):
        return []

    files = []
    for filename in os.listdir(user_upload_dir):
        file_path = os.path.join(user_upload_dir, filename)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)
            file_modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            files.append({
                'name': filename,
                'size': file_size,
                'modified': file_modified
            })

    return files

def is_admin(username):
    user = get_user(username)
    return user and user.get('is_admin', False)

def get_all_users():
    users = []
    user_dir = os.path.join(USER_DATA, 'users')
    for filename in os.listdir(user_dir):
        if filename.endswith('.json'):
            with open(os.path.join(user_dir, filename), 'r') as f:
                user_data = json.load(f)
                user_data.pop('password_hash', None)
                users.append(user_data)
    return users

if not os.path.exists(os.path.join(USER_DATA, 'users', f"{ADMIN_USERNAME}.json")):
    save_user(ADMIN_USERNAME, ADMIN_PASSWORD)
    with open(os.path.join(USER_DATA, 'users', f"{ADMIN_USERNAME}.json"), 'r') as f:
        admin_data = json.load(f)

    admin_data['is_admin'] = True
    with open(os.path.join(USER_DATA, 'users', f"{ADMIN_USERNAME}.json"), 'w') as f:
        json.dump(admin_data, f)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if get_user(username):
            flash('Benutzername bereits vergeben', 'error')
            return redirect(url_for('register'))

        user_id = save_user(username, password)
        session['user_id'] = user_id
        session['username'] = username

        os.makedirs(os.path.join(UPLOAD_FOLDER, user_id), exist_ok=True)

        flash('Registrierung erfolgreich', 'success')
        return redirect(url_for('dashboard'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user(username)
        if user and user['password_hash'] == hash_password(password):
            session['user_id'] = user['id']
            session['username'] = username

            if user.get('is_admin', False):
                session['is_admin'] = True

            flash('Anmeldung erfolgreich', 'success')
            return redirect(url_for('dashboard'))

        flash('Ungültiger Benutzername oder Passwort', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Du wurdest abgemeldet', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = get_user_files(session['user_id'])
    is_admin_user = session.get('is_admin', False)
    return render_template('dashboard.html', username=session['username'], files=files, is_admin=is_admin_user)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('Keine Datei ausgewählt', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('Keine Datei ausgewählt', 'error')
        return redirect(url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        user_upload_dir = os.path.join(UPLOAD_FOLDER, session['user_id'])
        os.makedirs(user_upload_dir, exist_ok=True)
        file.save(os.path.join(user_upload_dir, filename))
        flash('Datei erfolgreich hochgeladen', 'success')

    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    user_upload_dir = os.path.join(UPLOAD_FOLDER, session['user_id'])
    return send_from_directory(user_upload_dir, filename, as_attachment=True)

@app.route('/view/<filename>')
@login_required
def view_file(filename):
    user_upload_dir = os.path.join(UPLOAD_FOLDER, session['user_id'])
    file_path = os.path.join(user_upload_dir, filename)

    if not os.path.exists(file_path):
        flash('Datei nicht gefunden', 'error')
        return redirect(url_for('dashboard'))

    mime_type, _ = mimetypes.guess_type(file_path)

    if mime_type and (mime_type.startswith('text/') or mime_type.startswith('image/')):
        if mime_type.startswith('text/'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                return render_template('view_text.html', filename=filename, content=content)
            except UnicodeDecodeError:
                flash('Die Datei kann nicht als Text angezeigt werden', 'error')
                return redirect(url_for('download_file', filename=filename))
        else:
            return send_file(file_path)
    else:
        flash('Diese Datei kann nicht direkt angezeigt werden', 'info')
        return redirect(url_for('download_file', filename=filename))

@app.route('/delete/<filename>')
@login_required
def delete_file(filename):
    user_upload_dir = os.path.join(UPLOAD_FOLDER, session['user_id'])
    file_path = os.path.join(user_upload_dir, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        flash('Datei erfolgreich gelöscht', 'success')
    else:
        flash('Datei nicht gefunden', 'error')

    return redirect(url_for('dashboard'))

# Admin-Routen
@app.route('/admin')
@login_required
def admin_dashboard():
    if not session.get('is_admin', False):
        flash('Du hast keine Berechtigung für diese Seite', 'error')
        return redirect(url_for('dashboard'))

    users = get_all_users()
    return render_template('admin_dashboard.html', users=users, admin_name=session['username'])

@app.route('/admin/user/<user_id>')
@login_required
def admin_view_user(user_id):
    if not session.get('is_admin', False):
        flash('Du hast keine Berechtigung für diese Seite', 'error')
        return redirect(url_for('dashboard'))

    target_user = None
    for user in get_all_users():
        if user['id'] == user_id:
            target_user = user
            break

    if not target_user:
        flash('Benutzer nicht gefunden', 'error')
        return redirect(url_for('admin_dashboard'))

    files = get_user_files(user_id)

    return render_template('admin_user_files.html',
                          user=target_user,
                          files=files,
                          admin_name=session['username'])

@app.route('/admin/download/<user_id>/<filename>')
@login_required
def admin_download_file(user_id, filename):
    if not session.get('is_admin', False):
        flash('Du hast keine Berechtigung für diese Funktion', 'error')
        return redirect(url_for('dashboard'))

    user_upload_dir = os.path.join(UPLOAD_FOLDER, user_id)
    return send_from_directory(user_upload_dir, filename, as_attachment=True)

@app.route('/admin/view/<user_id>/<filename>')
@login_required
def admin_view_file(user_id, filename):
    if not session.get('is_admin', False):
        flash('Du hast keine Berechtigung für diese Funktion', 'error')
        return redirect(url_for('dashboard'))

    user_upload_dir = os.path.join(UPLOAD_FOLDER, user_id)
    file_path = os.path.join(user_upload_dir, filename)

    if not os.path.exists(file_path):
        flash('Datei nicht gefunden', 'error')
        return redirect(url_for('admin_view_user', user_id=user_id))

    mime_type, _ = mimetypes.guess_type(file_path)

    if mime_type and (mime_type.startswith('text/') or mime_type.startswith('image/')):
        if mime_type.startswith('text/'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                return render_template('admin_view_text.html',
                                      filename=filename,
                                      content=content,
                                      user_id=user_id,
                                      admin_name=session['username'])
            except UnicodeDecodeError:
                flash('Die Datei kann nicht als Text angezeigt werden', 'error')
                return redirect(url_for('admin_download_file', user_id=user_id, filename=filename))
        else:
            return send_file(file_path)
    else:
        flash('Diese Datei kann nicht direkt angezeigt werden', 'info')
        return redirect(url_for('admin_download_file', user_id=user_id, filename=filename))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
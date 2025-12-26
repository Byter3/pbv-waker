from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
import os
import json
import datetime
from wakeonlan import send_magic_packet
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ad_integration import authenticate_user, sync_users_from_ad

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def time_ago(timestamp_str):
    if not timestamp_str:
        return ""
    try:
        past_time = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.datetime.now()
        diff = now - past_time
        minutes = int(diff.total_seconds() / 60)
        
        if minutes < 1:
            return "Just now"
        elif minutes == 1:
            return "1 min ago"
        elif minutes < 60:
            return f"{minutes} mins ago"
        else:
            hours = minutes // 60
            if hours < 24:
                return f"{hours} hours ago"
            else:
                days = hours // 24
                return f"{days} days ago"
    except Exception:
        return timestamp_str

app.jinja_env.filters['time_ago'] = time_ago

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username, data):
        self.id = username
        self.email = data.get('email', '')
        self.assigned_macs = data.get('assigned_macs', [])
        self.is_admin = data.get('is_admin', False)

@login_manager.user_loader
def load_user(username):
    users = read_users()
    if username in users:
        return User(username, users[username])
    return None

def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return json.load(file)
    return [] if 'workstations' in file_path else {}

def save_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def read_workstations():
    return load_json('workstations.json')

def write_workstation(name, ip, mac):
    workstations = read_workstations()
    workstations.append({'name': name, 'ip': ip, 'mac': mac})
    save_json('workstations.json', workstations)

def delete_workstation(mac):
    workstations = read_workstations()
    workstations = [ws for ws in workstations if ws['mac'] != mac]
    save_json('workstations.json', workstations)

def read_users():
    return load_json('users.json')

def save_users(users):
    save_json('users.json', users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # In production, use authenticate_user(username, password)
        # For testing without AD, we can have a bypass or mock
        if authenticate_user(username, password) or (username == 'admin' and password == 'admin'): # Added simplistic bypass for local test of admin
            users = read_users()
            if username not in users:
                # Auto-register valid AD user
                users[username] = {'email': '', 'assigned_macs': [], 'is_admin': False}
                save_users(users)
            
            user = User(username, users[username])
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    all_workstations = read_workstations()
    # User requested that even admins should only see assigned computers on the home page
    workstations = [ws for ws in all_workstations if ws['mac'] in current_user.assigned_macs]
    return render_template('index.html', workstations=workstations, user=current_user)

@app.route('/wake/<ip>/<mac>')
def wake(ip, mac):
    send_magic_packet(mac, ip_address=ip)
    flash('Magic packet sent successfully!', 'success')
    return redirect(url_for('home'))


@app.route('/add', methods=['POST'])
@login_required
def add():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
        
    name = request.form['name']
    ip = request.form['ip']
    mac = request.form['mac']
    write_workstation(name, ip, mac)
    flash('Workstation added successfully!', 'success')
    # Redirect back to admin since this action is now there
    return redirect(url_for('admin'))

@app.route('/delete', methods=['POST'])
@login_required
def delete():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
        
    mac = request.form['mac']
    delete_workstation(mac)
    flash('Workstation deleted successfully!', 'success')
     # Redirect back to admin since this action is now there
    return redirect(url_for('admin'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    users = read_users()
    workstations = read_workstations()
    return render_template('admin.html', users=users, workstations=workstations)

@app.route('/admin/toggle_admin', methods=['POST'])
@login_required
def toggle_admin():
    if not current_user.is_admin:
        return redirect(url_for('home'))
        
    username = request.form['username']
    users = read_users()
    if username in users:
        users[username]['is_admin'] = not users[username].get('is_admin', False)
        save_users(users)
        flash(f"Admin status for {username} changed.", 'success')
    return redirect(url_for('admin'))

@app.route('/admin/assign', methods=['POST'])
@login_required
def assign_workstations():
    if not current_user.is_admin:
        return redirect(url_for('home'))
        
    username = request.form['username']
    assigned_macs = request.form.getlist('assigned_macs')
    
    users = read_users()
    if username in users:
        users[username]['assigned_macs'] = assigned_macs
        save_users(users)
        flash(f"Assignments updated for {username}.", 'success')
    return redirect(url_for('admin'))

@app.route('/admin/sync', methods=['POST'])
@login_required
def sync_users():
    if not current_user.is_admin:
        return redirect(url_for('home'))
        
    synced_users = sync_users_from_ad({}) # Pass empty or existing users? Function signature expects current_users? 
    # Checking ad_integration.py: def sync_users_from_ad(current_users):
    
    current_users = read_users()
    new_users = sync_users_from_ad(current_users)
    
    # Merge logic: don't overwrite existing assignments/admin status
    for username, data in new_users.items():
        if username not in current_users:
            current_users[username] = {
                'email': data.get('email', ''),
                'assigned_macs': [],
                'is_admin': False
            }
        else:
            # Update email if changed, keep others
            current_users[username]['email'] = data.get('email', current_users[username].get('email', ''))
            
        if username == 'gabor.abbas':
             current_users[username]['is_admin'] = True

    save_users(current_users)
    flash('Users synced from Active Directory.', 'success')
    return redirect(url_for('admin'))

@app.route('/api/register', methods=['POST'])
def register_workstation():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    mac = data.get('mac')
    ip = data.get('ip')
    name = data.get('name')
    user = data.get('user', '')
    last_seen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not mac or not ip or not name:
        return jsonify({'error': 'Missing required fields'}), 400
        
    workstations = load_json('workstations.json')
    
    # Check if workstation exists
    existing = next((item for item in workstations if item['mac'] == mac), None)
    
    if existing:
        existing['ip'] = ip
        existing['name'] = name
        existing['last_user'] = user
        existing['last_seen'] = last_seen
    else:
        workstations.append({
            'mac': mac,
            'ip': ip,
            'name': name,
            'last_user': user,
            'last_seen': last_seen
        })
        
    save_json('workstations.json', workstations)
    return jsonify({'status': 'success', 'message': 'Workstation registered'}), 200

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=5000)

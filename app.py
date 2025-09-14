from flask import Flask, render_template, redirect, url_for, request, flash
import os
from wakeonlan import send_magic_packet

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flashing messages

def read_workstations(file_path):
    workstations = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.strip().split(',')
                if len(parts) == 3:
                    workstations.append({
                        'name': parts[0],
                        'ip': parts[1],
                        'mac': parts[2]
                    })
    return workstations

def write_workstation(file_path, name, ip, mac):
    with open(file_path, 'a') as file:
        file.write(f"{name},{ip},{mac}\n")

def delete_workstation(file_path, mac):
    workstations = read_workstations(file_path)
    workstations = [ws for ws in workstations if ws['mac'] != mac]
    with open(file_path, 'w') as file:
        for ws in workstations:
            file.write(f"{ws['name']},{ws['ip']},{ws['mac']}\n")

@app.route('/')
def home():
    workstations = read_workstations('workstations.txt')
    return render_template('index.html', workstations=workstations)

@app.route('/wake/<ip>/<mac>')
def wake(ip, mac):
    send_magic_packet(mac, ip_address=ip)
    flash('Magic packet sent successfully!', 'success')
    return redirect(url_for('home'))


@app.route('/add', methods=['POST'])
def add():
    name = request.form['name']
    ip = request.form['ip']
    mac = request.form['mac']
    write_workstation('workstations.txt', name, ip, mac)
    flash('Workstation added successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/delete', methods=['POST'])
def delete():
    mac = request.form['mac']
    delete_workstation('workstations.txt', mac)
    flash('Workstation deleted successfully!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=5000)

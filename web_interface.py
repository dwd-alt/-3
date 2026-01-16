#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit
import json
import os
from datetime import datetime
import threading
import time
from server import VPNServer

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'
socketio = SocketIO(app, async_mode='eventlet')

# Инициализация VPN сервера
vpn_server = VPNServer()
server_thread = None


def run_vpn_server():
    """Запуск VPN сервера в отдельном потоке"""
    vpn_server.start()


@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Проверка учетных данных
        with open('users.json', 'r') as f:
            users = json.load(f)

        if username in users and users[username]['password_hash'] == vpn_server.hash_password(password):
            session['username'] = username
            session['is_admin'] = (username == 'admin')
            return redirect(url_for('dashboard'))

        return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    stats = vpn_server.get_stats()
    users = list(vpn_server.users.keys())

    return render_template('dashboard.html',
                           username=session['username'],
                           stats=stats,
                           users=users,
                           is_admin=session.get('is_admin', False))


@app.route('/api/start_vpn', methods=['POST'])
def start_vpn():
    global server_thread

    if 'username' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403

    if not vpn_server.running:
        server_thread = threading.Thread(target=run_vpn_server)
        server_thread.daemon = True
        server_thread.start()
        time.sleep(1)  # Даем время на запуск

    return jsonify({'status': 'started', 'stats': vpn_server.get_stats()})


@app.route('/api/stop_vpn', methods=['POST'])
def stop_vpn():
    if 'username' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403

    vpn_server.stop()
    return jsonify({'status': 'stopped'})


@app.route('/api/stats')
def get_stats():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    return jsonify(vpn_server.get_stats())


@app.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def manage_users():
    if 'username' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'GET':
        users_info = []
        for username, user in vpn_server.users.items():
            users_info.append({
                'username': username,
                'created_at': user.created_at.isoformat(),
                'connected': user.connected,
                'client_ip': user.client_ip,
                'data_usage': user.data_usage,
                'last_connection': user.last_connection.isoformat() if user.last_connection else None
            })
        return jsonify(users_info)

    elif request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        if vpn_server.add_user(username, password):
            return jsonify({'success': True, 'message': 'User added'})
        else:
            return jsonify({'error': 'User already exists'}), 409

    elif request.method == 'DELETE':
        username = request.args.get('username')
        if not username:
            return jsonify({'error': 'Username required'}), 400

        if vpn_server.remove_user(username):
            return jsonify({'success': True, 'message': 'User deleted'})
        else:
            return jsonify({'error': 'User not found or cannot be deleted'}), 404


@app.route('/api/kick_user', methods=['POST'])
def kick_user():
    if 'username' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403

    username = request.json.get('username')
    if username in vpn_server.active_connections:
        try:
            vpn_server.active_connections[username].close()
            del vpn_server.active_connections[username]
            vpn_server.users[username].connected = False
            return jsonify({'success': True, 'message': 'User kicked'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'User not connected'}), 404


@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        emit('connection_status', {'status': 'connected'})


@socketio.on('disconnect')
def handle_disconnect():
    pass


if __name__ == '__main__':
    # Создание необходимых директорий
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)

    # Загрузка конфигурации
    with open('config.json', 'r') as f:
        config = json.load(f)

    # Запуск веб-сервера
    socketio.run(
        app,
        host=config['web']['host'],
        port=config['web']['port'],
        debug=config['web']['debug']
    )
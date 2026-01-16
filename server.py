#!/usr/bin/env python3
import socket
import ssl
import threading
import logging
import json
import time
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import netifaces
import psutil
from OpenSSL import crypto
from cryptography.fernet import Fernet
import base64

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VPNUser:
    def __init__(self, username: str, password: str = None):
        self.username = username
        self.password_hash = self.hash_password(password) if password else None
        self.created_at = datetime.now()
        self.last_connection = None
        self.connected = False
        self.client_ip = None
        self.data_usage = {"upload": 0, "download": 0}
        self.sessions = []

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password: str) -> bool:
        return self.password_hash == self.hash_password(password)

    def add_session(self, client_ip: str):
        self.sessions.append({
            "start": datetime.now(),
            "client_ip": client_ip,
            "end": None,
            "data_used": {"upload": 0, "download": 0}
        })
        self.connected = True
        self.client_ip = client_ip
        self.last_connection = datetime.now()


class VPNServer:
    def __init__(self, config_path='config.json'):
        self.load_config(config_path)
        self.users: Dict[str, VPNUser] = {}
        self.active_connections: Dict[str, socket.socket] = {}
        self.running = False
        self.stats = {
            "total_connections": 0,
            "current_connections": 0,
            "total_data": {"upload": 0, "download": 0},
            "start_time": None
        }
        self.load_users()

    def load_config(self, config_path: str):
        with open(config_path, 'r') as f:
            config = json.load(f)
            self.config = config['vpn']
            self.web_config = config['web']

    def load_users(self):
        """Загрузка пользователей из файла"""
        try:
            with open('users.json', 'r') as f:
                users_data = json.load(f)
                for username, data in users_data.items():
                    user = VPNUser(username)
                    user.password_hash = data['password_hash']
                    user.created_at = datetime.fromisoformat(data['created_at'])
                    user.data_usage = data['data_usage']
                    self.users[username] = user
        except FileNotFoundError:
            # Создаем администратора по умолчанию
            admin = VPNUser("admin", "admin123")
            self.users["admin"] = admin
            self.save_users()

    def save_users(self):
        users_data = {}
        for username, user in self.users.items():
            users_data[username] = {
                "password_hash": user.password_hash,
                "created_at": user.created_at.isoformat(),
                "data_usage": user.data_usage
            }
        with open('users.json', 'w') as f:
            json.dump(users_data, f, indent=2)

    def generate_certificates(self):
        """Генерация SSL сертификатов"""
        os.makedirs('certs', exist_ok=True)

        # Генерация CA
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 2048)

        ca_cert = crypto.X509()
        ca_cert.set_version(2)
        ca_cert.set_serial_number(1)
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 год

        ca_subj = ca_cert.get_subject()
        ca_subj.countryName = "RU"
        ca_subj.organizationName = "Kildear VPN"
        ca_subj.commonName = "Kildear VPN CA"

        ca_cert.set_issuer(ca_subj)
        ca_cert.set_pubkey(ca_key)
        ca_cert.sign(ca_key, 'sha256')

        # Генерация серверного сертификата
        server_key = crypto.PKey()
        server_key.generate_key(crypto.TYPE_RSA, 2048)

        server_cert = crypto.X509()
        server_cert.set_version(2)
        server_cert.set_serial_number(2)
        server_cert.gmtime_adj_notBefore(0)
        server_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

        server_subj = server_cert.get_subject()
        server_subj.countryName = "RU"
        server_subj.organizationName = "Kildear VPN"
        server_subj.commonName = "vpn.kildear.com"

        server_cert.set_issuer(ca_cert.get_subject())
        server_cert.set_pubkey(server_key)
        server_cert.sign(ca_key, 'sha256')

        # Сохранение сертификатов
        with open('certs/ca.crt', 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
        with open('certs/server.crt', 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))
        with open('certs/server.key', 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key))

        logger.info("SSL certificates generated successfully")

    def authenticate_user(self, username: str, password: str) -> bool:
        """Аутентификация пользователя"""
        if username in self.users:
            return self.users[username].verify_password(password)
        return False

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Обработка клиентского подключения"""
        client_ip, client_port = address
        logger.info(f"New connection from {client_ip}:{client_port}")

        try:
            # Аутентификация
            auth_data = client_socket.recv(1024).decode().strip()
            if not auth_data:
                client_socket.close()
                return

            username, password = auth_data.split(':', 1)

            if not self.authenticate_user(username, password):
                client_socket.send(b'AUTH_FAILED')
                client_socket.close()
                logger.warning(f"Authentication failed for {username} from {client_ip}")
                return

            client_socket.send(b'AUTH_SUCCESS')

            # Регистрация подключения
            user = self.users[username]
            user.add_session(client_ip)
            self.active_connections[username] = client_socket
            self.stats["current_connections"] += 1
            self.stats["total_connections"] += 1

            logger.info(f"User {username} authenticated successfully")

            # Основной цикл обработки данных
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    # Здесь будет логика обработки VPN трафика
                    # Временная заглушка - эхо-сервер
                    client_socket.send(data)

                    # Обновление статистики
                    user.data_usage["download"] += len(data)
                    user.data_usage["upload"] += len(data)
                    self.stats["total_data"]["download"] += len(data)
                    self.stats["total_data"]["upload"] += len(data)

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error handling data from {username}: {e}")
                    break

        except Exception as e:
            logger.error(f"Error with client {client_ip}: {e}")
        finally:
            # Очистка
            if username in self.active_connections:
                del self.active_connections[username]
            if username in self.users:
                self.users[username].connected = False
                self.users[username].client_ip = None
            self.stats["current_connections"] = max(0, self.stats["current_connections"] - 1)

            if client_socket:
                client_socket.close()

            logger.info(f"Connection closed for {username if 'username' in locals() else 'unknown'}")

    def start(self):
        """Запуск VPN сервера"""
        if not os.path.exists('certs/server.crt'):
            self.generate_certificates()

        # Создание SSL контекста
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('certs/server.crt', 'certs/server.key')
        context.verify_mode = ssl.CERT_NONE  # Для самоподписанных сертификатов

        # Создание сокета
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config['host'], self.config['port']))
        sock.listen(self.config['max_clients'])

        self.server_socket = context.wrap_socket(sock, server_side=True)
        self.running = True
        self.stats["start_time"] = datetime.now()

        logger.info(f"VPN Server started on {self.config['host']}:{self.config['port']}")

        # Основной цикл принятия подключений
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(self.config['timeout'])

                # Запуск в отдельном потоке
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()

            except KeyboardInterrupt:
                logger.info("Server shutdown requested")
                self.stop()
                break
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                if not self.running:
                    break

    def stop(self):
        """Остановка VPN сервера"""
        self.running = False
        logger.info("Stopping VPN server...")

        # Закрытие всех активных подключений
        for username, sock in self.active_connections.items():
            try:
                sock.close()
            except:
                pass

        if hasattr(self, 'server_socket'):
            self.server_socket.close()

        self.save_users()
        logger.info("VPN server stopped")

    def get_stats(self) -> dict:
        """Получение статистики сервера"""
        uptime = None
        if self.stats["start_time"]:
            uptime = str(datetime.now() - self.stats["start_time"]).split('.')[0]

        return {
            "status": "running" if self.running else "stopped",
            "uptime": uptime,
            "current_connections": self.stats["current_connections"],
            "total_connections": self.stats["total_connections"],
            "total_data": self.stats["total_data"],
            "active_users": list(self.active_connections.keys())
        }

    def add_user(self, username: str, password: str) -> bool:
        """Добавление нового пользователя"""
        if username in self.users:
            return False

        user = VPNUser(username, password)
        self.users[username] = user
        self.save_users()
        return True

    def remove_user(self, username: str) -> bool:
        """Удаление пользователя"""
        if username == "admin":
            return False  # Нельзя удалить администратора

        if username in self.users:
            # Если пользователь подключен - отключаем
            if username in self.active_connections:
                try:
                    self.active_connections[username].close()
                except:
                    pass
                del self.active_connections[username]

            del self.users[username]
            self.save_users()
            return True
        return False


if __name__ == "__main__":
    # Запуск сервера
    server = VPNServer()

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
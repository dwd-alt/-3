#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# VPN Server для Render.com
# Запуск: python3 server.py

import socket
import threading
import ssl
import logging
import struct
import select
import os
import time
from OpenSSL import crypto
from cryptography.fernet import Fernet

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - VPN Server - %(levelname)s - %(message)s'
)


class VPNServer:
    def __init__(self, host='0.0.0.0', port=None):
        self.host = host
        self.port = port if port else int(os.environ.get('PORT', 8443))
        self.clients = {}
        self.running = True

        # Генерация ключа шифрования
        key = Fernet.generate_key()
        self.cipher = Fernet(key)
        logging.info(f"Encryption key: {key.decode()}")

        # Создание SSL контекста с самоподписанным сертификатом
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        # Генерация сертификата на лету
        cert_data, key_data = self.generate_self_signed_cert()
        self.context.load_cert_chain(certdata=cert_data, keydata=key_data)

        logging.info(f"Server initialized on port {self.port}")

    def generate_self_signed_cert(self):
        """Генерация самоподписанного SSL сертификата"""
        # Создаем ключ
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Создаем сертификат
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "California"
        cert.get_subject().O = "VPN Server"
        cert.get_subject().CN = "vpn-render-server"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 год
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        # Конвертируем в bytes
        cert_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_bytes = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

        return cert_bytes, key_bytes

    def handle_client(self, client_socket, client_address):
        """Обработка подключения клиента"""
        client_id = f"{client_address[0]}:{client_address[1]}"
        self.clients[client_id] = client_socket

        try:
            logging.info(f"Client connected: {client_id}")

            # Отправляем клиенту ключ шифрования
            key_message = f"KEY:{self.cipher._signing_key.decode()}"
            client_socket.send(key_message.encode())

            while self.running:
                try:
                    # Получаем данные
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    # Пытаемся дешифровать
                    try:
                        decrypted = self.cipher.decrypt(data)
                        logging.debug(f"Received from {client_id}: {len(decrypted)} bytes")

                        # Эхо-ответ (в реальном VPN здесь была бы маршрутизация)
                        response = f"Echo: {decrypted.decode()[:50]}..." if len(
                            decrypted) > 50 else f"Echo: {decrypted.decode()}"
                        encrypted_response = self.cipher.encrypt(response.encode())
                        client_socket.send(encrypted_response)

                    except Exception as e:
                        # Если не удалось дешифровать, возможно это начальное сообщение
                        message = data.decode().strip()
                        if message.startswith("HELLO:"):
                            response = f"HELLO_RESPONSE:{self.port}"
                            client_socket.send(response.encode())
                        else:
                            logging.warning(f"Invalid data from {client_id}")

                except ssl.SSLError as e:
                    logging.error(f"SSL error with {client_id}: {e}")
                    break
                except Exception as e:
                    logging.error(f"Error with {client_id}: {e}")
                    break

        except Exception as e:
            logging.error(f"Client handler error for {client_id}: {e}")
        finally:
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            logging.info(f"Client disconnected: {client_id}")

    def start(self):
        """Запуск сервера"""
        try:
            # Создаем сокет
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)

            # Оборачиваем в SSL
            ssl_socket = self.context.wrap_socket(server_socket, server_side=True)

            logging.info(f"✅ VPN Server started on {self.host}:{self.port}")
            logging.info(f"🔗 Your server URL: https://your-service.onrender.com")
            logging.info(f"📞 Clients can connect to port: {self.port}")

            while self.running:
                try:
                    client_socket, client_address = ssl_socket.accept()

                    # Запускаем обработку в отдельном потоке
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()

                except Exception as e:
                    if self.running:
                        logging.error(f"Accept error: {e}")

        except KeyboardInterrupt:
            logging.info("Shutdown requested...")
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            self.running = False
            if 'ssl_socket' in locals():
                ssl_socket.close()
            logging.info("Server stopped")

    def stop(self):
        """Остановка сервера"""
        self.running = False


if __name__ == "__main__":
    server = VPNServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
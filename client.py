#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# VPN Client для тестирования сервера
# Запуск: python3 client.py <server_url>

import socket
import ssl
import sys
import logging
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO, format='%(message)s')


class VPNClient:
    def __init__(self, server_host, server_port=8443):
        self.server_host = server_host
        self.server_port = server_port
        self.cipher = None
        self.socket = None

        # SSL контекст (без проверки для самоподписанных сертификатов)
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def connect(self):
        """Подключение к серверу"""
        try:
            # Создаем TCP соединение
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(10)

            # Оборачиваем в SSL
            self.socket = self.context.wrap_socket(
                raw_socket,
                server_hostname=self.server_host
            )
            self.socket.connect((self.server_host, self.server_port))

            # Получаем ключ от сервера
            key_message = self.socket.recv(1024).decode()
            if key_message.startswith("KEY:"):
                key = key_message.split(":")[1]
                self.cipher = Fernet(key.encode())
                logging.info(f"✅ Connected to {self.server_host}:{self.server_port}")
                logging.info(f"🔐 Encryption key received")
                return True
            else:
                logging.error("Invalid server response")
                return False

        except Exception as e:
            logging.error(f"Connection failed: {e}")
            return False

    def send_message(self, message):
        """Отправка сообщения на сервер"""
        if not self.cipher or not self.socket:
            logging.error("Not connected to server")
            return None

        try:
            # Шифруем и отправляем
            encrypted = self.cipher.encrypt(message.encode())
            self.socket.send(encrypted)

            # Получаем ответ
            response = self.socket.recv(4096)
            if response:
                decrypted = self.cipher.decrypt(response)
                return decrypted.decode()

        except Exception as e:
            logging.error(f"Send error: {e}")
            return None

    def disconnect(self):
        """Отключение от сервера"""
        if self.socket:
            self.socket.close()
        logging.info("Disconnected")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 client.py <server_host> [port]")
        print("Example: python3 client.py your-service.onrender.com 8443")
        sys.exit(1)

    server_host = sys.argv[1]
    server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443

    client = VPNClient(server_host, server_port)

    if client.connect():
        try:
            # Тестовое сообщение
            test_msg = "Hello VPN Server! This is a test message."
            print(f"Sending: {test_msg}")

            response = client.send_message(test_msg)
            if response:
                print(f"Response: {response}")

            # Можно добавить интерактивный режим
            print("\nInteractive mode (type 'exit' to quit):")
            while True:
                user_input = input("> ")
                if user_input.lower() == 'exit':
                    break

                response = client.send_message(user_input)
                if response:
                    print(f"Server: {response}")

        except KeyboardInterrupt:
            print("\nInterrupted by user")
        finally:
            client.disconnect()
    else:
        print("Failed to connect to server")


if __name__ == "__main__":
    main()
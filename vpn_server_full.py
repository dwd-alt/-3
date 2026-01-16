import socket
import threading
import ssl
import logging
import struct
import select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os
import time

logging.basicConfig(level=logging.INFO)


class Tunnel:
    def __init__(self, client_socket, client_addr):
        self.client_socket = client_socket
        self.client_addr = client_addr
        self.buffer = b''
        self.connected = True

    def read(self):
        try:
            data = self.client_socket.recv(8192)
            if data:
                return data
        except:
            pass
        return None

    def write(self, data):
        try:
            self.client_socket.sendall(data)
            return True
        except:
            return False


class FullVPNServer:
    def __init__(self, host='0.0.0.0', port=1194):
        self.host = host
        self.port = port
        self.tunnels = {}
        self.running = True

        # Конфигурация
        self.mtu = 1500
        self.keepalive = 10

        # Ключи (в реальности - из конфига)
        self.shared_secret = os.urandom(32)

        # SSL
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain('server.crt', 'server.key')

    def handle_handshake(self, client_socket):
        """Протокол рукопожатия"""
        try:
            # Получаем client hello
            hello = client_socket.recv(256)

            # Отправляем server hello с параметрами
            response = struct.pack('!B', 1)  # версия
            response += self.shared_secret
            client_socket.sendall(response)

            # Получаем подтверждение
            ack = client_socket.recv(64)

            return True
        except Exception as e:
            logging.error(f"Handshake failed: {e}")
            return False

    def encapsulate_packet(self, data, tunnel_id):
        """Инкапсуляция пакета (простой заголовок)"""
        header = struct.pack('!HH', tunnel_id, len(data))
        return header + data

    def decapsulate_packet(self, packet):
        """Декапсуляция пакета"""
        if len(packet) < 4:
            return None, None
        tunnel_id, length = struct.unpack('!HH', packet[:4])
        data = packet[4:4 + length]
        return tunnel_id, data

    def handle_client(self, client_socket, client_addr):
        """Основная обработка клиента"""
        tunnel_id = hash(client_addr)

        # Создаем туннель
        tunnel = Tunnel(client_socket, client_addr)
        self.tunnels[tunnel_id] = tunnel

        logging.info(f"New tunnel {tunnel_id} from {client_addr}")

        try:
            # Рукопожатие
            if not self.handle_handshake(client_socket):
                return

            # Основной цикл обработки данных
            while self.running and tunnel.connected:
                # Используем select для проверки доступности данных
                ready = select.select([client_socket], [], [], 1.0)

                if ready[0]:
                    # Получаем данные от клиента
                    raw_data = tunnel.read()
                    if raw_data is None:
                        break

                    # Обрабатываем инкапсулированные пакеты
                    tunnel_id, payload = self.decapsulate_packet(raw_data)
                    if payload:
                        # Здесь должна быть маршрутизация пакета
                        # Для примера - просто логируем
                        logging.debug(f"Packet from tunnel {tunnel_id}: {len(payload)} bytes")

                        # Эхо-ответ
                        response = payload
                        encapsulated = self.encapsulate_packet(response, tunnel_id)
                        tunnel.write(encapsulated)

                # Keep-alive
                if time.time() % self.keepalive < 0.1:
                    keepalive_msg = struct.pack('!B', 255)  # тип keepalive
                    encapsulated = self.encapsulate_packet(keepalive_msg, tunnel_id)
                    tunnel.write(encapsulated)

        except Exception as e:
            logging.error(f"Tunnel {tunnel_id} error: {e}")
        finally:
            client_socket.close()
            if tunnel_id in self.tunnels:
                del self.tunnels[tunnel_id]
            logging.info(f"Tunnel {tunnel_id} closed")

    def start(self):
        """Запуск полного сервера"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)

        logging.info(f"Full VPN server started on {self.host}:{self.port}")

        try:
            while self.running:
                client_socket, client_addr = server_socket.accept()

                # Оборачиваем в SSL
                try:
                    ssl_socket = self.context.wrap_socket(
                        client_socket,
                        server_side=True
                    )
                except Exception as e:
                    logging.error(f"SSL error: {e}")
                    client_socket.close()
                    continue

                # Запускаем обработчик
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(ssl_socket, client_addr)
                )
                thread.daemon = True
                thread.start()

        except KeyboardInterrupt:
            logging.info("Server stopping...")
        finally:
            server_socket.close()
            self.running = False


if __name__ == "__main__":
    server = FullVPNServer()
    server.start()
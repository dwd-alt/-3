import socket
import ssl
import threading
import struct
import select
import logging
import time
from queue import Queue
import sys

logging.basicConfig(level=logging.INFO)


class SOCKS5Proxy:
    def __init__(self, vpn_tunnel, listen_port=1080):
        self.vpn_tunnel = vpn_tunnel
        self.listen_port = listen_port
        self.running = True

    def handle_socks5_connection(self, client_socket):
        """Обработка SOCKS5 соединения"""
        try:
            # SOCKS5 приветствие
            greeting = client_socket.recv(256)
            client_socket.sendall(b'\x05\x00')  # No authentication

            # SOCKS5 запрос
            request = client_socket.recv(256)
            if len(request) < 7:
                client_socket.close()
                return

            # Парсим запрос
            version, cmd, _, addr_type = struct.unpack('!BBBB', request[:4])

            if addr_type == 1:  # IPv4
                dest_addr = socket.inet_ntoa(request[4:8])
                dest_port = struct.unpack('!H', request[8:10])[0]
            elif addr_type == 3:  # Domain name
                domain_length = request[4]
                dest_addr = request[5:5 + domain_length].decode()
                dest_port = struct.unpack('!H', request[5 + domain_length:7 + domain_length])[0]
            else:
                client_socket.close()
                return

            # Отправляем ответ об успехе
            response = struct.pack('!BBBBIH', 5, 0, 0, 1, 0, 0)
            client_socket.sendall(response)

            # Создаем подключение через VPN
            self.vpn_tunnel.forward_traffic(client_socket, dest_addr, dest_port)

        except Exception as e:
            logging.error(f"SOCKS5 error: {e}")
            client_socket.close()

    def start(self):
        """Запуск SOCKS5 прокси"""
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_socket.bind(('127.0.0.1', self.listen_port))
        proxy_socket.listen(5)

        logging.info(f"SOCKS5 proxy listening on 127.0.0.1:{self.listen_port}")

        while self.running:
            try:
                client_socket, client_addr = proxy_socket.accept()
                logging.debug(f"New SOCKS5 connection from {client_addr}")

                thread = threading.Thread(
                    target=self.handle_socks5_connection,
                    args=(client_socket,)
                )
                thread.daemon = True
                thread.start()

            except Exception as e:
                if self.running:
                    logging.error(f"Proxy error: {e}")

        proxy_socket.close()


class VPNTunnel:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.tunnel_id = None
        self.running = True
        self.connections = {}

        # Очередь для отправки
        self.send_queue = Queue()

        # SSL контекст
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def connect(self):
        """Подключение к серверу"""
        try:
            # TCP соединение
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(10)

            # SSL
            self.socket = self.context.wrap_socket(
                raw_socket,
                server_hostname=self.server_host
            )
            self.socket.connect((self.server_host, self.server_port))

            # Рукопожатие
            if self.handshake():
                logging.info("VPN tunnel established")
                return True

        except Exception as e:
            logging.error(f"Connection failed: {e}")
            self.disconnect()

        return False

    def handshake(self):
        """Рукопожатие с сервером"""
        try:
            # Отправляем client hello
            hello = struct.pack('!B16s', 1, b'VPN_CLIENT_HELLO')
            self.socket.sendall(hello)

            # Получаем ответ сервера
            response = self.socket.recv(256)
            if len(response) < 17:
                return False

            version, = struct.unpack('!B', response[:1])
            self.tunnel_id = hash((self.server_host, self.server_port))

            # Отправляем подтверждение
            ack = struct.pack('!B', 1)
            self.socket.sendall(ack)

            return True

        except Exception as e:
            logging.error(f"Handshake error: {e}")
            return False

    def encapsulate(self, data):
        """Инкапсуляция пакета"""
        if not self.tunnel_id:
            return None

        header = struct.pack('!HH', self.tunnel_id % 65536, len(data))
        return header + data

    def decapsulate(self, packet):
        """Декапсуляция пакета"""
        if len(packet) < 4:
            return None, None

        tunnel_id, length = struct.unpack('!HH', packet[:4])
        if len(packet) < 4 + length:
            return None, None

        return tunnel_id, packet[4:4 + length]

    def forward_traffic(self, client_socket, dest_addr, dest_port):
        """Перенаправление трафика"""
        connection_id = f"{dest_addr}:{dest_port}"

        def forward_loop():
            try:
                # Создаем сокет для назначения (через VPN)
                # В реальном VPN здесь было бы установление TCP соединения через туннель

                buffers = {client_socket: b'', self.socket: b''}
                sockets = [client_socket, self.socket]

                while self.running:
                    try:
                        readable, _, exceptional = select.select(
                            sockets, [], sockets, 1.0
                        )

                        for sock in readable:
                            data = sock.recv(4096)
                            if data:
                                if sock is client_socket:
                                    # Данные от клиента -> отправляем в VPN
                                    encapsulated = self.encapsulate(data)
                                    if encapsulated:
                                        self.socket.sendall(encapsulated)
                                else:
                                    # Данные от VPN -> отправляем клиенту
                                    client_socket.sendall(data)

                        for sock in exceptional:
                            break

                    except Exception as e:
                        logging.debug(f"Forwarding error: {e}")
                        break

            except Exception as e:
                logging.error(f"Forward loop error: {e}")
            finally:
                client_socket.close()
                if connection_id in self.connections:
                    del self.connections[connection_id]

        # Запускаем поток для пересылки
        thread = threading.Thread(target=forward_loop)
        thread.daemon = True
        thread.start()
        self.connections[connection_id] = thread

    def start_tunnel(self):
        """Основной цикл туннеля"""
        while self.running:
            try:
                # Проверяем данные от сервера
                ready = select.select([self.socket], [], [], 1.0)

                if ready[0]:
                    data = self.socket.recv(8192)
                    if data:
                        # Обрабатываем инкапсулированные данные
                        tunnel_id, payload = self.decapsulate(data)
                        if payload:
                            # В реальном VPN здесь была бы маршрутизация к клиентам
                            logging.debug(f"Received {len(payload)} bytes through tunnel")

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logging.error(f"Tunnel error: {e}")
                break

        self.disconnect()

    def disconnect(self):
        """Отключение"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        logging.info("VPN tunnel disconnected")


def main():
    if len(sys.argv) != 3:
        print("Usage: python vpn_client_full.py <server_ip> <server_port>")
        sys.exit(1)

    server_host = sys.argv[1]
    server_port = int(sys.argv[2])

    # Создаем VPN туннель
    vpn_tunnel = VPNTunnel(server_host, server_port)

    if vpn_tunnel.connect():
        # Запускаем SOCKS5 прокси
        proxy = SOCKS5Proxy(vpn_tunnel)
        proxy_thread = threading.Thread(target=proxy.start)
        proxy_thread.daemon = True
        proxy_thread.start()

        # Запускаем основной туннель
        try:
            vpn_tunnel.start_tunnel()
        except KeyboardInterrupt:
            logging.info("Shutting down...")
        finally:
            vpn_tunnel.disconnect()
            proxy.running = False
    else:
        logging.error("Failed to establish VPN connection")


if __name__ == "__main__":
    main()
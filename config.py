import json
import os


class VPNConfig:
    def __init__(self, config_file='vpn_config.json'):
        self.config_file = config_file
        self.config = self.load_config()

    def load_config(self):
        default_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 1194,
                "ssl_cert": "server.crt",
                "ssl_key": "server.key",
                "encryption": "AES-256-GCM",
                "keepalive": 10
            },
            "client": {
                "server_host": "your_server.com",
                "server_port": 1194,
                "local_proxy_port": 1080,
                "reconnect_timeout": 5
            },
            "security": {
                "handshake_timeout": 30,
                "max_packet_size": 65535,
                "allow_compression": False
            }
        }

        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                user_config = json.load(f)
                # Обновляем дефолтные значения
                default_config.update(user_config)

        return default_config

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def get(self, key, default=None):
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
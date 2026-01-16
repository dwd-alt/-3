#!/bin/bash
# install.sh

echo "Установка зависимостей для VPN..."

# Обновление пакетов
apt-get update

# Установка Python зависимостей
pip3 install --upgrade pip
pip3 install cryptography==41.0.0
pip3 install pyOpenSSL==23.2.0
pip3 install netifaces==0.11.0

# Установка системных утилит
apt-get install -y net-tools iptables iproute2

echo "Зависимости установлены"
echo ""
echo "Для генерации сертификатов выполните:"
echo "openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=VPN-Server'"
echo ""
echo "Запуск сервера: python3 vpn_server_full.py"
echo "Запуск клиента: python3 vpn_client_full.py <server_ip> <port>"
#!/usr/bin/env python3
import subprocess
import sys

print("Установка зависимостей для VPN...")

# Установка Python-зависимостей через pip
subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
subprocess.run([sys.executable, "-m", "pip", "install", "cryptography==41.0.0"])
subprocess.run([sys.executable, "-m", "pip", "install", "pyOpenSSL==23.2.0"])

print("Зависимости установлены")

import re
import json
import requests
from datetime import datetime

# Настройки
LOG_FILE = "auth.log"  # Файл журнала аутентификации
THREAT_INTEL_API = "https://api.abuseipdb.com/api/v2/check"  # API для проверки IP
API_KEY = "YOUR_API_KEY"  # Замените на ваш ключ
BLOCKLIST_FILE = "blocklist.txt"  # Файл для блокировки IP

# Фильтр подозрительных попыток входа
FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (invalid user )?(\w+) from ([\d\.]+) port")


def parse_logs(log_file):
    suspicious_ips = {}
    with open(log_file, "r") as file:
        for line in file:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                username = match.group(2)
                ip = match.group(3)
                if ip not in suspicious_ips:
                    suspicious_ips[ip] = {"count": 0, "users": set()}
                suspicious_ips[ip]["count"] += 1
                suspicious_ips[ip]["users"].add(username)
    return suspicious_ips


def check_threat_intel(ip):
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    response = requests.get(THREAT_INTEL_API, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return data["data"].get("abuseConfidenceScore", 0)  # Уровень угрозы
    return 0


def block_ip(ip):
    with open(BLOCKLIST_FILE, "a") as file:
        file.write(ip + "\n")
    print(f"IP {ip} добавлен в список блокировки")


def simulate_incidents():
    test_logs = [
        "Failed password for root from 192.168.1.10 port 22",
        "Failed password for admin from 203.0.113.45 port 22",
        "Failed password for invalid user guest from 185.199.110.153 port 22",
        "Failed password for user from 192.168.1.15 port 22",
        "Failed password for invalid user test from 203.0.113.45 port 22",
        "Failed password for root from 185.199.110.153 port 22"
    ]
    
    with open(LOG_FILE, "w") as file:
        for log in test_logs:
            file.write(log + "\n")


if __name__ == "__main__":
    simulate_incidents()  # Генерация тестовых данных
    logs = parse_logs(LOG_FILE)
    for ip, info in logs.items():
        if info["count"] > 2:  # Порог срабатывания
            threat_score = check_threat_intel(ip)
            print(f"Проверка IP {ip}: {threat_score}")
            if threat_score > 50:  # Порог угрозы
                block_ip(ip)

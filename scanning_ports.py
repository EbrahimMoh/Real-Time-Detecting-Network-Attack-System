#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP
import time
import threading
import requests
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

TELEGRAM_BOT_TOKEN = "6145984720:AAGYK4M30COAV2e_1Ja9sQOsjr9yiZm4j4g"
TELEGRAM_CHAT_ID = "1307626802"

EMAIL_ADDRESS = "sender352023@gmail.com"
EMAIL_PASSWORD = "737767010"
RECIPIENT_EMAIL = "alert352023@gmail.com"

APP_PASSWORD = "vdkr jmhl sksn usyf"  

# Threshold for the number of unique ports to trigger an alert
UNIQUE_PORT_THRESHOLD = 300

# Dictionary to store unique ports for each destination IP
unique_ports = {}

# Function to send a message using Telegram bot
def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }
    response = requests.post(url, data=data)
    if response.status_code != 200:
        print("Failed to send Telegram message")

# Function to send a message using email
def send_email_message(subject, body, app_password=None):
    try:
        # Create the email content
        message = MIMEMultipart()
        message["From"] = EMAIL_ADDRESS
        message["To"] = RECIPIENT_EMAIL
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        # Establish a secure connection with the SMTP server
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_ADDRESS, app_password or EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, RECIPIENT_EMAIL, message.as_string())

    except Exception as e:
        print(f"Failed to send email. Error: {e}")

# Function to prompt the user for confirmation
def prompt_user(ip_address):
    response = input(f"[*] There is someone scanning ports for the server, detected from {ip_address}. Block this IP? (yes/no): ").lower()
    if response == 'yes':
        # Block the attacker's IP address using ufw and send a Telegram alert
        block_ip_address(ip_address)
        print(f"[*] IP {ip_address} blocked. Waiting for upcoming connection...")
    else:
        print("[*] IP not blocked. Waiting for upcoming connection...")

# Function to block an IP address using ufw and send a Telegram alert
def block_ip_address(ip_address):
    try:
        # Basic example: block IP using ufw command
        subprocess.run(["ufw", "insert", "1", "deny", "from", ip_address], check=True)
        # Send a Telegram alert
        message = f"This IP address {ip_address} has been blocked."
        send_telegram_message(message)
        subject = "Block IP"
        body = f"{message}"
        send_email_message(subject, body, APP_PASSWORD)
    except Exception as e:
        print(f"Failed to block IP: {ip_address}. Error: {e}")

# Function to analyze outgoing packets
def analyze_packets(packet):
    if IP in packet and TCP in packet:
        dest_ip = packet[IP].dst
        dest_port = packet[TCP].dport

        # Update unique ports for the destination IP
        if dest_ip in unique_ports:
            unique_ports[dest_ip].add(dest_port)
        else:
            unique_ports[dest_ip] = {dest_port}

        # Check if the number of unique ports exceeds the threshold
        if len(unique_ports[dest_ip]) >= UNIQUE_PORT_THRESHOLD:
            src_ip = packet[IP].src
            message = f"There is someone scanning ports for the server, detected to IP: {src_ip}, from unauthorized user. Please check the system whether you want to block it or not"
            send_telegram_message(message)

            # Create the email content
            subject = "Port Scanning Alert"
            body = f"There is someone scanning ports for the server, detected to IP: {src_ip}, from unauthorized user. Please check the system whether you want to block it or not"

            send_email_message(subject, body, APP_PASSWORD)

            # Reset unique ports for the IP
            del unique_ports[dest_ip]
            # Prompt the user for confirmation
            prompt_user(src_ip)

# Start analyzing packets in a separate thread
def packet_capture():
    sniff(prn=analyze_packets, store=0)

# Start packet capture in a separate thread
packet_thread = threading.Thread(target=packet_capture)
packet_thread.start()

# Print the initial message
print("[*] Waiting for upcoming connections")

# Keep the script running
while True:
    pass

#!/usr/bin/env python3
import subprocess
import re
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time  # Import the time module for sleep

TELEGRAM_BOT_TOKEN = "6145984720:AAGYK4M30COAV2e_1Ja9sQOsjr9yiZm4j4g"
TELEGRAM_CHAT_ID = "1307626802"

FAILED_LOGIN_THRESHOLD = 15  # Adjust this threshold as needed

# Log file to monitor
VSFTPD_LOG_FILE = "/var/log/vsftpd.log"

# Regular expression to match failed VSFTPD login attempts
vsftpd_failed_pattern = re.compile(r".* FAIL LOGIN: Client \"::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\"")

SENDER_EMAIL = "sender352023@gmail.com"
APP_PASSWORD = "vdkr jmhl sksn usyf"
SENDER_PASSWORD = "737767010"

RECIPIENT_EMAIL = "alert352023@gmail.com"

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

# Function to send an email
def send_email(subject, body):
    message = MIMEMultipart()
    message["From"] = SENDER_EMAIL
    message["To"] = RECIPIENT_EMAIL
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    # Establish a secure connection with the SMTP server
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, APP_PASSWORD or SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, message.as_string())

# Function to send a notification to Telegram and email
def send_notification(ip_address, alert_count):
    # Send message to Telegram
    telegram_message = f"Possible brute force attack detected in FTP port from IP: {ip_address}. " \
                      f"Alert {alert_count}: Please check the software whether you want to block the IP address or not."
    send_telegram_message(telegram_message)

    # Send email notification
    email_subject = "FTP Brute Force Attack Alert"
    email_body = f"IP: {ip_address}\nAlert Count: {alert_count}\n\n{telegram_message}"

    send_email(email_subject, email_body)

# Function to block an IP address using ufw and send a Telegram alert
def block_ip_address(ip_address):
    try:
        subprocess.run(["ufw", "insert", "1", "deny", "from", ip_address], check=True)
        print(f"Blocked IP: {ip_address} using ufw")
        telegram_message = f"This IP address {ip_address} has been blocked."
        send_telegram_message(telegram_message)
        email_subject = "Block IP"
        email_body = f"{telegram_message}"
        send_email(email_subject, email_body)
    except subprocess.CalledProcessError:
        print(f"Failed to block IP: {ip_address}")

# Function to prompt the user for confirmation
def prompt_user(ip_address, alert_count):
    response = input(f"[*] More than {FAILED_LOGIN_THRESHOLD} failed login attempts from {ip_address} (Alert {alert_count}). Block this IP? (yes/no): ").lower()
    if response == 'yes':
        # Block the IP address using ufw and send a Telegram alert
        block_ip_address(ip_address)
        print("[*] IP blocked. Waiting for upcoming connection...")
        return True  # Return True to indicate that the IP was blocked
    else:
        print("[*] IP not blocked. Waiting for upcoming connection...")
        return False  # Return False to indicate that the IP was not blocked

# Function to clear the failed login attempts data
def clear_failed_attempts():
    return {}

# Function to monitor VSFTPD log file for new login attempts
def monitor_vsftpd_log():
    try:
        log_file = subprocess.Popen(["tail", "-n", "0", "-f", VSFTPD_LOG_FILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        failed_login_attempts = clear_failed_attempts()  # Initialize or clear failed login attempts
        alert_count = 1  # Initialize alert count

        while True:
            line = log_file.stdout.readline()
            match = vsftpd_failed_pattern.match(line)

            if match:
                ip_address = match.group(1)

                if ip_address not in failed_login_attempts:
                    failed_login_attempts[ip_address] = 1
                else:
                    failed_login_attempts[ip_address] += 1

                if failed_login_attempts[ip_address] >= FAILED_LOGIN_THRESHOLD:
                    # Send notification to Telegram and email
                    send_notification(ip_address, alert_count)

                    # Prompt the user for confirmation
                    if prompt_user(ip_address, alert_count):
                        # Clear the failed login attempts after blocking the IP
                        failed_login_attempts = clear_failed_attempts()

                        # Continue monitoring without resetting the alert count
                        continue

                    # Increment the alert count
                    alert_count += 1
                    failed_login_attempts[ip_address] = 0  # Reset the counter

            # Sleep for a short duration to avoid high CPU usage
            time.sleep(0)

    except FileNotFoundError:
        print(f"VSFTPD log file not found: {VSFTPD_LOG_FILE}")
        exit(1)

if __name__ == "__main__":
    print("[*] Waiting for upcoming connections")  # Print this line to indicate waiting
    monitor_vsftpd_log()

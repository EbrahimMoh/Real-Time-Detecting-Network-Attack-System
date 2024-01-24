import re
import subprocess
import requests
import urllib.parse
import time
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

php_log_file = '/var/log/apache2/error.log'

telegram_bot_token = '6145984720:AAGYK4M30COAV2e_1Ja9sQOsjr9yiZm4j4g' 
telegram_chat_id = '1307626802' 

sender_email = "sender352023@gmail.com"
app_password = "vdkr jmhl sksn usyf"  
sender_password = "737767010"  

recipient_email = "alert352023@gmail.com"

# Regular expression pattern to match potential URL-encoded SQL injection attempts
sql_injection_pattern = r"\\' OR 1=1 --"

# Function to send a notification via Telegram
def send_telegram_notification(message):
    url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage'
    data = {
        'chat_id': telegram_chat_id,
        'text': message
    }
    requests.post(url, data=data)

# Function to send an email notification
def send_email_notification(subject, body):
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    # Establish a secure connection with the SMTP server
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, app_password or sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())

# Function to block an IP address using ufw
def block_ip_address(ip_address):
    try:
        # Basic example: block IP using ufw command
        subprocess.run(["ufw", "insert", "1", "deny", "from", ip_address], check=True)
        print(f"Blocked IP address: {ip_address} using ufw.")
        telegram_message = f"This IP address {ip_address} has been blocked."
        send_telegram_notification(telegram_message)
        subject = "Block IP"
        body = f"{telegram_message}"
        send_email_notification(subject, body)
        print("[*] IP blocked. Waiting for upcoming connection...")
    except Exception as e:
        print(f"Failed to block IP: {ip_address} using ufw. Error: {e}")

# Function to monitor the log file for potential SQL injection attempts
def monitor_log_file():
    last_position = 0
    try:
        last_position = os.path.getsize(php_log_file)
    except os.error:
        pass

    while True:
        try:
            current_position = os.path.getsize(php_log_file)
            if current_position > last_position:
                with open(php_log_file, 'r') as file:
                    file.seek(last_position)
                    for line in file:
                        decoded_line = urllib.parse.unquote(line)
                        if re.search(sql_injection_pattern, decoded_line):
                            # Extract the IP address from the log entry (modify this based on your log format)
                            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                            if ip_match:
                                ip_address = ip_match.group()
                                message = f"Potential SQL Injection Attempt Detected from IP address: {ip_address}"
                                send_telegram_notification(message)

                                # Create the email content
                                subject = "SQL injection Attack Alert"
                                body = f"Potential SQL Injection Attempt Detected from IP address: {ip_address}"
                                send_email_notification(subject, body)

                                # Prompt the user
                                user_response = input(f"Potential SQL Injection Attempt Detected from IP {ip_address}. Do you want to block the IP? (yes/no): ").lower()
                                if user_response == 'yes':
                                    block_ip_address(ip_address)

                last_position = current_position

        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"An error occurred: {str(e)}")

        time.sleep(0)

if __name__ == "__main__":
    while True:
        print("[*] Waiting for upcoming connections")  # Print this line to indicate waiting
        monitor_log_file()

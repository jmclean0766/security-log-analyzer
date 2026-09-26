#Log Analyzer Project


import sys
import csv
from datetime import datetime, timedelta


threshold = 3
time_window = timedelta(minutes=2)
date_format = "%Y-%m-%d %H:%M:%S"

def main():
    if len(sys.argv) < 2:
        sys.exit("Missing Input and Output File Names")
    elif len(sys.argv) == 2:
        sys.exit("Missing Output File Name")
    elif len(sys.argv) > 3:
        sys.exit("Too Many Arguments")
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    logs = load_logs(input_file)
    failed_attempts = collect_failed_attempts(logs)
    bruteforce_alerts = detect_bruteforce(failed_attempts)
    password_spray_alerts = detect_password_spray(failed_attempts)
    if not bruteforce_alerts and not password_spray_alerts:
        print("No suspicious activity detected")
    else:
        if bruteforce_alerts:
            generate_bruteforce_report(bruteforce_alerts)
            save_bruteforce_alerts(bruteforce_alerts, output_file)
        if password_spray_alerts:
            generate_password_spray_report(password_spray_alerts)
            save_password_spray_alerts(password_spray_alerts, output_file)


def load_logs(input_file):
    logs = []
    with open(input_file) as file:
        reader = csv.DictReader(file)
        for row in reader:
            logs.append(row)

    return logs


def collect_failed_attempts(logs):
    failed_attempts = {}
    for log in logs:
        if log["event_type"] == 'FAILED_LOGIN':
            ip = log["ip_address"]
            timestamp = log["timestamp"]
            username = log["username"]

            if ip not in failed_attempts:
                timestamps = []
                usernames = {username}
                failed_attempts[ip] = {"count": 1, "timestamps": timestamps, "usernames": usernames}
                failed_attempts[ip]["timestamps"].append(timestamp)
            else:
                failed_attempts[ip]["count"] += 1
                failed_attempts[ip]["timestamps"].append(timestamp)
                failed_attempts[ip]["usernames"].add(username)

    return failed_attempts


def detect_password_spray(failed_attempts):
    password_spray_alerts = {}
    for ip in failed_attempts:
        if len(failed_attempts[ip]["usernames"]) > 1:
            ip_timestamps = failed_attempts[ip]["timestamps"]
            ip_count = failed_attempts[ip]["count"]
            ip_usernames = failed_attempts[ip]["usernames"]
            password_spray_alerts[ip] = {"timestamps": ip_timestamps, "count": ip_count, "usernames": ip_usernames}

    return password_spray_alerts


def detect_bruteforce(failed_attempts):
    bruteforce_alerts = {}
    for ip in failed_attempts:
        if failed_attempts[ip]["count"] >= threshold:
            alert_found = False
            ip_timestamps = failed_attempts[ip]["timestamps"]
            converted_times = []
    
            for ip_timestamp in ip_timestamps:
                converted_times.append(datetime.strptime(ip_timestamp, date_format))
            converted_times.sort()
                
            for index, start_time in enumerate(converted_times):
                counter = 1
                window = [datetime.strftime(start_time, date_format)]

                for check_time in converted_times[index+1:]:
                    difference = check_time - start_time
                    if difference <= time_window:
                        counter += 1
                        window.append(datetime.strftime(check_time, date_format))
                        if counter >= threshold:
                            alert_found = True
                            break
    
                if alert_found:
                    break
            if alert_found:
                bruteforce_alerts[ip] = { "window_count": counter, "timestamps": window}

    return bruteforce_alerts


def generate_bruteforce_report(bruteforce_alerts):
    print(" \n\n -----BRUTE FORCE REPORT----- \n\n ")
    for ip, details in bruteforce_alerts.items():
        print(f" Suspicious IP: {ip}\n  Suspicious Login Attempts: {details['window_count']}\n Time Window: {time_window.total_seconds() / 60:g} minutes\n Timestamps: {details['timestamps']}\n\n")


def generate_password_spray_report(password_spray_alerts):
    print(" \n\n -----PASSWORD SPRAY REPORT----- \n\n ")
    for ip, details in password_spray_alerts.items():
        print(f" Suspicious IP: {ip}\n Targeted Users: {details['usernames']}\n Suspicious Login Attempts: {details['count']}\n Timestamps: {details['timestamps']}\n\n")


def save_bruteforce_alerts(bruteforce_alerts, output_file):
    with open(output_file, "a") as file:
        file.write(" \n\n -----BRUTE FORCE REPORT----- \n\n ")
        for ip, details in bruteforce_alerts.items():
            file.write(f" Suspicious IP: {ip}\n  Suspicious Login Attempts: {details['window_count']}\n Time Window: {time_window.total_seconds() / 60:g} minutes\n Timestamps: {details['timestamps']}\n\n")


def save_password_spray_alerts(password_spray_alerts, output_file):
    with open(output_file, "a") as file:
        file.write(" \n\n -----PASSWORD SPRAY REPORT----- \n\n ")
        for ip, details in password_spray_alerts.items():
            file.write(f" Suspicious IP: {ip}\n Targeted Users: {details['usernames']}\n Suspicious Login Attempts: {details['count']}\n Timestamps: {details['timestamps']}\n\n")


if __name__ == "__main__":
    main()

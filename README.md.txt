# Security Log Analyzer

A Python command-line tool that analyzes authentication logs and detects potentially suspicious login activity.

## Features

- Detects potential brute-force login attempts
- Detects potential password-spraying activity
- Reports suspicious activity to the console
- Saves alerts to a text file

### Detection Rules

**Brute Force**
- 3 or more failed login attempts from the same IP
- Within a 2-minute window

**Password Spray**
- Failed login attempts from the same IP
- Against multiple usernames

## Usage

```bash
python3 analyzer.py <input_file> <output_file>
```

Example:

```bash
python3 analyzer.py sample_logs.csv alerts.txt
```

## Input Format

The tool expects a CSV file with the following columns:

```text
timestamp,username,event_type,ip_address
```

Example:

```text
2026-08-02 12:01:22,john,FAILED_LOGIN,192.168.1.50
```

## Technologies

- Python 3
- CSV processing
- `datetime`
- Command-line arguments

## Project Purpose

A hands-on Python cybersecurity project focused on security log analysis, detection logic, and security automation.
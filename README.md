# Python Network Port Scanner

A lightweight TCP port scanner written in Python for cybersecurity learning,
network troubleshooting, and authorized security testing.

## Features

- TCP connect scanning
- Hostname/IP resolution
- Custom ports and port ranges
- Concurrent scanning with a thread pool
- Common service-name identification
- Input validation
- Unit tests

## Requirements

- Python 3.9+
- No third-party packages required

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/network-port-scanner.git
cd network-port-scanner
```

## Usage

Scan common ports:

```bash
python src/scanner.py 127.0.0.1
```

Scan selected ports:

```bash
python src/scanner.py 127.0.0.1 -p 22,80,443
```

Scan a range:

```bash
python src/scanner.py 127.0.0.1 -p 1-100
```

Adjust timeout/workers:

```bash
python src/scanner.py 127.0.0.1 -p 1-1000 --timeout 0.3 --workers 50
```

## Example Output

```text
Target: localhost (127.0.0.1)
Scanning 3 TCP port(s)...

OPEN PORT   SERVICE
----------------------------
22          SSH
80          HTTP
443         HTTPS
```

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Project Structure

```text
network-port-scanner/
├── src/
│   └── scanner.py
├── tests/
│   └── test_scanner.py
├── screenshots/
├── README.md
├── requirements.txt
├── .gitignore
└── LICENSE
```

## Security / Ethical Use

Only scan computers, devices, and networks that you own or have explicit
permission to test. Unauthorized port scanning may violate policies or laws.

## Learning Objectives

This project demonstrates:

- TCP sockets
- IP/hostname resolution
- Port and service concepts
- Concurrent programming
- Exception handling
- Input validation
- Basic cybersecurity tooling

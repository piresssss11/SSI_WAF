# Python Web Application Firewall (WAF)

This project implements a **Web Application Firewall (WAF)** using the **Flask** framework to protect web applications from common attacks such as SQL Injection, XSS, Path Traversal, and more.

## Features

- **SQL Injection Protection**: Blocks attempts to manipulate SQL queries.
- **XSS Protection**: Prevents malicious JavaScript code from being injected into input fields.
- **Path Traversal Protection**: Prevents unauthorized access to system files.
- **DDoS Protection**: Limits the number of requests per second.
- **IP List**: Allows defining allowed (whitelist) and blocked (blacklist) IPs.
- **Attack Logs**: Records attack attempts for future analysis.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourname/SSI_WAF.git
    ```

2. Install the dependencies:
    pip install Flask Flask-Limiter


3. Start the server:
    ```bash
    python waf_server.py
    ```

## How to Use

- Access the application at `http://localhost:8080`.
- The WAF will automatically check all incoming requests for malicious patterns and protect the application.

## Technologies Used

- **Python**: Programming language.
- **Flask**: Web framework for building the application.
- **Flask-Limiter**: Rate limiting to prevent DDoS attacks.
- **Regex**: Used to detect malicious patterns.


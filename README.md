# SafeScan
Websites Vulnerability Scanner

Vulnerability Scanner is a comprehensive tool designed to help you identify and address security vulnerabilities in your web applications. Enter a URL, and let our scanner provide detailed insights into potential security issues, such as missing security headers, XSS vulnerabilities, SQL injection vulnerabilities, CSRF vulnerabilities, open redirects, and directory enumeration.

## Features

- **Scan for XSS vulnerabilities**
- **Scan for SQL Injection vulnerabilities**
- **Scan for CSRF vulnerabilities**
- **Check for missing security headers**
- **Check for open redirects**
- **Check for directory enumeration**
- **Analyze robots.txt for interesting URLs**

## Technologies Used

- Python
- Flask
- HTML/CSS
- JavaScript

## Installation

1. **Clone the repository**
   ```sh
   git clone
   cd SafeScan

2. **Create a virtual environment and activate it**
   ```sh
   pip install virtualenv
   virtualenv env
   .\env\Scripts\activate.bat
   # On Linux use `source env/bin/activate`

4. **Install the required packages**
   ```sh
   pip install -r requirements.txt

## Usage

1. **Run the Flask application**
   ```sh
   python app.py

3. **Open your web browser and navigate to**
   ```sh
   http://127.0.0.1:5000/

5. **Enter the URL you want to scan and click "Scan"**

6. **View the results and the recommended precautions**

## Project Structure
```sh
vulnerability-scanner/
│
├── static/
│   ├── css/
│   │   ├── index.css
│   │   ├── result.css
│   ├── images/
│   │   ├── logo.jpg
│   │   ├── background.jpg
│
├── templates/
│   ├── index.html
│   ├── result.html
│
├── app.py
├── requirements.txt
├── README.md

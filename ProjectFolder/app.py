from flask import Flask, request, render_template
import requests

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    if not url.startswith('http'):
        url = 'http://' + url

    results = {
        'xss': check_xss(url),
        'sql': check_sql_injection(url),
        'csrf': check_csrf(url),
        'robots': analyze_robots(url),
        'security_headers': check_security_headers(url),
        'open_redirect': check_for_open_redirect(url),
        'directory_enumeration': check_for_directory_enumeration(url)
    }
    return render_template('result.html', url=url, results=results)


def check_xss(url):
    test_script = "<script>alert('XSS');</script>"
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        xss_vulnerable_forms = []
        for form in forms:
            form_action = form.get('action')
            form_method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_data = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    if input_type == 'text':
                        form_data[input_name] = test_script
                    else:
                        form_data[input_name] = 'test'
            if form_action:
                action_url = urljoin(url, form_action)
            else:
                action_url = url
            if form_method == 'post':
                response = requests.post(action_url, data=form_data)
            else:
                response = requests.get(action_url, params=form_data)
            if test_script in response.text:
                xss_vulnerable_forms.append(action_url)
        return xss_vulnerable_forms
    except requests.RequestException:
        return []


def check_sql_injection(url):
    test_sql = "' OR '1'='1"
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        sql_vulnerable_forms = []
        for form in forms:
            form_action = form.get('action')
            form_method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_data = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    if input_type == 'text':
                        form_data[input_name] = test_sql
                    else:
                        form_data[input_name] = 'test'
            if form_action:
                action_url = urljoin(url, form_action)
            else:
                action_url = url
            if form_method == 'post':
                response = requests.post(action_url, data=form_data)
            else:
                response = requests.get(action_url, params=form_data)
            if "mysql" in response.text.lower() or "syntax error" in response.text.lower():
                sql_vulnerable_forms.append(action_url)
        return sql_vulnerable_forms
    except requests.RequestException:
        return []


def check_csrf(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        csrf_vulnerable_forms = []
        for form in forms:
            inputs = form.find_all('input')
            has_csrf_token = any('csrf' in input_tag.get('name', '').lower() for input_tag in inputs)
            if not has_csrf_token:
                csrf_vulnerable_forms.append(form)
        return csrf_vulnerable_forms
    except requests.RequestException:
        return []


def analyze_robots(url):
    robots_url = url + '/robots.txt'
    try:
        response = requests.get(robots_url)
        response.raise_for_status()
        robots_content = response.text
        interesting_urls = []
        for line in robots_content.split('\n'):
            if line.strip().lower().startswith('disallow'):
                parts = line.split(':')
                if len(parts) > 1:
                    path = parts[1].strip()
                    if path:
                        interesting_urls.append(urljoin(url, path))
        return interesting_urls
    except requests.RequestException:
        return []


def check_security_headers(url):
    headers_to_check = {
        'Content-Security-Policy': 'The Content-Security-Policy (CSP) header helps to protect against Cross-Site Scripting (XSS) and other attacks. It allows you to define which dynamic resources are allowed to load.',
        'X-Content-Type-Options': 'The X-Content-Type-Options header prevents browsers from interpreting files as a different MIME type than what is specified in the Content-Type header.',
        'X-Frame-Options': 'The X-Frame-Options header protects against Clickjacking attacks by controlling whether the browser should allow a page to be displayed in an iframe.',
        'Strict-Transport-Security': 'The Strict-Transport-Security header ensures that browsers only connect to your site using HTTPS.',
        'X-XSS-Protection': 'The X-XSS-Protection header enables the cross-site scripting (XSS) filter built into most browsers.',
        'Referrer-Policy': 'The Referrer-Policy header controls how much referrer information should be included with requests.'
    }
    missing_headers = {}
    try:
        response = requests.get(url)
        for header, description in headers_to_check.items():
            if header not in response.headers:
                missing_headers[header] = description
        return missing_headers
    except requests.RequestException:
        return {}


def check_for_open_redirect(url):
    test_redirect = 'http://example.com'
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        open_redirect_vulnerable_forms = []
        for form in forms:
            form_action = form.get('action')
            form_method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_data = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                if input_name and 'url' in input_name.lower():
                    form_data[input_name] = test_redirect
            if form_data:
                if form_action:
                    action_url = urljoin(url, form_action)
                else:
                    action_url = url
                if form_method == 'post':
                    response = requests.post(action_url, data=form_data, allow_redirects=False)
                else:
                    response = requests.get(action_url, params=form_data, allow_redirects=False)
                if response.status_code in (301, 302) and response.headers.get('Location') == test_redirect:
                    open_redirect_vulnerable_forms.append(action_url)
        return open_redirect_vulnerable_forms
    except requests.RequestException:
        return []


def check_for_directory_enumeration(url):
    common_directories = [
        'admin/', 'backup/', 'config/', 'db/', 'includes/', 'uploads/', 'logs/'
    ]
    directory_enumeration_vulnerabilities = []
    for directory in common_directories:
        check_url = urljoin(url, directory)
        try:
            response = requests.get(check_url)
            if response.status_code == 200:
                directory_enumeration_vulnerabilities.append(check_url)
        except requests.RequestException:
            continue
    return directory_enumeration_vulnerabilities


if __name__ == '__main__':
    app.run(debug=True)

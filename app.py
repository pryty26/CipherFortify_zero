
import logging
import secrets
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import os
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
from requests_functions import simple_request
from all_functions import login_check, verify_the_password, commonplace_text, white_ip_check, add_user
from datetime import datetime
from logging.handlers import RotatingFileHandler
from functools import wraps

print('import ready')

def cookies_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('cookies_accept'):
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
#Set secret key

handler = RotatingFileHandler(
    'honeypot.log',
    maxBytes=10*1024*1024,
    backupCount=3
)

logging.basicConfig(
    level=logging.WARNING,
    format = '%(asctime)s - %(message)s',
    handlers=[handler]
)


limiter = Limiter(
    app = app,
    key_func = get_remote_address,
    default_limits = ['3600 per minute']
)

@app.route('/')
#The home of website
@limiter.limit('80 per minute, 300 per hour')
def web_home():
    return render_template('home.html')

@app.route('/cookies', methods=['GET'])
@limiter.limit('10 per minute,100 per hour')
def cookies():
    return render_template('cookies.html')


@app.route('/accept-cookies', methods=['POST'])
def accept_cookies():
    accept_type = request.form.get('accept_type')
    session['cookies_accept'] = True
    session['cookies_form'] = accept_type
    return redirect('/register')

@app.route('/admin/login', methods=['GET', 'POST'])
#honeypot!!!!!!!!!!!!!!!!!!!!!!!
def admin_login_page_advanced():
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    logging.warning(f"Advanced admin page accessed - IP: {client_ip} | Time: {current_time} | UA: {user_agent}")

    if request.method == 'POST':
        ad_username = request.form.get('ad_username')
        ad_password = request.form.get('ad_password')
        if ad_username and ad_password:
            logging.warning(
                f"Login attempt on advanced admin - IP: {client_ip} | Username: {ad_username} | Password: {ad_password}")
        return render_template('JEESUS.html')  # Good karma +999(yeah!)!!!

    return render_template('admin_login.html')


@app.route('/register', methods=['POST', 'GET'])
@limiter.limit('5 per minute, 30 per hour')
@cookies_check
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')


        result = add_user(username, password)
        success_value = result.get('success')

        if success_value is True or success_value == "True":
            session['user_id'] = secrets.token_hex(32)
            session['username'] = f'{username}'
            session['login_time'] = time.time()
            return redirect('/home')
        elif result.get('success') == 'warning':
            return render_template('register.html', message=result.get('message','Illegal username'))

        else:
            return render_template('register.html', message=result.get('message', 'Registration failed'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@cookies_check
@limiter.limit('15 per minute,200 per hour')
def login_page():

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # check the password
        result = verify_the_password(username, password)
        success_value = result.get('success')
        if success_value is True or success_value == "True":
            session['user_id'] = secrets.token_hex(32)
            session['username'] = f'{username}'
            session['login_time'] = time.time()
            return redirect('/home')
        elif result.get('success') == 'warning':
            logging.warning(f'The IP:{request.remote_addr} is{result.get('message')}')
            return redirect('/admin/login')
        else:
            return render_template('login.html', message="Login False")

    return render_template('login.html')  # This line needs to be the last one

@app.route('/home', methods=['GET','POST'])
@cookies_check
@login_check
@limiter.limit('15 per minute,200 per hour')
def home():
    return render_template('main.html')


def main():
    print("🚀 启动 Flask 服务器 (使用 Waitress)...")
    print("📍 访问地址: http://localhost:8080")
    print("📍 局域网访问: http://你的IP:8080")
    print("⏹️  按 Ctrl+C 停止服务器\n")

    try:
        from waitress import serve
        serve(app, host='0.0.0.0', port=8080, threads=4)

    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")
    except Exception as e:
        print(f"❌ 启动失败: {e}")


if __name__ == '__main__':
    main()
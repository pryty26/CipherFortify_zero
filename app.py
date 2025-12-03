
import logging
import secrets as sec #huom！！！！！！！！！！！！！！！！！
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import os
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
from requests_functions import simple_request
from all_functions import login_check, verify_the_password, commonplace_text, white_ip_check, add_user, check_password
from datetime import datetime
from logging.handlers import RotatingFileHandler
from functools import wraps
from user_secrets import secrets_encrypt, secrets_decrypt, find_all_name, make_secrets, delete_secrets
import html
import string
print('import ready')

def cookies_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('cookies_accept'):
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

def generatePassword(length:int):
    alphabet = string.ascii_letters + string.digits + "!@#$^?"
    password = ''.join(sec.choice(alphabet) for _ in range(length))
    return password

app = Flask(__name__)





app.secret_key = os.environ.get('FLASK_SECRET_KEY', sec.token_hex(32))
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
    default_limits = ['3600 per minute'],
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
            session['user_id'] = sec.token_hex(32)
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
@limiter.limit('10 per minute,60 per hour')
def login_page():
#def verify_the_password(username:str,password:str) -> dict[str, any]:
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # check the password
        result = verify_the_password(username, password)
        success_value = result.get('success')
        if success_value is True or success_value == "True":
            session['user_id'] = sec.token_hex(32)
            session['username'] = f'{username}'
            session['login_time'] = time.time()
            return redirect('/home')
        elif result.get('success') == 'warning':
            print(f"The IP:{request.remote_addr} is {result.get('message')}")
            logging.warning(f'The IP:{request.remote_addr} is{result.get('message')}')
            return redirect('/admin/login')
        else:
            return render_template('login.html', message="Login False")

    return render_template('login.html')  # This line needs to be the last one

@app.route('/home', methods=['GET','POST'])
@cookies_check
@login_check
@limiter.limit('15 per minute,150 per hour')
def home():
    return render_template('main.html')

@app.route('/tips', methods=['GET','POST'])
@cookies_check
@login_check
@limiter.limit('10 per minute, 100 per hour')
def tips():
    return render_template('tips.html')




@app.route('/delete_secrets',methods=['GET','POST'])
@cookies_check
@login_check
@limiter.limit('10 per minute, 50 per hour')
def delete_secrets():
    username = session.get('username')
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        user_input = request.form.get('user_input')
        result = delete_secrets(username,password,name,user_input)
        return render_template('delete_secrets.html',
                               message=result.get('message','error'),
                               message_type='success' if result.get('success') else 'error')
    #def delete_secrets(username:str,password:str , name:str, user_input:str) -> dict:

    return render_template('delete_secrets.html')


@app.route('/secrets', methods=['GET', 'POST'])
@cookies_check
@login_check
@limiter.limit('10 per minute, 100 per hour')
def secrets_page():
    username = session.get('username')

    if request.method == 'POST':
        action = request.form.get('action')
        # From fronttend get action


        if action == 'encrypt':
            name = request.form.get('name')
            password = request.form.get('password')
            the_secrets = request.form.get('the_secrets')
            result = secrets_encrypt(username, password, the_secrets, name)

            return render_template('secrets.html',
                                   message=result.get('message'),
                                   message_type='success' if result.get('success') else 'error')

        elif action == 'decrypt':
            crsf_token = "pryty26"
            if crsf_token != request.form.get('csrf_token',None):
                logging.warning(f'Crsf attack!!! IP:{request.remote_addr},Username:{session['username']} UA:{request.headers.get('user-agent',None)}')
                return render_template('secrets.html',
                                       decrypt_result='Error',
                                       decrypt_name='Error')
            name = request.form.get('name',None)
            password = request.form.get('password')

            name = html.escape(name)
            result = secrets_decrypt(username, password, name)
            success = result.get('success')
            if success == 'warning':
                return render_template('secrets.html',
                                   decrypt_result=result.get('message'),
                                   decrypt_name='None')
            return render_template('secrets.html',
                                   decrypt_result=result.get('message'),
                                   decrypt_name=name,
                                   message_type=success)

        elif action == 'search':
            user_input = request.form.get('search_input')
            result = find_all_name(username, user_input)
            search_result = result.get('message')
            if search_result:
                success = result.get('success')
                if success == 'warning':
                    return render_template('secrets.html',
                                           decrypt_result=result.get('message'),
                                           decrypt_input='None')
                return render_template('secrets.html',
                                       search_result=search_result,
                                       search_input=html.escape(user_input),
                                       message_type=result.get('success'))
            else:
                search_result = 'You have not encrypt any data'
                return render_template('secrets.html',
                                       search_result=search_result,
                                       search_input=user_input,
                                       message_type=result.get('success'))
    return render_template('secrets.html')

@app.route('/admin', methods=['GET'])
@limiter.limit('5 per minute, 10 per hour')
def honey_admin():
    logging.warning(f"The IP:{request.remote_addr} and UA: {request.headers.get('user-agent'),'UA is None'} is on admin page")
    return render_template('honeystars.html')
@app.route('/password_tools', methods=['GET', 'POST'])
@cookies_check
@login_check
@limiter.limit('20 per minute, 300 per hour')
def password_tools():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'generate':
            try:
                length = int(request.form.get('password_length', 12))
            except (ValueError,TypeError):
                return render_template('password_tools.html',
                                       generated_password='Length must to be a number')
            generated_password = generatePassword(length)
            return render_template('password_tools.html',
                                   generated_password=generated_password)

        elif action == 'check':
            password = request.form.get('password_to_check')
            password = html.escape(password)
            result = check_password(password)

            return render_template('password_tools.html',
                                   strength_result=True,
                                   strength_class=result.get('message', ''), strength_message=result.get('message', ''))

    return render_template('password_tools.html')


def main():
    print("🚀 启动 Flask 服务器 (使用 Waitress)...")
    print("📍 访问地址: http://localhost:8080")
    print("📍 局域网访问: http://192.168.1.113:8080")
    print("⏹️  按 Ctrl+C 停止服务器\n")

    try:
        from waitress import serve
        serve(app,
              host='0.0.0.0',
              port=8080,
              threads=8,  # 增加线程数
              connection_limit=1000,  # 增加连接限制
              asyncore_loop_timeout=1,  # 减少超时
              channel_timeout=60)  # 增加通道超时

    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")
    except Exception as e:
        print(f"❌ 启动失败: {e}")


if __name__ == '__main__':
    main()
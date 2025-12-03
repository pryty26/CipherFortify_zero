import logging
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import random
import secrets
import time
from functools import wraps
from pygments.lexer import default
from scapy.all import *
import re
import sqlite3
import hashlib
import secrets
from tkinter.constants import INSERT
from flask import request
import html
import requests
import hmac





def login_check(f):# Functions to check if the user is logged in
    @wraps(f)
    def decorated_function(*args, **kwargs):    # save the state
        if 'user_id' not in session or 'username' not in session:# If user is logged in, userid should be in session;so,otherwise redirect to login page
            return redirect(url_for('login_page'))

        #check session timeout
        if 'login_time' not in session or time.time() - session['login_time'] > 18000:  #about 5 hours,if session is timeout redirect to login page
            accept_type = session.get('accept_type')
            cookies_accept = session.get('cookies_accept')
            session.clear()
            session['cookies_accept'] = cookies_accept
            session['cookies_form'] = accept_type
            return redirect(url_for('login_page'))

        return f(*args, **kwargs)   # if user had login, then return the saved state

    return decorated_function



def commonplace_text(world):
    #make user input beter! exemple:
    # userinput = sql Attack_tools ---> sqlattacktools
    if world:
        return world.lower().strip().replace(' ','').replace('_','')
    else:
        return ''


#white ip list check
def white_ip_check(f):
    @wraps(f)
    def decorated_functions(*args, **kwargs):
        white_list = ['127.0.0.1']
        user_ip = request.remote_addr
        if user_ip not in white_list:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_functions

class safe_waf:
    def __init__(self):
        self.simple_sql = [
            "1' or '1'='1", "1' and '1'='1", "1' or '1'='2",
            "1' UNION SELECT table_name,2,3 FROM information_schema.tables --",
            "1' UNION SELECT column_name,2,3 FROM information_schema.columns --"
                      ]

        self.sql_prefixes = ['1"', "1'", "'", '"', '%27', '1\'', '\'']
        self.simple_xss = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src='javascript:alert('XSS')'>"
        ]
        self.xss_prefixes = [
            '<script', '<iframe', '<img', '<svg', '<div', '<a', '<input', '<body', '<embed', '<object', '<video', '<audio',
         '<style'
        ]

    def sql_check(self,sql:str):
        try:
            #I had used Parameterized Query and html.escape so the waf is just warning
            rules = [
                lambda s: re.search(r"union|select|from", s, re.IGNORECASE) and re.search(r'from|select', s, re.IGNORECASE),

                lambda s: re.search(r"=|%|&|.+\|.+|--|>|<|\*|sleep", s, re.IGNORECASE)
            ]
            for rule in rules:
                if rule(sql):
                    return {'success':'warning','type':'sql'}

            return{'success':'normal','type':'sql'}

        except re.error as e:
            logging.error(f'sql re error{e}')
            return {'success':'error', 'type': 'error', 'message':f'sql re error:{e}'}
        except Exception as e:
            logging.error(f'sql check error{e}')
            return {'success':'error', 'type': 'error', 'message':f'sql error:{e}'}
    def xss_check(self,xss:str):
        try:
            xss_rules = [
                lambda s: s.endswith('>') and re.search(r"<", s, re.IGNORECASE),
                lambda s:re.search(
                    r"onerror=alert\(|href=\alert|onload=alert\(|javascript:alert\(|vbscript:msgbox\(|alert\(document\.cookie\)|prompt\(document\.domain\)", s, re.IGNORECASE)
            ]

            for xss_rule in xss_rules:
                if xss_rule(xss):
                    return {'success': 'warning', 'type': 'xss'}
            return {'success': 'normal', 'type': 'xss'}
        except re.error as e:
            logging.error(f'xss check re error{e}')
            return {'success':'error', 'type': 'error', 'message':f'xss re error:{e}'}
        except Exception as e:
            logging.error(f'xss check error{e}')
            return {'success':'error', 'type': 'error', 'message':f'xss error:{e}'}


    def all_check(self,user_input):
        try:
            xss_result = self.xss_check(user_input)
            sql_result = self.sql_check(user_input)


            if xss_result['success'] == 'warning' or sql_result['success'] == 'warning':

                attack_types = []
                if xss_result['success'] == 'warning':
                    attack_types.append('xss')
                if sql_result['success'] == 'warning':
                    attack_types.append('sql')

                return {
                    'success': 'warning',
                    'attack_types': attack_types,
                    'details': {
                        'xss': xss_result,
                        'sql': sql_result
                    }
                }

            elif xss_result['success'] == 'error' or sql_result['success'] == 'error':
                return{'success':'error','details':{'xss':xss_result,'sql':sql_result}}
            return{'success':'normal','type':'normal'}
        except Exception as e:
            return{'success':'error','details':{'type':'妈的(误！我赌你不懂中文)……In all_check error','message':f'all_check error:{e}'}}
    #道爷我成了!!!

waf = safe_waf()


def simple_create_sql():
    conn = sqlite3.connect('all_data.db')
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                salt TEXT,
                hashed_password TEXT
            )
        ''')

        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_name ON users (name)')  #magic!!!


        print('sqlite3 ready')
    except Exception as e:
        print(f"sqlite create error:{e}")


    conn.commit()
    conn.close()
simple_create_sql()

def add_user(username:str, password:str)->dict[str,any]:
    conn = None
    try:
        sql_check_result = waf.sql_check(username)
        xss_check_result = waf.xss_check(username)

        safe_username = html.escape(username)
        if sql_check_result.get('success') == 'warning':
            if xss_check_result.get('success') == 'warning':
                logging.warning(f'The IP:{request.remote_addr} is using sql injection, and xss injection!We have did the html escape he used:{safe_username}')

                return {'success': False,'message': 'Username contains special characters, please choose a different one'}

            logging.warning(f'The IP:{request.remote_addr} is using sql injection,He used {safe_username}')

            return {'success':False,'message':'Username contains special characters, please choose a different one'}


        elif xss_check_result.get('success') == 'warning':
            logging.warning(f'The IP:{request.remote_addr} is using xss injection,He used {safe_username}')

            return {'success': 'warning', 'message': 'the user is using xss injection!'}

        conn = sqlite3.connect('all_data.db')
        cursor = conn.cursor()
        salt = secrets.token_hex(16)
        add_hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()

        cursor.execute(
            "INSERT INTO users (name, salt, hashed_password) VALUES (?,?,?)",
            (safe_username, salt , add_hashed_password)
        )
        conn.commit()
        return {'success':True, 'message':'User added successfully'}
    except sqlite3.IntegrityError:
        return {'success':False,'message':'Username already exist'}
    except Exception as e:
        logging.error(f'register error:{e}')
        return {'success':False,'message':'error'}
    finally:
        if conn:
            conn.close()

def time_delay(start_time):
    try:
        delay = time.time() - start_time
        if delay < 0.8:
            time.sleep(0.8 - delay)
    except Exception as e:
        pass

def verify_the_password(username:str,password:str) -> dict[str, any]:
    try:
        start_time = time.time()
        conn = None

        sql_check_result = waf.sql_check(username)
        xss_check_result = waf.xss_check(username)

        safe_username = html.escape(username)
        if sql_check_result.get('success') == 'warning':
            if xss_check_result.get('success') == 'warning':
                logging.warning(f'The IP:{request.remote_addr} is using sql injection, and xss injection!We have did the html escape he used:{safe_username}')
                return{'success':'warning','message':'the user is using sql injection, and xss injection!'}
            logging.warning(f'The IP:{request.remote_addr} is using sql injection,He used {safe_username}')
            return {'success': 'warning', 'message': 'the user is using sql injection!'}
        elif xss_check_result.get('success') == 'warning':
            logging.warning(f'The IP:{request.remote_addr} is using xss injection,He used {safe_username}')
            return {'success': 'warning', 'message': 'the user is using xss injection!'}

        conn = sqlite3.connect('all_data.db')
        the_cursor = conn.cursor()
        cursor = the_cursor.execute('SELECT salt, hashed_password FROM users WHERE name = ?',
                              (safe_username,))
        user_item = cursor.fetchone()
        if user_item is None:
            time_delay(start_time)
            return {'success': False, 'message': 'username or password is wrong'}
        salt = user_item[0]
        stored_hashed_password = user_item[1]

        input_hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()

        password_correct = hmac.compare_digest(input_hashed_password, stored_hashed_password)

        if password_correct:
            #no delay in success because……he success! its no matter that has there any delay if he success= he know pass and username
            #if username is wrong we wont verify the pass so we dont need more delay in there
            return {'success': True, 'message': f'user:{safe_username}Login success!'}
        time_delay(start_time)
        return{'success':False, 'message':'username or password is wrong'}

    except sqlite3.OperationalError as e:
        logging.error(f'Database error during login: {e}')
        return {'success':False,'message':'System error, please try again later'}

    except TypeError as e:
        logging.error(f'Data format error: {e}')
        return {'success':False,'message':'System error'}

    except Exception as e:
        logging.error(f'Unexpected login error: {e}')
        return {'success':False,'message':'Login failed, please try again'}
    finally:
        if conn:
            conn.close()
"""
<!-- 用户访问这个页面就中招 -->
<body onload="stealMoney()">
    <script>
        function stealMoney() {
            // 静默提交转账请求
            fetch('http://真银行.com/transfer', {
                method: 'POST',
                credentials: 'include',  // 带上cookie
                body: JSON.stringify({
                    to: '黑客账号',
                    amount: 10000
                })
            });
        }
    </script>
</body>
解释"""

def check_password(password:str) -> dict:
    try:
        if len(password) < 3:
            return {'success': False, 'message': 'wtf are you dump or a dumpling'}
        rules = [
            lambda s: re.search('[a-z]',s),
            lambda s: re.search('[A-Z]',s),
            lambda s: len(s)>6,
            lambda s: re.search(r'\d',s),
            lambda s: re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]', s),
            lambda s: not re.search(r'abc|password|qwerty|abc123|letmein|111111|'
                                    r'admin|welcome|monkey|dragon|1234|hello', s,
                                    re.IGNORECASE),
            lambda s: not re.search(r'(.)\1\1',s),
            lambda s: len(s)>8,
            lambda s: len(s) > 12,
        ]
        rules2 = [
            lambda s: len(s)<8,
            lambda s: s.isalpha(),
            lambda s: re.search(r'abc|password|qwerty|abc123|letmein|111111|'
                                    r'admin|welcome|monkey|dragon|1234|hello', s,
                                    re.IGNORECASE),
            lambda s: re.search(r'(.)\1\1',s),
            lambda s: len(s)<6,
        ]
        if password:
            count = sum(1 for rule in rules if rule(password))

            miinus_pistet = sum(1 for rule in rules2 if rule(password))
            #emmä muista engu
            count = count - miinus_pistet
            pass_point = str(count)
            if count <= 2:
                strength = 'very weak!!!'
            elif count <= 3:
                strength = 'weak'
            elif count <= 6:
                strength = 'medium'
            else:
                strength = 'strong! nice password bro!'

            return{'success':True, 'message':f'{strength}'}
    except TypeError as e:
        logging.warning(f'check password:Type error:{e}')
        return{'success':'error'}
    except Exception as e:
        logging.warning(f'check password:error:{e}')
        return{'success':'error'}


"""
rules = [
    lambda s:s in self.simple_sql,
    lambda s:any(s.startswith(prefix)for prefix in self.sql_prefixes),
    lambda s:any(s.endswith(suffix)for suffix in ['--', '"1', "\'1",'#']),
    lambda s: re.search(r'"1|1"', s, re.IGNORECASE) and re.search(r'="', s, re.IGNORECASE),
    lambda s: re.search(r"'1|1'", s, re.IGNORECASE) and re.search(r"='", s, re.IGNORECASE),
    lambda s: re.search(r'.+".+=.?",|.+%.+', s, re.IGNORECASE),
    lambda s: re.search(r".+'.+=.?'|%27|.&.|.\\|.|%201|or.?.+.?=.?|or.?1.?=|and.?1.?=|union|select|drop|insert", s, re.IGNORECASE)
]

xss_rules = [
    lambda s: s in self.simple_xss,
    lambda s: any(s.startswith(prefix) for prefix in self.xss_prefixes),
    lambda s: s.endswith('>') and re.search(r"<", s, re.IGNORECASE),
    lambda s:re.search(r"onerror=alert|href=\alert|onload=alert|javascript:alert|vbscript:msgbox|alert|document\\.cookie|prompt\\(document\\.domain\\)"
]
Old rules
            """
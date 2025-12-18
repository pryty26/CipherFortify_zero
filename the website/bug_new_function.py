import hashlib
import hmac
import html
import logging
import sqlite3
import time
import re
import base64
"""
flag1{eazy_123}
flag2{hello_I_@m_flag}

HARD:
flag1{hard_flag_is_abc}
flag2{eazy_flag_is_mrKarsar_5five_mm}
flag3{hard_H@rry_berr123456_99}
"""
def make_hard_secrets():
    conn = sqlite3.connect('sql_test.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users(
     id INTEGER PRIMARY KEY AUTOINCREMENT, 
    name TEXT UNIQUE,
    key TEXT,
    password TEXT
    )''')
    try:
        conn.execute('CREATE INDEX IF NOT EXISTS idx ON users(id, name)')  # magic!!!
        cursor = conn.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        if len(rows) < 1:
            flag2 = base64.b64encode('hdcb_iodj_lv_puNduvdu_5iylh_pp'.encode('utf-8'))
            users = [
                ('admin', 'flag1{hard_flag_is_abc}', hashlib.md5('flag3{hard_H@rry_berr123456_99}'.encode()).hexdigest()),
                ('user1', f'iodj2{flag2}',  hashlib.md5('Its_kaesar_plus_3'.encode()).hexdigest()),#flag{eazy_flag_is_mrKarsar_5five_mm}
                ('test', 'test_key_789',  hashlib.md5('test_123456_d@Wnt_hack_me'.encode()).hexdigest()),
                ('the_user_is_handsome', 'hello_world',  hashlib.md5('piupiuqdiuwdhqui19276e7'.encode()).hexdigest())
            ]

            cursor.executemany(
                "INSERT INTO users (name, key, password) VALUES (?, ?, ?)",
                users
            )
            print('sql_test_@#@^(^*!400219o)ready!!!')
    except Exception as e:
        print('error:\n',e)
    finally:
        conn.commit()
        conn.close()
def make_eazy_secrets():
    conn = sqlite3.connect('sql_test_eazy.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users(
     id INTEGER PRIMARY KEY AUTOINCREMENT, 
    name TEXT UNIQUE,
    key TEXT,
    password TEXT
    )''')
    try:
        eazy_flag = base64.b64encode('hello_I_@m_flag'.encode('utf-8'))
        conn.execute('CREATE INDEX IF NOT EXISTS idx ON users(id, name)')  # magic!!!
        cursor = conn.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        if len(rows) < 1:
            users = [
                ('admin', 'flag1{eazy_123}', hashlib.md5('flag{hard_H@rry_berr123456_99}'.encode()).hexdigest()),
                ('user1', f'flag2{eazy_flag}',  hashlib.md5('user1'.encode()).hexdigest()),
                ('test', 'test_key_789',  hashlib.md5('test'.encode()).hexdigest()),
                ('the_user_is_handsome', 'hello_world',  hashlib.md5('piupiu'.encode()).hexdigest())
            ]

            cursor.executemany(
                "INSERT INTO users (name, key, password) VALUES (?, ?, ?)",
                users
            )
            print('sql_test_@#@^(^*!400219o)ready!!!')
    except Exception as e:
        print('error:\n',e)
    finally:
        conn.commit()
        conn.close()
make_hard_secrets()
make_eazy_secrets()


def verify_the_password_bug(username:str,password:str) -> dict[str, any]:
    try:
        logging.warning(f'{html.escape(username)}\n{html.escape(password)}')
        conn = None
        safe_username = html.escape(username)
        conn = sqlite3.connect('sql_test.db')
        the_cursor = conn.cursor()


        cursor = the_cursor.execute(f'SELECT * FROM users WHERE name = "{safe_username}"')
        user_item = cursor.fetchone()
        if user_item is None:
            return {'success': False, 'message': 'username or password is wrong'}

        stored_hashed_password = user_item[-1]

        input_hashed_password = hashlib.md5(password.encode()).hexdigest()

        password_correct = hmac.compare_digest(input_hashed_password, stored_hashed_password)

        if password_correct:
            return {'success': True, 'message': f'user:{safe_username}Login success!\nAnd all_data:{user_item}'}

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


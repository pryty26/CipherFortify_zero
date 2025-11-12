from cryptography.fernet import Fernet
import sqlite3
import hashlib
import base64
import logging
from all_functions import safe_waf, commonplace_text, check_password
from markupsafe import escape
from win32comext.adsi.demos.search import search
# You can use Argon or some strongger password encryption
waf = safe_waf()


def secrets_encrypt(username, password:str, the_secrets: str, name:str) -> dict:
    conn = sqlite3.connect('user_secrets.db')
    try:
        if not the_secrets:
            return {'success': False, 'message': 'No secrets provided'}
        if not all([password, name]):
            return {'success': False, 'message': 'Missing required fields'}
        if the_secrets:
            name_safe_check_result = waf.all_check(name)
            password_safe_check_result = waf.all_check(password)
            secrets_result = waf.all_check(the_secrets)
            if any(result['success']=='warning' for result in [name_safe_check_result,password_safe_check_result,secrets_result]):
                safe_username = escape(username)
                logging.warning(f'{safe_username} is using attack!{name_safe_check_result}\n{secrets_result}\n{password_safe_check_result}')
                return{'success':'warning','message':'we are under attack！(StarCraft meme)'}
        pass_strength = check_password(password)
        if pass_strength['success'] == True:
            pass
        elif pass_strength['success'] == False:
            return {'success': False, 'message': f"{pass_strength['message']}"}


            key = Fernet.generate_key()

            encoded_password = password.encode()

            combined = encoded_password + key

            cipher_key = hashlib.sha256(combined).digest()

            cipher = Fernet(base64.urlsafe_b64encode(cipher_key))

            secret = the_secrets.encode()

            encrypted = cipher.encrypt(secret)
            hashed_name=hashlib.sha256(name.encode()+key).hexdigest()
            hashed_username = hashlib.sha256(username.encode()).hexdigest()

            conn.execute(
                "INSERT INTO users(name, hashed_name, hashed_username, key, data)VALUES(?,?,?,?,?)",
                (name, hashed_name, hashed_username, key.decode(), encrypted))
            conn.commit()
            return {'success': True, 'message': f'encrypted:{encrypted}'}
    except sqlite3.IntegrityError as e:
        logging.error(f'Data error: {e}')
        return {'success': False, 'message': 'error, name already exists'}

    except sqlite3.OperationalError as e:
        logging.error(f'Database error during login: {e}')
        return {'success': False, 'message': 'error, sql error'}

    except TypeError as e:
        logging.error(f'Data format error: {e}')
        return {'success': False, 'message': 'System error'}

    except Exception as e:
        logging.error(f'Unexpected login error: {e}')
        return {'success': False, 'message': 'Login failed, please try again'}

    finally:
        conn.close()





def find_all_name(username, user_input:str) -> dict:
    try:
        user_query=commonplace_text(user_input)
        if user_query in['searchallname', 'searchall', 'searchalldata', 'allname', 'alldata']:
            hashed_username = hashlib.sha256(username.encode()).hexdigest()
            conn = sqlite3.connect('user_secrets.db')
            select_result = conn.execute("SELECT name FROM users WHERE hashed_username = ?",
                         (hashed_username,))
            select_result2 = select_result.fetchall()
            if select_result2:
                all_names = [item[0] for item in select_result2]
                all_data = '\n'.join(all_names)
            return {'success':True,'message':all_data}
        else:
            return{'success':False,'message':'user_input is ?'}
    except sqlite3.OperationalError as e:
        logging.error(f'Database error during login: {e}')
        return{'success':'error','message':'System error please try again later'}
    except TypeError as e:
        logging.error(f'Data format error: {e}')
        return{'success':'error','message':f'TypeError please try again'}
    except Exception as e:
        logging.error(f'Unexpected login error: {e}')
        return{'success':'error','message':'System error please try again later'}
    finally:
        conn.close()






def secrets_decrypt(username, password:str, name:str) -> dict:
    try:

        if name and password:
            name_safe_check_result = waf.all_check(name)
            password_safe_check_result = waf.all_check(password)
            if any(result['success']=='warning' for result in [name_safe_check_result,password_safe_check_result]):
                safe_username = escape(username)
                logging.warning(f'{safe_username} is using attack!{name_safe_check_result}\n{password_safe_check_result}')
                return{'success':'warning','message':'we are under attack！(StarCraft meme)'}



        conn = sqlite3.connect('user_secrets.db')
        hashed_username = hashlib.sha256(username.encode()).hexdigest()
        sql_select_result = conn.execute("SELECT key, data FROM users WHERE hashed_username = ? AND name = ?",
                     (hashed_username, name))
        select_result = sql_select_result.fetchone()



        if not select_result:
            return {"success": False, "message": "No data found"}

        key,data=select_result

        encoded_password = password.encode()
        encoded_key = key.encode()
        combined = encoded_password + encoded_key

        cipher_key = hashlib.sha256(combined).digest()
        cipher = Fernet(base64.urlsafe_b64encode(cipher_key))
        decrypted = cipher.decrypt(data)
        decrypted_text = decrypted.decode('utf-8')
        return{'success':True,'message':f'decrypted:{decrypted_text}'}


    except sqlite3.OperationalError as e:
        logging.error(f'Database error during login: {e}')
        return{'success':'error','message':'System error please try again later'}
    except TypeError as e:
        logging.error(f'Data format error: {e}')
        return{'success':'error','message':f'TypeError please try again'}
    except Exception as e:
        logging.error(f'Unexpected login error: {e}')
        return{'success':'error','message':'System error please try again later'}
    finally:
        conn.close()



def make_secrets():
    conn = sqlite3.connect('user_secrets.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users(
     id INTEGER PRIMARY KEY AUTOINCREMENT, 
    hashed_name TEXT UNIQUE,
    name TEXT,
    hashed_username TEXT,
    key TEXT,
    data BLOB
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_user_secrets ON users(hashed_username, name)')  # magic!!!
    cursor = conn.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    conn.commit()
    conn.close()
make_secrets()



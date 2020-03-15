import pathlib
import json
import os
import requests
import subprocess
import threading
import time

from web.models import SrcUrls
from web import DB, APP

requests.packages.urllib3.disable_warnings()
proxies = {
    'http': 'http://127.0.0.1:7778',
    'https': 'http://127.0.0.1:7778'
}

def writeurl(url):
    '''修改url扫描状态'''
    domain_query = SrcUrls.query.filter(SrcUrls.url == url).first()
    if domain_query:
        domain_query.xray = True
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            print('修改url任务状态xray SQL错误:%s' % e)

def enumdir():
    '''从爬虫结果目录里取一个文件'''
    urlscan = pathlib.Path(__file__).resolve().parent.parent.joinpath('results')
    if not urlscan.is_dir():
        print('不存在results目录')
        return None
    url_file = ''
    for file in urlscan.iterdir():
        url_file = str(file)
        continue  # 只取一个文件
    if not url_file:
        return None
    with open(url_file, 'r', encoding='utf-8') as file:
        try:
            url_dict = json.loads(file.read())
        except:
            print('%sURL文件json解析失败' % url_file)
            url_dict = None
    os.remove(url_file)
    return url_dict

def request(request_dict):
    if request_dict['method'] == 'GET':
        try:
            requests.get(url=request_dict['url'], headers=request_dict['headers'], verify=False, timeout=15, proxies=proxies)
        except:
            pass
    elif request_dict['method'] == 'POST':
        try:
            requests.post(url=request_dict['url'], data=request_dict['data'], headers=request_dict['headers'], verify=False, timeout=15, proxies=proxies)
        except:
            pass
    else:
        print('存在其他HTTP方法请求，xray不支持')

def xray_main():
    xraypath = str(pathlib.Path(__file__).parent.resolve()) + '/./xray'
    cmd = [xraypath, "webscan", "--listen", "127.0.0.1:7778", "--webhook-output", f"http://127.0.0.1:{APP.config['PORT']}/webhook"]
    try:
        completed = subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as err:
        print('xray ERROR:', err)
    else:
        print(completed.returncode)

def http(url_dict):
    '''HTTP请求发送到w13scan代理中'''
    data = url_dict['data']
    for tmp in data:
        request(tmp)
        time.sleep(0.1)

def scan():
    while True:
        result = enumdir()
        if not result:
            time.sleep(8)
        else:
            print('子域名[%s],URL[%s]，开始发送http请求到扫描器中' % (result['subdomain'], result['url']))
            http(result)
            writeurl(result['url'])
            print('子域名[%s],URL[%s]，漏洞扫描完成' % (result['subdomain'], result['url']))

def main():
    # 启动漏洞扫描器
    scanner = threading.Thread(target=xray_main)
    scanner.setDaemon(True)
    scanner.start()

    # 启动从文件加载HTTP请求发送
    http_scan = threading.Thread(target=scan)
    http_scan.start()

if __name__ == '__main__':
    main()
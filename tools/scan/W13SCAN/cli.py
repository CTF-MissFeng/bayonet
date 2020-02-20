import os
import sys
import threading
import pathlib
import json
import requests
import time
sys.path.append("../../../")
from colorama import deinit

try:
    from W13SCAN import VERSION
except ImportError:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from W13SCAN.lib.baseproxy import AsyncMitmProxy
from W13SCAN.lib.cmdparse import cmd_line_parser
from W13SCAN.lib.controller import start
from W13SCAN.lib.data import conf, logger
from W13SCAN.lib.option import init
from W13SCAN.lib.data import KB
from db_config import SrcUrls, DBSession

requests.packages.urllib3.disable_warnings()
proxies = {
    'http': 'http://127.0.0.1:7778',
    'https': 'http://127.0.0.1:7778'
}
session = DBSession()

def writeurl(url):
    '''修改url扫描状态'''
    domain_query = session.query(SrcUrls).filter(SrcUrls.url == url).first()
    if domain_query:
        domain_query.w13scan = True
        try:
            session.commit()
        except Exception as e:
            print('修改url任务状态w13scan SQL错误:%s' % e)

def enumdir():
    '''从爬虫结果目录里取一个文件'''
    urlscan = pathlib.Path(__file__).resolve().parent.parent.joinpath('urlscan')
    if not urlscan:
        print('不存在urlscan目录')
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

def http(url_dict):
    '''HTTP请求发送到w13scan代理中'''
    data = url_dict['data']
    for tmp in data:
        request(tmp)
        while int(KB["running"]) > 10:  # 取扫描器状态，防止扫描器待扫描过多
            time.sleep(0.5)

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
        print('存在其他HTTP方法请求，w13scan不支持')

def scan():
    while True:
        result = enumdir()
        if not result:
            time.sleep(5)
        else:
            print('子域名[%s],URL[%s]，开始发送http请求到扫描器中' % (result['subdomain'], result['url']))
            http(result)
            writeurl(result['url'])
            print('子域名[%s],URL[%s]，漏洞扫描完成' % (result['subdomain'], result['url']))

def main():
    # python version check
    if sys.version.split()[0] < "3.6":
        logger.error(
            "incompatible Python version detected ('{}'). To successfully run sqlmap you'll have to use version >= 3.6 (visit 'https://www.python.org/downloads/')".format(
                sys.version.split()[0]))
        sys.exit()
    # init
    root = os.path.dirname(os.path.abspath(__file__))
    cmdline = cmd_line_parser().__dict__
    init(root, cmdline)
    if conf["show_version"]:
        exit()

    # 启动漏洞扫描器
    scanner = threading.Thread(target=start)
    scanner.setDaemon(True)
    scanner.start()

    # 启动从文件加载HTTP请求发送
    http_scan = threading.Thread(target=scan)
    http_scan.start()

    # 启动代理服务器
    baseproxy = AsyncMitmProxy(server_addr=conf["server_addr"], https=True)
    try:
        baseproxy.serve_forever()
    except KeyboardInterrupt:
        scanner.join(0.1)
        threading.Thread(target=baseproxy.shutdown, daemon=True).start()
        deinit()
        print("\n[*] User quit")
    baseproxy.server_close()

if __name__ == '__main__':
    main()

import subprocess
import json
import tldextract
import socket
import pathlib
import uuid
from concurrent.futures import ThreadPoolExecutor
import time
import multiprocessing

from web.models import SrcUrls
from web import DB
from web.utils.logs import logger
from config import crawlergo
from tools.oneforall.iscdn import iscdn
from tools.oneforall.dbexport import SelectIP, WriteDb

crawlergo_path = str(pathlib.Path(__file__).parent.joinpath('crawlergo').resolve())

def ReadUrl():
    '''读取url任务, 一次读取一条记录'''
    sql_url = SrcUrls.query.filter(SrcUrls.flag == True).first()
    DB.session.commit()
    return sql_url

def WriteUrl(sql_url):
    '''修改爬虫任务状态'''
    sql_url.flag = False
    sql_url.reptile = True
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        logger.log('ALERT', '修改URL任务状态SQL错误:%s' % e)

def action(target):
    '''子程序执行'''
    cmd = [crawlergo_path, "-c", crawlergo.chromium_path, "-o", "json", '-t', crawlergo.max_tab_count, '-f', crawlergo.filter_mode,
          '-m', crawlergo.max_crawled_count, target]
    rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = rsp.communicate()
    try:
        result = json.loads(output.decode().split("--[Mission Complete]--")[1])
        req_list = result["req_list"]
        req_subdomain = result["sub_domain_list"]
    except Exception as e:
        logger.log('ALERT', '爬虫异常:%s' % e)
        return None
    else:
        return req_list, req_subdomain

def WriteSubdomain(req_subdomain):
    '''子域名入库'''
    for subdomain in req_subdomain:
        ip = domain_ip(subdomain)
        if not ip:
            continue
        cdn = iscdn(ip)
        city = SelectIP(ip)
        domain = FindDomain(subdomain)
        WriteDb(subdomain, domain, ip, city, cdn)

def FindDomain(subdomain):
    '''提取主域名'''
    try:
        result = tldextract.extract(subdomain)
    except:
        return None
    else:
        return result.domain + '.' + result.suffix

def domain_ip(subdomain):
    '''域名转IP'''
    try:
        ip =socket.gethostbyname(subdomain)
    except:
        return None
    else:
        return ip

def write_request(dict1):
    '''保存爬虫结果'''
    try:
        resule = json.dumps(dict1)
    except Exception as e:
        logger.log('ALERT', f'爬虫异常,json存储失败:{e}')
        return None
    file_dir = pathlib.Path(__file__).resolve().parent.parent.joinpath('results')
    if not file_dir.is_dir():
        file_dir.mkdir()
    save_file = str(uuid.uuid1()) + '.json'
    sub_file = str(file_dir.joinpath(save_file).resolve())
    with open(sub_file, 'w', encoding='utf-8') as file:
        file.write(resule)
    logger.log('INFOR', f'[{save_file}]爬虫结果保存完毕')

def main():
    process_name = multiprocessing.current_process().name
    logger.log('INFOR', f'爬虫进程启动:{process_name}')
    pool = ThreadPoolExecutor(max_workers=1)
    while True:
        sql_url = ReadUrl()
        if not sql_url:
            time.sleep(30)
        else:
            req_dict = {}
            url = sql_url.url
            logger.log('INFOR', f'[{url}]开始爬虫')
            futurel = pool.submit(action, url)
            req_result = futurel.result()
            if req_result:
                if req_result[1]:
                    WriteSubdomain(req_result[1])
                req_dict['data'] = req_result[0]
            else:
                logger.log('INFOR', f'[{url}]爬虫无数据')
            req_dict['subdomain'] = sql_url.subdomain
            req_dict['url'] = url
            write_request(req_dict)
            WriteUrl(sql_url)

if __name__ == '__main__':
    main()
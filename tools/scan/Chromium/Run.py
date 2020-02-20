# 爬虫模块
from concurrent.futures import ThreadPoolExecutor
import time
import sys
import json
import subprocess
sys.path.append("../../../")
from db_config import SrcUrls, DBSession
import pathlib
import uuid

session = DBSession()

def ReadUrl():
    '''读取url任务, 一次读取一条记录'''
    results = session.query(SrcUrls).filter(SrcUrls.reptile == False).first()
    return results

def Wurl(results):
    '''修改爬虫任务状态'''
    results.reptile = True
    try:
        session.commit()
    except Exception as e:
        print('修改URL爬虫任务状态SQL错误:%s' % e)
    else:
        print('URL爬虫修改状态完成:[%s]' % results.url)

def action(target):
    '''子线程执行'''
    cmd = ["./crawlergo", "-c", "Chromium.app/Contents/MacOS/Chromium", "-o", "json", '-m', '500', target]
    rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = rsp.communicate()
    try:
        result = json.loads(output.decode().split("--[Mission Complete]--")[1])
        req_list = result["req_list"]
    except Exception as e:
        print('爬虫异常：%s' % e)
        return None
    else:
        return req_list

def write(dict1):
    '''保存爬虫结果'''
    try:
        resule = json.dumps(dict1)
    except Exception as e:
        print('保存爬虫结果异常:%s' % e)
    file_dir = pathlib.Path(__file__).resolve().parent.parent.joinpath('urlscan')
    if not file_dir.is_dir():
        file_dir.mkdir()
    save_file = str(uuid.uuid1()) + '.json'
    sub_file = str(file_dir.joinpath(save_file).resolve())
    with open(sub_file, 'w', encoding='utf-8') as file:
        file.write(resule)
    print('[%s]爬虫结果保存完毕' % save_file)

def main():
    pool = ThreadPoolExecutor(max_workers=1)
    while True:
        results = ReadUrl()
        if not results:
            time.sleep(30)  # 没有任务延迟点时间
        else:
            req_dict = {}
            url = results.url
            print('[%s]开始爬虫' % url)
            futurel = pool.submit(action, url)
            url_result = futurel.result()  # 阻塞当前主线程，等待子线程返回
            if url_result:
                req_dict['data'] = url_result
                print('[%s]爬虫完毕' % url)
            else:
                print('[%s]爬虫无数据' % url)
            req_dict['subdomain'] = results.subdomain
            req_dict['url'] = url
            write(req_dict)
            Wurl(results)

    pool.shutdown()

if __name__ == '__main__':
    main()
import sys
import pathlib
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
import time
sys.path.append("../../")

from db_config import DBSession, SrcSubDomain, SrcDomain
from config import logger
from oneforall import OneForAll

session = DBSession()

class subdomain:

    def __init__(self, domain, domain_name):
        self.domain = domain
        self.domain_name = domain_name

    def run(self):
        logger.log('INFOR', '开始收集[%s]的子域名' % self.domain)
        result_dir = pathlib.Path(__file__).parent.resolve().joinpath('results')
        if not result_dir.is_dir():
            result_dir.mkdir(parents=True, exist_ok=True)
        try:
            one = OneForAll(target=self.domain, verify=False, valid=1, format='json')
            one.run()
        except Exception as e:
            logger.log('ERROR', '子域名搜集oneforall模块执行异常,异常信息：%s' % e)

    def subdomain_result(self):
        sub_file = pathlib.Path(__file__).parent.resolve().joinpath('results', self.domain + '_subdomain.json')
        if not sub_file.is_file():
            logger.log('ALERT', '子域名文件：%s未发现' % sub_file)
            return None
        with open(sub_file, 'r', encoding='utf-8') as file:
            tmp_str = file.read()
        try:
            tmp_dict = json.loads(tmp_str)
        except:
            logger.log('ALERT', '子域名文件:%s解析json格式错误' % sub_file)
            return None
        sql_fie = str(pathlib.Path(__file__).parent.joinpath('results'))
        try:
            shutil.rmtree(sql_fie)
        except:
            print('[-]删除子域名查找结果文件失败')
        logger.log('INFOR', '[%s]子域名搜集完成，共%s个' % (self.domain, str(len(tmp_dict))))
        for subdomain_dict in tmp_dict:
            subdomain = subdomain_dict['subdomain']  # 取子域名
            if self._check_subdomain(subdomain):
                print('[-]已存在%s子域名' % subdomain)
                continue
            self._add_srsubdomain(subdomain, self.domain, self.domain_name, subdomain_ip='', city='')
        return True

    def _check_subdomain(self, subdomain):
        if session.query(SrcSubDomain).filter(SrcSubDomain.subdomain == subdomain).first():
            return True
        else:
            return False

    def _add_srsubdomain(self, subdomain, domain, domain_name, subdomain_ip, city):
        sql_srcsubdomain = SrcSubDomain(subdomain=subdomain, domain=domain, domain_name=domain_name,
                                        subdomain_ip=subdomain_ip, city=city)
        try:
            session.add(sql_srcsubdomain)
            session.commit()
        except Exception as e:
            logger.log('ALERT', '子域名[%s]入库失败,错误代码：%s' % (subdomain, e))

def ReadDomain():
    '''读取主域名任务, 一次读取一条记录'''
    results = session.query(SrcDomain).filter_by(flag='未扫描').first()
    if results:
        results.flag = '开始进行子域名扫描'
        try:
            session.commit()
        except Exception as e:
            logger.log('ALERT', '修改主域名任务状态SQL错误:%s' % e)
    return results

def WriteDomain(results):
    '''修改任务状态'''
    results.flag = '子域名扫描完成'
    try:
        session.commit()
    except Exception as e:
        print('ALERT', '修改主域名任务状态SQL错误:%s' % e)
    else:
        print('INFOR', '[%s]任务子域名查找完成' % results.domain)

def action(dict1):
    '''子线程执行'''
    sub = subdomain(dict1['domain'], dict1['domain_name'])
    sub.run()
    return sub.subdomain_result()

def main():
    '''主方法'''
    pool = ThreadPoolExecutor(max_workers=1)
    while True:
        results = ReadDomain()
        if not results:
            time.sleep(30)  # 没有任务延迟点时间
        else:
            dict1 = {'domain': results.domain, 'domain_name': results.domain_name}
            futurel = pool.submit(action, dict1)
            flag = futurel.result()  # 阻塞当前主线程，等待子线程返回
            if flag:
                WriteDomain(results)

    pool.shutdown()

if __name__ == '__main__':
    main()
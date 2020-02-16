#  子域名执行线程模块
from concurrent.futures import ThreadPoolExecutor
import time
from config import logger
from db_config import SrcDomain, DBSession, shodan_key
import subdomain

session = DBSession()

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

def riteWDomain(domain):
    '''修改任务状态'''
    domain_query = session.query(SrcDomain).filter(SrcDomain.domain == domain).first()
    if domain_query:
        domain_query.flag = '子域名扫描完成'
        try:
            session.commit()
        except Exception as e:
            logger.log('ALERT', '修改主域名任务状态SQL错误:%s' % e)
        else:
            logger.log('INFOR', '[%s]任务子域名查找完成' % domain)

def action(dict1):
    '''子线程执行'''
    sub = subdomain.subdomain(dict1['domain'], dict1['domain_name'], dict1['shodan_api'])
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
            dict1 = {'domain': results.domain, 'domain_name': results.domain_name, 'shodan_api': shodan_key}
            futurel = pool.submit(action, dict1)
            flag = futurel.result()  # 阻塞当前主线程，等待子线程返回
            if flag:
                riteWDomain(results.domain)

    pool.shutdown()


if __name__ == '__main__':
    main()
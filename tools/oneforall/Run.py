import time
import multiprocessing

from web.models import SrcDomain
from web import DB
from web.utils.logs import logger
from tools.oneforall.oneforall import OneForAll

def ReadDomain():
    '''读取主域名任务'''
    results = SrcDomain.query.filter(SrcDomain.flag != '子域名扫描完成').first()
    DB.session.commit()
    if results:
        results.flag = '子域名扫描中'
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', '修改主域名任务状态SQL错误:%s' % e)
    return results

def WriteDomain(results):
    '''修改主域名任务状态'''
    results.flag = '子域名扫描完成'
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        logger.log('ALERT', '修改主域名任务状态SQL错误:%s' % e)

def action(domain):
    '''子程序执行'''
    OneForAll(domain).run()

def main():
    '''主方法'''
    process_name = multiprocessing.current_process().name
    logger.log('INFOR', f'子域名扫描进程启动:{process_name}')
    while True:
        results = ReadDomain()
        if not results:
            time.sleep(30)  # 没有任务延迟点时间
        else:
            action(results.domain)
            WriteDomain(results)

if __name__ == '__main__':
    main()
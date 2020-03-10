import shodan
import time
import multiprocessing

from config import PortScan
from web.models import SrcSubDomain, SrcPorts
from web import DB
from web.utils.logs import logger
from tools.portscan.shodan_scan import scan
from tools.portscan.socket_scan import socket_main
from tools.portscan.scan_nmap import Nmap_Portscan

check = True
if not PortScan.shodan_api:
    logger.log('ALERT', f'未填写shodan api秘钥')
    check = False
else:
    API = shodan.Shodan(PortScan.shodan_api)
    try:
        time.sleep(1)
        API.info()
    except shodan.exception.APIError as e:
        logger.log('ALERT', f'shodan api秘钥错误:{e}')
        check = False
    except Exception as e:
        logger.log('ALERT', f'shodan api异常:{e}')
        check = False

def ReadSubDomain():
    '''读取子域名任务'''
    if PortScan.cdn_scan:
        sql_subdomain = SrcSubDomain.query.filter(SrcSubDomain.flag == False, SrcSubDomain.cdn == False).first()
    else:
        sql_subdomain = SrcSubDomain.query.filter(SrcSubDomain.flag == False).first()
    DB.session.commit()
    return sql_subdomain

def WriteSubDomain(results):
    '''修改子域名任务状态'''
    sql_subdomain = SrcSubDomain.query.filter(SrcSubDomain.subdomain_ip == results.subdomain_ip).all()
    DB.session.commit()
    if sql_subdomain:
        for tmp in sql_subdomain:
            tmp.flag = True
            DB.session.add(tmp)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'更新子域名任务状态SQL错误:{e}')

def WritePorts(ip, subdomain, info_dict):
    '''端口扫描入库'''
    if not SrcPorts.query.filter(SrcPorts.subdomain_ip == ip).count():
        for info in info_dict:
            sql = SrcPorts(subdomain_ip=ip, subdomain=subdomain, port=info_dict[info]['port'], service=info_dict[info]['name'], product=info_dict[info]['product'],
                           version=info_dict[info]['version'])
            DB.session.add(sql)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'端口入库SQL错误:{e}')

def action(ip, subdomain):
    iplist = scan(ip, API)
    if PortScan.async_scan and not iplist:
        iplist1 = socket_main(ip)
        iplist.extend(iplist1)
    if not iplist:
        return True
    if len(iplist) > PortScan.port_num:
        return True
    iplist = list(set(iplist))
    info_dict = Nmap_Portscan(ip, iplist)
    if info_dict:
        WritePorts(ip, subdomain, info_dict)
        return True

def port_main():
    process_name = multiprocessing.current_process().name
    logger.log('INFOR', f'端口服务扫描进程启动:{process_name}')
    if not check:
        return
    while True:
        results = ReadSubDomain()
        if not results:
            time.sleep(30)  # 没有任务延迟点时间
        else:
            action(results.subdomain_ip, results.subdomain)
            WriteSubDomain(results)

if __name__ == '__main__':
    port_main()
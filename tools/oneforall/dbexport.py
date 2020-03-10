#!/usr/bin/python3
# coding=utf-8

"""
OneForAll数据库导出模块

:copyright: Copyright (c) 2019, Jing Ling. All rights reserved.
:license: GNU General Public License v3.0, see LICENSE for more details.
"""

import fire
import ipdb
from pathlib import Path

from tools.oneforall.common import utils
from tools.oneforall.common.database import Database
from web.models import SrcSubDomain, SrcDomain
from web import DB
from tools.oneforall.iscdn import iscdn
from web.utils.logs import logger

ipdata = Path(__file__).parent.joinpath('ipdata.ipdb')
if not ipdata.is_file():
    logger.log('ALERT', f'ipdata.ipdb IP数据库不存在')
    exit(0)
else:
    IPDB = ipdb.City(ipdata.resolve())

def export(table, db=None, valid=None, path=None, format='csv', show=False):
    """
    OneForAll数据库导出模块

    Example:
        python3 dbexport.py --table name --format csv --dir= ./result.csv
        python3 dbexport.py --db result.db --table name --show False

    Note:
        参数port可选值有'small', 'medium', 'large', 'xlarge'，详见config.py配置
        参数format可选格式有'txt', 'rst', 'csv', 'tsv', 'json', 'yaml', 'html',
                          'jira', 'xls', 'xlsx', 'dbf', 'latex', 'ods'
        参数path默认None使用OneForAll结果目录生成路径

    :param str table:   要导出的表
    :param str db:      要导出的数据库路径(默认为results/result.sqlite3)
    :param int valid:   导出子域的有效性(默认None)
    :param str format:  导出文件格式(默认csv)
    :param str path:    导出文件路径(默认None)
    :param bool show:   终端显示导出数据(默认False)
    """

    database = Database(db)
    rows = database.export_data(table, valid)
    format = utils.check_format(format, len(rows))
    path = utils.check_path(path, table, format)
    if show:
        print(rows.dataset)
    if format == 'txt':
        data = str(rows.dataset)
    else:
        data = rows.export(format)
    database.close()
    utils.save_data(path, data)

def Warehouse(table, domain, db=None):
    logger.log('INFOR', f'开始进行子域名入库')
    database = Database(db)
    rows = database.export_data(table, valid=None)
    for i in rows:
        if i.ips:
            ip = i.ips.replace("'", '')
            if ip.find(', '):
                ip = ip.split(', ')[0]
            city = SelectIP(ip)
            cdn = iscdn(ip)
            WriteDb(i.subdomain, domain, ip, city, cdn)
    database.close()
    logger.log('INFOR', f'子域名入库完成')

def SelectIP(ip):
    '''查询IP归属地'''
    try:
        result = IPDB.find_map(ip, 'CN')
    except Exception as e:
        logger.log('DEBUG', f'{ip}查询归属地失败:{e}')
        return ''
    else:
        if result['region_name'] == result['city_name']:
            ipinfo = result['country_name'] + result['region_name'] + result['isp_domain']
        else:
            ipinfo = result['country_name'] + result['region_name'] + result['city_name'] + result['isp_domain']
        return ipinfo

def WriteDb(subdomain, domain, subdomain_ip, city, cdn):
    '''写入数据库'''
    result = SrcSubDomain.query.filter(SrcSubDomain.subdomain == subdomain).count()
    if result:
        logger.log('DEBUG', f'数据库已有该子域名[{subdomain}]')
        return None
    if not SrcDomain.query.filter(SrcDomain.domain == domain).count():
        logger.log('DEBUG', f'数据库无已主域名[{domain}]')
        return None
    sql = SrcSubDomain(subdomain=subdomain, domain=domain, subdomain_ip=subdomain_ip, city=city, cdn=cdn)
    DB.session.add(sql)
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        logger.log('ALERT', f'子域名[{subdomain}]入库失败:{e}')


if __name__ == '__main__':
    # fire.Fire(export)
    # save('example_com_last', format='txt')
    pass

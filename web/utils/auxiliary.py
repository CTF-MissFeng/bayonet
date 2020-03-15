# 辅助模块，提供一些辅助功能

from urllib.parse import *
from flask import session, redirect, url_for
from functools import wraps

from web import DB
from web.utils.logs import logger
from web.models import UserLogs, SrcVulnerabilitie, SrcSubDomain, SrcUrls, SrcPorts

def login_required(func):
    '''登录验证装饰器'''
    @wraps(func)
    def inner(*args, **kwargs):
        user = session.get('status')
        if not user:
            return redirect(url_for('html_user_login'), 302)
        return func(*args, **kwargs)
    return inner

def addlog(username, logs_ip, logs_text):
    '''添加用户操作日志'''
    try:
        logs = UserLogs(username, logs_ip, logs_text)
        DB.session.add(logs)
        DB.session.commit()
    except Exception as e:
        logger.log('ALERT', f'用户操作日志添加失败，错误代码:{e}')
        DB.session.rollback()

def src_count():
    '''统计数据库数量'''
    Vulnerabilitie_count = SrcUrls.query.filter(SrcUrls.flag == True).count()
    subdomain_count = SrcSubDomain.query.count()
    SrcUrls_count = SrcUrls.query.count()
    SrcPorts_count = SrcPorts.query.count()
    dict1 = {}
    dict1['Vulnerabilitie_count'] = Vulnerabilitie_count
    dict1['subdomain_count'] = subdomain_count
    dict1['url_count'] = SrcUrls_count
    dict1['ports_count'] = SrcPorts_count
    return dict1

def Rsubdomain(url):
    '''提取子域名'''
    result = urlparse(url)
    return result.hostname

def scan_write(plugin, url, payload, raw, flag, scan_name):
    subdomain = Rsubdomain(url)
    new_scan = SrcVulnerabilitie(subdomain=subdomain, plugin=plugin, url=url, payload=payload, raw=raw, flag=flag, scan_name=scan_name)
    DB.session.add(new_scan)
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        print('新增漏洞扫描结果失败; %s' % e)

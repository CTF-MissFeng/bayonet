# 辅助模块，提供一些辅助功能

from flask import session, redirect, url_for
from functools import wraps
import requests

from web.models import UserLogs, SrcSubDomain, SrcUrls, SrcPorts, SrcVulnerabilitie
from web import DB
from web.utils.logs import logger

def login_required(func):
    '''登录验证装饰器'''
    @wraps(func)
    def inner(*args, **kwargs):
        user = session.get('status')
        if not user:
            return redirect(url_for('html_user_login'), 302)
        return func(*args, **kwargs)
    return inner

def addlog(username, log_ip, log_text):
    '''添加用户操作日志'''
    try:
        logs = UserLogs(username, log_ip, log_text)
        DB.session.add(logs)
        DB.session.commit()
    except Exception as e:
        logger.log('ALERT', '用户操作日志添加到数据库失败，原因: %s' % e)

def shodan_check(api_key):
    '''shodan key有效监测'''
    requests.packages.urllib3.disable_warnings()
    url = 'https://api.shodan.io/account/profile?key=%s' % api_key
    try:
        result = requests.get(url, verify=False, timeout=30)
    except:
        return False
    else:
        if result.status_code == 200:
            return True
        else:
            return False

def src_count():
    '''统计数据库数量'''
    Vulnerabilitie_count = SrcVulnerabilitie.query.count()
    subdomain_count = SrcSubDomain.query.count()
    SrcUrls_count = SrcUrls.query.count()
    SrcPorts_count = SrcPorts.query.count()
    dict1 = {}
    dict1['Vulnerabilitie_count'] = Vulnerabilitie_count
    dict1['subdomain_count'] = subdomain_count
    dict1['url_count'] = SrcUrls_count
    dict1['ports_count'] = SrcPorts_count
    return dict1

import datetime
from flask import escape
from werkzeug.security import generate_password_hash

from web import DB


class User(DB.Model):
    '''User表'''
    __tablename__ = 'user'
    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(20), index=True, unique=True)
    password = DB.Column(DB.String(128), nullable=False)
    name = DB.Column(DB.String(20))
    phone = DB.Column(DB.String(20))
    email = DB.Column(DB.String(50))
    remark = DB.Column(DB.Text)

    def __init__(self, username, password, name, phone, email, remark):
        self.username = escape(username)
        self.password = generate_password_hash(password)
        self.name = escape(name)
        self.phone = escape(phone)
        self.email = escape(email)
        self.remark = escape(remark)

class UserLoginLogs(DB.Model):
    '''User登录日志表'''
    __tablename__ = 'user_login_logs'
    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(20))
    login_time = DB.Column(DB.String(30))
    login_ip = DB.Column(DB.String(15))
    useragent = DB.Column(DB.Text)

    def __init__(self, username, login_ip, useragent):
        self.username = username
        self.login_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.login_ip = escape(login_ip)
        self.useragent = escape(useragent)

class UserLogs(DB.Model):
    '''User操作日志表'''
    __tablename__ = 'user_logs'
    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(20))
    login_ip = DB.Column(DB.String(15))
    login_time = DB.Column(DB.String(30))
    logtxt = DB.Column(DB.String(500))

    def __init__(self, username, login_ip, logtxt):
        self.username = username
        self.login_ip = login_ip
        self.login_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logtxt = logtxt

class SrcDomain(DB.Model):
    '''主域名任务表'''
    __tablename__ = 'srcdomain'
    id = DB.Column(DB.Integer, primary_key=True)
    domain = DB.Column(DB.String(50), unique=True)
    domain_name = DB.Column(DB.String(50))
    domain_time = DB.Column(DB.String(30))
    flag = DB.Column(DB.String(30))

    def __init__(self, domain, domain_name, flag='未扫描'):
        self.domain = domain
        self.domain_name = domain_name
        self.domain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.flag = flag

class SrcSubDomain(DB.Model):
    '''子域名信息表'''
    __tablename__ = 'srcsubdomain'
    subdomain = DB.Column(DB.String(150), primary_key=True)
    id = DB.Column(DB.Integer, autoincrement=True)
    domain = DB.Column(DB.String(50), nullable=False)
    domain_name = DB.Column(DB.String(50), nullable=False)
    subdomain_ip = DB.Column(DB.String(20))
    city = DB.Column(DB.String(50))
    subdomain_time = DB.Column(DB.String(30))
    srcports = DB.relationship('SrcPorts', back_populates='srcsubdomain')  # 建议双向关系
    srcurls = DB.relationship('SrcUrls', back_populates='srcsubdomain')  # 建议双向关系
    srcvulnerabilitie = DB.relationship('SrcVulnerabilitie', back_populates='srcsubdomain')  # 建议双向关系

    def __init__(self, subdomain, domain, domain_name, subdomain_ip, city):
        self.subdomain = subdomain
        self.domain = domain
        self.domain_name = domain_name
        self.subdomain_ip = subdomain_ip
        self.subdomain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.city = city

class SrcPorts(DB.Model):
    '''端口信息表'''
    __tablename__ = 'srcports'
    id = DB.Column(DB.Integer, primary_key=True)
    subdomain = DB.Column(DB.String(150), DB.ForeignKey('srcsubdomain.subdomain'))  # 定义外键
    port = DB.Column(DB.Integer)
    product = DB.Column(DB.String(80))
    version = DB.Column(DB.String(50))
    data = DB.Column(DB.String(200))
    flag = DB.Column(DB.Boolean)
    porttime = DB.Column(DB.String(30))
    srcsubdomain = DB.relationship('SrcSubDomain', back_populates='srcports')  # 建议双向关系

    def __init__(self, subdomain, port, product, version, data, porttime='', flag=False):
        self.subdomain = subdomain
        self.port = port
        self.product = product
        self.version = version
        self.data = data
        self.flag = flag
        self.porttime = porttime

class SrcUrls(DB.Model):
    '''url信息表'''
    __tablename__ = 'srcurls'
    id = DB.Column(DB.Integer, primary_key=True)
    subdomain = DB.Column(DB.String(150), DB.ForeignKey('srcsubdomain.subdomain'))  # 定义外键
    url = DB.Column(DB.Text)
    title = DB.Column(DB.String(500))
    reptile = DB.Column(DB.Boolean)
    w13scan = DB.Column(DB.Boolean)
    xray = DB.Column(DB.Boolean)
    srcsubdomain = DB.relationship('SrcSubDomain', back_populates='srcurls')  # 建议双向关系

    def __init__(self, subdomain, url, title, reptile=False, w13scan=False, xray=False):
        self.subdomain = subdomain
        self.url = url
        self.title = title
        self.reptile = reptile
        self.w13scan = w13scan
        self.xray = xray

class SrcVulnerabilitie(DB.Model):
    '''漏洞信息表'''
    __tablename__ = 'srcvulnerabilitie'
    id = DB.Column(DB.Integer, primary_key=True)
    subdomain = DB.Column(DB.String(150), DB.ForeignKey('srcsubdomain.subdomain'))  # 定义外键
    plugin = DB.Column(DB.String(200))
    url = DB.Column(DB.Text)
    payload = DB.Column(DB.Text)
    raw = DB.Column(DB.Text)
    time = DB.Column(DB.String(30))
    scan_name = DB.Column(DB.String(30))
    flag = DB.Column(DB.Boolean)
    srcsubdomain = DB.relationship('SrcSubDomain', back_populates='srcvulnerabilitie')  # 建议双向关系

    def __init__(self, subdomain, plugin, url, payload, raw, scan_name, flag=False):
        self.subdomain = subdomain
        self.plugin = plugin
        self.url = url
        self.payload = payload
        self.raw = raw
        self.time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_name = scan_name
        self.flag = flag
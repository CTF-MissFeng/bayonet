import datetime
from flask import escape
from werkzeug.security import generate_password_hash

from web import DB

class User(DB.Model):
    '''User表'''

    __tablename__ = 'src_user'
    username = DB.Column(DB.String(20), primary_key=True)
    password = DB.Column(DB.String(128), nullable=False)
    name = DB.Column(DB.String(20))
    phone = DB.Column(DB.String(20))
    email = DB.Column(DB.String(50))
    remark = DB.Column(DB.Text)
    src_user_login_logs = DB.relationship('UserLoginLogs', back_populates='src_user', cascade='all, delete-orphan')  # 双向关系
    src_user_logs = DB.relationship('UserLogs', back_populates='src_user', cascade='all, delete-orphan')  # 双向关系

    def __init__(self, username, password, name, phone, email, remark):
        self.username = escape(username)
        self.password = generate_password_hash(password)
        self.name = escape(name)
        self.phone = escape(phone)
        self.email = escape(email)
        self.remark = escape(remark)

class UserLoginLogs(DB.Model):
    '''User登录日志表'''

    __tablename__ = 'src_user_login_logs'
    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(20), DB.ForeignKey('src_user.username', ondelete='CASCADE'))  # 外键
    login_time = DB.Column(DB.String(30))
    login_ip = DB.Column(DB.String(15))
    useragent = DB.Column(DB.Text)
    src_user = DB.relationship('User', back_populates='src_user_login_logs')  # 双向关系

    def __init__(self, username, login_ip, useragent):
        self.username = username
        self.login_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.login_ip = escape(login_ip)
        self.useragent = escape(useragent)

class UserLogs(DB.Model):
    '''User操作日志表'''

    __tablename__ = 'src_user_logs'
    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(20), DB.ForeignKey('src_user.username', ondelete='CASCADE'))  # 外键
    logs_time = DB.Column(DB.String(30))
    logs_ip = DB.Column(DB.String(15))
    logs_text = DB.Column(DB.String(500))
    src_user = DB.relationship('User', back_populates='src_user_logs')  # 双向关系

    def __init__(self, username, logs_ip, logs_text):
        self.username = username
        self.logs_ip = logs_ip
        self.logs_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logs_text = logs_text

class SrcDomain(DB.Model):
    '''主域名表'''

    __tablename__ = 'src_domain'
    domain = DB.Column(DB.String(100), primary_key=True)
    domain_name = DB.Column(DB.String(100), nullable=True)
    domain_time = DB.Column(DB.String(30))
    flag = DB.Column(DB.String(50))
    src_subdomain = DB.relationship('SrcSubDomain', back_populates='src_domain',
                                          cascade='all, delete-orphan')  # 双向关系

    def __init__(self, domain, domain_name, flag='未扫描'):
        self.domain = domain
        self.domain_name = domain_name
        self.flag = flag
        self.domain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcSubDomain(DB.Model):
    '''子域名表'''

    __tablename__ = 'src_subdomain'
    subdomain = domain = DB.Column(DB.String(150), primary_key=True)
    domain = DB.Column(DB.String(100), DB.ForeignKey('src_domain.domain', ondelete='CASCADE'))  # 外键
    subdomain_ip = DB.Column(DB.String(20))
    city = DB.Column(DB.String(300))
    cdn = DB.Column(DB.Boolean)
    flag = DB.Column(DB.Boolean)
    subdomain_time = DB.Column(DB.String(30))
    src_domain = DB.relationship('SrcDomain', back_populates='src_subdomain')  # 双向关系
    src_ports = DB.relationship('SrcPorts', back_populates='src_subdomain',
                                    cascade='all, delete-orphan')  # 双向关系
    src_urls = DB.relationship('SrcUrls', back_populates='src_subdomain',
                                cascade='all, delete-orphan')  # 双向关系
    # src_vulnerabilitie = DB.relationship('SrcVulnerabilitie', back_populates='src_subdomain',
    #                            cascade='all, delete-orphan')  # 双向关系

    def __init__(self, subdomain, domain, subdomain_ip, city, cdn, flag=False):
        self.subdomain = subdomain
        self.domain = domain
        self.subdomain_ip = subdomain_ip
        self.city = city
        self.cdn = cdn
        self.flag = flag
        self.subdomain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcPorts(DB.Model):
    '''端口扫描表'''

    __tablename__ = 'src_ports'
    id = DB.Column(DB.Integer, primary_key=True)
    subdomain_ip = DB.Column(DB.String(20))
    subdomain = DB.Column(DB.String(150), DB.ForeignKey('src_subdomain.subdomain', ondelete='CASCADE'))
    port = DB.Column(DB.Integer)
    service = DB.Column(DB.String(30))
    product = DB.Column(DB.String(100))
    version = DB.Column(DB.String(100))
    flag = DB.Column(DB.Boolean)
    brute = DB.Column(DB.Boolean)
    port_time = DB.Column(DB.String(30))
    src_subdomain = DB.relationship('SrcSubDomain', back_populates='src_ports')  # 双向关系

    def __init__(self, subdomain_ip, subdomain, port, service, product, version, flag=False, brute=False):
        self.subdomain_ip = subdomain_ip
        self.subdomain = subdomain
        self.port = port
        self.service = service
        self.product = product
        self.version = version
        self.flag = flag
        self.brute = brute
        self.port_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcUrls(DB.Model):
    '''URL表'''

    __tablename__ = 'src_urls'
    url = DB.Column(DB.String(500), primary_key=True)
    subdomain = DB.Column(DB.String(150), DB.ForeignKey('src_subdomain.subdomain', ondelete='CASCADE'))
    title = DB.Column(DB.String(300))
    fingerprint = DB.Column(DB.TEXT)
    waf = DB.Column(DB.String(100))
    reptile = DB.Column(DB.Boolean)
    flag = DB.Column(DB.Boolean)
    w13scan = DB.Column(DB.Boolean)
    xray = DB.Column(DB.Boolean)
    url_time = DB.Column(DB.String(30))
    src_subdomain = DB.relationship('SrcSubDomain', back_populates='src_urls')  # 双向关系

    def __init__(self, url, subdomain, title, fingerprint, waf, reptile=False, flag=False, w13scan=False, xray=False):
        self.url = url
        self.subdomain = subdomain
        self.title = title
        self.fingerprint = fingerprint
        self.waf = waf
        self.reptile = reptile
        self.flag = flag
        self.w13scan = w13scan
        self.xray = xray
        self.url_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcVulnerabilitie(DB.Model):
    '''漏洞信息表'''

    __tablename__ = 'src_vulnerabilitie'
    id = DB.Column(DB.Integer, primary_key=True)
    subdomain = DB.Column(DB.String(150))
    plugin = DB.Column(DB.String(200))
    url = DB.Column(DB.Text)
    payload = DB.Column(DB.Text)
    raw = DB.Column(DB.Text)
    time = DB.Column(DB.String(30))
    scan_name = DB.Column(DB.String(30))
    flag = DB.Column(DB.Boolean)
    #src_subdomain = DB.relationship('SrcSubDomain', back_populates='src_vulnerabilitie')  # 双向关系

    def __init__(self, subdomain, plugin, url, payload, raw, scan_name, flag=False):
        self.subdomain = subdomain
        self.plugin = plugin
        self.url = url
        self.payload = payload
        self.raw = raw
        self.time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_name = scan_name
        self.flag = flag
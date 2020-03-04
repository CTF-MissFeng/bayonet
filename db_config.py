# 供其他工具连接数据库操作

from sqlalchemy import Column, String, create_engine, Integer, Boolean, Text, ForeignKey
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask import escape
from werkzeug.security import generate_password_hash
import datetime

SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:123456@127.0.0.1/bayonet'  # 数据库连接字符串
Base = declarative_base()

class User(Base):
    '''User表'''

    __tablename__ = 'src_user'
    username = Column(String(20), primary_key=True)
    password = Column(String(128), nullable=False)
    name = Column(String(20))
    phone = Column(String(20))
    email = Column(String(50))
    remark = Column(Text)
    src_user_login_logs = relationship('UserLoginLogs', back_populates='src_user', cascade='all, delete-orphan')  # 双向关系
    src_user_logs = relationship('UserLogs', back_populates='src_user', cascade='all, delete-orphan')  # 双向关系

    def __init__(self, username, password, name, phone, email, remark):
        self.username = escape(username)
        self.password = generate_password_hash(password)
        self.name = escape(name)
        self.phone = escape(phone)
        self.email = escape(email)
        self.remark = escape(remark)

class UserLoginLogs(Base):
    '''User登录日志表'''

    __tablename__ = 'src_user_login_logs'
    id = Column(Integer, primary_key=True)
    username = Column(String(20), ForeignKey('src_user.username', ondelete='CASCADE'))  # 外键
    login_time = Column(String(30))
    login_ip = Column(String(15))
    useragent = Column(Text)
    src_user = relationship('User', back_populates='src_user_login_logs')  # 双向关系

    def __init__(self, username, login_ip, useragent):
        self.username = username
        self.login_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.login_ip = escape(login_ip)
        self.useragent = escape(useragent)

class UserLogs(Base):
    '''User操作日志表'''

    __tablename__ = 'src_user_logs'
    id = Column(Integer, primary_key=True)
    username = Column(String(20), ForeignKey('src_user.username', ondelete='CASCADE'))  # 外键
    logs_time = Column(String(30))
    logs_ip = Column(String(15))
    logs_text = Column(String(500))
    src_user = relationship('User', back_populates='src_user_logs')  # 双向关系

    def __init__(self, username, logs_ip, logs_text):
        self.username = username
        self.logs_ip = logs_ip
        self.logs_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logs_text = logs_text

class SrcDomain(Base):
    '''主域名表'''

    __tablename__ = 'src_domain'
    domain = Column(String(100), primary_key=True)
    domain_name = Column(String(100), nullable=True)
    domain_time = Column(String(30))
    flag = Column(String(50))
    src_subdomain = relationship('SrcSubDomain', back_populates='src_domain',
                                          cascade='all, delete-orphan')  # 双向关系

    def __init__(self, domain, domain_name, flag='未扫描'):
        self.domain = domain
        self.domain_name = domain_name
        self.flag = flag
        self.domain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcSubDomain(Base):
    '''子域名表'''

    __tablename__ = 'src_subdomain'
    subdomain = domain = Column(String(150), primary_key=True)
    domain = Column(String(100), ForeignKey('src_domain.domain', ondelete='CASCADE'))  # 外键
    subdomain_ip = Column(String(20))
    city = Column(String(300))
    cdn = Column(Boolean)
    flag = Column(Boolean)
    subdomain_time = Column(String(30))
    src_domain = relationship('SrcDomain', back_populates='src_subdomain')  # 双向关系
    src_ports = relationship('SrcPorts', back_populates='src_subdomain',
                                    cascade='all, delete-orphan')  # 双向关系
    src_urls = relationship('SrcUrls', back_populates='src_subdomain',
                                cascade='all, delete-orphan')  # 双向关系
    src_vulnerabilitie = relationship('SrcVulnerabilitie', back_populates='src_subdomain',
                               cascade='all, delete-orphan')  # 双向关系

    def __init__(self, subdomain, domain, subdomain_ip, city, cdn, flag=False):
        self.subdomain = subdomain
        self.domain = domain
        self.subdomain_ip = subdomain_ip
        self.city = city
        self.cdn = cdn
        self.flag = flag
        self.subdomain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcPorts(Base):
    '''端口扫描表'''

    __tablename__ = 'src_ports'
    id = Column(Integer, primary_key=True)
    subdomain_ip = Column(String(20))
    subdomain = Column(String(150), ForeignKey('src_subdomain.subdomain', ondelete='CASCADE'))
    port = Column(Integer)
    service = Column(String(30))
    product = Column(String(100))
    version = Column(String(100))
    flag = Column(Boolean)
    brute = Column(Boolean)
    port_time = Column(String(30))
    src_subdomain = relationship('SrcSubDomain', back_populates='src_ports')  # 双向关系

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

class SrcUrls(Base):
    '''URL表'''

    __tablename__ = 'src_urls'
    url = Column(String(500), primary_key=True)
    subdomain = Column(String(150), ForeignKey('src_subdomain.subdomain', ondelete='CASCADE'))
    title = Column(String(300))
    fingerprint = Column(Text)
    waf = Column(String(100))
    reptile = Column(Boolean)
    flag = Column(Boolean)
    w13scan = Column(Boolean)
    xray = Column(Boolean)
    url_time = Column(String(30))
    src_subdomain = relationship('SrcSubDomain', back_populates='src_urls')  # 双向关系

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

class SrcVulnerabilitie(Base):
    '''漏洞信息表'''

    __tablename__ = 'src_vulnerabilitie'
    id = Column(Integer, primary_key=True)
    subdomain = Column(String(150), ForeignKey('src_subdomain.subdomain', ondelete='CASCADE'))
    plugin = Column(String(200))
    url = Column(Text)
    payload = Column(Text)
    raw = Column(Text)
    time = Column(String(30))
    scan_name = Column(String(30))
    flag = Column(Boolean)
    src_subdomain = relationship('SrcSubDomain', back_populates='src_vulnerabilitie')  # 双向关系

    def __init__(self, subdomain, plugin, url, payload, raw, scan_name, flag=False):
        self.subdomain = subdomain
        self.plugin = plugin
        self.url = url
        self.payload = payload
        self.raw = raw
        self.time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_name = scan_name
        self.flag = flag


sql_connect = SQLALCHEMY_DATABASE_URI

engine = create_engine(sql_connect)
DBSession = sessionmaker(bind=engine)
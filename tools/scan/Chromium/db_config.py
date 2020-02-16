# 供其他工具连接数据库操作

from sqlalchemy import Column, String, create_engine, Integer, Boolean, Text, ForeignKey
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class SrcDomain(Base):
    '''主域名任务表'''
    __tablename__ = 'srcdomain'
    id = Column(Integer, primary_key=True)
    domain = Column(String(50), unique=True)
    domain_name = Column(String(50))
    domain_time = Column(String(30))
    flag = Column(String(30))

    def __init__(self, domain, domain_name, flag='未扫描'):
        self.domain = domain
        self.domain_name = domain_name
        self.domain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.flag = flag

class SrcSubDomain(Base):
    '''子域名信息表'''
    __tablename__ = 'srcsubdomain'
    subdomain = Column(String(150), primary_key=True)
    id = Column(Integer, autoincrement=True)
    domain = Column(String(50), nullable=False)
    domain_name = Column(String(50), nullable=False)
    subdomain_ip = Column(String(20))
    city = Column(String(50))
    subdomain_time = Column(String(30))
    srcports = relationship('SrcPorts', back_populates='srcsubdomain')  # 建议双向关系
    srcurls = relationship('SrcUrls', back_populates='srcsubdomain')  # 建议双向关系
    srcvulnerabilitie = relationship('SrcVulnerabilitie', back_populates='srcsubdomain')  # 建议双向关系

    def __init__(self, subdomain, domain, domain_name, subdomain_ip, city):
        self.subdomain = subdomain
        self.domain = domain
        self.domain_name = domain_name
        self.subdomain_ip = subdomain_ip
        self.subdomain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.city = city

class SrcPorts(Base):
    '''端口信息表'''
    __tablename__ = 'srcports'
    id = Column(Integer, primary_key=True)
    subdomain = Column(String(150), ForeignKey('srcsubdomain.subdomain'))  # 定义外键
    port = Column(Integer)
    product = Column(String(80))
    version = Column(String(50))
    data = Column(String(200))
    flag = Column(Boolean)
    porttime = Column(String(30))
    srcsubdomain = relationship('SrcSubDomain', back_populates='srcports')  # 建议双向关系

    def __init__(self, subdomain, port, product, version, data, porttime='', flag='未扫描'):
        self.subdomain = subdomain
        self.port = port
        self.product = product
        self.version = version
        self.data = data
        self.flag = flag
        self.porttime = porttime

class SrcUrls(Base):
    '''url信息表'''
    __tablename__ = 'srcurls'
    id = Column(Integer, primary_key=True)
    subdomain = Column(String(150), ForeignKey('srcsubdomain.subdomain'))  # 定义外键
    url = Column(Text)
    title = Column(String(500))
    reptile = Column(Boolean)
    w13scan = Column(Boolean)
    xray = Column(Boolean)
    srcsubdomain = relationship('SrcSubDomain', back_populates='srcurls')  # 建议双向关系

    def __init__(self, subdomain, url, title, reptile=False, w13scan=False, xray=False):
        self.subdomain = subdomain
        self.url = url
        self.title = title
        self.reptile = reptile
        self.w13scan = w13scan
        self.xray = xray

class SrcVulnerabilitie(Base):
    '''漏洞信息表'''
    __tablename__ = 'srcvulnerabilitie'
    id = Column(Integer, primary_key=True)
    subdomain = Column(String(150), ForeignKey('srcsubdomain.subdomain'))  # 定义外键
    plugin = Column(String(200))
    url = Column(Text)
    payload = Column(Text)
    raw = Column(Text)
    time = Column(String(30))
    scan_name = Column(String(30))
    flag = Column(Boolean)
    srcsubdomain = relationship('SrcSubDomain', back_populates='srcvulnerabilitie')  # 建议双向关系

    def __init__(self, subdomain, plugin, url, payload, raw, scan_name, flag=False):
        self.subdomain = subdomain
        self.plugin = plugin
        self.url = url
        self.payload = payload
        self.raw = raw
        self.time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_name = scan_name
        self.flag = flag

sql_connect = 'postgresql://postgres:123456@127.0.0.1/bayonet'
shodan_key = 'xxxx'

engine = create_engine(sql_connect)
DBSession = sessionmaker(bind=engine)
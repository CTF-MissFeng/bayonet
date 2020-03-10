# 数据库操作模块

from sqlalchemy import Column, String, create_engine, Integer, Boolean, Text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class SrcVulnerabilities(Base):
    '''漏洞扫描结果表'''
    __tablename__ = 'src_Vulnerabilities'
    id = Column(Integer, primary_key=True)
    plugin = Column(String(50))  # 插件名
    url = Column(String(300))  # 漏洞URL
    payload = Column(Text)  # payload
    raw = Column(Text)  # 原始请求
    time = Column(String(50))  # 发现时间
    flag = Column(Boolean)  # 是否复现标志
    scan_name = Column(String(50))  # 哪个扫描器

    def __init__(self, plugin, url, payload, raw, flag, scan_name):
        self.plugin = plugin
        self.url = url
        self.payload = payload
        self.raw = raw
        self.time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.flag = flag
        self.scan_name = scan_name

class SrcSubDomain(Base):
    '''子域名信息表'''
    __tablename__ = 'src_subdomain'
    id = Column(Integer, primary_key=True)
    domain = Column(String(200), nullable=False)  # 主域名
    domain_name = Column(String(200))  # 厂商名
    subdomain = Column(String(200), index=True, unique=True)  # 子域名
    domain_ip = Column(String(20))  # 域名对应IP
    ports = Column(Text)  # IP对应的开放端口
    urls = Column(Text)  # IP开放的所有URL
    domian_time = Column(String(50))  # 发现时间
    flag = Column(String(50))  # 扫描标志 未扫描、子域名扫描完成、
    w13scan = Column(String(50))  # w13scan标志
    xray = Column(String(50))  # xray标志
    portscan = Column(String(50))  # 端口服务扫描标志

    def __init__(self, domain, domain_name, subdomain, domain_ip, ports, urls, flag, w13scan='未扫描', xray='未扫描', portscan='未扫描'):
        self.domain = domain
        self.domain_name = domain_name
        self.subdomain = subdomain
        self.domain_ip = domain_ip
        self.ports = ports
        self.urls = urls
        self.domian_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.flag = flag
        self.w13scan = w13scan
        self.xray = xray
        self.portscan = portscan

engine = create_engine('postgresql://postgres:xuanyuan520@127.0.0.1/src')

DBSession = sessionmaker(bind=engine)
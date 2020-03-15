import uuid
import os
import pathlib
import urllib3

class BayonetConfig(object):
    '''Flask数据配置'''
    SECRET_KEY = str(uuid.uuid4())
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:qazxsw@123@127.0.0.1/bayonet'  # 数据库连接字符串
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TITLE = 'Bayonet 资产管理系统'
    PORT = 80  # web端口

class PortScan:
    cdn_scan = True  # 不扫描识别为cdn的IP
    shodan_api = 'xxxxxxxx'  # shodan查询api
    async_scan = False  # 是否开启常规端口服务探测
    async_scan_timeout = 30  # 异步端口扫描超时时间
    async_scan_threads = 500  # 异步协程数
    # nmap程序路径地址，可指定具体路径或设置环境变量
    nmap_search_path = ('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap')
    port_num = 500  # 超过多少个端口识别为CDN丢弃

class Oneforall:
    # 模块API配置
    # Censys可以免费注册获取API：https://censys.io/api
    censys_api_id = ''
    censys_api_secret = ''
    # Binaryedge可以免费注册获取API：https://app.binaryedge.io/account/api
    # 免费的API有效期只有1个月，到期之后可以再次生成，每月可以查询250次。
    binaryedge_api = ''
    # Chinaz可以免费注册获取API：http://api.chinaz.com/ApiDetails/Alexa
    chinaz_api = ''
    # Bing可以免费注册获取API：https://azure.microsoft.com/zh-cn/services/
    # cognitive-services/bing-web-search-api/#web-json
    bing_api_id = ''
    bing_api_key = ''
    # SecurityTrails可以免费注册获取API：https://securitytrails.com/corp/api
    securitytrails_api = ''
    # https://fofa.so/api
    fofa_api_email = ''  # fofa用户邮箱
    fofa_api_key = ''  # fofa用户key
    # Google可以免费注册获取API:
    # https://developers.google.com/custom-search/v1/overview
    # 免费的API只能查询前100条结果
    google_api_key = ''  # Google API搜索key
    google_api_cx = ''  # Google API搜索cx
    # https://api.passivetotal.org/api/docs/
    riskiq_api_username = ''
    riskiq_api_key = ''
    # Shodan可以免费注册获取API: https://account.shodan.io/register
    # 免费的API限速1秒查询1次
    shodan_api_key = ''
    # ThreatBook API 查询子域名需要收费 https://x.threatbook.cn/nodev4/vb4/myAPI
    threatbook_api_key = ''
    # VirusTotal可以免费注册获取API: https://developers.virustotal.com/reference
    virustotal_api_key = ''
    # https://www.zoomeye.org/doc?channel=api
    zoomeye_api_usermail = ''
    zoomeye_api_password = ''
    # Spyse可以免费注册获取API: https://spyse.com/
    spyse_api_token = ''
    # https://www.circl.lu/services/passive-dns/
    circl_api_username = ''
    circl_api_password = ''
    # https://www.dnsdb.info/
    dnsdb_api_key = ''
    # ipv4info可以免费注册获取API: http://ipv4info.com/tools/api/
    # 免费的API有效期只有2天，到期之后可以再次生成，每天可以查询50次。
    ipv4info_api_key = ''
    # https://github.com/360netlab/flint
    # passivedns_api_addr默认空使用http://api.passivedns.cn
    # passivedns_api_token可为空
    passivedns_api_addr = ''
    passivedns_api_token = ''
    # Github Token可以访问https://github.com/settings/tokens生成,user为Github用户名
    # 用于子域接管
    github_api_user = ''
    github_api_token = ''
    # Github子域收集模块使用
    github_email = ''
    github_password = ''
    # 路径设置
    oneforall_relpath = pathlib.Path(__file__).parent.joinpath('tools', 'oneforall')  # oneforall代码相对路径
    oneforall_abspath = oneforall_relpath.resolve()  # oneforall代码绝对路径
    oneforall_module_path = oneforall_relpath.joinpath('modules')  # oneforall模块目录
    data_storage_path = oneforall_relpath.joinpath('data')  # 数据存放目录
    result_save_path = oneforall_relpath.joinpath('results')  # 结果保存目录
    if not result_save_path.is_dir():
        result_save_path.mkdir()
    # 模块设置
    save_module_result = False  # 保存各模块发现结果为json文件(默认False)
    enable_all_module = False  # 启用所有模块(默认True)
    enable_partial_module = [('modules.search', 'baidu'),
                             ('modules.search', 'bing'),
                             ('modules.search', 'exalead'),
                             ('modules.search', 'so'),
                             ('modules.search', 'sogou'),
                             ('modules.search', 'yandex'),
                             ('modules.intelligence', 'virustotal'),
                             ('modules.dnsquery', 'srv'),
                             ('modules.datasets', 'bufferover'),
                             ('modules.datasets', 'cebaidu'),
                             ('modules.datasets', 'chinaz'),
                             ('modules.datasets', 'dnsdumpster'),
                             ('modules.datasets', 'hackertarget'),
                             ('modules.datasets', 'netcraft'),
                             ('modules.datasets', 'ptrarchive'),
                             ('modules.datasets', 'riddler'),
                             ('modules.datasets', 'robtex'),
                             ('modules.datasets', 'sitedossier'),
                             ('modules.datasets', 'threatcrowd'),
                             ('modules.certificates', 'certspotter'),
                             ('modules.certificates', 'crtsh'),
                             ('modules.certificates', 'entrust'),
                             ('modules.check', 'axfr'),
                             ('modules.check', 'cert'),
                             ]
    # 只使用ask和baidu搜索引擎收集子域
    # enable_partial_module = [('modules.search', 'ask')
    #                          ('modules.search', 'baidu')]
    module_thread_timeout = 360.0  # 每个收集模块线程超时时间(默认6分钟)
    # 爆破模块设置
    enable_brute_module = False  # 使用爆破模块(默认False)
    enable_dns_resolve = True  # DNS解析子域(默认True)
    enable_http_request = False  # HTTP请求子域(默认True)
    enable_wildcard_check = True  # 开启泛解析检测(默认True)
    enable_wildcard_deal = True  # 开启泛解析处理(默认True)
    # 爆破时使用的进程数(根据系统中CPU数量情况设置 不宜大于CPU数量 默认为系统中的CPU数量)
    brute_process_num = os.cpu_count()
    brute_coroutine_num = 1024  # 爆破时每个进程下的协程数
    # 爆破所使用的字典路径 默认data/subdomains.txt
    brute_wordlist_path = data_storage_path.joinpath('subnames.txt')
    enable_recursive_brute = False  # 是否使用递归爆破(默认禁用)
    brute_recursive_depth = 2  # 递归爆破深度(默认2层)
    # 爆破下一层子域所使用的字典路径 默认data/next_subdomains.txt
    recursive_namelist_path = data_storage_path.joinpath('next_subnames.txt')
    enable_fuzz = False  # 是否使用fuzz模式枚举域名
    fuzz_rule = ''  # fuzz域名的正则 示例：[a-z][0-9] 第一位是字母 第二位是数字
    ips_appear_maximum = 10  # 同一IP集合出现次数超过10认为是泛解析
    # 代理设置
    enable_proxy = False  # 是否使用代理(全局开关)
    proxy_all_module = False  # 代理所有模块
    proxy_partial_module = ['GoogleQuery', 'AskSearch', 'DuckDuckGoSearch',
                            'GoogleAPISearch', 'GoogleSearch', 'YahooSearch',
                            'YandexSearch', 'CrossDomainXml',
                            'ContentSecurityPolicy']  # 代理自定义的模块
    proxy_pool = [{'http': 'http://127.0.0.1:1080',
                   'https': 'https://127.0.0.1:1080'}]  # 代理池
    # proxy_pool = [{'http': 'socks5h://127.0.0.1:10808',
    #                'https': 'socks5h://127.0.0.1:10808'}]  # 代理池
    # 网络请求设置
    enable_fake_header = True  # 启用伪造请求头
    request_delay = 1  # 请求时延
    request_timeout = 30  # 请求超时
    request_verify = False  # 请求SSL验证
    # 禁用安全警告信息
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # 搜索模块设置
    enable_recursive_search = False  # 递归搜索子域
    search_recursive_times = 2  # 递归搜索层数
    # DNS解析设置
    resolver_nameservers = [
        '119.29.29.29', '182.254.116.116',  # DNSPod
        '180.76.76.76',  # Baidu DNS
        '223.5.5.5', '223.6.6.6',  # AliDNS
        '114.114.114.114', '114.114.115.115'  # 114DNS
        # '8.8.8.8', '8.8.4.4',  # Google DNS
        # '1.0.0.1', '1.1.1.1'  # CloudFlare DNS
        # '208.67.222.222', '208.67.220.220'  # OpenDNS
    ]  # 指定查询的DNS域名服务器
    resolver_timeout = 5.0  # 解析超时时间
    resolver_lifetime = 30.0  # 解析存活时间
    limit_resolve_conn = 500  # 限制同一时间解析的数量(默认500)
    # 请求端口探测设置
    # 你可以在端口列表添加自定义端口
    default_ports = [80]  # 默认使用
    small_ports = [80, 443, 8000, 8080, 8443]
    # 注意：建议大厂的域名尽量不使用大端口范围，因为大厂的子域太多，加上使用大端口范围会导致生成的
    # 请求上十万，百万，千万级，可能会导致内存不足程序奔溃，另外这样级别的请求量等待时间也是漫长的。
    # OneForAll不是一个端口扫描工具，如果要扫端口建议使用nmap,zmap之类的工具。
    large_ports = [80, 81, 280, 300, 443, 591, 593, 832, 888, 901, 981, 1010, 1080,
                   1100, 1241, 1311, 1352, 1434, 1521, 1527, 1582, 1583, 1944, 2082,
                   2082, 2086, 2087, 2095, 2096, 2222, 2301, 2480, 3000, 3128, 3333,
                   4000, 4001, 4002, 4100, 4125, 4243, 4443, 4444, 4567, 4711, 4712,
                   4848, 4849, 4993, 5000, 5104, 5108, 5432, 5555, 5800, 5801, 5802,
                   5984, 5985, 5986, 6082, 6225, 6346, 6347, 6443, 6480, 6543, 6789,
                   7000, 7001, 7002, 7396, 7474, 7674, 7675, 7777, 7778, 8000, 8001,
                   8002, 8003, 8004, 8005, 8006, 8008, 8009, 8010, 8014, 8042, 8069,
                   8075, 8080, 8081, 8083, 8088, 8090, 8091, 8092, 8093, 8016, 8118,
                   8123, 8172, 8181, 8200, 8222, 8243, 8280, 8281, 8333, 8384, 8403,
                   8443, 8500, 8530, 8531, 8800, 8806, 8834, 8880, 8887, 8888, 8910,
                   8983, 8989, 8990, 8991, 9000, 9043, 9060, 9080, 9090, 9091, 9200,
                   9294, 9295, 9443, 9444, 9800, 9981, 9988, 9990, 9999, 10000,
                   10880, 11371, 12043, 12046, 12443, 15672, 16225, 16080, 18091,
                   18092, 20000, 20720, 24465, 28017, 28080, 30821, 43110, 61600]
    ports = {'default': default_ports, 'small': small_ports, 'large': large_ports}
    # aiohttp有关配置
    verify_ssl = False
    # aiohttp 支持 HTTP/HTTPS形式的代理
    aiohttp_proxy = None  # proxy="http://user:pass@some.proxy.com"
    allow_redirects = True  # 允许请求跳转
    fake_header = True  # 使用伪造请求头
    # 为了保证请求质量 请谨慎更改以下设置
    # request_method只能是HEAD或GET,HEAD请求方法更快，但是不能获取响应体并提取从中提取
    request_method = 'GET'  # 使用请求方法，默认GET
    sockread_timeout = 5  # 每个请求socket读取超时时间，默认5秒
    sockconn_timeout = 5  # 每个请求socket连接超时时间，默认5秒
    # 限制同一时间打开的连接总数
    limit_open_conn = 100  # 默认100
    # 限制同一时间在同一个端点((host, port, is_ssl) 3者都一样的情况)打开的连接数
    limit_per_host = 10  # 0表示不限制,默认10
    subdomains_common = {'i', 'w', 'm', 'en', 'us', 'zh', 'w3', 'app', 'bbs',
                         'web', 'www', 'job', 'docs', 'news', 'blog', 'data',
                         'help', 'live', 'mall', 'blogs', 'files', 'forum',
                         'store', 'mobile'}

class UrlScan:
    timeout = 15  # HTTP访问超时
    success_status_code = [200]  # 该状态码表示为有web应用程序
    failure_status_code = [403, 401]  # 该状态码表示为根目录无应用程序，要进行目录枚举寻找二级应用程序
    threads = 10  # 多线程数，表示同时处理ports表中的记录

    subdirectory = True  # 开启二级目录查找
    subdirectory_threads = 10  # 二级目录查找线程数
    subdirectory_path = ['www', 'web', 'admin', 'user', 'login', 'manager', 'root', 'member', 'bbs', 'index', 'system',
                         'cms', 'home', 'main', 'wap', 'app', 'console', 'Web', 'download', 'view', 'public', 'tushu',
                         'sys', 'test', 'api', 'about', 'html', 'site', 'list', 'service', 'help', 'sso', 'mobile',
                         'info', 'Home', 'blog', 'file', 'auth', 'pages']

class crawlergo:
    # chromium浏览器可执行文件绝对路径
    chromium_path = '/usr/lib/chromium-browser/chromium-browser'
    max_tab_count = '5'  # 爬虫同时开启最大标签页
    filter_mode = 'smart'   # 过滤模式 simple-简单、smart-智能、strict-严格
    max_crawled_count = '200'  # 爬虫最大任务数量
    cache_path = '/Users/[username]/Library/Caches/Google/Chrome/Default/Cache/'  # 浏览器缓存地址，会自动删除提高效率
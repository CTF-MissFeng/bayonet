# 子域名搜集入库调用模块

from oneforall import OneForAll
import pathlib
import json
from config import logger
import socket
import requests
import time
from db_config import DBSession, SrcSubDomain, SrcPorts, SrcUrls
from bs4 import BeautifulSoup
import chardet
import shutil


requests.packages.urllib3.disable_warnings()
session = DBSession()

class subdomain:
    def __init__(self, domain, domain_name, shodan_api):
        self.domain = domain
        self.domain_name = domain_name
        self.shodan_api = shodan_api

    def run(self):
        logger.log('INFOR', '开始收集[%s]的子域名' % self.domain)
        result_dir = pathlib.Path(__file__).parent.resolve().joinpath('results')
        if not result_dir.is_dir():
            result_dir.mkdir(parents=True, exist_ok=True)
        try:
            one = OneForAll(target=self.domain, verify=False, valid=1, format='json')
            one.run()
        except Exception as e:
            logger.log('ERROR', '子域名搜集oneforall模块执行异常,异常信息：%s' % e)

    def subdomain_result(self):
        sub_file = pathlib.Path(__file__).parent.resolve().joinpath('results', self.domain + '_subdomain.json')
        if not sub_file.is_file():
            logger.log('ALERT', '子域名文件：%s未发现' % sub_file)
            return None
        with open(sub_file, 'r', encoding='utf-8') as file:
            tmp_str = file.read()
        try:
            tmp_dict = json.loads(tmp_str)
        except:
            logger.log('ALERT', '子域名文件:%s解析json格式错误' % sub_file)
            return None
        sql_fie = str(pathlib.Path(__file__).parent.joinpath('results'))
        try:
            shutil.rmtree(sql_fie)
        except:
            print('[-]删除子域名查找结果文件失败')
        logger.log('INFOR', '[%s]子域名搜集完成，共%s个' % (self.domain, str(len(tmp_dict))))
        IP_list = []
        for tmp in tmp_dict:
            subdomain1 = tmp['subdomain']  # 取子域名
            if self.__check_subdomain(subdomain1):
                print('[-]已存在%s子域名' % subdomain1)
                continue
            subdomain_ip = self.__domiantoip(subdomain1)  # 子域名转IP
            if subdomain_ip:  # 转ip成功
                if not self.__Deduplication(subdomain_ip, IP_list):  # 检测IP是否重复
                    ip_dict = self.__shodan_ip(subdomain_ip)  # 进行shodan查询
                    time.sleep(1)  # shodan查询延迟
                    IP_list.append(subdomain_ip)
                    if ip_dict:  # shodan查询成功
                        self.__add_srsubdomain(subdomain=subdomain1, domain=self.domain,
                                               domain_name=self.domain_name, subdomain_ip=subdomain_ip,
                                               city=ip_dict['city'])
                        print('[+]执行HTTP探测：%s' % subdomain1)
                        port_list = ip_dict['ports']  # 取所有端口进行http访问
                        tmp_urls = self.__http(subdomain1, port_list)
                        for port in port_list:
                            for key, vaule in port.items():
                                self.__add_port(subdomain=subdomain1, port=key, product=vaule['product'],
                                                version=vaule['version'], data=vaule['data'])
                        for key, value in tmp_urls.items():
                            self.__add_srcurl(subdomain=subdomain1, url=value['url'], title=value['title'])

                        continue
            info_dict = self.__check1(subdomain1)
            if info_dict:  # 不记录无IP无网站的域名
                self.__add_srsubdomain(subdomain=subdomain1, domain=self.domain,
                                       domain_name=self.domain_name, subdomain_ip='', city='')
                self.__add_srcurl(subdomain=subdomain1, url=list(info_dict.values())[0]['url'],
                                  title=list(info_dict.values())[0]['title'])
        return True

    def __add_srcurl(self, subdomain, url, title):
        sql_srcurl = SrcUrls(subdomain=subdomain, url=url, title=title)
        try:
            session.add(sql_srcurl)
            session.commit()
        except Exception as e:
            logger.log('ALERT', '子域名[%s]入url库失败,错误代码：%s' % (subdomain, e))

    def __add_port(self, subdomain, port, product, version, data):
        data1 = data.replace("\x00", "\uFFFD")
        sql_srcport = SrcPorts(subdomain=subdomain, port=port, product=product, version=version, data=data1)
        try:
            session.add(sql_srcport)
            session.commit()
        except Exception as e:
            logger.log('ALERT', '子域名[%s]入port库失败,错误代码：%s' % (subdomain, e))

    def __add_srsubdomain(self, subdomain, domain, domain_name, subdomain_ip, city):
        sql_srcsubdomain = SrcSubDomain(subdomain=subdomain, domain=domain, domain_name=domain_name, subdomain_ip=subdomain_ip, city=city)
        try:
            session.add(sql_srcsubdomain)
            session.commit()
        except Exception as e:
            logger.log('ALERT', '子域名[%s]入库失败,错误代码：%s' % (subdomain, e))

    def __domiantoip(self, subdomain):
        '''域名转IP'''
        try:
            result = socket.getaddrinfo(subdomain, None)
        except:
            print('[-] %s域名转IP失败' % subdomain)
            return None
        else:
            ip = result[0][4][0]
            return ip

    def __check1(self, subdomain):
        '''若没有端口，则默认端口访问'''
        url = 'http://%s:%s' % (subdomain, 80)
        url1 = 'https://%s:%s' % (subdomain, 443)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'zh,en-US;q=0.9,en;q=0.8,zh-TW;q=0.7,zh-CN;q=0.6'
        }
        try:
            response = requests.get(url, verify=False, timeout=20, headers=headers)
        except:
            pass
        else:
            if response.status_code == 200:
                mychar = chardet.detect(response.content)
                bianma = mychar['encoding']  # 自动识别编码
                response.encoding = bianma
                title = self.__get_title(response.text)
                http_dict = {}
                http_dict[80] = {'url': url, 'title': title}
                return http_dict
            else:
                try:
                    response = requests.get(url1, verify=False, timeout=20, headers=headers)
                except:
                    pass
                else:
                    if response.status_code == 200:
                        mychar = chardet.detect(response.content)
                        bianma = mychar['encoding']  # 自动识别编码
                        response.encoding = bianma
                        title = self.__get_title(response.text)
                        http_dict = {}
                        http_dict[443] = {'url': url, 'title': title}
                        return http_dict

    def __get_title(self, markup):
        '''获取网页标题'''
        try:
            soup = BeautifulSoup(markup, 'lxml')
        except:
            return None
        title = soup.title
        if title:
            return title.text.strip()
        h1 = soup.h1
        if h1:
            return h1.text.strip()
        h2 = soup.h2
        if h2:
            return h2.text.strip()
        h3 = soup.h3
        if h2:
            return h3.text.strip()
        desc = soup.find('meta', attrs={'name': 'description'})
        if desc:
            return desc['content'].strip()
        word = soup.find('meta', attrs={'name': 'keywords'})
        if word:
            return word['content'].strip()
        if len(markup) <= 200:
            return markup.strip()
        text = soup.text
        if len(text) <= 200:
            return text.strip()
        return None

    def __Deduplication(self, ip, iplist):
        '''IP检测是否重复'''
        for tmp in iplist:
            if ip == tmp:
                return True

    def __shodan_ip(self, ip):
        '''shodan查询host信息'''
        print('[+]shodan查询%s' % ip)
        try:
            url = 'https://api.shodan.io/shodan/host/%s?key=%s' % (ip, self.shodan_api)
            response = requests.get(url, verify=False, timeout=40)
        except:
            print('[-]shodan连接失败')
        else:
            try:
                response.encoding = 'utf-8'
                host_dict = json.loads(response.text)
            except:
                print('[-]shodan json格式解析失败')
            else:
                try:
                    ipdict = {}
                    ipdict['city'] = str(host_dict.get('country_name', '无')) + '-' + str(host_dict.get('city', '无'))
                    tmp_list = []
                    for tmp in host_dict['data']:
                        portinfo = {'product': tmp.get('product', '无'), 'version': tmp.get('version', '无'),
                                    'data': tmp.get('data', '无')[0:50]}
                        tmp_list.append({tmp.get('port', 0): portinfo})
                    ipdict['ports'] = tmp_list
                except:
                    print('[-]%s解析shodan数据失败' % ip)
                else:
                    print('[+]shodan查询%s完成' % ip)
                    return ipdict

    def __http(self, domian, ports):
        '''把所有端口进行HTTP访问测试'''
        http_dict = {}
        for port in ports:
            port_tmp = list(port.keys())[0]
            info_dict = self.__check(domian, port_tmp)
            if info_dict:
                http_dict[port_tmp] = info_dict
        return http_dict

    def __check(self, ip, port):
        '''检查HTTP服务'''
        url = 'http://%s:%s' % (ip, port)
        url1 = 'https://%s:%s' % (ip, port)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'zh,en-US;q=0.9,en;q=0.8,zh-TW;q=0.7,zh-CN;q=0.6'
            }
        try:
            response = requests.get(url, verify=False, timeout=20, headers=headers)
        except:
            pass
        else:
            if response.status_code == 200:
                mychar = chardet.detect(response.content)
                bianma = mychar['encoding']  # 自动识别编码
                response.encoding = bianma
                title = self.__get_title(markup=response.text)
                return {'url': url, 'title': title}
            else:
                try:
                    response = requests.get(url1, verify=False, timeout=20, headers=headers)
                except:
                    pass
                else:
                    if response.status_code == 200:
                        mychar = chardet.detect(response.content)
                        bianma = mychar['encoding']  # 自动识别编码
                        response.encoding = bianma
                        title = self.__get_title(markup=response.text)
                        return {'url': url, 'title': title}

    def __check_subdomain(self, subdomain):
        if session.query(SrcSubDomain).filter(SrcSubDomain.subdomain == subdomain).first():
            return True
        else:
            return False

if __name__ == '__main__':
    sub = subdomain('xx.cn', 'xx', 'xx')
    sub.run()
    sub.subdomain_result()
import sys
import socket
import requests
import json
import time
import chardet
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
sys.path.append("../../")

from db_config import DBSession, SrcSubDomain, SrcPorts, SrcUrls, shodan_key

session = DBSession()
requests.packages.urllib3.disable_warnings()

class PortScan:
    def __init__(self, results):
        self.subdomain = results.subdomain
        self.results = results

    def run(self):
        subdomain_ip = self._domiantoip()  # 子域名转IP
        if not subdomain_ip:  # 转ip不成功
            self._WriteSubdomain('失败')
            return None
        if self._readsubdomain(subdomain_ip):  # 查询IP是否已查询
            print('%s子域名对应的IP%s已查询过' % (self.subdomain, subdomain_ip))
            self._WriteSubdomain(subdomain_ip)
            return None
        result = self._shodan_ip(subdomain_ip)
        if not result:
            self._WriteSubdomain('shodan失败')
            info_dict = self._check1()
            if info_dict:
                self._add_srcurl(url=list(info_dict.values())[0]['url'],
                                 title=list(info_dict.values())[0]['title'])
            return None
        time.sleep(1)  # shodan查询延迟
        self._WriteSubdomainInfo(subdomain_ip, result['city'])
        print('[+]执行HTTP探测：%s' % self.subdomain)
        port_list = result['ports']  # 取所有端口进行http访问
        tmp_urls = self._http(port_list)
        for port in port_list:
            for key, vaule in port.items():
                self._add_port(port=key, product=vaule['product'],
                                version=vaule['version'], data=vaule['data'])
        for key, value in tmp_urls.items():
            print('[+]%s %s' % (value['url'], value['title']))
            self._add_srcurl(url=value['url'], title=value['title'])
        return True

    def _domiantoip(self):
        '''域名转IP'''
        try:
            result = socket.getaddrinfo(self.subdomain, None)
        except:
            print('[-] %s域名转IP失败' % self.subdomain)
            return None
        else:
            ip = result[0][4][0]
            return ip

    def _readsubdomain(self, ip):
        '''查询IP是否已进行shodan查询'''
        results = session.query(SrcSubDomain).filter_by(subdomain_ip=ip).first()
        return results

    def _WriteSubdomain(self, flag):
        '''修改IP状态'''
        self.results.subdomain_ip = flag
        try:
            session.commit()
        except Exception as e:
            print('修改主域名任务状态SQL错误:%s' % e)

    def _WriteSubdomainInfo(self, ip, city):
        '''修改子域名数据'''
        self.results.subdomain_ip = ip
        self.results.city = city
        try:
            session.commit()
        except Exception as e:
            print('修改主域名任务状态SQL错误:%s' % e)

    def _shodan_ip(self, ip):
        '''shodan查询host信息'''
        print('[+]shodan查询%s' % ip)
        try:
            url = 'https://api.shodan.io/shodan/host/%s?key=%s' % (ip, shodan_key)
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

    def _http(self, ports):
        '''把所有端口进行HTTP访问测试'''
        http_dict = {}
        for port in ports:
            port_tmp = list(port.keys())[0]
            info_dict = self._check(port_tmp)
            if info_dict:
                http_dict[port_tmp] = info_dict
        return http_dict

    def _check(self, port):
        '''检查HTTP服务'''
        url = 'http://%s:%s' % (self.subdomain, port)
        url1 = 'https://%s:%s' % (self.subdomain, port)
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
                title = self._get_title(markup=response.text)
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
                        title = self._get_title(markup=response.text)
                        return {'url': url, 'title': title}

    def _get_title(self, markup):
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

    def _add_srcurl(self, url, title):
        sql_srcurl = SrcUrls(subdomain=self.subdomain, url=url, title=title)
        try:
            session.add(sql_srcurl)
            session.commit()
        except Exception as e:
            print('子域名[%s]入url库失败,错误代码：%s' % (self.subdomain, e))

    def _add_port(self, port, product, version, data):
        data1 = data.replace("\x00", "\uFFFD")
        sql_srcport = SrcPorts(subdomain=self.subdomain, port=port, product=product, version=version, data=data1)
        try:
            session.add(sql_srcport)
            session.commit()
        except Exception as e:
            print('子域名[%s]入port库失败,错误代码：%s' % (self.subdomain, e))

    def _check1(self):
        '''若没有端口，则默认端口访问'''
        url = 'http://%s:%s' % (self.subdomain, 80)
        url1 = 'https://%s:%s' % (self.subdomain, 443)
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
                title = self._get_title(response.text)
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
                        title = self._get_title(response.text)
                        http_dict = {}
                        http_dict[443] = {'url': url, 'title': title}
                        return http_dict

def ReadDomain():
    '''读取子域名任务, 一次读取一条记录'''
    results = session.query(SrcSubDomain).filter_by(subdomain_ip='').first()
    return results

def action(results):
    '''子线程执行'''
    sub = PortScan(results)
    sub.run()

def main():
    '''主方法'''
    pool = ThreadPoolExecutor(max_workers=1)
    while True:
        results = ReadDomain()
        if not results:
            time.sleep(30)  # 没有任务延迟点时间
        else:
            print('[+]开始查询子域名%s的端口服务' % results.subdomain)
            futurel = pool.submit(action, results)
            futurel.result()

    pool.shutdown()

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 2:28 PM
# @Author  : w8ay
# @File    : output.py
import sys
from threading import Lock
from urllib.parse import *
from colorama import Fore
sys.path.append("../../../../")

from W13SCAN.lib.data import Share, KB
from db_config import DBSession, SrcVulnerabilitie

session = DBSession()

def scan_write(plugin, url, payload, raw, flag, scan_name):
    subdomain = Rsubdomain(url)
    new_scan = SrcVulnerabilitie(subdomain=subdomain, plugin=plugin, url=url, payload=payload, raw=raw, flag=flag, scan_name=scan_name)
    session.add(new_scan)
    try:
        session.commit()
    except Exception as e:
        session.rollback()
        print('新增漏洞扫描结果失败; %s' % e)

def Rsubdomain(url):
    '''提取子域名'''
    result = urlparse(url)
    return result.hostname

class OutPut(object):

    def __init__(self):
        self.collect = []
        self.lock = Lock()
        self.result_set = set()

    def set(self, value):
        '''
        存储相同的结果，防止重复
        :param value:
        :return:
        '''
        if value not in self.result_set:
            self.result_set.add(value)
            return True
        return False

    def count(self):
        self.lock.acquire()
        count = len(self.collect)
        self.lock.release()
        return count

    def success(self, url, plugin='unknown', **kw):
        report = {
            "url": url,
            "plugin": plugin
        }
        scan_plugin = plugin
        scan_url = url
        scan_payload = ''
        report.update(kw)
        self.lock.acquire()
        self.collect.append(report)
        self.log("[{}]".format(report["plugin"]), Fore.RED)
        del report["plugin"]
        raw = None
        if "raw" in report:
            if isinstance(report['raw'], str):
                raw = [report['raw']]
            elif isinstance(report['raw'], list):
                raw = report['raw']
            del report['raw']
        for k, v in report.items():
            if isinstance(v, list):
                for i in v:
                    scan_payload += i + '<br/>'
                    self.log(i)
            elif isinstance(v, str):
                scan_payload += k + '  ' + v + '<br/>'
                if len(k) < 15:
                    msg = "{0}{1}{2}".format(k, " " * (15 - len(k)), str(v).strip())
                else:
                    msg = "{0}{1}{2}".format(k, " " * 4, str(v).strip())
                self.log(msg)
        self.log(' ')
        scan_raw = ''
        if raw:
            index = 0
            scan_raw = raw[0]
            for i in raw:
                self.log("#{0} 请求包".format(index))
                self.log(i)
                self.log(" ")
                index += 1
        if not scan_plugin == '基础信息收集':
            scan_write(scan_plugin, scan_url, scan_payload, scan_raw, False, 'w13scan')
        self.lock.release()

    def log(self, msg, color=Fore.YELLOW):
        width = KB["console_width"][0]
        outputs = []
        msgs = msg.split('\n')
        for i in msgs:
            line = i
            while len(line) >= width:
                _ = line[:width]
                outputs.append(_)
                # Share.dataToStdout('\r' + _ + ' ' * (width - len(msg)) + '\n\r')
                line = line[width:]
            outputs.append(line)
        for i in outputs:
            Share.dataToStdout('\r' + color + i + ' ' * (width - len(i)) + '\n\r')

    def output(self):
        '''
        todo output file
        :return:
        '''
        pass


out = OutPut()

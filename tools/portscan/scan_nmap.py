import nmap

from web.utils.logs import logger
from config import PortScan

def Nmap_Portscan(ip, port_info_list): # Nmap扫描
    logger.log('INFOR', f'nmap[{ip}]开始扫描')
    try:
        nm = nmap.PortScanner(nmap_search_path=PortScan.nmap_search_path)
    except Exception as e:
        logger.log('ERROR', f'nmap程序未找到:{e}')
        return None
    ports = ','.join([str(tmp) for tmp in port_info_list])
    nm.scan(hosts=ip, ports=ports, arguments='-Pn -T 4 -sV --version-intensity=3')
    try:
        port_list = nm[ip]['tcp'].keys()
    except Exception as e:
        logger.log('ERROR', f'nmap扫描端口异常{e}')
        return None
    else:
        port_dict = {}
        for port in port_list:
            if nm[ip].has_tcp(port):
                port_info = nm[ip]['tcp'][port]
                state = port_info.get('state', 'no')
                if state == 'open':
                    name = port_info.get('name', '')
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')
                    port_dict[port] = {'ip': ip, 'port': port, 'name': name, 'product': product, 'version': version}
                    logger.log('INFOR', f'nmap扫描:{ip}:{port} {name} {product} {version}')
        logger.log('INFOR', f'nmap[{ip}]扫描完成')
        return port_dict

if __name__ == '__main__':
    pass
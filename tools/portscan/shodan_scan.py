from web.utils.logs import logger

def scan(ip, API):
    logger.log('INFOR', f'开始Shodan端口扫描[{ip}]')
    try:
        ipinfo = API.host(ip)
    except Exception as e:
        logger.log('ALERT', f'Shodan查询[{ip}]失败，原因:{e}')
        return []
    port_list = ipinfo['data']
    result_list = []
    for tmp in port_list:
        port = tmp.get('port', '0')
        if port:
            result_list.append(port)
    logger.log('INFOR', f'Shodan端口扫描完成;[{ip}] {result_list}')
    return result_list

if __name__ == '__main__':
    pass

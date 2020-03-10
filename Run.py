import multiprocessing

import tools.oneforall.Run
import tools.portscan.Run
import tools.urlscan.Run
import tools.scan.Chromium.Run

def worker():
    subdomain_worker = multiprocessing.Process(target=tools.oneforall.Run.main, name='subdomain')
    subdomain_worker.start()

    portscan_worker = multiprocessing.Process(target=tools.portscan.Run.port_main, name='portscan')
    portscan_worker.start()

    urlscan_worker = multiprocessing.Process(target=tools.urlscan.Run.urlscan_main, name='urlscan')
    urlscan_worker.start()

    chromium_worker = multiprocessing.Process(target=tools.scan.Chromium.Run.main, name='chromiumscan')
    chromium_worker.start()

if __name__ == '__main__':
    worker()
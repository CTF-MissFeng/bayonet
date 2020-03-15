from flask import render_template, request

from web import APP, TITLE
from web.utils.auxiliary import login_required, scan_write

@APP.route('/html/src/domain')
@login_required
def html_src_domain():
    '''主域名添加任务页面'''
    return render_template('src/domain.html', title=TITLE)

@APP.route('/html/src/ports')
@login_required
def html_src_ports():
    '''端口管理界面'''
    return render_template('src/ports.html', title=TITLE)

@APP.route('/html/src/subdomain')
@login_required
def html_src_subdomain():
    '''子域名管理界面'''
    return render_template('src/subdomain.html', title=TITLE)

@APP.route('/html/src/urls')
@login_required
def html_src_urls():
    '''url扫描任务界面'''
    return render_template('src/urls.html', title=TITLE)

@APP.route('/html/src/urls1')
@login_required
def html_src_urls1():
    '''url管理界面'''
    return render_template('src/urls1.html', title=TITLE)

@APP.route('/html/src/scan')
@login_required
def html_src_scan():
    '''漏洞管理界面'''
    return render_template('src/scan.html', title=TITLE)

@APP.route('/html/src/scan_success')
@login_required
def html_src_scan_success():
    '''已提交漏洞管理界面'''
    return render_template('src/scan_success.html', title=TITLE)

@APP.route('/webhook', methods=['POST'])
def xray_webhook():
    try:
        vuln = request.json
    except:
        pass
    else:
        if 'create_time' in vuln:
            plugin = vuln.get('plugin', '') + '--' +vuln.get('vuln_class', '')
            url = vuln['detail'].get('url')
            payload = vuln['detail'].get('payload', '')
            raw = vuln['detail'].get('request', '')
            print(f'新漏洞：{url}')
            scan_write(plugin, url, payload, raw, flag=False, scan_name='xray')
    finally:
        return "ok"
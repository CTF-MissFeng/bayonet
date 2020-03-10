from flask import session, url_for, render_template, jsonify

from web import APP, TITLE
from web.utils.auxiliary import login_required, src_count

@APP.route('/html/home/index')
@login_required
def html_home_index():
    '''框架首页'''
    return render_template('/home/index.html', username=session['username'], title=TITLE)

@APP.route('/html/home/home')
@login_required
def html_home():
    '''主页'''
    dict1 = src_count()
    return render_template('home/welcome.html', title=TITLE, count=dict1)

@APP.route('/home/init')
@login_required
def api_menu_init():
    '''菜单栏目'''
    caching_menu = {'clearUrl': url_for('api_caching_clear')}  # 缓存菜单
    home_menu = {'title': '主页', 'icon': 'fa fa-home', 'href': url_for('html_home')}  # 主页菜单
    logo_menu = {'title': 'Bayonet', 'image': url_for('static', filename='images/logo.png'), 'href': ''}  # logo菜单
    assets_menu = {'title': '资产管理', 'icon': 'fa fa-address-book', 'child': [
        {'title': '添加任务', 'href': url_for('html_src_domain'), 'icon': 'fa fa-tachometer', 'target': '_self'},
        {'title': '子域名管理', 'href': url_for('html_src_subdomain'), 'icon': 'fa fa-globe', 'target': '_self'},
        {'title': '端口服务管理', 'href': url_for('html_src_ports'), 'icon': 'fa fa-cube', 'target': '_self'},
        {'title': 'URL管理', 'href': url_for('html_src_urls1'), 'icon': 'fa fa-paw', 'target': '_self'},
        {'title': '扫描任务管理', 'href': url_for('html_src_urls'), 'icon': 'fa fa-plus-square', 'target': '_self'},
        {'title': '漏洞管理', 'href': url_for('html_src_scan'), 'icon': 'fa fa-user-secret', 'target': '_self'},
        {'title': '已提交漏洞管理', 'href': url_for('html_src_scan_success'), 'icon': 'fa fa-bug', 'target': '_self'},
    ]}
    system_menu = {'title': '系统管理', 'icon': 'fa fa-gears', 'child': [
        {'title': '用户管理', 'href': '', 'icon': 'fa fa-user', 'target': '_self', 'child': [
            {'title': '用户管理', 'href': url_for('html_user_manager'), 'icon': 'fa fa-users', 'target': '_self'},
            {'title': '新增用户', 'href': url_for('html_user_add'), 'icon': 'fa fa-user-plus', 'target': '_self'}]},

        {'title': '日志管理', 'href': '', 'icon': 'fa fa-building-o', 'target': '_self', 'child': [
            {'title': '操作日志', 'href': url_for('html_user_logs'), 'icon': 'fa fa-area-chart', 'target': '_self'},
            {'title': '登录日志', 'href': url_for('html_user_loginlog'), 'icon': 'fa fa-bar-chart', 'target': '_self'}
        ]}
    ]}
    menu_dict = {'clearInfo': caching_menu, 'homeInfo': home_menu, 'logoInfo': logo_menu, 'menuInfo': {
            'a-assets': assets_menu, 'c-system': system_menu}}  # 菜单按照字母排序
    return jsonify(menu_dict)

@APP.route('/home/clear')
@login_required
def api_caching_clear():
    return jsonify({'code': 1, 'msg': '服务端缓存清理成功'})

@APP.errorhandler(404)
def page_not_found(e):
    return render_template('error/404.html'), 404

@APP.errorhandler(500)
def internal_server_error(e):
    return render_template('error/500.html'), 500

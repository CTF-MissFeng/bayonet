from flask import session, make_response, redirect, url_for, render_template, jsonify
from io import BytesIO

from web import APP, TITLE
from web.utils.captcha.captcha import get_verify_code
from web.utils.auxiliary import login_required, addlog, logger, src_count
from web.models import User

@APP.route('/api/user/captcha')
def api_get_code():
    '''图片验证码接口'''
    image, code = get_verify_code()
    buf = BytesIO()
    image.save(buf, 'jpeg')
    buf_str = buf.getvalue()
    response = make_response(buf_str)
    response.headers['Content-Type'] = 'image/jpeg'
    session['code'] = code  # 在session中保存验证码结果
    return response

@APP.route('/')
def html_user_login():
    '''user login页面'''
    if 'status' in session:
        return redirect(url_for('html_home_index'), 302)
    return render_template('user/login.html', title=TITLE)

@APP.route('/api/user/logout')
@login_required
def api_user_logout():
    '''用户注销'''
    addlog(session.get('username'), session.get('login_ip'), '注销登录成功')
    logger.log('INFOR', '用户[%s]注销成功' % session.get('username'))
    session.pop('status')
    session.pop('username')
    session.pop('login_ip')
    return redirect(url_for('html_user_login'), 302)

@APP.route('/html/home/index')
@login_required
def html_home_index():
    '''框架首页'''
    return render_template('/home/index.html', username=session['username'], title=TITLE)

@APP.route('/html/user/setting')
@login_required
def html_user_setting():
    '''用户资料修改'''
    user_query = User.query.filter(User.username == session.get('username')).first()  # 查询该用户信息
    if not user_query:
        return redirect(url_for('html_user_login'), 302)
    info_dict = {
        'username': session.get('username'),
        'xingming': user_query.name,
        'phone': user_query.phone,
        'email': user_query.email,
        'remark': user_query.remark
    }
    return render_template('user/setting.html', user=info_dict, title=TITLE)

@APP.route('/html/user/password')
@login_required
def html_user_password():
    '''修改用户密码'''
    return render_template('user/userpassword.html', title=TITLE)

@APP.route('/html/user/useradd')
@login_required
def html_user_add():
    '''新增用户'''
    return render_template('user/user-add.html', title=TITLE)

@APP.route('/html/user/usermanager')
@login_required
def html_user_manager():
    '''用户管理'''
    return render_template('user/user-manager.html', title=TITLE)

@APP.route('/html/user/logs')
@login_required
def html_user_logs():
    '''用户日志操作查询页面'''
    return render_template('user/userlogs.html')

@APP.route('/html/user/loginlog')
@login_required
def html_user_loginlog():
    '''用户日志登录查询页面'''
    return render_template('user/loginlogs.html')

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
        {'title': '端口服务管理', 'href': url_for('html_src_ports'), 'icon': 'fa fa-puzzle-piece', 'target': '_self'},
        {'title': 'URL管理', 'href': url_for('html_src_urls'), 'icon': 'fa fa-puzzle-piece', 'target': '_self'},
        {'title': '漏洞管理', 'href': url_for('html_src_scan'), 'icon': 'fa fa-puzzle-piece', 'target': '_self'},
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

@APP.route('/html/src/domain')
@login_required
def html_src_domain():
    '''主域名添加任务页面'''
    return render_template('src/domain.html', title=TITLE)

@APP.route('/html/src/subdomain')
@login_required
def html_src_subdomain():
    '''子域名管理界面'''
    return render_template('src/subdomain.html', title=TITLE)

@APP.route('/html/src/ports')
@login_required
def html_src_ports():
    '''端口管理界面'''
    return render_template('src/ports.html', title=TITLE)

@APP.route('/html/src/urls')
@login_required
def html_src_urls():
    '''url管理界面'''
    return render_template('src/urls.html', title=TITLE)

@APP.route('/html/src/scan')
@login_required
def html_src_scan():
    '''漏洞管理界面'''
    return render_template('src/scan.html', title=TITLE)

@APP.route('/html/home/home')
@login_required
def html_home():
    '''主页'''
    dict1 = src_count()
    return render_template('home/welcome.html', title=TITLE, count=dict1)
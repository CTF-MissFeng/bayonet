from flask import session, make_response, redirect, url_for, render_template
from io import BytesIO

from web import APP, TITLE
from web.utils.captcha.captcha import get_verify_code
from web.utils.auxiliary import login_required, addlog, logger
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
    logger.log('INFOR', f"用户[{session.get('username')}]注销成功")
    session.pop('status')
    session.pop('username')
    session.pop('login_ip')
    return redirect(url_for('html_user_login'), 302)

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
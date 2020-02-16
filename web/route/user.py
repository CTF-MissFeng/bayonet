from flask_restful import reqparse, Resource
from flask import session, request, json
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from web.utils.logs import logger
from web.models import User, UserLoginLogs, UserLogs
from web import DB, APP
from web.utils.auxiliary import addlog

class UserLogin(Resource):
    '''user login类'''
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("username", type=str, required=True, location='json')
        self.parser.add_argument("password", type=str, required=True, location='json')
        self.parser.add_argument("captcha", type=str, required=True, location='json')
        self.parser.add_argument("rememberMe", type=bool, location='json')

    def post(self):
        '''登录接口'''
        args = self.parser.parse_args()
        key_username = args.username
        key_password = args.password
        key_vercode = args.captcha
        key_remember = args.rememberMe
        if 'code' not in session:  # 判断session中是否有验证码
            return {'result': {'status_code': 202}}
        if session.get('code').lower() != key_vercode.lower():  # 判断验证码结果
            logger.log('INFOR', '验证码错误，用户名[%s]' % key_username)
            session.pop('code')
            return {'result': {'status_code': 202}}
        session.pop('code')
        user_query = User.query.filter(User.username == key_username).first()  # 进行数据库查询
        if not user_query:  # 若不存在此用户
            logger.log('INFOR', '用户[%s]登录失败，原因：用户名不存在，IP[%s]' % (key_username, request.remote_addr))
            return {'result': {'status_code': 201}}
        if check_password_hash(user_query.password, key_password):  # 进行密码核对
            session['status'] = True  # 登录成功设置session
            session['username'] = key_username
            try:  # 获取客户端IP地址
                login_ip = request.headers['X-Forwarded-For'].split(',')[0]
            except:
                login_ip = request.remote_addr
            session['login_ip'] = login_ip
            useragent = request.user_agent.string
            userlogins = UserLoginLogs(username=key_username, login_ip=login_ip, useragent=useragent)
            try:
                DB.session.add(userlogins)
                DB.session.commit()
            except Exception as e:
                logger.log('ALERT', '用户登录接口-SQL错误:%s' % e)
            logger.log('INFOR', '用户[%s]登录成功，IP[%s]' % (key_username, login_ip))
            addlog(key_username, login_ip, '登录系统成功')
            if key_remember:  # 若选择了记住密码选项
                session.permanent = True
                APP.permanent_session_lifetime = datetime.timedelta(weeks=7)  # 设置session到期时间7天
            return {'result': {'status_code': 200}}
        else:
            logger.log('INFOR', '用户[%s]登录失败，密码错误;IP[%s]' % (key_username, request.remote_addr))
            return {'result': {'status_code': 201}}

class UserSetting(Resource):
    '''user 修改用户资料类'''
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("xingming", type=str, required=True, location='json')
        self.parser.add_argument("phone", type=str, required=True, location='json')
        self.parser.add_argument("email", type=str, required=True, location='json')
        self.parser.add_argument("remark", type=str, location='json')

    def post(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_xingming = args.xingming
        key_phone = args.phone
        key_email = args.email
        key_remark = args.remark
        user_query = User.query.filter(User.username == session.get('username')).first()
        if not user_query:
            return {'result': {'status_code': 500}}
        user_query.name = key_xingming
        user_query.phone = key_phone
        user_query.email = key_email
        if key_remark:
            user_query.remark = key_remark
        try:
            DB.session.commit()
        except Exception as e:
            logger.log('ALERT', '用户修改资料接口SQL错误:%s' % e)
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), '修改用户资料成功')
        logger.log('INFOR', '[%s]修改用户资料成功' % session.get('username'))
        return {'result': {'status_code': 200}}

class UserPassword(Resource):
    '''user 修改用户密码类'''
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("old_password", type=str, required=True, location='json')
        self.parser.add_argument("new_password", type=str, required=True, location='json')
        self.parser.add_argument("again_password", type=str, required=True, location='json')

    def post(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_old_password = args.old_password
        key_new_password = args.new_password
        key_again_password = args.again_password
        if key_new_password != key_again_password:
            return {'result': {'status_code': 203}}
        if key_old_password == key_new_password:
            return {'result': {'status_code': 204}}
        user_query = User.query.filter(User.username == session.get('username')).first()
        if not user_query:
            return {'result': {'status_code': 500}}
        if not check_password_hash(user_query.password, key_old_password):  # 检测原密码
            addlog(session.get('username'), session.get('login_ip'), '修改用户密码失败，原密码不正确')
            return {'result': {'status_code': 201}}
        user_query.password = generate_password_hash(key_new_password)  # 更新密码
        try:
            DB.session.commit()
        except Exception as e:
            logger.log('ALERT', '用户修改密码接口SQL错误:%s' % e)
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), '修改用户密码成功')
        logger.log('INFOR', '[%s]修改用户密码成功' % session.get('username'))
        return {'result': {'status_code': 200}}

class UserAdd(Resource):
    '''user 新增用户类'''
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("username", type=str, required=True, location='json')
        self.parser.add_argument("password", type=str, required=True, location='json')
        self.parser.add_argument("xingming", type=str, required=True, location='json')
        self.parser.add_argument("phone", type=str, required=True, location='json')
        self.parser.add_argument("email", type=str, required=True, location='json')
        self.parser.add_argument("remark", type=str, required=True, location='json')

    def post(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_username = args.username
        key_password = args.password
        key_xingming = args.xingming
        key_phone = args.phone
        key_email = args.email
        key_remark = args.remark
        if session['username'] != 'root':
            return {'result': {'status_code': 202}}
        user_query = User.query.filter(User.username == key_username).first()
        if user_query:  # 用户名存在
            return {'result': {'status_code': 201}}
        user1 = User(username=key_username,
                         password=key_password, name=key_xingming, phone=key_phone, email=key_email, remark=key_remark)
        DB.session.add(user1)
        try:
            DB.session.commit()
        except Exception as e:
            logger.log('ALERT', '用户新增接口SQL错误:%s' % e)
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), '新增用户成功，用户为:%s' % key_username)
        return {'result': {'status_code': 200}}

class UserManager(Resource):
    '''user 用户管理类'''
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.parser.add_argument("username", type=str)

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = User.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = User.query.paginate(1, 20, False).items
            else:
                paginate = User.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = User.query.paginate(1, 20, False).items
            else:
                if 'username' not in search_dict or 'name' not in search_dict:  # 查询参数有误
                    paginate = User.query.paginate(1, 20, False).items
                else:
                    paginate1 = User.query.filter(
                            User.username.like("%" + search_dict['username'] + "%") if search_dict['username'] is not None else "",
                            User.name.like("%" + search_dict['name'] + "%") if search_dict['name'] is not None else "")
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items
        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['id'] = i.id
                data1['username'] = i.username
                data1['name'] = i.name
                data1['phone'] = i.phone
                data1['email'] = i.email
                data1['remark'] = i.remark
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def post(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_username = args.username
        if not key_username:
            return {'result': {'status_code': 500}}
        if 'root' == key_username:  # 不能删除root用户
            return {'result': {'status_code': 201}}
        user_query = User.query.filter(User.username == key_username).first()
        if not user_query:  # 删除的用户不存在
            return {'result': {'status_code': 202}}
        DB.session.delete(user_query)
        try:
            DB.session.commit()
        except:
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), '删除用户:%s 成功' % key_username)
        return {'result': {'status_code': 200}}

class UserLog(Resource):
    '''user 用户操作日志类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = UserLogs.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = UserLogs.query.paginate(1, 20, False).items
            else:
                paginate = UserLogs.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = UserLogs.query.paginate(1, 20, False).items
            else:
                if 'username' not in search_dict or 'log_ip' not in search_dict:  # 查询参数有误
                    paginate = UserLogs.query.paginate(1, 20, False).items
                else:
                    paginate1 = UserLogs.query.filter(
                            UserLogs.username.like("%" + search_dict['username'] + "%") if search_dict['username'] is not None else "",
                            UserLogs.login_ip.like("%" + search_dict['log_ip'] + "%") if search_dict['log_ip'] is not None else "")
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items
        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['id'] = i.id
                data1['username'] = i.username
                data1['log_ip'] = i.login_ip
                data1['log_time'] = i.login_time
                data1['log_text'] = i.logtxt
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

class UserLoginLog(Resource):
    '''user 用户登录日志类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = UserLoginLogs.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = UserLoginLogs.query.paginate(1, 20, False).items
            else:
                paginate = UserLoginLogs.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = UserLoginLogs.query.paginate(1, 20, False).items
            else:
                if 'username' not in search_dict or 'log_ip' not in search_dict:  # 查询参数有误
                    paginate = UserLoginLogs.query.paginate(1, 20, False).items
                else:
                    paginate1 = UserLoginLogs.query.filter(
                            UserLoginLogs.username.like("%" + search_dict['username'] + "%") if search_dict['username'] is not None else "",
                            UserLoginLogs.login_ip.like("%" + search_dict['log_ip'] + "%") if search_dict['log_ip'] is not None else "")
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items
        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['id'] = i.id
                data1['username'] = i.username
                data1['login_ip'] = i.login_ip
                data1['login_time'] = i.login_time
                data1['useragent'] = i.useragent
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata
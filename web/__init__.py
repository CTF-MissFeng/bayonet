from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api

from WebConfig import Config

APP = Flask(__name__)
APP.config.from_object(Config)
DB = SQLAlchemy(APP)
API = Api(APP)

TITLE = APP.config['TITLE']

from web.route import html
from web.route.user import UserLogin, UserSetting, UserPassword, UserAdd, UserManager, UserLog, UserLoginLog
from web.route.src import SrcDomainAPI, SrcSubDomainAPI, SrcPortsAPI, SrcUrlsAPI, SrcScanAPI

API.add_resource(UserLogin, '/api/user/login', endpoint='api_user_login')
API.add_resource(UserSetting, '/api/user/setting', endpoint='api_user_setting')
API.add_resource(UserPassword, '/api/user/password', endpoint='api_user_password')
API.add_resource(UserAdd, '/api/user/add', endpoint='api_user_add')
API.add_resource(UserManager, '/api/user/manager', endpoint='api_user_manager')
API.add_resource(UserLog, '/api/user/logs', endpoint='api_user_logs')
API.add_resource(UserLoginLog, '/api/user/loginlog', endpoint='api_user_loginlog')

API.add_resource(SrcDomainAPI, '/api/src/domain', endpoint='api_src_domain')
API.add_resource(SrcSubDomainAPI, '/api/src/subdomain', endpoint='api_src_subdomain')
API.add_resource(SrcPortsAPI, '/api/src/ports', endpoint='api_src_ports')
API.add_resource(SrcUrlsAPI, '/api/src/urls', endpoint='api_src_urls')
API.add_resource(SrcScanAPI, '/api/src/scan', endpoint='api_src_scan')
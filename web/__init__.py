from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api

from config import BayonetConfig

APP = Flask(__name__)
APP.config.from_object(BayonetConfig)
DB = SQLAlchemy(APP)
API = Api(APP)
TITLE = APP.config['TITLE']

from web.route.user import html
from web.route.home import html
from web.route.src import html

from web.route.user.api import UserLogin, UserSetting, UserPassword, UserAdd, UserManager, UserLog, UserLoginLog
from web.route.src.api import SrcDomainAPI, SrcPortsAPI, SrcSubDomainAPI, SrcUrlsAPI, SrcUrls1API, SrcScanAPI, SrcScanSuccessAPI

API.add_resource(UserLogin, '/api/user/login', endpoint='api_user_login')
API.add_resource(UserSetting, '/api/user/setting', endpoint='api_user_setting')
API.add_resource(UserPassword, '/api/user/password', endpoint='api_user_password')
API.add_resource(UserAdd, '/api/user/add', endpoint='api_user_add')
API.add_resource(UserManager, '/api/user/manager', endpoint='api_user_manager')
API.add_resource(UserLog, '/api/user/logs', endpoint='api_user_logs')
API.add_resource(UserLoginLog, '/api/user/loginlog', endpoint='api_user_loginlog')

API.add_resource(SrcDomainAPI, '/api/src/domain', endpoint='api_src_domain')
API.add_resource(SrcPortsAPI, '/api/src/ports', endpoint='api_src_ports')
API.add_resource(SrcSubDomainAPI, '/api/src/subdomain', endpoint='api_src_subdomain')
API.add_resource(SrcUrlsAPI, '/api/src/urls', endpoint='api_src_urls')
API.add_resource(SrcUrls1API, '/api/src/urls1', endpoint='api_src_urls1')
API.add_resource(SrcScanAPI, '/api/src/scan', endpoint='api_src_scan')
API.add_resource(SrcScanSuccessAPI, '/api/src/scansuccess', endpoint='api_src_scan_success')
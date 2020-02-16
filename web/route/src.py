from flask_restful import reqparse, Resource
from flask import session, escape, json

from web import DB, APP
from web.utils.auxiliary import addlog, shodan_check
from web.models import SrcDomain, SrcSubDomain, SrcPorts, SrcUrls, SrcVulnerabilitie
from web.utils.logs import logger


class SrcDomainAPI(Resource):
    '''src 主域名任务管理类'''
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("domain", type=str, location='json')
        self.parser.add_argument("domain_name", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def post(self):
        '''添加任务'''
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        if not APP.config.get('SHODAN_KEY'):
            return {'result': {'status_code': 301}}
        if not shodan_check(APP.config.get('SHODAN_KEY')):
            return {'result': {'status_code': 202}}
        args = self.parser.parse_args()
        key_domain = escape(args.domain.replace('/', ''))
        key_domain_name = escape(args.domain_name)
        if not key_domain or not key_domain_name:
            return {'result': {'status_code': 500}}
        src_query = SrcDomain.query.filter(SrcDomain.domain == key_domain).first()
        if src_query:  # 已经存在domain任务
            return {'result': {'status_code': 201}}
        SrcDomain1 = SrcDomain(domain=key_domain, domain_name=key_domain_name)
        DB.session.add(SrcDomain1)
        try:
            DB.session.commit()
        except Exception as e:
            logger.log('ALERT', '主域名添加任务接口SQL错误:%s' % e)
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), '添加主域名任务成功，主域名为：%s' % key_domain)
        logger.log('INFOR', '添加主域名任务成功-主域名[%s]-厂商[%s]' % (key_domain, key_domain_name))
        return {'result': {'status_code': 200}}

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcDomain.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcDomain.query.paginate(1, 20, False).items
            else:
                paginate = SrcDomain.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcDomain.query.paginate(1, 20, False).items
            else:
                if 'domain' not in search_dict or 'domain_name' not in search_dict:  # 查询参数有误
                    paginate = SrcDomain.query.paginate(1, 20, False).items
                else:
                    paginate1 = SrcDomain.query.filter(
                            SrcDomain.domain.like("%" + search_dict['domain'] + "%") if search_dict['domain'] is not None else "",
                            SrcDomain.domain_name.like("%" + search_dict['domain_name'] + "%") if search_dict['domain_name'] is not None else "")
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items
        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['id'] = i.id
                data1['domain'] = i.domain
                data1['domain_name'] = i.domain_name
                data1['domain_time'] = i.domain_time
                data1['flag'] = i.flag
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_domain = escape(args.domain)
        domain_query = SrcDomain.query.filter(SrcDomain.domain == key_domain).first()
        if not domain_query:  # 删除的domain不存在
            return {'result': {'status_code': 202}}
        DB.session.delete(domain_query)
        DB.session.commit()
        addlog(session.get('username'), session.get('login_ip'), '删除主域名:%s 成功' % key_domain)
        logger.log('INFOR', '删除主域名成功，[%s]' % key_domain)
        return {'result': {'status_code': 200}}

class SrcSubDomainAPI(Resource):
    '''src 子域名管理类'''
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
        count = SrcSubDomain.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcSubDomain.query.paginate(1, 20, False).items
            else:
                paginate = SrcSubDomain.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcSubDomain.query.paginate(1, 20, False).items
            else:
                if 'domain' not in search_dict or 'domain_name' not in search_dict:  # 查询参数有误
                    paginate = SrcSubDomain.query.paginate(key_page, key_limit, False).items
                else:
                    paginate1 = SrcSubDomain.query.filter(
                        SrcSubDomain.domain.like("%" + search_dict['domain'] + "%") if search_dict[
                        'domain'] is not None else "", SrcSubDomain.domain_name.like("%" + search_dict['domain_name'] + "%") if search_dict[
                        'domain_name'] is not None else "")
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items

        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['domain'] = i.domain
                data1['domain_name'] = i.domain_name
                data1['subdomain'] = i.subdomain
                data1['domain_ip'] = i.subdomain_ip
                data1['city'] = i.city
                data1['domian_time'] = i.subdomain_time
                data.append(data1)
                jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

class SrcPortsAPI(Resource):
    '''src 端口管理类'''
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
        count = SrcPorts.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcPorts.query.paginate(1, 20, False).items
            else:
                paginate = SrcPorts.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcPorts.query.paginate(1, 20, False).items
            else:
                if 'subdomain' not in search_dict or 'product' not in search_dict:  # 查询参数有误
                    paginate = SrcPorts.query.paginate(key_page, key_limit, False).items
                else:
                    paginate1 = SrcPorts.query.filter(
                        SrcPorts.subdomain.like("%" + search_dict['subdomain'] + "%") if search_dict[
                        'subdomain'] is not None else "", SrcPorts.product.like("%" + search_dict['product'] + "%") if search_dict[
                        'product'] is not None else "")
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items

        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['id'] = i.id
                data1['subdomain'] = i.subdomain
                data1['port'] = i.port
                data1['product'] = i.product
                data1['version'] = i.version
                data1['data'] = i.data
                data1['flag'] = i.flag
                data1['porttime'] = i.porttime
                data.append(data1)
                jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

class SrcUrlsAPI(Resource):
    '''src url管理类'''
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
        count = SrcUrls.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcUrls.query.paginate(1, 20, False).items
            else:
                paginate = SrcUrls.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcUrls.query.paginate(1, 20, False).items
            else:
                if 'subdomain' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcUrls.query.paginate(key_page, key_limit, False).items
                else:
                    paginate1 = SrcUrls.query.filter(
                        SrcUrls.subdomain.like("%" + search_dict['subdomain'] + "%") if search_dict[
                        'subdomain'] is not None else "", SrcUrls.url.like("%" + search_dict['url'] + "%") if search_dict[
                        'url'] is not None else "")
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items

        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['id'] = i.id
                data1['subdomain'] = i.subdomain
                data1['url'] = i.url
                data1['title'] = escape(i.title)
                data1['reptile'] = i.reptile
                data1['w13scan'] = i.w13scan
                data1['xray'] = i.xray
                data.append(data1)
                jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

class SrcScanAPI(Resource):
    '''src 漏洞管理类'''
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.parser.add_argument("time", type=str)

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcVulnerabilitie.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcVulnerabilitie.query.paginate(1, 20, False).items
            else:
                paginate = SrcVulnerabilitie.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcVulnerabilitie.query.paginate(1, 20, False).items
            else:
                if 'plugin' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcVulnerabilitie.query.paginate(key_page, key_limit, False).items
                else:
                    paginate1 = SrcVulnerabilitie.query.filter(
                        SrcVulnerabilitie.plugin.like("%" + search_dict['plugin'] + "%") if search_dict[
                        'plugin'] is not None else "", SrcVulnerabilitie.url.like("%" + search_dict['url'] + "%") if search_dict[
                        'url'] is not None else "")
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items

        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['id'] = i.id
                data1['plugin'] = i.plugin
                data1['url'] = escape(i.url)
                data1['payload'] = escape(i.payload)
                data1['raw'] = i.raw.replace('\n', '<br/>')
                data1['scan_name'] = i.scan_name
                data1['time'] = i.time
                flag = '未提交'
                if i.flag:
                    flag = '已提交'
                data1['flag'] = flag
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
        key_time = args.time
        scan_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_time).first()
        if not scan_query:
            return {'result': {'status_code': 500}}
        scan_query.flag = True
        DB.session.commit()
        return {'result': {'status_code': 200}}
import sys, pathlib
from web import APP, DB
from web.models import User


def CreateDatabase():
    '''创建数据库'''
    DB.create_all()

def CreateUser():
    '''创建测试账户'''
    user1 = User(username='root', password='qazxsw@123', name='管理员', phone='1388888888', email='admin@qq.com', remark='安全工程师')
    DB.session.add(user1)
    DB.session.commit()

def DeletDb():
    '''删除数据库'''
    DB.drop_all()
    CreateDatabase()

if __name__ == '__main__':
    #CreateDatabase()  # 创建数据
    #CreateUser()  # 创建默认用户
    #DeletDb()
    APP.run()
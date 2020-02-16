# Flask程序配置文件

class Config(object):
    '''Flask数据配置'''
    SHODAN_KEY = 'xxxxx'  # shodan key
    SECRET_KEY = 'a819f87b3e371a82dafb8c535c1242c9bba5e91da02ff1d87095367d1d4e188e'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:123456@127.0.0.1/bayonet'  # 数据库连接
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TITLE = 'Bayonet SRC资产管理系统'
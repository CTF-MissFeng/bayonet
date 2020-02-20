> bayonet是一款src资产管理系统，从子域名、端口服务、漏洞、爬虫等一体化的资产管理系统

#### 1、原理
- 子域名扫描：OneForAll-该作者集合了大量插件来实现在线查询子域名的收集，详情请查看[项目地址](https://github.com/shmilylty/OneForAll)
- 端口服务扫描：采用shodan查询
- 主动爬虫：crawlergo-也是使用chrome headless模式进行URL收集入口的动态爬虫，详情请查看[项目地址](https://github.com/0Kee-Team/crawlergohttps://github.com/0Kee-Team/crawlergo)
- 漏洞扫描：采用w13scan进行被动漏洞扫描

#### 2、项目设计
> 各工模块独立运行，数据源都与数据库交互，这样好处有两个：一是若其中一个工具崩溃了不影响其他工具运行，二是可以更方面添加其他工具，反正是与数据库交互，就不考虑包的兼容、项目集合导致的各种问题

#### 3、安装及使用方法

1、pip install -r requirements.txt # 安装所需模块(推荐python3.8)
2、安装postgreSql数据库(12版本)，创建一个数据库
3、修改项目下的`WebConfig.py`配置文件，配置`SHODAN_KEY`和数据库连接地址`SQLALCHEMY_DATABASE_URI`两个选项，若没有shodan key请去注册(免费)

```
SHODAN_KEY = 'xxxxx'  # shodan key
SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:123456@127.0.0.1/bayonet'  # 数据库连接
```
4、修改项目下的`app.py`的mian方法，如下所示，进行创建数据库和默认用户
> python app.py

```
if __name__ == '__main__':
    CreateDatabase()  # 创建数据
    CreateUser()  # 创建默认用户
    #DeletDb()
    #APP.run()
```
5、运行后若没有出错，说明数据库连接配置正确，已经创建了数据库和用户，再次修改`app.py`的main方法，如下所示，注释其他，app.run启动；

```
if __name__ == '__main__':
    #CreateDatabase()  # 创建数据
    #CreateUser()  # 创建默认用户
    #DeletDb()
    APP.run()
```

> python app.py # 运行此命令，打开输出提示中的连接，默认为http://127.0.0.1:500

> 进行登陆，默认用户名为: root/qazxsw@123

> 进入web端后，添加一个任务，如图所示

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/1.png)

6、添加完任务后进入项目下的tools目录，可看到有
- oneforall：子域名查找工具
- portscan：端口及url查找
- scan/Chromium：动态爬虫
- scan/W13scan：漏洞扫描

7、首先进入oneforall目录下，执行`python Run.py`命令进行子域名查找，然后挂起该窗口

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/2.png)

8、在进入portscan目录，执行`python Run.py`命令进行端口及URL扫描，然后挂起该窗口

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/3.png)

9、在进入scan/Chromium目录，如果你是mac平台，则下载`Chromium.app`放到该目录下即可。
如果是其他平台，请先下载对应平台的`crawlergo`工具，然后请安装好Chromium浏览器，并编辑`Run.py`下的该命令替换为Chromium可执行路径

crawlergo工具详情请查看[项目地址](https://github.com/0Kee-Team/crawlergohttps://github.com/0Kee-Team/crawlergo)

```
def action(target):
    '''子线程执行'''
    # 替换此命令：Chromium.app/Contents/MacOS/Chromium为你的可执行文件路径
    cmd = ["./crawlergo", "-c", "Chromium.app/Contents/MacOS/Chromium", "-o", "json", '-m', '500', target]
```
然后运行`python Run.py`即可开始爬虫,并挂起该窗口

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/4.png)

10、进入scan/w13scan目录，执行`python cli.py`命令，将爬虫获取到的数据进行漏洞扫描

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/5.png)

以上四个工具都在同时挂起运行，如果那个工具出错可重新执行。

此时进入web界面，查看各个模块，应该都会有相应的数据展示了

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/7.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/8.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/9.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/10.png)
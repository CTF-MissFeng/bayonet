### 项目更新
> Watchdog是bayonet优化版，重新优化了web、数据库模型，加入了多节点部署等功能，详情请查看：

> https://github.com/CTF-MissFeng/Watchdog

### 简介

> Bayonet是整合多款安全工具并以web形式展现，它辅助渗透测试人员对IT资产进行资产管理。

> 遇到问题，请查看lssues是否有解决方案

### 功能点

- 子域名扫描：oneforall
- 端口服务扫描：shodan+异步socket+nmap（ip数据库、CDN判断）
- URL可用探测
- 驱动浏览器爬虫采集数据：crawlergo
- 被动漏洞扫描：xray

### 安装说明

- Python3.7以上(推荐Python3.8)
- 数据库（推荐postgres）
- chromium浏览器

##### 以Ubuntu16.04为例

- 1、安装Python3.8以及相关编译环境(dev之类)，这里推荐使用`miniconda`安装，并安装`requirements.txt`文件所需模块

- 2、安装postgresql数据库，可将源换成国内源进行快速安装，完成后创建一个空数据库。

- 3、安装chromium浏览器

```
sudo apt-get install chromium-browser
```

- 4、安装nmap


### 使用说明
- 1、修改`config.py`文件，填入`数据库链接项`、`shodan api项`,其他选项选填（环境不一致需要更改选项，如nmap路径、chromium浏览器路径等，具体看配置文件）

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/10.png)

- 2、执行`sh bayonet.sh`脚本启动所有模块（注意，如果python3不是默认的python命令，请修改脚本为`python3`）

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/11.png)

- 3、登录web，添加一个主域名任务，等待片刻，刷新下，就会执行子域名扫描任务
> 如果是服务器搭建，则访问`http://服务器外网ip`，如果为本机搭建则访问`http://127.0.0.1`
> 默认用户名密码：root/qazxsw@123

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/12.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/13.png)

- 4、扫描器子域名需要一定时间，可查看日志观察进度（logs目录下是各个模块运行日志）

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/14.png)

- 5、当子域名、端口扫描、url探测都开始工作了，会在web中显示各模块结果，现在进入扫描任务管理，选择要扫描的URL进行扫描

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/15.png)

- 6、当选择了一个URL进行安全扫描，爬虫模块启动开始驱动浏览器进行爬取，爬取完后，xray开启工作进行漏洞扫描

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/16.png)

- 7、当xray扫描进行中，如果有漏洞会实时存入数据库中，刷新漏洞管理可看到，当点击提交按钮，说明此漏洞已复现或提交给SRC（会在已提交漏洞模块中保存），若误报可删除此漏洞。

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/17.png)

### docker使用

```
$ docker search bayonet  # 查看该项目docker镜像
missfeng/bayonet    bayonet项目docker镜像

$ docker pull missfeng/bayonet:v1.2  # 拉取镜像

$ docker run -itd --name bayonet -p 5000:80 missfeng/bayonet:v1.2  # 后台启动容器

$ docker ps  # 查看已启动的容器
822374ab6f7d        bayonet:v1.2

$ docker exec -it 8223 bash  # 进入容器中 8223是容器ID：822374ab6f7d简写

# /etc/init.d/postgresql start  # 启动数据库

# cd /root/bayonet/   # 进入项目目录

# vim config.py   # 编辑配置文件，找到 shodan_api，填入该参数值；其他配置可自己配置

# sh bayonet.sh  # 启动脚本

访问本机地址: http://127.0.0.1
默认用户名密码：root/qazxsw@123
```


### 更新日志

##### 2020年3月16日
> bayonet V1.1版本完成。添加并完善了：

- 1: 去除w13scan被动扫描器，添加xray被动扫描器
- 2: 主域名任务可重复扫描
- 3: 修复BUG

##### 2020年3月04日
> bayonet V1.1版本完成。添加并完善了：

- 1：加入了WAF、CDN、ip归属地识别，进行自动跳过，节约了扫描时间
- 2：加入了异步socket常规端口探测功能、nmap探测功能、防止shodan探测不完整
- 3：数据表进行了关联，新增且优化了web页面设计
- 4：爬虫采集到的子域名再次入库，URL探测支持二级目录扫描
- 5：子域名、端口扫描、URL扫描、爬虫模块整合到一个项目以便关联
- 6：修复了一些bug

尚未添加功能：
- 端口服务漏洞扫描

##### 2020年2月13日
> bayonet V1.0版本完成，基本连接了这几个工具模块到一起

### 演示

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/1.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/2.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/3.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/4.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/5.png)

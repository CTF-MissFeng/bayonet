### 简介

> Bayonet是整合多款安全工具并以web形式展现，它辅助渗透测试人员对IT资产进行资产管理。

> 遇到问题，请查看lssues是否有解决方案

### 功能点

- 子域名扫描：oneforall
- 端口服务扫描：shodan+异步socket+nmap
- URL可用探测
- 驱动浏览器爬虫采集数据：crawlergo
- 被动漏洞扫描：w13scan

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
- 1、修改`config.py`和`db_config.py`文件，填入`数据库链接项`、`shodanapi项`,其他选项选填。注意shodanapi需填写在端口扫描配置项中。

- 2、执行`python app.py`，开启web服务，若能正常访问说明数据库链接无误

- 3、执行`python Run.py`，将会起四个进程分别启动子域名扫描、端口扫描、URL扫描、爬虫模块（推荐各个模块独立执行，这样互不干扰，也容易查看模块日志）

- 4、进入`tools/scan/W13scan目录`，执行`python cli.py`开启被动漏洞扫描（w13scan未整合到项目中，故需手动执行）。以上操作可用`nohub`进行后台执行。

- 5、查看web页面数据状态，等待扫描即可。注意`漏洞扫描需要去web页面的扫描任务管理手动开启`，这样做是为了不必要扫描不需要的子域名。

### docker使用

```
$ docker search bayonet  # 查看该项目docker镜像
missfeng/bayonet    bayonet项目docker镜像

$ docker pull missfeng/bayonet:v1.1  # 拉取镜像

$ docker run -itd --name bayonet -p 5000:80 missfeng/bayonet:v1.1  # 后台启动容器

$ docker ps  # 查看已启动的容器
822374ab6f7d        bayonet:v1.1

$ docker exec -it 8223 bash  # 进入容器中 8223是容器ID：822374ab6f7d简写

# /etc/init.d/postgresql start  # 启动数据库

# cd /root/bayonet/   # 进入项目目录

# vim config.py   # 编辑配置文件，找到 shodan_api，填入该参数值；其他配置可自己配置

# nohup python3 -u app.py > web.log 2>&1 &  # 后台启动web服务
# nohup python3 -u Run.py > tools.log 2>&1 &  # 后台启动工具模块

# cd tools/scan/W13SCAN/
# nohup python3 -u cli.py > w13scan.log 2>&1 &  # 后台启动w13scan

访问本机地址: http://127.0.0.1:5000
默认用户名密码：root/qazxsw@123
```


### 更新日志

##### 2020年3月04日
> bayonet V1.1版本完成。添加并完善了：

- 1：加入了WAF、CDN、ip归属地识别，进行自动跳过，节约了扫描时间
- 2：加入了异步socket常规端口探测功能、nmap探测功能、防止shodan探测不完整
- 3：数据表进行了关联，新增且优化了web页面设计
- 4：爬虫采集到的子域名再次入库，URL探测支持二级目录扫描
- 5：子域名、端口扫描、URL扫描、爬虫模块整合到一个项目以便关联
- 6：修复了一些bug

尚未添加功能：
- xray扫描器
- 端口服务漏洞扫描

##### 2020年2月13日
> bayonet V1.0版本完成，基本连接了这几个工具模块到一起

### 演示

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/1.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/2.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/3.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/4.png)

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/5.png)

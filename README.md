# bayonet
> bayonet是一款src资产管理系统，从子域名、端口服务、漏洞、爬虫等一体化的资产管理系统


### 1、子域名收集
> 子域名收集有很多方法，如搜索引擎、枚举、证书信息、一些API查询接口等等，这里我用了以下方式：

- OneForAll：该作者集合了大量插件来实现在线查询子域名的收集，详情请查看：[项目地址](https://github.com/shmilylty/OneForAll)
- rapid7 opendata：这是Rapid7的一个项目，目的是收集全球Internet信息，里面包含了全球DNS数据，并且每月更新，就是体积较大，下载下来解压差不多170多个G，可导入数据库中进行查询调用（也可以找到某域名真实的IP地址），这里考虑到我的服务器没那么大的磁盘空间，就去掉了此功能(留下了没钱的眼泪)。[项目地址](https://opendata.rapid7.com/)

### 2、子域名端口服务收集
> 重要漏洞往往是在其他端口服务上，所以端口服务是必不可少的，那么怎么有效、快速找到该IP开放的端口服务呢？自己masscan扫描也太慢，这里我就用了shodan的接口进行查询

### 3、爬虫收集
> 这里一定要用动态爬虫才能收集更多信息，因为你不知道他的网站被别人用了多少扫描器进行扫描过了，你捡漏的几率较小。而关于动态爬虫就需要驱动浏览器模拟真实网页打开，抓取被动爬虫扫描不到的数据，其实burp在版本2.1.0.5之后就嵌入Chromium浏览器进行动态收集，当然这里用burp不太方便，有更好的工具

- crawlergo：也是使用chrome headless模式进行URL收集入口的动态爬虫。[项目地址](https://github.com/0Kee-Team/crawlergo)

### 4、漏洞扫描
> 关于漏洞扫描可选就很多了，你甚至可以用AWVS进行扫描，但是最好要支持代理方式的扫描器，这里目前好像就xray和w13scan，当然burp也可以。

- xray：使用go开发的被动扫描器，不开源，商业版（虽然免费版也可以，但是强迫症一定要用更好的）[项目地址](https://github.com/chaitin/xray)
- w13scan：这个大家不陌生了吧，读了下源码及使用了下，还不错，关键是开源，好方便组装轮子。

### 5、项目设计
> 各工具独立运行，数据源都与数据库交互，这样好处有两个：一是若其中一个工具崩溃了不影响其他工具运行，二是可以更方面添加其他工具，反正是与数据库交互，就不考虑包的兼容、项目集合导致的各种问题。

![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/index.png)
![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/1.png)
![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/2.png)
![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/3.png)
![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/4.png)
![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/5.png)
![index](https://github.com/CTF-MissFeng/bayonet/blob/master/doc/6.png)

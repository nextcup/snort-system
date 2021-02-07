# Snort管理系统安装部署文档

### 一、准备python与pip2

##### 1. 安装python2.7

   一般linux自带python2.7

##### 2. 安装pip2 

   **注意：version不要大于等于21**

```
yum install nginx
yum install -y epel-release
yum install -y python-pip
yum install gcc-c++
yum install python-devel
```
   **注意：万一version升高了，使用下方命令重装pip2**

```
yum reinstall -y python-pip
```

### 二、安装依赖

```
#将项目放在/home/tracy/snort-system下
pip2 install apscheduler
pip2 install enum34
pip2 install -r requirements.txt
```


### 三、修改nginx配置

```
cd /home/tracy/snort-system
vim mysite_nginx.conf
```

```
修改下文中的最后一行，令server_name 8.8.8.8成为你自己的ip
# mysite_nginx.conf

# the upstream component nginx needs to connect to
upstream django {
    server unix:///home/tracy/snort-system/mysite.sock; # for a file socket
   #server 127.0.0.1:8001; # for a web port socket (we'll use this first)
}
# configuration of the server
server {
    # the port your site will be served on
    listen      8000;
    # the domain name itse will serve for
    server_name 8.8.8.8; # substitute your machine's IP address or FQDN
```
### 四、初始化数据库

由于该项目用的是python2.7和Django1.6.8， 在./snort-system/目录下运行：

```
cd /home/tracy/snort-system
python manage.py syncdb
```

来同步数据库


### 五、检查代码&启动服务
首先查看代码./snort-system/panel/views.py, line1251和1252,改成下文这样
```
def import_local_rule(request):
    rule_path = get_rules_path()#get_local_rules_path()
```

启动服务

```
cd /home/tracy/snort-system
python manage.py runserver 0.0.0.0:8000
```













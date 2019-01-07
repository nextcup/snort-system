# Snort规则管理系统


## 一、需求概述

    PTD系统中包含一套用于入侵检测的snort规则，该规则平时的维护以及管理由人工完成，效率较低。现需开发一个用于管理snort规则的系统，该系统作为一个网络服务部署在某一台服务器上,其主要功能包括规则的增、删(屏蔽)、改、查基础操作，以及规则的自动更新、字段提取、规则出库和冲突解决功能,此外,还包括规则验证和pcap上传、下载和删除功能。


## 二、开发环境

    * Python语言
    * Django框架
    * Sqlite数据库
    * 182服务器搭建
    * Nginx + uwsgi部署


## 三、功能设计

### 1. 用户登录

    用户在使用系统之前首先要进行注册和登陆操作，才有权限管理系统中的规则。
    1.1 注册
        1.1.1 输入用户名
        1.1.2 输入密码
        1.1.3 确认密码
        1.1.4 提交注册
    1.2 登陆
        1.2.1 输入用户名
        1.2.2 输入密码
        1.2.3 登陆

### 2. 特征概要
    该模块默认会分页显示系统中所有规则特征，页面中包含对规则的增、删(屏蔽)、改、查、导出操作，pcap上传、下载和删除操作，以及规则特征详情查看和完整规则预览操作，其中涉及到规则变动的操作都有规则验证的过程。
    2.1 特征显示
        2.1.1  规则ID
        2.1.2  描述信息
        2.1.3  类型
        2.1.4  恶意家族名
        2.1.5  修订版本
        2.1.6  创建时间
        2.1.7  修改时间
        
    2.2 详情显示
        用户可以查看并作出修改。
        2.2.1  上一步所有特征
        2.2.2  引用信息
        2.2.3  匹配内容及其选项
        2.2.4  攻击者
        2.2.5  是否成功攻击
        2.2.6  控制源
        2.2.7  确认被控
        2.2.8  知识库信息
        2.2.9  是否屏蔽
        2.2.10 是否出库包含
        2.2.11 首次检出时间
        2.2.12 首次检出位置
        2.2.13 整体检出时间
        2.2.14 整体检出位置
        2.2.15 检出个数
        2.2.16 误报个数
        2.2.17 特征来源
        2.2.18 备注
        
    2.3 规则预览
        一条完整规则的展示，并且会实时显示修改后的规则信息。例如：
```
alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"BROWSER-PLUGINS Java Applet sql.DriverManager fakedriver exploit attempt"; flow:to_server,established; flowbits:isset,file.jar; file_data; content:"META-INF/services/java.sql.Driver"; fast_pattern:only; content:"Fakedriver"; nocase; metadata:policy balanced-ips drop, policy max-detect-ips drop, policy security-ips drop, service smtp; reference:bugtraq,58504; reference:cve,2013-1488; reference:url,osvdb.org/show/osvdb/91472; classtype:attempted-user; sid:26899; rev:4;)
```
    2.4 新增规则
        根据字段进行填写，提交新规则。添加字段有如下：
        2.4.1 规则ID（系统自动生成，范围200万-300万）
        2.4.2 协议（可选）
            2.4.2.1 TCP
            2.4.2.2 HTTP
        2.4.3 flow（可选）
            2.4.3.1 to_server,established
            2.4.3.2 to_client,established
        2.4.4   源IP
        2.4.5   源端口
        2.4.6   目的IP
        2.4.7   目的端口
        2.4.8   描述信息
        2.4.9   匹配内容（可添加多组）
        2.4.10  匹配选项
            2.4.10.1 distance
            2.4.10.2 offset
            2.4.10.3 nocase
            2.4.10.4 depth
            2.4.10.5 within
            
    2.5 屏蔽规则
        使规则失效。
        2.5.1 页面选择屏蔽（通过复选框）
        2.5.2 特征字段屏蔽（设置规则的屏蔽字段，“是”代表屏蔽，“否”代表不屏蔽或取消屏蔽）
        
    2.6 导出规则
        导出一套文件，rules文件和names文件。前者是规则文件，后者是规则特征文件。
        2.6.1 页面选择导出（通过复选框）
        2.6.2 时间范围导出（通过时间框）
        
    2.7 搜索规则
        2.7.1 根据规则特征字段检索
            2.7.1.1 规则ID
            2.7.1.2 描述信息
            2.7.1.3 类型
            2.7.1.4 恶意家族名
        2.7.2 根据规则修改时间范围检索
    
    2.8 规则检测
        2.8.1 pcap上传
            规则与pcap命中,pcap 上传至服务器保存
        2.8.2 pcap下载
            未命中,不保存
        2.8.3 pcap删除
            删除服务器中pcap
### 3. 规则操作
    规则操作模块主要包括两个功能，一是规则出库，二是表格导出。前者是通过判断用户是否为规则设置了出库包含字段进行部分导出，结果同样是之前描述过的两个文件；后者是导出用户给规则设置了出库包含且设置了扩展字段，并且经过翻译的规则，结果是一个xlsx表格文件。
    3.1 规则导出
        规则“是否出库包含”字段设置为“是”
    3.2 表格导出
        3.2.1 规则已翻译
        3.2.2 “是否出库包含”设置为“是”
        3.2.3 补充扩展字段
### 4. 冲突列表
    该模块会显示系统中存在冲突的规则信息，所谓冲突就是当前系统规则被修改，而且自动更新到了该规则且新旧规则特征不同。该模块给出了冲突解决的功能，用户会对比新旧规则进行修改，以选择最终选择哪条规则。解决完冲突后，下次更新再更新到此规则时，不会再报冲突。
    4.1 显示冲突规则
    4.2 解决冲突
        4.2.1 新旧规则对比解决冲突
            4.2.1.1 选择新规则
            4.2.1.2 选择旧规则
        4.2.2 未解决冲突
            保留旧规则有效
        4.2.3 解决完冲突
            如果当前规则冲突已解决,下次再更新到此规则,不报冲突
```
注：如果冲突未解决，系统中仍然保留前一个规则的有效性！
```
### 5. 未翻译列表
    该模块会显示系统中未被翻译的规则信息，所谓未被翻译就是规则中的msg（描述信息）字段未被翻译为中文，用户可以选择具体规则，填入中文msg即可完成翻译。
    5.1 显示未翻译规则
    5.2 翻译规则
        5.2.1 待翻译msg显示
        5.2.2 输入翻译信息
### 6. 系统日志
    该模块主要记录当前系统中的所有用户信息以及用户的操作记录，还会对系统异常进行记录以便于维护。主要记录以下信息：
    6.1 规则ID（如果操作规则）
    6.2 动作
        6.2.1   用户注册
        6.2.2   用户登陆
        6.2.3   用户注销
        6.2.4   规则修改
        6.2.5   规则屏蔽
        6.2.6   规则翻译
        6.2.7   规则导出
        6.2.8   规则检测
        6.2.9   文件上传
        6.2.10  pcap下载
        6.2.11  表格导出
        6.2.12  新增规则
        6.2.13  规则入库
        6.2.14  特征入库
        6.2.15  系统异常信息
    6.3 详细信息
        对指定动作进行详细描述。
    6.4 操作人
        当前登陆用户。
    6.5 状态
        6.5.1 成功
        6.5.2 失败
    6.6 访问IP
        当前登陆用户IP地址。
    6.7 时间
    6.8 修改历史
        显示规则所有修改记录。
### 7. 自动更新
    该系统每天0点自动更新规则到本系统，同步周期可通过config.ini配置文件进行配置，默认如下。用户可自行修改。
```shell
file: confing.ini
[update]
......          # 其他
days = mon-sun  # 周一到周日（每天）
hours = 0       # 0点
minutes = 0     # 0分
```
### 8. 关于
    该模块主要是对系统的功能进行了大致的描述，使初次使用该系统的用户对系统有个大致的了解。
# 四、系统截图
## 1. 注册
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/register.png)
## 2. 登陆
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/login.png)
## 3. 后台
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/backstage.png)
## 4. 未翻译
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/untranslate.png)
## 5. 日志
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/log.png)
## 6. 添加规则
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/add.png)
## 7. 完整规则
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/complete.png)
## 8. 特征详情
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/detail.png)
## 9. 关于
![Image text](https://raw.githubusercontent.com/TracyPro/snort-system/master/snort-system/images/about.png)
## 五、说明
```python
如有问题，联系zhangjiawei@antiy.cn
```

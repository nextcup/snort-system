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

### 2. 特征概要
该模块默认会分页显示系统中所有规则特征，页面中包含对规则的增、删(屏蔽)、改、查、导出操作，pcap上传、下载和删除操作，以及规则特征详情查看和完整规则预览操作，其中涉及到规则变动的操作都有规则验证的过程。

#### 2.1 新增规则

用户编写规则并添加到系统，规则ID字段系统会随机生成ID，范围在200万-300万。其他字段的编写根据提示填入即可，添加时会弹出特定编辑框告知使用者去填写特定字段。

#### 2.2 导出规则

导出规则模块首先需要用户选择特定的时间范围，然后再点击导出按钮进行导出。导出的规则解压缩后主要包括两个文件，rules文件和names文件，前者存储完整规则，后者存储的是从规则提取出的特征字段，一个json文件。

#### 2.3 查看详情
特征概要模块会在页面显示部分规则特征，如果用户选择查看该规则的所有特征，点击查看详情即可。详情页面会将规则的原有特征和扩展特征都会进行展示。
    
#### 2.4 修改规则
如果用户想修改规则的某些特征，那么点击该规则的详情页面，在此页面直接修改并提交即可。

#### 2.5 规则预览
预览模块的功能是显示完整规则。当用户修改了规则的某些特征或添加了某条新规则后，可以通过预览功能去查看修改后的或新添加到系统的规则，从而进行验证或其它操作。

#### 2.6 搜索规则
搜索功能主要是通过规则的某些特征进行检索，可以检索的特征字段包括以下。此外，还可以选择时间范围进行搜索，得到该时间范围内的所有规则。
```
可检索特征1：规则ID
可检索特征2：描述信息
可检索特征3：家族类型
可检索特征4：恶意家族
```
#### 2.7 检测规则
规则检测主要是检测系统是否支持当前规则以及该规则与上传的pcap包是否命中。如果命中，该pcap会被上传到服务器，供用户进行下载和删除；如果未命中，则会进行相关提示。
#### 2.8 pcap下载
下载命中规则的pcap包文件到本地。
#### 2.9 pcap删除
删除存储在服务器中的pcap包文件。
### 3. 规则操作
规则操作模块主要包括两个功能，一是规则出库，二是表格导出。前者是通过判断用户是否为规则设置了出库包含字段进行部分导出，结果同样是之前描述过的两个文件；后者是导出用户给规则设置了出库包含且设置了扩展字段，并且经过翻译的规则，结果是一个xlsx表格文件。
### 4. 冲突列表
该模块会显示系统中存在冲突的规则信息，所谓冲突就是当前系统规则被修改，而且自动更新到了该规则且新旧规则特征不同。该模块给出了冲突解决的功能，用户会对比新旧规则进行修改，以选择最终选择哪条规则。解决完冲突后，下次更新再更新到此规则时，不会再报冲突。
```
注：如果冲突未解决，系统中仍然保留前一个规则的有效性！
```
### 5. 未翻译列表
该模块会显示系统中未被翻译的规则信息，所谓未被翻译就是规则中的msg（描述信息）字段未被翻译为中文，用户可以选择具体规则，填入中文msg即可完成翻译。
### 6. 系统日志
该模块主要记录当前系统中的所有用户信息以及用户的操作记录，还会对系统异常进行记录以便于维护
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
## 一、说明
```python
如有问题，联系zhangjiawei@antiy.cn
```

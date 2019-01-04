# -*- coding: UTF-8 -*-

import os
import zipfile
from config import *
from models import *
from global_values import *
from django.http import StreamingHttpResponse


def get_custom_export_rule(id_list):
    """
    :describe:      获取自定义导出的规则
    :param param1:  规则id列表
    :return:        规则列表
    """
    rule_list = []
    for sid in id_list:
        rule_obj = Rule.objects.get(id=int(sid))
        complete_rule_obj = CompleteRule.objects.get(sid=str(rule_obj.sid))
        rule_list.append(complete_rule_obj.rule)
    return rule_list


def write_custom_export_rules(id_list):
    """
    :describe:      将待导出规则写入临时文件
    :param param1:  规则id列表 
    :return:        无
    """
    pwd = get_download_path() + 'custom_export'
    if not os.path.exists(pwd):
        os.mkdir(pwd)

    rules_path = pwd + '/export.rules'
    names_path = pwd + '/export'

    rule_list = get_custom_export_rule(id_list)
    for rule in rule_list:
        try:
            with open(rules_path, 'a+') as f:
                f.write(rule + '\n')
        except Exception as e:
            print 'error:', e

    extract_path = get_extract_path()
    cmd = 'python ' + extract_path + ' --rule ' + pwd + ' --out ' + names_path
    os.system(cmd)
    # 压缩文件并下载
    export_custom(pwd, rules_path, names_path)
    remove_dir_cmd = 'rm -rf ' + pwd
    os.system(remove_dir_cmd)


def export_custom(pwd, rules_path, names_path):
    """
    :describe:      导出到本地
    :param parma1:  临时规则文件存储目录 
    :param param2:  临时规则文件存储路径
    :param param3:  临时规则特征文件存储路径 
    :return:        导出的规则文件
    """
    file_list = []
    file_list.append(rules_path)
    file_list.append(names_path)
    path = pwd + 'rules.zip'
    f = zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED)

    for file in file_list:
        f.write(file)
    f.close()
    file = None
    try:
        file = open(path, 'rb')
    except Exception as e:
        print 'error:', e
        return HttpResponse('待导出文件打开出错')
    response = StreamingHttpResponse(file)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="rules.zip"'
    set_response(response)
    remove_zip_cmd = 'rm -rf ' + path
    os.system(remove_zip_cmd)

# -*- coding: UTF-8 -*-
import datetime
import os
import zipfile
from config import get_download_path, get_extract_path
from django.http import HttpResponse
from django.http import StreamingHttpResponse
from global_values import set_response


def get_start_end(date_str):
    """
    :describe:  获取时间范围: start end
    :param      前端传来的时间字符串 2018-12-01 00:00:00 - 2019-01-31 00:00:00
    :return:    start: 2018-12-01 00:00:00 end: 2019-01-31 00:00:00
    """
    if date_str == "":
        return "", ""

    start = datetime.datetime.strptime(
        date_str.split(' - ')[0].strip(), "%Y-%m-%d %H:%M:%S")

    end = datetime.datetime.strptime(
        date_str.split(' - ')[1].strip(), "%Y-%m-%d %H:%M:%S")

    return start, end


def write_time_export_rules(start, end, rule_list):
    """
    :describe:      时间范围内规则写入文件
    :param param1:  开始日期
    :param param2:  结束日期
    :param param3:  在日期范围内规则列表
    :return:        无
    """
    start = str(start).replace(" ", '_')
    end = str(end).replace(" ", '_')
    pwd = get_download_path() + start + end

    if not os.path.exists(pwd):
        os.mkdir(pwd)

    rules_path = pwd + '/export.rules'
    names_path = pwd + '/export'

    if len(rule_list) == 0:
        fp = open(rules_path, 'a+')
        fp.close()
    else:
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
    export_time_range(pwd, rules_path, names_path)
    remove_dir_cmd = 'rm -rf ' + pwd
    os.system(remove_dir_cmd)


def export_time_range(pwd, rules_path, names_path):
    """
    :describe:      时间范围规则文件下载到本地
    :param param1:  存储被导出的规则和特征文件目录
    :param param2:  被导出规则文件全路径
    :param param3:  被导出特征文件全路径
    :return:        无
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

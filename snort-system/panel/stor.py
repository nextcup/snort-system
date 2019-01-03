# -*- coding: UTF-8 -*-
import os
import zipfile
from config import *
from models import *


def write_check_rule(sid, rule):
    """
    :describe:      写入要被检测的规则到文件(ID命名)
    :param param1:  规则ID
    :param param2:  规则字符串
    :return:        成功: 文件路径 失败: None
    """
    pcaps_dir = get_upload_path()
    if not os.path.exists(pcaps_dir):
        os.makedirs(pcaps_dir)

    path = pcaps_dir + str(sid) + '.rules'

    try:
        with open(path, 'w') as f:
            f.write(rule)
            return path
    except Exception as e:
        print e
        return None


def stor_rule_pcap(sid, pcap):
    """
    :describe:      存储成功匹配的规则和pcap
    :param param1:  规则ID
    :param param2:  pcap文件
    :return:        无
    """
    rule_obj = RulePcap.objects.create(sid=sid, pcap=pcap)
    rule_obj.save()


def generate_zip():
    """
    :describe:  压缩要下载的文件
    :param:     无
    :return:    无
    """
    file_list = []
    path = get_download_path()
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            if not name.endswith('.py') \
                    and not name.endswith('.zip') \
                    and not name.endswith('.xlsx'):
                file_list.append(os.path.join(root, name))

    f = zipfile.ZipFile(
        path + 'rules.zip', 'w', zipfile.ZIP_DEFLATED)
    for file in file_list:
        f.write(file)
    f.close()

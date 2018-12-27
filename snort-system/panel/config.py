# -*- coding: UTF-8 -*-


import os
import ConfigParser


def get_update_path():
    """
    :describe:  获得更新程序路径
    :param:     无
    :return:    更新程序路径
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    update_path = cf.get('update', 'update_path')
    return update_path


def get_rules_path():
    """
    :describe:  获得规则文件目录
    :param:     无
    :return:    规则文件目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    rules_path = cf.get('update', 'new_rules_path')
    return rules_path


def get_file_path():
    """
    :describe:  获得names文件目录
    :param:     无
    :return:    names文件目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('tmp', 'path')
    return file_path


def get_upload_path():
    """
    :describe:  获得文件上传目录
    :param:     无
    :return:    文件上传目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('upload', 'path')
    return file_path


def get_download_path():
    """
    :describe:  获得规则导出目录
    :param:     无
    :return:    规则导出目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('download', 'path')
    return file_path


def get_pcap_path():
    """
    :describe:  获得pcap文件目录
    :param:     无
    :return:    pcap文件目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('pcap', 'download_path')
    return file_path


def get_stor_path():
    """
    :describe:  获得规则出库存储目录
    :param:     无
    :return:    规则出库存储目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('rule', 'rules_path')
    return file_path


def get_names_stor_path():
    """
    :describe:  获得特征出库存储目录
    :param:     无
    :return:    特征出库存储目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('rule', 'names_path')
    return file_path


def get_zip_path():
    """
    :describe:  获得zip文件目录
    :param:     无
    :return:    zip文件目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('download', 'zip_path')
    return file_path


def get_tmp_rule():
    """
    :describe:  获得临时规则文件目录
    :param:     无
    :return:    临时规则文件目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('tmp', 'rule')
    return file_path


def get_tmp_dir():
    """
    :describe:  获得临时目录
    :param:     无
    :return:    临时目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    file_path = cf.get('tmp', 'dir')
    return file_path


def get_time():
    """
    :describe:  获得更新规则周期
    :param:     无
    :return:    days: 哪天 hours: 几时 minutes: 几分
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    days = cf.get('update', 'days')
    hours = cf.get('update', 'hours')
    minutes = cf.get('update', 'minutes')
    return days, hours, minutes


def get_url():
    """
    :describe:  获得同步规则URL
    :param:     无
    :return:    URL
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    url = cf.get('update', 'url')
    return url


def get_storage_path():
    """
    :describe:  获得下载后规则存储目录
    :param:     无
    :return:    规则存储目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    rules_path = cf.get('update', 'rules_path')
    return rules_path


def get_xlsx_path():
    """
    :describe:  获得xlsx文件存储目录
    :param:     无
    :return:    xlsx文件存储目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    rules_path = cf.get('download', 'xlsx_path')
    return rules_path


def get_extract_path():
    """
    :describe:  获得特征提取脚本目录
    :param:     无
    :return:    特征脚本目录
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    rules_path = cf.get('extract', 'path')
    return rules_path


def get_tmp_names_path():
    """
    :describe:  获得特征提取后names文件暂存路径
    :param:     无
    :return:    names暂存路径
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    rules_path = cf.get('tmp', 'path')
    return rules_path


def get_out_names_path():
    """
    :describe:  获得导出包含的规则names文件存储路径
    :param:     无
    :return:    导出包含的规则names文件存储路径
    """
    path = os.getcwd() + '/panel/config.ini'
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    rules_path = cf.get('rule', 'out_names')
    return rules_path

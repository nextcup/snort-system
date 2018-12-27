# -*- coding: UTF-8 -*-

from apscheduler.schedulers.background import BackgroundScheduler
from db import *

import logging
import urllib
import tarfile


def download():
    """
    :describe:      下载规则文件
    :param param1:  无
    :return:        无
    """
    url = get_url()
    rules_path = get_storage_path()
    if not os.path.exists(rules_path):
        os.makedirs(rules_path)

    try:
        urllib.urlretrieve(url, rules_path + "rules.tar.gz")
    except Exception as e:
        print 'download error: ', e


def decompre():
    """
    :describe:      解压下载的tar.gz压缩包
    :param param1:  无
    :return:        无
    """
    rules_path = get_storage_path()
    if not os.path.exists(rules_path):
        os.makedirs(rules_path)

    try:
        tar = tarfile.open(rules_path + "rules.tar.gz")
        file_names = tar.getnames()
        [tar.extract(name, path=rules_path)
         for name in file_names if name.endswith(".rules")]
    except Exception as e:
        print 'decompression error: ', e


def task():
    """
    :describe:      定时任务
    :param param1:  无
    :return:        无
    """
    logging.basicConfig()
    download()
    decompre()
    rules_in()


def start_update():
    """
    :describe:      定时任务参数设置与开启
    :param param1:  无
    :return:        无
    """
    days, hours, minutes = get_time()
    sched = BackgroundScheduler()
    sched.add_job(task, 'cron', day_of_week=days, hour=hours, minute=minutes)
    sched.start()


def rules_in():
    """
    :describe:      下载后规则写入数据库
    :param param1:  无
    :return:        无
    """
    # 读取规则,插入数据库
    path_list = get_rule_files()
    rules_sections = get_all_rules(path_list)

    complete_rules = CompleteRule.objects.all()
    complete_sid = [str(rule.sid) for rule in complete_rules]

    for key, value in rules_sections.items():
        if key not in complete_sid:
            rule_obj = CompleteRule.objects.create(sid=key, rule=value)
            rule_obj.save()
        else:
            # 判断冲突
            judge_conflict(key)
            continue

    update_features(rules_sections, get_edited_rule_id())
    features_in()


def judge_conflict(key):
    """
    :describe:      冲突判断
    :param param1:  规则ID
    :return:        无
    """
    # 1. 查询已修改的规则
    # 2. 查看已修改规则是否被更新
    # 2.1 是: 冲突
    # 2.2 否: 未冲突
    log_obj = Log.objects.filter(action='规则修改')
    log_conflict = Log.objects.filter(action='冲突解决')
    log_list = [log.sid for log in log_obj]
    log_con_list = [log_con.sid for log_con in log_conflict]
    if set(log_list) == set(log_con_list):
        pass
    else:
        con_list = set(log_list) - set(log_con_list)
        set_edited_rule_id(con_list)

    [Rule.objects.filter(sid=rule_id).update(has_conflict='是')
     for rule_id in get_edited_rule_id() if str(key) == str(rule_id)]


def features_in():
    """
    :describe:      下载后规则特征入库
    :param param1:  无
    :return:        无
    """
    rule_obj = CompleteRule.objects.all()
    rule_path = get_tmp_rule()
    tmp_dir = get_tmp_dir()
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    if not os.path.exists(rule_path):
        fp = open(rule_path, 'w')
        fp.close()

    with open(rule_path, 'w') as f:
        for rule in rule_obj:
            f.write(str(rule.rule) + '\n')

    dict_data = get_dict()
    insert(dict_data)

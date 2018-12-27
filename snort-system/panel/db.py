# -*- coding: UTF-8 -*-


from config import *
from global_values import *
from models import *


import os
import re
import json
import time
import sys


def set_default_env():
    """
    :describe:  解决编码报错问题
    :param:     无
    :return:    无
    """
    reload(sys)
    sys.setdefaultencoding('utf-8')


def extract_feature():
    """
    :describe:  特征提取
    :param:     无
    :return:    无
    """
    rules = get_tmp_dir()
    shell = get_extract_path()
    names = get_tmp_names_path()
    cmd = 'python ' + shell + ' --rule ' + rules + ' --out ' + names
    os.system(cmd)


def get_dict():
    """
    :describe:  读取names文件获取字典数据
    :param:     无
    :return:    字典数据
    """
    extract_feature()
    file_path = get_file_path()
    try:
        with open(file_path)as fp:
            dict_data = json.load(fp)
    except IOError:
        dict_data = None
        print 'Open names file failed!'

    return dict_data


def get_content(key):
    """
    :describe:  提取规则中content内容
    :param:     规则ID
    :return:    content字符串
    """
    content = []
    content_str = ""
    options = ['offset', 'depth', 'nocase', 'distance', 'within']

    rule = CompleteRule.objects.get(sid=str(key)).rule
    result = rule.split(';')

    for val in result:
        if 'content' in val:
            content.append(val)
        else:
            [content.append(val) for v in options if v in val]

    if len(content) == 0:
        return ""

    flag = False

    for val in content:
        val = val.strip()

        if 'content' in val:
            if flag is True:
                content_str += '\n'
                content_str += val + ';'
            else:
                content_str += val + ';'
                flag = True
        else:
            content_str += val + ';'
            flag = True

    return content_str


def get_reference(value):
    """
    :describe:  提取规则中reference内容
    :param:     字典中reference列表
    :return:    reference字符串
    """
    val = ""
    for ref_val in value['reference']:
        val = val + ref_val + ';\n'

    return val


def insert(dict_data):
    """
    :describe:  将规则特征写入数据库
    :param:     特征字典
    :return:    无
    """
    rules = Rule.objects.all()
    rule_sid = [str(rule.sid) for rule in rules]

    for key, value in dict_data.items():
        if key not in rule_sid:
            val = get_reference(value)
            content_str = get_content(key)

            rule_obj = Rule.objects.create(
                sid=key,
                msg=value.get('msg', ''),
                reference=val,
                class_type=value.get('classtype', ''),
                malname=value.get('malname', ''),
                attacker=value.get('sponsor', ''),
                victim=value.get('destination', ''),
                success_attack=value.get('success', ''),
                controller=value.get('active', ''),
                confirm_controlled=value.get('confirm', ''),
                rev=value.get('rev', ''),
                create_time=get_date(),
                update_time=get_date(),
                is_translate='否',
                content=content_str,
                has_conflict='否'
            )
            rule_obj.save()

        else:
            continue


def get_rule_files():
    """
    :describe:  获取规则目录下所有规则文件
    :param:     无
    :return:    规则文件列表(内容为路径)
    """
    path = get_rules_path()
    filenames = []
    for root, dirs, files in os.walk(path):
        for fn in files:
            if root == path and fn[-6:] == ".rules":
                filename = None
                if root[-1] == '/':
                    filename = root + fn
                else:
                    filename = root + '/' + fn
                filenames.append(filename)
    return filenames


def get_all_rules(path_list):
    """
    :describe:  提取规则中规则内容
    :param:     规则文件列表
    :return:    规则特征字典
    """
    rules_sections = {}
    for path in path_list:
        f = open(path, 'r')
        rules_contents = f.readlines()
        pattern = 'sid:([\d]+);'
        regex = re.compile(pattern)
        j = 0
        for i in rules_contents:
            i = i.strip()
            if i.startswith('#') or len(i) == 0:
                pass
            else:
                sid_re = regex.findall(i)
                if len(sid_re) != 1:
                    sid = '[]error%d' % j
                else:
                    sid = sid_re[0]
                rules_sections[sid] = i
                j = j + 1
    return rules_sections


def db_to_file():
    """
    :describe:  将出库包含的规则写入文件
    :param:     无
    :return:    无
    """
    set_default_env()
    rule_obj = Rule.objects.filter(contain='是')
    for rule in rule_obj:
        complete_rule = CompleteRule.objects.get(sid=rule.sid).rule
        # 开始写
        stor_path = get_stor_path()
        if not os.path.exists(stor_path):
            os.makedirs(stor_path)
        with open(stor_path + '/all.rules', 'a+') as f:
            f.write(complete_rule + '\n')
    Rule.objects.filter(contain='是').update(contain='否')


def extract_contain_feature():
    """
    :describe:  导出出库包含规则的names文件
    :param:     无
    :return:    无
    """
    rules_path = get_stor_path()
    extract_path = get_extract_path()
    out_names = get_out_names_path()
    names_dir = get_names_stor_path()
    if not os.path.exists(names_dir):
        os.makedirs(names_dir)

    cmd = 'python ' + extract_path +\
        ' --rule ' + rules_path \
          + ' --out ' + out_names
    os.system(cmd)


def syn_msg(data, user, ip):
    """
    :describe:      同步修改后msg内容到规则
    :param param1:  前端返回数据
    :param param2:  当前登录用户
    :return:        无
    """
    rule_obj = CompleteRule.objects.get(sid=str(data[0]))
    old_msg = re.findall(r"msg:\"(.+?)\";", str(rule_obj.rule))

    try:
        result = rule_obj.rule.replace(old_msg[0], data[1])
        rule_obj.rule = result
        rule_obj.save()
    except Exception as e:
        record_log(rule_obj.sid, '规则修改同步msg', user, '失败', ip,
                   '错误信息:%s,原msg字段为%s,新msg字段为%s' % (e, old_msg, data[1]))


def replace_old_content(data, rule):
    """
    :describe:      删除规则中旧content内容
    :param param1:  前端返回数据
    :param param2:  完整规则
    :return:        待更新规则字符串
    """
    result = ""

    old_content = get_content(data[0])
    if old_content == "":
        return ""

    old_content_list = old_content.split(';')
    old_content_list.remove('')
    for v in old_content_list:
        v = v.strip() + ';'
        if v in rule:
            result = rule.replace(v, "")
            rule = result
    return result


def syn_content(data, user, ip):
    """
    :describe:      同步修改后content内容到规则
    :param param1:  前端返回数据
    :param param2:  当前登录用户
    :return:        无
    """
    rule_obj = CompleteRule.objects.get(sid=str(data[0]))
    rule = rule_obj.rule
    result = replace_old_content(data, rule)
    new_content = data[20]

    if result == "":
        sub_rule = rule[0:len(rule) - 1]
        final_rule = sub_rule + new_content + ')'
        rule_obj.rule = final_rule.replace('\n', "")
        rule_obj.save()
    else:
        try:
            msg = re.findall(r'msg:(.+?);', rule)
            msg = msg[0]
            result = result.replace(msg + ';', msg + ';' + new_content)
            rule_obj.rule = result.replace('\n', "")
            rule_obj.save()
        except Exception as e:
            record_log(rule_obj.sid, '规则修改同步content', user, '失败', ip,
                       '错误信息:%s,新content字段为%s' % (e, new_content))


def syn_classtype(data, user, ip):
    """
    :describe:      同步修改后classtype内容到规则
    :param param1:  前端返回数据
    :param param2:  当前登录用户
    :return:        无
    """
    rule_obj = CompleteRule.objects.get(sid=data[0])
    old_classtype = re.findall(r"classtype:(.+?);", str(rule_obj.rule))

    try:
        result = rule_obj.rule.replace(old_classtype[0], data[3])
        rule_obj.rule = result
        rule_obj.save()
    except Exception as e:
        record_log(rule_obj.sid, '规则修改同步classtype', user, '失败', ip,
                   '错误信息:%s,原classtype字段为%s,新classtype字段为%s' % (e, old_classtype, data[3]))


def syn_rev(data, user, ip):
    """
    :describe:      同步修改后rev内容到规则
    :param param1:  前端返回数据
    :param param2:  当前登录用户
    :return:        无
    """
    result = ""
    rule_obj = CompleteRule.objects.get(sid=data[0])
    old_rev = re.findall(r"rev:(.+?);", str(rule_obj.rule))

    try:
        if len(old_rev) == 0:
            result = rule_obj.rule + 'rev:' + data[10] + ';'
        else:
            result = rule_obj.rule.replace(old_rev[0], str(int(data[10]) + 1))
        rule_obj.rule = result
        rule_obj.save()
    except Exception as e:
        record_log(rule_obj.sid, '规则修改同步rev', user, '失败', ip,
                   '错误信息:%s,原rev字段为%s,新rev字段为%s' % (e, old_rev, data[10]))


def syn_shield_flag(data, user, ip):
    """
    :describe:      同步修改后屏蔽标志内容到规则
    :param param1:  前端返回数据
    :param param2:  当前登录用户
    :return:        无
    """
    shield_flag = data[12]
    rule_obj = CompleteRule.objects.get(sid=data[0])
    if shield_flag == '是' and not rule_obj.rule.startswith('#'):
        rule_obj.rule = '#' + rule_obj.rule
        rule_obj.save()
        record_log(rule_obj.sid, '规则屏蔽', user, '成功', ip, '屏蔽一条snort规则')
    elif shield_flag == '否' and rule_obj.rule.startswith('#'):
        rule_obj.rule = rule_obj.rule.lstrip('#')
        rule_obj.save()
        record_log(rule_obj.sid, '取消屏蔽', user, '成功', ip, '取消屏蔽一条snort规则')
    elif shield_flag == '是' and rule_obj.rule.startswith('#'):
        record_log(rule_obj.sid, '规则屏蔽', user, '失败', ip, '该规则重复屏蔽')


def get_new_refs(data):
    """
    :describe:  获取并处理前端传来reference内容
    :param:     前端返回数据
    :return:    处理后reference列表
    """
    refs_str = data[2]
    new_refs_list = refs_str.split(';')
    refs_list = []
    for val in new_refs_list:
        refs_list.append(val.strip())
    [refs_list.remove(v) for v in refs_list if v == ""]
    return refs_list


def get_old_refs_str(rule):
    """
    :describe:  获取原规则中reference内容
    :param:     规则字符串
    :return:    reference字符串
    """
    result = re.findall(r'reference:(.+?);', rule)
    reference_str = ""
    for val in result:
        reference_str += 'reference:' + val + ';'
    return reference_str


def get_old_refs_list(old_refs_str):
    """
    :describe:  获取原规则中reference内容
    :param:     原规则中reference字符串
    :return:    reference列表
    """
    old_refs_list = old_refs_str.split(';')
    refs_list = []
    for val in old_refs_list:
        refs_list.append(val.strip())
    refs_list.remove('')
    return refs_list


def del_old_refs(rule, refs_list):
    """
    :describe:      删除规则旧reference内容
    :param param1:  处理后的传来的reference列表
    :param param2:  前端传来的数据
    :return:        删除旧reference后规则字符串
    """
    result = ""
    for val in refs_list:
        val += ';'
        if val in rule:
            result = rule.replace(val, "")
            rule = result
    return result


def insert_new_refs(result, refs_list):
    """
    :describe:      删除规则旧reference内容规则
    :param param1:  删除规则旧reference内容规则
    :param param2:  处理后的传来的reference列表
    :return:        更新后的规则字符串
    """
    sub_rule = result[0:len(result) - 1]
    reference_str = ""
    for val in refs_list:
        reference_str += 'reference:' + val + ';'
    final_rule = sub_rule + reference_str + ')'
    return final_rule


def syn_reference(data, user, ip):
    """
    :describe:      同步修改后reference内容到规则
    :param param1:  前端返回数据
    :param param2:  当前登录用户
    :return:        无
    """
    rule_obj = CompleteRule.objects.get(sid=data[0])
    try:
        rule = rule_obj.rule
        old_refs_str = get_old_refs_str(rule)
        old_refs_list = get_old_refs_list(old_refs_str)
        refs_list = get_new_refs(data)

        if len(refs_list) == 0:
            result = del_old_refs(rule, old_refs_list)
            rule_obj.rule = result
            rule_obj.save()
        else:
            if len(old_refs_list) != 0:
                result = del_old_refs(rule, old_refs_list)
                final_rule = insert_new_refs(result, refs_list)
                rule_obj.rule = final_rule
                rule_obj.save()
            else:
                final_rule = insert_new_refs(rule, refs_list)
                rule_obj.rule = final_rule
                rule_obj.save()
    except Exception as e:
        record_log(rule_obj.sid, '规则修改同步reference',
                   user, '失败', ip, '错误信息: %s' % (e))


def syn_sid(data, user, ip):
    """
    :describe:  同步修改后保持规则id不变
    :param:     前端返回数据
    :return:    无
    """
    rule_obj = CompleteRule.objects.get(sid=data[0])
    try:
        old_sid = re.findall(r"sid:(.+?);", str(rule_obj.rule))
        result = rule_obj.rule.replace(old_sid[0], data[0])
        rule_obj.rule = result
        rule_obj.save()
    except Exception as e:
        record_log(rule_obj.sid, '规则修改同步sid', user, '失败', ip, '错误信息: %s' % (e))


def synchro(data, user, ip):
    """
    :describe:      同步修改后特征内容到规则
    :param param1:  前端返回数据
    :param param2:  当前登录用户
    :return:        无
    """
    syn_msg(data, user, ip)
    syn_content(data, user, ip)
    syn_classtype(data, user, ip)
    syn_rev(data, user, ip)
    syn_shield_flag(data, user, ip)
    syn_reference(data, user, ip)
    syn_sid(data, user, ip)


def record_log(sid, act, per, statu, ip, message):
    """
    :describe:      记录操作日志
    :param param1:  规则ID
    :param param2:  操作行为
    :param param3:  操作人
    :param param4:  操作状态
    :param param5:  详细信息
    :return:        无
    """
    log_obj = Log.objects.create(
        sid=sid, action=act, time=get_date(),
        person=per, status=statu, ip=ip, msg=message)
    log_obj.save()


def update_features(rules_sections, id_list):
    """
    :describe:      获取自动同步来的有修改的规则特征
    :param param1:  规则字典
    :param param2:  规则修改列表(值: sid)
    :return:        无
    """
    rules = UpdateRule.objects.all()
    sid = [str(rule.sid) for rule in rules]
    for key, value in rules_sections.items():
        for k in id_list:
            if str(key) == str(k) and str(key) not in sid:
                UpdateRule.objects.create(sid=key, rule=value)
            else:
                continue


''' 获取实时日期 '''


def get_date():
    """
    :describe: 获取实时日期
    :param:    无
    :return:   当前日期
    """
    ts = time.time()
    date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
    return date

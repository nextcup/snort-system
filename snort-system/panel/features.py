# -*- coding: UTF-8 -*-
from models import *
from django.http import HttpResponse
from db import *
from enum import Enum, unique


@unique
class Features(Enum):
    """
    特征枚举
    """
    sid = 0  				            # 规则ID
    msg = 1  				            # 描述信息
    reference = 2  			            # 引用信息
    class_type = 3  		            # 类型
    malname = 4  			            # 家族名
    attacker = 5  			            # 攻击者
    victim = 6  			            # 受害者
    success_attack = 7  		        # 成功攻击
    controller = 8  			        # 控制源
    confirm_controlled = 9  	        # 确认被控
    rev = 10  				            # 修订版本
    knowledge_base = 11  		        # 知识库信息
    shield = 12  			            # 是否屏蔽
    contain = 13  			            # 出库包含
    first_check_position = 14  	        # 首次检出位置
    overall_first_check_position = 15  	# 整体首次检出位置
    check_out_numbers = 16  		    # 检出个数
    error_numbers = 17  		        # 误报个数
    feature_source = 18  		        # 特征源
    remarks = 19  			            # 备注
    content = 20  			            # 匹配信息


def get_add_content():
    """
    :describe:  获取新增content字段
    :param      无
    :return:    content拼接结果
    """
    new_content_str = ""
    for val in get_another_content_list():
        new_content_str += val["content"] + '\n'
    return new_content_str


def combina_content(data_dict):
    """
    :describe:  content及其选项组合
    :param      前端返回字典数据
    :return:    字典中content字段和选项字段组合为一个字段
    """
    options = ['offset', 'depth', 'nocase', 'distance', 'within']
    option_str = ""
    start_content = ""

    for key, val in data_dict.items():
        if key == 'content':
            start_content = key + ':"' + val + '";'
        elif key in options and val != "":
            if key == "nocase" and val == "true":
                option_str += key + ';'
            elif key == "nocase" and val == "false":
                pass
            else:
                option_str += key + ':' + val + ';'
        else:
            continue
    data_dict["content"] = start_content + option_str
    for val in options:
        if val in data_dict.keys():
            data_dict.pop(val)
        else:
            continue
    return data_dict


def get_new_content(key):
    """
    :describe:  提取更新来的规则content字段
    :param:     规则ID
    :return:    拼接后的content字符串
    """
    content = []
    content_str = ""
    options = ['offset', 'depth', 'nocase', 'distance', 'within']
    rule = UpdateRule.objects.get(sid=int(key)).rule
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


def get_receive_data(request):
    """
    :describe:      获取前端传来数据
    :param param1:  http请求 
    :return:        数据,当前用户
    """
    receive_data = None
    user = request.session["user_name"]
    if request.method == "POST":
        receive_data = request.POST.get('data')
        receive_data = json.loads(receive_data)
    receive_data = combina_content(receive_data)
    if get_status() == "success":
        receive_data.pop("content")
    return receive_data, user


def get_final_rule(request, sid):
    """
    :describe:      获取最终规则
    :param param1:  http请求
    :param param2:  规则ID
    :return:        规则, 前端传来数据, 当前用户
    """
    sub_rule = ""
    final_rule = ""
    receive_data = None
    no_loop_key = ['protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port']
    receive_data, user = get_receive_data(request)
    try:
        rule_str = 'alert ' + receive_data["protocol"] + ' ' + receive_data["src_ip"] + ' ' + receive_data[
            "src_port"] + ' -> ' + \
            receive_data["dst_ip"] + ' ' + receive_data["dst_port"] + ' ('
    except Exception as e:
        print 'error:', e
        return HttpResponse(0)
    for k in no_loop_key:
        receive_data.pop(k)
    for key, val in receive_data.items():
        if key == "msg" or key == "pcre":
            sub_rule = sub_rule + key + ':"' + val + '";'
        elif key == "content":
            sub_rule = sub_rule + val
        else:
            sub_rule = sub_rule + key + ':' + val + ';'
    final_rule = rule_str + sub_rule + 'sid:' + str(sid) + ';'
    another_content = get_another_content_list()
    if another_content is not None:
        for val in another_content:
            final_rule += val["content"]
        final_rule += ')'
    return final_rule, receive_data, user


def syn_new_rule(sid, new_rule, user, ip):
    """
    :describe:      规则添加后同步规则入库
    :param param1:  规则ID
    :param param2:  规则字符串
    :param param3:  当前登录用户
    :return:        True:同步成功 False:同步失败
    """
    try:
        rule_obj = CompleteRule.objects.create(sid=str(sid), rule=new_rule)
        rule_obj.save()
        record_log(str(sid), '新增规则', user, '成功', ip, '成功新增一条snort规则并且规则成功入库')
        return True
    except Exception as e:
        record_log(str(sid), '新增规则', user, '失败', ip, '错误信息:%s' % (e))
        return False


def syn_features(sid, receive_data, user, ip):
    """
    :describe:      规则添加后同步特征入库
    :param param1:  规则ID
    :param param2:  前端返回字典数据(key:特征,value:具体值)
    :param param3:  当前登录用户
    :return:        True:同步成功 False:同步失败
    """
    if 'reference' in receive_data.keys():
        refs = receive_data['reference']
    else:
        refs = ""
    try:
        rule_obj = Rule.objects.create(
            sid=str(sid),
            msg=receive_data["msg"],
            reference=refs,
            class_type=receive_data["classtype"],
            malname=receive_data["classtype"] + '/Generic.' + str(sid),
            attacker='',
            victim='',
            success_attack='',
            controller='',
            confirm_controlled='',
            rev=receive_data["rev"],
            create_time=get_date(),
            update_time=get_date(),
            is_translate='否',
            content=get_add_content(),
            has_conflict='否'
        )
        rule_obj.save()
        record_log(str(sid), '新增规则后特征入库', user, '成功',
                   ip, '成功新增一条snort规则并且特征成功入库')
        return True
    except Exception as e:
        record_log(str(sid), '新增规则后特征入库', user, '失败', ip, '错误信息:%s' % (e))
        return False


def compare(old_features, new_features, user, ip):
    """
    :describe:      记录被修改的特征字段
    :param param1:  规则修改之前特征
    :param param2:  规则修改之后特征
    :param param3:  当前登录用户
    :return:        无
    """
    set_default_env()
    for k, v in old_features.items():
        for enum_v in Features:
            if k in str(enum_v):
                if k == 'id' or k == 'rev':
                    continue
                if v != new_features[enum_v.value]:
                    if v != "":
                        record_log(new_features[0], '规则修改', user, '成功', ip, '%s字段由%s修改为%s' % (
                            k, v, new_features[enum_v.value]))
                    else:
                        record_log(new_features[0], '规则修改', user, '成功', ip, '%s字段被设置为%s' % (
                            k, new_features[enum_v.value]))
                else:
                    continue
            else:
                continue

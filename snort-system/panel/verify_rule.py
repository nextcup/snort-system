# -*- coding: UTF-8 -*-
import commands
import re
from db import *


def rules_verify(rule):
    """
    :describe:  验证规则是否被支持
    :param:     待验证规则文件
    :return:    True:支持 False:不支持
    """
    cmd = './tool/test_tool ' + rule
    result = commands.getstatusoutput(cmd)
    result = re.findall(r'Rule(.+?):', str(result))
    if len(result) != 0:
        if 'unsupported' in result[0]:
            return False
        else:
            return True
    else:
        return True


def is_hit(rule, pcap, user, ip):
    """
    :describe:      检测规则是否命中pcap
    :param param1:  待检测规则文件
    :param param2:  待检测pcap文件
    :param param3:  当前登录用户
    :return:        True:命中 False:未命中
    """
    cmd = './tool/test_tool ' + rule + ' ' + pcap
    result = commands.getstatusoutput(cmd)

    set_default_env()
    if 'hit rules' in str(result):
        record_log(filter(str.isdigit, rule), '规则检测',
                   user, '成功', ip, '%s成功命中规则%s' % (pcap, rule))
        return True
    record_log(filter(str.isdigit, rule), '规则检测',
               user, '失败', ip, '%s未命中规则%s' % (pcap, rule))
    return False

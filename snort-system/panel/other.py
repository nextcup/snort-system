# -*- coding: UTF-8 -*-
import random
import hashlib
from db import *
from django.core.paginator import Paginator


def has_chinese(pattern):
    """
    :describe:  判断是否包含中文
    :param:     待判断字符串
    :return:    True: 包含 False: 不包含
    """
    set_default_env()
    for ch in pattern.decode('utf-8'):
        if u'\u4e00' <= ch <= u'\u9fff':
            return True
    return False


def random_sid():
    """
    :describe:  随机生成规则ID值(200万-300万)
    :param:     无
    :return:    生成的ID
    """
    sid = random.randint(2e6, 3e6)
    return sid


def encryption(clear_passwd, salt='snort'):
    """
    :describe:      密码加密(sha256算法)
    :param param1:  明文密码
    :param param2:  加密盐
    :return:        加密后密码
    """
    hash_obj = hashlib.sha256()
    clear_passwd += salt
    hash_obj.update(clear_passwd.encode())
    return hash_obj.hexdigest()


def set_page_data(request, rules_summary):
    """
    :param param1:  http请求
    :param param2:  查询结果
    :return:        分页对象及数据
    """
    paginator = Paginator(rules_summary, 10)
    page = request.GET.get('page', 1)
    result = paginator.page(page)
    return paginator, result

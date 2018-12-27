# -*- coding: UTF-8 -*-


from django.db import models

# Create your models here.


class User(models.Model):
    """
    用户表
    """
    username = models.CharField(max_length=200, verbose_name='用户名')
    password = models.CharField(max_length=128, verbose_name='密码')


class Rule(models.Model):
    """
    规则特征表
    """
    sid = models.CharField(unique=True, max_length=10, verbose_name='规则ID')
    msg = models.CharField(max_length=128, verbose_name='描述信息')
    reference = models.CharField(max_length=128, verbose_name='引用信息')
    class_type = models.CharField(max_length=64, verbose_name='类型')
    malname = models.CharField(
        null=True, max_length=128, default="", verbose_name='恶意家族名')
    attacker = models.CharField(
        null=True, max_length=10, default="", verbose_name='攻击者')
    victim = models.CharField(null=True, max_length=10,
                              default="", verbose_name='受害者')
    success_attack = models.CharField(
        null=True, max_length=10, default="", verbose_name='是否成功攻击')
    controller = models.CharField(
        null=True, max_length=10, default="", verbose_name='控制者')
    confirm_controlled = models.CharField(
        null=True, max_length=10, default="", verbose_name='确认被控')
    rev = models.CharField(max_length=10, verbose_name='修订版本')
    knowledge_base = models.CharField(
        null=True, max_length=128, default="", verbose_name='知识库信息')
    create_time = models.CharField(max_length=20, verbose_name='规则创建时间')
    update_time = models.CharField(max_length=20, verbose_name='规则修改时间')
    shield = models.CharField(null=True, max_length=10,
                              default="", verbose_name='是否屏蔽')
    contain = models.CharField(
        null=True, max_length=10, default="", verbose_name='是否出库包含')
    first_check_time = models.DateField(verbose_name='首次检出时间', auto_now=True)
    first_check_position = models.CharField(
        null=True, max_length=10, default="", verbose_name='首次检出位置')
    overall_first_check_time = models.DateField(
        verbose_name='整体首次检出时间', auto_now=True)
    overall_first_check_position = models.CharField(
        null=True, max_length=10, default="", verbose_name='整体首次检出位置')
    check_out_numbers = models.CharField(
        null=True, max_length=10, default="", verbose_name='检出个数')
    error_numbers = models.CharField(
        null=True, max_length=10, default="", verbose_name='误报个数')
    feature_source = models.CharField(
        null=True, max_length=10, default="", verbose_name='特征来源')
    remarks = models.CharField(
        null=True, max_length=10, default="", verbose_name='备注')
    is_translate = models.CharField(max_length=5, verbose_name='是否翻译')
    content = models.CharField(max_length=150, verbose_name='匹配内容')
    has_conflict = models.CharField(max_length=5, verbose_name='是否冲突')


class CompleteRule(models.Model):
    """
    完整规则表
    """
    sid = models.CharField(unique=True, max_length=10, verbose_name='规则ID')
    rule = models.CharField(max_length=500, verbose_name='完整规则')


class Log(models.Model):
    """
    操作日志表
    """
    sid = models.CharField(max_length=10, verbose_name='规则ID')
    action = models.CharField(max_length=100, verbose_name='动作')
    time = models.CharField(max_length=50, verbose_name='时间')
    person = models.CharField(max_length=20, verbose_name='操作人')
    status = models.CharField(max_length=20, verbose_name='状态')
    msg = models.CharField(max_length=100, verbose_name='详细描述')
    ip = models.IPAddressField(max_length=20, verbose_name='访问IP')


class UpdateRule(models.Model):
    """
    暂存更新来的带有冲突的规则
    """
    sid = models.CharField(max_length=10, verbose_name='规则ID')
    rule = models.CharField(max_length=500, verbose_name='新规则')


class RulePcap(models.Model):
    """
    暂存成功匹配的规则和pcap信息
    """
    sid = models.CharField(max_length=10, verbose_name='规则ID')
    pcap = models.CharField(max_length=50, verbose_name='pcap信息')

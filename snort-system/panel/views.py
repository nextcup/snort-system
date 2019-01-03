#!/usr/bin/python
# -*- coding: UTF-8 -*-


from django.shortcuts import render_to_response
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.views.generic import TemplateView, ListView
from django.http import StreamingHttpResponse
from update import *
from verify_pcap import *
from time_range import *
from features import *
from xlsx import *
from verify_rule import *
from other import *
from stor import *
import json


# Create your views here.


class Show(ListView):
    """
    规则概要展示
    """
    template_name = 'rules.html'
    paginate_by = 10

    def get_queryset(self):
        """
        :param:   类对象
        :return:  数据库特征表实例
        """
        rules_summary = Rule.objects.all()
        return rules_summary

    def set_data(self):
        """
        :param:   类对象
        :return:  分页对象, 每页数据
        """
        rules_summary = self.get_queryset()
        paginator = Paginator(rules_summary, 10)
        page = self.request.GET.get('page', 1)
        result = paginator.page(page)
        return paginator, result

    def get_context_data(self, **kwargs):
        """
        :param param1: 类对象
        :param param2: 可变参
        :return:       将分页对象和每页数据通过context封装返回
        """
        context = super(Show, self).get_context_data(**kwargs)
        context['paginator'], context['rules_sections'] = self.set_data()
        return context


class LogShow(ListView):
    """
    日志展示
    """
    template_name = 'log.html'
    paginate_by = 10

    def get_queryset(self):
        """
        :param:  类对象
        :return: 数据库日志表实例
        """
        logs = Log.objects.all()
        return logs

    def set_data(self):
        """
        :param:  类对象
        :return: 分页对象, 每页数据
        """
        logs = self.get_queryset()
        paginator = Paginator(logs, 10)
        page = self.request.GET.get('page', 1)
        result = paginator.page(page)
        return paginator, result

    def get_context_data(self, **kwargs):
        """
        :param param1:  类对象
        :param param2:  可变参
        :return:        将分页对象和每页数据通过context封装返回
        """
        context = super(LogShow, self).get_context_data(**kwargs)
        context['paginator'], context['rules_sections'] = self.set_data()
        return context


class Untranslate(ListView):
    """
    未翻译界面
    """
    template_name = 'untranslate.html'
    paginate_by = 10

    def get_queryset(self):
        """
        :param:  类对象
        :return: 数据库中未翻译的规则集合实例
        """
        rules_summary = Rule.objects.filter(is_translate='否')
        return rules_summary

    def set_data(self):
        """
        :param:  类对象
        :return: 分页对象, 每页数据
        """
        rules_summary = self.get_queryset()
        paginator = Paginator(rules_summary, 10)
        page = self.request.GET.get('page', 1)
        result = paginator.page(page)
        return paginator, result

    def get_context_data(self, **kwargs):
        """
        :param param1:  类对象
        :param param2:  可变参
        :return:        将分页对象和每页数据通过context封装返回
        """
        context = super(Untranslate, self).get_context_data(**kwargs)
        context['paginator'], context['rules_sections'] = self.set_data()
        return context


class ConflictShow(ListView):
    """
    冲突列表展示
    """
    template_name = 'conflict.html'
    paginate_by = 10

    def get_queryset(self):
        """
        :param:  类对象
        :return: 数据库中冲突的规则集合实例
        """
        rules = Rule.objects.filter(has_conflict='是')
        return rules

    def set_data(self):
        """
        :param:  类对象
        :return: 分页对象, 每页数据
        """
        rules = self.get_queryset()
        paginator = Paginator(rules, 10)
        page = self.request.GET.get('page', 1)
        result = paginator.page(page)
        return paginator, result

    def get_context_data(self, **kwargs):
        """
        :param param1:  类对象
        :param param2:  可变参
        :return:        将分页对象和每页数据通过context封装返回
        """
        context = super(ConflictShow, self).get_context_data(**kwargs)
        context['paginator'], context['rules_sections'] = self.set_data()
        return context


class SearchResult(object):
    """
    规则特征查询
    """

    def __init__(self):
        self.rules_summary = None
        self.search_data = get_search_data()
        self.start, self.end = get_start_end(get_date_range())
        self.option = get_option()

    def deal_not_chinese(self):
        """
        :param:  类对象
        :return: 用户输入的查询数据
        """
        if not has_chinese(self.search_data):
            self.search_data = str(self.search_data).strip()
            return self.search_data
        return self.search_data

    def option_is_sid(self):
        """
        :param:  类对象
        :return: 规则ID查询结果
        """
        self.search_data = self.deal_not_chinese()
        if self.start == "" and self.end == "":
            self.rules_summary = Rule.objects.filter(
                sid__contains=self.search_data)
        else:
            self.rules_summary = Rule.objects.filter(
                sid__contains=self.search_data, update_time__gte=self.start, update_time__lte=self.end)
        return self.rules_summary

    def option_is_msg(self):
        """
        :param:  类对象
        :return: 规则描述信息查询结果
        """
        self.search_data = self.deal_not_chinese()
        if self.start == "" and self.end == "":
            self.rules_summary = Rule.objects.filter(
                msg__contains=self.search_data)
        else:
            self.rules_summary = Rule.objects.filter(
                msg__contains=self.search_data, update_time__gte=self.start, update_time__lte=self.end)
        return self.rules_summary

    def option_is_classtype(self):
        """
        :param:  类对象
        :return: 规则病毒类型查询结果
        """
        self.search_data = self.deal_not_chinese()
        if self.start == "" and self.end == "":
            self.rules_summary = Rule.objects.filter(
                class_type__contains=self.search_data)
        else:
            self.rules_summary = Rule.objects.filter(
                class_type__contains=self.search_data, update_time__gte=self.start, update_time__lte=self.end)
        return self.rules_summary

    def option_is_malname(self):
        """
        :param:  类对象
        :return: 规则恶意家族查询结果
        """
        self.search_data = self.deal_not_chinese()
        if self.start == "" and self.end == "":
            self.rules_summary = Rule.objects.filter(
                malname__contains=self.search_data)
        else:
            self.rules_summary = Rule.objects.filter(
                malname__contains=self.search_data, update_time__gte=self.start, update_time__lte=self.end)
        return self.rules_summary

    def option_is_date_range(self):
        """
        :param:  类对象
        :return: 规则修改时间范围查询结果
        """
        self.rules_summary = Rule.objects.filter(
            update_time__gte=self.start, update_time__lte=self.end)
        return self.rules_summary


class UntransSearchResult(object):
    """
    未翻译规则查询
    """

    def __init__(self):
        self.rules_summary = None
        self.search_data = get_untrans_search_data()
        self.option = get_untrans_option()

    def deal_not_chinese(self):
        """
        :param:  类对象
        :return: 用户输入的查询数据
        """
        if not has_chinese(self.search_data):
            self.search_data = str(self.search_data).strip()
            return self.search_data
        return self.search_data

    def option_is_sid(self):
        """
        :param:  类对象
        :return: 规则ID查询结果
        """
        self.search_data = self.deal_not_chinese()
        self.rules_summary = Rule.objects.filter(
            sid__contains=self.search_data, is_translate='否')
        return self.rules_summary

    def option_is_msg(self):
        """
        :param:  类对象
        :return: 规则描述信息查询结果
        """
        self.search_data = self.deal_not_chinese()
        self.rules_summary = Rule.objects.filter(
            msg__contains=self.search_data, is_translate='否')
        return self.rules_summary

    def option_is_classtype(self):
        """
        :param:  类对象
        :return: 规则病毒类型查询结果
        """
        self.search_data = self.deal_not_chinese()
        self.rules_summary = Rule.objects.filter(
            class_type__contains=self.search_data, is_translate='否')
        return self.rules_summary

    def option_is_malname(self):
        """
        :param:  类对象
        :return: 规则恶意家族查询结果
        """
        self.search_data = self.deal_not_chinese()
        self.rules_summary = Rule.objects.filter(
            malname__contains=self.search_data, is_translate='否')
        return self.rules_summary


class Add(TemplateView):
    """
    新增规则界面
    """
    template_name = 'new_rules.html'


class Shield(TemplateView):
    """
    规则屏蔽界面
    """
    template_name = 'shield.html'


class Edit(TemplateView):
    """
    规则修改界面
    """
    template_name = 'edit.html'


class Upload(TemplateView):
    """
    文件上传界面
    """
    template_name = 'upload.html'


class Download(TemplateView):
    """
    导出规则文件界面
    """
    template_name = 'download.html'


class About(TemplateView):
    """
    系统功能简介界面
    """
    template_name = 'about.html'


class DownloadPcap(TemplateView):
    """
    下载pcap界面
    """
    template_name = 'download_pcap.html'


class DeletePcap(TemplateView):
    """
    删除pcap界面
    """
    template_name = 'delete_pcap.html'


class Xlsx(TemplateView):
    """
    导出xlsx表格界面
    """
    template_name = 'xlsx.html'


class PcapUpload(TemplateView):
    """
    pcap上传界面
    """
    template_name = 'pcap_upload.html'


def backstage(request):
    """
    :describe:  系统后台界面显示
    :param      http请求
    :return:    系统后台界面
    """
    start_update()
    try:
        user_now = request.session['user_name']
    except Exception as e:
        print 'login error:', e
        return HttpResponse('错误: 请访问http://192.168.18.182:8000/登陆!')
    return render_to_response('backstage.html', {'user': user_now})


@csrf_exempt
def register(request):
    """
    :describe:  用户注册
    :param      http请求
    :return:    登陆、注册界面
    """
    if request.method == 'GET':
        return render_to_response('index.html')

    username = request.POST.get('username_register')
    clear_passwd = request.POST.get('password_register')
    password = encryption(clear_passwd)

    if User.objects.filter(username=username):
        return HttpResponse(0)

    user = User.objects.create(username=username, password=password)
    ip = get_ip(request)
    if user:
        request.session['is_register'] = True
        record_log('无', '用户注册', username, '成功', ip, '用户成功注册')
        return HttpResponse(1)
    else:
        return HttpResponse(0)

    return render_to_response('index.html')


@csrf_exempt
def login(request):
    """
    :describe:  用户登录
    :param      http请求
    :return:    登陆响应值 0:成功 1:失败
    """
    if request.method == 'GET':
        return render_to_response('index.html')

    username = request.POST.get('username')
    password = request.POST.get('password')

    user = User.objects.filter(
        username=username, password=encryption(password))
    ip = get_ip(request)
    if request.session.get('is_login', None):
        if request.session['user_name'] == username:
            return HttpResponse(2)
    if user:
        request.session['is_login'] = True
        request.session['user_name'] = username
        record_log('无', '用户登录', username, '成功', ip, '用户成功登陆')
        return HttpResponse(1)
    else:
        return HttpResponse(0)


def logout(request):
    """
    :describe:  注销
    :param      http请求
    :return:    注销后返回注册、登陆界面
    """
    if not request.session.get('is_login', None):
        return render_to_response('index.html')
    ip = get_ip(request)
    username = request.session['user_name']
    record_log('无', '用户注销', username, '成功', ip, '用户成功注销')
    request.session.flush()

    return render_to_response('index.html')


@csrf_exempt
def detail_show(request):
    """
    :describe:  查看规则详情
    :param      http请求
    :return:    特征详情界面及其包含的数据
    """
    if request.method == 'POST':
        set_sid(request.POST.get('sid'))
        set_rule_data(Rule.objects.get(sid=get_sid()))

    return render_to_response('view_detail.html', {'rule': get_rule_data()})


@csrf_exempt
def complete_show(request):
    """
    :describe:  查看完整规则
    :param      http请求
    :return:    完整规则界面及其包含的数据
    """
    if request.method == 'POST':
        set_sid(request.POST.get('sid'))
        set_rule_data(CompleteRule.objects.get(sid=get_sid()))

    return render_to_response('complete.html', {'rule': get_rule_data()})


def log_detail(request):
    """
    :describe:  查看日志详情
    :param      http请求
    :return:    日志详情界面及其历史日志数据
    """
    index = 1
    msg_str = ""
    final_str = ""

    if request.method == 'POST':
        set_default_env()
        set_sid(request.POST.get('sid'))

        rules_summary = Log.objects.filter(sid=str(get_sid()))

        for v in rules_summary:
            msg_str = str(index) + '.  ' + msg_str + v.msg + \
                '    ' + v.time + '    ' + v.person + '\n\n'
            final_str += msg_str
            msg_str = ""
            index += 1
        set_history_log(final_str)

    return render_to_response('log_detail.html', {'rules_sections': get_history_log()})


@csrf_exempt
def search(request):
    """
    :describe:  特征概要模块查询
    :param      http请求
    :return:    响应值 0:成功 1:失败 成功后跳转结果展示
    """
    if request.method == 'GET':
        return render_to_response('rules.html')

    set_search_data(request.POST.get('search_data'))
    set_option(request.POST.get('option'))
    set_date_range(request.POST.get('date_range'))

    if get_search_data() or get_date_range():
        return HttpResponse(1)

    return HttpResponse(0)


''' 未翻译查询功能 '''


@csrf_exempt
def untrans_search(request):
    """
    :describe:  未翻译模块查询
    :param      http请求
    :return:    响应值 0:成功 1:失败 成功后跳转结果展示
    """
    if request.method == 'GET':
        return render_to_response('untranslate.html')

    set_untrans_search_data(request.POST.get('search_data'))
    set_untrans_option(request.POST.get('option'))

    if get_untrans_search_data():
        return HttpResponse(1)
    return HttpResponse(0)


def search_result(request):
    """
    :describe:  特征概要查询结果展示
    :param      http请求
    :return:    查询结果且分页展示
    """
    rules_summary = None
    search_obj = SearchResult()
    set_default_env()

    if 'sid' in search_obj.option:
        rules_summary = search_obj.option_is_sid()
    elif 'msg' in search_obj.option:
        rules_summary = search_obj.option_is_msg()
    elif 'class_type' in search_obj.option:
        rules_summary = search_obj.option_is_classtype()
    elif 'malname' in search_obj.option:
        rules_summary = search_obj.option_is_malname()
    elif '时间范围' in search_obj.option:
        rules_summary = search_obj.option_is_date_range()

    if rules_summary is None:
        return render_to_response('result.html', {'rules_sections': None})

    paginator, result = set_page_data(request, rules_summary)

    return render_to_response('result.html', {'rules_sections': result, 'paginator': paginator})


def untrans_result(request):
    """
    :describe:  未翻译模块查询结果展示
    :param      http请求
    :return:    查询结果且分页展示
    """
    rules_summary = None
    untrans_search_obj = UntransSearchResult()

    if 'sid' in untrans_search_obj.option:
        rules_summary = untrans_search_obj.option_is_sid()
    elif 'msg' in untrans_search_obj.option:
        rules_summary = untrans_search_obj.option_is_msg()
    elif 'class_type' in untrans_search_obj.option:
        rules_summary = untrans_search_obj.option_is_classtype()
    elif 'malname' in untrans_search_obj.option:
        rules_summary = untrans_search_obj.option_is_malname()

    paginator, result = set_page_data(request, rules_summary)

    return render_to_response('untrans_result.html', {'rules_sections': result, 'paginator': paginator})


@csrf_exempt
def add_content(request):
    """
    :describe:  添加多条content字段请求
    :param      http请求
    :return:    响应值 0:失败 1:成功
    """
    if request.method == "POST":
        try:
            receive_data = request.POST.get('another_content')
            status = request.POST.get('status')
            receive_data = json.loads(receive_data)
            set_another_content_list(receive_data)
            set_status(status)
        except Exception as e:
            print 'error: ', e
            return HttpResponse(0)

    return HttpResponse(1)


@csrf_exempt
def add_submit(request):
    """
    :describe:  新增规则并检验规则
    :param      http请求
    :return:    响应值 0:失败 1:成功 2:规则不支持
    """
    sid = random_sid()
    ip = get_ip(request)
    final_rule, receive_data, user = get_final_rule(request, sid)
    # 规则验证
    new_rule_path = get_pcap_path() + 'new.rules'
    with open(new_rule_path, 'w')as f:
        f.write(final_rule + '\n')
    if len(get_another_content_list()) == 0:
        return HttpResponse(3)
    if not rules_verify(new_rule_path):
        os.system('rm -rf ' + new_rule_path)
        return HttpResponse(2)
    os.system('rm -rf ' + new_rule_path)
    # 存储特征
    if not syn_features(sid, receive_data, user, ip):
        return HttpResponse(0)
    # 存储规则
    if not syn_new_rule(sid, final_rule, user, ip):
        return HttpResponse(0)
    reset_content()
    return HttpResponse(1)


@csrf_exempt
def shield(request):
    """
    :describe: 规则屏蔽
    :param:    http请求
    :return:   响应值: 0:失败 1:成功
    """
    # 屏蔽指定规则
    sid = request.POST.get('id')
    rule_obj = Rule.objects.get(id=sid)
    user = request.session['user_name']
    ip = get_ip(request)

    complete_rule = None
    try:
        complete_rule = CompleteRule.objects.get(sid=rule_obj.sid)
    except Exception as e:
        Rule.objects.filter(sid=rule_obj.sid).update(shield='否')
        record_log(rule_obj.sid, '规则屏蔽', user, '失败', ip, e)
        return HttpResponse(0)

    if complete_rule.rule.startswith('#'):
        record_log(rule_obj.sid, '规则屏蔽', user, '失败', ip, '该规则重复屏蔽')
        return HttpResponse(0)

    CompleteRule.objects.filter(sid=rule_obj.sid).update(
        rule="#" + complete_rule.rule)
    Rule.objects.filter(sid=rule_obj.sid).update(shield='是')
    record_log(rule_obj.sid, '规则屏蔽', user, '成功', ip, '规则屏蔽成功')

    return HttpResponse(1)


def get_ip(request):
    """
    :describe: 获取访问ip
    :param:    http请求
    :return:   ip地址
    """
    ip = None
    if request.META.has_key('HTTP_X_FORWARDED_FOR'):
        ip = request.META['HTTP_X_FORWARDED_FOR']
    else:
        ip = request.META['REMOTE_ADDR']
    return ip


@csrf_exempt
def edit(request):
    """
    :describe: 规则特征修改
    :param:    http请求
    :return:   响应值: 0:失败 1:成功
    """
    # 弹窗显示规则指定字段,可编辑并保存
    if request.method == 'GET':
        return render_to_response('rules.html')

    data = request.POST.getlist('data')
    user = request.session['user_name']
    ip = get_ip(request)
    flag = request.POST.get('flag')
    old_features_dict = {}

    if data:
        # 记录修改之前的特征
        old_features_dict = Rule.objects.filter(sid=str(data[0])).values()[0]
        # 将修改后内容插入数据库
        Rule.objects.filter(sid=data[Features.sid.value]).update(
            msg=data[Features.msg.value],
            reference=data[Features.reference.value],
            class_type=data[Features.class_type.value],
            malname=data[Features.malname.value],
            attacker=data[Features.attacker.value],
            victim=data[Features.victim.value],
            success_attack=data[Features.success_attack.value],
            controller=data[Features.controller.value],
            confirm_controlled=data[Features.confirm_controlled.value],
            rev=str(int(data[Features.rev.value]) + 1),
            knowledge_base=data[Features.knowledge_base.value],
            shield=data[Features.shield.value],
            contain=data[Features.contain.value],
            first_check_position=data[Features.first_check_position.value],
            overall_first_check_position=data[Features.overall_first_check_position.value],
            check_out_numbers=data[Features.check_out_numbers.value],
            error_numbers=data[Features.error_numbers.value],
            feature_source=data[Features.feature_source.value],
            remarks=data[Features.remarks.value],
            content=data[Features.content.value],
            update_time=get_date())

        if flag == 'conflict_flag':
            record_log(data[0], '冲突解决', user, '成功', ip, '自动更新发生冲突解决')
            Rule.objects.filter(sid=data[0]).update(has_conflict='否')
            if len(get_edited_rule_id()) != 0:
                get_edited_rule_id().remove(data[0])
            UpdateRule.objects.get(sid=data[0]).delete()
        else:
            pass
        compare(old_features_dict, data, user, ip)
        synchro(data, user, ip)
        return HttpResponse(1)
    return HttpResponse(0)


@csrf_exempt
def upload(request):
    """
    :describe: pcap上传
    :param:    http请求
    :return:   响应状态: 成功 失败 格式 是否选择 支持情况
    """
    set_default_env()

    if request.method == "POST":
        sid = request.POST.get('sid')
        if sid is not None:
            set_id(sid)
        rule = CompleteRule.objects.get(sid=get_id())
        # 将规则写入文件
        checked_rule = write_check_rule(get_id(), rule.rule)
        if checked_rule is None:
            return HttpResponse('待检测规则写入文件失败!')
        # 调用工具判断规则是否支持
        if not rules_verify(checked_rule):
            return HttpResponse('规则不支持,请修改或屏蔽!')

        result = upload_pcap(request, checked_rule)
        return HttpResponse(result)
    return HttpResponse("上传失败!")


@csrf_exempt
def hit_pcap_rule(request):
    hit_rule_obj = GetHitRule()
    return_str, pcap_path = upload_pcap_hit_rule(request)
    if return_str != "":
        return HttpResponse(return_str)
    check_pcap_rules(pcap_path)
    hit_rule_obj.touch_result_file()
    tips = hit_rule_obj.get_hit_result()
    hit_rule_obj.del_result_file()
    return HttpResponse(tips)


@csrf_exempt
def trans_submit(request):
    """
    :describe:  规则翻译
    :param:     http请求
    :return:    响应值 0:失败 1:成功
    """
    if request.method == 'GET':
        return render_to_response('untranslate.html')

    trans_msg = request.POST.get('msg')
    rule_sid = get_trans_sid()
    rule_obj = Rule.objects.get(sid=rule_sid)
    Rule.objects.filter(sid=rule_sid).update(msg=trans_msg, is_translate='是')
    user = request.session['user_name']
    ip = get_ip(request)
    set_default_env()
    record_log(rule_sid, '规则翻译', user, '成功', ip,
               '将%s翻译为%s' % (rule_obj.msg, trans_msg))

    return HttpResponse(1)


@csrf_exempt
def download(request):
    """
    :describe:  规则导出
    :param:     http请求
    :return:    导出的文件对象
    """
    db_to_file()
    extract_contain_feature()
    generate_zip()
    path = get_zip_path()

    file = None
    try:
        file = open(path, 'rb')
    except Exception as e:
        print e
        return HttpResponse('待导出文件打开出错')
    response = StreamingHttpResponse(file)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="rules.zip"'
    user = request.session['user_name']
    ip = get_ip(request)
    set_default_env()
    record_log('无', '规则导出', user, '成功', ip,
               '导出文件为rules.zip,下载路径为%s' % (path))

    return response


def upload_pcap(request, checked_rule):
    return_str = ""
    myFile = request.FILES.get("myfile", None)
    if not myFile:
        return_str = "未选择文件!"
        return return_str
    if not str(myFile).endswith('.pcap'):
        return_str = "文件格式错误"
        return return_str
    pcap_path = get_upload_path() + str(myFile)

    path = get_upload_path()
    destination = open(os.path.join(path, myFile.name), 'wb+')
    for chunk in myFile.chunks():
        destination.write(chunk)
    destination.close()
    user = request.session['user_name']
    ip = get_ip(request)
    if is_hit(checked_rule, pcap_path, user, ip) is False:
        set_default_env()
        tips = '%s号规则与pcap包%s未命中' % (get_id(), myFile)
        # 删除未命中pcap
        cmd = 'rm -rf ./data/pcaps/' + str(myFile)
        os.system(cmd)
        return tips
    record_log('无', '文件上传', user, '成功', ip,
               '文件为%s,服务器存储路径为%s' % (myFile.name, path))
    # 存储成功匹配的规则和pcap信息
    stor_rule_pcap(get_id(), myFile)
    tips = '%s号规则与pcap包%s成功命中' % (get_id(), myFile)
    return tips


def deal(request):
    """
    :describe:  冲突数据获取
    :param:     http请求
    :return:    无
    """
    if request.method == 'POST':
        set_sid(request.POST.get('sid'))
        set_rule_data(Rule.objects.get(sid=get_sid()))

        rule_obj = UpdateRule.objects.get(sid=get_sid())

        set_update_sid(re.findall(r'sid:(.+?);', rule_obj.rule))
        set_update_msg(re.findall(r'msg:\"(.+?)\";', rule_obj.rule))
        set_update_reference(re.findall(
            r'reference:(.+?);', rule_obj.rule))
        set_update_content(get_new_content(get_sid()))
        set_update_classtype(re.findall(r'classtype:(.+?);', rule_obj.rule))

    return render_to_response(
        'deal.html', {
            'rule': get_rule_data(),
            'sid': get_update_sid()[0],
            'msg': get_update_msg()[0],
            'reference': get_update_reference(),
            'content': get_update_content(),
            'class_type': get_update_classtype()[0]

        })


@csrf_exempt
def deal_conflict(request):
    """
    :describe:  冲突解决
    :param:     http请求
    :return:    响应值 0:失败 1:成功
    """
    set_default_env()
    if request.method == 'GET':
        return render_to_response('conflict.html')

    data = request.POST.getlist('data')
    user = request.session['user_name']
    ip = get_ip(request)

    if data:
        # 将修改后内容插入数据库
        Rule.objects.filter(sid=data[Features.sid.value]).update(
            msg=data[Features.msg.value],
            reference=data[Features.reference.value],
            class_type=data[Features.class_type.value],
            malname=data[Features.malname.value],
            attacker=data[Features.attacker.value],
            victim=data[Features.victim.value],
            success_attack=data[Features.success_attack.value],
            controller=data[Features.controller.value],
            confirm_controlled=data[Features.confirm_controlled.value],
            rev=data[Features.rev.value],
            knowledge_base=data[Features.knowledge_base.value],
            shield=data[Features.shield.value],
            contain=data[Features.contain.value],
            first_check_position=data[Features.first_check_position.value],
            overall_first_check_position=data[Features.overall_first_check_position.value],
            check_out_numbers=data[Features.check_out_numbers.value],
            error_numbers=data[Features.error_numbers.value],
            feature_source=data[Features.feature_source.value],
            remarks=data[Features.remarks.value],
            content=data[Features.content.value],
            update_time=get_date())

        record_log(data[0], '冲突解决', user, '成功', ip, '自动更新发生冲突解决')
        synchro(data, user)
        Rule.objects.filter(sid=data[0]).update(has_conflict='否')
        if len(get_edited_rule_id()) != 0:
            get_edited_rule_id().remove(data[0])
        UpdateRule.objects.get(sid=data[0]).delete()

        return HttpResponse(1)
    record_log('无', '冲突解决', user, '失败', ip, '数据有误')
    return HttpResponse(0)


@csrf_exempt
def download_pcap(request):
    """
    :describe:  pcap下载
    :param:     http请求
    :return:    下载的文件
    """
    pcap = ""
    sid = request.POST.get('sid')
    if sid is not None:
        set_rule_pcap(sid)

    rules = RulePcap.objects.all()
    if len(rules) == 0:
        return HttpResponse('该规则无命中的pcap')
    for rule in rules:
        if rule.sid == get_rule_pcap():
            pcap = rule.pcap

    file_list = []
    path = get_pcap_path()
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            if name.endswith('.pcap') and pcap in name and pcap != "":
                file_list.append(os.path.join(root, name))
            else:
                continue

    if len(file_list) == 0:
        return HttpResponse('该规则无命中的pcap')

    file = open(file_list[0], 'rb')
    response = StreamingHttpResponse(file)
    response['Content-Type'] = 'application/octet-stream'

    response['Content-Disposition'] = 'attachment;filename="rule.pcap"'
    user = request.session['user_name']
    ip = get_ip(request)
    set_default_env()
    record_log('无', 'pcap下载', user, '成功', ip,
               '导出文件为rule.pcap,下载路径为%s' % (path))
    return response


@csrf_exempt
def pcap_delete(request):
    """
    :describe:  pcap删除
    :param:     http请求
    :return:    响应状态: 成功 未命中(不包含此规则pcap)
    """
    sid = request.POST.get('sid')

    if sid is not None:
        set_del_id(sid)

    rules = RulePcap.objects.all()

    if len(rules) != 0:
        for rule in rules:
            if rule.sid == get_del_id():
                set_pcap(rule.pcap)
                break

    if get_pcap() == "":
        return HttpResponse('该规则无命中的pcap')

    cmd = 'rm -rf ./data/pcaps/' + get_pcap()
    os.system(cmd)
    RulePcap.objects.filter(sid=get_del_id()).delete()

    return HttpResponse('删除成功')


@csrf_exempt
def translate_show(request):
    """
    :describe:  获取要翻译的规则ID
    :param:     http请求
    :return:    输入翻译内容界面
    """
    if request.method == 'POST':
        set_trans_sid(request.POST.get('sid'))
    return render_to_response('translate_rule.html')


@csrf_exempt
def delete(request):
    """
    :describe:  日志删除
    :param:     http请求
    :return:    响应值 0:失败 1:成功
    """
    if request.method == 'POST':
        sid = request.POST.get('id')
        Log.objects.get(id=sid).delete()
        return HttpResponse(1)

    return HttpResponse(0)


@csrf_exempt
def get_xlsx(request):
    """
    :describe:  导出xlsx表格文件
    :param:     http请求
    :return:    表格文件
    """
    xlsx_path = get_xlsx_path()

    # 向表格写入数据
    write_data(xlsx_path)
    file = None
    try:
        file = open(xlsx_path, 'rb')
    except Exception as e:
        print e
        return HttpResponse('xlsx文件打开失败')

    response = StreamingHttpResponse(file)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="rules.xlsx"'
    user = request.session['user_name']
    ip = get_ip(request)
    set_default_env()
    record_log('无', '表格导出', user, '成功', ip,
               '导出文件为rules.xlsx,下载路径为%s' % (xlsx_path))

    return response


@csrf_exempt
def time_export(request):
    """
    :describe:  时间范围规则导出
    :param:     http请求
    :return:    导出的文件对象
    """
    rule_list = []
    if request.method == "POST":
        set_date_range(str(request.POST.get('date_range')))
        return HttpResponse(1)

    if request.method == "GET":
        start, end = get_start_end(get_date_range())
        rules_summary = Rule.objects.filter(
            update_time__gte=start, update_time__lte=end)
        for rule in rules_summary:
            rule_obj = CompleteRule.objects.get(sid=rule.sid)
            rule_list.append(rule_obj.rule)
        write_time_export_rules(start, end, rule_list)
    return get_response()

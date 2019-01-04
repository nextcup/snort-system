class Values(object):
    sid = None
    msg = None
    reference = None
    class_type = None
    malname = None
    attacker = None
    victim = None
    success_attack = None
    controller = None
    confirm_controlled = None
    rev = None
    knowledge_base = None
    create_time = None
    update_time = None
    shield = None
    contain = None
    first_check_time = None
    first_check_position = None
    overall_first_check_time = None
    overall_first_check_position = None
    check_out_numbers = None
    error_numbers = None
    feature_source = None
    remarks = None

    rule_data = None
    search_data = None
    option = None
    is_start = False
    is_close = False
    trans_sid = None
    untrans_search_data = None
    untrans_option = None
    edited_rule_id = []
    update_rule = []
    update_rule_data = None

    update_sid = []
    update_msg = None
    update_reference = None
    update_content = None
    update_classtype = None

    id = None
    rule_pcap = None
    del_id = None
    pcap = ""
    content_list = []
    history_log = None
    date_range = None
    another_content_list = []
    status = None
    response = None

    custom_id_list = []


def set_custom_id_list(id_list):
    Values.custom_id_list = id_list


def set_response(response):
    Values.response = response


def set_status(status):
    Values.status = status


def set_another_content_list(content_dict):
    Values.another_content_list.append(content_dict)


def set_date_range(data):
    Values.date_range = data


def set_history_log(log):
    Values.history_log = log


def set_content_list(list):
    Values.content_list = list


def set_pcap(pcap):
    Values.pcap = pcap


def set_del_id(id):
    Values.del_id = id


def set_rule_pcap(id):
    Values.rule_pcap = id


def set_id(id):
    Values.id = id


def set_update_classtype(class_type):
    Values.update_classtype = class_type


def set_update_content(content):
    Values.update_content = content


def set_update_reference(reference):
    Values.update_reference = reference


def set_update_msg(msg):
    Values.update_msg = msg


def set_update_sid(id_list):
    Values.update_sid = id_list


def set_update_rule_data(data):
    Values.update_rule_data = data


def set_update_rule(rule):
    Values.update_rule.append(rule)


def set_edited_rule_id(sid):
    Values.edited_rule_id.append(sid)
    # Values.edited_rule_id = id


def set_untrans_option(option):
    Values.untrans_option = option


def set_untrans_search_data(data):
    Values.untrans_search_data = data


def set_trans_sid(sid):
    Values.trans_sid = sid


def set_rule_data(rule):
    Values.rule_data = rule


def set_search_data(search_data):
    Values.search_data = search_data


def set_option(option):
    Values.option = option


def set_is_start(is_start):
    Values.is_start = is_start


def set_is_close(is_close):
    Values.is_close = is_close


def set_sid(sid):
    Values.sid = sid


def set_msg(msg):
    Values.msg = msg


def set_reference(reference):
    Values.reference = reference


def set_classtype(class_type):
    Values.class_type = class_type


def set_malname(malname):
    Values.malname = malname


def get_rule_data():
    return Values.rule_data


def get_search_data():
    return Values.search_data


def get_option():
    return Values.option


def get_is_start():
    return Values.is_start


def get_is_close():
    return Values.is_close


def get_sid():
    return Values.sid


def get_msg():
    return Values.msg


def get_reference():
    return Values.reference


def get_classtype():
    return Values.class_type


def get_malname():
    return Values.malname


def get_trans_sid():
    return Values.trans_sid


def get_untrans_search_data():
    return Values.untrans_search_data


def get_untrans_option():
    return Values.untrans_option


def get_edited_rule_id():
    return Values.edited_rule_id


def get_update_rule():
    return Values.update_rule


def get_update_rule_data():
    return Values.update_rule_data


def get_update_sid():
    return Values.update_sid


def get_update_msg():
    return Values.update_msg


def get_update_reference():
    val = ""
    for ref_val in Values.update_reference:
        val = val + ref_val + ';\n'
    return val


def get_update_content():
    return Values.update_content


def get_update_classtype():
    return Values.update_classtype


def get_id():
    return Values.id


def get_rule_pcap():
    return Values.rule_pcap


def get_del_id():
    return Values.del_id


def get_pcap():
    return Values.pcap


def get_content_list():
    return Values.content_list


def get_history_log():
    return Values.history_log


def get_date_range():
    return Values.date_range


def get_another_content_list():
    return Values.another_content_list


def get_status():
    return Values.status


def reset_content():
    Values.another_content_list = []


def get_response():
    return Values.response


def get_custom_id_list():
    return Values.custom_id_list

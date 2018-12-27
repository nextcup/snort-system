# -*- encoding:utf-8 -*-
"""
snort规则转PTD描述规则的脚本，
使用方式：python snort2ptd.py --rule snort文件目录 --out 生成文件的名字
不支持目录递归，只在指定的目录下找.rules文件，并进行转换
"""
import json
import os
import argparse
import collections


all_data = {}
content = []

# 获得小括号中间的数据


def getcontext(line_data):
    len1 = 0
    len2 = 0
    command_line = len(line_data)
    for i in range(command_line):
        if line_data[i] == '(':
            len1 = i
            break

    for e in range(command_line):
        if line_data[command_line - e - 1] == ')':
            len2 = command_line - e - 1
            break
    return line_data[len1 + 1:len2]


def get_key_value(line_info_data, key):
    while len(line_info_data) > 2:
        parse_data = parse(line_info_data)
        if key == parse_data[0][0]:
            return parse_data[0][1]
        line_info_data = parse_data[1]
    return None


def get_key_values(line_info_data, key):
    values = []
    while len(line_info_data) > 2:
        parse_data = parse(line_info_data)
        if key == parse_data[0][0]:
            values.append(parse_data[0][1])
        line_info_data = parse_data[1]
    return values


def get_data(command_string):
    node = collections.OrderedDict()
    node["msg"] = get_key_value(command_string, "msg")
    if node["msg"] == None:
        node.pop("msg")
    nodename = get_key_value(command_string, "sid")
    node["classtype"] = get_key_value(command_string, "classtype")
    if node["classtype"] == None:
        node.pop("classtype")
    else:
        if node["classtype"] == "unknown":
            node["classtype"] = "unknown-traffic"
    rev = get_key_value(command_string, "rev")
    if rev == None:
        node["rev"] = 1
    else:
        node["rev"] = int(rev)
    node["reference"] = get_key_values(command_string, "reference")
    if nodename != None:
        if "classtype" in node:
            node["malname"] = node["classtype"] + "/Generic." + str(nodename)
        else:
            node["malname"] = "[IDS]/Generic." + str(nodename)
        all_data[nodename] = node


def traverse_files(path):
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


def get_first_value(new_string):
    msginfo = None
    otherinfo = None
    # 如果没有引号
    if new_string and new_string[0] != "\"":
        # 找分号
        for j in range(len(new_string)):
            if new_string[j] == ";":
                msginfo = new_string[:j].strip()
                otherinfo = new_string[j + 1:].strip()
                break
    # 如果有引号
    if new_string and new_string[0] == "\"":
        for k in range(len(new_string)):
            if k > 0:
                if new_string[k] == "\"":
                    if new_string[k - 1] != "\\":
                        msginfo = new_string[1:k]
                        otherinfo = new_string[k + 2:].strip()
                        break
                    else:
                        a = 0
                        for i in range(k - 1, 0, -1):
                            if new_string[i] != "\\":  # 从右到左找不上\的
                                a = i
                                break
                        if (k - 1 - a) % 2 == 0:  # 如果引号" 的左边连续的\是偶数个
                            msginfo = new_string[1:k]
                            otherinfo = new_string[k + 2:].strip()
                            break
    info = []
    info.append(msginfo)
    info.append(otherinfo)
    return info


def parse(line_info_data):
    string = line_info_data.strip()
    strlen = len(line_info_data)
    # 从头开始一个一个的找冒号 “：”
    colon_position = 0
    semicolon_position = 0
    for i in range(strlen):
        if string[i] == ";":
            semicolon_position = i
        if string[i] == ":":
            colon_position = i
            break
    # 获取key
    # key = None
    if semicolon_position:
        key = string[semicolon_position + 1:colon_position].strip()
    else:
        key = string[:colon_position].strip()
    # 按照之前获取msg值的方式获取key的值
    new_string = string[colon_position + 1:].strip()
    info = get_first_value(new_string)
    value = info[0]
    ret_data = []
    ret_data.append((key, value))
    ret_data.append(info[1])
    return ret_data


def read_file(filename):
    print "reading " + filename
    with open(filename, "r") as f:
        for line in f.readlines():
            line = line.lstrip()
            if line[:5] == "alert":
                line_info_data = getcontext(line)
                get_data(line_info_data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manual to this script')
    parser.add_argument('--rule', type=str, default=None)
    parser.add_argument('--out', type=str, default=None)

    args = parser.parse_args()
    if os.path.isdir(args.rule):
        try:
            filenames = traverse_files(args.rule)
            for filename in filenames:
                read_file(filename)
            data = collections.OrderedDict()
            list_intkey = []
            for key in sorted(all_data.keys()):
                list_intkey.append(int(key))
            for key in sorted(list_intkey):
                data[str(key)] = all_data[str(key)]
            json.dump(data, open(args.out, "w"),
                      ensure_ascii=False, indent=4)
            print "over"
        except Exception, e:
            print e
    else:
        print "Please enter the correct directory "

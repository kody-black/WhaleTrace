#!/usr/bin/env python3
#-*- coding:UTF-8 -*-

from netifaces import interfaces
import winreg as wr

#定义获取Windows系统网卡接口的在注册表的键值的函数
def get_key(ifname):
    #获取所有网络接口卡的键值
    id = interfaces()
    #存放网卡键值与键值名称的字典
    key_name = {}
    try:
        #建立链接注册表，"HKEY_LOCAL_MACHINE"，None表示本地计算机
        reg = wr.ConnectRegistry(None,wr.HKEY_LOCAL_MACHINE)
        # 打开r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'，固定的
        reg_key = wr.OpenKey(reg , r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    except :
        return ('路径出错或者其他问题，请仔细检查')

    for i in id:
        try:
            #尝试读取每一个网卡键值下对应的Name
            reg_subkey = wr.OpenKey(reg_key , i + r'\Connection')
            #如果存在Name，写入key_name字典
            key_name[wr.QueryValueEx(reg_subkey , 'Name')[0]] = i
            # print(wr.QueryValueEx(reg_subkey , 'Name')[0])
        except FileNotFoundError:
            pass
    print('所有接口信息字典列表： ' + str(key_name) + '\n')
    return key_name

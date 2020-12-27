# Sniffer

> 会当凌绝顶，一览众山小

---
说明：本项目由`黄弘骏 518021910577`一人独立完成

本项目主要基于python库`scapy`和`pyqt`搭建了一个网络嗅探器，能够根据规则完成（后台）抓包，返回抓包结果，并对其进行操作并保存。本项目可以
结合网络发包器共同实现更加强大的功能。
目前项目仍处于功能开发阶段，由于笔者能力和时间有限，项目还有很大的提升空间。

## 环境安装
打开终端，输入以下命令：
```shell script
pip3 install -r requirements.txt
```
运行项目：
```shell script
sudo python UI.py
```
注意：此项目涉及网卡抓包，需要root权限运行，可以通过`sudo chmod 777 UI.py`完成授权。\
项目的可执行文件位于`dist`文件夹下

## 功能说明
项目主界面为4个ui，一个为*Sniffer*入口，其余三个分别为实时抓包界面caputre、加载分析修改界面analyze以及网络环境监视界面monitor。本项目
还有一些其他的功能性ui如detail、ListDialog、QuickModify、TextDialog等，这些界面都注重设计成模版形式加以复用。

## 测试方法
点击capture->在各种空间中输入需求，点击start->运行结束后会弹出sessions对话框，可以根据需求点击->关闭弹出对话框，点击列表中的数据包查看详情
->点击关键字搜索，根据需求输入并回车\
参考测试输入
test1：iface: `选择无线网卡`; filter: `tcp`; timeout:`10`\
test2：iface: `选择无线网卡`; filter: `udp`; timeout:`5`\
test3：iface: `选择无线网卡`; filter: `src xx.xx.xx.xx`; timeout:`5`\
test4：iface: `选择无线网卡`; filter: `port xx`; timeout:`5`\
test5：iface: `选择无线网卡`; filter: `tcp`; count: `10`\
点击analyse->file->open->选择文件->点击列表查看对应数据包->右下角十六进制处更改变动查看右上角的输出->点击quick modify->选择IP.ttl->
输入`64`->点击ok->返回查看任意数据包的ttl，都是64->点击quick modify->选择IP.src->输入`一个列表中存在的src,127.0.0.1`->返回查看原数据
包的src发生变化。\
点击monitor->选择网卡->点击start。
----

作者：黄弘骏，github主页：[传送门](https://github.com/Harry-hhj)。
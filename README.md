# Sniffer

> 会当凌绝顶，一览众山小

---
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
注意：此项目涉及网卡抓包，需要root权限运行，可以通过`sudo chmod 777 UI.py`完成授权。

## 功能说明
项目主界面为4个ui，一个为*Sniffer*入口，其余三个分别为实时抓包界面caputre、加载分析修改界面analyze以及网络环境监视界面monitor。本项目
还有一些其他的功能性ui如detail、ListDialog、QuickModify、TextDialog等，这些界面都注重设计成模版形式加以复用。


----

作者：黄弘骏，github主页：[传送门](https://github.com/Harry-hhj)。
<a href="https://github.com/GhostWolfTeam/Ghost-OSINT"><img src="https://raw.githubusercontent.com/GhostWolfTeam/Ghost-OSINT/main/ghostosint/static/img/ghostosint-header.png"></a>


[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](https://raw.githubusercontent.com/GhostWolfTeam/Ghost-OSINT/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7+-green)](https://www.python.org)
[![Stable Release](https://img.shields.io/badge/version-3.5-blue.svg)](https://github.com/GhostWolfTeam/Ghost-OSINT/releases/tag/v3.5)
[![CI status](https://github.com/smicallef/ghostosint/workflows/Tests/badge.svg)](https://github.com/GhostWolfTeam/Ghost-OSINT/actions?query=workflow%3A"Tests")
[![Last Commit](https://img.shields.io/github/last-commit/smicallef/ghostosint)](https://github.com/GhostWolfTeam/Ghost-OSINT/commits/master)
[![Discord](https://img.shields.io/discord/770524432464216074)](https://hack.chat/?Ghost-OSINT)

**Ghost-OSINT**

一个基于SpiderFoot二次开发的开源OSINT工具.

集成了几乎所有可以使用的数据源，并使数据易于显示.

**Ghost-OSINT**

集成了WEB UI界面，也可以使用命令行使用. 基于 **Python 3** 语言编写.

<img src="https://s2.loli.net/2022/01/18/iya1WsF8DIfGwBq.png" >

### 特点

- Web UI界面和命令行界面
- 多大200多个模块
- CSV/JSON/GEXF 格式导出
- API 密钥批量导入导出
- 高度可定制
- 可以搜索暗网记录
- 可以调用其他工具

### 用途

Ghost-OSINT 可用于攻防演练或渗透测试以侦查目标在互联网上暴露的所有信息.

可以在 Ghost-OSINT 中扫描的所有实体类型:

 - IP 地址
 - 域名和子域名
 - 主机名
 - 子网 (CIDR)
 - ASN 地址
 - 电子邮件地址
 - 手机号
 - 用户名
 - 人名
 - 区块链地址，如比特币、以太坊等

### 安装和运行

要安装运行 Ghost-OSINT, 需要 Python 3.7 环境和 `pip`.

#### 克隆到本地:

```
$ git clone https://github.com/GhostWolfTeam/Ghost-OSINT
$ cd Ghost-OSINT
$ pip3 install -r requirements.txt
$ python3 ghostosint.py -l 127.0.0.1:5001
```

### 文档

阅读更多 [项目文档](https://github.com/GhostWolfTeam/Ghost-OSINT/wiki)

包含完整文档、使用指南、开启身份验证.

#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import cmd
import codecs
import json
import os
import re
import shlex
import sys
import time
from os.path import expanduser

import requests


ASCII_LOGO = r"""
                   ___       ___       ___       ___       ___
                  /\  \     /\__\     /\  \     /\  \     /\  \
                 /::\  \   /:/__/_   /::\  \   /::\  \    \:\  \
                /:/\:\__\ /::\/\__\ /:/\:\__\ /\:\:\__\   /::\__\
                \:\:\/__/ \/\::/  / \:\/:/  / \:\:\/__/  /:/\/__/
                 \::/  /    /:/  /   \::/  /   \::/  /   \/__/
                  \/__/     \/__/     \/__/     \/__/
                   ___       ___       ___       ___       ___
                  /\  \     /\  \     /\  \     /\__\     /\  \
                 /::\  \   /::\  \   _\:\  \   /:| _|_    \:\  \
                /:/\:\__\ /\:\:\__\ /\/::\__\ /::|/\__\   /::\__\
                \:\/:/  / \:\:\/__/ \::/\/__/ \/|::/  /  /:/\/__/
                 \::/  /   \::/  /   \:\__\     |:/  /   \/__/
                  \/__/     \/__/     \/__/     \/__/
                开源自动化OSINT工具."""
COPYRIGHT_INFO = "               by Snow Wolf | @ghostosint\n"

try:
    import readline
except ImportError:
    import pyreadline as readline


# Colors to make things purty
class bcolors:
    GREYBLUE = '\x1b[38;5;25m'
    GREY = '\x1b[38;5;243m'
    DARKRED = '\x1b[38;5;124m'
    DARKGREEN = '\x1b[38;5;30m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    GREYBLUE_DARK = '\x1b[38;5;24m'


class GhostOsintCMD(cmd.Cmd):
    version = "1.0.0"
    pipecmd = None
    output = None
    modules = []
    types = []
    prompt = "GhostOsint> "
    nohelp = "[!] 未知命令 '%s'."
    knownscans = []
    ownopts = {
        "cli.debug": False,
        "cli.silent": False,
        "cli.color": True,
        "cli.output": "pretty",
        "cli.history": True,
        "cli.history_file": "",
        "cli.spool": False,
        "cli.spool_file": "",
        "cli.ssl_verify": True,
        "cli.username": "",
        "cli.password": "",
        "cli.server_baseurl": "http://127.0.0.1:5001"
    }

    def default(self, line):
        if line.startswith('#'):
            return

        self.edprint("未知命令")

    # Auto-complete for these commands
    def complete_start(self, text, line, startidx, endidx):
        return self.complete_default(text, line, startidx, endidx)

    def complete_find(self, text, line, startidx, endidx):
        return self.complete_default(text, line, startidx, endidx)

    def complete_data(self, text, line, startidx, endidx):
        return self.complete_default(text, line, startidx, endidx)

    # Command completion for arguments
    def complete_default(self, text, line, startidx, endidx):
        ret = list()

        if not isinstance(text, str):
            return ret

        if not isinstance(line, str):
            return ret

        if "-m" in line and line.find("-m") > line.find("-t"):
            for m in self.modules:
                if m.startswith(text):
                    ret.append(m)

        if "-t" in line and line.find("-t") > line.find("-m"):
            for t in self.types:
                if t.startswith(text):
                    ret.append(t)
        return ret

    def dprint(self, msg, err=False, deb=False, plain=False, color=None):
        cout = ""
        sout = ""
        pfx = ""
        col = ""
        if err:
            pfx = "[!]"
            if self.ownopts['cli.color']:
                col = bcolors.DARKRED
        else:
            pfx = "[*]"
            if self.ownopts['cli.color']:
                col = bcolors.DARKGREEN
        if deb:
            if not self.ownopts["cli.debug"]:
                return
            pfx = "[+]"
            if self.ownopts['cli.color']:
                col = bcolors.GREY

        if color:
            pfx = ""
            col = color

        if err or not self.ownopts["cli.silent"]:
            if not plain or color:
                cout = col + bcolors.BOLD + pfx + " " + bcolors.ENDC + col + msg + bcolors.ENDC
                # Never include color in the spool
                sout = pfx + " " + msg
            else:
                cout = msg
                sout = msg

            print(cout)

        if self.ownopts['cli.spool']:
            f = codecs.open(self.ownopts['cli.spool_file'], "a", encoding="utf-8")
            f.write(sout)
            f.write('\n')
            f.close()

    # Shortcut commands
    def do_debug(self, line):
        """debug
        快捷键设置开启 cli.debug = 1"""
        if self.ownopts['cli.debug']:
            val = "0"
        else:
            val = "1"
        return self.do_set("cli.debug = " + val)

    def do_spool(self, line):
        """spool
        快捷键设置开启或关闭 cli.spool = 1/0"""
        if self.ownopts['cli.spool']:
            val = "0"
        else:
            val = "1"

        if self.ownopts['cli.spool_file']:
            return self.do_set("cli.spool = " + val)

        self.edprint("你尚未设置cli.spool_file文件,在脱机之前赶快给我进行设置.")

        return None

    def do_history(self, line):
        """history [-l]
        快捷键设置开启或关闭 cli.history = 1/0.
        使用 -l 选项以列出历史记录."""
        c = self.myparseline(line)

        if '-l' in c[0]:
            i = 0
            while i < readline.get_current_history_length():
                self.dprint(readline.get_history_item(i), plain=True)
                i += 1
            return None

        if self.ownopts['cli.history']:
            val = "0"
        else:
            val = "1"

        return self.do_set("cli.history = " + val)

    # Run before all commands to handle history and spooling
    def precmd(self, line):
        if self.ownopts['cli.history'] and line != "EOF":
            f = codecs.open(self.ownopts["cli.history_file"], "a", encoding="utf-8")
            f.write(line)
            f.write('\n')
            f.close()
        if self.ownopts['cli.spool']:
            f = codecs.open(self.ownopts["cli.spool_file"], "a", encoding="utf-8")
            f.write(self.prompt + line)
            f.write('\n')
            f.close()

        return line

    # Debug print
    def ddprint(self, msg):
        self.dprint(msg, deb=True)

    # Error print
    def edprint(self, msg):
        self.dprint(msg, err=True)

    # Print nice tables.
    def pretty(self, data, titlemap=None):
        if not data:
            return ""

        out = list()
        # Get the column titles
        maxsize = dict()
        if type(data[0]) == dict:
            cols = list(data[0].keys())
        else:
            # for lists, use the index numbers as titles
            cols = list(map(str, list(range(0, len(data[0])))))

        # Strip out columns that don't have titles
        if titlemap:
            nc = list()
            for c in cols:
                if c in titlemap:
                    nc.append(c)
            cols = nc

        spaces = 2
        # Find the maximum column sizes
        for r in data:
            i = 0
            for c in r:
                if type(r) == list:
                    # we have  list index
                    cn = str(i)
                    if type(c) == int:
                        v = str(c)
                    if type(c) == str:
                        v = c
                else:
                    # we have a dict key
                    cn = c
                    v = str(r[c])
                # print(str(cn) + ", " + str(c) + ", " + str(v))
                if len(v) > maxsize.get(cn, 0):
                    maxsize[cn] = len(v)
                i += 1

        # Adjust for long titles
        if titlemap:
            for c in maxsize:
                if len(titlemap.get(c, c)) > maxsize[c]:
                    maxsize[c] = len(titlemap.get(c, c))

        # Display the column titles
        i = 0
        for c in cols:
            if titlemap:
                t = titlemap.get(c, c)
            else:
                t = c
            # out += t
            out.append(t)
            sdiff = maxsize[c] - len(t) + 1
            # out += " " * spaces
            out.append(" " * spaces)
            if sdiff > 0 and i < len(cols) - 1:
                # out += " " * sdiff
                out.append(" " * sdiff)
            i += 1
        # out += "\n"
        out.append('\n')

        # Then the separator
        i = 0
        for c in cols:
            # out += "-" * ((maxsize[c]+spaces))
            out.append("-" * ((maxsize[c] + spaces)))
            if i < len(cols) - 1:
                # out += "+"
                out.append("+")
            i += 1
        # out += "\n"
        out.append("\n")

        # Then the actual data
        # ts = time.time()
        for r in data:
            i = 0
            di = 0
            tr = type(r)
            for c in r:
                if tr == list:
                    # we have  list index
                    cn = str(i)
                    tc = type(c)
                    if tc == int:
                        v = str(c)
                    if tc == str:
                        v = c
                else:
                    # we have a dict key
                    cn = c
                    v = str(r[c])
                if cn not in cols:
                    i += 1
                    continue

                out.append(v)
                lv = len(v)
                # there is a preceeding space if this is after the
                # first column
                # sdiff = number of spaces between end of word and |
                if di == 0:
                    sdiff = (maxsize[cn] - lv) + spaces
                else:
                    sdiff = (maxsize[cn] - lv) + spaces - 1
                if di < len(cols) - 1:
                    # out += " " * sdiff
                    out.append(" " * sdiff)
                if di < len(cols) - 1:
                    # out += "| "
                    out.append("| ")
                di += 1
                i += 1
            # out += "\n"
            out.append("\n")

        # print("time: " + str(time.time() - ts))
        return ''.join(out)

    # Make a request to the GhostOSINT server
    def request(self, url, post=None):
        if not url:
            self.edprint("请求URL无效")
            return None

        if not isinstance(url, str):
            self.edprint(f"无效请求URL: {url}")
            return None

        # logging.basicConfig()
        # logging.getLogger().setLevel(logging.DEBUG)
        # requests_log = logging.getLogger("requests.packages.urllib3")
        # requests_log.setLevel(logging.DEBUG)
        # requests_log.propagate = True
        headers = {
            "User-agent": "GhostOSINT-CMD/" + self.version,
            "Accept": "application/json"
        }

        try:
            self.ddprint(f"读取: {url}")
            if not post:
                r = requests.get(
                    url,
                    headers=headers,
                    verify=self.ownopts['cli.ssl_verify'],
                    auth=requests.auth.HTTPDigestAuth(
                        self.ownopts['cli.username'],
                        self.ownopts['cli.password']
                    )
                )
            else:
                self.ddprint(f"入值: {post}")
                r = requests.post(
                    url,
                    headers=headers,
                    verify=self.ownopts['cli.ssl_verify'],
                    auth=requests.auth.HTTPDigestAuth(
                        self.ownopts['cli.username'],
                        self.ownopts['cli.password']
                    ),
                    data=post
                )
            self.ddprint(f"响应: {r}")
            if r.status_code == requests.codes.ok:  # pylint: disable=no-member
                return r.text
            r.raise_for_status()
        except BaseException as e:
            self.edprint(f"无法与服务器通信: {e}")
            return None

    def emptyline(self):
        return

    def completedefault(self, text, line, begidx, endidx):
        return []

    # Parse the command line, returns a list of lists:
    # GhostOsint> scans "blahblah test" | top 10 | grep foo ->
    # [[ 'blahblah test' ], [[ 'top', '10' ], [ 'grep', 'foo']]]
    def myparseline(self, cmdline, replace=True):
        ret = [list(), list()]

        if not cmdline:
            return ret

        try:
            s = shlex.split(cmdline)
        except Exception as e:
            self.edprint(f"解析命令时出错: {e}")
            return ret

        for c in s:
            if c == '|':
                break
            if replace and c.startswith("$") and c in self.ownopts:
                ret[0].append(self.ownopts[c])
            else:
                ret[0].append(c)

        if s.count('|') == 0:
            return ret

        # Handle any pipe commands at the end
        ret[1] = list()
        i = 0
        ret[1].append(list())
        for t in s[(s.index('|') + 1):]:
            if t == '|':
                i += 1
                ret[1].append(list())
            # Replace variables
            elif t.startswith("$") and t in self.ownopts:
                ret[1][i].append(self.ownopts[t])
            else:
                ret[1][i].append(t)

        return ret

    # Send the command output to the user, processing the pipes
    # that may have been used.
    def send_output(self, data, cmd, titles=None, total=True, raw=False):
        out = None
        try:
            if raw:
                j = data
                totalrec = 0
            else:
                j = json.loads(data)
                totalrec = len(j)
        except BaseException as e:
            self.edprint(f"无法从服务器解析数据: {e}")
            return

        if raw:
            out = data
        else:
            if self.ownopts['cli.output'] == "json":
                out = json.dumps(j, indent=4, separators=(',', ': '))

            if self.ownopts['cli.output'] == "pretty":
                out = self.pretty(j, titlemap=titles)

            if not out:
                self.edprint(f"未知输出格式 '{self.ownopts['cli.output']}'.")
                return

        c = self.myparseline(cmd)

        # If no pipes, just disply the output
        if len(c[1]) == 0:
            self.dprint(out, plain=True)
            if total:
                self.dprint(f"总计: {totalrec}")
            return

        for pc in c[1]:
            newout = ""
            if len(pc) == 0:
                self.edprint("语法无效.")
                return
            pipecmd = pc[0]
            pipeargs = " ".join(pc[1:])
            if pipecmd not in ["str", "regex", "file", "grep", "top", "last"]:
                self.edprint("无法识别的管道命令.")
                return

            if pipecmd == "regex":
                p = re.compile(pipeargs, re.IGNORECASE)
                for r in out.split("\n"):
                    if re.match(p, r.strip()):
                        newout += r + "\n"

            if pipecmd in ['str', 'grep']:
                for r in out.split("\n"):
                    if pipeargs.lower() in r.strip().lower():
                        newout += r + "\n"

            if pipecmd == "top":
                if not pipeargs.isdigit():
                    self.edprint("语法无效.")
                    return
                newout = "\n".join(out.split("\n")[0:int(pipeargs)])

            if pipecmd == "last":
                if not pipeargs.isdigit():
                    self.edprint("无效语法.")
                    return
                tot = len(out.split("\n"))
                i = tot - int(pipeargs)
                newout = "\n".join(out.split("\n")[i:])

            if pipecmd == "file":
                try:
                    f = codecs.open(pipeargs, "w", encoding="utf-8")
                    f.write(out)
                    f.close()
                except BaseException as e:
                    self.edprint(f"无法写入文件: {e}")
                    return
                self.dprint(f"成功写入文件 '{pipeargs}'.")
                return

            out = newout

        self.dprint(newout, plain=True)

    # Run SQL against the DB.
    def do_query(self, line):
        """query <SQL query>
        对数据库运行SQL查询."""
        c = self.myparseline(line)
        if len(c[0]) < 1:
            self.edprint("语法无效.")
            return
        query = ' '.join(c[0])
        d = self.request(self.ownopts['cli.server_baseurl'] + "/query",
                         post={"query": query})
        if not d:
            return
        j = json.loads(d)
        if j[0] == "ERROR":
            self.edprint(f"运行查询时出错: {j[1]}")
            return
        self.send_output(d, line)

    # Ping the server.
    def do_ping(self, line):
        """ping
        ping Ghost-OSINT 服务器以确保其响应."""
        d = self.request(self.ownopts['cli.server_baseurl'] + "/ping")
        if not d:
            return

        s = json.loads(d)
        if s[0] == "SUCCESS":
            self.dprint(f"Server {self.ownopts['cli.server_baseurl']} responding.")
            self.do_modules("", cacheonly=True)
            self.do_types("", cacheonly=True)
        else:
            self.dprint(f"怪了，好像有BUG: {d}")

        if s[1] != self.version:
            self.edprint(f"服务器和客户端版本不同 ({s[1]} / {self.version}). 可能会导致我变得奇怪!,kimoji")

    # List all GhostOSINT modules.
    def do_modules(self, line, cacheonly=False):
        """modules
        列出所有可用模块及其说明."""
        d = self.request(self.ownopts['cli.server_baseurl'] + "/modules")
        if not d:
            return

        if cacheonly:
            j = json.loads(d)
            for m in j:
                self.modules.append(m['name'])
            return

        self.send_output(d, line, titles={"name": "Module name",
                                          "descr": "Description"})

    # List all GhostOSINT data element types.
    def do_types(self, line, cacheonly=False):
        """types
        列出所有可用元素类型及其说明."""
        d = self.request(self.ownopts['cli.server_baseurl'] + "/eventtypes")

        if not d:
            return

        if cacheonly:
            j = json.loads(d)
            for t in j:
                self.types.append(t[0])
            return

        self.send_output(
            d,
            line,
            titles={
                "1": "元素描述",
                "0": "元素名称"
            }
        )

    # Load commands from a file.
    def do_load(self, line):
        """load <file>
        加载文件 <file>中的命令使Ghost-OSINT执行."""
        pass

    # Get scan info and config.
    def do_scaninfo(self, line):
        """scaninfo <sid> [-c]
        获取指定扫描ID <sid>的详细信息, -c选项可以获取其配置."""
        c = self.myparseline(line)
        if len(c[0]) < 1:
            self.edprint("无效语法.")
            return

        sid = c[0][0]
        d = self.request(self.ownopts['cli.server_baseurl'] + f"/scanopts?id={sid}")
        if not d:
            return
        j = json.loads(d)
        if len(j) == 0:
            self.dprint("不存在这样的扫描.")
            return

        out = list()
        out.append(f"Name: {j['meta'][0]}")
        out.append(f"ID: {sid}")
        out.append(f"Target: {j['meta'][1]}")
        out.append(f"Started: {j['meta'][3]}")
        out.append(f"Completed: {j['meta'][4]}")
        out.append(f"Status: {j['meta'][5]}")

        if "-c" in c[0]:
            out.append("Configuration:")
            for k in sorted(j['config']):
                out.append(f"  {k} = {j['config'][k]}")

        self.send_output("\n".join(out), line, total=False, raw=True)

    # List scans.
    def do_scans(self, line):
        """scans [-x]
        列出所有扫描. -x选项用于扩展视图."""
        d = self.request(self.ownopts['cli.server_baseurl'] + "/scanlist")
        if not d:
            return
        j = json.loads(d)
        if len(j) == 0:
            self.dprint("不存在扫描.")
            return

        c = self.myparseline(line)
        titles = dict()
        if "-x" in c[0]:
            titles = {
                "0": "ID",
                "1": "扫描名称",
                "2": "扫描目标",
                "4": "开始时间",
                "5": "完成时间",
                "6": "扫描状态",
                "7": "全部元素"
            }
        else:
            titles = {
                "0": "ID",
                "2": "扫描目标",
                "6": "扫描状态",
                "7": "全部元素"
            }

        self.send_output(d, line, titles=titles)

    # Show the data from a scan.
    def do_data(self, line):
        """data <sid> [-t type] [-x] [-u]
        获取指定扫描ID <sid> 和元素（可选）的扫描数据和
        类型 [type] (例如 EMAILADDR), [type]. -x 选项用于扩展格式.
        使用-u选项获得特殊结果."""
        c = self.myparseline(line)
        if len(c[0]) < 1:
            self.edprint("无效语法.")
            return

        post = {"id": c[0][0]}

        if "-t" in c[0]:
            post["eventType"] = c[0][c[0].index("-t") + 1]
        else:
            post["eventType"] = "ALL"

        if "-u" in c[0]:
            url = self.ownopts['cli.server_baseurl'] + "/scaneventresultsunique"
            titles = {
                "0": "数据"
            }
        else:
            url = self.ownopts['cli.server_baseurl'] + "/scaneventresults"
            titles = {
                "10": "类型",
                "1": "数据"
            }

        d = self.request(url, post=post)
        if not d:
            return
        j = json.loads(d)
        if len(j) < 1:
            self.dprint("没有结果.")
            return

        if "-x" in c[0]:
            titles["0"] = "最后一次出现"
            titles["3"] = "模块"
            titles["2"] = "源数据"

        d = d.replace("&lt;/SFURL&gt;", "").replace("&lt;SFURL&gt;", "")
        self.send_output(d, line, titles=titles)

    # Export data from a scan.
    def do_export(self, line):
        """export <sid> [-t type]
        将指定扫描ID <sid> 扫描到的数据导出为类型 [type].
        有效类型: csv, json, gexf (默认: json)."""
        c = self.myparseline(line)

        if len(c[0]) < 1:
            self.edprint("无效语法.")
            return

        export_format = 'json'
        if '-t' in c[0]:
            export_format = c[0][c[0].index("-t") + 1]

        base_url = self.ownopts['cli.server_baseurl']
        post = {"ids": c[0][0]}

        if export_format == 'json':
            res = self.request(base_url + '/scanexportjsonmulti', post=post)

            if not res:
                self.dprint("没有结果.")
                return

            j = json.loads(res)

            if len(j) < 1:
                self.dprint("没有结果.")
                return

            self.send_output(json.dumps(j), line, titles=None, total=False, raw=True)

        elif export_format == 'csv':
            res = self.request(base_url + '/scaneventresultexportmulti', post=post)

            if not res:
                self.dprint("没有结果.")
                return

            self.send_output(res, line, titles=None, total=False, raw=True)

        elif export_format == 'gexf':
            res = self.request(base_url + '/scanvizmulti', post=post)

            if not res:
                self.dprint("没有结果.")
                return

            self.send_output(res, line, titles=None, total=False, raw=True)

        else:
            self.edprint(f"导出格式无效: {export_format}")

    # Show logs.
    def do_logs(self, line):
        """logs <sid> [-l count] [-w]
        显示指定扫描ID的最新 [count] 日志, <sid>.
        如果没提供计数，则显示所有日志.
        如果使用了-w选项, 则日志会直接显示到控制台，直到键入
        Ctrl-C."""
        c = self.myparseline(line)

        if len(c[0]) < 1:
            self.edprint("无效语法.")
            return

        sid = c[0][0]
        limit = None
        if "-l" in c[0]:
            limit = c[0][c[0].index("-l") + 1]

            if not limit.isdigit():
                self.edprint(f"无效总计: {limit}")
                return

            limit = int(limit)

        if "-w" not in c[0]:
            d = self.request(
                self.ownopts['cli.server_baseurl'] + "/scanlog",
                post={'id': sid, 'limit': limit}
            )
            if not d:
                return
            j = json.loads(d)
            if len(j) < 1:
                self.dprint("没有结果.")
                return

            self.send_output(
                d,
                line,
                titles={
                    "0": "生成的",
                    "1": "类型",
                    "2": "源",
                    "3": "信息"
                }
            )
            return

        # Get the rowid of the latest log message
        d = self.request(
            self.ownopts['cli.server_baseurl'] + "/scanlog",
            post={'id': sid, 'limit': '1'}
        )
        if not d:
            return

        j = json.loads(d)
        if len(j) < 1:
            self.dprint("没有日志(还没有).")
            return

        rowid = j[0][4]

        if not limit:
            limit = 10

        d = self.request(
            self.ownopts['cli.server_baseurl'] + "/scanlog",
            post={'id': sid, 'reverse': '1', 'rowId': rowid - limit}
        )
        if not d:
            return

        j = json.loads(d)
        for r in j:
            # self.send_output(str(r), line, total=False, raw=True)
            if r[2] == "ERROR":
                self.edprint(f"{r[1]}: {r[3]}")
            else:
                self.dprint(f"{r[1]}: {r[3]}")

        try:
            while True:
                d = self.request(
                    self.ownopts['cli.server_baseurl'] + "/scanlog",
                    post={'id': sid, 'reverse': '1', 'rowId': rowid}
                )
                if not d:
                    return
                j = json.loads(d)
                for r in j:
                    if r[2] == "ERROR":
                        self.edprint(f"{r[1]}: {r[3]}")
                    else:
                        self.dprint(f"{r[1]}: {r[3]}")
                    rowid = str(r[4])
                time.sleep(0.5)
        except KeyboardInterrupt:
            return

    # Start a new scan.
    def do_start(self, line):
        """start <target> (-m m1,... | -t t1,... | -u case) [-n name] [-w]
        开始扫描 <target> 使用模块 m1,... 或者
        类型 t1,...
        或者按用例 ("all", "investigate", "passive" and "footprint").

        可选择将扫描命名为 [name], 而不对目标进行命名.
        使用 -w 选项查看扫描的日志. Ctrl-C 中止记录
        (但不会中止扫描).
        """
        c = self.myparseline(line)
        if len(c[0]) < 3:
            self.edprint("无效语法.")
            return None

        mods = ""
        types = ""
        usecase = ""

        if "-m" in c[0]:
            mods = c[0][c[0].index("-m") + 1]

        if "-t" in c[0]:
            # Scan by type
            types = c[0][c[0].index("-t") + 1]

        if "-u" in c[0]:
            # Scan by use case
            usecase = c[0][c[0].index("-u") + 1]

        if not mods and not types and not usecase:
            self.edprint("无效语法.")
            return None

        target = c[0][0]
        if "-n" in c[0]:
            title = c[0][c[0].index("-n") + 1]
        else:
            title = target

        post = {
            "扫描名称": title,
            "扫描目标": target,
            "列出模块": mods,
            "列出类型": types,
            "用例": usecase
        }
        d = self.request(
            self.ownopts['cli.server_baseurl'] + "/startscan",
            post=post
        )
        if not d:
            return None

        s = json.loads(d)
        if s[0] == "SUCCESS":
            self.dprint("成功启动扫描.")
            self.dprint(f"扫描ID: {s[1]}")
        else:
            self.dprint(f"无法启动扫描: {s[1]}")

        if "-w" in c[0]:
            return self.do_logs("{s[1]} -w")

        return None

    # Stop a running scan.
    def do_stop(self, line):
        """stop <sid>
        中止指定扫描ID任务, <sid>."""
        c = self.myparseline(line)
        try:
            scan_id = c[0][0]
        except BaseException:
            self.edprint("无效语法.")
            return

        self.request(self.ownopts['cli.server_baseurl'] + f"/stopscan?id={scan_id}")
        self.dprint(f"已成功请求扫描 {id} ,要停止的话得需要等一会哦，么么哒(づ￣ 3￣)づ.")

    # Search for data, alias to find
    def do_search(self, line):
        """search (同 'find')
        """
        return self.do_find(line)

    # Search for data
    def do_find(self, line):
        """find "<string|/regex/>" <[-s sid]|[-t type]> [-x]
        通过字符串或正则表达式搜索结果, 仅限扫描ID或
        事件类型. -x 选项扩展格式."""
        c = self.myparseline(line)
        if len(c[0]) < 1:
            self.edprint("无效语法.")
            return

        val = c[0][0]
        sid = None
        etype = None

        if "-t" in c[0]:
            etype = c[0][c[0].index("-t") + 1]
        if "-s" in c[0]:
            sid = c[0][c[0].index("-s") + 1]

        titles = {
            "0": "最后一次出现时间",
            "1": "数据",
            "3": "模块"
        }
        if "-x" in c[0]:
            titles["2"] = "源数据"

        d = self.request(
            self.ownopts['cli.server_baseurl'] + "/search",
            post={'value': val, 'id': sid, 'eventType': etype}
        )
        if not d:
            return
        j = json.loads(d)

        if not j:
            self.dprint("未找到结果.")
            return
        if len(j) < 1:
            self.dprint("未找到结果.")
            return

        self.send_output(d, line, titles)

    # Summary of a scan
    def do_summary(self, line):
        """summary <sid> [-t]
        汇总扫描ID的结果, <sid>. -t仅显示
        元素类型."""
        c = self.myparseline(line)
        if len(c[0]) < 1:
            self.edprint("无效语法.")
            return

        sid = c[0][0]

        if "-t" in c[0]:
            titles = {"0": "元素类型"}
        else:
            titles = {
                "0": "元素类型",
                "1": "元素描述",
                "3": "总计",
                "4": "特殊"
            }

        d = self.request(self.ownopts['cli.server_baseurl'] + f"/scansummary?id={sid}&by=type")
        if not d:
            return

        j = json.loads(d)

        if not j:
            self.dprint("未找到结果.")
            return
        if len(j) < 1:
            self.dprint("未找到结果.")
            return

        self.send_output(d, line, titles, total=False)

    # Delete a scan
    def do_delete(self, line):
        """delete <sid>
        删除指定扫描ID任务, <sid>."""
        c = self.myparseline(line)
        try:
            scan_id = c[0][0]
        except BaseException:
            self.edprint("无效语法.")
            return

        self.request(self.ownopts['cli.server_baseurl'] + f"/scandelete?id={scan_id}")
        self.dprint(f"成功删除扫描 {scan_id}.")

    # Override the default help
    def print_topics(self, header, cmds, cmdlen, maxcol):
        if not cmds:
            return

        helpmap = [
            ["help [command]", "帮助信息."],
            ["debug", "启用/禁止 调试输出."],
            ["clear", "清除屏幕消息."],
            ["history", "启用/禁用/列出 历史记录."],
            ["spool", "启用/禁用 脱机输出."],
            ["shell", "执行Shell命令."],
            ["exit", "退出 GhostOSINT CMD (不会影响正在运行的扫描)."],
            ["ping", "测试与 GhostOSINT 服务器的连接."],
            ["modules", "列出可用模块."],
            ["types", "列出可用数据类型."],
            ["set", "变量设置和配置设置."],
            ["scans", "列出已运行和正在运行的扫描."],
            ["start", "开始新建一个扫描."],
            ["stop", "停止一个扫描."],
            ["delete", "删除一个扫描."],
            ["scaninfo", "扫描信息."],
            ["data", "显示来自扫描结果的数据."],
            ["summary", "扫描结果摘要信息."],
            ["find", "在扫描结果中搜索数据."],
            ["query", "对 GhostOSINT SQLite 数据库运行数据库查询."],
            ["logs", "查看/实时 扫描日志."]
        ]

        self.send_output(
            json.dumps(helpmap),
            "",
            titles={"0": "命令", "1": "描述"},
            total=False
        )

    # Get/Set configuration
    def do_set(self, line):
        """set [opt [= <val>]]
        Set a configuration variable in GhostOSINT."""

        c = self.myparseline(line, replace=False)
        cfg = None
        val = None

        if len(c[0]) > 0:
            cfg = c[0][0]

        if len(c[0]) > 2:
            try:
                val = c[0][2]
            except BaseException:
                self.edprint("无效语法.")
                return

        # Local CLI config
        if cfg and val:
            if cfg.startswith('$'):
                self.ownopts[cfg] = val
                self.dprint(f"{cfg} set to {val}")
                return

            if cfg in self.ownopts:
                if isinstance(self.ownopts[cfg], bool):
                    if val.lower() == "false" or val == "0":
                        val = False
                    else:
                        val = True

                self.ownopts[cfg] = val
                self.dprint(f"{cfg} set to {val}")
                return

        # Get the server-side config
        d = self.request(self.ownopts['cli.server_baseurl'] + "/optsraw")
        if not d:
            self.edprint("无法获取 GhostOSINT 服务器端配置.")
            return

        j = list()
        serverconfig = dict()
        token = ""  # nosec
        j = json.loads(d)
        if j[0] == "ERROR":
            self.edprint("获取 GhostOSINT 服务器端配置出错了呢.")
            return

        serverconfig = j[1]['data']
        token = j[1]['token']

        self.ddprint(str(serverconfig))

        # Printing current config, not setting a value
        if not cfg or not val:
            ks = list(self.ownopts.keys())
            ks.sort()
            output = list()
            for k in ks:
                c = self.ownopts[k]
                if isinstance(c, bool):
                    c = str(c)

                if not cfg:
                    output.append({'opt': k, 'val': c})
                    continue

                if cfg == k:
                    self.dprint(f"{k} = {c}", plain=True)

            for k in sorted(serverconfig.keys()):
                if type(serverconfig[k]) == list:
                    serverconfig[k] = ','.join(serverconfig[k])
                if not cfg:
                    output.append({'opt': k, 'val': str(serverconfig[k])})
                    continue
                if cfg == k:
                    self.dprint(f"{k} = {serverconfig[k]}", plain=True)

            if len(output) > 0:
                self.send_output(
                    json.dumps(output),
                    line,
                    {'opt': "Option", 'val': "Value"},
                    total=False
                )
            return

        if val:
            # submit all non-CLI vars to the Ghost OSINT server
            confdata = dict()
            found = False
            for k in serverconfig:
                if k == cfg:
                    serverconfig[k] = val
                    found = True

            if not found:
                self.edprint("未找到变量，所以没有设置.")
                return

            # Sanitize the data before sending it to the server
            for k in serverconfig:
                optstr = ":".join(k.split(".")[1:])
                if type(serverconfig[k]) == bool:
                    if serverconfig[k]:
                        confdata[optstr] = "1"
                    else:
                        confdata[optstr] = "0"
                if type(serverconfig[k]) == list:
                    # If set by the user, it must already be a
                    # string, not a list
                    confdata[optstr] = ','.join(serverconfig[k])
                if type(serverconfig[k]) == int:
                    confdata[optstr] = str(serverconfig[k])
                if type(serverconfig[k]) == str:
                    confdata[optstr] = serverconfig[k]

            self.ddprint(str(confdata))
            d = self.request(
                self.ownopts['cli.server_baseurl'] + "/savesettingsraw",
                post={'token': token, 'allopts': json.dumps(confdata)}
            )
            j = list()

            if not d:
                self.edprint("无法设置 GhostOSINT 服务器端配置.")
                return

            j = json.loads(d)
            if j[0] == "ERROR":
                self.edprint(f"设置 GhostOSINT 服务器端配置出错了: {j[1]}")
                return

            self.dprint(f"{cfg} set to {val}")
            return

        if cfg not in self.ownopts:
            self.edprint("未找到变量,因此没有设置.要不你试试使用$变量？")
            return

    # Execute a shell command locally and return the output
    def do_shell(self, line):
        """shell
        在本地运行shell命令."""
        self.dprint("正在运行的Shell命令:" + str(line))
        self.dprint(os.popen(line).read(), plain=True)  # noqa: DUO106

    def do_clear(self, line):
        """clear
        清屏."""
        sys.stderr.write("\x1b[2J\x1b[H")

    # Exit the CLI
    def do_exit(self, line):
        """exit
        退出 Ghost-OSINT CMD."""
        return True

    # Ctrl-D
    def do_EOF(self, line):
        """EOF (Ctrl-D)
        退出 Ghost-OSINT CMD."""
        print("\n")
        return True


if __name__ == "__main__":
    p = argparse.ArgumentParser(description='GhostOSINT: 开源自动化OSINT工具.')
    p.add_argument("-d", "--debug", help="启用调试输出.", action='store_true')
    p.add_argument("-s", metavar="URL", type=str, help="连接到URL的 GhostOSINT 服务器. 默认会尝试连接 http://127.0.0.1:5001 .")
    p.add_argument("-u", metavar="USER", type=str, help=" GhostOSINT 服务器身份验证的用户名.")
    p.add_argument("-p", metavar="PASS", type=str, help=" GhostOSINT 服务器身份验证的密码.可以使用 '-p 密码文件' 选项,这样密码就不会出现在历史记录或进程列表中!")
    p.add_argument("-P", metavar="PASSFILE", type=str, help="包含用于 向GhostOSINT 服务器身份验证的密码文件.要确保文件权限设置正确哦!")
    p.add_argument("-e", metavar="FILE", type=str, help="从文件中执行命令.")
    p.add_argument("-l", metavar="FILE", type=str, help="将命令历史记录记录到文件中.默认情况下,历史记录存储在~/.ghostosint_history中,除非使用 -n 选项禁用.")
    p.add_argument("-n", action='store_true', help="禁用历史记录.")
    p.add_argument("-o", metavar="FILE", type=str, help="假脱机并将数据输出到文件中.")
    p.add_argument("-i", help="使用SSL时允许不安全的服务器进行连接", action='store_true')
    p.add_argument("-q", help="不提示输出，仅输出错误.", action='store_true')
    p.add_argument("-k", help="关闭带颜色的输出.", action='store_true')
    p.add_argument("-b", "-v", help="打印Banner和版本信息并退出.", action='store_true')

    args = p.parse_args()

    # Load commands from a file
    if args.e:
        try:
            cin = open(args.e, "r")
        except BaseException as e:
            print("无法打开 " + args.e + ":" + " (" + str(e) + ")")
            sys.exit(-1)
    else:
        cin = sys.stdin
    s = GhostOsintCMD(stdin=cin)
    s.identchars += "$"

    # Map command-line to config
    if args.u:
        s.ownopts['cli.username'] = args.u
    if args.p:
        s.ownopts['cli.password'] = args.p
    if args.P:
        try:
            pf = open(args.P, "r")
            s.ownopts['cli.password'] = pf.readlines()[0].strip('\n')
            pf.close()
        except BaseException as e:
            print(f"无法打开 {args.P}: ({e})")
            sys.exit(-1)
    if args.i:
        s.ownopts['cli.ssl_verify'] = False
    if args.k:
        s.ownopts['cli.color'] = False
    if args.s:
        s.ownopts['cli.server_baseurl'] = args.s
    if args.debug:
        s.ownopts['cli.debug'] = True
    if args.q:
        s.ownopts['cli.silent'] = True
    if args.n:
        s.ownopts['cli.history'] = False
    if args.l:
        s.ownopts['cli.history_file'] = args.l
    else:
        try:
            s.ownopts['cli.history_file'] = expanduser("~") + "/.ghostosint_history"
        except BaseException as e:
            s.dprint(f"Failed to set 'cli.history_file': {e}")
            s.dprint("在工作目录中使用 '.ghostosint_history' ")
            s.ownopts['cli.history_file'] = ".ghostosint_history"
    if args.o:
        s.ownopts['cli.spool'] = True
        s.ownopts['cli.spool_file'] = args.o

    if args.e or not os.isatty(0):
        try:
            s.use_rawinput = False
            s.prompt = ""
            s.cmdloop()
        finally:
            cin.close()
        sys.exit(0)

    if not args.q:
        s = GhostOsintCMD()
        s.dprint(ASCII_LOGO, plain=True, color=bcolors.GREYBLUE)
        s.dprint(COPYRIGHT_INFO, plain=True,
                 color=bcolors.GREYBLUE_DARK)
        s.dprint(f"Version {s.version}.")
        if args.b:
            sys.exit(0)

    # Test connectivity to the server
    s.do_ping("")

    if not args.n:
        try:
            f = codecs.open(s.ownopts['cli.history_file'], "r", encoding="utf-8")
            for line in f.readlines():
                readline.add_history(line.strip())
            s.dprint("已加载之前的命令记录.")
        except BaseException:
            pass

    try:
        s.dprint("Type 'help' or '?'.")
        s.cmdloop()
    except KeyboardInterrupt:
        print("\n")
        sys.exit(0)

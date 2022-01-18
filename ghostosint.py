#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import multiprocessing as mp
import os
import os.path
import random
import signal
import sys
import time
from copy import deepcopy

import cherrypy
import cherrypy_cors
from cherrypy.lib import auth_digest

from ghostosintlib import GhostOSINT
from ghostosintscan import GhostOsintScan
from ghostosintweb import GhostOsintWEB
from ghostosint import GhostOsintHelp
from ghostosint import GhostOsintDB
from ghostosint.logger import logListenerSetup, logWorkerSetup
from ghostosint import __version__

scanId = None
dbh = None


def main():
    # web server config
    GhostOsintWEBConfig = {
        'host': '127.0.0.1',
        'port': 5001,
        'root': '/',
        'cors_origins': [],
    }

    # 'Global' configuration options
    # These can be overriden on a per-module basis, and some will
    # be overridden from saved configuration settings stored in the DB.
    GhostOsintConfig = {
        '_debug': False,  # Debug
        '_maxthreads': 3,  # Number of modules to run concurrently
        '__logging': True,  # Logging in general
        '__outputfilter': None,  # Event types to filter from modules' output
        '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',  # User-Agent to use for HTTP requests
        '_dnsserver': '',  # Override the default resolver
        '_fetchtimeout': 5,  # number of seconds before giving up on a fetch
        '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
        '_internettlds_cache': 72,
        '_genericusers': "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,registrar,registry,root,routing-registry,rr,sales,security,spam,support,sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www",
        '__database': f"{GhostOsintHelp.dataPath()}/ghostosint.db",
        '__modules__': None,  # List of modules. Will be set after start-up.
        '_socks1type': '',
        '_socks2addr': '',
        '_socks3port': '',
        '_socks4user': '',
        '_socks5pwd': '',
    }

    GhostOsintPtd = {
        '_debug': "启用调试?",
        '_maxthreads': "并发运行的最大模块数",
        '_useragent': "User-Agent 用于HTTP请求.前缀为“@”,以从包含每个请求的用户代理字符串的文件中随机选择用户代理,例如@C:\\useragents.txt,也可以提供一个URL地址来获取User-Agent.",
        '_dnsserver': "使用其他DNS服务器,例如8.8.8.8是Google的开放DNS服务器.",
        '_fetchtimeout': "放弃HTTP请求之前的秒数倒计时.",
        '_internettlds': "联网TLDs.",
        '_internettlds_cache': "用于缓存互联网TLDs的小时数.",
        '_genericusers': "如果发现作为用户名或电子邮件地址的一部分的用户名列表，将其特别显示.",
        '_socks1type': "SOCKS 服务类型. 可以 '4', '5', 'HTTP' 或 'TOR'",
        '_socks2addr': 'SOCKS 服务器IP地址.',
        '_socks3port': "SOCKS 服务器TCP端口t. 通常 '4'或'5'端口为 1080, HTTP为8080, TOR为9050.",
        '_socks4user': 'SOCKS 用户名. 仅对SOCKS4和SOCKS5 服务有效.',
        '_socks5pwd': "SOCKS 密码. 仅对SOCKS5服务有效.",
        '_modulesenabled': "为扫描启用的模块."  # This is a hack to get a description for an option not actually available.
    }

    # Legacy way to run the server
    args = None
    p = argparse.ArgumentParser(description=f"GhostOSINT {__version__}: 开源自动化的OSINT工具.")
    p.add_argument("-d", "--debug", action='store_true', help="启用调试输出.")
    p.add_argument("-l", metavar="IP:port", help="要监听的IP地址和端口.")
    p.add_argument("-m", metavar="mod1,mod2,...", type=str, help="扫描启用的模块.")
    p.add_argument("-M", "--modules", action='store_true', help="列出可用模块.")
    p.add_argument("-s", metavar="TARGET", help="扫描目标.")
    p.add_argument("-t", metavar="type1,type2,...", type=str, help="要收集的事件类型(自动选择的模块).")
    p.add_argument("-T", "--types", action='store_true', help="列出可用的事件类型.")
    p.add_argument("-o", metavar="tab|csv|json", type=str, help="输出格式,默认选项'tap'.")
    p.add_argument("-H", action='store_true', help="不输出字段标题，只输出数据内容.")
    p.add_argument("-n", action='store_true', help="数据中去除换行符.")
    p.add_argument("-r", action='store_true', help="在tab/csv文件中输出包括的源数据字段.")
    p.add_argument("-S", metavar="LENGTH", type=int, help="要显示的最大数据长度,默认显示所有数据.")
    p.add_argument("-D", metavar='DELIMITER', type=str, help="用于csv文件中的分隔符，默认为 ','.")
    p.add_argument("-f", action='store_true', help="使用 -t 选项筛选出未请求的其他事件类型.")
    p.add_argument("-F", metavar="type1,type2,...", type=str, help="仅显示一组数据类型，以','分隔.")
    p.add_argument("-x", action='store_true', help="严格模式,仅启用可以直接对目标使用的模块,如果指定了 -t 选项,则模块将仅使用这些事件,将覆盖 -t 选项 和 -m 选项.")
    p.add_argument("-q", action='store_true', help="禁用日志，不会显示错误信息的喵~")
    p.add_argument("-V", "--version", action='store_true', help="显示Ghost OSINT的版本信息并退出.")
    args = p.parse_args()

    if args.version:
        print(f"GhostOSINT {__version__}: 开源自动化的OSINT工具.")
        sys.exit(0)

    if args.debug:
        GhostOsintConfig['_debug'] = True
    else:
        GhostOsintConfig['_debug'] = False

    if args.q:
        GhostOsintConfig['__logging'] = False

    loggingQueue = mp.Queue()
    logListenerSetup(loggingQueue, GhostOsintConfig)
    logWorkerSetup(loggingQueue)
    log = logging.getLogger(f"ghostosint.{__name__}")

    GhostOsintModules = dict()
    GhostOsintM = GhostOSINT(GhostOsintConfig)

    # Load each module in the modules directory with a .py extension
    mod_dir = GhostOsintM.myPath() + '/modules/'

    if not os.path.isdir(mod_dir):
        log.critical(f"模块目录不存在: {mod_dir}")
        sys.exit(-1)

    for filename in os.listdir(mod_dir):
        if not filename.endswith(".py"):
            continue
        if not filename.startswith("GO_"):
            continue
        if filename in ('GO_template.py'):
            continue

        modName = filename.split('.')[0]

        # Load and instantiate the module
        GhostOsintModules[modName] = dict()
        try:
            mod = __import__('modules.' + modName, globals(), locals(), [modName])
            GhostOsintModules[modName]['object'] = getattr(mod, modName)()
            mod_dict = GhostOsintModules[modName]['object'].asdict()
            GhostOsintModules[modName].update(mod_dict)
        except BaseException as e:
            log.critical(f"无法加载该模块 {modName}: {e}")
            sys.exit(-1)

    if not GhostOsintModules:
        log.critical(f"在模块目录中没找到模块啊，大兄弟: {mod_dir}")
        sys.exit(-1)

    # Add module info to GhostOsintConfig so it can be used by the UI
    GhostOsintConfig['__modules__'] = GhostOsintModules
    # Add descriptions of the global config options
    GhostOsintConfig['__globaloptdescs__'] = GhostOsintPtd

    if args.modules:
        log.info("可用模块:")
        for m in sorted(GhostOsintModules.keys()):
            if "__" in m:
                continue
            print(('{0:25}  {1}'.format(m, GhostOsintModules[m]['descr'])))
        sys.exit(0)

    if args.types:
        dbh = GhostOsintDB(GhostOsintConfig, init=True)
        log.info("可用类型:")
        typedata = dbh.eventTypes()
        types = dict()
        for r in typedata:
            types[r[1]] = r[0]

        for t in sorted(types.keys()):
            print(('{0:45}  {1}'.format(t, types[t])))
        sys.exit(0)

    if args.l:
        try:
            (host, port) = args.l.split(":")
        except BaseException:
            log.critical("无效的IP端口格式.")
            sys.exit(-1)

        GhostOsintWEBConfig['host'] = host
        GhostOsintWEBConfig['port'] = port

        start_web_server(GhostOsintWEBConfig, GhostOsintConfig, loggingQueue)
        exit(0)

    start_scan(GhostOsintConfig, GhostOsintModules, args, loggingQueue)


def start_scan(GhostOsintConfig, GhostOsintModules, args, loggingQueue):
    """Start scan

    Args:
        GhostOsintConfig (dict): GhostOSINT config options
        GhostOsintModules (dict): modules
        args (argparse.Namespace): command line args
        loggingQueue (Queue): main GhostOSINT logging queue
    """
    log = logging.getLogger(f"ghostosint.{__name__}")

    global dbh
    global scanId

    dbh = GhostOsintDB(GhostOsintConfig, init=True)
    GhostOsint = GhostOSINT(GhostOsintConfig)

    if not args.s:
        log.error("在扫描模式下运行时,必须指定目标,输入--help查看帮助信息.")
        sys.exit(-1)

    if args.x and not args.t:
        log.error("-x 选项只能与 -t 选项一起使用,输入--help查看帮助信息.")
        sys.exit(-1)

    if args.x and args.m:
        log.error("-x 选项只能与 -t 选项一起使用,不能与 -m 选项一起使用,输入--help查看帮助信息.")
        sys.exit(-1)

    if args.r and (args.o and args.o not in ["tab", "csv"]):
        log.error("-r 选项只能在输出格式为tab或csv时使用.")
        sys.exit(-1)

    if args.H and (args.o and args.o not in ["tab", "csv"]):
        log.error("-h 选项只能在输出格式为tab或csv时使用.")
        sys.exit(-1)

    if args.D and args.o != "csv":
        log.error("-d 选项只能在使用CSV输出格式时使用.")
        sys.exit(-1)

    target = args.s
    # Usernames and names - quoted on the commandline - won't have quotes,
    # so add them.
    if " " in target:
        target = f"\"{target}\""
    if "." not in target and not target.startswith("+") and '"' not in target:
        target = f"\"{target}\""
    targetType = GhostOsintHelp.targetTypeFromString(target)

    if not targetType:
        log.error(f"无法确定目标类型啊，目标无效: {target}")
        sys.exit(-1)

    target = target.strip('"')

    modlist = list()
    if not args.t and not args.m:
        log.warning("你要是没有指定任何模块或类型，我可就全部启用了啊.")
        for m in list(GhostOsintModules.keys()):
            if "__" in m:
                continue
            modlist.append(m)

    signal.signal(signal.SIGINT, handle_abort)
    # If the user is scanning by type..
    # 1. Find modules producing that type
    if args.t:
        types = args.t
        modlist = GhostOsint.modulesProducing(types)
        newmods = deepcopy(modlist)
        newmodcpy = deepcopy(newmods)

        # 2. For each type those modules consume, get modules producing
        while len(newmodcpy) > 0:
            for etype in GhostOsint.eventsToModules(newmodcpy):
                xmods = GhostOsint.modulesProducing([etype])
                for mod in xmods:
                    if mod not in modlist:
                        modlist.append(mod)
                        newmods.append(mod)
            newmodcpy = deepcopy(newmods)
            newmods = list()

    # Easier if scanning by module
    if args.m:
        modlist = list(filter(None, args.m.split(",")))

    # Add GO__stor_stdout to the module list
    typedata = dbh.eventTypes()
    types = dict()
    for r in typedata:
        types[r[1]] = r[0]

    GO__stor_stdout_opts = GhostOsintConfig['__modules__']['GO__stor_stdout']['opts']
    GO__stor_stdout_opts['_eventtypes'] = types
    if args.f:
        if args.f and not args.t:
            log.error("只能将 -f 选项与 -t 选项一起使用,输入--help查看帮助信息.")
            sys.exit(-1)
        GO__stor_stdout_opts['_showonlyrequested'] = True
    if args.F:
        GO__stor_stdout_opts['_requested'] = args.F.split(",")
        GO__stor_stdout_opts['_showonlyrequested'] = True
    if args.o:
        if args.o not in ["tab", "csv", "json"]:
            log.error("选择的输出格式不符合，必须是 'tab', 'csv' 或 'json'.")
            sys.exit(-1)
        GO__stor_stdout_opts['_format'] = args.o
    if args.t:
        GO__stor_stdout_opts['_requested'] = args.t.split(",")
    if args.n:
        GO__stor_stdout_opts['_stripnewline'] = True
    if args.r:
        GO__stor_stdout_opts['_showsource'] = True
    if args.S:
        GO__stor_stdout_opts['_maxlength'] = args.S
    if args.D:
        GO__stor_stdout_opts['_csvdelim'] = args.D
    if args.x:
        tmodlist = list()
        modlist = list()
        xmods = GhostOsint.modulesConsuming([targetType])
        for mod in xmods:
            if mod not in modlist:
                tmodlist.append(mod)

        # Remove any modules not producing the type requested
        rtypes = args.t.split(",")
        for mod in tmodlist:
            for r in rtypes:
                if not GhostOsintModules[mod]['provides']:
                    continue
                if r in GhostOsintModules[mod].get('provides', []) and mod not in modlist:
                    modlist.append(mod)

    if len(modlist) == 0:
        log.error("根据你的选择，不使用任何模块.")
        sys.exit(-1)

    modlist += ["GO__stor_db", "GO__stor_stdout"]

    if GhostOsintConfig['__logging']:
        log.info(f"Modules enabled ({len(modlist)}): {','.join(modlist)}")

    cfg = GhostOsint.configUnserialize(dbh.configGet(), GhostOsintConfig)

    # Debug mode is a variable that gets stored to the DB, so re-apply it
    if args.debug:
        cfg['_debug'] = True
    else:
        cfg['_debug'] = False

    # If strict mode is enabled, filter the output from modules.
    if args.x and args.t:
        cfg['__outputfilter'] = args.t.split(",")

    # Prepare scan output headers
    if args.o == "json":
        print("[", end='')
    elif not args.H:
        delim = "\t"

        if args.o == "tab":
            delim = "\t"

        if args.o == "csv":
            if args.D:
                delim = args.D
            else:
                delim = ","

        if args.r:
            if delim == "\t":
                headers = '{0:30}{1}{2:45}{3}{4}{5}{6}'.format("源", delim, "类型", delim, "源数据", delim, "数据")
            else:
                headers = delim.join(["源", "类型", "源数据", "数据"])
        else:
            if delim == "\t":
                headers = '{0:30}{1}{2:45}{3}{4}'.format("源", delim, "类型", delim, "数据")
            else:
                headers = delim.join(["源", "类型", "数据"])

        print(headers)

    # Start running a new scan
    scanName = target
    scanId = GhostOsintHelp.genScanInstanceId()
    try:
        p = mp.Process(target=GhostOsintScan, args=(loggingQueue, scanName, scanId, target, targetType, modlist, cfg))
        p.daemon = True
        p.start()
    except BaseException as e:
        log.error(f"Scan [{scanId}] failed: {e}")
        sys.exit(-1)

    # Poll for scan status until completion
    while True:
        time.sleep(1)
        info = dbh.scanInstanceGet(scanId)
        if not info:
            continue
        if info[5] in ["ERROR-FAILED", "ABORT-REQUESTED", "ABORTED", "FINISHED"]:
            if GhostOsintConfig['__logging']:
                log.info(f"扫描完成了，你看看当前的状态是 {info[5]}")
            if args.o == "json":
                print("]")
            sys.exit(0)

    return


def start_web_server(GhostOsintWEBConfig, GhostOsintConfig, loggingQueue=None):
    """Start the web server so you can start looking at results

    Args:
        GhostOsintWEBConfig (dict): web server options
        GhostOsintConfig (dict): GhostOSINT config options
        loggingQueue (Queue): main GhostOSINT logging queue
    """
    log = logging.getLogger(f"ghostosint.{__name__}")

    web_host = GhostOsintWEBConfig.get('host', '127.0.0.1')
    web_port = GhostOsintWEBConfig.get('port', 5001)
    web_root = GhostOsintWEBConfig.get('root', '/')
    cors_origins = GhostOsintWEBConfig.get('cors_origins', [])

    cherrypy.config.update({
        'log.screen': False,
        'server.socket_host': web_host,
        'server.socket_port': int(web_port)
    })

    log.info(f"正在启动WEB服务器 {web_host}:{web_port} ...")

    GhostOsint = GhostOSINT(GhostOsintConfig)

    # Enable access to static files via the web directory
    conf = {
        '/query': {
            'tools.encode.text_only': False,
            'tools.encode.add_charset': True,
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
            'tools.staticdir.root': f"{GhostOsint.myPath()}/ghostosint"
        }
    }

    secrets = dict()
    passwd_file = GhostOsintHelp.dataPath() + '/passwd'
    if os.path.isfile(passwd_file):
        if not os.access(passwd_file, os.R_OK):
            log.error("无法读取密码文件,权限被拒.")
            sys.exit(-1)

        pw = open(passwd_file, 'r')

        for line in pw.readlines():
            if line.strip() == '':
                continue

            if ':' not in line:
                log.error("密码文件格式不正确,每行必须是用户名:密码.")
                sys.exit(-1)

            u = line.strip().split(":")[0]
            p = ':'.join(line.strip().split(":")[1:])

            if not u or not p:
                log.error("密码文件格式不正确,每行必须是用户名:密码.")
                sys.exit(-1)

            secrets[u] = p

    if secrets:
        log.info("基于提供的密码文件启动身份验证.")
        conf['/'] = {
            'tools.auth_digest.on': True,
            'tools.auth_digest.realm': web_host,
            'tools.auth_digest.get_ha1': auth_digest.get_ha1_dict_plain(secrets),
            'tools.auth_digest.key': random.SystemRandom().randint(0, 99999999)
        }
    else:
        warn_msg = "\n********************************************************************\n"
        warn_msg += "警告:密码文件不包含密码,身份验证已关闭.\n"
        warn_msg += "请考虑添加身份验证已保护该实例!\n"
        warn_msg += "创建passwd文件并存入用户名密码即可添加身份验证.\n"
        warn_msg += "********************************************************************\n"
        log.warning(warn_msg)

    using_ssl = False
    key_path = GhostOsintHelp.dataPath() + '/ghostosint.key'
    crt_path = GhostOsintHelp.dataPath() + '/ghostosint.crt'
    if os.path.isfile(key_path) and os.path.isfile(crt_path):
        if not os.access(crt_path, os.R_OK):
            log.critical(f"无法读取 {crt_path} 文件. 权限被拒.")
            sys.exit(-1)

        if not os.access(key_path, os.R_OK):
            log.critical(f"无法读取 {key_path} 文件. 权限被拒.")
            sys.exit(-1)

        log.info("根据提供的密钥和证书开启SSL.")
        cherrypy.server.ssl_module = 'builtin'
        cherrypy.server.ssl_certificate = crt_path
        cherrypy.server.ssl_private_key = key_path
        using_ssl = True

    if using_ssl:
        url = "https://"
    else:
        url = "http://"

    if web_host == "0.0.0.0":  # nosec
        url = f"{url}127.0.0.1:{web_port}"
    else:
        url = f"{url}{web_host}:{web_port}{web_root}"
        cors_origins.append(url)

    cherrypy_cors.install()
    cherrypy.config.update({
        'cors.expose.on': True,
        'cors.expose.origins': cors_origins,
        'cors.preflight.origins': cors_origins
    })

    print("")
    print("         ____    __                       __                    ")
    print("        /\  _`\ /\ \                     /\ \__                 ")
    print("        \ \ \L\_\ \ \___     ___     ____\ \ ,_\                ")
    print("         \ \ \L_L\ \  _ `\  / __`\  /',__\\ \ \/       _______  ")
    print("          \ \ \/, \ \ \ \ \/\ \L\ \/\__, `\\ \ \_     /\______\ ")
    print("           \ \____/\ \_\ \_\ \____/\/\____/ \ \__\    \/______/ ")
    print("            \/___/  \/_/\/_/\/___/  \/___/   \/__/              ")
    print("")
    print("")
    print("               _____   ____    ______   __  __  ______          ")
    print("              /\  __`\/\  _`\ /\__  _\ /\ \/\ \/\__  _\         ")
    print("              \ \ \/\ \ \,\L\_\/_/\ \/ \ \ `\\ \/_/\ \/         ")
    print("               \ \ \ \ \/_\__ \  \ \ \  \ \ , ` \ \ \ \         ")
    print("                \ \ \_\ \/\ \L\ \ \_\ \__\ \ \`\ \ \ \ \        ")
    print("                 \ \_____\ `\____\/\_____\\ \_\ \_\ \ \_\       ")
    print("                  \/_____/\/_____/\/_____/ \/_/\/_/  \/_/       ")
    print(" 通过启动浏览器访问Ghost OSINT， ")
    print(f" 访问该 {url} 地址即可.")
    print("*************************************************************")
    print("")

    # Disable auto-reloading of content
    cherrypy.engine.autoreload.unsubscribe()

    cherrypy.quickstart(GhostOsintWEB(GhostOsintWEBConfig, GhostOsintConfig, loggingQueue), script_name=web_root, config=conf)


def handle_abort(signal, frame):
    """Handle interrupt and abort scan.

    Args:
        signal: TBD
        frame: TBD
    """
    log = logging.getLogger(f"ghostosint.{__name__}")

    global dbh
    global scanId

    if scanId and dbh:
        log.info(f"正在中止扫描 [{scanId}] ...")
        dbh.scanInstanceSet(scanId, None, None, "ABORTED")
    sys.exit(-1)


if __name__ == '__main__':
    if sys.version_info < (3, 7):
        print("GhostOSINT 需要 Python 3.7 或更高版本.")
        sys.exit(-1)

    if len(sys.argv) <= 1:
        print("Ghost OSINT 需要 -l <ip>:<port> 来启动WEB服务器. 输入 --help 获取帮助信息.")
        sys.exit(-1)

    from pathlib import Path
    if os.path.exists('ghostosint.db'):
        print(f"错误: ghostosint.db 文件中存在 {os.path.dirname(__file__)}")
        print("Ghost OSINT 不再支持从应用程序目录中加载 ghostosint.db 数据库文件.")
        print(f"数据库文件已从你的主目录中加载: {Path.home()}/.ghostosint/ghostosint.db")
        print(f"此消息会在你移动或删除 ghostosint.db 文件中的 {os.path.dirname(__file__)} 内容后消失")
        sys.exit(-1)

    from pathlib import Path
    if os.path.exists('passwd'):
        print(f"错误: passwd文件中存在{os.path.dirname(__file__)}")
        print("GhostOSINT 不再支持从应用程序中加载密码文件.")
        print(f"密码文件现在已经从你的主目录中加载: {Path.home()}/.ghostosint/passwd")
        print(f"此消息会在你移动或删除passwd文件中的 {os.path.dirname(__file__)} 内容后消失")
        sys.exit(-1)

    main()

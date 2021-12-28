#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import time
import queue
import traceback
from time import sleep
from copy import deepcopy
from contextlib import suppress
from collections import OrderedDict

import dns.resolver

from ghostosintlib import GhostOSINT
from ghostosint import GhostOsintDB, GhostOsintEvent, GhostOsintPlugin, GhostOsintTarget, GhostOsintHelp, GhostOsintThread, logger


def GhostOsintScan(loggingQueue, *args, **kwargs):
    logger.logWorkerSetup(loggingQueue)
    return GhostOsintScanner(*args, **kwargs)


class GhostOsintScanner():
    """GhostOsintScanner object.

    Attributes:
        scanId (str): unique ID of the scan
        status (str): status of the scan
    """

    __scanId = None
    __status = None
    __config = None
    __go = None
    __dbh = None
    __targetValue = None
    __targetType = None
    __moduleList = list()
    __target = None
    __moduleInstances = dict()
    __modconfig = dict()
    __scanName = None

    def __init__(self, scanName, scanId, targetValue, targetType, moduleList, globalOpts, start=True):
        """Initialize GhostOsintScanner object.

        Args:
            scanName (str): name of the scan
            scanId (str): unique ID of the scan
            targetValue (str): scan target
            targetType (str): scan target type
            moduleList (list): list of modules to run
            globalOpts (dict): scan options
            start (bool): start the scan immediately

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid

        Todo:
             Eventually change this to be able to control multiple scan instances
        """
        if not isinstance(globalOpts, dict):
            raise TypeError(f"扫描配置为 {type(globalOpts)}; expected dict()")
        if not globalOpts:
            raise ValueError("扫描配置为空")

        self.__config = deepcopy(globalOpts)
        self.__dbh = GhostOsintDB(self.__config)

        if not isinstance(scanName, str):
            raise TypeError(f"扫描名称为 {type(scanName)}; expected str()")
        if not scanName:
            raise ValueError("扫描名称值为空")

        self.__scanName = scanName

        if not isinstance(scanId, str):
            raise TypeError(f"扫描ID为 {type(scanId)}; expected str()")
        if not scanId:
            raise ValueError("扫描ID为空")

        if not isinstance(targetValue, str):
            raise TypeError(f"目标值为 {type(targetValue)}; expected str()")
        if not targetValue:
            raise ValueError("目标值为空")

        self.__targetValue = targetValue

        if not isinstance(targetType, str):
            raise TypeError(f"目标属性为 {type(targetType)}; expected str()")
        if not targetType:
            raise ValueError("目标属性值为空")

        self.__targetType = targetType

        if not isinstance(moduleList, list):
            raise TypeError(f"模块列表为 {type(moduleList)}; expected list()")
        if not moduleList:
            raise ValueError("模块列表为空")

        self.__moduleList = moduleList

        self.__go = GhostOSINT(self.__config)
        self.__go.dbh = self.__dbh

        # Create a unique ID for this scan in the back-end DB.
        if scanId:
            self.__scanId = scanId
        else:
            self.__scanId = GhostOsintHelp.genScanInstanceId()

        self.__go.scanId = self.__scanId
        self.__dbh.scanInstanceCreate(self.__scanId, self.__scanName, self.__targetValue)

        # Create our target
        try:
            self.__target = GhostOsintTarget(self.__targetValue, self.__targetType)
        except (TypeError, ValueError) as e:
            self.__go.status(f"扫描 [{self.__scanId}] 失败了呢: {e}")
            self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
            raise ValueError(f"无效目标: {e}")

        # Save the config current set for this scan
        self.__config['_modulesenabled'] = self.__moduleList
        self.__dbh.scanConfigSet(self.__scanId, self.__go.configSerialize(deepcopy(self.__config)))

        # Process global options that point to other places for data

        # If a proxy server was specified, set it up
        proxy_type = self.__config.get('_socks1type')
        if proxy_type:
            # TODO: allow DNS lookup to be configurable when using a proxy
            # - proxy DNS lookup: socks5h:// and socks4a://
            # - local DNS lookup: socks5:// and socks4://
            if proxy_type == '4':
                proxy_proto = 'socks4://'
            elif proxy_type == '5':
                proxy_proto = 'socks5://'
            elif proxy_type == 'HTTP':
                proxy_proto = 'http://'
            elif proxy_type == 'TOR':
                proxy_proto = 'socks5h://'
            else:
                self.__go.status(f"扫描 [{self.__scanId}] 失败: 无效代理类型: {proxy_type}")
                self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
                raise ValueError(f"无效代理类型: {proxy_type}")

            proxy_host = self.__config.get('_socks2addr', '')

            if not proxy_host:
                self.__go.status(f"扫描 [{self.__scanId}] 失败: 代理类型为 ({proxy_type}) 但是代理地址为空")
                self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
                raise ValueError(f"代理类型为 ({proxy_type}) 但是代理地址为空")

            proxy_port = int(self.__config.get('_socks3port') or 0)

            if not proxy_port:
                if proxy_type in ['4', '5']:
                    proxy_port = 1080
                elif proxy_type.upper() == 'HTTP':
                    proxy_port = 8080
                elif proxy_type.upper() == 'TOR':
                    proxy_port = 9050

            proxy_username = self.__config.get('_socks4user', '')
            proxy_password = self.__config.get('_socks5pwd', '')

            if proxy_username or proxy_password:
                proxy_auth = f"{proxy_username}:{proxy_password}"
                proxy = f"{proxy_proto}{proxy_auth}@{proxy_host}:{proxy_port}"
            else:
                proxy = f"{proxy_proto}{proxy_host}:{proxy_port}"

            self.__go.debug(f"Using proxy: {proxy}")
            self.__go.socksProxy = proxy
        else:
            self.__go.socksProxy = None

        # Override the default DNS server
        if self.__config['_dnsserver']:
            res = dns.resolver.Resolver()
            res.nameservers = [self.__config['_dnsserver']]
            dns.resolver.override_system_resolver(res)
        else:
            dns.resolver.restore_system_resolver()

        # Set the user agent
        self.__config['_useragent'] = self.__go.optValueToData(self.__config['_useragent'])

        # Get internet TLDs
        tlddata = self.__go.cacheGet("internet_tlds", self.__config['_internettlds_cache'])

        # If it wasn't loadable from cache, load it from scratch
        if tlddata is None:
            self.__config['_internettlds'] = self.__go.optValueToData(self.__config['_internettlds'])
            self.__go.cachePut("internet_tlds", self.__config['_internettlds'])
        else:
            self.__config["_internettlds"] = tlddata.splitlines()

        self.__setStatus("INITIALIZING", time.time() * 1000, None)

        self.__sharedThreadPool = GhostOsintThread(threads=self.__config.get("_maxthreads", 3), name='sharedThreadPool')

        # Used when module threading is enabled
        self.eventQueue = None

        if start:
            self.__startScan()

    @property
    def scanId(self):
        return self.__scanId

    @property
    def status(self):
        return self.__status

    def __setStatus(self, status, started=None, ended=None):
        """Set the status of the currently running scan (if any).

        Args:
            status (str): scan status
            started (float): timestamp at start of scan
            ended (float): timestamp at end of scan

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
        """
        if not isinstance(status, str):
            raise TypeError(f"status is {type(status)}; expected str()")

        if status not in [
            "INITIALIZING",
            "STARTING",
            "STARTED",
            "RUNNING",
            "ABORT-REQUESTED",
            "ABORTED",
            "ABORTING",
            "FINISHED",
            "ERROR-FAILED"
        ]:
            raise ValueError(f"无效扫描状态 {status}")

        self.__status = status
        self.__dbh.scanInstanceSet(self.__scanId, started, ended, status)

    def __startScan(self):
        """Start running a scan.

        Raises:
            AssertionError: Never actually raised.
        """
        failed = True

        try:
            self.__setStatus("STARTING", time.time() * 1000, None)
            self.__go.status(f"Scan [{self.__scanId}] for '{self.__target.targetValue}' initiated.")

            self.eventQueue = queue.Queue()

            self.__sharedThreadPool.start()

            # moduleList = list of modules the user wants to run
            self.__go.debug(f"Loading {len(self.__moduleList)} modules ...")
            for modName in self.__moduleList:
                if not modName:
                    continue

                # Module may have been renamed or removed
                if modName not in self.__config['__modules__']:
                    self.__go.error(f"无法加载模块: {modName}")
                    continue

                try:
                    module = __import__('modules.' + modName, globals(), locals(), [modName])
                except ImportError:
                    self.__go.error(f"无法加载模块: {modName}")
                    continue

                try:
                    mod = getattr(module, modName)()
                    mod.__name__ = modName
                except Exception:
                    self.__go.error(f"模块 {modName} 初始化失败: {traceback.format_exc()}")
                    continue

                # Set up the module options, scan ID, database handle and listeners
                try:
                    # Configuration is a combined global config with module-specific options
                    self.__modconfig[modName] = deepcopy(self.__config['__modules__'][modName]['opts'])
                    for opt in list(self.__config.keys()):
                        self.__modconfig[modName][opt] = deepcopy(self.__config[opt])

                    # clear any listener relationships from the past
                    mod.clearListeners()
                    mod.setScanId(self.__scanId)
                    mod.setSharedThreadPool(self.__sharedThreadPool)
                    mod.setDbh(self.__dbh)
                    mod.setup(self.__go, self.__modconfig[modName])
                except Exception:
                    self.__go.error(f"模块 {modName} 初始化失败: {traceback.format_exc()}")
                    mod.errorState = True
                    continue

                # Override the module's local socket module to be the SOCKS one.
                if self.__config['_socks1type'] != '':
                    try:
                        mod._updateSocket(socket)
                    except Exception as e:
                        self.__go.error(f"模块 {modName} 安装失败: {e}")
                        continue

                # Set up event output filters if requested
                if self.__config['__outputfilter']:
                    try:
                        mod.setOutputFilter(self.__config['__outputfilter'])
                    except Exception as e:
                        self.__go.error(f"模块 {modName} 输出过滤设置失败: {e}")
                        continue

                # Give modules a chance to 'enrich' the original target with aliases of that target.
                try:
                    newTarget = mod.enrichTarget(self.__target)
                    if newTarget is not None:
                        self.__target = newTarget
                except Exception as e:
                    self.__go.error(f"模块 {modName} 目标充能失败: {e}")
                    continue

                # Register the target with the module
                try:
                    mod.setTarget(self.__target)
                except Exception as e:
                    self.__go.error(f"模块 {modName} 设置目标失败 '{self.__target}': {e}")
                    continue

                # Set up the outgoing event queue
                try:
                    mod.outgoingEventQueue = self.eventQueue
                    mod.incomingEventQueue = queue.Queue()
                except Exception as e:
                    self.__go.error(f"模块 {modName} 事件队列设置失败: {e}")
                    continue

                self.__moduleInstances[modName] = mod
                self.__go.status(f"{modName} 模块已加载.")

            self.__go.debug(f"扫描 [{self.__scanId}] 已加载 {len(self.__moduleInstances)} 模块.")

            if not self.__moduleInstances:
                self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
                self.__dbh.close()
                return

            # sort modules by priority
            self.__moduleInstances = OrderedDict(sorted(self.__moduleInstances.items(), key=lambda m: m[-1]._priority))

            # Now we are ready to roll..
            self.__setStatus("RUNNING")

            # Create a pseudo module for the root event to originate from
            psMod = GhostOsintPlugin()
            psMod.__name__ = "GhostOSINT UI"
            psMod.setTarget(self.__target)
            psMod.setDbh(self.__dbh)
            psMod.clearListeners()
            psMod.outgoingEventQueue = self.eventQueue
            psMod.incomingEventQueue = queue.Queue()

            # Create the "ROOT" event which un-triggered modules will link events to
            rootEvent = GhostOsintEvent("ROOT", self.__targetValue, "", None)
            psMod.notifyListeners(rootEvent)
            firstEvent = GhostOsintEvent(self.__targetType, self.__targetValue,
                                         "GhostOSINT UI", rootEvent)
            psMod.notifyListeners(firstEvent)

            # Special case.. check if an INTERNET_NAME is also a domain
            if self.__targetType == 'INTERNET_NAME':
                if self.__go.isDomain(self.__targetValue, self.__config['_internettlds']):
                    firstEvent = GhostOsintEvent('DOMAIN_NAME', self.__targetValue,
                                                 "GhostOSINT UI", rootEvent)
                    psMod.notifyListeners(firstEvent)

            # If in interactive mode, loop through this shared global variable
            # waiting for inputs, and process them until my status is set to
            # FINISHED.

            # Check in case the user requested to stop the scan between modules
            # initializing
            scanstatus = self.__dbh.scanInstanceGet(self.__scanId)
            if scanstatus and scanstatus[5] == "ABORT-REQUESTED":
                raise AssertionError("ABORT-REQUESTED")

            # start threads
            self.waitForThreads()
            failed = False

        except (KeyboardInterrupt, AssertionError):
            self.__go.status(f"Scan [{self.__scanId}] aborted.")
            self.__setStatus("ABORTED", None, time.time() * 1000)

        except BaseException as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.__go.error(f"未处理的异常 ({e.__class__.__name__}) 在扫描过程中遇到."
                            + "请导出这个BUG: "
                            + repr(traceback.format_exception(exc_type, exc_value, exc_traceback)))
            self.__go.status(f"扫描 [{self.__scanId}] 失败了呢: {e}")
            self.__setStatus("ERROR-FAILED", None, time.time() * 1000)

        finally:
            if not failed:
                self.__go.status(f"扫描 [{self.__scanId}] 已完成.")
                self.__setStatus("FINISHED", None, time.time() * 1000)
            self.__dbh.close()

    def waitForThreads(self):
        counter = 0

        try:
            if not self.eventQueue:
                return

            # start one thread for each module
            for mod in self.__moduleInstances.values():
                mod.start()
            final_passes = 3

            # watch for newly-generated events
            while True:

                # log status of threads every 10 iterations
                log_status = counter % 10 == 0
                counter += 1

                if log_status:
                    scanstatus = self.__dbh.scanInstanceGet(self.__scanId)
                    if scanstatus and scanstatus[5] == "ABORT-REQUESTED":
                        raise AssertionError("ABORT-REQUESTED")

                try:
                    GOEvent = self.eventQueue.get_nowait()
                    self.__go.debug(f"waitForThreads() got event, {GOEvent.eventType}, from eventQueue.")
                except queue.Empty:
                    # check if we're finished
                    if self.threadsFinished(log_status):
                        sleep(.1)
                        # but are we really?
                        if self.threadsFinished(log_status):
                            if final_passes < 1:
                                break
                            # Trigger module.finished()
                            for mod in self.__moduleInstances.values():
                                if not mod.errorState and mod.incomingEventQueue is not None:
                                    mod.incomingEventQueue.put('FINISHED')
                            sleep(.1)
                            while not self.threadsFinished(log_status):
                                log_status = counter % 100 == 0
                                counter += 1
                                sleep(.01)
                            final_passes -= 1

                    else:
                        # save on CPU
                        sleep(.1)
                    continue

                if not isinstance(GOEvent, GhostOsintEvent):
                    raise TypeError(f"GOEvent is {type(GOEvent)}; expected GhostOsintEvent")

                # for every module
                for mod in self.__moduleInstances.values():
                    # if it's been aborted
                    if mod._stopScanning:
                        # break out of the while loop
                        raise AssertionError(f"{mod.__name__} requested stop")

                    # send it the new event if applicable
                    if not mod.errorState and mod.incomingEventQueue is not None:
                        watchedEvents = mod.watchedEvents()
                        if GOEvent.eventType in watchedEvents or "*" in watchedEvents:
                            mod.incomingEventQueue.put(deepcopy(GOEvent))

        finally:
            # tell the modules to stop
            for mod in self.__moduleInstances.values():
                mod._stopScanning = True
            self.__sharedThreadPool.shutdown(wait=True)

    def threadsFinished(self, log_status=False):
        if self.eventQueue is None:
            return True

        modules_waiting = dict()
        for m in self.__moduleInstances.values():
            try:
                if m.incomingEventQueue is not None:
                    modules_waiting[m.__name__] = m.incomingEventQueue.qsize()
            except Exception:
                with suppress(Exception):
                    m.errorState = True
        modules_waiting = sorted(modules_waiting.items(), key=lambda x: x[-1], reverse=True)

        modules_running = []
        for m in self.__moduleInstances.values():
            try:
                if m.running:
                    modules_running.append(m.__name__)
            except Exception:
                with suppress(Exception):
                    m.errorState = True

        modules_errored = []
        for m in self.__moduleInstances.values():
            try:
                if m.errorState:
                    modules_errored.append(m.__name__)
            except Exception:
                with suppress(Exception):
                    m.errorState = True

        queues_empty = [qsize == 0 for m, qsize in modules_waiting]

        for mod in self.__moduleInstances.values():
            if mod.errorState and mod.incomingEventQueue is not None:
                self.__go.debug(f"Clearing and unsetting incomingEventQueue for errored module {mod.__name__}.")
                with suppress(Exception):
                    while 1:
                        mod.incomingEventQueue.get_nowait()
                mod.incomingEventQueue = None

        if not modules_running and not queues_empty:
            self.__go.debug("Clearing queues for stalled/aborted modules.")
            for mod in self.__moduleInstances.values():
                try:
                    while True:
                        mod.incomingEventQueue.get_nowait()
                except Exception:
                    pass

        if log_status:
            events_queued = ", ".join([f"{mod}: {qsize:,}" for mod, qsize in modules_waiting[:5] if qsize > 0])
            if not events_queued:
                events_queued = 'None'
            self.__go.debug(f"Events queued: {sum([m[-1] for m in modules_waiting]):,} ({events_queued})")
            if modules_running:
                self.__go.debug(f"Modules running: {len(modules_running):,} ({', '.join(modules_running)})")
            if modules_errored:
                self.__go.debug(f"Modules errored: {len(modules_errored):,} ({', '.join(modules_errored)})")

        if all(queues_empty) and not modules_running:
            return True
        return False

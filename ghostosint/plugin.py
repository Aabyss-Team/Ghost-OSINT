from contextlib import suppress
import io
import logging
import os
import queue
import sys
import threading
from time import sleep
import traceback

from .threadpool import GhostOsintThread

# begin logging overrides
# these are copied from the python logging module
# https://github.com/python/cpython/blob/main/Lib/logging/__init__.py

if hasattr(sys, 'frozen'):  # support for py2exe
    _srcfile = f"logging{os.sep}__init__{__file__[-4:]}"
elif __file__[-4:].lower() in ['.pyc', '.pyo']:
    _srcfile = __file__[:-4] + '.py'
else:
    _srcfile = __file__
_srcfile = os.path.normcase(_srcfile)


class GhostOsintPluginLog(logging.Logger):
    """Used only in GhostOsintPlugin to prevent modules
    from having to initialize their own loggers.

    Preserves filename, module, line numbers, etc. from the caller.
    """

    def findCaller(self, stack_info=False, stacklevel=1):
        """Find the stack frame of the caller so that we can note the source
        file name, line number and function name.

        Args:
            stack_info: boolean
            stacklevel: int

        Returns:
            rv: tuple, filename, line number, module name, and stack trace
        """
        f = logging.currentframe()
        # On some versions of IronPython, currentframe() returns None if
        # IronPython isn't run with -X:Frames.
        if f is not None:
            f = f.f_back
        orig_f = f
        while f and stacklevel > 1:
            f = f.f_back
            stacklevel -= 1
        if not f:
            f = orig_f
        rv = "(unknown file)", 0, "(unknown function)", None
        while hasattr(f, "f_code"):
            co = f.f_code
            filename = os.path.normcase(co.co_filename)
            if filename in (logging._srcfile, _srcfile):  # This is the only change
                f = f.f_back
                continue
            sinfo = None
            if stack_info:
                sio = io.StringIO()
                sio.write('Stack (most recent call last):\n')
                traceback.print_stack(f, file=sio)
                sinfo = sio.getvalue()
                if sinfo[-1] == '\n':
                    sinfo = sinfo[:-1]
                sio.close()
            rv = (co.co_filename, f.f_lineno, co.co_name, sinfo)
            break
        return rv  # noqa R504

# end of logging overrides


class GhostOsintPlugin():
    """GhostOsintPlugin module object

    Attributes:
        _stopScanning (bool): Will be set to True by the controller if the user aborts scanning
        listenerModules (list): Modules that will be notified when this module produces events
        _currentEvent (GhostOsintEvent): Current event being processed
        _currentTarget (str): Target currently being acted against
        _name_: Name of this module, set at startup time
        __GODB__: Direct handle to the database - not to be directly used
                  by modules except the GO__stor_db module.
        __scanId__: ID of the scan the module is running against
        __datasource__: (Unused) tracking of data sources
        __outputFilter: If set, events not matching this list are dropped
        _priority (int): Priority, smaller numbers should run first
        errorState (bool): error state of the module
        socksProxy (str): SOCKS proxy
    """

    # Will be set to True by the controller if the user aborts scanning
    _stopScanning = False
    # Modules that will be notified when this module produces events
    _listenerModules = list()
    # Current event being processed
    _currentEvent = None
    # Target currently being acted against
    _currentTarget = None
    # Name of this module, set at startup time
    __name__ = "module_name_not_set!"
    # Direct handle to the database - not to be directly used
    # by modules except the GO__stor_db module.
    __GODB__ = None
    # ID of the scan the module is running against
    __scanId__ = None
    # (only used in GhostOSINT HX) tracking of data sources
    __dataSource__ = None
    # If set, events not matching this list are dropped
    __outputFilter__ = None
    # Priority, smaller numbers should run first
    _priority = 1
    # Plugin meta information
    meta = None
    # Error state of the module
    errorState = False
    # SOCKS proxy
    socksProxy = None
    # Queue for incoming events
    incomingEventQueue = None
    # Queue for produced events
    outgoingEventQueue = None
    # GhostOSINT object, set in each module's setup() function
    GhostOsint = None
    # Configuration, set in each module's setup() function
    opts = dict()
    # Maximum thread
    maxThreads = 1

    def __init__(self):
        # Holds the thread object when module threading is enabled
        self.thread = None
        # logging overrides
        self._log = None
        # Shared thread pool for all modules
        self.sharedThreadPool = None

    @property
    def log(self):
        if self._log is None:
            logging.setLoggerClass(GhostOsintPluginLog)  # temporarily set logger class
            self._log = logging.getLogger(f"ghostosint.{self.__name__}")  # init GhostOsintPluginLog
            logging.setLoggerClass(logging.Logger)  # reset logger class to default
        return self._log

    def _updateSocket(self, socksProxy):
        """Hack to override module's use of socket, replacing it with
        one that uses the supplied SOCKS server.

        Args:
            socksProxy (str): SOCKS proxy
        """
        self.socksProxy = socksProxy

    def clearListeners(self):
        """Used to clear any listener relationships, etc. This is needed because
        Python seems to cache local variables even between threads."""

        self._listenerModules = list()
        self._stopScanning = False

    def setup(self, GhostOsint, userOpts={}):
        """Will always be overriden by the implementer.

        Args:
            GhostOsint (GhostOSINT): GhostOSINT object
            userOpts (dict): TBD
        """
        pass

    def debug(self, *args, **kwargs):
        """For logging.
        A wrapper around logging.debug() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.debug()
            *kwargs: passed through to logging.debug()
        """
        self.log.debug(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def info(self, *args, **kwargs):
        """For logging.
        A wrapper around logging.info() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.info()
            *kwargs: passed through to logging.info()
        """
        self.log.info(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def error(self, *args, **kwargs):
        """For logging.
        A wrapper around logging.error() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.error()
            *kwargs: passed through to logging.error()
        """
        self.log.error(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def enrichTarget(self, target):
        """Find aliases for a target.

        Note: rarely used in special cases

        Args:
            target (str): TBD
        """
        pass

    def setTarget(self, target):
        """Assigns the current target this module is acting against.

        Args:
            target (GhostOsintTarget): target

        Raises:
            TypeError: target argument was invalid type
        """
        from ghostosint import GhostOsintTarget

        if not isinstance(target, GhostOsintTarget):
            raise TypeError(f"target is {type(target)}; expected GhostOsintTarget")

        self._currentTarget = target

    def setDbh(self, dbh):
        """Used to set the database handle, which is only to be used
        by modules in very rare/exceptional cases (e.g. GO__stor_db)

        Args:
            dbh (GhostOsintDB): database handle
        """
        self.__GODB__ = dbh

    def setScanId(self, scanId):
        """Set the scan ID.

        Args:
            scanId (str): scan instance ID

        Raises:
            TypeError: scanId argument was invalid type
        """
        if not isinstance(scanId, str):
            raise TypeError(f"scanId is {type(scanId)}; expected str")

        self.__scanId__ = scanId

    def getScanId(self):
        """Get the scan ID.

        Returns:
            str: scan ID

        Raises:
            TypeError: Module called getScanId() but no scanId is set.
        """
        if not self.__scanId__:
            raise TypeError("Module called getScanId() but no scanId is set.")

        return self.__scanId__

    def getTarget(self):
        """Gets the current target this module is acting against.

        Returns:
            str: current target

        Raises:
            TypeError: Module called getTarget() but no target is set.
        """
        if not self._currentTarget:
            raise TypeError("Module called getTarget() but no target is set.")

        return self._currentTarget

    def registerListener(self, listener):
        """Listener modules which will get notified once we have data for them to
        work with.

        Args:
            listener: TBD
        """

        self._listenerModules.append(listener)

    def setOutputFilter(self, types):
        self.__outputFilter__ = types

    def tempStorage(self):
        """For future use. Module temporary storage.

        A dictionary used to persist state (in memory) for a module.

        Todo:
            Move all module state to use this, which then would enable a scan to be paused/resumed.

        Note:
            Required for GhostOSINT HX compatibility of modules.

        Returns:
            dict: module temporary state data
        """
        return dict()

    def notifyListeners(self, GOEvent):
        """Call the handleEvent() method of every other plug-in listening for
        events from this plug-in. Remember that those plug-ins will be called
        within the same execution context of this thread, not on their own.

        Args:
            GOEvent (GhostOsintEvent): event

        Raises:
            TypeError: GOEvent argument was invalid type
        """

        from ghostosint import GhostOsintEvent

        if not isinstance(GOEvent, GhostOsintEvent):
            raise TypeError(f"GOEvent is {type(GOEvent)}; expected GhostOsintEvent")

        eventName = GOEvent.eventType
        eventData = GOEvent.data

        if self.__outputFilter__:
            # Be strict about what events to pass on, unless they are
            # the ROOT event or the event type of the target.
            if eventName not in ('ROOT', self.getTarget().targetType):
                if eventName not in self.__outputFilter__:
                    return

        storeOnly = False  # Under some conditions, only store and don't notify

        if not eventData:
            return

        if self.checkForStop():
            return

        # Look back to ensure the original notification for an element
        # is what's linked to children. For instance, GO_dns may find
        # xyz.abc.com, and then GO_ripe obtains some raw data for the
        # same, and then GO_dns finds xyz.abc.com in there, we should
        # suppress the notification of that to other modules, as the
        # original xyz.abc.com notification from GO_dns will trigger
        # those modules anyway. This also avoids messy iterations that
        # traverse many many levels.

        # storeOnly is used in this case so that the source to dest
        # relationship is made, but no further events are triggered
        # from dest, as we are already operating on dest's original
        # notification from one of the upstream events.

        prevEvent = GOEvent.sourceEvent
        while prevEvent is not None:
            if prevEvent.sourceEvent is not None:
                if prevEvent.sourceEvent.eventType == GOEvent.eventType and prevEvent.sourceEvent.data.lower() == eventData.lower():
                    storeOnly = True
                    break
            prevEvent = prevEvent.sourceEvent

        # output to queue if applicable
        if self.outgoingEventQueue is not None:
            self.outgoingEventQueue.put(GOEvent)
        # otherwise, call other modules directly
        else:
            self._listenerModules.sort(key=lambda m: m._priority)

            for listener in self._listenerModules:
                if eventName not in listener.watchedEvents() and '*' not in listener.watchedEvents():
                    continue

                if storeOnly and "__stor" not in listener.__module__:
                    continue

                listener._currentEvent = GOEvent

                # Check if we've been asked to stop in the meantime, so that
                # notifications stop triggering module activity.
                if self.checkForStop():
                    return

                try:
                    listener.handleEvent(GOEvent)
                except Exception as e:
                    self.GhostOsint.error(f"Module ({listener.__module__}) encountered an error: {e}")
                    # set errorState
                    self.errorState = True
                    # clear incoming queue
                    if self.incomingEventQueue:
                        with suppress(queue.Empty):
                            while 1:
                                self.incomingEventQueue.get_nowait()

    def checkForStop(self):
        """For modules to use to check for when they should give back control.

        Returns:
            bool
        """
        # Stop if module is in error state.
        if self.errorState:
            return True

        # If threading is enabled, check the _stopScanning attribute instead.
        # This is to prevent each thread needing its own sqlite db handle.
        if self.outgoingEventQueue is not None and self.incomingEventQueue is not None:
            return self._stopScanning

        if not self.__scanId__:
            return False

        scanstatus = self.__GODB__.scanInstanceGet(self.__scanId__)

        if not scanstatus:
            return False

        if scanstatus[5] == "ABORT-REQUESTED":
            self._stopScanning = True
            return True

        return False

    @property
    def running(self):
        """Indicates whether the module is currently processing data.
        Modules that process data in pools/batches typically override this method.

        Returns:
            bool
        """
        return self.sharedThreadPool.countQueuedTasks(f"{self.__name__}_threadWorker") > 0

    def watchedEvents(self):
        """What events is this module interested in for input. The format is a list
        of event types that are applied to event types that this module wants to
        be notified of, or * if it wants everything.
        Will usually be overriden by the implementer, unless it is interested
        in all events (default behavior).

        Returns:
            list: list of events this modules watches
        """

        return ['*']

    def producedEvents(self):
        """What events this module produces
        This is to support the end user in selecting modules based on events
        produced.

        Returns:
            list: list of events produced by this module
        """

        return []

    def handleEvent(self, GOEvent):
        """Handle events to this module.
        Will usually be overriden by the implementer, unless it doesn't handle any events.

        Args:
            GOEvent (GhostOsintEvent): event
        """

        return

    def asdict(self):
        return {
            'name': self.meta.get('name'),
            'descr': self.meta.get('summary'),
            'cats': self.meta.get('categories', []),
            'group': self.meta.get('useCases', []),
            'labels': self.meta.get('flags', []),
            'provides': self.producedEvents(),
            'consumes': self.watchedEvents(),
            'meta': self.meta,
            'opts': self.opts,
            'optdescs': self.optdescs,
        }

    def start(self):
        self.thread = threading.Thread(target=self.threadWorker)
        self.thread.start()

    def finish(self):
        """Perform final/cleanup functions before module exits
        Note that this function may be called multiple times
        Overridden by the implementer
        """

        return

    def threadWorker(self):
        try:
            # create new database handle since we're in our own thread
            from ghostosint import GhostOsintDB
            self.setDbh(GhostOsintDB(self.opts))
            self.GhostOsint._dbh = self.__GODB__

            if not (self.incomingEventQueue and self.outgoingEventQueue):
                self.GhostOsint.error("Please set up queues before starting module as thread")
                return

            while not self.checkForStop():
                try:
                    GOEvent = self.incomingEventQueue.get_nowait()
                except queue.Empty:
                    sleep(.3)
                    continue
                if GOEvent == 'FINISHED':
                    self.GhostOsint.debug(f"{self.__name__}.threadWorker() got \"FINISHED\" from incomingEventQueue.")
                    self.poolExecute(self.finish)
                else:
                    self.GhostOsint.debug(f"{self.__name__}.threadWorker() got event, {GOEvent.eventType}, from incomingEventQueue.")
                    self.poolExecute(self.handleEvent, GOEvent)
        except KeyboardInterrupt:
            self.GhostOsint.debug(f"Interrupted module {self.__name__}.")
            self._stopScanning = True
        except Exception as e:
            import traceback
            self.GhostOsint.error(f"Exception ({e.__class__.__name__}) in module {self.__name__}."
                          + traceback.format_exc())
            # set errorState
            self.GhostOsint.debug(f"Setting errorState for module {self.__name__}.")
            self.errorState = True
            # clear incoming queue
            if self.incomingEventQueue:
                self.GhostOsint.debug(f"Emptying incomingEventQueue for module {self.__name__}.")
                with suppress(queue.Empty):
                    while 1:
                        self.incomingEventQueue.get_nowait()
                # set queue to None to prevent its use
                # if there are leftover objects in the queue, the scan will hang.
                self.incomingEventQueue = None

    def poolExecute(self, callback, *args, **kwargs):
        """Execute a callback with the given args.
        If we're in a storage module, execute normally.
        Otherwise, use the shared thread pool.

        Args:
            callback: function to call
            args: args (passed through to callback)
            kwargs: kwargs (passed through to callback)
        """
        if self.__name__.startswith('GO__stor_'):
            callback(*args, **kwargs)
        else:
            self.sharedThreadPool.submit(callback, *args, taskName=f"{self.__name__}_threadWorker", maxThreads=self.maxThreads, **kwargs)

    def threadPool(self, *args, **kwargs):
        return GhostOsintThread(*args, **kwargs)

    def setSharedThreadPool(self, sharedThreadPool):
        self.sharedThreadPool = sharedThreadPool

# end of GhostOsintPlugin class

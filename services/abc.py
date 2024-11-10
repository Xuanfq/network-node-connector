from abc import ABC, abstractmethod
from threading import Thread, Lock, Event
from threading import Thread
import importlib
import inspect
import time
import logging

logger = logging.getLogger(__name__)

# 
# Service ABC
# 
# Usage: Once start BaseDaemonService, 
#           it will find all the sub-base-service and start the it.
# 

class BaseService(ABC):
    def __init__(self) -> None:
        self._running_stop_event = Event()
        self._running_process = None
        self._running_lock = Lock()
        self._running = False

    @abstractmethod
    def run_main_loop(self) -> None:
        pass

    def run(self) -> None:
        self._running = True
        while not self._running_stop_event.is_set():
            self.run_main_loop()
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running_stop_event.clear()
        self._running_process = Thread(target=self.run)
        self._running_process.start()
        logger.info(f"{self.__class__.__name__} started")

    def stop(self):
        self._running_stop_event.set()

    def alive(self):
        return self._running


class BaseDaemonService(Thread):
    def __init__(self, appd_service_class: BaseService = BaseService):
        self.appd_service_class = appd_service_class
        self.appd_services = []
        self.appd_service_check_time = 30
        self.stop_flag = False
        super().__init__()

    def find_app_service(self, base_class, submodule_name="services"):
        subclasses = []
        appnames = [
            appstr.split(".")[0]
            for appstr in importlib.import_module("config").ULAB_APPS
        ]
        for appname in appnames:
            try:
                submodule = importlib.import_module(
                    f"{appname}.{submodule_name}")
                for _, cls in inspect.getmembers(submodule, inspect.isclass):
                    if issubclass(cls, base_class) and cls is not base_class:
                        # Check if the class has a custom flag or uses the abstract method
                        if hasattr(cls, "__is_abstract") and not getattr(
                            cls, "__is_abstract"
                        ):
                            subclasses.append(cls)
                        elif not inspect.isabstract(cls):
                            subclasses.append(cls)
            except Exception as e:
                pass
        return subclasses

    def run(self):
        appd_service_cls = self.find_app_service(self.appd_service_class)
        self.appd_services = [subcls() for subcls in appd_service_cls]
        for service in self.appd_services:
            service.start()
        while True:
            alive = 0
            for service in self.appd_services:
                if service.alive():
                    alive += 1
                    msg = f"Appd {service} is running."
                else:
                    msg = f"Appd {service} is not running."
                logger.info(msg)
            if self.stop_flag and alive == 0:
                break
            time.sleep(self.appd_service_check_time)
        logger.info("\n- Stopped Appd Service")

    def start(self):
        logger.info("\n- Start Appd as Appd Service")
        return super().start()

    def stop(self):
        logger.info("\n- Stopping Appd Service...")
        for service in self.appd_services:
            service.stop()
        self.stop_flag = True

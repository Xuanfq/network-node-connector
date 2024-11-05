from threading import Thread, Lock
import socket
import random
import logging

logger = logging.getLogger(__name__)


class PortPool:
    """PortPool: 
    
    A thread safe pool of ports, maybe the port in range will be occupied by other programs.
    """

    def __init__(self, min_port, max_port) -> None:
        self._min_port = min_port
        self._max_port = max_port
        self._used_ports = set()
        self._used_ports_lock = Lock()

    def _generate_port(self):
        return random.randint(self._min_port, self._max_port)

    def _is_available(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return True
            except socket.error:
                return False

    def clear(self):
        with self._used_ports_lock:
            for port in self._used_ports.copy():
                if not self._is_available(port):
                    self._used_ports.remove(port)

    def allocate(self):
        available_number = self._max_port - self._min_port + 1 - len(self._used_ports)
        if available_number == 0:
            # clear not available
            self.clear()
        while True:
            port = self._generate_port()
            with self._used_ports_lock:
                if port not in self._used_ports and self._is_available(port):
                    self._used_ports.add(port)
                    return port

    def release(self, port):
        with self._used_ports_lock:
            if port in self._used_ports:
                self._used_ports.remove(port)


class KeepPortPool:
    """KeepPortPool: 
    
    A thread safe pool of ports that the port added will not be occupied by other programs.
    """

    def __init__(self) -> None:
        self._pool = {}
        self._pool_lock = Lock()

    def _keep_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            self._pool[port] = s
            return True
        except socket.error:
            return False

    def _unkeep_port(self, port):
        if port in self._pool:
            try:
                self._pool[port].close()
            except Exception as e:
                pass
        return True

    def add(self, port):
        with self._pool_lock:
            if self._keep_port(port):
                return True
            return False

    def allocate(self, port):
        with self._pool_lock:
            if port not in self._pool:
                return False
            return self._unkeep_port(port)

    def release(self, port):
        with self._pool_lock:
            if port in self._pool:
                return True
            return self._keep_port(port)

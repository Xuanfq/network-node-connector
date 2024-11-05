from threading import Condition, Lock


class ReadWriteLock:
    """A read-write lock class that allows multiple readers or one writer."""

    def __init__(self):
        self._read_ready = Condition(Lock())
        self._readers = 0
        self._writer = False

    def acquire_read(self):
        """Acquire a read lock. Multiple threads can hold this type of lock."""
        with self._read_ready:
            while self._writer:
                self._read_ready.wait()
            self._readers += 1

    def release_read(self):
        """Release a read lock."""
        with self._read_ready:
            self._readers -= 1
            if not self._readers:
                self._read_ready.notify_all()

    def acquire_write(self):
        """Acquire a write lock. Only one thread can hold this lock, and no readers can be active."""
        with self._read_ready:
            while self._readers > 0 or self._writer:
                self._read_ready.wait()
            self._writer = True

    def release_write(self):
        """Release a write lock."""
        with self._read_ready:
            self._writer = False
            self._read_ready.notify_all()

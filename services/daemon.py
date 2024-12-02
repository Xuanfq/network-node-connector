import os
import sys
import time
import atexit
import signal
from pathlib import Path


TMP_STD_IN = "/dev/null"
TMP_STD_OUT = "/tmp/nnc/daemon.stdout"
TMP_STD_ERR = "/tmp/nnc/daemon.stderr"


class Daemon:
    def __init__(
        self,
        pidfile,
        stdin=TMP_STD_IN,
        stdout=TMP_STD_OUT,
        stderr=TMP_STD_ERR,
        name="daemon",
        *args,
        **kwargs,
    ):
        """
        Initialize the daemon with file paths for standard input, output, and error, as well as the PID file.
        """
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.pid = None
        self.name = name
        try:
            os.makedirs(Path(self.stdout).parent)
            os.makedirs(Path(self.stderr).parent)
            os.makedirs(Path(self.pidfile).parent)
        except:
            pass

    def daemonize(self):
        """
        Create a daemon process.
        """
        try:
            pid = os.fork()
            if pid > 0:
                # First parent process exits
                os._exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #1 failed: {e}\n")
            sys.exit(1)

        # Child process continues
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # try:
        #     pid = os.fork()
        #     if pid > 0:
        #         # Second parent process exits
        #         os._exit(0)
        # except OSError as e:
        #     sys.stderr.write(f"Fork #2 failed: {e}\n")
        #     sys.exit(1)
        
        # Redirect standard file descriptors
        with open(self.stdin, "r") as si:
            os.dup2(si.fileno(), sys.stdin.fileno())
        with open(self.stdout, "a+") as so:
            os.dup2(so.fileno(), sys.stdout.fileno())
        with open(self.stderr, "a+") as se:
            os.dup2(se.fileno(), sys.stderr.fileno())

        # Register exit handler to remove PID file
        atexit.register(self.delpid)

        # Write the current process ID to the PID file
        pid = str(os.getpid())
        with open(self.pidfile, "w+") as f:
            f.write(f"{pid}\n")

        self.pid = pid

    def delpid(self):
        """
        Remove the PID file.
        """
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon.
        """
        if self.is_running():
            print(f"{self.name} is already running.")
            return

        # Create the daemon process
        self.daemonize()
        self.run()

    def stop(self):
        """
        Stop the daemon.
        """
        if not self.is_running():
            print(f"{self.name} not running.")
            return

        try:
            with open(self.pidfile, "r") as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None

        if not pid:
            print(f"{self.name} not running.")
            return

        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print(str(err))
                sys.exit(1)

    def restart(self):
        """
        Restart the daemon.
        """
        self.stop()
        self.start()

    def is_running(self):
        """
        Check if the daemon is running.
        """
        if not os.path.exists(self.pidfile):
            return False

        try:
            with open(self.pidfile, "r") as pf:
                pid = int(pf.read().strip())
        except IOError:
            return False

        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True

    def status(self):
        """
        Check the status of the daemon.
        """
        if self.is_running():
            print("status: running")
        else:
            print("status: not running")

    def run(self):
        """
        Subclasses should override this method to implement the specific task logic.
        """
        print(f"{self.name} is running...")
        while True:
            time.sleep(1)

    def main(self):
        """
        Main entry point for the script.
        """
        if len(sys.argv) < 2:
            print(f"Usage: python3 {__file__} [start|stop|restart|status]")
            sys.exit(1)

        action = sys.argv[1].lower()
        if action == "start":
            self.start()
        elif action == "stop":
            self.stop()
        elif action == "restart":
            self.restart()
        elif action == "status":
            self.status()
        else:
            print("Invalid action. Use 'start', 'stop', 'restart', or 'status'.")


if __name__ == "__main__":
    daemon = Daemon("/tmp/nnc/daemon.pid")
    daemon.main()

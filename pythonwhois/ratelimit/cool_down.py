import thread
import threading
import time

cool_down_start = 1.0
cool_down_time = 0.5


def decrement_thread(cool_down_object):
    """
    After sleeping for cool_down_time, decrement
    all cool downs with cool_down_time
    :param cool_down_object:
    :return:
    """
    while True:
        time.sleep(cool_down_time)
        cool_down_object.decrement_cool_downs()


class CoolDown:
    """
    Handle the cooldown period for asking a WHOIS server again
    """

    def __init__(self):
        """
        Creates a dictionary for storing cool downs and starts
        a thread for decrementing the cool down values
        """
        self.lock = threading.Lock()
        self.servers_on_cool_down = {}
        thread.start_new_thread(decrement_thread, (self,))

    def can_use_server(self, whois_server):
        """
        Check whether a server can be used again
        :param whois_server: The WHOIS server to check
        :return: True if the server can be used, False if not
        """
        with self.lock:
            cooldown = self.servers_on_cool_down.get(whois_server)
        return cooldown is None or cooldown <= 0

    def use_server(self, whois_server):
        """
        Tell the CoolDown instance that a WHOIS server is going to be used.
        The cool down will then be reset
        :param whois_server: The WHOIS server that is going to be used
        """
        with self.lock:
            self.servers_on_cool_down[whois_server] = cool_down_start

    def decrement_cool_downs(self):
        """
        Decrement all the cool downs with cool_down_time
        """
        with self.lock:
            for server, cool_down in self.servers_on_cool_down.iteritems():
                self.servers_on_cool_down[server] = cool_down - cool_down_time

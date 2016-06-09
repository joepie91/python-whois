import thread
import threading
import time

default_cool_down = 10
cool_down_time = 1


def decrement_thread(cool_down_object):
    while True:
        time.sleep(cool_down_time)
        cool_down_object.decrement_cool_downs()


class CoolDown:
    def __init__(self):
        self.lock = threading.Lock()
        self.servers_on_cool_down = {}
        thread.start_new_thread(decrement_thread, (self,))

    def can_use_server(self, whois_server):
        with self.lock:
            cooldown = self.servers_on_cool_down.get(whois_server)
        return cooldown is None or cooldown <= 0

    def use_server(self, whois_server):
        with self.lock:
            self.servers_on_cool_down[whois_server] = default_cool_down
        print self.servers_on_cool_down

    def decrement_cool_downs(self):
        with self.lock:
            for server, cool_down in self.servers_on_cool_down.iteritems():
                self.servers_on_cool_down[server] = cool_down - cool_down_time

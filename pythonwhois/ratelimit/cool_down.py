import ConfigParser
import thread
import threading
import time

default_cool_down_length = 1.0
cool_down_period = 0.5


def decrement_thread(cool_down_object):
    """
    After sleeping for cool_down_time, decrement
    all cool downs with cool_down_time
    :param cool_down_object:
    :return:
    """
    while True:
        time.sleep(cool_down_period)
        cool_down_object.decrement_cool_downs()


class CoolDown:
    """
    Handle the cooldown period for asking a WHOIS server again
    """

    def __init__(self):
        """
        Creates a dictionary for storing cool downs.
        """
        self.lock = threading.Lock()
        self.servers_on_cool_down = {}

    def start(self):
        """
        Start a thread decrementing all the cool down values.
        """
        thread.start_new_thread(decrement_thread, (self,))

    def can_use_server(self, whois_server):
        """
        Check whether a server can be used again
        :param whois_server: The WHOIS server to check
        :return: True if the server can be used, False if not
        """
        with self.lock:
            cooldown = self.servers_on_cool_down.get(whois_server)
        return cooldown is None or cooldown.current_cool_down <= 0

    def use_server(self, whois_server):
        """
        Tell the CoolDown instance that a WHOIS server is going to be used.
        The cool down will then be reset
        :param whois_server: The WHOIS server that is going to be used
        """
        with self.lock:
            if whois_server not in self.servers_on_cool_down:
                self.servers_on_cool_down[whois_server] = CoolDownTracker(default_cool_down_length)
            self.servers_on_cool_down[whois_server].use()

    def decrement_cool_downs(self):
        """
        Decrement all the cool downs with cool_down_time
        """
        with self.lock:
            for server, cool_down in self.servers_on_cool_down.iteritems():
                self.servers_on_cool_down[server].decrement_cooldown(cool_down_period)

    def set_cool_down_config(self, path_to_file):
        """
        Tell the CoolDown instance of a configuration file, describing specific settings
        for certain WHOIS servers. This configuration will
        then be read and inserted into the cool down dictionary.
        :param path_to_file: The path to the configuration file
        """
        config = ConfigParser.ConfigParser()
        config.read(path_to_file)
        for domain in config.sections():
            cool_down_length = self.get_from_config(config, domain, "cool_down_length", default_cool_down_length)
            max_requests_minute = self.get_from_config(config, domain, "max_requests_minute")
            max_requests_hour = self.get_from_config(config, domain, "max_requests_hour")
            max_requests_day = self.get_from_config(config, domain, "max_requests_day")
            with self.lock:
                self.servers_on_cool_down[domain] = CoolDownTracker(cool_down_length,
                                                                    max_requests_minute,
                                                                    max_requests_hour,
                                                                    max_requests_day)

    def get_from_config(self, config, section, key, default=None):
        """
        Get a value from the config if it exists, otherwise return the default value
        :param config: The configuration to get the value from
        :param section: The section to get the value from
        :param key: The key that may or may not exist
        :param default: The default value to return, which is None by default
        :return: The value if it exists, else default
        """
        if config.has_option(section, key):
            return config.getfloat(section, key)
        else:
            return default


class CoolDownTracker:
    """
    Keep track of cool down settings for a specific WHOIS server
    """

    def __init__(self, cool_down_length, max_requests_minute=None, max_requests_hour=None, max_requests_day=None):
        """
        Create a tracker. It can accept three maximums. When a maximum is reached, it will wait a set amount of time
        before trying again, which is a minute, hour and day respectively.
        :param cool_down_length: The default length of the cool down
        :param max_requests_minute: The maximum number of requests per minute.
        :param max_requests_hour: The maximum number of requests per hour
        :param max_requests_day: The maximum number of request per day
        """
        self.cool_down_length = cool_down_length
        self.max_requests_minute = max_requests_minute
        self.max_requests_hour = max_requests_hour
        self.max_requests_day = max_requests_day

        self.request_count = 0
        self.current_cool_down = 0

    def use(self):
        """
        Tell the tracker that the corresponding server is going to be used.
        It will set the cool down, based on the amount of requests that already have been made
        """
        self.request_count += 1
        if self.max_requests_reached(self.max_requests_minute):
            self.current_cool_down = 60
        elif self.max_requests_reached(self.max_requests_hour):
            self.current_cool_down = 3600
        elif self.max_requests_reached(self.max_requests_day):
            self.current_cool_down = 86400
        else:
            self.current_cool_down = self.cool_down_length

    def decrement_cooldown(self, decrement):
        """
        Decrement the current cooldown with the given value, implying
        that a given time has passed.
        :param decrement: The value to decrement the current cool down value with
        """
        self.current_cool_down -= decrement

    def max_requests_reached(self, limit):
        """
        Check whether the maximum has been reached for a given limit.
        :param limit: The limit that should be checked for
        :return: True if the limit has been reached, false if not
        """
        return limit is not None and self.request_count % limit == 0

import ConfigParser
import thread
import threading
import time

from pythonwhois.ratelimit.cool_down_tracker import CoolDownTracker


def decrement_thread(cool_down_object):
    """
    After sleeping for cool_down_time, decrement
    all cool downs with cool_down_time
    :param cool_down_object: An instance of CoolDown
    """
    while True:
        time.sleep(cool_down_object.cool_down_period)
        cool_down_object.decrement_cool_downs()


def get_float_from_config(config, section, key, default=None):
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


class CoolDown:
    """
    Handle the cool down period for asking a WHOIS server again
    """

    def __init__(self):
        """
        Creates a dictionary for storing cool downs and starts
        a new thread to decrement them every time after a set period
        of time has passed, which is 0.5 seconds by default.
        """
        self.lock = threading.Lock()
        self.servers_on_cool_down = {}
        self.default_cool_down_length = 1.0
        self.cool_down_period = 0.5
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
                self.servers_on_cool_down[whois_server] = CoolDownTracker(self.default_cool_down_length)
            self.servers_on_cool_down[whois_server].use()

    def decrement_cool_downs(self):
        """
        Decrement all the cool downs with cool_down_time
        """
        with self.lock:
            for server, cool_down in self.servers_on_cool_down.iteritems():
                self.servers_on_cool_down[server].decrement_cool_down(self.cool_down_period)

    def set_cool_down_config(self, path_to_file):
        """
        Tell the CoolDown instance of a configuration file, describing specific settings
        for certain WHOIS servers. This configuration will then be read and inserted into
        the cool down dictionary.
        If the configuration contains a general section, this will be consumed and removed from the config instance
        (not the file). This is done to keep all the configuration in one file, but to be able to easily loop
        over all the WHOIS server sections.
        :param path_to_file: The path to the configuration file
        """
        config = ConfigParser.ConfigParser()
        config.read(path_to_file)
        config = self.consume_defaults_from_config(config)
        self.apply_cool_down_config(config)

    def apply_cool_down_config(self, config):
        """
        Read all the WHOIS server sections from the configuration and build
        CoolDownTracker objects for them containing the read information.
        These CoolDownTracker instances are then placed in servers_on_cool_down.
        :param config: A configuration file with only WHOIS server sections
        """
        for whois_server in config.sections():
            cool_down_length = get_float_from_config(config, whois_server, "cool_down_length",
                                                     self.default_cool_down_length)
            max_requests_minute = get_float_from_config(config, whois_server, "max_requests_minute")
            max_requests_hour = get_float_from_config(config, whois_server, "max_requests_hour")
            max_requests_day = get_float_from_config(config, whois_server, "max_requests_day")
            with self.lock:
                self.servers_on_cool_down[whois_server] = CoolDownTracker(cool_down_length,
                                                                          max_requests_minute,
                                                                          max_requests_hour,
                                                                          max_requests_day)

    def consume_defaults_from_config(self, config):
        """
        Gets the general settings from the config. Then removes them
        and returns the modified config.
        :param config: The config to obtain the default values from
        :return: The modified config, without the 'general' section
        """
        if config.has_section("general"):
            self.default_cool_down_length = get_float_from_config(config, "general", "default_cool_down_length",
                                                                  self.default_cool_down_length)
            self.cool_down_period = get_float_from_config(config, "general", "cool_down_period", self.cool_down_period)
            config.remove_section("general")

        return config

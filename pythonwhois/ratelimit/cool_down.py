import datetime

from pythonwhois.ratelimit.cool_down_config import CoolDownConfig
from pythonwhois.ratelimit.cool_down_tracker import CoolDownTracker


class CoolDown:
    """
    Handle the cool down period for asking a WHOIS server again
    """

    def __init__(self):
        """
        Creates a dictionary for storing cool downs.
        """
        self.servers_on_cool_down = {}
        self.default_cool_down_seconds = 2.0
        self.last_request_time = datetime.datetime.now()

    def can_use_server(self, whois_server):
        """
        Check whether a server can be used again
        :param whois_server: The WHOIS server to check
        :return: True if the server can be used, False if not
        """
        cool_down = self.servers_on_cool_down.get(whois_server)
        return cool_down is None or cool_down.current_cool_down <= 0

    def try_to_use_server(self, whois_server):
        """
        Try to use a WHOIS server. On True, it was a success and the cool down has been reset.
        On False, the server was not available yet
        :param whois_server: The WHOIS server that is going to be used
        :return True if the server was successfully marked as used and the cool down has been reset,
        False if the server was not yet available
        """
        self.decrement_cool_downs()
        if not self.can_use_server(whois_server):
            return False

        if whois_server not in self.servers_on_cool_down:
            self.servers_on_cool_down[whois_server] = CoolDownTracker(self.default_cool_down_seconds)
        self.servers_on_cool_down[whois_server].use_whois_server()
        return True

    def decrement_cool_downs(self):
        """
        Decrement all the cool downs with cool_down_time
        """
        time_diff = self.get_time_difference()
        for server, cool_down_tracker in self.servers_on_cool_down.iteritems():
            cool_down_tracker.decrement_cool_down(time_diff)

    def warn_limit_exceeded(self, whois_server):
        """
        Warn the CoolDown instance of an exceeded limit for a WHOIS server.
        The CoolDown instance will then make sure that the cool down for the WHOIS server
        will be longer next time
        :param whois_server: The WHOIS server the limit has been exceeded for
        """
        self.servers_on_cool_down[whois_server].double_cool_down()

    def get_time_difference(self):
        """
        Get the difference in time between te last time this was called
        and now.
        :return: The difference in seconds
        """
        now = datetime.datetime.now()
        diff = now - self.last_request_time
        self.last_request_time = now
        return diff.total_seconds()

    def set_cool_down_config(self, path_to_file):
        """
        Tell the CoolDown instance of a configuration file, describing specific settings
        for certain WHOIS servers. This configuration will then be read and inserted into
        the cool down dictionary.
        :param path_to_file: The path to the configuration file
        """
        cool_down_config = CoolDownConfig(path_to_file, self.default_cool_down_seconds)
        for whois_server in cool_down_config.get_sections():
            self.servers_on_cool_down[whois_server] = cool_down_config.get_cool_down_tracker_for_server(whois_server)

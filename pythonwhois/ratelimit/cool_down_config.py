import ConfigParser

from pythonwhois.ratelimit.cool_down_tracker import CoolDownTracker


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


class CoolDownConfig:
    """
    Read and handle the contents of a configuration file for the cool down process.
    """

    def __init__(self, path_to_file, default_cool_down):
        """
        Read the configuration file.
        If the configuration contains a general section, this will be consumed and removed from the config instance
        (not the file). This is done to keep all the configuration in one file, but to be able to easily loop
        over all the WHOIS server sections.
        :param path_to_file: The path to the configuration file
        :param default_cool_down: The default value for the cool down length, in case it is not defined in the config
        """
        self.config = ConfigParser.ConfigParser()
        self.config.read(path_to_file)

        self.cool_down_length = default_cool_down
        self.config = self.consume_defaults_from_config(self.config)

    def consume_defaults_from_config(self, config):
        """
        Gets the general settings from the config. Then removes them
        and returns the modified config.
        :param config: The config to obtain the default values from
        :return: The modified config, without the 'general' section
        """
        if config.has_section("general"):
            self.cool_down_length = get_float_from_config(config, "general", "default_cool_down_length")
            config.remove_section("general")
        return config

    def get_sections(self):
        """
        Return a list of sections
        :return: A list of sections
        """
        return self.config.sections()

    def get_cool_down_tracker_for_server(self, whois_server):
        """
        Create a new CoolDownTracker instance based on the contents of the configuration file.
        If the configuration file does not have settings for this WHOIS server, a default CoolDownTracker with
        the cool down length is returned.
        :param whois_server: The WHOIS server to build a CoolDownTracker for
        :return: A CoolDownTracker instance based on the settings
        """
        if self.config.has_section(whois_server):
            cool_down_length = get_float_from_config(self.config, whois_server, "cool_down_length",
                                                     self.cool_down_length)
            max_requests_minute = get_float_from_config(self.config, whois_server, "max_requests_minute")
            max_requests_hour = get_float_from_config(self.config, whois_server, "max_requests_hour")
            max_requests_day = get_float_from_config(self.config, whois_server, "max_requests_day")
            return CoolDownTracker(cool_down_length,
                                   max_requests_minute,
                                   max_requests_hour,
                                   max_requests_day)

        return CoolDownTracker(self.cool_down_length)

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

    def use_whois_server(self):
        """
        Tell the tracker that the corresponding server is going to be used.
        It will set the cool down, based on the amount of requests that already have been made
        """
        self.request_count += 1
        self.start_cool_down()

    def start_cool_down(self):
        """
        Start a new cool_down
        """
        time_passed = self.cool_down_length - self.current_cool_down
        if time_passed < 86400 and self.max_requests_reached(self.max_requests_day):
            self.current_cool_down = 86400
        elif time_passed < 3600 and self.max_requests_reached(self.max_requests_hour):
            self.current_cool_down = 3600
        elif time_passed < 60 and self.max_requests_reached(self.max_requests_minute):
            self.current_cool_down = 60
        else:
            self.current_cool_down = self.cool_down_length

    def decrement_cool_down(self, seconds):
        """
        Decrement the current cooldown with the given value, implying
        that a given time has passed.
        :param seconds: The seconds to decrement the current cool down value with
        """
        self.current_cool_down -= seconds

    def max_requests_reached(self, limit):
        """
        Check whether the maximum has been reached for a given limit.
        :param limit: The limit that should be checked for
        :return: True if the limit has been reached, false if not
        """
        return limit is not None and self.request_count % limit == 0

    def increase_cool_down(self):
        """
        Increase the cool down length, as in, the cool down length that is always used,
        not the current cool down that happening.
        The cool down length is multiplied by 1.5
        """
        self.cool_down_length *= 1.5
        self.start_cool_down()

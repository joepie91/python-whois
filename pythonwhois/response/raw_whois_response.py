class RawWhoisResponse:
    """
    Holder class for WHOIS responses. Is capable of marking the retrieval as a failure.
    """

    def __init__(self, response="", request_failure=False, still_in_cool_down=False, server_is_dead=False):
        """
        Hold the WHOIS response
        :param response: The received response, if any
        :param request_failure: If the request was a failure
        :param still_in_cool_down: Whether the server was unavailable due to a cool down or not
        """
        self.response = response
        self.request_failure = request_failure
        self.still_in_cool_down = still_in_cool_down
        self.server_is_dead = server_is_dead

        if len(response) > 0:
            self.request_failure = self.check_for_exceeded_limit()

    def check_for_exceeded_limit(self):
        """
        Check whether the limit has been exceeded. This is done by
        looking at the size of the response. If it has less than 4 lines,
        it is probably not a useful response and most likely a message about spamming
        the WHOIS server
        :return: True if the message is really short, false if not
        """
        return self.response is not None and len(self.response.splitlines()) < 4

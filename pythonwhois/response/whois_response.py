class WhoisResponse:
    """
    Holder class for WHOIS responses. Is capable of marking the retrieval as a failure.
    """

    def __init__(self, response=None, request_failure=False, cool_down_failure=False, server_is_dead=False):
        """
        Hold the WHOIS response
        :param response: The received response, if any
        :param request_failure: If the request was a failure
        :param cool_down_failure: Whether the server was unavailable due to a cool down or not
        """
        self.response = response
        self.request_failure = request_failure
        self.cool_down_failure = cool_down_failure
        self.server_is_dead = server_is_dead

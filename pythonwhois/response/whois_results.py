class WhoisResult:
    """
    Holder class for the final results. This includes all the retrieved WHOIS responses,
    whether this is the complete list of responses available and whether there is a WHOIS
    server available at all.
    """

    def __init__(self, responses, complete=True, whois_server_available=True, server_list=None):
        self.responses = responses
        self.complete = complete
        self.whois_server_available = whois_server_available
        self.server_list = server_list

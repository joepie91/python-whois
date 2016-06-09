import ast
import os

cache_file_name = "pythonwhois/caching/whois_server.cache"


def read_cache():
    if os.path.isfile(cache_file_name):
        return ast.literal_eval(open(cache_file_name).read())

    return {}


def write_cache(cache):
    cache_file = open(cache_file_name, 'w')
    cache_file.write(str(cache))


class WhoisServerCache:
    """
    Cache handler for easy of use. Do not instantiate. import server_cache instead.
    Otherwise an inconsistent cache can happen as a result of multiple caches.
    """

    def __init__(self):
        self.cache = read_cache()

    def get_server(self, tld):
        """
        Get a WHOIS server for a given TLD
        :param tld: The TLD to get the WHOIS server for
        :return: The WHOIS server if it is known, or None otherwise
        """
        return self.cache.get(tld)

    def put_server(self, tld, whois_server):
        """
        Store a new WHOIS server in the cache. The cache is then also
        written to disk again. Because the WHOIS servers don't change that often,
        it simply writes to a file.
        :param tld: The TLD to store a WHOIS server for
        :param whois_server: The WHOIS server to store
        """
        self.cache[tld] = whois_server
        write_cache(self.cache)


server_cache = WhoisServerCache()

import ast
import os


def read_cache(file_path):
    if os.path.isfile(file_path):
        return ast.literal_eval(open(file_path).read())
    else:
        if os.path.dirname(file_path):
            os.makedirs(os.path.dirname(file_path))
        return {}


def write_cache(cache, file_path):
    cache_file = open(file_path, 'w')
    cache_file.write(str(cache))


class WhoisServerCache:
    """
    Cache handler for easy of use. Do not instantiate. import server_cache instead.
    Otherwise an inconsistent cache can happen as a result of multiple caches.
    """

    def __init__(self):
        self.cache = {}
        self.persistent = False
        self.file_path = None

    def get_server(self, tld):
        """
        Get a WHOIS server for a given TLD
        :param tld: The TLD to get the WHOIS server for
        :return: The WHOIS server if it is known, or None otherwise
        """
        return self.cache.get(tld)

    def put_server(self, tld, whois_server):
        """
        Store a new WHOIS server in the cache. If the cache is persistent,
        it is also written to disk again. Because the WHOIS servers
        don't change that often, it simply writes to a file.
        :param tld: The TLD to store a WHOIS server for
        :param whois_server: The WHOIS server to store
        """
        self.cache[tld] = whois_server
        if self.persistent:
            write_cache(self.cache, self.file_path)

    def set_persistent_location(self, file_path):
        """
        Store the cache in a persistent location
        :param file_path: The path to store the cache
        """
        self.file_path = file_path
        self.cache = read_cache(file_path)
        self.persistent = True


server_cache = WhoisServerCache()

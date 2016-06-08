import ast
import os

cache_file_name = "pythonwhois/whois_server_cache.dat"


def read_cache():
    if os.path.isfile(cache_file_name):
        return ast.literal_eval(open(cache_file_name).read())

    return {}


def write_cache(cache):
    cache_file = open(cache_file_name, 'w')
    cache_file.write(str(cache))


class WhoisServerCache:
    def __init__(self):
        self.cache = read_cache()

    def getServer(self, tld):
        return self.cache.get(tld)

    def putServer(self, tld, whois_server):
        self.cache[tld] = whois_server
        write_cache(self.cache)

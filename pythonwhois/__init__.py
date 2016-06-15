from . import net, parse


def get_whois(domain, normalized=[]):
    raw_data, server_list = net.get_whois_raw(domain, with_server_list=True)
    # Unlisted handles will be looked up on the last WHOIS server that was queried. This may be changed to also query
    # other servers in the future, if it turns out that there are cases where the last WHOIS server in the chain doesn't
    # actually hold the handle contact details, but another WHOIS server in the chain does.
    if len(server_list) > 0:
        handle_server = server_list[-1]
    else:
        handle_server = ""
    return parse.parse_raw_whois(raw_data, normalized=normalized, never_query_handles=False,
                                 handle_server=handle_server)


def set_persistent_cache(path_to_cache):
    """
    Set a persistent cache. If the file does not yet exist, it is created.
    :param path_to_cache: The place where the cache is stored or needs to be created
    """
    net.server_cache.set_persistent_location(path_to_cache)


def set_cool_down_config(path_to_config):
    """
    Set a cool down configuration file, describing specific settings for certain WHOIS servers.
    :param path_to_config: The path to the configuration file, this needs to exist
    """
    net.cool_down_tracker.set_cool_down_config(path_to_config)

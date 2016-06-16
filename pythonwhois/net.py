import os
import re
import socket
import subprocess
import sys
from codecs import encode, decode

from pythonwhois.caching.whois_server_cache import server_cache
from pythonwhois.ratelimit.cool_down import CoolDown
from pythonwhois.response.raw_whois_response import RawWhoisResponse

incomplete_result_message = "THE_WHOIS_ORACLE_INCOMPLETE_RESULT"

cool_down_tracker = CoolDown()

# Sometimes IANA simply won't give us the right root WHOIS server
exceptions = {
    ".ac.uk": "whois.ja.net",
    ".ps": "whois.pnina.ps",
    ".buzz": "whois.nic.buzz",
    ".moe": "whois.nic.moe",
    ".arpa": "whois.iana.org",
    ".bid": "whois.nic.bid",
    ".int": "whois.iana.org",
    ".kred": "whois.nic.kred",
    ".nagoya": "whois.gmoregistry.net",
    ".nyc": "whois.nic.nyc",
    ".okinawa": "whois.gmoregistry.net",
    ".qpon": "whois.nic.qpon",
    ".sohu": "whois.gtld.knet.cn",
    ".tokyo": "whois.nic.tokyo",
    ".trade": "whois.nic.trade",
    ".webcam": "whois.nic.webcam",
    ".xn--rhqv96g": "whois.nic.xn--rhqv96g",
    # The following is a bit hacky, but IANA won't return the right answer for example.com because it's a direct registration.
    "example.com": "whois.verisign-grs.com"
}


def get_whois_raw(domain, server="", previous=None, rfc3490=True, never_cut=False, with_server_list=False,
                  server_list=None):
    previous = previous or []
    server_list = server_list or []

    if rfc3490:
        if sys.version_info < (3, 0):
            domain = encode(domain if type(domain) is unicode else decode(domain, "utf8"), "idna")
        else:
            domain = encode(domain, "idna").decode("ascii")

    target_server = get_target_server(domain, previous, server)
    query = prepare_query(target_server, domain)
    whois_response = query_server(target_server, query)
    response = whois_response.response

    if never_cut:
        # If the caller has requested to 'never cut' responses, he will get the original response from the server (this is
        # useful for callers that are only interested in the raw data). Otherwise, if the target is verisign-grs, we will
        # select the data relevant to the requested domain, and discard the rest, so that in a multiple-option response the
        # parsing code will only touch the information relevant to the requested domain. The side-effect of this is that
        # when `never_cut` is set to False, any verisign-grs responses in the raw data will be missing header, footer, and
        # alternative domain options (this is handled a few lines below, after the verisign-grs processing).
        new_list = [response] + previous
    if target_server == "whois.verisign-grs.com":
        # VeriSign is a little... special. As it may return multiple full records and there's no way to do an exact query,
        # we need to actually find the correct record in the list.
        for record in response.split("\n\n"):
            if re.search("Domain Name: %s\n" % domain.upper(), record):
                response = record
                break
    if not never_cut:
        new_list = [response] + previous

    if whois_response.server_is_dead:
        # That's probably as far as we can go, the road ends here
        return build_return_value(with_server_list, new_list, server_list)
    elif whois_response.request_failure:
        # Mark this result as incomplete, so we can try again later but still use the data if we have any
        new_list = [incomplete_result_message] + previous
        cool_down_tracker.warn_limit_exceeded(target_server)
        return build_return_value(with_server_list, new_list, server_list)
    elif whois_response.still_in_cool_down:
        new_list = [incomplete_result_message] + previous
        return build_return_value(with_server_list, new_list, server_list)

    server_list.append(target_server)

    # Ignore redirects from registries who publish the registrar data themselves
    if target_server not in ('whois.nic.xyz',):
        for line in [x.strip() for x in response.splitlines()]:
            match = re.match("(refer|whois server|referral url|whois server|registrar whois):\s*([^\s]+\.[^\s]+)", line,
                             re.IGNORECASE)
            if match is not None:
                referal_server = match.group(2)
                if referal_server != server and "://" not in referal_server \
                        and "www." not in referal_server and server_is_alive(referal_server):
                    # We want to ignore anything non-WHOIS (eg. HTTP) for now, and servers that are not reachable
                    # Referal to another WHOIS server...
                    return get_whois_raw(domain, referal_server, new_list, server_list=server_list,
                                         with_server_list=with_server_list)

    return build_return_value(with_server_list, new_list, server_list)


def build_return_value(with_server_list, responses, server_list):
    """
    Create a return value
    :param with_server_list: Whether the server list should be returned as well
    :param responses: The list of responses
    :param server_list: The server list
    :return: A list of responses without the empty ones, plus possibly a server list
    """
    non_empty_responses = filter((lambda text: text), responses)

    if with_server_list:
        return non_empty_responses, server_list
    else:
        return non_empty_responses


def query_server(whois_server, query):
    """
    Send out the query, if the server is available. if the server is still in cool down,
    return a RawWhoisResponse instance describing the failure
    :param whois_server: The WHOIS server to query
    :param query: The query to send
    :return: A RawWhoisResponse containing either the response or the reason of failure
    """
    if whois_server and cool_down_tracker.try_to_use_server(whois_server):
        return whois_request(query, whois_server)
    else:
        return RawWhoisResponse(still_in_cool_down=True)


def prepare_query(whois_server, domain):
    """
    Some WHOIS servers have a different way of querying.
    This methods returns an appropriate query for the WHOIS server
    :param domain: The domain to query
    :return: The fitting query
    """
    if whois_server == "whois.jprs.jp":
        return "%s/e" % domain  # Suppress Japanese output
    elif domain.endswith(".de") and (whois_server == "whois.denic.de" or whois_server == "de.whois-servers.net"):
        return "-T dn,ace %s" % domain  # regional specific stuff
    elif whois_server == "whois.verisign-grs.com":
        return "=%s" % domain  # Avoid partial matches
    else:
        return domain


def get_target_server(domain, previous_results, given_server):
    """
    Get the target server based on the current situation.
    :param domain: The domain to get the server for
    :param previous_results: The previously acquired results, as a result of referrals
    :param given_server:
    :return: The server to use
    """
    if len(previous_results) == 0 and given_server == "":
        # Root query
        for exception, exc_serv in exceptions.items():
            if domain.endswith(exception):
                target_server = exc_serv
                return target_server

        target_server = get_non_exception_server(domain)
        return target_server
    else:
        return given_server


def get_non_exception_server(domain):
    """
    Get a server that does not belong to the list of exceptions,
    either by asking IANA or by looking in the cache
    :param domain: The domain to get the WHOIS server for
    :return: The WHOIS server to use
    """
    tld = get_tld(domain)
    cached_server = server_cache.get_server(tld)
    if cached_server is not None:
        target_server = cached_server
    else:
        target_server = get_root_server(domain)
        server_cache.put_server(tld, target_server)

    return target_server


def server_is_alive(server):
    response = subprocess.call(["ping", "-c 1", "-w2", server], stdout=open(os.devnull, "w"),
                               stderr=subprocess.STDOUT)
    return response == 0


def get_tld(domain):
    return domain.split(".")[-1]


def get_root_server(domain):
    """
    Find the WHOIS server for a given domain
    :param domain: The domain to find a WHOIS server for
    :return: The WHOIS server, or an empty string if no server is found
    """
    data = whois_request(domain, "whois.iana.org").response or ""
    for line in [x.strip() for x in data.splitlines()]:
        match = re.match("refer:\s*([^\s]+)", line)
        if match is None:
            continue
        return match.group(1)
    return ""


def whois_request(domain, server, port=43, timeout=10):
    """
    Request WHOIS information.
    :param domain: The domain to request WHOIS information for
    :param server: The WHOIS server to use
    :param port: The port to use, 43 by default
    :param timeout: The length of the time out, 10 seconds by default
    :return: A WHOIS response containing either the result, or containing information about the failure
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.send(("%s\r\n" % domain).encode("utf-8"))
        buff = b""
        while True:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            buff += data
        return RawWhoisResponse(buff.decode("utf-8", "replace"))
    except Exception:
        server_is_dead = not server_is_alive(server)
        return RawWhoisResponse(request_failure=True, server_is_dead=server_is_dead)

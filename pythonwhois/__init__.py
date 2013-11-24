from . import net, parse

def get_whois(domain, normalized=[]):
	raw_data = net.get_whois_raw(domain)
	return parse.parse_raw_whois(raw_data, normalized=normalized)

def whois(*args, **kwargs):
	raise Exception("The whois() method has been replaced by a different method (with a different API), since pythonwhois 2.0. Either install the older pythonwhois 1.2.3, or change your code to use the new API.")

from . import net, parse

def get_whois(domain):
	raw_data = net.get_whois_raw(domain)
	return parse.parse_raw_whois(raw_data)

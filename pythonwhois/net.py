import socket, re
from . import shared

def get_whois_raw(domain, server="", previous=[]):
	if len(previous) == 0:
		# Root query
		target_server = get_root_server(domain)
	else:
		target_server = server
	if domain.endswith(".jp") and target_server == "whois.jprs.jp":
		request_domain = "%s/e" % domain # Suppress Japanese output
	elif target_server == "whois.verisign-grs.com":
		request_domain = "=%s" % domain # Avoid partial matches
	else:
		request_domain = domain
	response = whois_request(request_domain, target_server)
	new_list = [response] + previous
	if target_server == "whois.verisign-grs.com":
		# VeriSign is a little... special. As it may return multiple full records and there's no way to do an exact query,
		# we need to actually find the correct record in the list.
		for record in response.split("\n\n"):
			if re.search("Domain Name: %s\n" % domain.upper(), record):
				response = record
				break
	for line in [x.strip() for x in response.splitlines()]:
		match = re.match("(refer|whois server|referral url|whois server|registrar whois):\s*([^\s]+)", line, re.IGNORECASE)
		if match is not None:
			referal_server = match.group(2)
			if referal_server != server:
				# Referal to another WHOIS server...
				return get_whois_raw(domain, referal_server, new_list)
	return new_list
	
def get_root_server(domain):
	data = whois_request(domain, "whois.iana.org")
	for line in [x.strip() for x in data.splitlines()]:
		match = re.match("refer:\s*([^\s]+)", line)
		if match is None:
			continue
		return match.group(1)
	raise shared.WhoisException("No root WHOIS server found for TLD.")
	
def whois_request(domain, server, port=43):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((server, port))
	sock.send("%s\r\n" % domain)
	buff = ""
	while True:
		data = sock.recv(1024)
		if len(data) == 0:
			break
		buff += data
	return buff

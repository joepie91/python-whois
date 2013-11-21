import re, datetime

grammar = {
	"_data": {
		'status':		['\[Status\]\s*(?P<val>.+)',
					 'Status\s*:\s?(?P<val>.+)',
					 'state:\s*(?P<val>.+)'],
		'creation_date':	['\[Created on\]\s*(?P<val>.+)',
					 'Creation Date:\s?(?P<val>.+)',
					 'Created on:\s?(?P<val>.+)',
					 'Created on\s?[.]*:\s?(?P<val>.+)\.',
					 'Date Registered\s?[.]*:\s?(?P<val>.+)',
					 'Domain Created\s?[.]*:\s?(?P<val>.+)',
					 'Domain registered\s?[.]*:\s?(?P<val>.+)',
					 'Domain record activated\s?[.]*:\s*?(?P<val>.+)',
					 'Record created on\s?[.]*:?\s*?(?P<val>.+)',
					 'Record created\s?[.]*:?\s*?(?P<val>.+)',
					 'Created\s?[.]*:?\s*?(?P<val>.+)',
					 'Registered on\s?[.]*:?\s*?(?P<val>.+)',
					 'Registered\s?[.]*:?\s*?(?P<val>.+)',
					 'Domain Create Date\s?[.]*:?\s*?(?P<val>.+)',
					 'Domain Registration Date\s?[.]*:?\s*?(?P<val>.+)',
					 'created:\s*(?P<val>.+)',
					 'registered:\s*(?P<val>.+)'],
		'expiration_date':	['\[Expires on\]\s*(?P<val>.+)',
					 'Expiration Date:\s?(?P<val>.+)',
					 'Expires on:\s?(?P<val>.+)',
					 'Expires on\s?[.]*:\s?(?P<val>.+)\.',
					 'Expiry Date\s?[.]*:\s?(?P<val>.+)',
					 'Expiry\s*:\s?(?P<val>.+)',
					 'Domain Currently Expires\s?[.]*:\s?(?P<val>.+)',
					 'Record will expire on\s?[.]*:\s?(?P<val>.+)',
					 'Domain expires\s?[.]*:\s*?(?P<val>.+)',
					 'Record expires on\s?[.]*:?\s*?(?P<val>.+)',
					 'Record expires\s?[.]*:?\s*?(?P<val>.+)',
					 'Expires\s?[.]*:?\s*?(?P<val>.+)',
					 'Expire Date\s?[.]*:?\s*?(?P<val>.+)',
					 'Expired\s?[.]*:?\s*?(?P<val>.+)',
					 'Domain Expiration Date\s?[.]*:?\s*?(?P<val>.+)',
					 'paid-till:\s*(?P<val>.+)',
					 'expire:\s*(?P<val>.+)'],
		'updated_date':		['\[Last Updated\]\s*(?P<val>.+)',
					 'Updated Date:\s?(?P<val>.+)',
					 #'Database last updated on\s?[.]*:?\s*?(?P<val>.+)\s[a-z]+\.?',
					 'Record last updated on\s?[.]*:?\s?(?P<val>.+)\.',
					 'Domain record last updated\s?[.]*:\s*?(?P<val>.+)',
					 'Domain Last Updated\s?[.]*:\s*?(?P<val>.+)',
					 'Last updated on:\s?(?P<val>.+)',
					 'Date Modified\s?[.]*:\s?(?P<val>.+)',
					 'Last Modified\s?[.]*:\s?(?P<val>.+)',
					 'Domain Last Updated Date\s?[.]*:\s?(?P<val>.+)',
					 'Record last updated\s?[.]*:\s?(?P<val>.+)',
					 'Modified\s?[.]*:\s?(?P<val>.+)',
					 'changed:\s*(?P<val>.+)',
					 'Last Update\s?[.]*:\s?(?P<val>.+)',
					 'Last updated on (?P<val>.+) [a-z]{3}',
					 'Last update of whois database:\s?[a-z]{3}, (?P<val>.+) [a-z]{3}'],
		'registrar':		['registrar:\s*(?P<val>.+)',
					 'Registrar:\s*(?P<val>.+)',
					 'Registered through:\s?(?P<val>.+)',
					 'Registrar Name:\s?(?P<val>.+)',
					 'Record maintained by:\s?(?P<val>.+)',
					 'Registration Service Provided By:\s?(?P<val>.+)',
					 'Registrar of Record:\s?(?P<val>.+)',
					 '\tName:\t\s(?P<val>.+)'],
		'whois_server':		['Whois Server:\s?(?P<val>.+)',
					 'Registrar Whois:\s?(?P<val>.+)'],
		'name_servers':		['Name Server:\s?(?P<val>[^ ]+)',
					 '(?P<val>[a-z]*d?ns[0-9]+([a-z]{3})?\.([a-z0-9-]+\.)+[a-z0-9]+)',
					 'nameserver:\s*(?P<val>.+)',
					 'nserver:\s*(?P<val>[^[\s]+)',
					 'DNS[0-9]+:\s*(?P<val>.+)',
					 'ns[0-9]+:\s*(?P<val>.+)',
					 'NS [0-9]+\s*:\s*(?P<val>.+)',
					 '(?P<val>[a-z0-9-]+\.d?ns[0-9]*\.([a-z0-9-]+\.)+[a-z0-9]+)',
					 '(?P<val>([a-z0-9-]+\.)+[a-z0-9]+)(\s+([0-9]{1,3}\.){3}[0-9]{1,3})',
					 '[^a-z0-9.-](?P<val>d?ns\.([a-z0-9-]+\.)+[a-z0-9]+)'],
		'emails':		['(?P<val>[\w.-]+@[\w.-]+\.[\w]{2,4})',
					 '(?P<val>[\w.-]+\sAT\s[\w.-]+\sDOT\s[\w]{2,4})']
	},
	"_dateformats": (
		'(?P<day>[0-9]{1,2})[./ -](?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[./ -](?P<year>[0-9]{4}|[0-9]{2})'
			'(\s+(?P<hour>[0-9]{1,2})[:.](?P<minute>[0-9]{1,2})[:.](?P<second>[0-9]{1,2}))?',
		'[a-z]{3}\s(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[./ -](?P<day>[0-9]{1,2})'
			'(\s+(?P<hour>[0-9]{1,2})[:.](?P<minute>[0-9]{1,2})[:.](?P<second>[0-9]{1,2}))?'
			'\s[a-z]{3}\s(?P<year>[0-9]{4}|[0-9]{2})',
		'(?P<year>[0-9]{4})[./-](?P<month>[0-9]{1,2})[./-](?P<day>[0-9]{1,2})',
		'(?P<day>[0-9]{1,2})[./ -](?P<month>[0-9]{1,2})[./ -](?P<year>[0-9]{4}|[0-9]{2})',
		'(?P<year>[0-9]{4})(?P<month>[0-9]{2})(?P<day>[0-9]{2})\s((?P<hour>[0-9]{1,2})[:.](?P<minute>[0-9]{1,2})[:.](?P<second>[0-9]{1,2}))'
	),
	"_months": {
		'jan': 1,
		'january': 1,
		'feb': 2,
		'february': 2,
		'mar': 3,
		'march': 3,
		'apr': 4,
		'april': 4,
		'may': 5,
		'jun': 6,
		'june': 6,
		'jul': 7,
		'july': 7,
		'aug': 8,
		'august': 8,
		'sep': 9,
		'sept': 9,
		'september': 9,
		'oct': 10,
		'october': 10,
		'nov': 11,
		'november': 11,
		'dec': 12,
		'december': 12
	}
}
	
def parse_raw_whois(raw_data):
	data = {}
	
	raw_data = [segment.replace("\r", "") for segment in raw_data] # Carriage returns are the devil
	
	for segment in raw_data:
		for rule_key, rule_regexes in grammar['_data'].iteritems():
			if data.has_key(rule_key) == False:
				for line in segment.splitlines():
					for regex in rule_regexes:
						result = re.search(regex, line, re.IGNORECASE)
						
						if result is not None:
							val = result.group("val").strip()
							if val != "":
								try:
									data[rule_key].append(val)
								except KeyError, e:
									data[rule_key] = [val]
		
	# Fill all missing values with None
	for rule_key, rule_regexes in grammar['_data'].iteritems():		
		if data.has_key(rule_key) == False:
			data[rule_key] = None
			
	data["contacts"] = parse_registrants(raw_data)
			
	# Parse dates
	if data['expiration_date'] is not None:
		data['expiration_date'] = remove_duplicates(data['expiration_date'])
		data['expiration_date'] = parse_dates(data['expiration_date'])
	
	if data['creation_date'] is not None:
		data['creation_date'] = remove_duplicates(data['creation_date'])
		data['creation_date'] = parse_dates(data['creation_date'])
	
	if data['updated_date'] is not None:
		data['updated_date'] = remove_duplicates(data['updated_date'])
		data['updated_date'] = parse_dates(data['updated_date'])
	
	if data['name_servers'] is not None:
		data['name_servers'] = remove_duplicates([ns.rstrip(".") for ns in data['name_servers']])
	
	if data['emails'] is not None:
		data['emails'] = remove_duplicates(data['emails'])
	
	if data['registrar'] is not None:
		data['registrar'] = remove_duplicates(data['registrar'])
		
	# Remove e-mail addresses if they are already listed for any of the contacts
	known_emails = []
	for contact in ("registrant", "tech", "admin", "billing"):
		if data["contacts"][contact] is not None:
			try:
				known_emails.append(data["contacts"][contact]["email"])
			except KeyError, e:
				pass # No e-mail recorded for this contact...
	if data['emails'] is not None:
		data['emails'] = [email for email in data["emails"] if email not in known_emails]
	
	data["raw"] = raw_data
	
	return data

def parse_dates(dates):
	global grammar
	parsed_dates = []
	
	for date in dates:
		for rule in grammar['_dateformats']:
			result = re.match(rule, date, re.IGNORECASE)
			
			if result is not None:
				try:
					# These are always numeric. If they fail, there is no valid date present.
					year = int(result.group("year"))
					day = int(result.group("day"))
					
					# Detect and correct shorthand year notation
					if year < 60:
						year += 2000
					elif year < 100:
						year += 1900
					
					# This will require some more guesswork - some WHOIS servers present the name of the month
					try:
						month = int(result.group("month"))
					except ValueError, e:
						# Apparently not a number. Look up the corresponding number.
						try:
							month = grammar['_months'][result.group("month").lower()]
						except KeyError, e:
							# Unknown month name, default to 0
							month = 0
					
					try:
						hour = int(result.group("hour"))
					except IndexError, e:
						hour = 0
					except TypeError, e:
						hour = 0
					
					try:
						minute = int(result.group("minute"))
					except IndexError, e:
						minute = 0
					except TypeError, e:
						minute = 0
					
					try:
						second = int(result.group("second"))
					except IndexError, e:
						second = 0
					except TypeError, e:
						second = 0
					
					break
				except ValueError, e:
					# Something went horribly wrong, maybe there is no valid date present?
					year = 0
					month = 0
					day = 0
					hour = 0
					minute = 0
					second = 0
					print e.message
		try:
			if year > 0:
				try:
					parsed_dates.append(datetime.datetime(year, month, day, hour, minute, second))
				except ValueError, e:
					# We might have gotten the day and month the wrong way around, let's try it the other way around
					# If you're not using an ISO-standard date format, you're an evil registrar!
					parsed_dates.append(datetime.datetime(year, day, month, hour, minute, second))
		except UnboundLocalError, e:
			pass
	
	if len(parsed_dates) > 0:
		return parsed_dates
	else:
		return None

def remove_duplicates(data):
	cleaned_list = []
	
	for entry in data:
		if entry not in cleaned_list:
			cleaned_list.append(entry)
	
	return cleaned_list

def parse_registrants(data):
	registrant = None
	tech_contact = None
	billing_contact = None
	admin_contact = None
	
	registrant_regexes = [
		"Registrant:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", # OVH
		"Registrant ID:(?P<handle>.+)\nRegistrant Name:(?P<name>.*)\nRegistrant Organization:(?P<organization>.*)\nRegistrant Street1:(?P<street1>.*)\nRegistrant Street2:(?P<street2>.*)\nRegistrant Street3:(?P<street3>.*)\nRegistrant City:(?P<city>.*)\nRegistrant State/Province:(?P<state>.*)\nRegistrant Postal Code:(?P<postalcode>.*)\nRegistrant Country:(?P<country>.*)\nRegistrant Phone:(?P<phone>.*)\nRegistrant Phone Ext.:(?P<phone_ext>.*)\nRegistrant FAX:(?P<fax>.*)\nRegistrant FAX Ext.:(?P<fax_ext>.*)\nRegistrant Email:(?P<email>.*)", # Public Interest Registry (.org)
		"Registrant ID:\s*(?P<handle>.+)\nRegistrant Name:\s*(?P<name>.+)\nRegistrant Organization:\s*(?P<organization>.*)\nRegistrant Address1:\s*(?P<street1>.+)\nRegistrant Address2:\s*(?P<street2>.*)\nRegistrant City:\s*(?P<city>.+)\nRegistrant State/Province:\s*(?P<state>.+)\nRegistrant Postal Code:\s*(?P<postalcode>.+)\nRegistrant Country:\s*(?P<country>.+)\nRegistrant Country Code:\s*(?P<country_code>.+)\nRegistrant Phone Number:\s*(?P<phone>.+)\nRegistrant Email:\s*(?P<email>.+)\n", # .CO Internet
		"Registrant Contact: (?P<handle>.+)\nRegistrant Organization: (?P<organization>.+)\nRegistrant Name: (?P<name>.+)\nRegistrant Street: (?P<street>.+)\nRegistrant City: (?P<city>.+)\nRegistrant Postal Code: (?P<postalcode>.+)\nRegistrant State: (?P<state>.+)\nRegistrant Country: (?P<country>.+)\nRegistrant Phone: (?P<phone>.*)\nRegistrant Phone Ext: (?P<phone_ext>.*)\nRegistrant Fax: (?P<fax>.*)\nRegistrant Fax Ext: (?P<fax_ext>.*)\nRegistrant Email: (?P<email>.*)\n", # Key-Systems GmbH
		"Registrant Name:[ ]*(?P<name>.*)\nRegistrant Organization:[ ]*(?P<organization>.*)\nRegistrant Street:[ ]*(?P<street1>.+)\n(?:Registrant Street:[ ]*(?P<street2>.+)\n)?Registrant City:[ ]*(?P<city>.+)\nRegistrant State\/Province:[ ]*(?P<state>.+)\nRegistrant Postal Code:[ ]*(?P<postalcode>.+)\nRegistrant Country:[ ]*(?P<country>.+)\n(?:Registrant Phone:[ ]*(?P<phone>.*)\n)?(?:Registrant Phone Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Registrant Fax:[ ]*(?P<fax>.*)\n)?(?:Registrant Fax Ext:[ ]*(?P<fax_ext>.*)\n)?(?:Registrant Email:[ ]*(?P<email>.+)\n)?", # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio
		"Registrant\n    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", # internet.bs
		"Holder of domain name:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\nContractual Language", # nic.ch
		"\n\n(?:Owner)?\s+: (?P<name>.*)\n(?:\s+: (?P<organization>.*)\n)?\s+: (?P<street>.*)\n\s+: (?P<city>.*)\n\s+: (?P<state>.*)\n\s+: (?P<country>.*)\n", # nic.io
		"Contact Information:\n\[Name\]\s*(?P<name>.*)\n\[Email\]\s*(?P<email>.*)\n\[Web Page\]\s*(?P<url>.*)\n\[Postal code\]\s*(?P<postalcode>.*)\n\[Postal Address\]\s*(?P<street1>.*)\n(?:\s+(?P<street2>.*)\n)?(?:\s+(?P<street3>.*)\n)?\[Phone\]\s*(?P<phone>.*)\n\[Fax\]\s*(?P<fax>.*)\n", # jprs.jp
		"person:\s+(?P<name>.+)", # nic.ru (person)
		"org:\s+(?P<organization>.+)", # nic.ru (organization)
	]

	tech_contact_regexes = [
		"Technical Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", # OVH
		"Tech ID:(?P<handle>.+)\nTech Name:(?P<name>.*)\nTech Organization:(?P<organization>.*)\nTech Street1:(?P<street1>.*)\nTech Street2:(?P<street2>.*)\nTech Street3:(?P<street3>.*)\nTech City:(?P<city>.*)\nTech State/Province:(?P<state>.*)\nTech Postal Code:(?P<postalcode>.*)\nTech Country:(?P<country>.*)\nTech Phone:(?P<phone>.*)\nTech Phone Ext.:(?P<phone_ext>.*)\nTech FAX:(?P<fax>.*)\nTech FAX Ext.:(?P<fax_ext>.*)\nTech Email:(?P<email>.*)", # Public Interest Registry (.org)
		"Technical Contact ID:\s*(?P<handle>.+)\nTechnical Contact Name:\s*(?P<name>.+)\nTechnical Contact Organization:\s*(?P<organization>.*)\nTechnical Contact Address1:\s*(?P<street1>.+)\nTechnical Contact Address2:\s*(?P<street2>.*)\nTechnical Contact City:\s*(?P<city>.+)\nTechnical Contact State/Province:\s*(?P<state>.+)\nTechnical Contact Postal Code:\s*(?P<postalcode>.+)\nTechnical Contact Country:\s*(?P<country>.+)\nTechnical Contact Country Code:\s*(?P<country_code>.+)\nTechnical Contact Phone Number:\s*(?P<phone>.+)\nTechnical Contact Email:\s*(?P<email>.+)\n", # .CO Internet
		"Tech Contact: (?P<handle>.+)\nTech Organization: (?P<organization>.+)\nTech Name: (?P<name>.+)\nTech Street: (?P<street>.+)\nTech City: (?P<city>.+)\nTech Postal Code: (?P<postalcode>.+)\nTech State: (?P<state>.+)\nTech Country: (?P<country>.+)\nTech Phone: (?P<phone>.*)\nTech Phone Ext: (?P<phone_ext>.*)\nTech Fax: (?P<fax>.*)\nTech Fax Ext: (?P<fax_ext>.*)\nTech Email: (?P<email>.*)\n", # Key-Systems GmbH
		"Tech[ ]*Name:[ ]*(?P<name>.*)\nTech[ ]*Organization:[ ]*(?P<organization>.*)\nTech[ ]*Street:[ ]*(?P<street1>.+)\n(?:Tech[ ]*Street:[ ]*(?P<street2>.+)\n)?Tech[ ]*City:[ ]*(?P<city>.+)\nTech[ ]*State\/Province:[ ]*(?P<state>.+)\nTech[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nTech[ ]*Country:[ ]*(?P<country>.+)\n(?:Tech[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Tech[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Tech[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Tech[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Tech[ ]*Email:[ ]*(?P<email>.+)\n)?", # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio
		"Technical Contact\n    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", # internet.bs
		"Technical contact:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\n\n" # nic.ch
	]
	
	admin_contact_regexes = [
		"Administrative Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", # OVH
		"Admin ID:(?P<handle>.+)\nAdmin Name:(?P<name>.*)\nAdmin Organization:(?P<organization>.*)\nAdmin Street1:(?P<street1>.*)\nAdmin Street2:(?P<street2>.*)\nAdmin Street3:(?P<street3>.*)\nAdmin City:(?P<city>.*)\nAdmin State/Province:(?P<state>.*)\nAdmin Postal Code:(?P<postalcode>.*)\nAdmin Country:(?P<country>.*)\nAdmin Phone:(?P<phone>.*)\nAdmin Phone Ext.:(?P<phone_ext>.*)\nAdmin FAX:(?P<fax>.*)\nAdmin FAX Ext.:(?P<fax_ext>.*)\nAdmin Email:(?P<email>.*)", # Public Interest Registry (.org)
		"Administrative Contact ID:\s*(?P<handle>.+)\nAdministrative Contact Name:\s*(?P<name>.+)\nAdministrative Contact Organization:\s*(?P<organization>.*)\nAdministrative Contact Address1:\s*(?P<street1>.+)\nAdministrative Contact Address2:\s*(?P<street2>.*)\nAdministrative Contact City:\s*(?P<city>.+)\nAdministrative Contact State/Province:\s*(?P<state>.+)\nAdministrative Contact Postal Code:\s*(?P<postalcode>.+)\nAdministrative Contact Country:\s*(?P<country>.+)\nAdministrative Contact Country Code:\s*(?P<country_code>.+)\nAdministrative Contact Phone Number:\s*(?P<phone>.+)\nAdministrative Contact Email:\s*(?P<email>.+)\n", # .CO Internet
		"Admin Contact: (?P<handle>.+)\nAdmin Organization: (?P<organization>.+)\nAdmin Name: (?P<name>.+)\nAdmin Street: (?P<street>.+)\nAdmin City: (?P<city>.+)\nAdmin State: (?P<state>.+)\nAdmin Postal Code: (?P<postalcode>.+)\nAdmin Country: (?P<country>.+)\nAdmin Phone: (?P<phone>.*)\nAdmin Phone Ext: (?P<phone_ext>.*)\nAdmin Fax: (?P<fax>.*)\nAdmin Fax Ext: (?P<fax_ext>.*)\nAdmin Email: (?P<email>.*)\n", # Key-Systems GmbH
		"Admin[ ]*Name:[ ]*(?P<name>.*)\nAdmin[ ]*Organization:[ ]*(?P<organization>.*)\nAdmin[ ]*Street:[ ]*(?P<street1>.+)\n(?:Admin[ ]*Street:[ ]*(?P<street2>.+)\n)?Admin[ ]*City:[ ]*(?P<city>.+)\nAdmin[ ]*State\/Province:[ ]*(?P<state>.+)\nAdmin[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nAdmin[ ]*Country:[ ]*(?P<country>.+)\n(?:Admin[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Admin[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Admin[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Admin[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Admin[ ]*Email:[ ]*(?P<email>.+)\n)?", # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio
		"Administrative Contact\n    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", # internet.bs
	]
	
	billing_contact_regexes = [
		"Billing Contact ID:\s*(?P<handle>.+)\nBilling Contact Name:\s*(?P<name>.+)\nBilling Contact Organization:\s*(?P<organization>.*)\nBilling Contact Address1:\s*(?P<street1>.+)\nBilling Contact Address2:\s*(?P<street2>.*)\nBilling Contact City:\s*(?P<city>.+)\nBilling Contact State/Province:\s*(?P<state>.+)\nBilling Contact Postal Code:\s*(?P<postalcode>.+)\nBilling Contact Country:\s*(?P<country>.+)\nBilling Contact Country Code:\s*(?P<country_code>.+)\nBilling Contact Phone Number:\s*(?P<phone>.+)\nBilling Contact Email:\s*(?P<email>.+)\n", # .CO Internet
		"Billing Contact: (?P<handle>.+)\nBilling Organization: (?P<organization>.+)\nBilling Name: (?P<name>.+)\nBilling Street: (?P<street>.+)\nBilling City: (?P<city>.+)\nBilling Postal Code: (?P<postalcode>.+)\nBilling State: (?P<state>.+)\nBilling Country: (?P<country>.+)\nBilling Phone: (?P<phone>.*)\nBilling Phone Ext: (?P<phone_ext>.*)\nBilling Fax: (?P<fax>.*)\nBilling Fax Ext: (?P<fax_ext>.*)\nBilling Email: (?P<email>.*)\n", # Key-Systems GmbH
		"Billing Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", # OVH
	]
	
	# Some registries use NIC handle references instead of directly listing contacts...
	
	nic_contact_regexes = [
		"personname:\s*(?P<name>.+)\norganization:\s*(?P<organization>.+)\nstreet address:\s*(?P<street>.+)\npostal code:\s*(?P<postalcode>.+)\ncity:\s*(?P<city>.+)\ncountry:\s*(?P<country>.+)\nphone:\s*(?P<phone>.+)\nfax-no:\s*(?P<fax>.+)\ne-mail:\s*(?P<email>.+)\nnic-hdl:\s*(?P<handle>.+)\nchanged:\s*(?P<changedate>.+)", # nic.at
		"nic-hdl:\s*(?P<handle>.+)\ntype:\s*(?P<type>.+)\ncontact:\s*(?P<name>.+)\n(?:.+\n)*?(?:address:\s*(?P<street1>.+)\naddress:\s*(?P<street2>.+)\naddress:\s*(?P<street3>.+)\naddress:\s*(?P<country>.+)\n)?(?:phone:\s*(?P<phone>.+)\n)?(?:fax-no:\s*(?P<fax>.+)\n)?(?:.+\n)*?(?:e-mail:\s*(?P<email>.+)\n)?(?:.+\n)*?changed:\s*(?P<changedate>[0-9]{2}\/[0-9]{2}\/[0-9]{4}).*\n", # AFNIC madness without country field
		"nic-hdl:\s*(?P<handle>.+)\ntype:\s*(?P<type>.+)\ncontact:\s*(?P<name>.+)\n(?:.+\n)*?(?:address:\s*(?P<street1>.+)\n)?(?:address:\s*(?P<street2>.+)\n)?(?:address:\s*(?P<street3>.+)\n)?(?:phone:\s*(?P<phone>.+)\n)?(?:fax-no:\s*(?P<fax>.+)\n)?(?:.+\n)*?(?:e-mail:\s*(?P<email>.+)\n)?(?:.+\n)*?changed:\s*(?P<changedate>[0-9]{2}\/[0-9]{2}\/[0-9]{4}).*\n", # AFNIC madness any country -at all-
		"nic-hdl:\s*(?P<handle>.+)\ntype:\s*(?P<type>.+)\ncontact:\s*(?P<name>.+)\n(?:.+\n)*?(?:address:\s*(?P<street1>.+)\n)?(?:address:\s*(?P<street2>.+)\n)?(?:address:\s*(?P<street3>.+)\n)?(?:address:\s*(?P<street4>.+)\n)?country:\s*(?P<country>.+)\n(?:phone:\s*(?P<phone>.+)\n)?(?:fax-no:\s*(?P<fax>.+)\n)?(?:.+\n)*?(?:e-mail:\s*(?P<email>.+)\n)?(?:.+\n)*?changed:\s*(?P<changedate>[0-9]{2}\/[0-9]{2}\/[0-9]{4}).*\n", # AFNIC madness with country field
		
	]
	
	nic_contact_references = {
		"registrant": [
			"registrant:\s*(?P<handle>.+)", # nic.at
			"holder-c:\s*(?P<handle>.+)", # AFNIC
		],
		"tech": [
			"tech-c:\s*(?P<handle>.+)", # nic.at, AFNIC
		],
		"admin": [
			"admin-c:\s*(?P<handle>.+)", # nic.at, AFNIC
		],
	}
	
	for regex in registrant_regexes:
		for segment in data:
			match = re.search(regex, segment)
			if match is not None:
				registrant = match.groupdict()
				break
	
	for regex in tech_contact_regexes:
		for segment in data:
			match = re.search(regex, segment)
			if match is not None:
				tech_contact = match.groupdict()
				break
	
	for regex in admin_contact_regexes:
		for segment in data:
			match = re.search(regex, segment)
			if match is not None:
				admin_contact = match.groupdict()
				break
	
	for regex in billing_contact_regexes:
		for segment in data:
			match = re.search(regex, segment)
			if match is not None:
				billing_contact = match.groupdict()
				break
		
	# Find NIC handle contact definitions
	handle_contacts = []
	for regex in nic_contact_regexes:
		for segment in data:
			matches = re.finditer(regex, segment)
			for match in matches:
				handle_contacts.append(match.groupdict())
	
	# Find NIC handle references and process them
	for category in nic_contact_references:
		for regex in nic_contact_references[category]:
			for segment in data:
				match = re.search(regex, segment)
				if match is not None:
					data_reference = match.groupdict()
					for contact in handle_contacts:
						if contact["handle"] == data_reference["handle"]:
							data_reference.update(contact)
					if category == "registrant":
						registrant = data_reference
					elif category == "tech":
						tech_contact = data_reference
					elif category == "billing":
						billing_contact = data_reference
					elif category == "admin":
						admin_contact = data_reference
					break
		
	# Post-processing		
	for obj in (registrant, tech_contact, billing_contact, admin_contact):
		if obj is not None:
			for key in obj.keys():
				if obj[key] is None or obj[key].strip() == "": # Just chomp all surrounding whitespace
					del obj[key]
			if "phone_ext" in obj:
				if "phone" in obj:
					obj["phone"] += "ext. %s" % obj["phone_ext"]
					del obj["phone_ext"]
			if "street1" in obj:
				street_items = []
				i = 1
				while True:
					try:
						street_items.append(obj["street%d" % i])
						del obj["street%d" % i]
					except KeyError, e:
						break
					i += 1
				obj["street"] = "\n".join(street_items)
			if 'changedate' in obj:
				obj['changedate'] = parse_dates([obj['changedate']])[0]
			if 'street' in obj and "\n" in obj["street"] and 'postalcode' not in obj:
				# Deal with certain mad WHOIS servers that don't properly delimit address data... (yes, AFNIC, looking at you)
				lines = [x.strip() for x in obj["street"].splitlines()]
				if " " in lines[-1]:
					postal_code, city = lines[-1].split(" ", 1)
					obj["postalcode"] = postal_code
					obj["city"] = city
					obj["street"] = "\n".join(lines[:-1])
	
	return {
		"registrant": registrant,
		"tech": tech_contact,
		"admin": admin_contact,
		"billing": billing_contact,
	}

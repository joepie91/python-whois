from __future__ import print_function
import re, sys, datetime

grammar = {
	"_data": {
		'id':			['Domain ID:[ ]*(?P<val>.+)'],
		'status':		['\[Status\]\s*(?P<val>.+)',
					 'Status\s*:\s?(?P<val>.+)',
					 '^state:\s*(?P<val>.+)'],
		'creation_date':	['\[Created on\]\s*(?P<val>.+)',
					 'Created on[.]*: [a-zA-Z]+, (?P<val>.+)',
					 'Creation Date:\s?(?P<val>.+)',
					 'Creation date\s*:\s?(?P<val>.+)',
					 'Created Date:\s?(?P<val>.+)',
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
					 'created-date:\s*(?P<val>.+)',
					 'registered:\s*(?P<val>.+)',
					 'registration:\s*(?P<val>.+)'],
		'expiration_date':	['\[Expires on\]\s*(?P<val>.+)',
					 'Registrar Registration Expiration Date:[ ]*(?P<val>.+)-[0-9]{4}',
					 'Expires on[.]*: [a-zA-Z]+, (?P<val>.+)',
					 'Expiration Date:\s?(?P<val>.+)',
					 'Expiration date\s*:\s?(?P<val>.+)',
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
					 'expiration_date:\s*(?P<val>.+)',
					 'renewal:\s*(?P<val>.+)',
					 'expire:\s*(?P<val>.+)'],
		'updated_date':		['\[Last Updated\]\s*(?P<val>.+)',
					 'Record modified on[.]*: (?P<val>.+) [a-zA-Z]+',
					 'Record last updated on[.]*: [a-zA-Z]+, (?P<val>.+)',
					 'Updated Date:\s?(?P<val>.+)',
					 'Updated date\s*:\s?(?P<val>.+)',
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
					 '(C|c)hanged:\s*(?P<val>.+)',
					 'last_update:\s*(?P<val>.+)',
					 'Last Update\s?[.]*:\s?(?P<val>.+)',
					 'Last updated on (?P<val>.+) [a-z]{3,4}',
					 'Last updated:\s*(?P<val>.+)',
					 'Last update of whois database:\s?[a-z]{3}, (?P<val>.+) [a-z]{3,4}'],
		'registrar':		['registrar:\s*(?P<val>.+)',
					 'Registrar:\s*(?P<val>.+)',
					 'Sponsoring Registrar Organization:\s*(?P<val>.+)',
					 'Registered through:\s?(?P<val>.+)',
					 'Registrar Name[.]*:\s?(?P<val>.+)',
					 'Record maintained by:\s?(?P<val>.+)',
					 'Registration Service Provided By:\s?(?P<val>.+)',
					 'Registrar of Record:\s?(?P<val>.+)',
					 'Domain Registrar :\s?(?P<val>.+)',
					 '\tName:\t\s(?P<val>.+)'],
		'whois_server':		['Whois Server:\s?(?P<val>.+)',
					 'Registrar Whois:\s?(?P<val>.+)'],
		'nameservers':		['Name Server:[ ]*(?P<val>[^ ]+)',
					 'Nameservers:[ ]*(?P<val>[^ ]+)',
					 '(?<=[ .]{2})(?P<val>([a-z0-9-]+\.)+[a-z0-9]+)(\s+([0-9]{1,3}\.){3}[0-9]{1,3})',
					 'nameserver:\s*(?P<val>.+)',
					 'nserver:\s*(?P<val>[^[\s]+)',
					 'Name Server[.]+ (?P<val>[^[\s]+)',
					 'Hostname:\s*(?P<val>[^\s]+)',
					 'DNS[0-9]+:\s*(?P<val>.+)',
					 'ns[0-9]+:\s*(?P<val>.+)',
					 'NS [0-9]+\s*:\s*(?P<val>.+)',
					 '\[Name Server\]\s*(?P<val>.+)',
					 '(?<=[ .]{2})(?P<val>[a-z0-9-]+\.d?ns[0-9]*\.([a-z0-9-]+\.)+[a-z0-9]+)',
					 '(?<=[ .]{2})(?P<val>([a-z0-9-]+\.)+[a-z0-9]+)(\s+([0-9]{1,3}\.){3}[0-9]{1,3})',
					 '(?<=[ .]{2})[^a-z0-9.-](?P<val>d?ns\.([a-z0-9-]+\.)+[a-z0-9]+)',
                                         'Nserver:\s*(?P<val>.+)'],
		'emails':		['(?P<val>[\w.-]+@[\w.-]+\.[\w]{2,6})', # Really need to fix this, much longer TLDs now exist...
					 '(?P<val>[\w.-]+\sAT\s[\w.-]+\sDOT\s[\w]{2,6})']
	},
	"_dateformats": (
		'(?P<day>[0-9]{1,2})[./ -](?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[./ -](?P<year>[0-9]{4}|[0-9]{2})'
		'(\s+(?P<hour>[0-9]{1,2})[:.](?P<minute>[0-9]{1,2})[:.](?P<second>[0-9]{1,2}))?',
		'[a-z]{3}\s(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[./ -](?P<day>[0-9]{1,2})(\s+(?P<hour>[0-9]{1,2})[:.](?P<minute>[0-9]{1,2})[:.](?P<second>[0-9]{1,2}))?\s[a-z]{3}\s(?P<year>[0-9]{4}|[0-9]{2})',
		'[a-zA-Z]+\s(?P<day>[0-9]{1,2})(?:st|nd|rd|th)\s(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\s(?P<year>[0-9]{4})',
		'(?P<year>[0-9]{4})[./-]?(?P<month>[0-9]{2})[./-]?(?P<day>[0-9]{2})(\s|T|/)((?P<hour>[0-9]{1,2})[:.-](?P<minute>[0-9]{1,2})[:.-](?P<second>[0-9]{1,2}))',
		'(?P<year>[0-9]{4})[./-](?P<month>[0-9]{1,2})[./-](?P<day>[0-9]{1,2})',
		'(?P<day>[0-9]{1,2})[./ -](?P<month>[0-9]{1,2})[./ -](?P<year>[0-9]{4}|[0-9]{2})',
		'(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?P<day>[0-9]{1,2}),? (?P<year>[0-9]{4})',
		'(?P<day>[0-9]{1,2})-(?P<month>January|February|March|April|May|June|July|August|September|October|November|December)-(?P<year>[0-9]{4})',
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


if sys.version_info < (3, 0):
	def is_string(data):
		"""Test for string with support for python 2."""
		return isinstance(data, basestring)
else:
	def is_string(data):
		"""Test for string with support for python 3."""
		return isinstance(data, str)


def parse_raw_whois(raw_data, normalized=[]):
	data = {}

	raw_data = [segment.replace("\r", "") for segment in raw_data] # Carriage returns are the devil

	for segment in raw_data:
		for rule_key, rule_regexes in grammar['_data'].items():
			if (rule_key in data) == False:
				for line in segment.splitlines():
					for regex in rule_regexes:
						result = re.search(regex, line, re.IGNORECASE)

						if result is not None:
							val = result.group("val").strip()
							if val != "":
								try:
									data[rule_key].append(val)
								except KeyError as e:
									data[rule_key] = [val]

		# Whois.com is a bit special... Fabulous.com also seems to use this format. As do some others.
		match = re.search("^\s?Name\s?[Ss]ervers:\s*\n((?:\s*.+\n)+?\s?)\n", segment, re.MULTILINE)
		if match is not None:
			chunk = match.group(1)
			for match in re.findall("[ ]*(.+)\n", chunk):
				if match.strip() != "":
					if not re.match("^[a-zA-Z]+:", match):
						try:
							data["nameservers"].append(match.strip())
						except KeyError as e:
							data["nameservers"] = [match.strip()]
		# Nominet also needs some special attention
		match = re.search("    Registrar:\n        (.+)\n", segment)
		if match is not None:
			data["registrar"] = [match.group(1).strip()]
		match = re.search("    Registration status:\n        (.+)\n", segment)
		if match is not None:
			data["status"] = [match.group(1).strip()]
		match = re.search("    Name servers:\n([\s\S]*?\n)\n", segment)
		if match is not None:
			chunk = match.group(1)
			for match in re.findall("        (.+)\n", chunk):
				match = match.split()[0]
				try:
					data["nameservers"].append(match.strip())
				except KeyError as e:
					data["nameservers"] = [match.strip()]
		# janet (.ac.uk) is kinda like Nominet, but also kinda not
		match = re.search("Registered By:\n\t(.+)\n", segment)
		if match is not None:
			data["registrar"] = [match.group(1).strip()]
		match = re.search("Entry created:\n\t(.+)\n", segment)
		if match is not None:
			data["creation_date"] = [match.group(1).strip()]
		match = re.search("Renewal date:\n\t(.+)\n", segment)
		if match is not None:
			data["expiration_date"] = [match.group(1).strip()]
		match = re.search("Entry updated:\n\t(.+)\n", segment)
		if match is not None:
			data["updated_date"] = [match.group(1).strip()]
		match = re.search("Servers:([\s\S]*?\n)\n", segment)
		if match is not None:
			chunk = match.group(1)
			for match in re.findall("\t(.+)\n", chunk):
				match = match.split()[0]
				try:
					data["nameservers"].append(match.strip())
				except KeyError as e:
					data["nameservers"] = [match.strip()]
		# .am plays the same game
		match = re.search("   DNS servers:([\s\S]*?\n)\n", segment)
		if match is not None:
			chunk = match.group(1)
			for match in re.findall("      (.+)\n", chunk):
				match = match.split()[0]
				try:
					data["nameservers"].append(match.strip())
				except KeyError as e:
					data["nameservers"] = [match.strip()]
		# SIDN isn't very standard either. And EURid uses a similar format.
		match = re.search("Registrar:\n\s+(?:Name:\s*)?(\S.*)", segment)
		if match is not None:
			data["registrar"].insert(0, match.group(1).strip())
		match = re.search("(?:Domain nameservers|Name servers):([\s\S]*?\n)\n", segment)
		if match is not None:
			chunk = match.group(1)
			for match in re.findall("\s+?(.+)\n", chunk):
				match = match.split()[0]
				# Prevent nameserver aliases from being picked up.
				if not match.startswith("[") and not match.endswith("]"):
					try:
						data["nameservers"].append(match.strip())
					except KeyError as e:
						data["nameservers"] = [match.strip()]
		# The .ie WHOIS server puts ambiguous status information in an unhelpful order
		match = re.search('ren-status:\s*(.+)', segment)
		if match is not None:
			data["status"].insert(0, match.group(1).strip())
		

	data["contacts"] = parse_registrants(raw_data)

	# Parse dates
	try:
		data['expiration_date'] = remove_duplicates(data['expiration_date'])
		data['expiration_date'] = parse_dates(data['expiration_date'])
	except KeyError as e:
		pass # Not present

	try:
		data['creation_date'] = remove_duplicates(data['creation_date'])
		data['creation_date'] = parse_dates(data['creation_date'])
	except KeyError as e:
		pass # Not present

	try:
		data['updated_date'] = remove_duplicates(data['updated_date'])
		data['updated_date'] = parse_dates(data['updated_date'])
	except KeyError as e:
		pass # Not present

	try:
		data['nameservers'] = remove_suffixes(data['nameservers'])
		data['nameservers'] = remove_duplicates([ns.rstrip(".") for ns in data['nameservers']])
	except KeyError as e:
		pass # Not present

	try:
		data['emails'] = remove_duplicates(data['emails'])
	except KeyError as e:
		pass # Not present

	try:
		data['registrar'] = remove_duplicates(data['registrar'])
	except KeyError as e:
		pass # Not present

	# Remove e-mail addresses if they are already listed for any of the contacts
	known_emails = []
	for contact in ("registrant", "tech", "admin", "billing"):
		if data["contacts"][contact] is not None:
			try:
				known_emails.append(data["contacts"][contact]["email"])
			except KeyError as e:
				pass # No e-mail recorded for this contact...
	try:
		data['emails'] = [email for email in data["emails"] if email not in known_emails]
	except KeyError as e:
		pass # Not present

	for key in list(data.keys()):
		if data[key] is None or len(data[key]) == 0:
			del data[key]

	data["raw"] = raw_data

	if normalized != []:
		data = normalize_data(data, normalized)

	return data

def normalize_data(data, normalized):
	for key in ("nameservers", "emails", "whois_server"):
		if key in data and data[key] is not None and (normalized == True or key in normalized):
			if is_string(data[key]):
				data[key] = data[key].lower()
			else:
				data[key] = [item.lower() for item in data[key]]

	for key, threshold in (("registrar", 4), ("status", 3)):
		if key in data and data[key] is not None and (normalized == True or key in normalized):
			if is_string(data[key]):
				data[key] = normalize_name(data[key], abbreviation_threshold=threshold, length_threshold=1)
			else:
				data[key] = [normalize_name(item, abbreviation_threshold=threshold, length_threshold=1) for item in data[key]]

	for contact_type, contact in data['contacts'].items():
		if contact is not None:
			for key in ("email",):
				if key in contact and contact[key] is not None and (normalized == True or key in normalized):
					if isinstance(contact[key], str):
						contact[key] = contact[key].lower()
					else:
						contact[key] = [item.lower() for item in contact[key]]

			for key in ("name", "street"):
				if key in contact and contact[key] is not None and (normalized == True or key in normalized):
					contact[key] = normalize_name(contact[key], abbreviation_threshold=3)

			for key in ("city", "organization", "state", "country"):
				if key in contact and contact[key] is not None and (normalized == True or key in normalized):
					contact[key] = normalize_name(contact[key], abbreviation_threshold=3, length_threshold=3)

			for key in list(contact.keys()):
				try:
					contact[key] = contact[key].strip(", ")
				except AttributeError as e:
					pass # Not a string
	return data

def normalize_name(value, abbreviation_threshold=4, length_threshold=8, lowercase_domains=True):
	normalized_lines = []
	for line in value.split("\n"):
		line = line.strip(",") # Get rid of useless comma's
		if (line.isupper() or line.islower()) and len(line) >= length_threshold:
			# This line is likely not capitalized properly
			words = line.split()
			normalized_words = []
			if len(words) >= 1:
				# First word
				if len(words[0]) >= abbreviation_threshold and "." not in words[0]:
					normalized_words.append(words[0].capitalize())
				elif lowercase_domains and "." in words[0] and not words[0].endswith(".") and not words[0].startswith("."):
					normalized_words.append(words[0].lower())
				else:
					# Probably an abbreviation or domain, leave it alone
					normalized_words.append(words[0])
			if len(words) >= 3:
				# Words between the first and last
				for word in words[1:-1]:
					if len(word) >= abbreviation_threshold and "." not in word:
						normalized_words.append(word.capitalize())
					elif lowercase_domains and "." in word and not word.endswith(".") and not word.startswith("."):
						normalized_words.append(word.lower())
					else:
						# Probably an abbreviation or domain, leave it alone
						normalized_words.append(word)
			if len(words) >= 2:
				# Last word
				if len(words[-1]) >= abbreviation_threshold and "." not in words[-1]:
					normalized_words.append(words[-1].capitalize())
				elif lowercase_domains and "." in words[-1] and not words[-1].endswith(".") and not words[-1].startswith("."):
					normalized_words.append(words[-1].lower())
				else:
					# Probably an abbreviation or domain, leave it alone
					normalized_words.append(words[-1])
			line = " ".join(normalized_words)
		normalized_lines.append(line)
	return "\n".join(normalized_lines)

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
					except ValueError as e:
						# Apparently not a number. Look up the corresponding number.
						try:
							month = grammar['_months'][result.group("month").lower()]
						except KeyError as e:
							# Unknown month name, default to 0
							month = 0

					try:
						hour = int(result.group("hour"))
					except IndexError as e:
						hour = 0
					except TypeError as e:
						hour = 0

					try:
						minute = int(result.group("minute"))
					except IndexError as e:
						minute = 0
					except TypeError as e:
						minute = 0

					try:
						second = int(result.group("second"))
					except IndexError as e:
						second = 0
					except TypeError as e:
						second = 0

					break
				except ValueError as e:
					# Something went horribly wrong, maybe there is no valid date present?
					year = 0
					month = 0
					day = 0
					hour = 0
					minute = 0
					second = 0
					print(e.message) # FIXME: This should have proper logging of some sort...?
		try:
			if year > 0:
				try:
					parsed_dates.append(datetime.datetime(year, month, day, hour, minute, second))
				except ValueError as e:
					# We might have gotten the day and month the wrong way around, let's try it the other way around
					# If you're not using an ISO-standard date format, you're an evil registrar!
					parsed_dates.append(datetime.datetime(year, day, month, hour, minute, second))
		except UnboundLocalError as e:
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

def remove_suffixes(data):
	# Removes everything before and after the first non-whitespace continuous string.
	# Used to get rid of IP suffixes for nameservers.
	cleaned_list = []
	
	for entry in data:
		cleaned_list.append(re.search("([^\s]+)\s*[\s]*", entry).group(1).lstrip())
		
	return cleaned_list

def preprocess_regex(regex):
	return re.sub(r"\\s\*\(\?P<([^>]+)>\.\+\)", r"\s*(?P<\1>\S.*)", regex)

def parse_registrants(data):
	registrant = None
	tech_contact = None
	billing_contact = None
	admin_contact = None

	registrant_regexes = [
		"   Registrant:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n", # Corporate Domains, Inc.
		"Registrant:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", # OVH
		"Registrant ID:(?P<handle>.+)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Street1?:(?P<street1>.*)\n(?:Registrant Street2:(?P<street2>.*)\n)?(?:Registrant Street3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\nRegistrant State/Province:(?P<state>.*)\nRegistrant Postal Code:(?P<postalcode>.*)\nRegistrant Country:(?P<country>.*)\nRegistrant Phone:(?P<phone>.*)\n(?:Registrant Phone Ext.:(?P<phone_ext>.*)\n)?(?:Registrant FAX:(?P<fax>.*)\n)?(?:Registrant FAX Ext.:(?P<fax_ext>.*)\n)?Registrant Email:(?P<email>.*)", # Public Interest Registry (.org), nic.pw
		"Registrant ID:(?P<handle>.+)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Address1?:(?P<street1>.*)\n(?:Registrant Address2:(?P<street2>.*)\n)?(?:Registrant Address3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\nRegistrant State/Province:(?P<state>.*)\nRegistrant Country/Economy:(?P<country>.*)\nRegistrant Postal Code:(?P<postalcode>.*)\nRegistrant Phone:(?P<phone>.*)\n(?:Registrant Phone Ext.:(?P<phone_ext>.*)\n)?(?:Registrant FAX:(?P<fax>.*)\n)?(?:Registrant FAX Ext.:(?P<fax_ext>.*)\n)?Registrant E-mail:(?P<email>.*)", # .ME, DotAsia
		"Registrant ID:\s*(?P<handle>.+)\nRegistrant Name:\s*(?P<name>.+)\nRegistrant Organization:\s*(?P<organization>.*)\nRegistrant Address1:\s*(?P<street1>.+)\nRegistrant Address2:\s*(?P<street2>.*)\nRegistrant City:\s*(?P<city>.+)\nRegistrant State/Province:\s*(?P<state>.+)\nRegistrant Postal Code:\s*(?P<postalcode>.+)\nRegistrant Country:\s*(?P<country>.+)\nRegistrant Country Code:\s*(?P<country_code>.+)\nRegistrant Phone Number:\s*(?P<phone>.+)\nRegistrant Email:\s*(?P<email>.+)\n", # .CO Internet
		"Registrant Contact: (?P<handle>.+)\nRegistrant Organization: (?P<organization>.+)\nRegistrant Name: (?P<name>.+)\nRegistrant Street: (?P<street>.+)\nRegistrant City: (?P<city>.+)\nRegistrant Postal Code: (?P<postalcode>.+)\nRegistrant State: (?P<state>.+)\nRegistrant Country: (?P<country>.+)\nRegistrant Phone: (?P<phone>.*)\nRegistrant Phone Ext: (?P<phone_ext>.*)\nRegistrant Fax: (?P<fax>.*)\nRegistrant Fax Ext: (?P<fax_ext>.*)\nRegistrant Email: (?P<email>.*)\n", # Key-Systems GmbH
		"(?:Registrant ID:[ ]*(?P<handle>.*)\n)?Registrant Name:[ ]*(?P<name>.*)\n(?:Registrant Organization:[ ]*(?P<organization>.*)\n)?Registrant Street:[ ]*(?P<street1>.+)\n(?:Registrant Street:[ ]*(?P<street2>.+)\n)?(?:Registrant Street:[ ]*(?P<street3>.+)\n)?Registrant City:[ ]*(?P<city>.+)\nRegistrant State(?:\/Province)?:[ ]*(?P<state>.*)\nRegistrant Postal Code:[ ]*(?P<postalcode>.+)\nRegistrant Country:[ ]*(?P<country>.+)\n(?:Registrant Phone:[ ]*(?P<phone>.*)\n)?(?:Registrant Phone Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Registrant Fax:[ ]*(?P<fax>.*)\n)?(?:Registrant Fax Ext:[ ]*(?P<fax_ext>.*)\n)?(?:Registrant Email:[ ]*(?P<email>.+)\n)?", # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
		"Registrant\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", # internet.bs
		" Registrant Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)", # Whois.com
		"owner-id:[ ]*(?P<handle>.*)\n(?:owner-organization:[ ]*(?P<organization>.*)\n)?owner-name:[ ]*(?P<name>.*)\nowner-street:[ ]*(?P<street>.*)\nowner-city:[ ]*(?P<city>.*)\nowner-zip:[ ]*(?P<postalcode>.*)\nowner-country:[ ]*(?P<country>.*)\n(?:owner-phone:[ ]*(?P<phone>.*)\n)?(?:owner-fax:[ ]*(?P<fax>.*)\n)?owner-email:[ ]*(?P<email>.*)", # InterNetworX
		"Registrant:\n registrant_org: (?P<organization>.*)\n registrant_name: (?P<name>.*)\n registrant_email: (?P<email>.*)\n registrant_address: (?P<address>.*)\n registrant_city: (?P<city>.*)\n registrant_state: (?P<state>.*)\n registrant_zip: (?P<postalcode>.*)\n registrant_country: (?P<country>.*)\n registrant_phone: (?P<phone>.*)", # Bellnames
		"Holder of domain name:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\nContractual Language", # nic.ch
		"\n\n(?:Owner)?\s+: (?P<name>.*)\n(?:\s+: (?P<organization>.*)\n)?\s+: (?P<street>.*)\n\s+: (?P<city>.*)\n\s+: (?P<state>.*)\n\s+: (?P<country>.*)\n", # nic.io
		"Contact Information:\n\[Name\]\s*(?P<name>.*)\n\[Email\]\s*(?P<email>.*)\n\[Web Page\]\s*(?P<url>.*)\n\[Postal code\]\s*(?P<postalcode>.*)\n\[Postal Address\]\s*(?P<street1>.*)\n(?:\s+(?P<street2>.*)\n)?(?:\s+(?P<street3>.*)\n)?\[Phone\]\s*(?P<phone>.*)\n\[Fax\]\s*(?P<fax>.*)\n", # jprs.jp
		"Registrant ID:[ ]*(?P<handle>.*)\nRegistrant Name:[ ]*(?P<name>.*)\n(?:Registrant Organization:[ ]*(?P<organization>.*)\n)?Registrant Address1:[ ]*(?P<street1>.*)\n(?:Registrant Address2:[ ]*(?P<street2>.*)\n)?(?:Registrant Address3:[ ]*(?P<street3>.*)\n)?Registrant City:[ ]*(?P<city>.*)\nRegistrant State/Province:[ ]*(?P<state>.*)\nRegistrant Postal Code:[ ]*(?P<postalcode>.*)\nRegistrant Country:[ ]*(?P<country>.*)\nRegistrant Country Code:[ ]*.*\nRegistrant Phone Number:[ ]*(?P<phone>.*)\n(?:Registrant Facsimile Number:[ ]*(?P<facsimile>.*)\n)?Registrant Email:[ ]*(?P<email>.*)", # .US (NeuStar)
		"  Organisation Name[.]* (?P<name>.*)\n  Organisation Address[.]* (?P<street1>.*)\n  Organisation Address[.]* (?P<street2>.*)\n(?:  Organisation Address[.]* (?P<street3>.*)\n)?  Organisation Address[.]* (?P<city>.*)\n  Organisation Address[.]* (?P<postalcode>.*)\n  Organisation Address[.]* (?P<state>.*)\n  Organisation Address[.]* (?P<country>.*)", # Melbourne IT (what a horrid format...)
		"Registrant:[ ]*(?P<name>.+)\n[\s\S]*Eligibility Name:[ ]*(?P<organization>.+)\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n", # .au business
		"Eligibility Type:[ ]*Citizen\/Resident\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n[\s\S]*Registrant Contact Name:[ ]*(?P<name>.+)\n", # .au individual
		"Registrant:[ ]*(?P<organization>.+)\n[\s\S]*Eligibility Type:[ ]*(Higher Education Institution|Company|Incorporated Association|Other)\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n[\s\S]*Registrant Contact Name:[ ]*(?P<name>.+)\n", # .au educational, company, 'incorporated association' (non-profit?), other (spotted for linux.conf.au, unsure if also for others)
		"    Registrant:\n        (?P<name>.+)\n\n    Registrant type:\n        .*\n\n    Registrant's address:\n        The registrant .* opted to have", # Nominet (.uk) with hidden address
		"    Registrant:\n        (?P<name>.+)\n\n[\s\S]*    Registrant type:\n        .*\n\n    Registrant's address:\n        (?P<street1>.+)\n(?:        (?P<street2>.+)\n(?:        (?P<street3>.+)\n)??)??        (?P<city>[^0-9\n]+)\n(?:        (?P<state>.+)\n)?        (?P<postalcode>.+)\n        (?P<country>.+)\n\n", # Nominet (.uk) with visible address
		"Domain Owner:\n\t(?P<organization>.+)\n\n[\s\S]*?(?:Registrant Contact:\n\t(?P<name>.+))?\n\nRegistrant(?:'s)? (?:a|A)ddress:(?:\n\t(?P<street1>.+)\n(?:\t(?P<street2>.+)\n)?(?:\t(?P<street3>.+)\n)?\t(?P<city>.+)\n\t(?P<postalcode>.+))?\n\t(?P<country>.+)(?:\n\t(?P<phone>.+) \(Phone\)\n\t(?P<fax>.+) \(FAX\)\n\t(?P<email>.+))?\n\n", # .ac.uk - what a mess...
		"Registrant contact:\n  (?P<name>.+)\n  (?P<street>.*)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n\n", # Fabulous.com
		"registrant-name:\s*(?P<name>.+)\nregistrant-type:\s*(?P<type>.+)\nregistrant-address:\s*(?P<street>.+)\nregistrant-postcode:\s*(?P<postalcode>.+)\nregistrant-city:\s*(?P<city>.+)\nregistrant-country:\s*(?P<country>.+)\n(?:registrant-phone:\s*(?P<phone>.+)\n)?(?:registrant-email:\s*(?P<email>.+)\n)?", # Hetzner
		"Registrant Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", # GAL Communication
		"Contact Information : For Customer # [0-9]+[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", # GAL Communication alternative (private WHOIS) format?
		"   Registrant:\n      (?P<name>.+)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)", # .am
		"owner:\s+(?P<name>.+)", # .br
		"person:\s+(?P<name>.+)", # nic.ru (person)
		"org:\s+(?P<organization>.+)", # nic.ru (organization)
	]

	tech_contact_regexes = [
		"   Technical Contact:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n", # Corporate Domains, Inc.
		"Technical Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", # OVH
		"Tech ID:(?P<handle>.+)\nTech Name:(?P<name>.*)\n(:?Tech Organization:(?P<organization>.*)\n)?Tech Street1?:(?P<street1>.*)\n(?:Tech Street2:(?P<street2>.*)\n)?(?:Tech Street3:(?P<street3>.*)\n)?Tech City:(?P<city>.*)\nTech State/Province:(?P<state>.*)\nTech Postal Code:(?P<postalcode>.*)\nTech Country:(?P<country>.*)\nTech Phone:(?P<phone>.*)\n(?:Tech Phone Ext.:(?P<phone_ext>.*)\n)?(?:Tech FAX:(?P<fax>.*)\n)?(?:Tech FAX Ext.:(?P<fax_ext>.*)\n)?Tech Email:(?P<email>.*)", # Public Interest Registry (.org), nic.pw
		"Tech(?:nical)? ID:(?P<handle>.+)\nTech(?:nical)? Name:(?P<name>.*)\n(?:Tech(?:nical)? Organization:(?P<organization>.*)\n)?Tech(?:nical)? Address1?:(?P<street1>.*)\n(?:Tech(?:nical)? Address2:(?P<street2>.*)\n)?(?:Tech(?:nical)? Address3:(?P<street3>.*)\n)?Tech(?:nical)? City:(?P<city>.*)\nTech(?:nical)? State/Province:(?P<state>.*)\nTech(?:nical)? Country/Economy:(?P<country>.*)\nTech(?:nical)? Postal Code:(?P<postalcode>.*)\nTech(?:nical)? Phone:(?P<phone>.*)\n(?:Tech(?:nical)? Phone Ext.:(?P<phone_ext>.*)\n)?(?:Tech(?:nical)? FAX:(?P<fax>.*)\n)?(?:Tech(?:nical)? FAX Ext.:(?P<fax_ext>.*)\n)?Tech(?:nical)? E-mail:(?P<email>.*)", # .ME, DotAsia
		"Technical Contact ID:\s*(?P<handle>.+)\nTechnical Contact Name:\s*(?P<name>.+)\nTechnical Contact Organization:\s*(?P<organization>.*)\nTechnical Contact Address1:\s*(?P<street1>.+)\nTechnical Contact Address2:\s*(?P<street2>.*)\nTechnical Contact City:\s*(?P<city>.+)\nTechnical Contact State/Province:\s*(?P<state>.+)\nTechnical Contact Postal Code:\s*(?P<postalcode>.+)\nTechnical Contact Country:\s*(?P<country>.+)\nTechnical Contact Country Code:\s*(?P<country_code>.+)\nTechnical Contact Phone Number:\s*(?P<phone>.+)\nTechnical Contact Email:\s*(?P<email>.+)\n", # .CO Internet
		"Tech Contact: (?P<handle>.+)\nTech Organization: (?P<organization>.+)\nTech Name: (?P<name>.+)\nTech Street: (?P<street>.+)\nTech City: (?P<city>.+)\nTech Postal Code: (?P<postalcode>.+)\nTech State: (?P<state>.+)\nTech Country: (?P<country>.+)\nTech Phone: (?P<phone>.*)\nTech Phone Ext: (?P<phone_ext>.*)\nTech Fax: (?P<fax>.*)\nTech Fax Ext: (?P<fax_ext>.*)\nTech Email: (?P<email>.*)\n", # Key-Systems GmbH
		"(?:Tech ID:[ ]*(?P<handle>.*)\n)?Tech[ ]*Name:[ ]*(?P<name>.*)\n(?:Tech[ ]*Organization:[ ]*(?P<organization>.*)\n)?Tech[ ]*Street:[ ]*(?P<street1>.+)\n(?:Tech[ ]*Street:[ ]*(?P<street2>.+)\n)?(?:Tech[ ]*Street:[ ]*(?P<street3>.+)\n)?Tech[ ]*City:[ ]*(?P<city>.+)\nTech[ ]*State(?:\/Province)?:[ ]*(?P<state>.*)\nTech[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nTech[ ]*Country:[ ]*(?P<country>.+)\n(?:Tech[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Tech[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Tech[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Tech[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Tech[ ]*Email:[ ]*(?P<email>.+)\n)?", # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
		"Technical Contact\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", # internet.bs
		" Technical Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)", # Whois.com
		"tech-id:[ ]*(?P<handle>.*)\n(?:tech-organization:[ ]*(?P<organization>.*)\n)?tech-name:[ ]*(?P<name>.*)\ntech-street:[ ]*(?P<street>.*)\ntech-city:[ ]*(?P<city>.*)\ntech-zip:[ ]*(?P<postalcode>.*)\ntech-country:[ ]*(?P<country>.*)\n(?:tech-phone:[ ]*(?P<phone>.*)\n)?(?:tech-fax:[ ]*(?P<fax>.*)\n)?tech-email:[ ]*(?P<email>.*)", # InterNetworX
		"Technical Contact:\n tech_org: (?P<organization>.*)\n tech_name: (?P<name>.*)\n tech_email: (?P<email>.*)\n tech_address: (?P<address>.*)\n tech_city: (?P<city>.*)\n tech_state: (?P<state>.*)\n tech_zip: (?P<postalcode>.*)\n tech_country: (?P<country>.*)\n tech_phone: (?P<phone>.*)", # Bellnames
		"Technical contact:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\n\n", # nic.ch
		"Tech Contact ID:[ ]*(?P<handle>.+)\nTech Contact Name:[ ]*(?P<name>.+)", # .au
		"Technical Contact ID:[ ]*(?P<handle>.*)\nTechnical Contact Name:[ ]*(?P<name>.*)\n(?:Technical Contact Organization:[ ]*(?P<organization>.*)\n)?Technical Contact Address1:[ ]*(?P<street1>.*)\n(?:Technical Contact Address2:[ ]*(?P<street2>.*)\n)?(?:Technical Contact Address3:[ ]*(?P<street3>.*)\n)?Technical Contact City:[ ]*(?P<city>.*)\nTechnical Contact State/Province:[ ]*(?P<state>.*)\nTechnical Contact Postal Code:[ ]*(?P<postalcode>.*)\nTechnical Contact Country:[ ]*(?P<country>.*)\nTechnical Contact Country Code:[ ]*.*\nTechnical Contact Phone Number:[ ]*(?P<phone>.*)\n(?:Technical Contact Facsimile Number:[ ]*(?P<facsimile>.*)\n)?Technical Contact Email:[ ]*(?P<email>.*)", # .US (NeuStar)
		"Tech Name[.]* (?P<name>.*)\n  Tech Address[.]* (?P<street1>.*)\n  Tech Address[.]* (?P<street2>.*)\n(?:  Tech Address[.]* (?P<street3>.*)\n)?  Tech Address[.]* (?P<city>.*)\n  Tech Address[.]* (?P<postalcode>.*)\n  Tech Address[.]* (?P<state>.*)\n  Tech Address[.]* (?P<country>.*)\n  Tech Email[.]* (?P<email>.*)\n  Tech Phone[.]* (?P<phone>.*)\n  Tech Fax[.]* (?P<fax>.*)", # Melbourne IT
		"Technical contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n", # Fabulous.com
		"tech-c-name:\s*(?P<name>.+)\ntech-c-type:\s*(?P<type>.+)\ntech-c-address:\s*(?P<street>.+)\ntech-c-postcode:\s*(?P<postalcode>.+)\ntech-c-city:\s*(?P<city>.+)\ntech-c-country:\s*(?P<country>.+)\n(?:tech-c-phone:\s*(?P<phone>.+)\n)?(?:tech-c-email:\s*(?P<email>.+)\n)?", # Hetzner
		"Admin Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", # GAL Communication
		"   Technical contact:\n      (?P<name>.+)\n      (?P<organization>.*)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)\n      (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)", # .am
		"Technical:\n\s*Name:\s*(?P<name>.*)\n\s*Organisation:\s*(?P<organization>.*)\n\s*Language:.*\n\s*Phone:\s*(?P<phone>.*)\n\s*Fax:\s*(?P<fax>.*)\n\s*Email:\s*(?P<email>.*)\n", # EURid
                "\[Zone-C\]\nType: (?P<type>.+)\nName: (?P<name>.+)\n(Organisation: (?P<organization>.+)\n){0,1}(Address: (?P<street1>.+)\n){1}(Address: (?P<street2>.+)\n){0,1}(Address: (?P<street3>.+)\n){0,1}(Address: (?P<street4>.+)\n){0,1}PostalCode: (?P<postalcode>.+)\nCity: (?P<city>.+)\nCountryCode: (?P<country>[A-Za-z]{2})\nPhone: (?P<phone>.+)\nFax: (?P<fax>.+)\nEmail: (?P<email>.+)\n(Remarks: (?P<remark>.+)\n){0,1}Changed: (?P<changed>.+)", # DeNIC
	]

	admin_contact_regexes = [
		"   Administrative Contact:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n", # Corporate Domains, Inc.
		"Administrative Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", # OVH
		"Admin ID:(?P<handle>.+)\nAdmin Name:(?P<name>.*)\n(?:Admin Organization:(?P<organization>.*)\n)?Admin Street1?:(?P<street1>.*)\n(?:Admin Street2:(?P<street2>.*)\n)?(?:Admin Street3:(?P<street3>.*)\n)?Admin City:(?P<city>.*)\nAdmin State/Province:(?P<state>.*)\nAdmin Postal Code:(?P<postalcode>.*)\nAdmin Country:(?P<country>.*)\nAdmin Phone:(?P<phone>.*)\n(?:Admin Phone Ext.:(?P<phone_ext>.*)\n)?(?:Admin FAX:(?P<fax>.*)\n)?(?:Admin FAX Ext.:(?P<fax_ext>.*)\n)?Admin Email:(?P<email>.*)", # Public Interest Registry (.org), nic.pw
		"Admin(?:istrative)? ID:(?P<handle>.+)\nAdmin(?:istrative)? Name:(?P<name>.*)\n(?:Admin(?:istrative)? Organization:(?P<organization>.*)\n)?Admin(?:istrative)? Address1?:(?P<street1>.*)\n(?:Admin(?:istrative)? Address2:(?P<street2>.*)\n)?(?:Admin(?:istrative)? Address3:(?P<street3>.*)\n)?Admin(?:istrative)? City:(?P<city>.*)\nAdmin(?:istrative)? State/Province:(?P<state>.*)\nAdmin(?:istrative)? Country/Economy:(?P<country>.*)\nAdmin(?:istrative)? Postal Code:(?P<postalcode>.*)\nAdmin(?:istrative)? Phone:(?P<phone>.*)\n(?:Admin(?:istrative)? Phone Ext.:(?P<phone_ext>.*)\n)?(?:Admin(?:istrative)? FAX:(?P<fax>.*)\n)?(?:Admin(?:istrative)? FAX Ext.:(?P<fax_ext>.*)\n)?Admin(?:istrative)? E-mail:(?P<email>.*)", # .ME, DotAsia
		"Administrative Contact ID:\s*(?P<handle>.+)\nAdministrative Contact Name:\s*(?P<name>.+)\nAdministrative Contact Organization:\s*(?P<organization>.*)\nAdministrative Contact Address1:\s*(?P<street1>.+)\nAdministrative Contact Address2:\s*(?P<street2>.*)\nAdministrative Contact City:\s*(?P<city>.+)\nAdministrative Contact State/Province:\s*(?P<state>.+)\nAdministrative Contact Postal Code:\s*(?P<postalcode>.+)\nAdministrative Contact Country:\s*(?P<country>.+)\nAdministrative Contact Country Code:\s*(?P<country_code>.+)\nAdministrative Contact Phone Number:\s*(?P<phone>.+)\nAdministrative Contact Email:\s*(?P<email>.+)\n", # .CO Internet
		"Admin Contact: (?P<handle>.+)\nAdmin Organization: (?P<organization>.+)\nAdmin Name: (?P<name>.+)\nAdmin Street: (?P<street>.+)\nAdmin City: (?P<city>.+)\nAdmin State: (?P<state>.+)\nAdmin Postal Code: (?P<postalcode>.+)\nAdmin Country: (?P<country>.+)\nAdmin Phone: (?P<phone>.*)\nAdmin Phone Ext: (?P<phone_ext>.*)\nAdmin Fax: (?P<fax>.*)\nAdmin Fax Ext: (?P<fax_ext>.*)\nAdmin Email: (?P<email>.*)\n", # Key-Systems GmbH
		"(?:Admin ID:[ ]*(?P<handle>.*)\n)?Admin[ ]*Name:[ ]*(?P<name>.*)\n(?:Admin[ ]*Organization:[ ]*(?P<organization>.*)\n)?Admin[ ]*Street:[ ]*(?P<street1>.+)\n(?:Admin[ ]*Street:[ ]*(?P<street2>.+)\n)?(?:Admin[ ]*Street:[ ]*(?P<street3>.+)\n)?Admin[ ]*City:[ ]*(?P<city>.+)\nAdmin[ ]*State(?:\/Province)?:[ ]*(?P<state>.*)\nAdmin[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nAdmin[ ]*Country:[ ]*(?P<country>.+)\n(?:Admin[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Admin[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Admin[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Admin[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Admin[ ]*Email:[ ]*(?P<email>.+)\n)?", # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
		"Administrative Contact\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", # internet.bs
		" Administrative Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)", # Whois.com
		"admin-id:[ ]*(?P<handle>.*)\n(?:admin-organization:[ ]*(?P<organization>.*)\n)?admin-name:[ ]*(?P<name>.*)\nadmin-street:[ ]*(?P<street>.*)\nadmin-city:[ ]*(?P<city>.*)\nadmin-zip:[ ]*(?P<postalcode>.*)\nadmin-country:[ ]*(?P<country>.*)\n(?:admin-phone:[ ]*(?P<phone>.*)\n)?(?:admin-fax:[ ]*(?P<fax>.*)\n)?admin-email:[ ]*(?P<email>.*)", # InterNetworX
		"Administrative Contact:\n admin_org: (?P<organization>.*)\n admin_name: (?P<name>.*)\n admin_email: (?P<email>.*)\n admin_address: (?P<address>.*)\n admin_city: (?P<city>.*)\n admin_state: (?P<state>.*)\n admin_zip: (?P<postalcode>.*)\n admin_country: (?P<country>.*)\n admin_phone: (?P<phone>.*)", # Bellnames
		"Administrative Contact ID:[ ]*(?P<handle>.*)\nAdministrative Contact Name:[ ]*(?P<name>.*)\n(?:Administrative Contact Organization:[ ]*(?P<organization>.*)\n)?Administrative Contact Address1:[ ]*(?P<street1>.*)\n(?:Administrative Contact Address2:[ ]*(?P<street2>.*)\n)?(?:Administrative Contact Address3:[ ]*(?P<street3>.*)\n)?Administrative Contact City:[ ]*(?P<city>.*)\nAdministrative Contact State/Province:[ ]*(?P<state>.*)\nAdministrative Contact Postal Code:[ ]*(?P<postalcode>.*)\nAdministrative Contact Country:[ ]*(?P<country>.*)\nAdministrative Contact Country Code:[ ]*.*\nAdministrative Contact Phone Number:[ ]*(?P<phone>.*)\n(?:Administrative Contact Facsimile Number:[ ]*(?P<facsimile>.*)\n)?Administrative Contact Email:[ ]*(?P<email>.*)", # .US (NeuStar)
		"Admin Name[.]* (?P<name>.*)\n  Admin Address[.]* (?P<street1>.*)\n  Admin Address[.]* (?P<street2>.*)\n(?:  Admin Address[.]* (?P<street3>.*)\n)?  Admin Address[.]* (?P<city>.*)\n  Admin Address[.]* (?P<postalcode>.*)\n  Admin Address[.]* (?P<state>.*)\n  Admin Address[.]* (?P<country>.*)\n  Admin Email[.]* (?P<email>.*)\n  Admin Phone[.]* (?P<phone>.*)\n  Admin Fax[.]* (?P<fax>.*)", # Melbourne IT
		"Administrative contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n", # Fabulous.com
		"admin-c-name:\s*(?P<name>.+)\nadmin-c-type:\s*(?P<type>.+)\nadmin-c-address:\s*(?P<street>.+)\nadmin-c-postcode:\s*(?P<postalcode>.+)\nadmin-c-city:\s*(?P<city>.+)\nadmin-c-country:\s*(?P<country>.+)\n(?:admin-c-phone:\s*(?P<phone>.+)\n)?(?:admin-c-email:\s*(?P<email>.+)\n)?", # Hetzner
		"Tech Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", # GAL Communication
		"   Administrative contact:\n      (?P<name>.+)\n      (?P<organization>.*)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)\n      (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)", # .am
                "\[Tech-C\]\nType: (?P<type>.+)\nName: (?P<name>.+)\n(Organisation: (?P<organization>.+)\n){0,1}(Address: (?P<street1>.+)\n){1}(Address: (?P<street2>.+)\n){0,1}(Address: (?P<street3>.+)\n){0,1}(Address: (?P<street4>.+)\n){0,1}PostalCode: (?P<postalcode>.+)\nCity: (?P<city>.+)\nCountryCode: (?P<country>[A-Za-z]{2})\nPhone: (?P<phone>.+)\nFax: (?P<fax>.+)\nEmail: (?P<email>.+)\n(Remarks: (?P<remark>.+)\n){0,1}Changed: (?P<changed>.+)", # DeNIC
	]

	billing_contact_regexes = [
		"Billing ID:(?P<handle>.+)\nBilling Name:(?P<name>.*)\nBilling Organization:(?P<organization>.*)\nBilling Street1:(?P<street1>.*)\n(?:Billing Street2:(?P<street2>.*)\n)?(?:Billing Street3:(?P<street3>.*)\n)?Billing City:(?P<city>.*)\nBilling State/Province:(?P<state>.*)\nBilling Postal Code:(?P<postalcode>.*)\nBilling Country:(?P<country>.*)\nBilling Phone:(?P<phone>.*)\n(?:Billing Phone Ext.:(?P<phone_ext>.*)\n)?(?:Billing FAX:(?P<fax>.*)\n)?(?:Billing FAX Ext.:(?P<fax_ext>.*)\n)?Billing Email:(?P<email>.*)", # nic.pw
		"Billing ID:(?P<handle>.+)\nBilling Name:(?P<name>.*)\n(?:Billing Organization:(?P<organization>.*)\n)?Billing Address1?:(?P<street1>.*)\n(?:Billing Address2:(?P<street2>.*)\n)?(?:Billing Address3:(?P<street3>.*)\n)?Billing City:(?P<city>.*)\nBilling State/Province:(?P<state>.*)\nBilling Country/Economy:(?P<country>.*)\nBilling Postal Code:(?P<postalcode>.*)\nBilling Phone:(?P<phone>.*)\n(?:Billing Phone Ext.:(?P<phone_ext>.*)\n)?(?:Billing FAX:(?P<fax>.*)\n)?(?:Billing FAX Ext.:(?P<fax_ext>.*)\n)?Billing E-mail:(?P<email>.*)", # DotAsia
		"Billing Contact ID:\s*(?P<handle>.+)\nBilling Contact Name:\s*(?P<name>.+)\nBilling Contact Organization:\s*(?P<organization>.*)\nBilling Contact Address1:\s*(?P<street1>.+)\nBilling Contact Address2:\s*(?P<street2>.*)\nBilling Contact City:\s*(?P<city>.+)\nBilling Contact State/Province:\s*(?P<state>.+)\nBilling Contact Postal Code:\s*(?P<postalcode>.+)\nBilling Contact Country:\s*(?P<country>.+)\nBilling Contact Country Code:\s*(?P<country_code>.+)\nBilling Contact Phone Number:\s*(?P<phone>.+)\nBilling Contact Email:\s*(?P<email>.+)\n", # .CO Internet
		"Billing Contact: (?P<handle>.+)\nBilling Organization: (?P<organization>.+)\nBilling Name: (?P<name>.+)\nBilling Street: (?P<street>.+)\nBilling City: (?P<city>.+)\nBilling Postal Code: (?P<postalcode>.+)\nBilling State: (?P<state>.+)\nBilling Country: (?P<country>.+)\nBilling Phone: (?P<phone>.*)\nBilling Phone Ext: (?P<phone_ext>.*)\nBilling Fax: (?P<fax>.*)\nBilling Fax Ext: (?P<fax_ext>.*)\nBilling Email: (?P<email>.*)\n", # Key-Systems GmbH
		"(?:Billing ID:[ ]*(?P<handle>.*)\n)?Billing[ ]*Name:[ ]*(?P<name>.*)\n(?:Billing[ ]*Organization:[ ]*(?P<organization>.*)\n)?Billing[ ]*Street:[ ]*(?P<street1>.+)\n(?:Billing[ ]*Street:[ ]*(?P<street2>.+)\n)?Billing[ ]*City:[ ]*(?P<city>.+)\nBilling[ ]*State\/Province:[ ]*(?P<state>.+)\nBilling[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nBilling[ ]*Country:[ ]*(?P<country>.+)\n(?:Billing[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Billing[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Billing[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Billing[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Billing[ ]*Email:[ ]*(?P<email>.+)\n)?", # Musedoma (.museum)
		"Billing Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", # OVH
		" Billing Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)", # Whois.com
		"billing-id:[ ]*(?P<handle>.*)\n(?:billing-organization:[ ]*(?P<organization>.*)\n)?billing-name:[ ]*(?P<name>.*)\nbilling-street:[ ]*(?P<street>.*)\nbilling-city:[ ]*(?P<city>.*)\nbilling-zip:[ ]*(?P<postalcode>.*)\nbilling-country:[ ]*(?P<country>.*)\n(?:billing-phone:[ ]*(?P<phone>.*)\n)?(?:billing-fax:[ ]*(?P<fax>.*)\n)?billing-email:[ ]*(?P<email>.*)", # InterNetworX
		"Billing Contact:\n bill_org: (?P<organization>.*)\n bill_name: (?P<name>.*)\n bill_email: (?P<email>.*)\n bill_address: (?P<address>.*)\n bill_city: (?P<city>.*)\n bill_state: (?P<state>.*)\n bill_zip: (?P<postalcode>.*)\n bill_country: (?P<country>.*)\n bill_phone: (?P<phone>.*)", # Bellnames
		"Billing Contact ID:[ ]*(?P<handle>.*)\nBilling Contact Name:[ ]*(?P<name>.*)\n(?:Billing Contact Organization:[ ]*(?P<organization>.*)\n)?Billing Contact Address1:[ ]*(?P<street1>.*)\n(?:Billing Contact Address2:[ ]*(?P<street2>.*)\n)?(?:Billing Contact Address3:[ ]*(?P<street3>.*)\n)?Billing Contact City:[ ]*(?P<city>.*)\nBilling Contact State/Province:[ ]*(?P<state>.*)\nBilling Contact Postal Code:[ ]*(?P<postalcode>.*)\nBilling Contact Country:[ ]*(?P<country>.*)\nBilling Contact Country Code:[ ]*.*\nBilling Contact Phone Number:[ ]*(?P<phone>.*)\n(?:Billing Contact Facsimile Number:[ ]*(?P<facsimile>.*)\n)?Billing Contact Email:[ ]*(?P<email>.*)", # .US (NeuStar)
		"Billing contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n", # Fabulous.com
		"Billing Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", # GAL Communication
	]

	# Some registries use NIC handle references instead of directly listing contacts...

	nic_contact_regexes = [
		"personname:\s*(?P<name>.+)\norganization:\s*(?P<organization>.+)\nstreet address:\s*(?P<street>.+)\npostal code:\s*(?P<postalcode>.+)\ncity:\s*(?P<city>.+)\ncountry:\s*(?P<country>.+)\n(?:phone:\s*(?P<phone>.+)\n)?(?:fax-no:\s*(?P<fax>.+)\n)?(?:e-mail:\s*(?P<email>.+)\n)?nic-hdl:\s*(?P<handle>.+)\nchanged:\s*(?P<changedate>.+)", # nic.at
		"contact-handle:[ ]*(?P<handle>.+)\ncontact:[ ]*(?P<name>.+)\n(?:organisation:[ ]*(?P<organization>.+)\n)?address:[ ]*(?P<street1>.+)\n(?:address:[ ]*(?P<street2>.+)\n)?(?:address:[ ]*(?P<street3>.+)\n)?(?:address:[ ]*(?P<street4>.+)\n)?address:[ ]*(?P<city>.+)\naddress:[ ]*(?P<state>.+)\naddress:[ ]*(?P<postalcode>.+)\naddress:[ ]*(?P<country>.+)\n(?:phone:[ ]*(?P<phone>.+)\n)?(?:fax:[ ]*(?P<fax>.+)\n)?(?:email:[ ]*(?P<email>.+)\n)?", # LCN.com
		"person:\s*(?P<name>.+)\nnic-hdl:\s*(?P<handle>.+)\n", # .ie
		"nic-hdl:\s*(?P<handle>.+)\ntype:\s*(?P<type>.+)\ncontact:\s*(?P<name>.+)\n(?:.+\n)*?(?:address:\s*(?P<street1>.+)\naddress:\s*(?P<street2>.+)\naddress:\s*(?P<street3>.+)\naddress:\s*(?P<country>.+)\n)?(?:phone:\s*(?P<phone>.+)\n)?(?:fax-no:\s*(?P<fax>.+)\n)?(?:.+\n)*?(?:e-mail:\s*(?P<email>.+)\n)?(?:.+\n)*?changed:\s*(?P<changedate>[0-9]{2}\/[0-9]{2}\/[0-9]{4}).*\n", # AFNIC madness without country field
		"nic-hdl:\s*(?P<handle>.+)\ntype:\s*(?P<type>.+)\ncontact:\s*(?P<name>.+)\n(?:.+\n)*?(?:address:\s*(?P<street1>.+)\n)?(?:address:\s*(?P<street2>.+)\n)?(?:address:\s*(?P<street3>.+)\n)?(?:phone:\s*(?P<phone>.+)\n)?(?:fax-no:\s*(?P<fax>.+)\n)?(?:.+\n)*?(?:e-mail:\s*(?P<email>.+)\n)?(?:.+\n)*?changed:\s*(?P<changedate>[0-9]{2}\/[0-9]{2}\/[0-9]{4}).*\n", # AFNIC madness any country -at all-
		"nic-hdl:\s*(?P<handle>.+)\ntype:\s*(?P<type>.+)\ncontact:\s*(?P<name>.+)\n(?:.+\n)*?(?:address:\s*(?P<street1>.+)\n)?(?:address:\s*(?P<street2>.+)\n)?(?:address:\s*(?P<street3>.+)\n)?(?:address:\s*(?P<street4>.+)\n)?country:\s*(?P<country>.+)\n(?:phone:\s*(?P<phone>.+)\n)?(?:fax-no:\s*(?P<fax>.+)\n)?(?:.+\n)*?(?:e-mail:\s*(?P<email>.+)\n)?(?:.+\n)*?changed:\s*(?P<changedate>[0-9]{2}\/[0-9]{2}\/[0-9]{4}).*\n", # AFNIC madness with country field

	]

	nic_contact_references = {
		"registrant": [
			"registrant:\s*(?P<handle>.+)", # nic.at
			"owner-contact:\s*(?P<handle>.+)", # LCN.com
			"holder-c:\s*(?P<handle>.+)", # AFNIC
			"holder:\s*(?P<handle>.+)", # iis.se (they apparently want to be difficult, and won't give you contact info for the handle over their WHOIS service)
		],
		"tech": [
			"tech-c:\s*(?P<handle>.+)", # nic.at, AFNIC, iis.se
			"technical-contact:\s*(?P<handle>.+)", # LCN.com
		],
		"admin": [
			"admin-c:\s*(?P<handle>.+)", # nic.at, AFNIC, iis.se
			"admin-contact:\s*(?P<handle>.+)", # LCN.com
		],
		"billing": [
			"billing-c:\s*(?P<handle>.+)", # iis.se
			"billing-contact:\s*(?P<handle>.+)", # LCN.com
		]
	}

	# Why do the below? The below is meant to handle with an edge case (issue #2) where a partial match followed
	# by a failure, for a regex containing the \s*.+ pattern, would send the regex module on a wild goose hunt for
	# matching positions. The workaround is to use \S.* instead of .+, but in the interest of keeping the regexes
	# consistent and compact, it's more practical to do this (predictable) conversion on runtime.
	# FIXME: This breaks on NIC contact regex for nic.at. Why?
	registrant_regexes = [preprocess_regex(regex) for regex in registrant_regexes]
	tech_contact_regexes = [preprocess_regex(regex) for regex in tech_contact_regexes]
	admin_contact_regexes = [preprocess_regex(regex) for regex in admin_contact_regexes]
	billing_contact_regexes = [preprocess_regex(regex) for regex in billing_contact_regexes]

	for segment in data:
		for regex in registrant_regexes:
			match = re.search(regex, segment)
			if match is not None:
				registrant = match.groupdict()
				break

	for segment in data:
		for regex in tech_contact_regexes:
			match = re.search(regex, segment)
			if match is not None:
				tech_contact = match.groupdict()
				break

	for segment in data:
		for regex in admin_contact_regexes:
			match = re.search(regex, segment)
			if match is not None:
				admin_contact = match.groupdict()
				break

	for segment in data:
		for regex in billing_contact_regexes:
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
					if data_reference["handle"] == "-" or re.match("https?:\/\/", data_reference["handle"]) is not None:
						pass  # Reference was either blank or a URL; the latter is to deal with false positives for nic.ru
					else:
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
			for key in list(obj.keys()):
				if obj[key] is None or obj[key].strip() == "": # Just chomp all surrounding whitespace
					del obj[key]
				else:
					obj[key] = obj[key].strip()
			if "phone_ext" in obj:
				if "phone" in obj:
					obj["phone"] += " ext. %s" % obj["phone_ext"]
					del obj["phone_ext"]
			if "street1" in obj:
				street_items = []
				i = 1
				while True:
					try:
						street_items.append(obj["street%d" % i])
						del obj["street%d" % i]
					except KeyError as e:
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
			if 'firstname' in obj or 'lastname' in obj:
				elements = []
				if 'firstname' in obj:
					elements.append(obj["firstname"])
				if 'lastname' in obj:
					elements.append(obj["lastname"])
				obj["name"] = " ".join(elements)

	return {
		"registrant": registrant,
		"tech": tech_contact,
		"admin": admin_contact,
		"billing": billing_contact,
	}

#!/usr/bin/python

import re, subprocess, datetime

grammar = {
	"_default": {
		'domain_name':		'Domain Name:\s?(?P<val>.+)',
		'registrar':		'Registrar:\s?(?P<val>.+)',
		'whois_server':		'Whois Server:\s?(?P<val>.+)',
		'referral_url':		'Referral URL:\s?(?P<val>.+)',
		'updated_date':		'Updated Date:\s?(?P<val>.+)',
		'creation_date':	'Creation Date:\s?(?P<val>.+)',
		'expiration_date':	'Expiration Date:\s?(?P<val>.+)',
		'name_servers':		'Name Server:\s?(?P<val>.+)',
		'status':		'Status:\s?(?P<val>.+)'
	},
	"_fallback": {
		'creation_date':	['Created on:\s?(?P<val>.+)',
					 'Created on\s?[.]*:\s?(?P<val>.+)\.',
					 'Date Registered\s?[.]*:\s?(?P<val>.+)',
					 'Domain Created\s?[.]*:\s?(?P<val>.+)',
					 'Domain registered\s?[.]*:\s?(?P<val>.+)',
					 'Domain record activated\s?[.]*:\s*?(?P<val>.+)',
					 'Record created on\s?[.]*:?\s*?(?P<val>.+)',
					 'Record created\s?[.]*:?\s*?(?P<val>.+)',
					 'Created\s?[.]*:?\s*?(?P<val>.+)',
					 'Registered on\s?[.]*:?\s*?(?P<val>.+)',
					 'Domain Registration Date\s?[.]*:?\s*?(?P<val>.+)'],
		'expiration_date':	['Expires on:\s?(?P<val>.+)',
					 'Expires on\s?[.]*:\s?(?P<val>.+)\.',
					 'Expiry Date\s?[.]*:\s?(?P<val>.+)',
					 'Domain Currently Expires\s?[.]*:\s?(?P<val>.+)',
					 'Record will expire on\s?[.]*:\s?(?P<val>.+)',
					 'Domain expires\s?[.]*:\s*?(?P<val>.+)',
					 'Record expires on\s?[.]*:?\s*?(?P<val>.+)',
					 'Record expires\s?[.]*:?\s*?(?P<val>.+)',
					 'Expires\s?[.]*:?\s*?(?P<val>.+)',
					 'Expire Date\s?[.]*:?\s*?(?P<val>.+)',
					 'Domain Expiration Date\s?[.]*:?\s*?(?P<val>.+)'],
		'updated_date':		['Database last updated on\s?[.]*:?\s*?(?P<val>.+)\s[a-z]+\.?',
					 'Record last updated on\s?[.]*:\s?(?P<val>.+)\.',
					 'Domain record last updated\s?[.]*:\s*?(?P<val>.+)',
					 'Domain Last Updated\s?[.]*:\s*?(?P<val>.+)',
					 'Last updated on:\s?(?P<val>.+)',
					 'Date Modified\s?[.]*:\s?(?P<val>.+)',
					 'Last Modified\s?[.]*:\s?(?P<val>.+)',
					 'Domain Last Updated Date\s?[.]*:\s?(?P<val>.+)',
					 'Record last updated\s?[.]*:\s?(?P<val>.+)',
					 'Modified\s?[.]*:\s?(?P<val>.+)',
					 'Last Update\s?[.]*:\s?(?P<val>.+)',
					 'Last update of whois database:\s?[a-z]{3}, (?P<val>.+) [a-z]{3}'],
		'registrar':		['Registered through:\s?(?P<val>.+)',
					 'Registrar Name:\s?(?P<val>.+)',
					 'Record maintained by:\s?(?P<val>.+)',
					 'Registration Service Provided By:\s?(?P<val>.+)',
					 'Registrar of Record:\s?(?P<val>.+)',
					 '\tName:\t\s(?P<val>.+)'],
		'whois_server':		['Registrar Whois:\s?(?P<val>.+)'],
		'name_servers':		['(?P<val>[a-z]*d?ns[0-9]+([a-z]{3})?\.([a-z0-9-]+\.)+[a-z0-9]+)',
					 '(?P<val>[a-z0-9-]+\.d?ns[0-9]*\.([a-z0-9-]+\.)+[a-z0-9]+)',
					 '(?P<val>([a-z0-9-]+\.)+[a-z0-9]+)(\s+([0-9]{1,3}\.){3}[0-9]{1,3})',
					 'DNS[0-9]+:\s*(?P<val>.+)',
					 'ns[0-9]+:\s*(?P<val>.+)',
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
	},
	".*\.ru$": {
		'domain_name':		'domain:\s*(?P<val>.+)',
		'registrar':		'registrar:\s*(?P<val>.+)',
		'creation_date':	'created:\s*(?P<val>.+)',
		'expiration_date':	'paid-till:\s*(?P<val>.+)',
		'name_servers':		'nserver:\s*(?P<val>.+)',
		'status':		'state:\s*(?P<val>.+)',
		'updated_date':		'Last updated on (?P<val>.+) [a-z]{3}'
	},
	".*\.ee$": {
		'domain_name':		'domain:\s*(?P<val>.+)',
		'registrar':		'registrar:\s*(?P<val>.+)',
		'creation_date':	'registered:\s*(?P<val>.+)',
		'expiration_date':	'expire:\s*(?P<val>.+)',
		'name_servers':		'nserver:\s*(?P<val>.+)',
		'status':		'state:\s*(?P<val>.+)'
	},
	".*\.at$": {
		'domain_name':		'domain:\s*(?P<val>.+)',
		'name_servers':		'nserver:\s*(?P<val>.+)',
		'status':		'state:\s*(?P<val>.+)',
		'updated_date':		'changed:\s*(?P<val>.+)'
	}
}

def whois(domain):
	global grammar
	ruleset = None
	
	for regex, rules in grammar.iteritems():
		if regex.startswith("_") == False and re.match(regex, domain):
			ruleset = rules
		
	if ruleset is None:
		ruleset = grammar['_default']
	
	data = {}
	
	ping = subprocess.Popen(["whois", domain], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	out, error = ping.communicate()
	
	for line in out.splitlines():
		for rule_key, rule_regex in ruleset.iteritems():
			result = re.search(rule_regex, line, re.IGNORECASE)
			
			if result is not None:
				val = result.group("val").strip()
				if val != "":
					try:
						data[rule_key].append(val)
					except KeyError, e:
						data[rule_key] = [val]
	
	# Run through fallback detection to gather missing info
	for rule_key, rule_regexes in grammar['_fallback'].iteritems():
		if data.has_key(rule_key) == False:
			for line in out.splitlines():
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
			if data.has_key(rule_key) == False:
				data[rule_key] = None
	
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
		data['name_servers'] = remove_duplicates(data['name_servers'])
	
	if data['emails'] is not None:
		data['emails'] = remove_duplicates(data['emails'])
	
	if data['registrar'] is not None:
		data['registrar'] = remove_duplicates(data['registrar'])
	
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

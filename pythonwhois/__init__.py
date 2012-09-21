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
					 'Domain Created\s?[.]*:\s?(?P<val>.+)'],
		'expiration_date':	['Expires on:\s?(?P<val>.+)',
					 'Expires on\s?[.]*:\s?(?P<val>.+)\.',
					 'Expiry Date\s?[.]*:\s?(?P<val>.+)',
					 'Domain Currently Expires\s?[.]*:\s?(?P<val>.+)'],
		'registrar':		['Registered through:\s?(?P<val>.+)',
					 'Registrar Name:\s?(?P<val>.+)'],
		'whois_server':		['Registrar Whois:\s?(?P<val>.+)'],
		'name_servers':		['(?P<val>d?ns[0-9]+\.[a-z0-9-]+\.[a-z0-9]+)',
					 '(?P<val>[a-z0-9-]+\.d?ns[0-9]*\.[a-z0-9-]+\.[a-z0-9]+)'],
		'emails':		['(?P<val>[\w.-]+@[\w.-]+\.[\w]{2,4})']
	},
	"_dateformats": (
		'(?P<day>[0-9]{1,2})[./ -](?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[./ -](?P<year>[0-9]{4}|[0-9]{2})'
			'(\s+(?P<hour>[0-9]{1,2})[:.](?P<minute>[0-9]{1,2})[:.](?P<second>[0-9]{1,2}))?',
		'(?P<year>[0-9]{4})[./-](?P<month>[0-9]{1,2})[./-](?P<day>[0-9]{1,2})',
		'(?P<day>[0-9]{1,2})(?P<month>[0-9]{1,2})(?P<year>[0-9]{4}|[0-9]{2})',
		'(?P<day>)(?P<month>)(?P<year>)',
		'(?P<day>)(?P<month>)(?P<year>)'
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
		'status':		'state:\s*(?P<val>.+)'
	}
}

def whois(domain):
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
				try:
					data[rule_key].append(result.group("val").strip())
				except KeyError, e:
					data[rule_key] = [result.group("val").strip()]
	
	# Run through fallback detection to gather missing info
	for rule_key, rule_regexes in grammar['_fallback'].iteritems():
		if data.has_key(rule_key) == False:
			for line in out.splitlines():
				for regex in rule_regexes:
					result = re.search(regex, line, re.IGNORECASE)
					
					if result is not None:
						try:
							data[rule_key].append(result.group("val").strip())
						except KeyError, e:
							data[rule_key] = [result.group("val").strip()]
			
			# Fill all missing values with None
			if data.has_key(rule_key) == False:
				data[rule_key] = None
	
	# Parse dates
	if data['expiration_date'] is not None:
		data['expiration_date'] = parse_dates(data['expiration_date'])
	
	if data['creation_date'] is not None:
		data['creation_date'] = parse_dates(data['creation_date'])
	
	return data

def parse_dates(dates):
	parsed_dates = []
	
	for date in dates:
		for rule in grammar['_dateformats']:
			result = re.match(rule, date)
			
			if result is not None:
				# These are always numeric.
				year = int(result.group("year"))
				day = int(result.group("day"))
				
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
				
				try:
					minute = int(result.group("minute"))
				except IndexError, e:
					minute = 0
				
				try:
					second = int(result.group("second"))
				except IndexError, e:
					second = 0
				
				break
		
		parsed_dates.append(datetime.datetime(year, month, day, hour, minute, second))
		
	return parsed_dates

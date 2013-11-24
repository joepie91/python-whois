#!/usr/bin/env python2

import sys, argparse, os, pythonwhois, json, datetime

parser = argparse.ArgumentParser(description="Runs or modifies the test suite for python-whois.")
parser.add_argument("mode", nargs=1, choices=["run", "update"], default="run", help="Whether to run or update the tests. Only update if you know what you're doing!")
parser.add_argument("target", nargs="+", help="The targets to run/modify tests for. Use 'all' to run the full test suite.")
args = parser.parse_args()

OK = '\033[92m'
FAIL = '\033[91m'
ENDC = '\033[0m'

def encoded_json_dumps(obj):
	try:
		return json.dumps(obj, default=json_fallback)
	except UnicodeDecodeError, e:
		return json.dumps(recursive_encode(obj, "latin-1"), default=json_fallback)

def json_fallback(obj):
	if isinstance(obj, datetime.datetime):
		return obj.isoformat()
	else:
		return obj

def recursive_encode(obj, encoding):
	for key in obj.keys():
		if isinstance(obj[key], dict):
			obj[key] = recursive_encode(obj[key], encoding)
		elif isinstance(obj[key], list):
			obj[key] = [x.decode(encoding) for x in obj[key]]
		else:
			try:
				obj[key] = obj[key].decode(encoding)
			except:
				pass
	return obj

def recursive_compare(obj1, obj2, chain=[]):
	errors = []
	chain_name = " -> ".join(chain)
	s1 = set(obj1.keys())
	s2 = set(obj2.keys())
	
	for item in s1.difference(s2):
		errors.append("(%s) Key present in previous data, but missing in current data: %s" % (chain_name, item))
	
	for item in s2.difference(s1):
		errors.append("(%s) New key present in current data, but missing in previous data: %s" % (chain_name, item))
		
	for key in s1.intersection(s2):
		if isinstance(obj1[key], dict) and isinstance(obj2[key], dict):
			errors += recursive_compare(obj1[key], obj2[key], chain + [key])
		elif isinstance(obj1[key], list) and isinstance(obj2[key], list):
			lst1 = [json_fallback(x) for x in obj1[key]]
			lst2 = [json_fallback(x) for x in obj2[key]]
			if set(lst1) != set(lst2):
				errors.append("(%s) List mismatch in key %s.\n   [old] %s\n   [new] %s" % (chain_name, key, set(lst1), set(lst2)))
		else:
			if json_fallback(obj1[key]) != json_fallback(obj2[key]):
				errors.append("(%s) Data mismatch in key %s.\n   [old] %s\n   [new] %s" % (chain_name, key, json_fallback(obj1[key]), json_fallback(obj2[key])))
				
	return errors

if "all" in args.target:
	targets = os.listdir("test/data")
else:
	targets = args.target

targets.sort()

if args.mode[0] == "run":
	errors = False
	suites = []
	for target in targets:
		try:
			with open(os.path.join("test/data", target), "r") as f:
				data = f.read().split("\n--\n")
		except IOError, e:
			sys.stderr.write("Invalid domain %(domain)s specified. No test case or base data exists.\n" % {"domain": target})
			errors = True
			continue
		try:			
			with open(os.path.join("test/target_default", target), "r") as f:
				default = f.read()
			with open(os.path.join("test/target_normalized", target), "r") as f:
				normalized = f.read()
		except IOError, e:
			sys.stderr.write("Missing target data for domain %(domain)s. Run `./test.py update %(domain)s` to correct this, after verifying that pythonwhois can correctly parse this particular domain.\n" % {"domain": target})
			errors = True
			continue
		
		suites.append((target, data, default, normalized))

	if errors:
		exit(1)
		
	total_errors = 0
	total_failed = 0
	total_passed = 0
	done = 1
	total = len(suites) * 2
	for target, data, target_default, target_normalized in suites:
		for normalization in (True, []):
			parsed = pythonwhois.parse.parse_raw_whois(data, normalized=normalization)
			parsed = json.loads(encoded_json_dumps(parsed)) # Stupid Unicode hack
			
			if normalization == True:
				target_data = json.loads(target_normalized)
			else:
				target_data = json.loads(target_default)
			
			errors = recursive_compare(target_data, parsed, chain=["root"])
			
			if normalization == True:
				mode ="normalized"
			else:
				mode ="default"
				
			progress_prefix = "[%s/%s] " % (str(done).rjust(len(str(total))), str(total).rjust(len(str(total))))
			
			if len(errors) == 0:
				sys.stdout.write(OK)
				sys.stdout.write(progress_prefix + "%s passed in %s mode.\n" % (target, mode))
				sys.stderr.write(ENDC)
				total_passed += 1
			else:
				sys.stderr.write(FAIL)
				sys.stderr.write(progress_prefix + "%s TEST CASE FAILED, ERRORS BELOW\n" % target)
				sys.stderr.write("Mode: %s\n" % mode)
				sys.stderr.write("=======================================\n")
				for error in errors:
					sys.stderr.write(error + "\n")
				sys.stderr.write("=======================================\n")
				sys.stderr.write(ENDC)
				total_errors += len(errors)
				total_failed += 1
			done += 1
		
	if total_failed == 0:
		sys.stdout.write(OK)
		sys.stdout.write("All tests passed!\n")
		sys.stderr.write(ENDC)
	else:
		sys.stdout.write(FAIL)
		sys.stdout.write("%d tests failed, %d errors in total.\n" % (total_failed, total_errors))
		sys.stderr.write(ENDC)
					
						
elif args.mode[0] == "update":
	errors = False
	updates = []
	for target in targets:
		try:
			with open(os.path.join("test/data", target), "r") as f:
				data = f.read().split("\n--\n")
			updates.append((target, data))
		except IOError, e:
			sys.stderr.write("Invalid domain %(domain)s specified. No base data exists.\n" % {"domain": target})
			errors = True
			continue
	
	if errors:
		exit(1)
	
	for target, data in updates:
		default = pythonwhois.parse.parse_raw_whois(data)
		normalized = pythonwhois.parse.parse_raw_whois(data, normalized=True)
		with open(os.path.join("test/target_default", target), "w") as f:
			f.write(encoded_json_dumps(default))
		with open(os.path.join("test/target_normalized", target), "w") as f:
			f.write(encoded_json_dumps(normalized))	
		print "Generated target data for %s." % target

#!/usr/bin/python
import sys, pythonwhois

testlist = open("testlist.txt").readlines()

#for line in testlist:
#	result = pythonwhois.whois(line)
#	
#	if result['updated_date'] is None:
#		print "WHOIS for %s does not contain an update date?" % line

#result = pythonwhois.whois("google.com")
raw, result = pythonwhois.whois(sys.argv[1])
print raw
print result
		
#print "Creation date: ",
#print result['creation_date']
#print "Expiration date: ",
#print result['expiration_date']

#!/usr/bin/python
import sys, pythonwhois

result =  pythonwhois.whois(sys.argv[1])
print result
#print "Creation date: ",
#print result['creation_date']
#print "Expiration date: ",
#print result['expiration_date']

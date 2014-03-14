pythonwhois
===========

A WHOIS retrieval and parsing library for Python.

## Dependencies

None! All you need is the Python standard library.

## Instructions

The manual (including install instructions) can be found in the doc/ directory. A HTML version is also viewable [here](http://cryto.net/pythonwhois).

## Goals

* 100% coverage of WHOIS formats.
* Accurate and complete data.
* Consistently functional parsing; constant tests to ensure the parser isn't accidentally broken.

## Features

* WHOIS data retrieval
	* Able to follow WHOIS server redirects
	* Won't get stuck on multiple-result responses from verisign-grs
* WHOIS data parsing
	* Base information (registrar, etc.)
	* Dates/times (registration, expiry, ...)
	* Full registrant information (!)
	* Nameservers
* Optional WHOIS data normalization
	* Attempts to intelligently reformat WHOIS data for better (human) readability
* `pwhois`, a simple WHOIS tool using pythonwhois
	* Easily readable output format
	* Can also output raw WHOIS data
	* ... and JSON.
* Automated testing suite
	* Will detect and warn about any changes in parsed data compared to previous runs
	* Guarantees that previously working WHOIS parsing doesn't unintentionally break when changing code

## It doesn't work!

* It doesn't work at all?
* It doesn't parse the data for a particular domain?
* There's an inaccuracy in parsing the data for a domain, even just a small one?

If any of those apply, don't hesitate to file an issue! The goal is 100% coverage, and we need your feedback to reach that goal.

## Contributing

Feel free to fork and submit pull requests! If you change any parsing or normalization logic, ensure to run the full test suite before opening a pull request. Instructions for that are below.

All commands are relative to the root directory of the repository.

**Pull requests that do _not_ include output from test.py will be rejected!**

### Adding new WHOIS data to the testing set

	pwhois --raw thedomain.com > test/data/thedomain.com
	
### Checking the currently parsed data (while editing the parser)

	./pwhois -f test/data/thedomain.com/ .
	
(don't forget the dot at the end!)
	
### Marking the current parsed data as correct for a domain

Make sure to verify (using `pwhois` or otherwise) that the WHOIS data for the domain is being parsed correctly, before marking it as correct!

	./test.py update thedomain.com
	
### Running all tests

	./test.py run all
	
### Testing a specific domain

	./test.py run thedomain.com

### Running the full test suite including support for multiple python versions

    tox

### Generating documentation

You need [ZippyDoc](http://cryto.net/zippydoc) (which can be installed through `pip install zippydoc`).

	zpy2html doc/*.zpy

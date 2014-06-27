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

## Important update notes

*2.3.0 and up*: Python 3 support was fixed. Creation date parsing for contacts was fixed; correct timestamps will now be returned, rather than unformatted ones - if your application relies on the broken variant, you'll need to change your code. Some additional parameters were added to the `net` and `parse` methods to facilitate NIC handle lookups; the defaults are backwards-compatible, and these changes should not have any consequences for your code. Thai WHOIS parsing was implemented, but is a little spotty - data may occasionally be incorrectly split up. Please submit a bug report if you run across any issues.

*2.2.0 and up*: The internal workings of `get_whois_raw` have been changed, to better facilitate parsing of WHOIS data from registries that may return multiple partial matches for a query, such as `whois.verisign-grs.com`. This change means that, by default, `get_whois_raw` will now strip out the part of such a response that does not pertain directly to the requested domain. If your application requires an unmodified raw WHOIS response and is calling `get_whois_raw` directly, you should use the new `never_cut` parameter to keep pythonwhois from doing this post-processing. As this is a potentially breaking behaviour change, the minor version has been bumped.

## It doesn't work!

* It doesn't work at all?
* It doesn't parse the data for a particular domain?
* There's an inaccuracy in parsing the data for a domain, even just a small one?

If any of those apply, don't hesitate to file an issue! The goal is 100% coverage, and we need your feedback to reach that goal.

## Contributing

Feel free to fork and submit pull requests (to the `develop` branch)! If you change any parsing or normalization logic, ensure to run the full test suite before opening a pull request. Instructions for that are below.

Please note that this project uses tabs for indentation.

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

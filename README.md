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
	* Attempts to intelligently reformat WHOIS data for better accuracy and (human) readability
	* Converts various abbreviation types to full locality names
		* Airport codes
		* Country names (2- and 3-letter ISO codes)
		* US states and territories
		* Canadian states and territories
		* Australian states
	* Identifies both organization and person names, and moves or reformats them where necessary
	* Identifies names where the first and last name are swapped around, and fixes them
	* Deduplicates names, even *across fields*, and even when they're not 100% identical
	* Recognizes common (legal) abbreviations, and ensures that they are in the correct case
* `pwhois`, a simple WHOIS tool using pythonwhois
	* Easily readable output format
	* Can also output raw WHOIS data
	* ... and JSON.
* Automated testing suite
	* Will detect and warn about any changes in parsed data compared to previous runs
	* Guarantees that previously working WHOIS parsing doesn't unintentionally break when changing code

## IP range WHOIS

`pythonwhois` does not yet support WHOIS lookups on IP ranges (including single IPs), although this will be added at some point in the future. In the meantime, consider using [`ipwhois`](https://github.com/secynic/ipwhois) - it offers functionality and an API similar to `pythonwhois`, but for IPs. It also supports delegated RWhois.

Do note that `ipwhois` does not offer a normalization feature, and does not (yet) come with a command-line tool. Additionally, `ipwhois` is maintained by Philip Hane and not by me; please make sure to file bugs relating to it in the `ipwhois` repository, not in that of `pythonwhois`.

## Important update notes

*2.4.0 and up*: A lot of changes were made to the normalization, and the performance under Python 2.x was significantly improved. The average parsing time under Python 2.7 has dropped by 94% (!), and on my system averages out at 18ms. Performance under Python 3.x is [unchanged](https://github.com/joepie91/python-whois/issues/27). `pythonwhois` will now expand a lot of abbreviations in normalized mode, such as airport codes, ISO country codes, and US/CA/AU state abbreviations. The consequence of this is that the library is now bigger (as it ships a list of these abbreviations). Also note that there *may* be licensing consequences, in particular regarding the airport code database. More information about that can be found below.

*2.3.0 and up*: Python 3 support was fixed. Creation date parsing for contacts was fixed; correct timestamps will now be returned, rather than unformatted ones - if your application relies on the broken variant, you'll need to change your code. Some additional parameters were added to the `net` and `parse` methods to facilitate NIC handle lookups; the defaults are backwards-compatible, and these changes should not have any consequences for your code. Thai WHOIS parsing was implemented, but is a little spotty - data may occasionally be incorrectly split up. Please submit a bug report if you run across any issues.

*2.2.0 and up*: The internal workings of `get_whois_raw` have been changed, to better facilitate parsing of WHOIS data from registries that may return multiple partial matches for a query, such as `whois.verisign-grs.com`. This change means that, by default, `get_whois_raw` will now strip out the part of such a response that does not pertain directly to the requested domain. If your application requires an unmodified raw WHOIS response and is calling `get_whois_raw` directly, you should use the new `never_cut` parameter to keep pythonwhois from doing this post-processing. As this is a potentially breaking behaviour change, the minor version has been bumped.

## It doesn't work!

* It doesn't work at all?
* It doesn't parse the data for a particular domain?
* There's an inaccuracy in parsing the data for a domain, even just a small one?

If any of those apply, don't hesitate to file an issue! The goal is 100% coverage, and we need your feedback to reach that goal.

## License

This library may be used under the WTFPL - or, if you take issue with that, consider it to be under the CC0.

## Data sources

This library uses a number of third-party datasets for normalization:

* `airports.dat`: [OpenFlights Airports Database](http://openflights.org/data.html) ([Open Database License 1.0](http://opendatacommons.org/licenses/odbl/1.0/), [Database Contents License 1.0](http://opendatacommons.org/licenses/dbcl/1.0/))
* `countries.dat`: [Country List](https://github.com/umpirsky/country-list) (MIT license)
* `countries3.dat`: [ISO countries list](https://gist.github.com/eparreno/205900) (license unspecified)
* `states_au.dat`: Part of `pythonwhois` (WTFPL/CC0)
* `states_us.dat`: [State Table](http://statetable.com/) (license unspecified, free reuse encouraged)
* `states_ca.dat`: [State Table](http://statetable.com/) (license unspecified, free reuse encouraged)
* `common_first_names.dat`: [Social Security Administration](http://www.ssa.gov/OACT/babynames/), via [hadley/data-baby-names](https://github.com/hadley/data-baby-names) (license unspecified, provided by US government)

Be aware that the OpenFlights database in particular has potential licensing consequences; if you do not wish to be bound by these potential consequences, you may simply delete the `airports.dat` file from your distribution. `pythonwhois` will assume there is no database available, and will not perform airport code conversion (but still function correctly otherwise). This also applies to other included datasets.

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

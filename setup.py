from setuptools import setup

setup(name='pythonwhois',
      version='2.0.3',
      description='Module for retrieving and parsing the WHOIS data for a domain. Supports most domains. No dependencies.',
      author='Sven Slootweg',
      author_email='pythonwhois@cryto.net',
      url='http://cryto.net/pythonwhois',
      packages=['pythonwhois'],
      provides=['pythonwhois'],
      scripts=["pwhois"],
      license="WTFPL"
     )

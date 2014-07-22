from setuptools import setup

setup(name='pythonwhois',
      version='2.4.3',
      description='Module for retrieving and parsing the WHOIS data for a domain. Supports most domains. No dependencies.',
      author='Sven Slootweg',
      author_email='pythonwhois@cryto.net',
      url='http://cryto.net/pythonwhois',
      packages=['pythonwhois'],
      package_dir={"pythonwhois":"pythonwhois"},
      package_data={"pythonwhois":["*.dat"]},
      install_requires=['argparse'],
      provides=['pythonwhois'],
      scripts=["pwhois"],
      license="WTFPL"
     )

"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
long_description = '''pyca/cryptography-based wrappers for OpenSSL engine operations'''

setup(
    name='cryptography_engine',
    version='0.5.1',
    description='Wrappers for OpenSSL engine operations based on pyca/cryptography',
    long_description=long_description,
    author='SPChan',
    author_email='shihping.chan@gmail.com',
    packages=['cryptography_engine'],
    install_requires=['cryptography>=3.4.7',  ],
)

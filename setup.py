#!/usr/bin/env python

from setuptools import setup

setup(
    name='ccanalyzer', version='1.0',
    description='Cisco Config Analyzer',
    author='Lao Tze', author_email='ltze@dao.cn',
    url='http://www.python.org/sigs/distutils-sig/',
    install_requires=[
        'Django==1.8.4',
        'ciscoconfparse>=1.2',
        'python-magic==0.4.11'
    ],
    dependency_links=[
        'https://pypi.python.org/simple/django/',
        'https://pypi.python.org/pypi/python-magic',
        'https://pypi.python.org/pypi/ciscoconfparse',
    ],
)

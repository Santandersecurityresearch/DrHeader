#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup

import os
import re

base_dir = os.path.dirname(__file__)

long_description = ''

with open(os.path.join(base_dir, "README.md")) as readme:
    readme_lines = readme.readlines()
    for line in readme_lines:
        if not re.search(r'\(assets\/img\b',line):
            long_description = long_description + line

with open('HISTORY.md') as history_file:
    history = history_file.read()

with open('requirements.txt') as f:
    requirements = f.read()

setup_requirements = ['pytest-runner', ]

test_requirements = ['pytest']

setup(
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.7',
        'Environment :: Console',
        'Topic :: Security'
    ],
    entry_points={
        'console_scripts': [
            'drheader=drheader.cli:main',
        ],
    },
    install_requires=requirements,

    description="DrHEADer helps with the audit of security headers received in response to a single request or a list of requests.",
    long_description_content_type='text/markdown',
    long_description=long_description,
    include_package_data=True,
    keywords='drheader',
    author='Santander UK Security Engineering',
    name='drheader',
    packages=['drheader'],
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements, 
    url='https://github.com/santandersecurityresearch/drheader',
    version='1.5.3',
    zip_safe=False,
)

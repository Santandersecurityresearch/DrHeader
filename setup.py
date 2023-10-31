#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

import os
import re

from setuptools import setup

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

setup(
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security'
    ],
    entry_points={
        'console_scripts': [
            'drheader=drheader.cli.cli:start',
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
    packages=['drheader', 'drheader/cli', 'drheader/validators'],
    test_suite='tests',
    url='https://github.com/santandersecurityresearch/drheader',
    version='2.0.0',
    zip_safe=False,
)

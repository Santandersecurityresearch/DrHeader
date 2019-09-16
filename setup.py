#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('HISTORY.md') as history_file:
    history = history_file.read()

requirements = ['Click>=6.0',
                'requests==2.22.0',
                'jsonschema==3.0.2',
                'jsonschema[format]',
                'validators==0.13.0',
                'tabulate==0.8.3',
                'pyyaml==5.1.2']

setup_requirements = ['pytest-runner', ]

test_requirements = ['pytest']

setup(
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Environment :: Console',
        'Topic :: Security'
    ],
    description="scan request headers against a set of rules",
    entry_points={
        'console_scripts': [
            'drheader=drheader.cli:main',
        ],
    },
    install_requires=requirements,
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='drheader',
    name='drheader',
    packages=['drheader'],
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/santandersecurityresearch/drheader',
    version='0.1.0',
    zip_safe=False,
)

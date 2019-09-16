![drHEADer](assets/img/hero.png)

# Welcome to drHEADer

<!--[![Updates](https://pyup.io/repos/github/santandersecurityresearch/drheader/shield.svg)](https://pyup.io/repos/github/santandersecurityresearch/drheader/) -->

drHEADer is a module and command line tool to audit security headers received in response to a single request or a list of requests.

# Installation

## Stable release

To install drHEADer core, run this command in your terminal:

``` console
$ pip install drheader
```

This is the preferred method to install drHEADer, as it will always
install the most recent stable release.

If you don't have [pip](https://pip.pypa.io) installed, this [Python
installation
guide](http://docs.python-guide.org/en/latest/starting/installation/)
can guide you through the process.

## From sources

The sources for drHEADer core can be downloaded from the [Github
repo](https://github.com/santandersecurityresearch/drheader).

You can either clone the public repository:

``` console
$ git clone git://github.com/<GROUPNAME>/drheader
```

Or download the
[tarball](https://github.com/santandersecurityresearch/drheader/tarball/master):

``` console
$ curl  -OL https://github.com/<GROUPNAME>/drheader/tarball/master
```

Once you have a copy of the source, you can install it with:

``` console
$ python setup.py install
``` 

# Example Usage

To use drHEADer in a project:
    
    from drheader import Drheader
    
    # create drheader instance
    drheader_instance = Drheader(headers={'X-XSS-Protection': '1; mode=block'}, status_code=200)
    
    report = drheader_instance.analyze()
    print(report)


To use the drHEADer cli:

    $ drheader --help
    
    Usage: drheader [OPTIONS] COMMAND [ARGS]...
    
      Console script for drheader.
    
    Options:
      --help  Show this message and exit.
    
    Commands:
      compare  Compare your headers through drheader.
      scan     Scan endpoints with drheader.

# API

## Submodules

## drheader.cli module

Console script for drheader.

## drheader.core module

**class drheader.core.Drheader(url=None, headers=None,
status\_code=None, post=False, params=None)**

> Bases: `object`
> 
> Something about the core should probably go here
> 
> **\_\_init\_\_(url=None, headers=None, status\_code=None, post=False,
> params=None)**
> 
> > NOTE: at least one param required.
> > 
> >   - Parameters
> >     
> >       - **url** (*str*) – \[optional\] URL of target
> >       - **headers** (*dict*) – \[optional\] Override headers
> >       - **status\_code** (*int*) – \[optional\] Override status code
> >       - **post** (*bool*) – \[optional\] Use post for request
> >       - **params** (*dict*) – \[optional\] Request params
> 
> **analyze(rules=None)**
> 
> > Analyze the currently loaded headers against provided rules.
> > 
> >   - Parameters  
> >     **rules** (*dict*) – override rules to compare headers against
> > 
> >   - Returns  
> >     audit report
> > 
> >   - Return type  
> >     list
> 
> `error_types = {1: 'Header not incl ... id directive included'}`

## drheader.utils module

Utils for drheader.

**drheader.utils.load\_rules(rule\_file=None)**

> Loads drheader ruleset. Will load local defaults unless overridden.
> :param rule\_file: file object of rules. :type rule\_file: file
> :return: drheader rules :rtype: dict

## Module contents

Top-level package for drHEADer core.


.. highlight:: shell

============
Installation
============


Stable release
--------------

To install drHEADer, run this command in your terminal:

.. code-block:: console

    $ pip3 install https://github.com/Santandersecurityresearch/DrHeader/releases/download/v1.0.0/drheader-1.0.0-py2.py3-none-any.whl --user

This is the easiet method to install drHEADer from a wheel built from the 1.0.0 release.

on a Linux or MacOS system you can add an alias to make it easy to access drheader

.. code-block: console

    $ alias drheader='python3 -m drheader.cli'

on a Windows 

    $ doskey drheader=python3 -m drheader.cli


In future we will upload releases to pip and update these instructions.
All releases of DrHeader can be found at https://github.com/Santandersecurityresearch/DrHeader/releases

If you don't have `pip`_ installed, this `Python installation guide`_ can guide
you through the process.

.. _pip: https://pip.pypa.io
.. _Python installation guide: http://docs.python-guide.org/en/latest/starting/installation/
.. _releases: https://github.com/Santandersecurityresearch/DrHeader/releases

From sources
------------

The sources for drHEADer core can be downloaded from the `Github repo`_.

You can either clone the public repository:

.. code-block:: console

    $ git clone git://github.com/Santandersecurityresearch/DrHeader

Or download a zip file containing the current master:

.. code-block:: console

    $ curl  -OL https://github.com/Santandersecurityresearch/DrHeader/archive/master.zip

Once you have a copy of the source, you can install it with:

.. code-block:: console

    $ python3 setup.py install --user


.. _Github repo: https://github.com/Santandersecurityresearch/DrHeader/
.. _tarball: https://github.com/Santandersecurityresearch/DrHeader/tarball/master
.. _zipfile: https://github.com/Santandersecurityresearch/DrHeader/archive/master.zip

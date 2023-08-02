# Contributing

Contributions are welcome, and they are greatly appreciated\! Every
little bit helps, and credit will always be given.

You can contribute in many ways:

## Types of Contributions

### Report Bugs

Report bugs at <https://github.com/santandersecurityresearch/drheader/issues>.

If you are reporting a bug, please include:

  - Your operating system name and version.
  - Any details about your local setup that might be helpful in
    troubleshooting.
  - Detailed steps to reproduce the bug.

### Fix Bugs

Look through the GitHub issues for bugs. Anything tagged with "bug" and
"help wanted" is open to whoever wants to implement it.

### Implementing Features

Look through the GitHub issues for features. Anything tagged with
"enhancement" and "help wanted" is open to whoever wants to implement
it.

### Write Documentation

drHEADer core could always use more documentation, whether as part of
the official drHEADer core docs, in docstrings, or even on the web in
blog posts, articles, and such.

### Submit Feedback

The best way to send feedback is to file an issue at
<https://github.com/santandersecurityresearch/drheader/issues>.

If you are proposing a feature:

  - Explain in detail how it would work.
  - Keep the scope as narrow as possible, to make it easier to
    implement.
  - Remember that this is a volunteer-driven project, and that
    contributions are welcome :)

## Get Started\!

Ready to contribute? Here's how to set up
<span class="title-ref">drheader</span> for local development.

1.  Fork the <span class="title-ref">drheader</span> repo on GitHub.

2.  Clone your fork locally:

        $ git clone git@github.com:your_name_here/drheader.git

3.  Install your local copy into a virtualenv. Assuming you have
    virtualenvwrapper installed, this is how you set up your fork for
    local development:

        $ mkvirtualenv drheader
        $ cd drheader/
        $ python setup.py develop

4.  Create a branch for local development:

        $ git checkout -b name-of-your-bugfix-or-feature

    Now you can make your changes locally.

5.  When you're done making changes, check that your changes pass flake8
    and the tests, including testing other Python versions with tox:

        $ tox

    To get tox, just pip install it into your virtualenv.

6.  Commit your changes and push your branch to GitHub:

        $ git add .
        $ git commit -m "Your detailed description of your changes."
        $ git push origin name-of-your-bugfix-or-feature

7.  Submit a pull request through the GitHub website.

## Pull Request Guidelines

When submitting a pull request, please ensure that:

1.  You submit it to 'develop' branch and there's no conflicts.
2.  You check all tests are passing and have created new ones if change not covered in current test suite.
3.  You update `README.md` if functionality has been added or modified. If you are creating new classes or methods, please use docstring to document the code.
4.  You update `RULES.md` when extending or modifying the way rules can be used, adding documentation and examples for the new/modified feature.
5.  Code works for Python >= 3.8
6.  Once PR is submitted, workflow steps are successful (e.g.: Flake8, Bandit, Safety, etc.)

![drHEADer](assets/img/hero.png)

# Contributing

Contributions are welcome and greatly appreciated! Every little bit helps and credit will always be given. You can
contribute in many ways:

### Report a bug

Report a bug on the [issue tracker](https://github.com/santandersecurityresearch/drheader/issues).

Please include in the report:

- Your operating system name and version
- Any details about your local setup that might be helpful in troubleshooting
- Detailed steps to reproduce the bug

### Fix a bug

Look through the [bug tracker](https://github.com/santandersecurityresearch/drheader/labels/bug) for open issues.
Anything tagged with `bug` and `help wanted` is open to whoever wants to fix it.

### Implement a new feature

Look through the [issue tracker](https://github.com/santandersecurityresearch/drheader/labels/enhancement) for open
feature requests. Anything tagged with `enhancement` and `help wanted` is open to whoever wants to implement it.

### Write documentation

drheader documentation can always be enhanced, whether as part of the official drheader docs, in docstrings, or even on
the web such as in blog posts and articles.

### Submit feedback

The best way to send feedback is to open an issue on the
[issue tracker](https://github.com/santandersecurityresearch/drheader/issues).

If you are proposing a feature:

- Explain in detail how it would work
- Keep the scope as narrow as possible to make it easier to implement
- Remember that this is a volunteer-driven project, and that contributions are welcome

## Get Started!

Ready to contribute? This section walks through how to set up drheader for local development and prepare a pull request.
Any steps that display an input symbols icon ( :symbols: ) require you to insert some user-specific information into the
command before running it.

#### Pre-requisites

drheader is built using Python 3.8 and Poetry. If you already have these installed, skip ahead to step 3.

1. Install [Python 3.8+](https://www.python.org/downloads)

2. Install [Poetry](https://python-poetry.org/docs/#installation)

3. Fork drheader into your GitHub account

4. Clone your fork locally :symbols:
   ```shell
   $ git clone git@github.com:<your-github-username>/drheader.git`
   ```

5. Set up a virtual environment in your local repo
   ```shell
   $ python -m venv venv
   ```

6. Activate the virtual environment using the appropriate activation command from
   [here](https://docs.python.org/3/library/venv.html#how-venvs-work) :symbols:
   ```shell
   $ source venv/bin/activate
   ```

7. Install the project dependencies into your local environment
   ```shell
   $ poetry install --all-extras --no-root
   ```

8. Create a branch for local development :symbols:
   ```shell
   $ git checkout -b <name-of-your-bug-fix-or-feature>
   ```

9. After making your changes, verify that the tests and required checks are passing (see [running tox](#running-tox))
   ```shell
   $ tox
   ```

10. Commit your changes and push your branch :symbols:
    ```shell
    $ git add .
    $ git commit -m '<description of your changes>'
    $ git push origin <name-of-your-bug-fix-or-feature>
    ```

11. Submit a pull request at <https://github.com/santandersecurityresearch/drheader/pulls>

## Pull Request Guidelines

When submitting a pull request, please ensure that:

1. The existing tests are passing, and new functionality is adequately covered with new tests
2. The relevant documentation e.g. `README.md`, `RULES.md`, `CLI.md` is updated to reflect new or changed functionality
3. The code works for Python >= 3.8
4. The pull request is submitted against the `develop` branch with no merge conflicts
5. The pull request pipeline has succeeded

#### Running tox

You can use tox to replicate the workflow environment on your local machine prior to submitting a pull request. This
allows you run exactly the same steps that will run in the pipeline, and ensure that the pull request is ready to be
merged.

```shell
$ tox
```

This will do the following:

- Run the tests against all supported Python versions ** and verify that test coverage is at least 80%
- Run a static security scan
- Run all required linters
- Verify that `poetry.lock` is up-to-date

** When testing against a specific Python version, tox expects an interpreter that satisfies the version requirement to
be installed already and visible to tox. If it cannot find a suitable interpreter, the environment will be skipped. To
efficiently manage multiple Python versions, you can use [pyenv](https://github.com/pyenv/pyenv).

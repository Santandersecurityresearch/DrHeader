=====
Usage
=====

To use drHEADer core in a project::

    import drheader
    import yaml

    # load rules file
    with open('rules.yml', 'r') as f:
       rules = yaml.safe_load(file)

    # create drheader instance
    drheader_instance = Drheader(headers={'X-XSS-Protection': '1; mode=block'}, status_code=200)

    report = drheader_instance.analyze(rules)
    print(report)

To use the drHEADer cli::

    $ drheader --help

    Usage: drheader [OPTIONS] COMMAND [ARGS]...

      Console script for drheader.

    Options:
      --help  Show this message and exit.

    Commands:
      compare  Compare your headers through drheader.
      scan     Scan endpoints with drheader.

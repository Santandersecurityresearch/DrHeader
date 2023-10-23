![drHEADer](assets/img/hero.png)

# CLI Usage
This page describes how to use the drHEADer command line interface.

## Contents
* [Analysing Headers Locally](#analysing-headers-locally)
  * [Bulk Scanning](#bulk-scanning)
  * [Scan Options](#scan-options)
* [Scanning Remote Endpoints](#scanning-remote-endpoints)
  * [Configuring the HTTP Request](#configuring-the-http-request)
  * [Bulk Scanning](#bulk-scanning-1)
    * [File Input Format](#file-input-format)
    * [Configuring the HTTP Request](#configuring-the-http-request-1)
  * [Scan Options](#scan-options-1)
* [Report Output](#report-output)

## Analysing Headers Locally
You can validate a set of headers against a drHEADer ruleset using the `compare single` command:
```shell
$ drheader compare single [SCAN_OPTIONS] FILE
```

This will parse the contents of `FILE`, analyse the headers within it against a drHEADer ruleset, and report back any
rule violations. `FILE` is the path to a JSON file containing the headers to be analysed.

### Bulk Scanning
You can validate several sets of headers at once using the `compare bulk` command:
```shell
$ drheader compare bulk [SCAN_OPTIONS] FILE
```

The contents of `FILE` must be a JSON array with each item specifying a set of headers to be analysed and an associated
endpoint:

```json
  [
    {
        "url": "https://example.com",
        "headers": {
            "Cache-Control": "private, must-revalidate",
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"
        }
    },
    {
        "url": "https://example.net",
        "headers": {
            "Referrer-Policy": "strict-origin",
            "Strict-Transport-Security": "max-age=31536000; preload",
            "X-Content-Type-Options": "nosniff"
        }
    }
  ]
```

You can view the JSON schema for bulk scanning with `compare` [here](drheader/resources/cli/bulk_compare_schema.json).

### Scan Options
This table lists the scan options available when using the `compare` command:

| Option                     | Description                                                 |
|:---------------------------|:------------------------------------------------------------|
| `--cross-origin-isolated`  | Enable cross-origin isolation validations ¹                 |
| `--debug`                  | Enable debug logging                                        |
| `--junit`                  | Generate a JUnit report *(not available for bulk scanning)* |
| `--merge`                  | Merge a custom ruleset with the default rules               |
| `--output` [json \| table] | Report output format  [default: table]                      |
| `--rules-file FILENAME`    | Use a custom ruleset, loaded from file ²                    |
| `--rules-uri URI`          | Use a custom ruleset, downloaded from URI ²                 |

¹ Cross-origin isolation validations are opt-in. See [Cross-Origin Isolation](README.md#cross-origin-isolation).

² For information on defining a custom ruleset see [RULES](RULES.md).

## Scanning Remote Endpoints
You can scan a remote endpoint using the `scan single` command:

```shell
$ drheader scan single [SCAN_OPTIONS] TARGET_URL [REQUEST_ARGS]
```

This will send an HTTP `HEAD` request to `TARGET_URL`, validate the headers that are returned in the response and report
back any rule violations.

### Configuring the HTTP Request
Internally, drHEADer uses the [`requests`](https://requests.readthedocs.io/en/latest/) package to make the HTTP call,
and you can customise the request with the same configuration options that can be processed by this package. Any
arguments received in `[REQUEST_ARGS]` will be propagated to the HTTP call. This means, you can for instance...

* Change the request method:
    ```shell
    $ drheader scan single https://example.com --method POST
    ```

* Send request parameters:
    ```shell
    $ drheader scan single https://example.com --params '{"name": "h_simpson", "department": "Sector 7G"}'
    ```

* Send data in the request body:
    ```shell
    $ drheader scan single https://example.com --json '{"number": "42", "street": "Wallaby Way", "city": "Sydney"}'
    ```

* Configure the timeout on the request:
    ```shell
    $ drheader scan single https://example.com --timeout 30
    $ drheader scan single https://example.com --timeout '(5, 30)'
    ```

* Configure SSL verification:
    ```shell
    $ drheader scan single https://example.com --verify false
    $ drheader scan single https://example.com --verify 'path/to/ca/bundle'
    ```

See the [requests](https://requests.readthedocs.io/en/latest/_modules/requests/api/#request) documentation for a full
list of options.

### Bulk Scanning
You can scan several endpoints at once using the `scan bulk` command:
```shell
$ drheader scan bulk [SCAN_OPTIONS] FILE
```

The contents of `FILE` must be a JSON array with each item specifying a URL to target and additional request args:
```json
[
    {
        "url": "https://example.com"
    },
    {
        "url": "https://example.net"
    },
    {
        "url": "https://example.org"
    }
]
```

You can view the JSON schema for bulk scanning with `scan` [here](drheader/resources/cli/bulk_scan_schema.json). See
[configuring the HTTP request](#configuring-the-http-request-1) for details on request args.

#### File Input Format
The default input format for `FILE` is JSON, which allows you to configure more complex HTTP requests (see
[configuring the HTTP request](#configuring-the-http-request-1)). If you only want to target each endpoint with a basic
HTTP HEAD request and no additional configuration, you can choose to pass the input file in a simpler `.txt` format by
specifying the `-ff` (file format) option:

```shell
$ drheader scan bulk -ff txt FILE
```

Each endpoint must be on a separate line:
```
https://example.com
https://example.net
https://example.org
```

#### Configuring the HTTP Request
For bulk scanning, [request args](#configuring-the-http-request) are configured on a per-target basis in the JSON file:
```json
[
    {
        "url": "https://example.com",
        "method": "POST"
    },
    {
        "url": "https://example.net",
        "params": {
            "name": "h_simpson",
            "department": "Sector 7G"
        }
    },
    {
        "url": "https://example.org",
        "json": {
            "number": "42",
            "street": "Wallaby Way",
            "city": "Sydney"
        },
        "timeout": 30,
        "verify": false
    }
]
```

See the [requests](https://requests.readthedocs.io/en/latest/_modules/requests/api/#request) documentation for a full
list of options.

### Scan Options
This table lists the scan options available when using the `scan` command:

| Option                        | Description                                                 |
|:------------------------------|:------------------------------------------------------------|
| `--cross-origin-isolated`     | Enable cross-origin isolation validations ¹                 |
| `--debug`                     | Enable debug logging                                        |
| `--file-format` [json \| txt] | FILE input format  [default: json] *(bulk scanning only)*   |
| `--junit`                     | Generate a JUnit report *(not available for bulk scanning)* |
| `--merge`                     | Merge a custom ruleset with the default rules               |
| `--output` [json \| table]    | Report output format  [default: table]                      |
| `--rules-file FILENAME`       | Use a custom ruleset, loaded from file ²                    |
| `--rules-uri URI`             | Use a custom ruleset, downloaded from URI ²                 |

¹ Cross-origin isolation validations are opt-in. See [Cross-Origin Isolation](README.md#cross-origin-isolation).

² For information on defining a custom ruleset see [RULES](RULES.md).

## Report Output
By default, results will be output in a tabulated format:

```
https://example.com: 9 issues found
----
 rule      | Cache-Control
 message   | Value does not match security policy
 severity  | high
 value     | max-age=604800
 expected  | ['no-store', 'max-age=0']
 delimiter | ,
----
 rule     | Content-Security-Policy
 message  | Header not included in response
 severity | high
----
 rule     | Pragma
 message  | Header not included in response
 severity | high
 expected | ['no-cache']
```

You can change this using the `--output` option. Currently, the only other supported option is JSON:
```sh
$ drheader scan single --output json
```

In order to save scan results, you can pipe the JSON output to [jq](https://stedolan.github.io/jq/), which is a
lightweight and flexible command-line JSON processor:
```sh
$ drheader scan single --output json https://example.com | jq '.'
```

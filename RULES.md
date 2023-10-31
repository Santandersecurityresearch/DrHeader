# Introduction

This document describes the format of the `rules.yml` file, which defines the policy drHEADer uses to audit your
security headers. It also documents how to make changes to it so that you can configure your custom policy based on
your specific requirements.

## Contents

* [Sample Policy](#sample-policy)
* [File Structure](#file-structure)
    * [Expected and Disallowed Values](#expected-and-disallowed-values)
        * [Permissible Values](#permissible-values)
        * [Validation Order](#validation-order)
    * [Validating Policy Headers](#validating-policy-headers)
    * [Validating Directives](#validating-directives)
    * [Validating Cookies](#validating-cookies)
        * [Validating Cookies Globally](#validating-cookies-globally)
        * [Validating Named Cookies](#validating-named-cookies)
    * [Validating Custom Headers](#validating-custom-headers)
* [Example Use Cases](#example-use-cases)
    * [Hardening the CSP](#hardening-the-csp)
    * [Securing Cookies](#securing-cookies)
    * [Preventing Caching](#preventing-caching)
    * [Enforcing Cross-Origin Isolation](#enforcing-cross-origin-isolation)
    * [Enforcing a Fallback Referrer Policy](#enforcing-a-fallback-referrer-policy)

## Sample Policy

drHEADer policy is defined in a yaml file. An example policy is given below:

```yaml
Cache-Control:
    Required: True
    Value:
        - no-store
        - max-age=0
Content-Security-Policy:
    Required: True
    Must-Avoid:
        - block-all-mixed-content
        - referrer
        - unsafe-inline
        - unsafe-eval
    Directives:
        Default-Src:
            Required: True
            Value-One-Of:
                - none
                - self
            Severity: Critical
        Report-To:
            Required: Optional
            Value: /_/csp_report
Referrer-Policy:
    Required: True
    Value-One-Of:
        - no-referrer
        - same-origin
        - strict-origin
Server:
    Required: False
    Severity: Warning
Set-Cookie:
    Required: Optional
    Must-Contain:
        - HttpOnly
        - Secure
    Must-Contain-One:
        - Expires
        - Max-Age
X-Frame-Options:
    Required: True
    Value-One-Of:
        - DENY
        - SAMEORIGIN
X-XSS-Protection:
    Required: True
    Value: 0
```

## File Structure

The yaml file structure for drHEADer is described below. All elements are case-insensitive, and all checks against
expected and disallowed values are case-insensitive.

* There can be as many elements as headers you want to audit *(e.g. Content-Security-Policy, Set-Cookie)*

* Each header must specify whether the header is required via the `required` element. It can take the following values:
    * `True`: The item must be present in the HTTP response
    * `False`: The item must not be present in the HTTP response
    * `Optional`: The header may be present in the HTTP response, but it is not mandatory

* For items that are set as required or optional, the following additional rules may also be set. The checks will only
  run if the item is present in the HTTP response:
    * `Value`: The item value must be an exact match with the expected value
    * `Value-One-Of`: The item value must be an exact match with exactly one of the expected values
    * `Value-Any-Of`: The item value must be an exact match with one or more of the expected values
    * `Must-Avoid`: The item value must not contain any of the disallowed values
    * `Must-Contain`: The item value must contain all the expected values
    * `Must-Contain-One`: The item value must contain one or more of the expected values

* You can override the default severity for an item by providing a custom severity in the `severity` element

Within each header element, rules can be set for individual directives via the `directives` element. There can be as
many directive elements as directives you want to audit *(e.g. default-src, script-src)*. The same validations
as above are available for individual directives.

### Expected and Disallowed Values

For elements that define expected or disallowed values, those values can be given either as a list or a string. The two
elements shown below are equivalent:

```yaml
Value:
    - max-age=31536000
    - includeSubDomains
```

```yaml
Value: max-age=31536000; includeSubDomains
```

If given as a string, individual items must be separated with the correct item delimiter for the header or directive
being evaluated. Therefore, for expected or disallowed values that specify multiple items, giving them as a list is
generally preferred.

#### Permissible Values

For checks that define expected or disallowed values, these values can take a number of different formats to cover
various scenarios that you might want to enforce:

* Enforce or disallow standalone directives or values

```yaml
Value: no-store
```

* Enforce or disallow entire key-value directives

```yaml
Value: max-age=0
```

* Enforce or disallow specific keys for key-value directives, without stipulating the value

```yaml
Value: max-age
```

You can also specify keyword values *(e.g. unsafe-eval, unsafe-inline)* as valid disallowed values for must-avoid checks
when validating policy headers *(see [validating policy headers](#validating-policy-headers))*.

The validations will match the expected or disallowed values against the whole item value *(standalone directive/value,
entire key-value directive, or key for key-value directive)*. If a value is typically declared in quotation marks,
such as those for [`Clear-Site-Data`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data), or
keywords for policy headers, you must omit the quotation marks:

```yaml
Clear-Site-Data:
    Required: True
    Value:
        - cache
        - storage
```

#### Validation Order

By default, order is not preserved when validating. That is, both values shown below are valid for the `Cache-Control`
rule in the sample policy at the beginning of this document:

```json
{
    "Cache-Control": "no-store; max-age=0"
}
```

```json
{
    "Cache-Control": "max-age=0; no-store"
}
```

There may be scenarios in which you want to preserve order, such as when specifying a fallback policy for
[`Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy#specify_a_fallback_policy).
In such scenarios, you can set `preserve-order` to `True`:

```yaml
Value:
    - no-referrer
    - strict-origin-when-cross-origin
Preserve-Order: True
```

This option is only supported by the `value` validation for headers. Directive and cookie validations are not supported.

### Validating Policy Headers

Policy headers are those that generally follow the syntax `<policy-directive>; <policy-directive>` where
`<policy-directive>` consists of `<directive> <value>` and `<value>` can consist of multiple items and keywords.
Currently, this covers
[`Content-Security-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) and
[`Feature-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy).

You can define disallowed values in must-avoid checks that will be searched for in the values of all key-value
directives. The below will report back all directives in the CSP that contain `unsafe-eval` or `unsafe-inline` as
non-compliant:

```yaml
Content-Security-Policy:
    Required: True
    Must-Avoid:
        - unsafe-eval
        - unsafe-inline
```

The quotation marks around keywords such as `'none'`, `'self'` and `'unsafe-inline'` in policy headers must not be
included in expected or disallowed values. The quotation marks are stripped from these values in HTTP responses before
they are compared to the expected and disallowed values. The exception to this is if you're enforcing an exact value for
the policy header (i.e. using the `value`, `value-any-of` or `value-one-of` validation), in which case you must keep the
quotation marks around keywords:

```yaml
Content-Security-Policy:
    Required: True
    Value: default-src 'none'; script-src 'self'; style-src 'unsafe-inline'
```

### Validating Directives

The mechanism for validating directives is the same as that for validating headers, and all the same validations are
available. You can use it to validate any directive that is declared in a key-value format for any header. Each
directive to be audited needs to be specified as an element under the `directives` element:

```yaml
Content-Security-Policy:
    Required: True
    Directives:
        Default-Src:
            Required: True
            Value-One-Of:
                - none
                - self
        Style-Src:
            Required: True
            Must-Contain: https://stylesheet-url.com
```

Note that if you want to enforce exists or not-exists validations for a directive, without enforcing any validations on
its value, it is generally simpler to do so using contain and avoid validations respectively at the header level:

```yaml
Content-Security-Policy:
    Required: True
    Must-Contain:
        - default-src
    Must-Avoid:
        - frame-src
```

### Validating Cookies

Cookie validations are defined in the `set-cookie` element. The validations for cookies work slightly differently to
those for headers and directives.

When defining a rule for a cookie, you have two options:

1. [Apply the rule globally to all cookies](#validating-cookies-globally)
2. [Apply the rule only to a specific named cookie](#validating-named-cookies)

#### Validating Cookies Globally

To validate cookies globally, you must define the rule under the `set-cookie` element as you would for other headers.

```yaml
Set-Cookie:
    Required: Optional
    Must-Contain:
        - HttpOnly
        - Secure
```

This example will enforce that all cookies returned set the `HttpOnly` and `Secure` flags. Global validations support
only `must-avoid`, `must-contain` and `must-contain-one` rules.

#### Validating Named Cookies

To validate a named cookie, you must specify the cookie to be validated as an element under the `cookies` element. You
can then define validation rules per cookie. DrHEADer will search for a cookie matching the named one and apply the
validations only to that cookie.

```yaml
Set-Cookie:
    Required: True
    Cookies:
        Session-Id:
            Required: True
            Must-Contain: Max-Age
```

The cookie validation mechanism for a named cookie assumes the following:

* The cookie name and value are declared as the first attribute in the format `<cookie-name>=<cookie-value>;`
* The cookie name does contain an equals sign `=`
* The cookie value does contain a semicolon `;`

The `value`, `value-any-of` and `value-one-of` validations are not supported for named cookies. The `directives`
element is also not supported for named cookies.

### Validating Custom Headers

You can include custom headers for validation, and run the same validations on them, as you would any standard headers.
If providing multiple expected or disallowed values for value, avoid or contain checks, you need to specify the relevant
delimiters in the `item-delimiter`, `key-delimiter` and `value-delimiter` elements:

```yaml
X-Custom-Header:
    Required: True
    Must-Contain:
        - item_value_1
        - item_value_2
    Item-Delimiter: ;
    Key-Delimiter: =
    Value-Delimiter: ,
```

For example, the above rule would identify the directives `item_1 = value_1, value_2`, `item_2 = value_1` and `item_3`
from the header given below:

```json
{
    "X-Custom-Header": "item_1 = value_1, value_2; item_2 = value_1; item_3"
}
```

If the directives are not declared in a key-value format, or the value does not support multiple items, you can omit the
`key-delimiter` and `value-delimiter` elements respectively.

## Example Use Cases

### Hardening the CSP

```yaml
Content-Security-Policy:
    Required: True
    Must-Avoid:
        - unsafe-inline
        - unsafe-eval
        - unsafe-hashes
    Directives:
        Default-Src:
            Required: True
            Must-Contain: 'https:'
        Script-Src:
            Required: True
            Value: self
```

### Securing Cookies

```yaml
Set-Cookie:
    Required: Optional
    Must-Contain:
        - HttpOnly
        - SameSite=Strict
        - Secure
    Must-Contain-One:
        - Max-Age
        - Expires
```

### Preventing Caching

```yaml
Cache-Control:
    Required: True
    Value:
        - no-store
        - max-age=0
Pragma:
    Required: True
    Value: no-cache
```

### Enforcing Cross-Origin Isolation

```yaml
Cross-Origin-Embedder-Policy:
    Required: True
    Value: require-corp
Cross-Origin-Opener-Policy:
    Required: True
    Value: same-origin
```

** Note that cross-origin isolation validations are opt-in *(see
[cross-origin isolation](README.md#cross-origin-isolation))*

### Enforcing a Fallback Referrer Policy

```yaml
Referrer-Policy:
    Required: True
    Value:
        - no-referrer
        - strict-origin-when-cross-origin
    Preserve-Order: True
```

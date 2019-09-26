# Introduction

This document describes the format of the `rules.yml` file. This file defines the policy drHEADer relies on to audit security headers. It also documents how to make changes to it so that you can configure your custom policy based on your particular requirements. 

# File Format

drHEADer policy is a yaml file, which is a human-readable format commonly used for configuration files. See a yaml sample drHEADer policy below:

```yaml
Headers:
  X-Frame-Options:
    Required: True
    Enforce: True
    Value:
    - SAMEORIGIN
    - DENY
  X-XSS-Protection:
    Required: True
    Enforce: True
    Value:
    - 1; mode=block
  Server:
    Required: False
    Enforce: False
    Value:
  Content-Security-Policy:
    Required: True
    Enforce: False
    Value:
    Must-Contain-One:
    - default-src 'none'
    - default-src 'self'
    Must-Avoid:
    - unsafe-inline
    - unsafe-eval
  Set-Cookie:
    Required: Optional
    Enforce: False
    Value:
    Must-Contain:
    - HttpOnly
    - Secure
  Cache-Control:
    Required: True
    Enforce: True
    Delimiter: ','
    Value:
    - no-cache, no-store, must-revalidate
```

# File Structure

The yaml file structure for drHEADwe is as follows:

* There must always be a root element with name 'Headers:'
* Inside the root element, there must be as many elements as headers you want drHEADer to audit (ie: Content-Security-Policy, Set-Cookie, etc.)
* For each of these elements (or security headers to audit), the following flags can be set based on the specific requirements for that header:
    * Required:
        * 'True' if header is required to be present in the HTTP response
        * 'False' if header is not required to be present in the HTTP response
        * 'Optional' if header can be present in the HTTP response but is not mandatory
    * Enforce:
        * 'True' if the policy enforces a value for that header (full match)
        * 'False' if the policy does not enforce a value for that header
    * Value:
        * It must be empty if 'Enforce' is set to False, otherwise
        * It must be set to a list of values that would be accepted for that header. The validation will be successful if there is a full match (value in header matches with value in policy) with one of the values defined
    * Delimiter: To be used when a header is enforced and the value specified contains multiple values that would be valid in any order (see example for Cache-Control). Default delimiter is ';'.  
    * Must-Contain: To be used when 'Required' is set to True or Optional and 'Enforce' is set to False.  
        * It can be set to a list of values that should be part of the header value. The validation will be successful if all values specified are found in the value set for that header (ie: for set-cookie the policy specifies that httponly AND secure should be part of the header value)
    * Must-Contain-One: To be used when 'Required' is set to True or Optional and 'Enforce' is set to False.  
        * It can be set to a list of values where at least one should be part of the header. The validation will be successful if at least one value is found in the value set for that header (ie: for Content-Security-Policy the policy specifies that either "default-src 'none'" OR "default-src 'self'" should be part of the header value)
    * Must-Avoid: To be used when 'Required' is set to True or Optional and 'Enforce' is set to False.
        * It can be set to a list of values that should not be part of the header. The validation will be successful if none of the values are found in the value set for that header (ie: for Content-Security-Policy the policy specifies that "unsafe-inline" AND "unsafe-eval" should not be part of the header value)

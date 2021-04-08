# Content Security Policy (CSP) module for Silverstripe websites

> Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement to distribution of malware.

Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

This module provides the ability to:

+ Create one or more CSP records within the administration area of your website and make one of those the base policy for use on the website
+ Set a CSP record to be [report only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only)
+ Collect CSP Violation reports internally via a controller or via a specific URL/service
+ Add page specific CSP records, which work with or without the base policy
+ Add a per-request nonce

Once a CSP is in place and working, any assets loads that do not meet policy requirements will be blocked from loading, with warnings similar to this in the browser dev console:

<code>Refused to load the script 'https://badactor.example.com/eval.js' because it violates the following Content Security Policy directive: "script-src 'self' 'nonce-example' https://cdnjs.cloudflare.com/".</code>

## Versioning

This is the Silverstripe 4.x version of the module, with releases tagged as v0.2 and up

The Silverstripe 3.x version with releases tagged as v0.1. While none are planned, any future releases of the `ss3` branch will remain at 0.1.x

## Installation

The only supported method of installing this module is via composer:

```
composer require nswdpc/silverstripe-csp
```

## Instructions

> :warning: An incorrectly implemented CSP can have negative effects for valid visitors to your website.

0. Read the [initial documentation](./docs/en/00_index.md)
0. Read the [good-to-know section](./docs/en/01_good_to_know.md)
0. Install the module on a development instance of your website and [configure it]((./docs/en/00_index.md#configuration))
0. Add at least one Policy record in the "CSP" administration section.
    * Set it to 'report only'
    * Mark it as the 'base policy'
    * Optionally, make it available on your draft site only
0. Set the policy to be delivered via a HTTP headers (you can use meta tags but this method limits the feature you can use).
0. Add some Directives
0. Mark the Policy 'Enabled', save it and
0. Watch for violation reports or look at your browser dev console

When you are pleased with the settings, check the "Use on published website" setting and save.

After UAT is complete, implement the same process on your production website. You should run the policy as report-only and monitor reports, initially.

## Page specific policies

By default Pages can define an extra Policy for delivery when requested with the following caveat:

> Adding additional policies can only further restrict the capabilities of the protected resource

[MDN provides some useful information on this process](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#Multiple_content_security_policies):

This means that you can't (currently) relax the base policy restrictions from within your page policy.

## Using a nonce

See [using a nonce](./docs/en/10_using_a_nonce.md)

## Good-to-know

See [good-to-know](./docs/en/01_good_to_know.md)

## Violation Reports

See [reporting](./docs/en/05_reporturi_and_other_services.md)

## Minimum CSP Level

Refer to the following for changes between levels:

+ [Changes from Level 1 to 2](https://www.w3.org/TR/CSP2/#changes-from-level-1)
+ [Changes from Level 2 to 3](https://www.w3.org/TR/CSP3/#changes-from-level-2)

## Additional Help

See [further reading](./docs/en/00_index.md#further-reading)

## Browser Compatibility

See [browser support](./docs/en/02_browser_support.md)

## Maintainers

+ [dpcdigital@NSWDPC:~$](https://dpc.nsw.gov.au)


## Bugtracker

We welcome bug reports, pull requests and feature requests on the Github Issue tracker for this project.

Please review the [code of conduct](./code-of-conduct.md) prior to opening a new issue.

## Security

If you have found a security issue with this module, please email digital[@]dpc.nsw.gov.au in the first instance, detailing your findings.

## Development and contribution

If you would like to make contributions to the module please ensure you raise a pull request and discuss with the module maintainers.

Please review the [code of conduct](./code-of-conduct.md) prior to completing a pull request.

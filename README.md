# SilverStripe Content Security Policy module

This module provides the ability to:

+ Create one or more CSP records within the administration area and make one of those the base policy for use on the website
+ Set a CSP record to be report only
+ Collect CSP Violation reports internally via a controller or via a specific URL
+ Add page specific CSP records, which work with or without the base policy
+ Add a per-request nonce

## Versioning
This is the Silverstripe 4.x version of the module, with releases tagged as v0.2 and up

The Silverstripe 3.x version with releases tagged as v0.1 - any future versions will remain at 0.1.x

## Instructions

0. Read the gotchas section below
0. Install the module
0. Add at least one Policy record in the "CSP" administration section.
    * Set it to 'report only'
    * Mark it as the 'base policy'
    * Optionally, make it available on your draft site only
0. Set the policy to be delivered via a HTTP headers (you can use meta tags but this method limits the feature you can use).
0. Add some Directives
0. Mark the Policy 'Enabled', save it and
0. Watch for violation reports or look at your browser dev console

When you are pleased with the settings, check the "Use on published website" setting and save.

## Page specific policies

By default Pages can define an extra Policy for delivery when requested with the following caveat:

> Adding additional policies can only further restrict the capabilities of the protected resource

[MDN provides some useful information on this process](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#Multiple_content_security_policies):

This means that you can't (currently) relax the base policy restrictions from within your page policy.

## Using a nonce

The module will set a nonce ('number once') per request, which will be applied to relevant elements in the page prior to output. This is a handy way to whitelist inline trusted scripts that are added by modules.

In order to use the nonce in the relevant elements, the directive value "Use Nonce" must be checked in the Directive's admin screen.

### Examples
Before nonce
```
<script>var = 'foo';</script>
```

After nonce
```
<script nonce="request_nonce">var = 'foo';</script>
```

Application of the nonce occurs in middleware regardless of the Requirements backend used.

Only inline scripts and style elements added by the Requirements API will get the nonce attribute added.

Any script added in a template will not receive a nonce, to whitelist these scripts you should add a matching SHA256, SHA384 or SHA512 hash for the script (of everything between the <script></script> tags) to whitelist these scripts.

If inline scripts are injected into your page, supporting browsers will block their execution.

## Gotchas

### unsafe-eval in the /admin
The Silverstripe Admin requires the CSP directive ```'unsafe-eval'``` for ```script-src```. [It's wise to not allow unsafe-eval in a policy](https://developers.google.com/web/fundamentals/security/csp/#eval_too) - but if this is not set in a policy, the admin will not load.

To avoid getting locked out of the admin, set the ```run_in_admin``` config value to ```false``` - note that this will stop the policy from being delivered in any controller that is a child of ```LeftAndMain```

The configuration value ```run_in_admin``` is shipped as false by default.

### Whitelisting controllers

You can whitelist certain controllers in module config. This will block the policy from being delivered in those controllers.

> Override module configuration in your project configuration.

### Using meta tags

You can choose to deliver the CSP via meta tags.

Choosing this option will cause certain features to be unavailable
* The ```report-uri``` and ```report-to``` directives are not supported in meta tags and will not be present
* The ```Content-Security-Policy-Report-Only``` header is not supported, currently.

The only way to received policy violation reports is via HTTP Header delivery method.

## Violation Reports

You can choose to receive violation reports when they occur at a reporting service that can handle CSP reports.

The module provides its own controller for receiving violation reports - be aware that enabling local reporting could cause load issues on higher traffic websites.

## Minimum CSP Level

Refer to the following for changes between levels
+ [Changes from Level 1 to 2](https://www.w3.org/TR/CSP2/#changes-from-level-1)
+ [Changes from Level 2 to 3](https://www.w3.org/TR/CSP3/#changes-from-level-2)

## Additional Help

The following developer documention URLs provide a wealth of information regarding CSP and web browser support:
* [Google Developer Docs - CSP](https://developers.google.com/web/fundamentals/security/csp/)
* [MDN docs - CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
* [Content Security Policy (CSP) Quick Reference Guide](https://content-security-policy.com/)

## Browser Compatibility

MDN provides an [extensive browser support matrix](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#Browser_compatibility), as does [Can I Use](https://caniuse.com/#feat=contentsecuritypolicy)

Note that Internet Explorer will never get support for nearly all CSP directives.

## Authors

+ [dpcdigital@NSWDPC:~$](https://dpc.nsw.gov.au)

## Bugs

Please report bugs to the Github issues list

## License

BSD-3 clause

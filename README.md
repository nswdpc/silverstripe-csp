# SilverStripe Content Security Policy module

This module provides the ability to:

+ Create one or CSP records and make one of those the active record
+ Set a CSP record to be report only
+ Collect CSP Violation reports internally via a controller or via a specific URL

> This module is under development and currently supports Silverstripe 3


## Instructions

0. Read the gotchas section below
1. Install the module
2. Add at least one policy record, best if you set it to 'report only' at the start & make it available on your draft site only
3. Set the policy to be delivered via a meta tag or via a HTTP headers (recommended: HTTP headers)
4. Enable the policy
5. Watch for any violation reports

A good set of settings to start out with is:
1. Enabled: on - make it available for use
2. Use on published website: off - only draft site readers will get the Content-Security-Policy
3. Report Only: off or on - this is up to you. When off, assets that violate the policy will not be shown/evaluated
4. Send Violation Reports: off or on - when on, reports will be sent to the configured reporting endpoint

When you are pleased with the settings, check the "Use on published website" setting and save.

## Gotchas

### unsafe-eval in the /admin
The Silverstripe Admin requires the CSP rule ```'unsafe-eval'``` for ```script-src```. [It's wise to not allow unsafe-eval in a policy](https://developers.google.com/web/fundamentals/security/csp/#eval_too) - but if this is not set in a policy, the admin will not load.

To avoid getting locked out of the admin, set the ```run_in_admin``` config value to ```false``` - note that this will stop the policy from being delivered in any controller that is a child of ```LeftAndMain```

The configuration value ```run_in_admin``` is shipped as false by default.

### Whitelisting controllers

You can whitelist certain controllers in module config. This will block the policy from being delivered in those controllers.

> Override module configuration in your project configuration.

### Using meta tags
You can choose to deliver the CSP via meta tags.

Choosing this option will cause certain features to be unavailable, for instance ```report-uri``` and ```report-to``` are not supported in meta tags. You can only get Violation Reports when using the ```Via an HTTP Header``` delivery method.

### Violation Reports
You can receive violation reports when they occur.

The module provides its own endpoint for receiving violation reports - be aware that enabling the local reporting endpoint could cause load issues on higher traffic websites.

## Additional Help

The following developer documention URLs provide a wealth of information regarding CSP and web browser suport:
* [Google Developer Docs - CSP](https://developers.google.com/web/fundamentals/security/csp/)
* [MDN docs - CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

### Browser Compatibility

MDN provides an [extensive browser support matrix](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#Browser_compatibility), as does [Can I Use](https://caniuse.com/#feat=contentsecuritypolicy)

## Bugs

Report bugs to the Github issues list

# SilverStripe Content Security Policy module

This module provides the ability to:

+ Create one or more CSP records and make one of those the base policy for use on the website
+ Set a CSP record to be report only
+ Collect CSP Violation reports internally via a controller or via a specific URL
+ Add page specific CSP records, which work with or without the base policy

> This is the Silverstripe 4.x version of the module

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

## Page specific policies

By default Pages can define a specific Policy for delivery when requested.
If one is selected, it is merged into the base policy (if it exists) or is used as the policy for that request.

[MDN provides some useful information on this process](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#Multiple_content_security_policies):
> Adding additional policies can only further restrict the capabilities of the protected resource
This means that you can't relax the base policy restrictions from within your page policy.

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

Choosing this option will cause certain features to be unavailable, for instance ```report-uri``` and ```report-to``` are not supported in meta tags. You can only get Violation Reports when using the ```Via an HTTP Header``` delivery method.

## Violation Reports
You can receive violation reports when they occur.

The module provides its own endpoint for receiving violation reports - be aware that enabling the local reporting endpoint could cause load issues on higher traffic websites.

## Minimum CSP Level

Refer to the following for changes between levels
+ [Changes from Level 1 to 2](https://www.w3.org/TR/CSP2/#changes-from-level-1)
+ [Changes from Level 2 to 3](https://www.w3.org/TR/CSP3/#changes-from-level-2)

## Additional Help

The following developer documention URLs provide a wealth of information regarding CSP and web browser support:
* [Google Developer Docs - CSP](https://developers.google.com/web/fundamentals/security/csp/)
* [MDN docs - CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

### Browser Compatibility

MDN provides an [extensive browser support matrix](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#Browser_compatibility), as does [Can I Use](https://caniuse.com/#feat=contentsecuritypolicy)

## Bugs

Report bugs to the Github issues list

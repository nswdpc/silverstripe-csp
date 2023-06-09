# Good-to-know

## unsafe-eval in the /admin
The Silverstripe Admin requires the CSP directive ```'unsafe-eval'``` for ```script-src```. [It's wise to not allow unsafe-eval in a policy](https://developers.google.com/web/fundamentals/security/csp/#eval_too) - but if this is not set in a policy, the admin will not load.

To avoid getting locked out of the admin, set the ```run_in_admin``` config value to ```false``` - note that this will stop the policy from being delivered in any controller that is a child of ```LeftAndMain```

The configuration value ```run_in_admin``` is shipped as false by default.

## Whitelisting controllers

You can whitelist certain controllers in module config. This will block the policy from being delivered in those controllers.

> Override module configuration in your project configuration.

## Getting started with a CSP

> For an overview of the module, view the README.md in the module root.


Once the module is installed, a "CSP" menu entry will be available to certain users in the administration area.

As an administrator, you can modify the members who have access to this by assigning the relevant permissions to certain groups via the "Security" section. For instance you have a trusted group that can edit a Policy and/or Directives.

> Anyone who can edit your the Policy and Directives can modify the CSP restrictions in place

### Policy Options

+ **Title** - add a human readable title, only used in the admin
+ **Enabled** - turn the policy on/off
+ **Minimum CSP Level** - 1, 2 or 3
+ **Use on published website** - when checked, the policy will be available on Live stage requests. You can use this to test a policy on the Draft stage only
+ **Is Base Policy** - check to make this the site-wide policy
+ **Report Only** - adds the header "Content-Security-Policy-Report-Only", the policy will report to the browser's dev console and log to an endpoint if you have one configured. Reporting is not available when using meta tags to deliver CSP rules.
+ **Send violation reports** - when checked, adds the Report-To header and report-uri directive to the policy
+ **Reporting URL** - add the reporting URL for logging violations, this can be left empty to report back to the website (not recommended). You can add, for instance, a report-uri.com logging URL here.
+ **Enable NEL** - turned on Network Error Logging via the NEL header
+ **NEL Reporting URL** - adds the NEL logging URL to the Report-To header
+ **Delivery Method** -  Via an HTTP header (recommended) or a metatag. The module may remove the Metatag option in the future to simplify code.

To start with, add a policy with the "Enabled" box unchecked. Once the policy is configured you can then add directives to it.

Once a policy with directives is saved, an example of the policy will display.

### Adding Directives

Either enter the directive name or choose from the list of pre-defined directives.

The list of available directives is [defined at MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) and other places.

> Prior to adding a directive, you should understand the format required for each directive. Some directives require no values e.g ```upgrade-insecure-requests```

The value of the directive will be the URLs and other rules that make up the allowed sources.

### Rules and Restrictions

In this section add directive names in the left field. The right field can be used for your own notes/reasoning for the rule.

+ **Include Self** - adds the 'self' value to the directive
+ **Unsafe Inline** - allows inline scripts to be run, this is not recommended. See the ['Using a nonce'](./10_using_a_nonce.md) documentation page for more information
+ **Allow Data URI** - adds the ```data:``` value to the directive, e.g allowing images to be loaded from base64 encoded data.
+ **Enabled** - enables the directive
+ **Use Nonce** - Adds a system generated nonce value to supporting directives. See the ['Using a nonce'](./10_using_a_nonce.md) documentation page for more information

### Violation Reports

You can choose to report policy violations to your own website. This is not recommended if you have a high traffic website and your policy is causing lots of reports. It can be used in a development/testing environment to fine tune a report.

In production you can use a reporting tool such as report-uri.com to handle report collection.

> The ```PruneViolationReportsJob``` exists to remove old reports after a certain time.

## Further reading

+ [MDN Content-Security-Policy documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
+ [Google Web Fundamentals - Content Security Policy](https://developers.google.com/web/fundamentals/security/csp/)
+ [Chrome Content Security Policy notes](https://developer.chrome.com/extensions/contentSecurityPolicy)
+ [W3C CSP Level 2 Recommendation](https://www.w3.org/TR/CSP2/)
+ [W3C CSP Level 3 Draft Spec](https://www.w3.org/TR/CSP3/)
* [Content Security Policy (CSP) Quick Reference Guide](https://content-security-policy.com/)

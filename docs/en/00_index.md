## Getting started with a CSP

> For an overview of the module, view the README.md in the module root.

### Configuration

The default configuration can be found in  `_config/config.yml` and set on [a per-environment basis](https://docs.silverstripe.org/en/5/developer_guides/configuration/configuration/#before-after-rules)

```yml
---
Name: app-csp-config
After:
  - '#csp_configuration'
---
NSWDPC\Utilities\ContentSecurityPolicy\Policy:
  # reduce the max_age value
  max_age: 120
```


#### About the `nonce_injection_method`

+ Value = 'requirements' uses an injected Requirements_Backend to add the nonce as an attribute to assets required via the Requirements API
+ Value = 'middleware' uses DOMDocument to add the nonce attribute to applicable elements in the page, prior to it being delivered.

In the future, the 'requirements' method will become the only option.

## Post-installation

Once the module is installed, a "CSP" menu entry will be available to certain users in the administration area.

As an administrator, you can modify the members who have access to this by assigning the relevant permissions to certain groups via the "Security" section. For instance you have a trusted group that can edit a Policy and/or Directives.

> Anyone who can edit your the Policy and Directives can modify the CSP restrictions in place

### Policy

To start with, add a policy with the "Enabled" box unchecked. Once the policy is configured you can then add directives to it.

+ **Title** - add a human readable title, only used in the admin

#### Policy Options

+ **Enabled** - turn the policy on/off
+ **Minimum CSP Level** - 1, 2 or 3. Setting this value to 3 will turn off the "report-uri" directive
+ **Use on published website** - when checked, the policy will be available on Live stage requests. You can use this to test a policy on the Draft stage only
+ **Is Base Policy** - check to make this the site-wide policy

#### CSP Reporting

+ **Send violation reports** - when checked, adds the Report-To header and report-uri directive to the policy
+ **Report Only** - adds the header "Content-Security-Policy-Report-Only", the policy will report to the browser's dev console and log to an endpoint if you have one configured.
+ **Endpoint for report-uri violation reports** - add the reporting URL for logging violations, this can be left empty to report back to the website (not recommended). You can add, for instance, a report-uri.com logging URL here.
+ **Endpoint for Reporting API (report-to) violation reports** - add a URL for handling Reporting API reports. Some services have separate CSP reporting endpoints for report-uri and report-to.

#### NEL Reporting
+ **Set an NEL/Reporting API reporting URL** - adds the NEL logging URL to the Report-To header. You must use an external service for this.
+ **Enable Network Error Logging (NEL)** - turned on Network Error Logging via the NEL header

### Delivery options
+ **Delivery Method** - The policy is delivered by HTTP response headers

### Adding Directives

Either enter the directive name or choose from the list of pre-defined directives.

The list of available directives is [defined at MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) and other places.

> Prior to adding a directive, you should understand the format required for each directive. Some directives require no values e.g ```upgrade-insecure-requests```

The value of the directive will be the URLs and other rules that make up the allowed sources.

### Supported options

> If you have a requirement to use 'unsafe-eval', add it as an extra quoted value. See Extra values, below.

+ **Enabled** - enables the directive. Unchecking this allows you to remove a directive, temporarily, from a live policy
+ **Include Self** - adds the 'self' value to the directive
+ **Unsafe Inline** - allows inline scripts to be run, this is not recommended. See the ['Using a nonce'](./10_using_a_nonce.md) documentation page for more information
+ **Allow Data URI** - adds the ```data:``` value to the directive, e.g allowing images to be loaded from base64 encoded data.
+ **Use Nonce** - Adds a per-request, system generated nonce value to supporting directives. See the ['Using a nonce'](./10_using_a_nonce.md) documentation page for more information

### Extra values

In this section add extra values for the directives in the left field. The right field can be used for your own notes/reasoning for the rule, and to aid with historical context.

### Violation Reports

You can choose to report policy violations to your own website (turned off by default).

This is not recommended if you have a high traffic website and your policy is causing lots of reports. It can be used in a development/testing environment to fine tune a report.

In production you can use a reporting tool such as report-uri.com to handle report collection.

> The ```PruneViolationReportsJob``` exists to remove old reports after a certain time.

## Further reading

+ [MDN Content-Security-Policy documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
+ [Google Web Fundamentals - Content Security Policy](https://developers.google.com/web/fundamentals/security/csp/)
+ [Chrome Content Security Policy notes](https://developer.chrome.com/extensions/contentSecurityPolicy)
+ [W3C CSP Level 2 Recommendation](https://www.w3.org/TR/CSP2/)
+ [W3C CSP Level 3 Draft Spec](https://www.w3.org/TR/CSP3/)
* [Content Security Policy (CSP) Quick Reference Guide](https://content-security-policy.com/)

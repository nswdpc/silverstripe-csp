## Reporting Services

There are a number of services that can be used to collect CSP reports, one example is report-uri.com.

> The NSW Department of Premier and Cabinet does not make any service recommendations, this information is provided as a guide only and you are free to use whichever service you find suitable.

### Configuring Report URI

Assuming you have set up your account, to configure this module to use report-uri as a reporting endpoint:

1. Set your Policy to "Report Only", this will produce a "Content-Security-Policy-Report-Only" header
2. Choose Setup, then choose "Wizard" under "Policy Disposition"
3. Copy the URL provided to the reporting URL field in the CSP module admin screen
4. If you are using NEL, copy the Reporting API URL value to the "NEL/Reporting API reporting URL" field in the policy
5. Save the policy in the CSP screen admin.

Once that is done, load your website and you may see some reports in the browser dev console tab. Over in the report-uri.com website, choose "CSP > Wizard" and you will see a list of directives and values that should be added to your policy.

Add and/or update the relevant directives and when happy, save your policy.

### Set to Report-Only URL
Once your policy is not reporting anything to the wizard (hint: Choose 'Clear all' in the Wizard screen), you can then switch the Reporting URL to the "Report Only" URL provided in the report-uri setup screen.

This will log violations to report-uri.com which will appear in the Reporting screen and graphs.

### Enforcing the policy
When you are comfortable your website will operate correctly with the Policy in place, you can switch to using the 'Enforce' URL and turn off "Report Only" in the module admin screen for the policy.


##$ Other services for reporting

+ [https://github.com/seek-oss/csp-server - CSP (Content Security Policy) reports server which forwards reports to Elasticsearch.](https://github.com/seek-oss/csp-server)
+ [ttps://docs.sentry.io/error-reporting/security-policy-reporting/ - Sentry Security Policy Reporting](https://docs.sentry.io/error-reporting/security-policy-reporting/)

If you know of any other services, please make a pull request on this file or create an issue on this module.

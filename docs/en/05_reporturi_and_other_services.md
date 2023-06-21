## Reporting Services

You can choose to receive violation reports when they occur at a reporting service that can handle CSP reports.

> NSWDPC does not make any service recommendations, this information is provided as a guide only and you are free to use whichever service you find suitable.

### Using a reporting service

Most services have both a report-uri reporting endpoint and a report-to reporting endpoint.

In the policy screen:

1. Copy the report-uri URL provided by the service to the "Endpoint for report-uri violation reports" field in the Policy editing screen
1. Copy the "Reporting API" URL provided to the "Endpoint for Reporting API (report-to) violation reports" field in the Policy editing screen
4. If you are using NEL, copy the Network Error Logging "Reporting API" URL value to the "NEL/Reporting API reporting URL" field in the Policy editing screen
5. Save the policy

Reports will show up in your report-uri.com within a few minutes.

### Other services for reporting

+ [report-uri](https://report-uri.com)
+ [Sentry Security Policy Reporting](https://docs.sentry.io/error-reporting/security-policy-reporting/)
+ [csper](https://csper.io/about)
+ [Raygun](https://raygun.com/documentation/language-guides/browser-reporting/crash-reporting/csp/)
+ [Datadog](https://www.datadoghq.com/blog/content-security-policy-reporting-with-datadog/#csp-reporting-with-datadog)
+ [Seek OSS / CSP Server](https://github.com/seek-oss/csp-server)

If you know of any other services, please make a pull request on this file or create an issue on this module.

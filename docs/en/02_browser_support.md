## Browser support

According to Can I Use, [CSP Level 1](https://caniuse.com/#feat=contentsecuritypolicy) is supported by about 92% of the browser population.

Notable exceptions are Internet Explorer 10 and 11, which only support the ```sandbox``` directive.

All versions of Internet Explorer are end-of-life and this module will not support CSP.

[CSP Level 2](https://caniuse.com/#feat=contentsecuritypolicy2) is supported by nearly all modern browsers, with the following exceptions:

+ Firefox is missing the ```plugin-types``` directive
+ [Edge non-Chromium has broken nonce support](https://developer.microsoft.com/en-us/microsoft-edge/platform/issues/13246371/)

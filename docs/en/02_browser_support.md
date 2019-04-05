## Browser support

Accodrding to Can I Use, [CSP Level 1](https://caniuse.com/#feat=contentsecuritypolicy) is supported by about 92% of the browser population.

Notable exceptions are Internet Explorer 10 and 11, which only support the ```sandbox``` directive.

All versions of Internet Explorer are end-of-life and this module will not support them, it's recommended you upgrade to a modern browser in order to benefit from a CSP.

[CSP Level 2](https://caniuse.com/#feat=contentsecuritypolicy2) is supported by nearly all modern browsers, with the following exceptions:

+ Firefox is missing the ```plugin-types``` directive
+ [Edge has broken nonce support](https://developer.microsoft.com/en-us/microsoft-edge/platform/issues/13246371/) - it is probable this will be fixed when Edge moves to Chromium.

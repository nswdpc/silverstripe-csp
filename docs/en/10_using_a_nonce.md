# Using a nonce

## Background

The module will set a nonce ('number once') per request, which will be applied to relevant elements in the page prior to output. This is a handy way to whitelist inline trusted scripts that are added by modules.

In order to use the nonce in the relevant elements, the directive value "Use Nonce" must be checked in the Directive's administration screen.

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

> If inline scripts are injected into your page, supporting browsers will block their execution.


## Further information

Most websites will make use of inline scripts to perform certain actions. This can be as simple as an onload attribute in an ```<img>``` tag or  use of Google Tag Manager.

Services like Google Tag Manager rely on the ability to run scripts on your website, for instance you can add tracking scripts to your website via GTM. These will be blocked by your CSP.

One workaround is to use the ```unsafe-inline``` and/or ```unsafe-eval``` to allow these scripts; but as the same suggests this is 'unsafe'. Any attacker that can inject scripts onto a web page would then bypass the Policy which is not the desired result.

To work with inline scripts, either:

+ remove the inline scripts if possible. Do you really need onload/onclick handlers? These can be moved into an external script.
+ try to move any scripts in ```<script>``` tags to external scripts loaded from an approved host name.
+ use a hash of the script contents to approve certain inline scripts
+ use a nonce (**n**umber **once**) on all approved scripts
+ use the `strict-dynamic` directive

### Alternative: using an integrity hash

CSP allows you to use a hash of the contents of a script or style tag to be added to the relevant directive, such that inline resources matching the hash are allowed to run.

Consider the following script without a nonce

```
<script> var foo = 'bar'; </script>
```

Using a sha256 hash, this will produce the following value:

```
sha256-TtP3pUooIY6AQqO/ARoT0XwDLJ5XkPvFN7Pr5uJynHk=
```

The method of obtaining this value is as follows, in pseudocode:

```
$hash_value = 'sha256-' + base64_encode( sha256_hash( " var foo = 'bar'; " ) );
```

In PHP, the value can be obtained via the following script:
```
php -a
php > print 'sha256-' . base64_encode( hash("sha256", " var foo = 'bar'; ", true) );
sha256-TtP3pUooIY6AQqO/ARoT0XwDLJ5XkPvFN7Pr5uJynHk=
```

When generating a value, note the following information from the CSP spec:

>  When generating the hash, don't include the ```<script>``` or ```<style>``` tags and note that capitalisation and whitespace matter, including leading or trailing whitespace

Once you have obtained the hash value, it can be added to the relevant directive.

Some browsers will report the required hash that needs to be added to the policy but you should ensure this is the hash of a valid script prior to whitelisting it!

> Inline scripts that are added dynamically will need to have a hash generated for them. If you use a service such as Google Tag Manager, this is something to be aware of.

## Dynamically generated scripts

If you have the misfortune of loading inline scripts that return modified contents when requested then you will find these difficult to allow unless they can be hosted under a URL that is whitelisted. Try contacting the author of the script if this is the case.

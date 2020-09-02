<html lang="en">
<head>
    <meta charset="utf-8">
    <title>NONCE TEST FOR SITETREE</title>
    <!-- this script has been added inline in the template and should not get a nonce -->
    <script data-should-nonce="0">var foo='bar';</script>
    <% require customScript("var template_custom_script=1;","template_custom_script") %>
    <% require customCSS("address { background:ultra-black; }","template_custom_style") %>
    <link rel="stylesheet" type="text/css" href="/path/to/some/style.css" data-should-nonce="0">
</head>
        <body>
                <h1>Home</h1>

                <div class="text">

                    <h2>This is a test page to check how nonces attributes are added to elements in the page</h2>
                    <p>Spare ribs ribeye filet mignon meatloaf beef landjaeger bacon turducken cow tongue pork loin.<.p>
                    <p>Brisket strip steak meatloaf ball tip, jowl hamburger pork loin pancetta spare ribs turducken biltong.</p>
                    <p>Jowl ham hock chicken cow. Filet mignon spare ribs capicola, sausage t-bone fatback drumstick.<br>
                        Short ribs capicola turducken t-bone chicken. Salami chicken pig pork sirloin shoulder.</p>

                    <p><code>&lt;script data-should-nonce=&quot;0&quot;&gt;var foo=&#039;code&#039;;&lt;/script&gt;</code></p>

                </div>

                <!-- <script data-should-nonce="0">var test='a comment';</script> -->

                <style type="text/css" data-should-nonce="0">
                    p {
                        color : 'bacon';
                    }
                </style>

                <!-- <style data-should-nonce="0"> h2 { color: #000; }</style> -->

        </body>

        <script src="/path/to/some/script.js" data-should-nonce="0"></script>
        <script src="/path/to/another/script.js" data-should-nonce="0">
            <!-- override nonce in this script -->
        </script>
</html>

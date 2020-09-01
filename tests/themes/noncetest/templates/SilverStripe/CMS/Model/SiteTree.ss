<html lang="en">
<head>
    <meta charset="utf-8">
    <title>NONCE TEST FOR SITETREE</title>
    <script data-should-nonce="1">var foo='bar';</script>
    <link rel="stylesheet" type="text/css" href="/path/to/some/style.css" data-should-nonce="1">
</head>
        <body>
                <h1>Home</h1>

                <div class="text">

                    <h2>This is a test page to check how nonces attributes are added to elements in the page</h2>
                    <p>Spare ribs ribeye filet mignon meatloaf beef landjaeger bacon turducken cow tongue pork loin.<.p>
                    <p>Brisket strip steak meatloaf ball tip, jowl hamburger pork loin pancetta spare ribs turducken biltong.</p>
                    <p>Jowl ham hock chicken cow. Filet mignon spare ribs capicola, sausage t-bone fatback drumstick.<br>
                        Short ribs capicola turducken t-bone chicken. Salami chicken pig pork sirloin shoulder.</p>

                    <p><code>&lt;script&gt;var foo='code';&lt;/script&gt;</code></p>

                </div>

                <!-- <script>var test='a comment';</script> -->

                <style type="text/css" data-should-nonce="1">
                    p {
                        color : 'bacon';
                    }
                </style>

                <!-- <style> h2 { color: #000; }</style> -->

        </body>

        <script src="/path/to/some/script.js" data-should-nonce="1"></script>
        <script src="/path/to/some/script.js" data-should-nonce="1" nonce="another-nonce">
            <!-- override nonce in this script -->
        </script>
</html>

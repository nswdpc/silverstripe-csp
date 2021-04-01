<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\Core\Config\Config;

class NonceTest extends SapphireTest {

    public function testShortNonce() {
        $min_length = Nonce::MIN_LENGTH;
        // set an 8 chr nonce length
        $length = round($min_length / 2);
        Config::inst()->update( Policy::class, 'nonce_length', $length);
        $nonce = new Nonce(true);
        $this->assertNotEmpty($nonce->get(), "Nonce is empty");
        // nonce should be a minimum of 32 chrs
        $value = $nonce->get();
        $this->assertNotEquals(strlen($value), $length, "Nonce should not be {$length} chrs, {$min_length} chr minimum");
    }

    public function testExactLengthNonce() {
        $min_length = Nonce::MIN_LENGTH;

        // set a $min_length chr nonce length
        $length = $min_length;
        Config::inst()->update( Policy::class, 'nonce_length', $length);
        $nonce = new Nonce(true);
        $this->assertNotEmpty($nonce->get(), "Nonce is empty");
        $value = $nonce->get();
        $this->assertEquals(strlen($value), $length, "Nonce should be {$length} chrs");

    }

    public function testLongLengthNonce() {
        $min_length = Nonce::MIN_LENGTH;

        // set a $min_length chr nonce length
        $length = ($min_length * 2);
        Config::inst()->update( Policy::class, 'nonce_length', $length);
        $nonce = new Nonce(true);
        $this->assertNotEmpty($nonce->get(), "Nonce is empty");
        $value = $nonce->get();
        $this->assertEquals(strlen($value), $length, "Nonce should not be {$length} chrs");

    }
}

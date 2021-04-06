<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Nonce;
use NSWDPC\Utilities\ContentSecurityPolicy\Policy;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;

class NonceTest extends SapphireTest {

    public function testShortNonce() {
        $min_length = Nonce::MIN_LENGTH;
        // set an 8 chr nonce length
        $length = round($min_length / 2);
        Config::inst()->update( Policy::class, 'nonce_length', $length);
        $nonce = new Nonce(true);
        $this->assertNotEmpty(Nonce::getNonce(), "Nonce is empty");
        // nonce should be a minimum of 32 chrs
        $value = Nonce::getNonce();
        $this->assertNotEquals(strlen($value), $length, "Nonce should not be {$length} chrs, {$min_length} chr minimum");
    }

    public function testExactLengthNonce() {
        $min_length = Nonce::MIN_LENGTH;

        // set a $min_length chr nonce length
        $length = $min_length;
        Config::inst()->update( Policy::class, 'nonce_length', $length);
        $nonce = new Nonce(true);
        $this->assertNotEmpty(Nonce::getNonce(), "Nonce is empty");
        $value = Nonce::getNonce();
        $this->assertEquals(strlen($value), $length, "Nonce should be {$length} chrs");

    }

    public function testLongLengthNonce() {
        $min_length = Nonce::MIN_LENGTH;

        // set a $min_length chr nonce length
        $length = ($min_length * 2);
        Config::inst()->update( Policy::class, 'nonce_length', $length);
        $nonce = new Nonce(true);
        $this->assertNotEmpty(Nonce::getNonce(), "Nonce is empty");
        $value = Nonce::getNonce();
        $this->assertEquals(strlen($value), $length, "Nonce should not be {$length} chrs");

    }

    /**
     * Test application of attributes
     */
    public function testApplyAttributes() {

        Config::inst()->update( Policy::class, 'override_apply', false);

        $this->assertFalse( Policy::checkCanApply(), 'Policy should NOT be applicable' );

        Config::inst()->update( Policy::class, 'override_apply', true);

        $this->assertTrue( Policy::checkCanApply(), 'Policy should be applicable' );

        $attributes = [
            'type' => 'text/css',
            'media' => 'screen'
        ];

        $nonce = new Nonce(true);
        $nonceValue = Nonce::getNonce();
        Nonce::addToAttributes('style', $attributes);

        $this->assertTrue( array_key_exists('nonce', $attributes) );
        $this->assertEquals( $nonceValue, $attributes['nonce'] );
    }
}

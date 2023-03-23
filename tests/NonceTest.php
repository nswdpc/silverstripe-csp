<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Nonce;
use NSWDPC\Utilities\ContentSecurityPolicy\Policy;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;

class NonceTest extends SapphireTest {

    public function setUp() : void {
        parent::setUp();
        // clear nonce for each test
        Nonce::clear();
    }

    public function testNonceStaysTheSame() {
        Config::modify()->set( Policy::class, 'nonce_length', Nonce::MIN_LENGTH);
        $nonce = Nonce::getNonce();
        $this->assertNotEmpty($nonce, "Nonce is empty");
        $nonce2 = Nonce::getNonce();
        $this->assertEquals($nonce, $nonce2, "Nonce should remain the same");
    }

    public function testShortNonce() {
        $min_length = Nonce::MIN_LENGTH;
        // set an 8 chr nonce length
        $length = round($min_length / 2);
        Config::modify()->set( Policy::class, 'nonce_length', $length);
        $nonce = Nonce::getNonce();
        $this->assertNotEmpty($nonce, "Nonce is empty");
        // nonce should be a minimum of 32 chrs
        $this->assertNotEquals(strlen($nonce), $length, "Nonce should not be {$length} chrs, {$min_length} chr minimum");
    }

    public function testExactLengthNonce() {
        $min_length = Nonce::MIN_LENGTH;

        // set a $min_length chr nonce length
        $length = $min_length;
        Config::modify()->set( Policy::class, 'nonce_length', $length);
        $nonce = Nonce::getNonce();
        $this->assertNotEmpty($nonce, "Nonce is empty");
        $this->assertEquals(strlen($nonce), $length, "Nonce should be {$length} chrs");

    }

    public function testLongLengthNonce() {
        $min_length = Nonce::MIN_LENGTH;

        // set a $min_length chr nonce length
        $length = ($min_length * 2);
        Config::modify()->set( Policy::class, 'nonce_length', $length);
        $nonce = Nonce::getNonce();
        $this->assertNotEmpty($nonce, "Nonce is empty");
        $this->assertEquals(strlen($nonce), $length, "Nonce should not be {$length} chrs");

    }

    /**
     * Test application of attributes
     */
    public function testApplyAttributes() {

        $controller = Controller::curr();

        Config::modify()->set( Policy::class, 'override_apply', false);

        $this->assertFalse( Policy::checkCanApply($controller), 'Policy should NOT be applicable' );

        Config::modify()->set( Policy::class, 'override_apply', true);

        $this->assertTrue( Policy::checkCanApply($controller), 'Policy should be applicable' );

        $attributes = [
            'type' => 'text/css',
            'media' => 'screen'
        ];

        $nonce = Nonce::getNonce();
        Nonce::addToAttributes('style', $attributes);

        $this->assertTrue( array_key_exists('nonce', $attributes) );
        $this->assertEquals( $nonce, $attributes['nonce'] );
    }
}

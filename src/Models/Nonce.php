<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

/**
 * Model handling creation and retrieval of a nonce
 * @author james.ellis@dpc.nsw.gov.au
 */
class Nonce
{
    private static $nonce = '';

    /**
     * Create a nonce
     * @param int $length
     * @return void
     */
    private static function create($length)
    {
        self::$nonce = bin2hex(random_bytes($length / 2));
    }

    /**
     * Get the current nonce, if one does not exist, create it
     * @return string
     */
    public static function get($length = 32)
    {
        if (!self::$nonce) {
            self::create($length);
        }
        return self::$nonce;
    }
}

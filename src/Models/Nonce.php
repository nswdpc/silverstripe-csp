<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Core\Config\Config;
use SilverStripe\View\Requirements;

/**
 * Model handling creation and retrieval of a nonce
 * @author james.ellis@dpc.nsw.gov.au
 */
class Nonce
{

    /**
     * @var string
     */
    private static $nonce = '';

    /**
     * @var int
     */
    private static $length;

    const MIN_LENGTH = 16;

    /**
     * @param boolean $recreate force recreation of a nonce, this is generally only used in tests
     */
    public function __construct($recreate = false) {
        $length = intval(Config::inst()->get( Policy::class, 'nonce_length'));
        if($length < self::MIN_LENGTH) {
            $length = self::MIN_LENGTH;
        }
        if($recreate) {
            self::$nonce = '';
        }
        self::$length = $length;
        self::create();
    }

    /**
     * Create a nonce
     * @return void
     */
    private static function create()
    {
        self::$nonce = bin2hex(random_bytes(self::$length / 2));
    }

    /**
     * Return the nonce
     * @return string
     */
    public static function getNonce() : string {
        return self::$nonce;
    }

    /**
     * Add nonce to an array of HTML attributes
     * @param string $tag
     * @param array $attributes
     * @return void
     */
    public static function addToAttributes(string $tag, array &$attributes) {
        if(Policy::checkCanApply()) {
            // inline scripts and style tags get the nonce
            switch($tag) {
                case 'script':
                    if(!empty($attributes['src'])) {
                        // no nonce
                        break;
                    }
                    // else
                case 'style':
                    $attributes['nonce'] = self::getNonce();
                    break;
                default:
                    // no nonce
                    break;
            }
        }
    }

    /**
     * Add nonce to HTML nodes
     * @param DOMNodeList $list
     * @return void
     */
    public static function addToElements(\DOMNodeList &$domNodeList) {
        foreach($domNodeList as $domElement) {
            $nonce = trim($domElement->getAttribute('nonce'));
            if($nonce) {
                continue;
            }
            if(self::applicableElement($domElement)) {
                $textContent = htmlspecialchars($domElement->textContent);
                $domElement->setAttribute('nonce', self::$nonce);
            }
        }
    }

    /**
     * Inline script and all style elements are given a nonce
     * Elements referencing an external resource should have their hosts referenced in the CSP script-src directive
     * @param DOMElement $element
     * @return bool
     */
    protected static function applicableElement(\DOMElement $domElement) : bool {
        $inline = false;
        switch(strtolower($domElement->nodeName)) {
            case "script":
                // inline scripts get a nonce
                $inline = !$domElement->hasAttribute('src');
                break;
            case "style":
                // styles are inline elements and get a nonce
                $inline = true;
                break;
            default:
                // unhandled element nodeName
                $inline = false;
                break;
        }
        return $inline;
    }

}

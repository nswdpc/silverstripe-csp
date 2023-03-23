<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Core\Config\Config;
use SilverStripe\View\Requirements;

/**
 * Model handling creation and retrieval of a nonce
 *
 * To create the nonce or get the current nonce value, call Nonce::getNonce()
 *
 * @author james
 */
class Nonce
{

    /**
     * @var string
     * @config
     */
    private static $nonce = '';

    const MIN_LENGTH = 16;

    /**
     * Create a nonce
     * @return void
     */
    private static function create($length)
    {
        self::$nonce = bin2hex(random_bytes($length / 2));
    }

    /**
     * Return the nonce
     * @return string
     */
    public static function getNonce() : string {
        // Return existing nonce
        if(self::$nonce) {
            return self::$nonce;
        }
        // Create the nonce
        $length = intval(Config::inst()->get( Policy::class, 'nonce_length'));
        if($length < self::MIN_LENGTH) {
            $length = self::MIN_LENGTH;
        }
        self::create($length);
        return self::$nonce;
    }

    /**
     * Clear the nonce value
     * This is only used in tests
     */
    public static function clear() {
        self::$nonce = '';
    }

    /**
     * Add nonce to an array of HTML attributes
     * @param string $tag
     * @param array $attributes
     * @return void
     */
    public static function addToAttributes(string $tag, array &$attributes) {
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

    /**
     * Add nonce to HTML nodes
     * @note a \DOMNodeList can contain items that extend \DOMNode but only \DOMElement provides get/setAttribute methods
     * @param \DOMNodeList $domNodeList
     * @return void
     */
    public static function addToElements(\DOMNodeList &$domNodeList) {
        foreach($domNodeList as $domElement) {
            if(!($domElement instanceof \DOMElement)) {
                continue;
            }
            $nonce = trim($domElement->getAttribute('nonce'));
            if($nonce) {
                continue;
            }
            if(self::applicableElement($domElement)) {
                $textContent = htmlspecialchars($domElement->textContent);
                $domElement->setAttribute('nonce', self::getNonce());
            }
        }
    }

    /**
     * Inline script and all style elements are given a nonce
     * Elements referencing an external resource should have their hosts referenced in the CSP script-src directive
     * @param \DOMElement $domElement
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

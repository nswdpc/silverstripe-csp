<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Core\Config\Config;
use DOMNodeList;
use DOMElement;

/**
 * Model handling creation and retrieval of a nonce
 * @author james.ellis@dpc.nsw.gov.au
 */
class Nonce
{
    private static $nonce = '';

    private static $length;

    const MIN_LENGTH = 32;

    /**
     * @param boolean $recreate force recreation of a nonce, this is generally only used in tests
     */
    public function __construct($recreate = false) {
        $length = Config::inst()->get( Policy::class, 'nonce_length');
        if($length < self::MIN_LENGTH) {
            $length = self::MIN_LENGTH;
        }
        if($recreate) {
            self::$nonce = '';
        }
        self::$length = $length;
    }

    /**
     * Create a nonce
     * @return void
     */
    private function create()
    {
        self::$nonce = bin2hex(random_bytes(self::$length / 2));
    }

    /**
     * Get the current nonce, if one does not exist, create it
     * @return string
     */
    public function get()
    {
        if (!self::$nonce) {
            self::create();
        }
        return self::$nonce;
    }

    public function __toString() {
        return $this->get();
    }

    /**
     * Add nonce to elements
     * @param DOMNodeList $list
     * @returns void
     */
    public function addToElements(DOMNodeList &$list) {
        foreach($list as $element) {
            if($this->applicableElement($element)) {
                $element->setAttribute('nonce', $this->get());
            }
        }
    }

    /**
     * Inline  script and all style elements are given a nonce
     * @param DOMElement $element
     */
    public function applicableElement(DOMElement $element) {
        switch(strtolower($element->nodeName)) {
            case "script":
                // inline scripts get a nonce
                $src = $element->hasAttribute('src');
                return !$src;
                break;
            case "style":
                // styles are inline elements and get a nonce
                return true;
                break;
            default:
                // unhandled element nodeName
                return false;
                break;
        }
    }

}

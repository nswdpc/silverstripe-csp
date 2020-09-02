<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Core\Config\Config;
use SilverStripe\View\Requirements;
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
        $inline = false;
        switch(strtolower($element->nodeName)) {
            case "script":
                // inline scripts get a nonce
                $src = $element->hasAttribute('src');
                $inline = !$src;
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
        if($inline) {
            return $this->isInRequirements($element);
        } else {
            // non inline element
            return false;
        }
    }

    /**
     * Test if the element was added via {@link Requirements}
     * Any element found in the HTML will not be given a nonce (e.g injected element)
     * @param DOMElement $element
     */
    public function isInRequirements(DOMElement $element) {
        $backend = Requirements::backend();
        $value = trim($element->nodeValue);
        switch(strtolower($element->nodeName)) {
            case "script":
                $scripts = $backend->getCustomScripts();
                foreach($scripts as $uniq => $script) {
                    $script_value = $this->addCdata($script);
                    if($value == $script_value) {
                        return true;
                    }
                }
                return false;
                break;
            case "style":
                $styles = $backend->getCustomCSS();
                foreach($styles as $uniq => $style_value) {
                    if($value == $style_value) {
                        return true;
                    }
                }
                return false;
                break;
            default:
                return false;
                break;
        }
    }

    /**
     * Add the CDATA to match requirements, saves us from regex hell
     * The templated requirement will include CDATA already
     */
    public function addCdata($script) {
        return "//<![CDATA[\n{$script}\n//]]>";
    }

}

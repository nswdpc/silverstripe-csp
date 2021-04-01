<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\View\Requirements_Backend;
use SilverStripe\Core\Config\Config;

class NonceRequirements_Backend extends Requirements_Backend
{

    /**
     * @var \DOMDocument
     */
    protected $domDocument = null;

    /**
     * @return DOMDocument
     */
    protected function getDOMDocument() : \DOMDocument {
        if(!$this->domDocument) {
            $this->domDocument = new \DOMDocument();
        }
        return $this->domDocument;
    }

    /**
     * Given an HTML string containing script, style or link tags
     * apply the nonce value to each tag
     */
    protected function applyNonce(string $html) : string {
        // check if enabled
        if( Config::inst()->get( Policy::class, 'nonce_injection_method') != Policy::NONCE_INJECT_VIA_REQUIREMENTS ) {
            return $html;
        }
        $html = trim($html);
        \libxml_use_internal_errors(true);
        $dom = $this->getDOMDocument();
        $id = bin2hex(random_bytes(4));
        // document prefix and suffix
        // use a random ID comment to avoid collisions in str_replace
        $prefix = "<html><!-- {$id} --><body>";
        $suffix = "</body><!-- {$id} --></html>";
        // create an html document out of the fragment
        $document = $prefix . $html . $suffix;
        $dom->loadHTML( $document, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD );
        $tags = ['script','style'];
        $modified = false;
        foreach($tags as $tag) {
            $elements = $dom->getElementsByTagName($tag);
            if($elements->length > 0) {
                $modified = true;
                Nonce::addToElements( $elements );
            }
        }
        if($modified) {
            $html = $dom->saveHTML();
            // ensure the surrounding html and body tags are removed
            $html = str_replace([$prefix, $suffix], "", $html);
        }
        \libxml_clear_errors();
        return $html;
    }

    /**
     * @inheritDoc
     * Add the nonce attribute to the HTML passed in prior to adding to content
     */
    protected function insertScriptsIntoBody($html, $content)
    {
        $html = $this->applyNonce($html);
        $content = parent::insertScriptsIntoBody($html, $content);
        return $content;
    }

    /**
     * @inheritDoc
     * Add the nonce attribute to the HTML passed in prior to adding to content
     */
    protected function insertTagsIntoHead($html, $content)
    {
        $html = $this->applyNonce($html);
        $content = parent::insertTagsIntoHead($html, $content);
        return $content;
    }

    /**
     * @inheritDoc
     * Add the nonce attribute to the HTML passed in prior to adding to content
     */
    protected function insertScriptsAtBottom($html, $content)
    {
        $html = $this->applyNonce($html);
        $content = parent::insertScriptsAtBottom($html, $content);
        return $content;
    }

}

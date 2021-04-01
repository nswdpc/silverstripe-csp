<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Config\Config;
use DOMDocument;

/**
 * Apply modifications to the document, e.g add a defined CSP nonce to relevant elements
 * @author james
 */
class CSPMiddleware implements HTTPMiddleware
{

    const CONTENT_TYPE_HTML = "text/html";

    public function process(HTTPRequest $request, callable $delegate)
    {
        return $this->applyCSP($request, $delegate);
    }

    /**
     * Return the policy applied, if it can be found, if not or the policy cannot be applied, return false
     * Refer to https://tools.ietf.org/html/rfc7231#section-3.1.1.1 for Content-Type detection
     * Modifications only occur on text/html documents - if a controller returns HTML text but the content-type is not text/html, this will be ignored
     * @returns mixed
     */
    protected function getPolicy(HTTPResponse $response) {
        $content_type = $response->getHeader('Content-Type');
        if(!( strpos( strtolower($content_type), self::CONTENT_TYPE_HTML ) === 0) ) {
            // only apply to text/html documents
            return false;
        }

        $policy = $response->getHeader( Policy::HEADER_CSP );
        if(!$policy) {
            // check for a CSPRO header
            $policy = $response->getHeader( Policy::HEADER_CSP_REPORT_ONLY );
        }
        return $policy;
    }

    /**
     * Apply the Content Security Policy changes, if any are required.
     * If the middleware is not enabled, no changes are applied
     * @return SilverStripe\Control\HTTPResponse
     */
    protected function applyCSP(HTTPRequest $request, callable $delegate) : HTTPResponse {

        $response = $delegate($request);

        // check if enabled
        if( Config::inst()->get( Policy::class, 'nonce_injection_method' ) != Policy::NONCE_INJECT_VIA_MIDDLEWARE ) {
            return $response;
        }

        // get the policy in use
        $policy = $this->getPolicy($response);
        if(!$policy) {
            // no policy is set
            return $response;
        }

        \libxml_use_internal_errors(true);
        $body = $response->getBody();
        if(!$body) {
            return $response;
        }

        // apply nonce to these tags
        $tags = ['script','style'];
        $dom = new DOMDocument();
        $dom->loadHTML( $body , LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD );
        foreach($tags as $tag) {
            $elements = $dom->getElementsByTagName($tag);
            Nonce::addToElements($elements);
        }
        $html = $dom->saveHTML();
        $response->setBody($html);
        \libxml_clear_errors();

        return $response;
    }

}

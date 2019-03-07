<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use DOMDocument;

/**
 * Apply modifications to the document, e.g add a defined CSP nonce to relevant elements
 * @author james
 */
class CSPMiddleware implements HTTPMiddleware
{

    public function process(HTTPRequest $request, callable $delegate)
    {
        $response = $this->applyCSP($request, $delegate);
        return $response;
    }

    protected function applyCSP(HTTPRequest $request, callable $delegate) {
        $response = $delegate($request);
        if(defined('CSP_NONCE') && CSP_NONCE) {
            $policy = $response->getHeader( Policy::HEADER_CSP );
            if(!$policy) {
                $policy = $response->getHeader( Policy::HEADER_CSP_REPORT_ONLY );
            }
            if($policy) {
                $parts = Policy::getNonceEnabledDirectives($policy);
                if(!empty($parts)) {
                    libxml_use_internal_errors(true);
                    $body = $response->getBody();
                    $dom = new DOMDocument();
                    $dom->loadHTML( $body );
                    if(!empty($parts['script-src'])) {
                        $scripts = $dom->getElementsByTagName('script');
                        foreach($scripts as $script) {
                            $script->setAttribute('nonce', CSP_NONCE);
                        }
                    }
                    if(!empty($parts['style-src'])) {
                        $styles = $dom->getElementsByTagName('style');
                        foreach($styles as $style) {
                            $style->setAttribute('nonce', CSP_NONCE);
                        }
                        $links = $dom->getElementsByTagName('link');
                        foreach($links as $link) {
                            if($link->getAttribute('rel') == 'stylesheet') {
                                $link->setAttribute('nonce', CSP_NONCE);
                            }
                        }
                    }
                    $html = $dom->saveHTML();
                    $response->setBody($html);
                    libxml_clear_errors();
                }
            }
        }
        return $response;
    }

}

<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Directive;
use NSWDPC\Utilities\ContentSecurityPolicy\Nonce;
use NSWDPC\Utilities\ContentSecurityPolicy\Policy;
use NSWDPC\Utilities\ContentSecurityPolicy\SiteTreeExtension;
use SilverStripe\Control\Controller;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\View\Requirements;
use Exception;

abstract class AbstractPolicyFunctionalTest extends FunctionalTest
{

    protected $injectionMethod = '';

    protected static $disable_themes = true;

    // protected $usesDatabase = true;

    protected static $fixture_file = 'PolicyFunctionalTest.yml';

    protected static $extra_dataobjects = [
        SiteTree::class,
    ];

    protected static $required_extensions = [
        SiteTree::class => [
            SiteTreeExtension::class,
        ],
    ];

    abstract protected function getInjectionMethod();

    public function setUp() : void
    {
        Config::modify()->set( Policy::class, 'nonce_injection_method', $this->getInjectionMethod());
        parent::setUp();
    }

    public function tearDown() : void
    {
        parent::tearDown();
    }

    private function createPolicy($data)
    {
        $policy = Policy::create($data);
        $policy->write();
        return $policy;
    }

    private function createDirective($data)
    {
        $directive = Directive::create($data);
        $directive->write();
        return $directive;
    }

    public function clearAllPolicies()
    {
        $policies = Policy::get();
        foreach ($policies as $policy) {
            $policy->delete();
        }

        $directives = Directive::get();
        foreach ($directives as $directive) {
            $directive->delete();
        }
    }

    /**
     * Given an {@link DOMNodeList} list of nodes, verify that each one has the current nonce
     * @param \DOMNodeList $nodelist
     * @return int
     */
    protected function verifyElements(\DOMNodeList $nodelist) : int {
        $found_nonces = 0;
        $nonce_value = Nonce::getNonce();// the current nonce
        foreach($nodelist as $element) {
            if(!($element instanceof \DOMElement)) {
                continue;
            }
            /**
             * verify that every element having a nonce attribute,
             * that its value matches the nonce value
             */
            if($element->hasAttribute('nonce')) {
                $nonce_found_value = $element->getAttribute('nonce');
                $this->assertEquals(
                        $nonce_found_value,
                        $nonce_value,
                        "<{$element->nodeName}> nonce found value={$nonce_found_value} != {$nonce_value}"
                );
            } else if($element->hasAttribute('data-should-nonce')) {
                // no nonce attribute found.. but maybe it should have a nonce ?
                $should = $element->getAttribute('data-should-nonce');
                // to pass, the value should be zero
                $this->assertEquals(
                        $should, // 1 will mean it should have gotten a nonce, which is a failure
                        0,
                        "Found <{$element->nodeName}> with value {$element->nodeValue} which has a data-should-nonce={$should}"
                );
            }

        }
        return $found_nonces;
    }

    /**
     * Test nonce injection method
     */
    public function testInjectionMethod() {
        $this->assertEquals( $this->getInjectionMethod(), Config::inst()->get( Policy::class, 'nonce_injection_method') );
    }


    /**
     * Test HTTP headers in policy
     */
    public function testHttpHeaders()
    {
        $this->clearAllPolicies();

        $policy = $this->createPolicy([
            'Title' => 'Test HTTP Header Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 1,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $directives = [];
        $directives[] = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://font.example.com' => '', 'https://font.example.net' => '', 'https://*.font.example.org' => '']),
            'IncludeSelf' => 0,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $directives[] = $this->createDirective([
            'Key' => 'media-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://media.example.com' => '']),
            'IncludeSelf' => 1,
            'UnsafeInline' => 1,
            'AllowDataUri' => 0,
            'Enabled' => 1,
        ]);

        $directives[] = $this->createDirective([
            'Key' => 'script-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://script.example.com' => '']),
            'IncludeSelf' => 1,
            'UnsafeInline' => 1,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $directives[] = $this->createDirective([
            'Key' => 'upgrade-insecure-requests',
            'Value' => '',
            'RulesValue' => json_encode(['https://uir.example.com' => '']), // test for empty value
            // the following values should be ignored
            'IncludeSelf' => 1,
            'UnsafeInline' => 1,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $directives[] = $this->createDirective([
            'Key' => 'block-all-mixed-content',
            'Value' => '',
            'RulesValue' => json_encode(['https://bamc.example.com' => '']), // test for empty value
            // the following values should be ignored
            'IncludeSelf' => 1,
            'UnsafeInline' => 1,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        foreach ($directives as $directive) {
            $policy->Directives()->add($directive);
        }

        $this->assertEquals($policy->Directives()->count(), count($directives));

        $home = SiteTree::get()->filter('URLSegment', 'home')->first();
        $home->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $result = $this->get('home/');

        $this->assertTrue($result instanceof HTTPResponse);

        $header_csp = $result->getHeader(Policy::HEADER_CSP);
        $this->assertNotNull($header_csp, "No " . Policy::HEADER_CSP . " Header!");

        $header_nel = $result->getHeader(Policy::HEADER_NEL);
        $this->assertNotNull($header_nel, "No " . Policy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader(Policy::HEADER_REPORTING_ENDPOINTS);
        $this->assertNotNull($header_report_to, "No " . Policy::HEADER_REPORTING_ENDPOINTS . " Header!");

        $policy->ReportOnly = 1;
        $policy->write();

        $result = $this->get('home/');

        $this->assertTrue($result instanceof HTTPResponse);

        $header_csp_report_only = $result->getHeader(Policy::HEADER_CSP_REPORT_ONLY);
        $this->assertNotNull($header_csp_report_only, "No " . Policy::HEADER_CSP_REPORT_ONLY . " Header!");

        // Turn off Reporting and NEL
        $policy->SendViolationReports = 0;
        $policy->EnableNEL = 0;
        $policy->write();

        $result = $this->get('home/');

        $this->assertTrue($result instanceof HTTPResponse);

        $header_csp_report_only = $result->getHeader(Policy::HEADER_CSP_REPORT_ONLY);
        $this->assertNotNull($header_csp_report_only, "No " . Policy::HEADER_CSP_REPORT_ONLY . " Header!");

        $header_nel = $result->getHeader(Policy::HEADER_NEL);
        $this->assertNull($header_nel, Policy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader(Policy::HEADER_REPORT_TO);
        $this->assertNull($header_report_to, Policy::HEADER_REPORT_TO . " Header!");
    }

    /**
     * Test HTTP headers
     */
    public function testPageHttpHeaders()
    {
        $this->clearAllPolicies();

        // create a system policy
        $policy = $this->createPolicy([
            'Title' => 'Test HTTP Header Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 1,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $directives = [];
        $directives[] = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://base.font.example.com' => '', 'https://base.font.example.net' => '', 'https://*.base.font.example.org' => '']),
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        foreach ($directives as $directive) {
            $policy->Directives()->add($directive);
        }


        // create a page policy and check the headers are returned
        $page_policy = $this->createPolicy([
            'Title' => 'Test Csp Page Header Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 0,
            'ReportOnly' => 0,
            'SendViolationReports' => 0,
            'EnableNEL' => 0,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://pagetestfont.example.com' => '']),
            'IncludeSelf' => 1, // add to make stricter
            'UnsafeInline' => 1, // add unsafe inline
            'AllowDataUri' => 0,
            'Enabled' => 1,
        ]);

        $page_policy->Directives()->add($directive);

        $test_page = SiteTree::get()->filter('URLSegment', 'testcsppolicypage')->first();
        $test_page->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $test_page->CspPolicyID = $page_policy->ID;
        $test_page->write();
        $test_page->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $test_page_policy = $test_page->CspPolicy();

        $this->assertEquals($test_page_policy->ID, $page_policy->ID);

        $result = $this->get('testcsppolicypage/');

        $this->assertTrue($result instanceof HTTPResponse);

        $header_csp = $result->getHeader(Policy::HEADER_CSP);
        $this->assertNotNull($header_csp, "No " . Policy::HEADER_CSP . " Header!");

        $formatted_values = Policy::parsePolicy($header_csp);

        $this->assertTrue(!empty($formatted_values['font-src']), 'No font-src in headers response');

        $this->assertTrue(
            strpos($formatted_values['font-src'], "'self'") !== false
            && strpos($formatted_values['font-src'], " data: ") !== false
            && strpos($formatted_values['font-src'], "https://base.font.example.com") !== false
            && strpos($formatted_values['font-src'], "https://base.font.example.net") !== false
            && strpos($formatted_values['font-src'], "https://*.base.font.example.org") !== false
            && strpos($formatted_values['font-src'], "https://pagetestfont.example.com") !== false
        );

        // the main base policy sets these
        $header_nel = $result->getHeader(Policy::HEADER_NEL);
        $this->assertNotNull($header_nel, "No " . Policy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader(Policy::HEADER_REPORTING_ENDPOINTS);
        $this->assertNotNull($header_report_to, "No " . Policy::HEADER_REPORTING_ENDPOINTS . " Header!");
    }

    /**
     * Test headers delivered via Meta Tags
     */
    public function testPageMetaTag()
    {
        $this->clearAllPolicies();

        // create a system policy
        $policy = $this->createPolicy([
            'Title' => 'Test Meta Tag Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,// turn off to deliver the CSP header without RO
            'SendViolationReports' => 1,// will be ignored
            'EnableNEL' => 1,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_METATAG,
            'MinimumCspLevel' => 1,
        ]);

        $directives = [];
        $directives[] = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://base.font.example.com' => '', 'https://base.font.example.net' => '', 'https://*.base.font.example.org' => '']),
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        foreach ($directives as $directive) {
            $policy->Directives()->add($directive);
        }


        // create a page policy and check the headers are returned
        $page_policy = $this->createPolicy([
            'Title' => 'Test Csp Page MetaTag Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 0,
            'ReportOnly' => 0,
            'SendViolationReports' => 0,
            'EnableNEL' => 0,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_METATAG,
            'MinimumCspLevel' => 1,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://pagetestfont.example.com' => '']),
            'IncludeSelf' => 1, // add to make stricter
            'UnsafeInline' => 1, // add unsafe inline
            'AllowDataUri' => 0,
            'Enabled' => 1,
        ]);

        $page_policy->Directives()->add($directive);

        $test_page = SiteTree::get()->filter('URLSegment', 'testcsppolicypage')->first();
        $test_page->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $test_page->CspPolicyID = $page_policy->ID;
        $test_page->write();
        $test_page->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $test_page_policy = $test_page->CspPolicy();

        $this->assertEquals($test_page_policy->ID, $page_policy->ID);

        $result = $this->get('testcsppolicypage/');

        $this->assertTrue($result instanceof HTTPResponse);

        $body = $result->getBody();

        $csp_meta_tags = [];
        try {
            $dom = new \DOMDocument();
            $utf8_body = '<?xml encoding="UTF-8">' . $body;
            $dom->loadHTML($body);
            $tags = $dom->getElementsByTagName('meta');
            foreach ($tags as $tag) {
                $equiv = $tag->getAttribute('http-equiv');
                switch ($equiv) {
                    case Policy::HEADER_CSP_REPORT_ONLY:
                    case Policy::HEADER_REPORT_TO:
                    case Policy::HEADER_NEL:
                        // none of these headers are allowed
                        throw new Exception("Header {$equiv} found");
                        break;
                    case Policy::HEADER_CSP:
                        $csp_meta_tags[] = $tag;
                        break;
                    default:
                        // some other meta
                        break;
                }
            }
        } catch (Exception $e) {
            $this->assertTrue(false, $e->getMessage());
        }

        $this->assertEquals(count($csp_meta_tags), 2, "Header count is: " . count($csp_meta_tags));

        try {
            $expected_found = 0;
            foreach ($csp_meta_tags as $csp_tag) {
                $content = $csp_tag->getAttribute('content');
                $content = html_entity_decode($content);

                //<meta http-equiv="Content-Security-Policy" content="font-src &#039;self&#039; data: https://base.font.example.com https://base.font.example.net https://*.base.font.example.org;" />
                // <meta http-equiv="Content-Security-Policy" content="font-src &#039;self&#039; &#039;unsafe-inline&#039; https://pagetestfont.example.com;" />

                // test for report-uri and report-to directives with trailing space, these directives should NOT be present in metatag content attribute value
                if (strpos($content, 'report-uri ')) {
                    throw new Exception("report-uri directive found in '{$content}'");
                }
                if (strpos($content, 'report-to ')) {
                    throw new Exception("report-to directive found in '{$content}'");
                }

                if (strpos($content, "https://pagetestfont.example.com") !== false) {
                    if (strpos($content, "'unsafe-inline'") !== false) {
                        $expected_found++;
                    }
                }


                if (strpos($content, "https://base.font.example.com") !== false
                    && strpos($content, "https://base.font.example.net")
                    && strpos($content, "https://*.base.font.example.org")) {
                    if (strpos($content, "data:") !== false) {
                        $expected_found++;
                    }
                }
            }

            $this->assertEquals($expected_found, 2, "Expected values not found in meta tags");
        } catch (Exception $e) {
            $this->assertTrue(false, $e->getMessage());
        }
    }



    /**
     * Test headers delivered via Meta Tags with reporting, no tags should appear
     */
    public function testPageMetaTagWithReporting()
    {
        $this->clearAllPolicies();

        // create a system policy
        $policy = $this->createPolicy([
            'Title' => 'Test Meta Tag Policy with Report Only',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 1,
            'SendViolationReports' => 1,
            'EnableNEL' => 1,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_METATAG,
            'MinimumCspLevel' => 1,
        ]);

        $directives = [];
        $directives[] = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://base.font.example.com' => '', 'https://base.font.example.net' => '', 'https://*.base.font.example.org' => '']),
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        foreach ($directives as $directive) {
            $policy->Directives()->add($directive);
        }


        // create a page policy and check the headers are returned
        $page_policy = $this->createPolicy([
            'Title' => 'Test Csp Page MetaTag Policy with Report Only',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 0,
            'ReportOnly' => 1,
            'SendViolationReports' => 0,
            'EnableNEL' => 0,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_METATAG,
            'MinimumCspLevel' => 1,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://pagetestfont.example.com' => '']),
            'IncludeSelf' => 1, // add to make stricter
            'UnsafeInline' => 1, // add unsafe inline
            'AllowDataUri' => 0,
            'Enabled' => 1,
        ]);

        $page_policy->Directives()->add($directive);

        $test_page = SiteTree::get()->filter('URLSegment', 'testcsppolicypage')->first();
        $test_page->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $test_page->CspPolicyID = $page_policy->ID;
        $test_page->write();
        $test_page->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $test_page_policy = $test_page->CspPolicy();

        $this->assertEquals($test_page_policy->ID, $page_policy->ID);

        $result = $this->get('testcsppolicypage/');

        $this->assertTrue($result instanceof HTTPResponse);

        $body = $result->getBody();

        try {
            $dom = new \DOMDocument();
            $utf8_body = '<?xml encoding="UTF-8">' . $body;
            $dom->loadHTML($body);
            $tags = $dom->getElementsByTagName('meta');
            foreach ($tags as $tag) {
                $equiv = $tag->getAttribute('http-equiv');
                switch ($equiv) {
                        case Policy::HEADER_CSP_REPORT_ONLY:
                        case Policy::HEADER_REPORT_TO:
                        case Policy::HEADER_NEL:
                            // causes the test to fail
                            throw new Exception("Header {$equiv} found");
                            break;
                        case Policy::HEADER_CSP:
                        default:
                            // some other meta
                            break;
                    }
            }
        } catch (Exception $e) {
            $this->assertTrue(false, $e->getMessage());
        }

        // none of the blocked metatags have appeared
    }

    /**
     * Test nonce existence in policy
     */
    public function testPolicyNonce()
    {
        $test = $this;

        $theme_base_dir = '/vendor/nswdpc/silverstripe-csp/tests';// TODO another way?
        $this->useTestTheme($theme_base_dir, 'noncetest', function () use ($test) {

            $test->clearAllPolicies();

            $policy = $test->createPolicy([
                'Title' => 'Test Nonce Header Policy',
                'Enabled' => 1,
                'IsLive' => 1,
                'IsBasePolicy' => 1,
                'ReportOnly' => 0,
                'SendViolationReports' => 1,
                'EnableNEL' => 1,
                'AlternateReportURI' => '',
                'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
                'MinimumCspLevel' => 1,
            ]);

            $directives = [];
            $directives[] = $test->createDirective([
                'Key' => 'font-src',
                'Value' => '',
                'RulesValue' => json_encode(['https://font.example.com' => '', 'https://font.example.net' => '', 'https://*.font.example.org' => '']),
                'IncludeSelf' => 0,
                'UnsafeInline' => 0,
                'AllowDataUri' => 1,
                'Enabled' => 1,
            ]);

            $directives[] = $test->createDirective([
                'Key' => 'media-src',
                'Value' => '',
                'RulesValue' => json_encode(['https://media.example.com' => '']),
                'IncludeSelf' => 1,
                'UnsafeInline' => 1,
                'AllowDataUri' => 0,
                'Enabled' => 1,
            ]);

            $directives[] = $test->createDirective([
                'Key' => 'script-src',
                'Value' => '',
                'RulesValue' => json_encode(['https://script.example.com' => '']),
                'IncludeSelf' => 1,
                'UnsafeInline' => 1,
                'AllowDataUri' => 1,
                'Enabled' => 1,
                'UseNonce' => 1,// expect scripts to have a nonce
            ]);

            $directives[] = $test->createDirective([
                'Key' => 'style-src',
                'Value' => '',
                'RulesValue' => json_encode(['https://css.example.com' => '']),
                'IncludeSelf' => 1,
                'UnsafeInline' => 1,
                'AllowDataUri' => 1,
                'Enabled' => 1,
                'UseNonce' => 1,// expect styles to have a nonce
            ]);

            $directives[] = $test->createDirective([
                'Key' => 'upgrade-insecure-requests',
                'Value' => '',
                'RulesValue' => json_encode(['https://uir.example.com' => '']), // test for empty value
                // the following values should be ignored
                'IncludeSelf' => 1,
                'UnsafeInline' => 1,
                'AllowDataUri' => 1,
                'Enabled' => 1,
            ]);

            $directives[] = $test->createDirective([
                'Key' => 'block-all-mixed-content',
                'Value' => '',
                'RulesValue' => json_encode(['https://bamc.example.com' => '']), // test for empty value
                // the following values should be ignored
                'IncludeSelf' => 1,
                'UnsafeInline' => 1,
                'AllowDataUri' => 1,
                'Enabled' => 1,
            ]);

            foreach ($directives as $directive) {
                $policy->Directives()->add($directive);
            }

            $test->assertEquals($policy->Directives()->count(), count($directives));

            $home = SiteTree::get()->filter('URLSegment','home')->first();
            $home->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

            $result = $test->get('home/');// nonce created here

            // $nonce = new Nonce(true);
            $nonceValue = Nonce::getNonce();// get the nonce created
            $this->assertNotEmpty($nonceValue, "Generated nonce is empty");

            $test->assertTrue($result instanceof HttpResponse);

            $policy = $result->getHeader( Policy::HEADER_CSP );

            $test->assertNotEmpty($policy);

            $parts = Policy::parsePolicy($policy);
            $enabled_directives = Policy::getNonceEnabledDirectives($policy);

            $test->assertTrue( array_key_exists('script-src', $parts), 'script-src is not in the policy' );
            $test->assertTrue( array_key_exists('style-src', $parts), 'style-src is not in the policy' );

            $test->assertTrue( array_key_exists('script-src', $enabled_directives), 'script-src does not have a nonce' );
            $test->assertTrue( array_key_exists('style-src', $enabled_directives), 'style-src does not have a nonce' );

            $test->assertTrue( strpos($parts['script-src'], "'nonce-{$nonceValue}'") !== false, "Unmatched nonce {$nonceValue} in script-src {$parts['script-src']}" );
            $test->assertTrue( strpos($parts['style-src'], "'nonce-{$nonceValue}'") !== false, "Unmatched nonce {$nonceValue} in style-src {$parts['style-src']}" );

            try {

                $expected_nonces = 0;
                $found_nonces = 0;
                libxml_use_internal_errors(true);
                $body = $result->getBody();

                $dom = new \DOMDocument();
                $dom->loadHTML( $body , LIBXML_HTML_NODEFDTD );
                // gather scripts and styles, check nonces
                $scripts = $dom->getElementsByTagName('script');
                $styles = $dom->getElementsByTagName('style');

                $expected_nonces += $scripts->length;
                $found_nonces += $this->verifyElements($scripts);

                $expected_nonces += $styles->length;
                $found_nonces += $this->verifyElements($styles);

            } catch (Exception $e) {
                $test->assertTrue(false, "Exception:" . $e->getMessage());
            }

        });

    }
}

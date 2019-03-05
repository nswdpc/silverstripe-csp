<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use Controller;
use FunctionalTest;
use SiteTree;
use Versioned;
use SS_HTTPResponse;
use Config;
use DOMDocument;
use Exception;
use CspPolicy;
use CspDirective;
use Director;

class PolicyFunctionalTest extends FunctionalTest
{

    // protected $usesDatabase = true;

    protected static $fixture_file = 'PolicyFunctionalTest.yml';

    protected static $use_draft_site = true;

    protected static $extra_dataobjects = [
        SiteTree::class,
    ];

    protected static $required_extensions = [
        SiteTree::class => [
            SiteTreeExtension::class,
        ],
    ];

    private $site; // for MultiSite support


    public function setUp()
    {
        parent::setUp();
        Config::inst()->update(Director::class, 'alternate_base_url' , null);
        $this->findOrCreateSite();
    }

    public function tearDown() {
        parent::tearDown();
    }

    private function findOrCreateSite() {
      $site_title = 'CSP TEST SITE';
      $this->site = null;
      $site_class = \Site::class;
      if( class_exists( $site_class )) {
        $params = [ 'Title' => $site_title ];
        $site = $site_class::get()->filter($params)->first();
        if(!empty($site->ID)) {
          $this->site = $site;
        } else {
            $params = [
                'Title' => $site_title,
                'Host' => 'localhost',
            ];
            $site = $site_class::create($params);
            $site->write();
            $site->IsDefault = 1;
            $site->Theme = '';
            $site->write();
            $site->doPublish();

            $this->site = $site;
        }
      }
    }

    private function assignToSite(SiteTree &$page) {
      $page->ParentID = 0;
      if($this->site) {
        $page->ParentID = $this->site->ID;
      }
    }

    private function createPolicy($data)
    {
        $policy = CspPolicy::create($data);
        $policy->write();
        return $policy;
    }

    private function createDirective($data)
    {
        $directive = CspDirective::create($data);
        $directive->write();
        return $directive;
    }

    public function clearAllPolicies()
    {
        $policies = CspPolicy::get();
        foreach ($policies as $policy) {
            $policy->delete();
        }

        $directives = CspDirective::get();
        foreach ($directives as $directive) {
            $directive->delete();
        }
    }

    public function testHttpHeaders()
    {

        $this->logInWithPermission('ADMIN');

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
            'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $directives = [];
        $directives[] = $this->createDirective([
            'Key' => 'font-src',
            'Value' => 'https://font.example.com https://font.example.net https://*.font.example.org',
            'IncludeSelf' => 0,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $directives[] = $this->createDirective([
            'Key' => 'media-src',
            'Value' => 'https://media.example.com',
            'IncludeSelf' => 1,
            'UnsafeInline' => 1,
            'AllowDataUri' => 0,
            'Enabled' => 1,
        ]);

        $directives[] = $this->createDirective([
            'Key' => 'script-src',
            'Value' => 'https://script.example.com',
            'IncludeSelf' => 1,
            'UnsafeInline' => 1,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $directives[] = $this->createDirective([
            'Key' => 'upgrade-insecure-requests',
            'Value' => 'https://uir.example.com', // test for empty value
            // the following values should be ignored
            'IncludeSelf' => 1,
            'UnsafeInline' => 1,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $directives[] = $this->createDirective([
            'Key' => 'block-all-mixed-content',
            'Value' => 'https://bamc.example.com', // test for empty value
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

        $home = $this->objFromFixture(SiteTree::class, 'home');
        $this->assignToSite( $home );
        $home->write();
        $home->doPublish();

        $result = $this->get( 'home/' );

        $this->assertTrue( $result instanceof SS_HTTPResponse );

        $header_csp = $result->getHeader( CspPolicy::HEADER_CSP );
        $this->assertNotNull( $header_csp, "No " . CspPolicy::HEADER_CSP . " Header!");

        $header_nel = $result->getHeader( CspPolicy::HEADER_NEL );
        $this->assertNotNull( $header_nel, "No " . CspPolicy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader( CspPolicy::HEADER_REPORT_TO );
        $this->assertNotNull( $header_report_to, "No " . CspPolicy::HEADER_REPORT_TO . " Header!");

        $policy->ReportOnly = 1;
        $policy->write();

        $result = $this->get('home/');

        $this->assertTrue( $result instanceof SS_HTTPResponse );

        $header_csp_report_only = $result->getHeader( CspPolicy::HEADER_CSP_REPORT_ONLY );
        $this->assertNotNull( $header_csp_report_only, "No " . CspPolicy::HEADER_CSP_REPORT_ONLY . " Header!");

        // Turn off Report-To and NEL
        $policy->SendViolationReports = 0;
        $policy->EnableNEL = 0;
        $policy->write();

        $result = $this->get('home/');

        $this->assertTrue( $result instanceof SS_HTTPResponse );

        $header_csp_report_only = $result->getHeader( CspPolicy::HEADER_CSP_REPORT_ONLY );
        $this->assertNotNull( $header_csp_report_only, "No " . CspPolicy::HEADER_CSP_REPORT_ONLY . " Header!");

        $header_nel = $result->getHeader( CspPolicy::HEADER_NEL );
        $this->assertNull( $header_nel, CspPolicy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader( CspPolicy::HEADER_REPORT_TO );
        $this->assertNull( $header_report_to, CspPolicy::HEADER_REPORT_TO . " Header!");
    }

    /**
     * Test HTTP headers
     */
    public function testPageHttpHeaders() {

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
            'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $directives = [];
        $directives[] = $this->createDirective([
            'Key' => 'font-src',
            'Value' => 'https://base.font.example.com https://base.font.example.net https://*.base.font.example.org',
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
            'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => 'https://pagetestfont.example.com',
            'IncludeSelf' => 1, // add to make stricter
            'UnsafeInline' => 1, // add unsafe inline
            'AllowDataUri' => 0,
            'Enabled' => 1,
        ]);

        $page_policy->Directives()->add($directive);

        $test_page = $this->objFromFixture(SiteTree::class, 'testpage');
        $this->assignToSite( $test_page );
        $test_page->write();
        $test_page->writeToStage(Versioned::LIVE);

        $test_page->CspPolicyID = $page_policy->ID;
        $test_page->write();
        $test_page->writeToStage(Versioned::LIVE);

        $test_page_policy = $test_page->CspPolicy();

        $this->assertEquals( $test_page_policy->ID, $page_policy->ID );

        $result = $this->get('testcsppolicypage/');

        $this->assertTrue( $result instanceof SS_HTTPResponse );

        $header_csp = $result->getHeader( CspPolicy::HEADER_CSP );
        $this->assertNotNull( $header_csp, "No " . CspPolicy::HEADER_CSP . " Header!");

        $formatted_values = CspPolicy::parsePolicy($header_csp);

        $this->assertTrue( !empty($formatted_values['font-src']), 'No font-src in headers response' );

        $this->assertTrue(
            strpos( $formatted_values['font-src'], "'self'" ) !== false
            && strpos( $formatted_values['font-src'], " data: ") !== false
            && strpos( $formatted_values['font-src'], "https://base.font.example.com" ) !== false
            && strpos( $formatted_values['font-src'], "https://base.font.example.net" ) !== false
            && strpos( $formatted_values['font-src'], "https://*.base.font.example.org" ) !== false
            && strpos( $formatted_values['font-src'], "https://pagetestfont.example.com" ) !== false
        );

        // the main base policy sets these
        $header_nel = $result->getHeader( CspPolicy::HEADER_NEL );
        $this->assertNotNull( $header_nel, "No " . CspPolicy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader( CspPolicy::HEADER_REPORT_TO );
        $this->assertNotNull( $header_report_to, "No " . CspPolicy::HEADER_REPORT_TO . " Header!");


    }

    /**
     * Test headers delivered via Meta Tags
     */
    public function testPageMetaTag() {

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
            'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_METATAG,
            'MinimumCspLevel' => 1,
        ]);

        $directives = [];
        $directives[] = $this->createDirective([
            'Key' => 'font-src',
            'Value' => 'https://base.font.example.com https://base.font.example.net https://*.base.font.example.org',
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
            'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_METATAG,
            'MinimumCspLevel' => 1,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => 'https://pagetestfont.example.com',
            'IncludeSelf' => 1, // add to make stricter
            'UnsafeInline' => 1, // add unsafe inline
            'AllowDataUri' => 0,
            'Enabled' => 1,
        ]);

        $page_policy->Directives()->add($directive);

        $test_page = $this->objFromFixture(SiteTree::class, 'testpage');
        $this->assignToSite( $test_page );
        $test_page->writeToStage(Versioned::LIVE);

        $test_page->CspPolicyID = $page_policy->ID;
        $test_page->write();
        $test_page->writeToStage(Versioned::LIVE);

        $test_page_policy = $test_page->CspPolicy();

        $this->assertEquals( $test_page_policy->ID, $page_policy->ID );

        $result = $this->get('testcsppolicypage/');

        $this->assertTrue( $result instanceof SS_HTTPResponse );

        $body = $result->getBody();

        $csp_meta_tags = [];
        try {
            $dom = new DOMDocument();
            $utf8_body = '<?xml encoding="UTF-8">' . $body;
            $dom->loadHTML($body);
            $tags = $dom->getElementsByTagName('meta');
            foreach ($tags as $tag) {
                $equiv = $tag->getAttribute('http-equiv');
                switch($equiv) {
                    case CspPolicy::HEADER_CSP_REPORT_ONLY:
                    case CspPolicy::HEADER_REPORT_TO:
                    case CspPolicy::HEADER_NEL:
                        // none of these headers are allowed
                        throw new Exception("Header {$equiv} found");
                        break;
                    case CspPolicy::HEADER_CSP:
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

        $this->assertEquals( count($csp_meta_tags), 2, "Header count is: " . count($csp_meta_tags) );

        try {
            $expected_found = 0;
            foreach($csp_meta_tags as $csp_tag) {
                $content = $csp_tag->getAttribute('content');
                $content = html_entity_decode($content);

                //<meta http-equiv="Content-Security-Policy" content="font-src &#039;self&#039; data: https://base.font.example.com https://base.font.example.net https://*.base.font.example.org;" />
                // <meta http-equiv="Content-Security-Policy" content="font-src &#039;self&#039; &#039;unsafe-inline&#039; https://pagetestfont.example.com;" />

                // test for report-uri and report-to directives with trailing space, these directives should NOT be present in metatag content attribute value
                if(strpos( $content, 'report-uri ' ) ) {
                    throw new Exception("report-uri directive found in '{$content}'");
                }
                if(strpos( $content, 'report-to ' ) ) {
                    throw new Exception("report-to directive found in '{$content}'");
                }

                if(strpos( $content, "https://pagetestfont.example.com") !== false) {
                    if(strpos( $content, "'unsafe-inline'") !== false) {
                        $expected_found++;
                    }
                }


                if(strpos( $content, "https://base.font.example.com") !== false
                    && strpos( $content, "https://base.font.example.net")
                    && strpos( $content, "https://*.base.font.example.org")) {

                        if(strpos( $content, "data:") !== false) {
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
        public function testPageMetaTagWithReporting() {

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
                'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_METATAG,
                'MinimumCspLevel' => 1,
            ]);

            $directives = [];
            $directives[] = $this->createDirective([
                'Key' => 'font-src',
                'Value' => 'https://base.font.example.com https://base.font.example.net https://*.base.font.example.org',
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
                'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_METATAG,
                'MinimumCspLevel' => 1,
            ]);

            $directive = $this->createDirective([
                'Key' => 'font-src',
                'Value' => 'https://pagetestfont.example.com',
                'IncludeSelf' => 1, // add to make stricter
                'UnsafeInline' => 1, // add unsafe inline
                'AllowDataUri' => 0,
                'Enabled' => 1,
            ]);

            $page_policy->Directives()->add($directive);

            $test_page = $this->objFromFixture(SiteTree::class, 'testpage');
            $this->assignToSite( $test_page );
            $test_page->writeToStage(Versioned::LIVE);

            $test_page->CspPolicyID = $page_policy->ID;
            $test_page->write();
            $test_page->writeToStage(Versioned::LIVE);

            $test_page_policy = $test_page->CspPolicy();

            $this->assertEquals( $test_page_policy->ID, $page_policy->ID );

            $result = $this->get('testcsppolicypage/');

            $this->assertTrue( $result instanceof SS_HTTPResponse );

            $body = $result->getBody();

            try {
                $dom = new DOMDocument();
                $utf8_body = '<?xml encoding="UTF-8">' . $body;
                $dom->loadHTML($body);
                $tags = $dom->getElementsByTagName('meta');
                foreach ($tags as $tag) {
                    $equiv = $tag->getAttribute('http-equiv');
                    switch($equiv) {
                        case CspPolicy::HEADER_CSP_REPORT_ONLY:
                        case CspPolicy::HEADER_REPORT_TO:
                        case CspPolicy::HEADER_NEL:
                            // causes the test to fail
                            throw new Exception("Header {$equiv} found");
                            break;
                        case CspPolicy::HEADER_CSP:
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


}

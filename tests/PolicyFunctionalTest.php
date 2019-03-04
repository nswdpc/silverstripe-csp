<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use SilverStripe\Control\Controller;
use SilverStripe\Dev\FunctionalTest;
use Silverstripe\CMS\Model\SiteTree;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;

class PolicyFunctionalTest extends FunctionalTest
{

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


    public function setUp()
    {
        parent::setUp();
    }

    public function tearDown() {
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

        $home = SiteTree::get()->filter('URLSegment','home')->first();
        $home->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $result = $this->get('home/');

        $this->assertTrue( $result instanceof HTTPResponse );

        $header_csp = $result->getHeader( Policy::HEADER_CSP );
        $this->assertNotNull( $header_csp, "No " . Policy::HEADER_CSP . " Header!");

        $header_nel = $result->getHeader( Policy::HEADER_NEL );
        $this->assertNotNull( $header_nel, "No " . Policy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader( Policy::HEADER_REPORT_TO );
        $this->assertNotNull( $header_report_to, "No " . Policy::HEADER_REPORT_TO . " Header!");

        $policy->ReportOnly = 1;
        $policy->write();

        $result = $this->get('home/');

        $this->assertTrue( $result instanceof HTTPResponse );

        $header_csp_report_only = $result->getHeader( Policy::HEADER_CSP_REPORT_ONLY );
        $this->assertNotNull( $header_csp_report_only, "No " . Policy::HEADER_CSP_REPORT_ONLY . " Header!");

        // Turn off Report-To and NEL
        $policy->SendViolationReports = 0;
        $policy->EnableNEL = 0;
        $policy->write();

        $result = $this->get('home/');

        $this->assertTrue( $result instanceof HTTPResponse );

        $header_csp_report_only = $result->getHeader( Policy::HEADER_CSP_REPORT_ONLY );
        $this->assertNotNull( $header_csp_report_only, "No " . Policy::HEADER_CSP_REPORT_ONLY . " Header!");

        $header_nel = $result->getHeader( Policy::HEADER_NEL );
        $this->assertNull( $header_nel, Policy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader( Policy::HEADER_REPORT_TO );
        $this->assertNull( $header_report_to, Policy::HEADER_REPORT_TO . " Header!");
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
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
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
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
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

        $test_page = SiteTree::get()->filter('URLSegment','testcsppolicypage')->first();
        $test_page->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $test_page->CspPolicyID = $page_policy->ID;
        $test_page->write();
        $test_page->copyVersionToStage(Versioned::DRAFT, Versioned::LIVE);

        $test_page_policy = $test_page->CspPolicy();

        $this->assertEquals( $test_page_policy->ID, $page_policy->ID );

        $result = $this->get('testcsppolicypage/');

        $this->assertTrue( $result instanceof HTTPResponse );

        $header_csp = $result->getHeader( Policy::HEADER_CSP );
        $this->assertNotNull( $header_csp, "No " . Policy::HEADER_CSP . " Header!");

        $formatted_values = Policy::parsePolicy($header_csp);

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
        $header_nel = $result->getHeader( Policy::HEADER_NEL );
        $this->assertNotNull( $header_nel, "No " . Policy::HEADER_NEL . " Header!");

        $header_report_to = $result->getHeader( Policy::HEADER_REPORT_TO );
        $this->assertNotNull( $header_report_to, "No " . Policy::HEADER_REPORT_TO . " Header!");


    }
}

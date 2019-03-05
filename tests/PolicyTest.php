<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use CspPolicy;
use CspDirective;
use SapphireTest;
use Config;

class PolicyTest extends SapphireTest
{

    protected $usesDatabase = true;

    private $include_report_to = false;

    public function setUp()
    {
        parent::setUp();
        $this->include_report_to = Config::inst()->get( CspPolicy::class, 'include_report_to' );
        Config::inst()->update( CspPolicy::class, 'include_report_to', true );
    }

    public function tearDown() {
        parent::tearDown();
        Config::inst()->update( CspPolicy::class, 'include_report_to', $this->include_report_to );
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

    public function testPolicy()
    {

        $this->clearAllPolicies();

        $policy = $this->createPolicy([
            'Title' => 'Test Policy',
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

        $non_enabled_policy = $this->createPolicy([
            'Title' => 'Test Policy',
            'Enabled' => 0,
            'IsLive' => 0,
            'IsBasePolicy' => 0,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 1,
            'AlternateReportURI' => '',
            'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);
        $non_enabled_policy->write();

        $base_policy = CspPolicy::getDefaultBasePolicy();

        $this->assertTrue($policy->ID == $base_policy->ID, "The base policy was not the expected policy");

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => 'https://example.com https://www.example.net https://*.example.org',
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $policy->Directives()->add($directive);

        $this->assertEquals($policy->Directives()->count(), 1);

        $header = $policy->HeaderValues(1, CspPolicy::POLICY_DELIVERY_METHOD_HEADER);
        //print_r($header);exit;

        $this->assertTrue(isset($header['header']) && isset($header['policy_string']) && isset($header['reporting']) && isset($header['nel']));

        $this->assertEquals($header['header'], CspPolicy::HEADER_CSP);
        $this->assertTrue(strpos($header['policy_string'], 'data:') !== false);
        $this->assertTrue(strpos($header['policy_string'], "'self'") !== false);
        $this->assertTrue(strpos($header['policy_string'], "font-src") === 0);
        $this->assertTrue(strpos($header['policy_string'], "https://example.com https://www.example.net https://*.example.org") !== false);
        $this->assertEquals($header['reporting'][0]['endpoints'][0]['url'], ReportingEndpoint::getCurrentReportingUrl(true));
        $this->assertEquals($header['nel']['report_to'], CspPolicy::DEFAULT_REPORTING_GROUP_NEL);
        $this->assertEquals($header['reporting'][0]['group'], CspPolicy::DEFAULT_REPORTING_GROUP);// TODO handle based on group name ?

        $policy->EnableNEL = 0;
        $policy->write();

        $header = $policy->HeaderValues(1, CspPolicy::POLICY_DELIVERY_METHOD_HEADER);
        $this->assertTrue(empty($header['nel']));

        $policy->SendViolationReports = 0;
        $policy->write();
        $header = $policy->HeaderValues(1, CspPolicy::POLICY_DELIVERY_METHOD_HEADER);

        $this->assertTrue(empty($header['reporting']));

        $policy->ReportOnly = 1;
        $policy->write();

        $header = $policy->HeaderValues(1, CspPolicy::POLICY_DELIVERY_METHOD_HEADER);

        $this->assertTrue(isset($header['header']) && CspPolicy::HEADER_CSP_REPORT_ONLY);

        $policy->Enabled = 0;
        $policy->IsBasePolicy = 0;
        $policy->write();

        // There should be no base policy now
        $not_base_policy = CspPolicy::getDefaultBasePolicy();

        $this->assertNull($not_base_policy);

        // play switcheroo with the Base Policy
        $policy->IsBasePolicy = 1;
        $policy->write();

        $non_enabled_policy->IsBasePolicy = 1;
        $non_enabled_policy->write();

        $check_policy = CspPolicy::get()->byId($policy->ID);

        $this->assertTrue($check_policy && $check_policy->IsBasePolicy == 0, 'Previous Base policy was not valid');

        $check_policy = CspPolicy::get()->byId($non_enabled_policy->ID);

        $this->assertTrue($check_policy && $check_policy->IsBasePolicy == 1, 'New Base policy was not valid');

    }

    public function testDirectives()
    {
        $this->clearAllPolicies();

        $policy = $this->createPolicy([
            'Title' => 'Test Policy',
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
            'IncludeSelf' => 1,
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
            if (in_array($directive->Key, CspDirective::KeysWithoutValues())) {
                $test_directive = CspDirective::get()->byId($directive->ID);
                $this->assertTrue(
                    $test_directive->Value == ""
                    && $test_directive->AllowDataUri == 0
                    && $test_directive->UnsafeInline == 0
                    && $test_directive->IncludeSelf == 0
                );
            }
        }

        $this->assertEquals($policy->Directives()->count(), count($directives));

        $headers = $policy->HeaderValues(1, CspPolicy::POLICY_DELIVERY_METHOD_HEADER);

        /**
         * The CSP values should look like:
         * block-all-mixed-content;
         * font-src 'self' data: https://example.com https://www.example.net https://*.example.org;
         * media-src 'self' data: https://media.example.com;
         * script-src 'self' 'unsafe-inline' https://media.example.com;
         * upgrade-insecure-requests;
         * report-uri http://localhost/csp/v1/report;
         * report-to default;
         */

        $this->assertTrue(!empty($headers['header']) && $headers['header'] == CspPolicy::HEADER_CSP);
        $this->assertTrue(!empty($headers['reporting']));
        $this->assertTrue(!empty($headers['nel']));
        $this->assertTrue(!empty($headers['policy_string']));

        $formatted_values = CspPolicy::parsePolicy($headers['policy_string']);

        foreach ($formatted_values as $key => $value) {
            if (in_array($key, CspDirective::KeysWithoutValues())) {
                $this->assertTrue($value === "", "Key {$key} not empty");
            } else {
                switch ($key) {
                    case 'font-src':
                        $this->assertTrue(
                            strpos( $value, "'self'" ) !== false
                            && strpos( $value, " data: ") !== false
                            && strpos( $value, "https://font.example.com" ) !== false
                            && strpos( $value, "https://font.example.net" ) !== false
                            && strpos( $value, "https://*.font.example.org" ) !== false
                        );
                        break;
                    case 'media-src':
                        $this->assertTrue(
                            strpos( $value, "'self'" ) !== false
                            && strpos( $value, "'unsafe-inline'" ) !== false
                            && strpos( $value, "https://media.example.com" ) !== false
                        );
                        break;
                    case 'script-src':
                        $this->assertTrue(
                            strpos( $value, "'self'" ) !== false
                            && strpos( $value, " data: " ) !== false
                            && strpos( $value, "'unsafe-inline'" ) !== false
                            && strpos( $value, "https://script.example.com" ) !== false
                        );
                        break;
                    case 'report-uri':
                        $this->assertEquals($value,  ReportingEndpoint::getCurrentReportingUrl(true));
                        break;
                    case 'report-to':
                        $this->assertEquals($value, CspPolicy::DEFAULT_REPORTING_GROUP);
                        break;
                    default:
                        // have to test these if added
                        break;
                }

            }
        }
    }

    // set a Policy to 3 which should drop report-uri
    public function testCspLevel() {
        $this->clearAllPolicies();

        $policy = $this->createPolicy([
            'Title' => 'Test Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 1,
            'AlternateReportURI' => '',
            'DeliveryMethod' => CspPolicy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 3,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => 'https://font.example.com https://font.example.net https://*.font.example.org',
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);
        $policy->Directives()->add($directive);

        $headers = $policy->HeaderValues(1, CspPolicy::POLICY_DELIVERY_METHOD_HEADER);

        $this->assertTrue( !empty($headers['policy_string']) );

        $formatted_values = CspPolicy::parsePolicy($headers['policy_string']);

        $this->assertTrue( !array_key_exists('report-uri', $formatted_values) );

        $this->assertTrue(
                    array_key_exists('report-to', $formatted_values)
                    && $formatted_values['report-to'] == CspPolicy::DEFAULT_REPORTING_GROUP
        );

    }
}

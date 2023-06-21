<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Directive;
use NSWDPC\Utilities\ContentSecurityPolicy\Nonce;
use NSWDPC\Utilities\ContentSecurityPolicy\ReportingEndpoint;
use NSWDPC\Utilities\ContentSecurityPolicy\Policy;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Core\Config\Config;
use SilverStripe\Control\Director;

class PolicyTest extends SapphireTest
{

    protected $usesDatabase = true;

    protected function setUp() : void
    {
        parent::setUp();
        // Ensure protocol is https, to ensure reporting URL is validated
        Config::modify()->set(
            Director::class,
            'alternate_base_url',
            'https://localhost/'
        );
    }

    protected function tearDown() : void
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
            'EnableNEL' => 1, // NEL not enabled as not NEL reporting URL
            'AlternateReportURI' => 'https://localhost/csp/reporting',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $base_policy = Policy::getDefaultBasePolicy();

        $this->assertTrue($policy->ID == $base_policy->ID, "The base policy was not the expected policy");

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode([ 'https://example.com' => '1', 'https://www.example.net' => '2', 'https://*.example.org' => '3' ]),
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $policy->Directives()->add($directive);

        $this->assertEquals($policy->Directives()->count(), 1);

        $header = $policy->getPolicyData(true);

        $this->assertTrue(isset($header['header']));
        $this->assertTrue(isset($header['policy_string']));
        $this->assertTrue(isset($header['reporting_endpoints']));
        $this->assertEmpty($header['report_to']);
        $this->assertEmpty($header['nel']);

        $this->assertEquals($header['header'], Policy::HEADER_CSP);
        $this->assertTrue(strpos($header['policy_string'], 'data:') !== false);
        $this->assertTrue(strpos($header['policy_string'], "'self'") !== false);
        $this->assertTrue(strpos($header['policy_string'], "font-src") === 0);
        $this->assertTrue(strpos($header['policy_string'], "https://example.com https://www.example.net https://*.example.org") !== false);

        $this->assertArrayHasKey(Policy::DEFAULT_REPORTING_GROUP, $header['reporting_endpoints']);
        $this->assertEquals(
            $header['reporting_endpoints'][ Policy::DEFAULT_REPORTING_GROUP ],
            Policy::getReportingEndpoint(
                Policy::DEFAULT_REPORTING_GROUP,
                $policy->getReportingUrl()
            )
        );

        // NEL not enabled as no NEL reporting URL in policy
        $this->assertEmpty( $policy->isNELEnabled() );

        // Turn off violation report sending
        $policy->SendViolationReports = 0;
        $policy->write();
        $this->assertEmpty( $policy->isCspReportingEnabled() );

        // Policy should have no endpoints
        $header = $policy->getPolicyData(true);
        $this->assertTrue(empty($header['reporting_endpoints']));

        $policy->ReportOnly = 1;
        $policy->write();

        // Violation reporting is still off
        $this->assertEmpty( $policy->isCspReportingEnabled() );

        // Header should have changed
        $header = $policy->getPolicyData(true);
        $this->assertTrue(isset($header['header']) && Policy::HEADER_CSP_REPORT_ONLY);

        // Make policy non-enabled
        $policy->Enabled = 0;
        $policy->IsBasePolicy = 0;
        $policy->write();

        // There should be no base policy now
        $not_base_policy = Policy::getDefaultBasePolicy();
        $this->assertNull($not_base_policy);


    }

    public function testReportingURLs() {
        $this->clearAllPolicies();

        $policy = $this->createPolicy([
            'Title' => 'Test Policy with 2 reporting URLs',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 0, // NEL not enabled as not NEL reporting URL
            'AlternateReportURI' => 'https://example.net/csp/report-uri',// for report-uri reports
            'AlternateReportToURI' => 'https://example.net/csp/report-to',// for Reporting API reports
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 2,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode([ 'https://example.com' => '1', 'https://www.example.net' => '2', 'https://*.example.org' => '3' ]),
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);

        $policy->Directives()->add($directive);

        $this->assertEquals($policy->Directives()->count(), 1);

        $header = $policy->getPolicyData(true);

        // Test report-uri
        $policy_string = $header['policy_string'];
        $this->assertStringContainsString(
            "report-uri https://example.net/csp/report-uri",
            $policy_string
        );

        // Test Reporting-Endpoints
        $this->assertArrayHasKey(Policy::DEFAULT_REPORTING_GROUP, $header['reporting_endpoints']);
        $this->assertEquals(
            $header['reporting_endpoints'][ Policy::DEFAULT_REPORTING_GROUP ],
            Policy::getReportingEndpoint(
                Policy::DEFAULT_REPORTING_GROUP,
                $policy->getReportingApiUrl()
            )
        );
    }

    public function testBasePolicyChange() {

        $this->clearAllPolicies();

        $policy = $this->createPolicy([
            'Title' => 'Test Base Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 0, // NEL not enabled as not NEL reporting URL
            'AlternateReportURI' => 'https://localhost/csp/reporting',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $base_policy = Policy::getDefaultBasePolicy();

        $this->assertEquals($base_policy->ID, $policy->ID, "The base policy was not the expected policy");

        // Create another policy, make it the base policy
        $new_policy = $this->createPolicy([
            'Title' => 'Test Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 0,
            'AlternateReportURI' => 'https://localhost/csp/reporting',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);
        $new_policy->write();

        $base_policy = Policy::getDefaultBasePolicy();
        $this->assertEquals($base_policy->ID, $new_policy->ID, "The base policy was not the new base policy");

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
            'EnableNEL' => 0,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 1,
        ]);

        $directives = [];
        $directives[] = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://font.example.com' => '', 'https://font.example.net' => '', 'https://*.font.example.org' => '']),
            'IncludeSelf' => 1,
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
            if (in_array($directive->Key, Directive::KeysWithoutValues())) {
                $test_directive = Directive::get()->byId($directive->ID);
                $this->assertTrue(
                    $test_directive->RulesValue == ""
                    && $test_directive->AllowDataUri == 0
                    && $test_directive->UnsafeInline == 0
                    && $test_directive->IncludeSelf == 0
                );
            }
        }

        $this->assertEquals($policy->Directives()->count(), count($directives));

        $policyData = $policy->getPolicyData(true);

        /**
         * The CSP values should look like:
         * block-all-mixed-content;
         * font-src 'self' data: https://example.com https://www.example.net https://*.example.org;
         * media-src 'self' data: https://media.example.com;
         * script-src 'self' 'unsafe-inline' https://media.example.com;
         * upgrade-insecure-requests;
         * report-uri http://localhost/csp/v1/report;
         * report-to csp-endpoint;
         */

        $this->assertTrue(!empty($policyData['header']) && $policyData['header'] == Policy::HEADER_CSP);
        $this->assertTrue(!empty($policyData['reporting_endpoints']));
        $this->assertTrue(empty($policyData['nel']));
        $this->assertTrue(empty($policyData['report_to']));
        $this->assertTrue(!empty($policyData['policy_string']));

        $formatted_values = Policy::parsePolicy($policyData['policy_string']);

        foreach ($formatted_values as $key => $value) {
            if (in_array($key, Directive::KeysWithoutValues())) {
                $this->assertTrue($value === "", "Key {$key} not empty");
            } else {
                switch ($key) {
                    case 'font-src':
                        $this->assertTrue(
                            strpos($value, "'self'") !== false
                            && strpos($value, "data:") !== false
                            && strpos($value, "https://font.example.com") !== false
                            && strpos($value, "https://font.example.net") !== false
                            && strpos($value, "https://*.font.example.org") !== false
                        );
                        break;
                    case 'media-src':
                        $this->assertTrue(
                            strpos($value, "'self'") !== false
                            && strpos($value, "'unsafe-inline'") !== false
                            && strpos($value, "https://media.example.com") !== false
                        );
                        break;
                    case 'script-src':
                        $this->assertTrue(
                            strpos($value, "'self'") !== false
                            && strpos($value, "data:") !== false
                            && strpos($value, "'unsafe-inline'") !== false
                            && strpos($value, "https://script.example.com") !== false
                        );
                        break;
                    case 'report-uri':
                        $this->assertEquals($value, ReportingEndpoint::getCurrentReportingUrl(true));
                        break;
                    case 'report-to':
                        $this->assertEquals($value, Policy::DEFAULT_REPORTING_GROUP);
                        break;
                    default:
                        // have to test these if added
                        break;
                }
            }
        }
    }

    // set a Policy to 3 which should drop report-uri
    public function testCspLevel()
    {
        $this->clearAllPolicies();

        $policy = $this->createPolicy([
            'Title' => 'Test Policy',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 0,
            'AlternateReportURI' => '',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 3,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://font.example.com' => '', 'https://font.example.net' => '', 'https://*.font.example.org' => '']),
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);
        $policy->Directives()->add($directive);

        // policy should have a policy string
        $policyData = $policy->getPolicyData(true);
        $this->assertTrue(!empty($policyData['policy_string']));

        // report-uri should not be in the string
        $formatted_values = Policy::parsePolicy($policyData['policy_string']);
        $this->assertTrue(!array_key_exists('report-uri', $formatted_values));

        // report-to should be in the policy directives
        $this->assertTrue(
            array_key_exists('report-to', $formatted_values)
                    && $formatted_values['report-to'] == Policy::DEFAULT_REPORTING_GROUP
        );

        // test reporting endpoints is present
        $this->assertEmpty($policyData['report_to']);// Report-To header is not present
        $this->assertArrayHasKey(Policy::DEFAULT_REPORTING_GROUP, $policyData['reporting_endpoints']);
        $this->assertEquals(
            $policyData['reporting_endpoints'][ Policy::DEFAULT_REPORTING_GROUP ],
            Policy::getReportingEndpoint(
                Policy::DEFAULT_REPORTING_GROUP,
                $policy->getReportingUrl()
            )
        );
    }

    public function testNEL()
    {
        $this->clearAllPolicies();

        $policy = $this->createPolicy([
            'Title' => 'Test Policy with NEL enabled',
            'Enabled' => 1,
            'IsLive' => 1,
            'IsBasePolicy' => 1,
            'ReportOnly' => 0,
            'SendViolationReports' => 1,
            'EnableNEL' => 1,
            'AlternateReportURI' => 'https://csp.example.com/report',
            'AlternateNELReportURI' => 'https://nel.example.com/report',
            'DeliveryMethod' => Policy::POLICY_DELIVERY_METHOD_HEADER,
            'MinimumCspLevel' => 3,
        ]);

        $directive = $this->createDirective([
            'Key' => 'font-src',
            'Value' => '',
            'RulesValue' => json_encode(['https://font.example.com' => '', 'https://font.example.net' => '', 'https://*.font.example.org' => '']),
            'IncludeSelf' => 1,
            'UnsafeInline' => 0,
            'AllowDataUri' => 1,
            'Enabled' => 1,
        ]);
        $policy->Directives()->add($directive);

        // policy should have a policy string
        $policyData = $policy->getPolicyData(true);
        $this->assertTrue(!empty($policyData['policy_string']));

        // report-uri should not be in the string
        $formatted_values = Policy::parsePolicy($policyData['policy_string']);
        $this->assertTrue(!array_key_exists('report-uri', $formatted_values));

        // report-to should be in the policy directives
        $this->assertTrue(
            array_key_exists('report-to', $formatted_values)
                    && $formatted_values['report-to'] == Policy::DEFAULT_REPORTING_GROUP
        );

        // test reporting endpoints is present
        $this->assertNotEmpty($policyData['report_to']);// Report-To header is present
        $this->assertArrayHasKey(Policy::DEFAULT_REPORTING_GROUP, $policyData['reporting_endpoints']);
        $this->assertEquals(
            $policyData['reporting_endpoints'][ Policy::DEFAULT_REPORTING_GROUP ],
            Policy::getReportingEndpoint(
                Policy::DEFAULT_REPORTING_GROUP,
                $policy->getReportingUrl()
            )
        );
    }
}

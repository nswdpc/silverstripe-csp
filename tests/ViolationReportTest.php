<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\ViolationReport;
use NSWDPC\Utilities\ContentSecurityPolicy\ReportingEndpoint;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;

class ViolationReportTest extends SapphireTest
{
    protected $usesDatabase = true;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        // Ensure protocol is https, to ensure reporting URL is validated
        Config::modify()->set(
            Director::class,
            'alternate_base_url',
            'https://localhost/'
        );

        Config::modify()->set(
            ReportingEndpoint::class,
            'accept_reports',
            true
        );
    }

    protected function getCspViolationReport(): array
    {
        return [
            [
                'age' => 14,
                'type' => 'csp-violation',
                'url' => 'https://example.com/page',
                'user_agent' => 'Mozilla/5.0 SomeBrowser',
                'body' => [
                    'documentURL' => 'https://example.com/page',
                    'blockedURL' => 'https://some.example.net/script.js',
                    'referrer' => 'https://example.com/page',
                    'effectiveDirective' => 'script-src-elem',
                    'originalPolicy' => "default-src 'self'; script-src https://example.org 'self' 'report-sample' 'nonce-example'; style-src-attr 'unsafe-inline' 'report-sample'; style-src 'self' 'nonce-example'; frame-src 'self'; object-src 'none'; form-action 'self'; base-uri 'self'; report-uri 'https://reporting.example.com/v1/report; report-to csp-endpoint",
                    'sourceFile' => '',
                    'sample' => '',
                    'disposition' => 'enforce',
                    'statusCode' => 200,
                    'lineNumber' => '',
                    'columnNumber' => ''
                ]
            ],
            [
                'age' => 12,
                'type' => 'csp-violation',
                'url' => 'https://example.com/page',
                'user_agent' => 'Mozilla/5.0 SomeBrowser',
                'body' => [
                    'documentURL' => 'https://example.com/page',
                    'blockedURL' => 'inline',
                    'referrer' => 'https://example.com/page',
                    'effectiveDirective' => 'script-src-elem',
                    'originalPolicy' => "default-src 'self'; script-src https://example.org 'self' 'report-sample' 'nonce-example'; style-src-attr 'unsafe-inline' 'report-sample'; style-src 'self' 'nonce-example'; frame-src 'self'; object-src 'none'; form-action 'self'; base-uri 'self'; report-uri 'https://reporting.example.com/v1/report; report-to csp-endpoint",
                    'sourceFile' => 'https://example.com/page',
                    'sample' =>  "console.log('CSP says hello');",
                    'disposition' => 'enforce',
                    'statusCode' => 200,
                    'lineNumber' => 49,
                    'columnNumber' => 13
                ]
            ],
            [
                'age' => 11,
                'type' => 'csp-violation',
                'url' => 'https://example.com/page',
                'user_agent' => 'Mozilla/5.0 SomeBrowser',
                'body' => [
                    'documentURL' => 'https://example.com/page',
                    'blockedURL' => 'https://cdn.example.net/vendor/script.min.js',
                    'referrer' => 'https://example.com/page',
                    'effectiveDirective' => 'script-src-elem',
                    'originalPolicy' => "default-src 'self'; script-src https://example.org 'self' 'report-sample' 'nonce-example'; style-src-attr 'unsafe-inline' 'report-sample'; style-src 'self' 'nonce-example'; frame-src 'self'; object-src 'none'; form-action 'self'; base-uri 'self'; report-uri 'https://reporting.example.com/v1/report; report-to csp-endpoint",
                    'sourceFile' => '',
                    'sample' => '',
                    'disposition' => 'enforce',
                    'statusCode' => 200,
                    'lineNumber' => '',
                    'columnNumber' => '',
                ]
            ]
        ];
    }

    protected function getCspReport(): array
    {
        return [
            "csp-report" => [
                "document-uri" => "https://example.com/page/",
                "referrer" => "https://example.com/anotherpage",
                "blocked-uri" => "inline",
                "violated-directive" => "script-src-elem",
                "effective-directive" => "script-src-elem",
                "original-policy" => "default-src 'self'; report-uri https://reporting.example.org/v1/report",
                "disposition" => "enforce",
                "source-file" => "https://example.com/page/",
                "status-code" => 200,
                "line-number" => 46,
                "column-number" => 12,
                "script-sample" => ""
            ]
        ];
    }

    public function testViolationReportCspViolation(): void
    {
        $reports = $this->getCspViolationReport();
        $lastReport = ViolationReport::create_report($reports, "application/reports+json");
        $this->assertInstanceOf(ViolationReport::class, $lastReport);
        $this->assertEquals('https://cdn.example.net/vendor/script.min.js', $lastReport->BlockedUri);
        $this->assertEquals(3, ViolationReport::get()->count());
    }

    public function testPostingViolationReportCspViolation(): void
    {
        $reports = $this->getCspViolationReport();
        $controller = ReportingEndpoint::create();
        $controller->doInit();

        $body = json_encode($reports);
        $request = new HTTPRequest('POST', '/csp/v1/report', [], [], $body);
        $request->addHeader('Content-Type', "application/reports+json");

        $response = $controller->report($request);
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertNull($response->getBody());
        $this->assertEquals(3, ViolationReport::get()->count());
    }

    public function testPostingEmptyViolationReport(): void
    {
        $controller = ReportingEndpoint::create();
        $controller->doInit();
        // empty body
        $request = new HTTPRequest('POST', '/csp/v1/report', [], []);
        $request->addHeader('Content-Type', "application/reports+json");

        $response = $controller->report($request);
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertNull($response->getBody());
        $this->assertEquals(0, ViolationReport::get()->count());
    }

    public function testPostingReportInactiveEndpoint(): void
    {

        Config::modify()->set(
            ReportingEndpoint::class,
            'accept_reports',
            false
        );

        $controller = ReportingEndpoint::create();
        $controller->doInit();
        // empty body
        $request = new HTTPRequest('POST', '/csp/v1/report', [], []);
        $request->addHeader('Content-Type', "application/reports+json");

        $response = $controller->report($request);
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertNull($response->getBody());
        $this->assertEquals(0, ViolationReport::get()->count());
    }



    public function testPostReportInvalidBody(): void
    {
        $controller = ReportingEndpoint::create();
        $controller->doInit();
        // empty body
        $request = new HTTPRequest('POST', '/csp/v1/report', [], [], 'some {invalid} json');
        $request->addHeader('Content-Type', "application/reports+json");

        $response = $controller->report($request);
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertNull($response->getBody());
        $this->assertEquals(0, ViolationReport::get()->count());
    }


    public function testViolationReportCspReport(): void
    {
        $reports = $this->getCspReport();
        $lastReport = ViolationReport::create_report($reports, "application/csp-report");
        $this->assertInstanceOf(ViolationReport::class, $lastReport);
        $this->assertEquals('inline', $lastReport->BlockedUri);
        $this->assertEquals(1, ViolationReport::get()->count());
    }

    public function testPostingViolationReportCspReport(): void
    {
        $reports = $this->getCspReport();
        $controller = ReportingEndpoint::create();
        $controller->doInit();

        $body = json_encode($reports);
        $request = new HTTPRequest('POST', '/csp/v1/report', [], [], $body);
        $request->addHeader('Content-Type', "application/csp-report");

        $response = $controller->report($request);
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertNull($response->getBody());
        $this->assertEquals(1, ViolationReport::get()->count());
    }

    public function testInvalidReportTypeForContenType(): void
    {
        $reports = $this->getCspViolationReport();
        $controller = ReportingEndpoint::create();
        $controller->doInit();

        $body = json_encode($reports);
        $request = new HTTPRequest('POST', '/csp/v1/report', [], [], $body);
        // invalid content type
        $request->addHeader('Content-Type', "application/csp-report");

        $response = $controller->report($request);
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertNull($response->getBody());
        $this->assertEquals(0, ViolationReport::get()->count());
    }

    public function testInvalidMethodViolationReportCspReport(): void
    {
        $reports = $this->getCspReport();
        $controller = ReportingEndpoint::create();
        $controller->doInit();

        $body = json_encode($reports);
        // GET not POST
        $request = new HTTPRequest('GET', '/csp/v1/report', [], [], $body);
        $request->addHeader('Content-Type', "application/csp-report");

        $response = $controller->report($request);
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertNull($response->getBody());
        $this->assertEquals(0, ViolationReport::get()->count());
    }

}

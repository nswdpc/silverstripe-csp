<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;

/*
 * Reporting endpoint used to collect violations
 * Note that this *could* collect LOTS of reports, in production it would be wiser + better
 * to use an external reporting service
 * You can use this reporting endpoint to assist with policy/directive creation on staging/draft sites
 * it's best to get your policy working prior to rolling it out to production.
 *
 */
class ReportingEndpoint extends Controller
{
    /**
     * Whether reports are accepted by this endpoint
     * @config
     */
    private static bool $accept_reports = false;

    /**
     * @config
     */
    private static array $allowed_actions = [
        'report'
    ];

    /**
     * @config
     */
    private static array $url_handlers = [
        'v1/report' => 'report'
    ];

    public function index(HTTPRequest $request): HTTPResponse
    {
        return $this->returnHeader();
    }

    /**
     * Return appropriate response header, only
     */
    protected function returnHeader(): HTTPResponse
    {
        return HTTPResponse::create(null, "204", "No Content");
    }

    public static function getCurrentReportingUrl($include_host = true): string
    {
        return ($include_host ? rtrim(Director::absoluteBaseURL(), '/') : '') . '/csp/v1/report';
    }

    /**
     * Handle reports by POST, the incoming content-type is application/csp-report, which may not be supported in the environment
     */
    public function report(HTTPRequest $request): HTTPResponse
    {
        // collect the body
        try {

            if (!self::config()->get('accept_reports')) {
                throw new \Exception("This endpoint does not accept reports");
            }

            if (!$request->isPOST()) {
                throw new \Exception("The request method is not POST");
            }

            $contentType = $request->getHeader('Content-Type');
            $acceptedContentTypes = [ 'application/csp-report', 'application/reports+json' ];
            if (!in_array($contentType, $acceptedContentTypes)) {
                throw new \Exception("The request does not have an accepted content type");
            }

            $body = $request->getBody();
            if (!$body) {
                throw new \Exception("The body of the request is empty");
            }

            $report = json_decode($body, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception("CSP report JSON decode error: " . json_last_error_msg());
            }

            $violationReport = ViolationReport::create_report($report, $contentType);

        } catch (\Exception $exception) {
            Logger::log("ReportingEndpoint: " . $exception->getMessage(), "NOTICE");
        }

        return $this->returnHeader();
    }
}

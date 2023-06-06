<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use Exception;

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
     * @var bool
     * @config
     */
    private static $accept_reports = false;

    /**
     * @var array
     * @config
     */
    private static $allowed_actions = [
        'report'
    ];

    /**
     * @var array
     * @config
     */
    private static $url_handlers = [
        'v1/report' => 'report'
    ];

    public function index(HTTPRequest $request)
    {
        $this->returnHeader();
    }

    /**
     * Return appropriate response header, only
     */
    private function returnHeader()
    {
        header("HTTP/1.1 204 No Content");
        exit;
    }

    public static function getCurrentReportingUrl($include_host = true) : string
    {
        return ($include_host ? Director::absoluteBaseURL() : '/') . 'csp/v1/report';
    }

    /**
     * Handle reports by POST, the incoming content-type is application/csp-report, which may not be supported in the environment
     * We use php://input to get the raw input here
     */
    public function report(HTTPRequest $request)
    {
        // collect the body
        try {

            if(!self::config()->get('accept_reports')) {
                $this->returnHeader();
            }

            if (!$request->isPOST()) {
                $this->returnHeader();
            }

            $contentType = $request->getHeader('Content-Type');
            $acceptedContentTypes = [ 'application/csp-report', 'application/reports+json' ];
            if(!in_array($contentType, $acceptedContentTypes)) {
                $this->returnHeader();
            }

            $body = $request->getBody();
            if(!$body) {
                $this->returnHeader();
            }

            $report = json_decode($body, true);
            if(json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception("CSP report JSON decode error: " . json_last_error_msg());
            }
            $violationReport = ViolationReport::create_report($report , $contentType);
        } catch (Exception $e) {
        }

        $this->returnHeader();
    }
}

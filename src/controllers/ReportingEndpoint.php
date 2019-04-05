<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use Exception;

/*
 * Reporting endpoint used to collect violations
 * Note that this *could* collect LOTS of reportsm, in production it would be wiser + better to use a service like report-uri
 * You can use this reporting endpoint to assist with policy/directive creation on staging/draft sites - it's best to get your policy working prior to rolling it out to production.

 * @author james.ellis@dpc.nsw.gov.au
 * The following JSON report is POSTed to this controller using the Content-Type application/csp-report
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only#Violation_report_syntax
 <code>
 {
  "csp-report": {
    "document-uri": "http://example.com/signup.html",
    "referrer": "",
    "blocked-uri": "http://example.com/css/style.css",
    "violated-directive": "style-src cdn.example.com",
    "original-policy": "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports"
  }
}
// Example report sent from Chrome
Array
(
    [csp-report] => Array
        (
            [document-uri] => https://example.com/path
            [referrer] =>
            [violated-directive] => script-src
            [effective-directive] => script-src
            [original-policy] => default-src 'self'; report-uri /csp/v1/report/;report-to default;
            [disposition] => report
            [blocked-uri] => eval
            [line-number] => 673
            [column-number] => 18
            [source-file] => https://example.com/path/script.js
            [status-code] => 0
            [script-sample] =>
        )

)
</code>
 *
 */
class ReportingEndpoint extends Controller
{
    private static $allowed_actions = [
        'report'
    ];

    private static $url_handlers = [
        'v1/report' => 'report'
    ];

    public function index(HTTPRequest $request)
    {
    }

    private function returnHeader()
    {
        header("HTTP/1.1 204 No Content");
        exit;
    }

    public static function getCurrentReportingUrl($include_host = true)
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
            if (!$request->isPOST()) {
                $this->returnHeader();
            }

            $post = file_get_contents("php://input");
            if (empty($post)) {
                $this->returnHeader();
            }
            $post = json_decode($post, true);
            if (empty($post['csp-report'])) {
                throw new Exception('No csp-report index found in POSTed data');
            }
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            $report = ViolationReport::create_report($post['csp-report'], $user_agent);
            if (empty($report->ID)) {
                throw new Exception('Could not create report from data submitted');
            }
        } catch (Exception $e) {
            // Not a warning :)
        }

        $this->returnHeader();
    }
}

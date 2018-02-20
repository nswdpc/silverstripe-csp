<?php
namespace NSWDPC\CSP;
/*
 * Reporting endpoint used to collect violations
 * @author james.ellis@dpc.nsw.gov.au
 * The following JSON report is POSTed to this controller
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
</code>
 *
 */
class ReportingEndpoint extends Controller {
	
	private static $allowed_actions = array(
		'report'
	);

	private static $url_handlers = array(
		'v1/report' => 'report'
	);
	
	public function report(\SS_HTTPRequest $request) {
		// collect the body
		try {
			$post = $request->postVars();
			$post = json_decode($post);
			if(empty($post['csp-report'])) {
				throw new \Exception('No csp-report index found in POSTed data');
			}
			$report = CspViolationReport::create_report( $post['csp-report'] );
			if(empty($report->ID)) {
				throw new \Exception('Could not create report from data submitted');
			}
		} catch (\Exception $e) {
			// Not a warning :)
			\SS_Log::log("Failed: {$e->getMessage()}", \SS_Log::NOTICE);
		}
		return;
	}
}

<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\ORM\DataObject;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ReadonlyTransformation;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;

/**
 * CSP Violation Report
 * @note refer to https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#Sample_violation_report
 */
class ViolationReport extends DataObject implements PermissionProvider
{

    /**
     * @var string
     * Report type created by report-uri requests
     */
    const REPORT_TYPE_CSP_REPORT = "csp-report";

    /**
     * @var string
     * Report type created by Reporting-Endpoint requests
     */
    const REPORT_TYPE_CSP_VIOLATION = "csp-violation";

    /**
     * @var string
     * @config
     */
    private static $table_name = 'CspViolationReport';

    /**
     * Singular name for CMS
     * @var string
     * @config
     */
    private static $singular_name = 'Report';

    /**
     * Plural name for CMS
     * @var string
     * @config
     */
    private static $plural_name = 'Reports';

    /**
     * Database fields
     * @var array
     * @config
     */
    private static $db = [
        'DocumentUri' => 'Varchar(255)',
        'Referrer' => 'Varchar(255)',
        'BlockedUri' => 'Varchar(255)',
        'ViolatedDirective' => 'Varchar(255)',
        'OriginalPolicy' => 'Text',
        'SourceFile' => 'Varchar(255)',
        'LineNumber' =>'Int',
        'ColumnNumber' =>'Int',
        'Disposition' => 'Varchar(32)',
        'UserAgent' => 'Varchar(255)',
        'ScriptSample' => 'Varchar(40)' // per w3c spec (https://www.w3.org/TR/CSP3/#violation-sample)
    ];

    /**
     * Database indexes
     * @var array
     * @config
     */
    private static $indexes = [
        'DocumentUri' => true,
        'LastEdited' => true,
        'Created' => true,
    ];

    /**
     * Defines summary fields commonly used in table columns
     * as a quick overview of the data for this dataobject
     * @var array
     * @config
     */
    private static $summary_fields = [
        'ID' => '#',//for referring to report numbers
        'Created.Nice' => 'Created',
        'UserAgent' => 'User Agent',
        'DocumentUri' => 'Document URI',
        'BlockedUri' => 'Blocked URI',
        'ViolatedDirective' => 'Directive',
    ];

    /**
     * @var string
     * @config
     */
    private static $default_sort = 'Created DESC';

    /**
     * Create a new Violation Report per data spec
     */
    public static function create_report(array $data, string $contentType) : ?ViolationReport
    {
        if(isset($data[ self::REPORT_TYPE_CSP_REPORT ]) && $contentType == "application/csp-report") {
            // report-uri report (application/csp-report)
            return self::create_csp_report($data[ self::REPORT_TYPE_CSP_REPORT ]);
        } else if($contentType == "application/reports+json") {
            // Reporting-Endpoints report (multiple reports - application/reports+json)
            return self::create_csp_violation($data);
        } else {
            return null;
        }
    }

    /**
     * Create a new Violation Report for report-uri spec submitted reports
     * Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri
     */
    protected static function create_csp_report(array $data) : ?ViolationReport {
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $report = ViolationReport::create();
        $report->DocumentUri = isset($data['document-uri']) ? $data['document-uri'] : '';
        $report->Referrer = isset($data['referrer']) ? $data['referrer'] : '';
        $report->BlockedUri = isset($data['blocked-uri']) ? $data['blocked-uri'] : '';
        $report->ViolatedDirective = isset($data['violated-directive']) ? $data['violated-directive'] : '';
        $report->OriginalPolicy = isset($data['original-policy']) ? $data['original-policy'] : '';
        $report->LineNumber =  isset($data['line-number']) ? $data['line-number'] : '';
        $report->ColumnNumber =  isset($data['column-number']) ? $data['column-number'] : '';
        $report->Disposition =  isset($data['disposition']) ? $data['disposition'] : '';
        $report->SourceFile =  isset($data['source-file']) ? $data['source-file'] : '';
        $report->UserAgent = $user_agent;
        $report->ScriptSample =  isset($data['script-sample']) ? $data['script-sample'] : '';
        $report->write();
        return $report;
    }

    /**
     * Handle Reporting API reports, for csp-violation reports
     * Ref: https://w3c.github.io/reporting/
     */
    protected static function create_csp_violation(array $reports) : ?ViolationReport {
        if(count($reports) == 0) {
            return null;
        }
        $report = null;
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        foreach($reports as $reportBody) {
            if(empty($reportBody['body'])) {
                continue;
            }
            if( isset($reportBody['type']) && $reportBody['type'] == self::REPORT_TYPE_CSP_VIOLATION ) {
                $data = $reportBody['body'];
                $report = ViolationReport::create();
                $report->DocumentUri = isset($data['documentURL']) ? $data['documentURL'] : '';
                $report->Referrer = isset($data['referrer']) ? $data['referrer'] : '';
                $report->BlockedUri = isset($data['blockedURL']) ? $data['blockedURL'] : '';
                $report->ViolatedDirective = isset($data['effectiveDirective']) ? $data['effectiveDirective'] : '';
                $report->OriginalPolicy = isset($data['originalPolicy']) ? $data['originalPolicy'] : '';
                $report->LineNumber =  isset($data['lineNumber']) ? $data['lineNumber'] : '';
                $report->ColumnNumber =  isset($data['columnNumber']) ? $data['columnNumber'] : '';
                $report->Disposition =  isset($data['disposition']) ? $data['disposition'] : '';
                $report->SourceFile =  isset($data['sourceFile']) ? $data['sourceFile'] : '';
                $report->UserAgent = $user_agent;
                $report->write();
            }
        }
        // return the last report created
        return $report;
    }

    /**
     * In a report, all fields are readonly
     * @return FieldList
     */
    public function getCMSFields()
    {
        $fields = parent::getCMSFields();
        $fields = $fields->transform(new ReadonlyTransformation());
        return $fields;
    }


    public function canView($member = null)
    {
        return Permission::check('CSP_VIOLATION_REPORTS_VIEW');
    }

    public function canEdit($member = null)
    {
        return Permission::check('CSP_VIOLATION_REPORTS_EDIT');
    }

    public function canDelete($member = null)
    {
        return Permission::check('CSP_VIOLATION_REPORTS_DELETE');
    }

    public function canCreate($member = null, $context = [])
    {
        return false;
    }

    public function providePermissions()
    {
        return [
            'CSP_VIOLATION_REPORTS_VIEW' => [
                'name' => 'View reports',
                'category' => 'CSP',
            ],
            'CSP_VIOLATION_REPORTS_EDIT' => [
                'name' => 'Edit & Create reports',
                'category' => 'CSP',
            ],
            'CSPE_VIOLATION_REPORTS_DELETE' => [
                'name' => 'Delete reports',
                'category' => 'CSP',
            ]
        ];
    }
}

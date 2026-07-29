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
 * @property ?string $DocumentUri
 * @property ?string $Referrer
 * @property ?string $BlockedUri
 * @property ?string $ViolatedDirective
 * @property ?string $OriginalPolicy
 * @property ?string $SourceFile
 * @property int $LineNumber
 * @property int $ColumnNumber
 * @property ?string $Disposition
 * @property ?string $UserAgent
 * @property ?string $ScriptSample
 */
class ViolationReport extends DataObject implements PermissionProvider
{
    /**
     * @var string
     * Report type created by report-uri requests
     */
    public const REPORT_TYPE_CSP_REPORT = "csp-report";

    /**
     * @var string
     * Report type created by Reporting-Endpoint requests
     */
    public const REPORT_TYPE_CSP_VIOLATION = "csp-violation";

    /**
     * @config
     */
    private static string $table_name = 'CspViolationReport';

    /**
     * Singular name for CMS
     * @config
     */
    private static string $singular_name = 'Report';

    /**
     * Plural name for CMS
     * @config
     */
    private static string $plural_name = 'Reports';

    /**
     * Database fields
     * @config
     */
    private static array $db = [
        'DocumentUri' => 'Varchar(255)',
        'Referrer' => 'Varchar(255)',
        'BlockedUri' => 'Varchar(255)',
        'ViolatedDirective' => 'Varchar(255)',
        'OriginalPolicy' => 'Text',
        'SourceFile' => 'Varchar(255)',
        'LineNumber' => 'Int',
        'ColumnNumber' => 'Int',
        'Disposition' => 'Varchar(32)',
        'UserAgent' => 'Varchar(255)',
        'ScriptSample' => 'Varchar(40)' // per w3c spec (https://www.w3.org/TR/CSP3/#violation-sample)
    ];

    /**
     * Database indexes
     * @config
     */
    private static array $indexes = [
        'DocumentUri' => true,
        'LastEdited' => true,
        'Created' => true,
    ];

    /**
     * Defines summary fields commonly used in table columns
     * as a quick overview of the data for this dataobject
     * @config
     */
    private static array $summary_fields = [
        'ID' => '#',//for referring to report numbers
        'Created.Nice' => 'Created',
        'UserAgent' => 'User Agent',
        'DocumentUri' => 'Document URI',
        'BlockedUri' => 'Blocked URI',
        'ViolatedDirective' => 'Directive',
    ];

    /**
     * @config
     */
    private static string $default_sort = 'Created DESC';

    /**
     * Create a new Violation Report per data spec
     */
    public static function create_report(array $data, string $contentType): ?ViolationReport
    {
        if (isset($data[ self::REPORT_TYPE_CSP_REPORT ]) && $contentType === "application/csp-report") {
            // report-uri report (application/csp-report)
            return self::create_csp_report($data[ self::REPORT_TYPE_CSP_REPORT ]);
        } elseif ($contentType === "application/reports+json") {
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
    protected static function create_csp_report(array $data): ?ViolationReport
    {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $report = ViolationReport::create();
        $report->DocumentUri = $data['document-uri'] ?? '';
        $report->Referrer = $data['referrer'] ?? '';
        $report->BlockedUri = $data['blocked-uri'] ?? '';
        $report->ViolatedDirective = $data['violated-directive'] ?? '';
        $report->OriginalPolicy = $data['original-policy'] ?? '';
        $report->LineNumber =  $data['line-number'] ?? '';
        $report->ColumnNumber =  $data['column-number'] ?? '';
        $report->Disposition =  $data['disposition'] ?? '';
        $report->SourceFile =  $data['source-file'] ?? '';
        $report->UserAgent = $user_agent;
        $report->ScriptSample =  $data['script-sample'] ?? '';
        $report->write();
        return $report;
    }

    /**
     * Handle Reporting API reports, for csp-violation reports
     * Ref: https://w3c.github.io/reporting/
     */
    protected static function create_csp_violation(array $reports): ?ViolationReport
    {
        if ($reports === []) {
            return null;
        }

        $report = null;
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        foreach ($reports as $reportBody) {
            if (empty($reportBody['body'])) {
                continue;
            }

            if (isset($reportBody['type']) && $reportBody['type'] == self::REPORT_TYPE_CSP_VIOLATION) {
                $data = $reportBody['body'];
                $report = ViolationReport::create();
                $report->DocumentUri = $data['documentURL'] ?? '';
                $report->Referrer = $data['referrer'] ?? '';
                $report->BlockedUri = $data['blockedURL'] ?? '';
                $report->ViolatedDirective = $data['effectiveDirective'] ?? '';
                $report->OriginalPolicy = $data['originalPolicy'] ?? '';
                $report->LineNumber =  $data['lineNumber'] ?? '';
                $report->ColumnNumber =  $data['columnNumber'] ?? '';
                $report->Disposition =  $data['disposition'] ?? '';
                $report->SourceFile =  $data['sourceFile'] ?? '';
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
    #[\Override]
    public function getCMSFields()
    {
        $fields = parent::getCMSFields();
        return $fields->transform(ReadonlyTransformation::create());
    }


    #[\Override]
    public function canView($member = null)
    {
        return Permission::check('CSP_VIOLATION_REPORTS_VIEW');
    }

    #[\Override]
    public function canEdit($member = null)
    {
        return Permission::check('CSP_VIOLATION_REPORTS_EDIT');
    }

    #[\Override]
    public function canDelete($member = null)
    {
        return Permission::check('CSP_VIOLATION_REPORTS_DELETE');
    }

    #[\Override]
    public function canCreate($member = null, $context = [])
    {
        return false;
    }

    public function providePermissions()
    {
        return [
            'CSP_VIOLATION_REPORTS_VIEW' => [
                'name' => _t('ContentSecurityPolicy.CSP_VIOLATION_REPORTS_VIEW', 'View reports'),
                'category' => 'CSP',
            ],
            'CSP_VIOLATION_REPORTS_EDIT' => [
                'name' => _t('ContentSecurityPolicy.CSP_VIOLATION_REPORTS_EDIT', 'Edit & Create reports'),
                'category' => 'CSP',
            ],
            'CSPE_VIOLATION_REPORTS_DELETE' => [
                'name' => _t('ContentSecurityPolicy.CSPE_VIOLATION_REPORTS_DELETE', 'Delete reports'),
                'category' => 'CSP',
            ]
        ];
    }
}

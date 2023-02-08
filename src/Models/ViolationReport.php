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
 * @author james.ellis@dpc.nsw.gov.au
 */
class ViolationReport extends DataObject implements PermissionProvider
{

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
    public static function create_report($data, $user_agent)
    {
        $report = new ViolationReport();
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
        $report->write();
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

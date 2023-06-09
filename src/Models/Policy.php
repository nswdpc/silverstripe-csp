<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Admin\LeftAndMain;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Convert;
use SilverStripe\ORM\DataObject;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\CompositeField;
use SilverStripe\Forms\TextField;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\HeaderField;
use SilverStripe\Forms\OptionsetField;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use SilverStripe\ORM\DB;
use SilverStripe\CMS\Controllers\ContentController;
use SilverStripe\CMS\Model\SiteTree;

/**
 * A Content Security Policy policy record
 */
class Policy extends DataObject implements PermissionProvider
{

    /**
     * @var string
     * @config
     */
    private static $table_name = 'CspPolicy';

    /**
     * @var string
     * @config
     */
    private static $singular_name = 'Policy';

    /**
     * @var string
     * @config
     */
    private static $plural_name = 'Policies';

    /**
     * @var bool
     * @config
     */
    private static $run_in_modeladmin = false;// whether to set the policy in ModelAdmin and descendants of ModelAdmin

    /**
     * @var array
     * @config
     */
    private static $whitelisted_controllers = [];// do not set a policy when current controller is in this list of controllers

    /**
     * @var bool
     * @config
     */
    private static $include_subdomains = true;// include subdomains in NEL

    /**
     * @var int
     * @config
     */
    private static $nonce_length = 16;// the minimum length to create 128 bit nonce value

    /**
     * @var string
     * @config
     */
    private static $nonce_injection_method = 'requirements';// how a nonce is added

    /**
     * @var int
     * @config
     */
    private static $max_age = 3600;

    /**
     * Set to true to override the result of  self::checkCanApply()
     * @var bool
     * @config
     */
    private static $override_apply = false;

    /**
     * @var Policy|null
     */
    private $merge_from_policy;// at runtime set a policy to merge other directives from, into this policy

    const POLICY_DELIVERY_METHOD_HEADER = 'Header';
    const POLICY_DELIVERY_METHOD_METATAG = 'MetaTag';

    const DEFAULT_REPORTING_GROUP = 'csp-endpoint';
    const DEFAULT_REPORTING_GROUP_NEL = 'network-error-logging';

    const HEADER_CSP_REPORT_ONLY = 'Content-Security-Policy-Report-Only';
    const HEADER_CSP = 'Content-Security-Policy';
    const HEADER_REPORT_TO = 'Report-To';
    const HEADER_REPORTING_ENDPOINTS = 'Reporting-Endpoints';
    const HEADER_NEL = 'NEL';

    const NONCE_INJECT_VIA_REQUIREMENTS = 'requirements';
    const NONCE_INJECT_VIA_MIDDLEWARE = 'middleware';

    /**
     * Database fields
     * @var array
     * @config
     */
    private static $db = [
        'Title' => 'Varchar(255)',
        'Enabled' => 'Boolean',
        'MinimumCspLevel' => 'Enum(\'1,2,3\')',// CSP level to support, specifically used for reporting, which changed between 2 and 3
        'IsLive' => 'Boolean',
        'IsBasePolicy' => 'Boolean',
        'ReportOnly' => 'Boolean',
        'SendViolationReports' => 'Boolean',
        'AlternateReportURI' => 'Varchar(255)',// Reporting URL e.g an external service
        'AlternateReportToURI' => 'Varchar(255)',// Reporting URL for Reporting API reports
        'EnableNEL' => 'Boolean', // Enable Network Error Logging (for supporting browsers)
        'AlternateNELReportURI' => 'Varchar(255)', // NEL reporting URL e.g an external service
        'DeliveryMethod' => 'Enum(\'Header,MetaTag\')',
    ];

    /**
     * Default field values
     * @var array
     * @config
     */
    private static $defaults = [
        'Enabled' => 0,
        'IsLive' => 0,
        'MinimumCspLevel' => 2,// CSP Level 1 by default
        'DeliveryMethod' => self::POLICY_DELIVERY_METHOD_HEADER,
        'ReportOnly' => 1,
        'SendViolationReports' => 0,
        'IsBasePolicy' => 0,
        'EnableNEL' => 0,
    ];

    /**
     * Defines summary fields commonly used in table columns
     * as a quick overview of the data for this dataobject
     * @var array
     * @config
     */
    private static $summary_fields = [
        'ID' => '#',
        'Title' => 'Title',
        'DeliveryMethod' => 'Method',
        'ReportOnly.Nice' => 'Report Only',
        'SendViolationReports.Nice' => 'Report Violations',
        'Enabled.Nice' => 'Enabled',
        'IsBasePolicy.Nice' => 'Base Policy',
        'IsLive.Nice' => 'Use on published site',
        'Directives.Count' => 'Directive count'
    ];

    /**
     * Many_many relationship
     * @var array
     * @config
     */
    private static $many_many = [
        'Directives' => Directive::class,
    ];

    /**
     * Database indexes
     * @var array
     * @config
     */
    private static $indexes = [
        'Enabled' => true,
        'IsLive' => true,
        'DeliveryMethod' => true,
        'IsBasePolicy' => true
    ];

    /**
     * Has_many relationship
     * @var array
     * @config
     */
    private static $has_many = [
        'Pages' => SiteTree::class
    ];

    /**
     * Default sort ordering
     * @var string
     * @config
     */
    private static $default_sort = 'IsBasePolicy DESC, Enabled DESC, Title ASC';

    /**
     * Return the default base policy
     * @param bool $is_live
     * @param string $delivery_method
     */
    public static function getDefaultBasePolicy($is_live = false, $delivery_method = self::POLICY_DELIVERY_METHOD_HEADER)
    {
        $filter = [ 'Enabled' => 1, 'IsBasePolicy' => 1, 'DeliveryMethod' => $delivery_method ];
        $list = Policy::get()->filter($filter);
        if ($is_live) {
            $list = $list->filter('IsLive', 1);
        }
        return $list->first();
    }

    /**
     * Get a page specific policy based on the Page
     * @param SiteTree $page
     * @param bool $is_live
     * @param string $delivery_method
     */
    public static function getPagePolicy(SiteTree $page, $is_live = false, $delivery_method = self::POLICY_DELIVERY_METHOD_HEADER)
    {
        if (empty($page->CspPolicyID)) {
            // early return if none linked
            return;
        }
        // Check that the policy is enabled, it's not a base policy..
        $filter = [ 'Enabled' => 1,  'IsBasePolicy' => 0, 'DeliveryMethod' => $delivery_method ];
        $list = Policy::get()->filter($filter)
              ->innerJoin('SiteTree', "SiteTree.CspPolicyID = CspPolicy.ID AND SiteTree.ID = '" . Convert::raw2sql($page->ID) . "'");
        // ... and if live, it's available on Live stage
        if ($is_live) {
            $list = $list->filter('IsLive', 1);
        }
        $policy = $list->first();
        return $policy;
    }

    /**
     * Handle changes made after write
     */
    public function onAfterWrite()
    {
        parent::onAfterWrite();
        if ($this->exists() && $this->IsBasePolicy == 1) {
            // clear other base policies, without using ORM
            DB::query("UPDATE `CspPolicy` SET IsBasePolicy = 0 WHERE IsBasePolicy = 1 AND ID <> '" . Convert::raw2sql($this->ID) . "'");
        }
    }

    /**
     * Returns an array of duplicate directive Keys found
     */
    public function DuplicateDirectives()
    {
        $sql = "SELECT d.`Key`, COUNT(d.`ID`) AS Dupes\n"
            . " FROM `CspDirective` d\n"
            . " JOIN `CspPolicy_Directives` pd ON pd.CspDirectiveID = d.ID\n"
            . " JOIN `CspPolicy` p ON p.ID = pd.CspPolicyID AND p.ID='" . Convert::raw2sql($this->ID) . "'"
            . " GROUP BY d.`Key`"
            . " HAVING Dupes > 1";
        $result = DB::query($sql);
        $records = [];
        foreach ($result  as $record) {
            $records[] = $record['Key'];
        }
        return $records;
    }

    /**
     * CMS Fields
     * @return FieldList
     */
    public function getCMSFields()
    {
        $fields = parent::getCMSFields();


        // Directives handling
        if ($this->exists()) {
            $keys = $this->DuplicateDirectives();
            if (!empty($keys)) {
                $fields->addFieldToTab(
                    'Root.Directives',
                    LiteralField::create('DuplicateDirectivesWarning', '<p class="message warning">This policy has the following duplicate directives: '
                    . htmlspecialchars(implode(", ", $keys))
                    . ". Redundant directives should be unlinked or merged.</p>"),
                    'Directives'
                );
            }
        }

        $fields->insertAfter(
            'Title',
            OptionsetField::create(
                'DeliveryMethod',
                _t(
                    'ContentSecurityPolicy.DELIVERY_METHOD',
                    'Delivery Method'
                ),
                [
                    self::POLICY_DELIVERY_METHOD_HEADER => 'Via an HTTP Header',
                    self::POLICY_DELIVERY_METHOD_METATAG => 'As a meta tag'
                ]
            )->setDescription(
                _t(
                    'ContentSecurityPolicy.REPORT_VIA_META_TAG',
                    'Reporting violations is not supported when using the meta tag delivery method'
                )
            )
        );

        // Policy options
        $useOnPublishedSiteField = $fields->dataFieldByName('IsLive')
            ->setTitle(
                'Use on published website'
            )->setDescription(
                _t(
                    'ContentSecurityPolicy.USE_ON_PUBLISHED_SITE',
                    'When unchecked, this policy will be used on the draft site only'
                )
            );
        $isBasePolicyField = $fields->dataFieldByName('IsBasePolicy')
            ->setTitle('Is Base Policy')
            ->setDescription(
                _t(
                    'ContentSecurityPolicy.IS_BASE_POLICY_NOTE',
                    'When checked, this policy will be come the base/default policy for the entire site'
                )
            );
        $minCspLevelField = $fields->dataFieldByName('MinimumCspLevel')
            ->setTitle(
                _t(
                    'ContentSecurityPolicy.MINIMUM_CSP_LEVEL',
                    'Minimum CSP Level'
                )
            )->setDescription(
                _t(
                    'ContentSecurityPolicy.MINIMUM_CSP_LEVEL_DESCRIPTION',
                    "Setting a higher level will remove from features deprecated in previous versions, such as the 'report-uri' directive"
                )
            );
        $enabledField = $fields->dataFieldByName('Enabled');

        $fields->removeByName(['Enabled', 'MinimumCspLevel', 'IsBasePolicy', 'IsLive']);
        $policyOptionsField = CompositeField::create(
            $enabledField,
            $minCspLevelField,
            $useOnPublishedSiteField,
            $isBasePolicyField
        )->setTitle(
            _t(
                'ContentSecurityPolicy.POLICY_OPTIONS',
                "Policy options"
            )
        );

        $fields->insertBefore(
            'DeliveryMethod',
            $policyOptionsField
        );

        // Reporting fields
        $sendViolationReportsField = $fields->dataFieldByName('SendViolationReports')
            ->setDescription(
                _t(
                    'ContentSecurityPolicy.SEND_VIOLATION_REPORTS',
                    'Send violation reports to a reporting system'
                )
            );

        $reportOnlyField = $fields->dataFieldByName('ReportOnly')
            ->setDescription(
                _t(
                    'ContentSecurityPolicy.REPORT_ONLY',
                    'Allows experimenting with the policy by monitoring (but not enforcing) its effects.'
                )
            );

        if ($this->DeliveryMethod == self::POLICY_DELIVERY_METHOD_METATAG && $this->ReportOnly == 1) {
            $reportOnlyField->setRightTitle(
                _t(
                    'ContentSecurityPolicy.REPORT_ONLY_METATAG_WARNING',
                    'The delivery method is set to \'meta tag\', this setting will be ignored'
                )
            );
        }

        $internal_reporting_url = ReportingEndpoint::getCurrentReportingUrl(true);
        $reportUriField = $fields->dataFieldByName('AlternateReportURI')
            ->setTitle(
                _t(
                    'ContentSecurityPolicy.ALTERNATE_REPORT_URI_TITLE',
                    'Endpoint for report-uri violation reports'
                )
            )->setDescription(
                _t(
                    'ContentSecurityPolicy.ALTERNATE_REPORT_URI_DESCRIPTION',
                    'If not set and the sending of violation reports is enabled,'
                    . ' reports will be directed to <code>{internal_reporting_url}</code> and will appear in the CSP/Reports screen.'
                    . ' <br>Sending reports back to your own website may cause performance degradation.',
                    [
                        'internal_reporting_url' => htmlspecialchars($internal_reporting_url)
                    ]
                )
            );

        $reportToField = $fields->dataFieldByName('AlternateReportToURI')
            ->setTitle(
                _t(
                    'ContentSecurityPolicy.ALTERNATE_REPORT_TO_TITLE',
                    'Endpoint for Reporting API (report-to) violation reports'
                )
            )->setDescription(
                _t(
                    'ContentSecurityPolicy.ALTERNATE_REPORT_TO_URI_DESCRIPTION',
                    'For services that have a separate Reporting API endpoint.<br>'
                    . 'If not set and the sending of violation reports is enabled,'
                    . ' reports will be directed to <code>{internal_reporting_url}</code> and will appear in the CSP/Reports screen.'
                    . ' <br>Sending reports back to your own website may cause performance degradation.',
                    [
                        'internal_reporting_url' => htmlspecialchars($internal_reporting_url)
                    ]
                )
            );
        $fields->removeByName(['ReportOnly','SendViolationReports','AlternateReportURI','AlternateReportToURI']);
        $fields->insertBefore(
            "DeliveryMethod",
            CompositeField::create(
                $sendViolationReportsField,
                $reportOnlyField,
                $reportUriField,
                $reportToField
            )->setTitle(
                _t(
                    'ContentSecurityPolicy.CSP_REPORTING_URLS',
                    'CSP Reporting'
                )
            )
        );

        // NEL fields
        $nelReportToField = $fields->dataFieldByName('AlternateNELReportURI')
            ->setTitle(
                _t(
                    'ContentSecurityPolicy.ALTERNATE_NEL_REPORT_URI_TITLE',
                    'NEL/Reporting API reporting URL that will accept Network Error Logging reports')
                )
            ->setDescription(
                _t(
                    'ContentSecurityPolicy.ALTERNATE_NEL_REPORT_URI_EXTERNAL',
                    'You must use an external reporting service.'
                )
            );
        $enableNelField = $fields->dataFieldByName('EnableNEL')
                ->setTitle(
                    _t(
                        'ContentSecurityPolicy.ENABLE_NEL',
                        'Enable Network Error Logging (NEL)'
                    )
                );
        $fields->removeByName(['AlternateNELReportURI','EnableNEL']);
        $fields->insertBefore(
            "DeliveryMethod",
            CompositeField::create(
                $nelReportToField,
                $enableNelField
            )->setTitle(
                _t('ContentSecurityPolicy.NEL_REPORTING_URLS', 'NEL Reporting')
            )
        );

        // default policies aren't linked to any Pages
        if ($this->IsBasePolicy == 1) {
            $fields->removeByName('Pages');
        }
        return $fields;
    }

    /**
     * Tests whether the URL value passed is valid for reporting
     * Must include scheme and host. A path is optional.
     */
    public static function validateUrl(string $url) : string {
        try {
            $parts = parse_url($url);
            if(!isset($parts['scheme'])) {
                throw new \Exception("Missing scheme");
            }
            if($parts['scheme'] != "https") {
                throw new \Exception("Scheme is not https");
            }
            if(!isset($parts['host'])) {
                throw new \Exception("Missing host");
            }
            return $url;
        } catch (\Exception $e) {
            return "";
        }
    }

    /**
     * Returns the max_age value from configuration
     */
    public function getMaxAge() : int {
        $maxAge = self::config()->get('max_age');
        if(!is_int($maxAge)) {
            $maxAge = 3600;
        }
        return abs($maxAge);
    }

    /**
     * Returns the include_subdomains value from configuration
     */
    public function getIncludeSubdomains() : bool {
        $include = self::config()->get('include_subdomains');
        return $include ? true : false;
    }

    /**
     * Return the reporting URL, based on value saved or default URL
     */
    public function getReportingUrl() : string {
        // Determine which reporting URI to use, external or internal
        if ($this->AlternateReportURI) {
            $reporting_url = $this->AlternateReportURI;
        } else {
            $reporting_url = ReportingEndpoint::getCurrentReportingUrl();
        }
        $reporting_url = self::validateUrl($reporting_url);
        return $reporting_url;
    }

    /**
     * Return the reporting URL for Reporting API reports, based on value saved or default URL
     * May not be supplied.. this is used for services that have different report-uri and report-to endpoints
     */
    public function getReportingApiUrl() : string {
        $url = "";
        if ($this->AlternateReportToURI) {
            $url = $this->AlternateReportToURI;
        }
        $url = self::validateUrl($url);
        return $url;
    }

    /**
     * Given an array of reporting endpoints, return the "Reporting-Endpoints" header value
     */
    public static function getReportingEndpointsHeader(array $reportingEndpoints) : string {
        if(count($reportingEndpoints) == 0) {
            // No reporting endpoints provided
            return "";
        } else {
            return implode(",", $reportingEndpoints);
        }
    }

    /**
     * Create an endpoint for the Reporting-Endpoints header
     */
    public static function getReportingEndpoint(string $endpointName, string $endpointUrl) : string {
        if($endpointUrl = self::validateUrl($endpointUrl)) {
            return $endpointName . "=\"" . $endpointUrl . "\"";
        } else {
            return "";
        }
    }

    /**
     * Given an array of reporting endpoints, return the "Reporting-To" header value
     */
    public static function getReportToHeader(array $reportToGroups) : string {
        if(count($reportToGroups) == 0) {
            // Nothing provided
            return "";
        } else {
            $headerValue = "";
            $reportTo = [];
            foreach($reportToGroups as $reportToGroup) {
                $entry = [];
                if(!isset($reportToGroup['group']) || !is_string($reportToGroup['group'])) {
                    continue;
                }
                $entry['group'] = $reportToGroup['group'];
                if(isset($reportToGroup['max_age']) && is_int($reportToGroup['max_age'])) {
                    $entry['max_age'] = $reportToGroup['max_age'];
                }
                if(isset($reportToGroup['endpoints']) && is_array($reportToGroup['endpoints'])) {
                    $entry['endpoints'] = [];
                    foreach($reportToGroup['endpoints'] as $endpointUrl) {
                        if($endpointUrl = self::validateUrl($endpointUrl)) {
                            $entry['endpoints'][] = [
                                'url' => $endpointUrl
                            ];
                        }
                    }
                }
                if(isset($reportToGroup['include_subdomains'])) {
                    $entry['include_subdomains'] = $reportToGroup['include_subdomains'] ? true : false;
                }
                $reportTo[] = $entry;
            }
            if(count($reportTo) > 0) {
                $headerValue = json_encode( $reportTo, JSON_UNESCAPED_SLASHES );
                /**
                 * W3C spec:
                 * The header’s value is interpreted as a JSON-formatted array of objects without the outer [ and ],
                 * as described in Section 4 of [HTTP-JFV].
                 */
                $headerValue = trim($headerValue, "[]");
            }
            return $headerValue;
        }
    }

    /**
     * Return if NEL can be supported in this policy
     */
    public function isNELEnabled() : string {
        $nelReportUrl = '';
        if(is_string($this->AlternateNELReportURI)) {
            $nelReportUrl = self::validateUrl( $this->AlternateNELReportURI );
        }
        if($this->DeliveryMethod == self::POLICY_DELIVERY_METHOD_HEADER && $this->EnableNEL == 1 && $nelReportUrl) {
            return $nelReportUrl;
        } else {
            return "";
        }
    }

    /**
     * Checks if CSP reporting is enabled in this policy
     * Returns the URL for reporting, if enabled
     */
    public function isCspReportingEnabled() : string {
        $reporting_url = $this->getReportingUrl();
        if($this->DeliveryMethod == self::POLICY_DELIVERY_METHOD_HEADER && $this->SendViolationReports && $reporting_url) {
            return $reporting_url;
        } else {
            return "";
        }
    }

    /**
     * Takes the Policy provided and merges it into this Policy by matching directives
     * According to MDN "Adding additional policies can only further restrict the capabilities of the protected resource"
     * @param Policy $merge_from_policy the policy to merge directives from, into this Policy
     */
    public function setMergeFromPolicy(Policy $merge_from_policy)
    {
        $this->merge_from_policy = $merge_from_policy;
    }

    /**
     * Retrieve the policy in a format for use in the Header or Meta Tag handling
     * @param mixed $enabled filter by Enabled directives only
     * @param bool $pretty format each policy line on a new line
     * @return string
     */
    public function getPolicy($enabled = true, $pretty = false) : string
    {
        $directives = $this->Directives()->sort("ID ASC");
        if (!is_null($enabled)) {
            $directives = $directives->filter(['Enabled' => $enabled ]);
        }
        $policy = "";

        $merge_from_policy_directives = null;
        if ($this->merge_from_policy instanceof Policy) {
            $merge_from_policy_directives = $this->merge_from_policy->Directives()->sort("ID ASC");
            if (!is_null($enabled)) {
                $merge_from_policy_directives = $merge_from_policy_directives->filter(['Enabled' => $enabled ]);
            }
        }

        $keys = [];
        foreach ($directives as $directive) {
            // get the Directive value
            $value = $directive->getDirectiveValue();
            if ($merge_from_policy_directives) {
                // merge a directive from this policy
                $merge_directive = $merge_from_policy_directives->filter('Key', $directive->Key)->first();
                if (!empty($merge_directive->Rules)) {
                    $merge_directive_value = $merge_directive->getDirectiveValue();
                    if ($merge_directive_value != "") {
                        $value .= " " . $merge_directive_value;
                    } else {
                        $value = $merge_directive_value;
                    }
                }
            }
            // add the Key then value to the policy
            $policy .= $this->KeyValue($directive, $value, $pretty);
            $keys[] = $directive->Key;
        }

        if ($merge_from_policy_directives) {
            // find out if there are any directives to add
            $create_directives = $merge_from_policy_directives->exclude('Key', $keys);
            if ($create_directives) {
                foreach ($create_directives as $create_directive) {
                    // get the Directive value
                    $value = $create_directive->getDirectiveValue();
                    // add the Key then value to the policy
                    $policy .= $this->KeyValue($create_directive, $value, $pretty);
                }
            }
        }
        return $policy;
    }

    /**
     * Form the policy line key/value pairings
     * @param Directive $directive
     * @param string $value
     * @param bool $pretty
     */
    private function KeyValue(Directive $directive, $value = "", $pretty = false)
    {
        $policy_line = $directive->Key . ($value ? " {$value};" : ";");
        // if pretty printing it, add a line break
        $policy_line .= ($pretty ? "\n" : "");
        return $policy_line;
    }

    /**
     * Header values
     * @deprecated
     * @param bool|null $enabled
     * @param string $method
     * @param bool $pretty
     */
    public function HeaderValues($enabled = 1, $method = self::POLICY_DELIVERY_METHOD_HEADER, $pretty = false)
    {
        if(!is_null($enabled)) {
            $enabled = $enabled == 1;
        }
        return $this->getPolicyData($enabled);
    }

    /**
     * Header values
     * @param bool|null $enabled
     * @param bool $pretty
     */
    public function getPolicyData(?bool $enabled, bool $pretty = false ) : ?array {
        $policy_string = trim($this->getPolicy($enabled, $pretty));
        if (!$policy_string) {
            return null;
        }
        $report_to = $reporting_endpoints = $nel = [];
        $header = self::HEADER_CSP;
        if ($this->ReportOnly == 1) {
            if ($this->DeliveryMethod == self::POLICY_DELIVERY_METHOD_METATAG) {
                // MetaTag delivery does not support CSPRO, go no further (delivers NO CSP headers)
                return null;
            } elseif ($this->DeliveryMethod == self::POLICY_DELIVERY_METHOD_HEADER) {
                // only HTTP Header can use CSPRO currently
                $header = self::HEADER_CSP_REPORT_ONLY;
            }
        }

        /**
         * The REQUIRED max-age member defines the endpoint group’s lifetime, as a non-negative integer number of seconds
         * https://wicg.github.io/reporting/#max-age-member
         */
        $max_age = $this->getMaxAge();
        $include_subdomains = $this->getIncludeSubdomains();

        // Get Reporting URL for CSP
        if ($reporting_url = $this->isCspReportingEnabled()) {

            /**
             * Reporting changed between CSP Level 2 and 3
             * With a min. level < 3, we send report-uri and report-to directives
             * With a min. level of 3, we send report-to with accompanying headers
             * @see https://wicg.github.io/reporting/#examples
             * @see https://w3c.github.io/webappsec-csp/#directives-reporting
             * @note the Abort steps here - https://w3c.github.io/reporting/#process-header
             * If you are testing locally with a self signed cert or without a cert, it's possible Report-To / Reporting-Endpoints will make no difference in supporting Browsers e.g Chrome 70+
             */

            $report_to_directive = $report_uri_directive = "";

            $reporting_group = self::DEFAULT_REPORTING_GROUP;

            if ($this->MinimumCspLevel < 3) {
                // Only 1,2 will add a report-uri, when selecting '3' this is ignored
                $report_uri_directive = "report-uri {$reporting_url};";
            }

            // report-to directive for CSP
            $report_to_directive = "report-to {$reporting_group};";
            // The report-to endpoint url can be different from the report-uri URL, in some services
            $reportingapi_url = $this->getReportingApiUrl();
            if(!$reportingapi_url) {
                $reportingapi_url = $reporting_url;
            }
            // Reporting-Endpoints for CSP
            $reporting_endpoints[ self::DEFAULT_REPORTING_GROUP ] = self::getReportingEndpoint(self::DEFAULT_REPORTING_GROUP, $reportingapi_url);

            if($report_uri_directive || $report_to_directive) {
                $policy_string .= $report_uri_directive . $report_to_directive;
            }

        }

        // Network Error Logging support
        if ($nelReportUrl = $this->isNELEnabled()) {
            // NEL header values
            $nel = [
                "report_to" => self::DEFAULT_REPORTING_GROUP_NEL,
                "max_age" => $max_age,
                "include_subdomains" => $include_subdomains
            ];
            // NEL requires Report-To header
            $report_to[ self::DEFAULT_REPORTING_GROUP_NEL ] = [
                "group" => self::DEFAULT_REPORTING_GROUP_NEL,
                "max_age" => $max_age,
                "include_subdomains" => $include_subdomains,
                "endpoints" => [
                    $nelReportUrl
                ]
            ];
        }

        $response = [
            'header' => $header, // the CSP header
            'policy_string' => trim($policy_string), // the CSP policy
            'reporting' => [],// See report entries below
            'report_to' => $report_to, // Report-To data
            'reporting_endpoints' => $reporting_endpoints, // Reporting-Endpoints data
            'nel' => $nel // NEL support
        ];

        return $response;
    }

    /**
     * Given a policy string, parse out the parts into key value pairs
     * @return array
     * @param string $policy_string the value of a Content-Security-Policy[-Report-Only] header
     */
    public static function parsePolicy($policy_string) : array
    {
        $parts = explode(";", rtrim($policy_string, ";"));
        $data = [];
        foreach ($parts as $part) {
            $pieces = explode(" ", $part, 2);
            $data[$pieces[0]] = isset($pieces[1]) ? $pieces[1] : '';
        }
        return $data;
    }

    /**
     * Get directives that have a nonce-* value
     */
    public static function getNonceEnabledDirectives($policy_string) : array {
        $directives = [];
        $parts = self::parsePolicy($policy_string);
        foreach($parts as $k=>$v) {
            if(strpos($v, "'nonce-") !== false) {
                $directives[$k] = true;
            }
        }
        return $directives;
    }

    /**
     * Check if the policy can be applied based on configuration and the state of the current request
     * @param Controller $controller the controller to check against, if not supplied the current controller is used
     * @return bool
     */
    public static function checkCanApply(Controller $controller) : bool {

        $override = Config::inst()->get(Policy::class, 'override_apply');
        if($override) {
            return true;
        }

        // check if the controller is part of the administration area
        // and whether to apply the policy or not
        if ($controller instanceof LeftAndMain) {
            return Config::inst()->get(Policy::class, 'run_in_modeladmin');
        }

        // Configured controllers with no CSP
        if(self::controllerWithoutCsp($controller)) {
            return false;
        }

        // all ContentControllers are enabled
        if ($controller instanceof ContentController) {
            return true;
        }

        // Any controller that implements this method can determine whether to apply the policy or not
        if (method_exists($controller, 'EnableContentSecurityPolicy')
            || $controller->hasMethod('EnableContentSecurityPolicy')) {
            return $controller->EnableContentSecurityPolicy();
        }

        // Do not enable by default on all controllers
        return false;
    }

    /**
     * Return whether the provided controller is configured to have no CSP
     */
    public static function controllerWithoutCsp(Controller $controller) : bool {
        // Allow certain controllers to remove headers (as in the request is 'whitelisted')
        // @deprecated and will be renamed in a future release
        $whitelisted_controllers = Config::inst()->get(Policy::class, 'whitelisted_controllers');
        if (is_array($whitelisted_controllers) && in_array(get_class($controller), $whitelisted_controllers)) {
            return true;
        }

        return false;
    }

    /**
     * @inheritdoc
     */
    public function validate()
    {
        $result = parent::validate();
        if ($this->AlternateReportURI) {
            $valid = self::validateUrl( $this->AlternateReportURI );
            if(!$valid) {
                $result->addError(
                    _t(
                        'ContentSecurityPolicy.INVALID_URL',
                        'The reporting URL is not valid'
                    )
                );
            }
        }
        if ($this->AlternateNELReportURI) {
            $valid = self::validateUrl( $this->AlternateNELReportURI );
            if(!$valid) {
                $result->addError(
                    _t(
                        'ContentSecurityPolicy.INVALID_URL_NEL',
                        'The NEL reporting URL is not valid'
                    )
                );
            }
        }
        return $result;
    }

    public function canView($member = null)
    {
        return Permission::check('CSP_POLICY_VIEW');
    }

    public function canEdit($member = null)
    {
        return Permission::check('CSP_POLICY_EDIT');
    }

    public function canDelete($member = null)
    {
        return Permission::check('CSPE_POLICY_DELETE');
    }

    public function canCreate($member = null, $context = [])
    {
        return Permission::check('CSP_POLICY_EDIT');
    }

    public function providePermissions()
    {
        return [
            'CSP_POLICY_VIEW' => [
                'name' => 'View policies',
                'category' => 'CSP',
            ],
            'CSP_POLICY_EDIT' => [
                'name' => 'Edit & Create policies',
                'category' => 'CSP',
            ],
            'CSPE_POLICY_DELETE' => [
                'name' => 'Delete policies',
                'category' => 'CSP',
            ]
        ];
    }
}

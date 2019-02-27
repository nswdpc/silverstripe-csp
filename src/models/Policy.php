<?php
use NSWDPC\Utilities\ContentSecurityPolicy\ReportingEndpoint;

/**
 * A Content Security Policy policy record
 * @author james.ellis@dpc.nsw.gov.au
 */
class CspPolicy extends DataObject implements PermissionProvider {

  private static $singular_name = 'Policy';
  private static $plural_name = 'Policies';

  private static $run_in_modeladmin = false;// whether to set the policy in ModelAdmin and descendants of ModelAdmin
  private static $whitelisted_controllers = [];// do not set a policy when current controller is in this list of controllers

  private $merge_from_policy;// at runtime set a policy to merge other directives from, into this policy

  const POLICY_DELIVERY_METHOD_HEADER = 'Header';
  const POLICY_DELIVERY_METHOD_METATAG = 'MetaTag';

  const DEFAULT_REPORTING_GROUP = 'default';

  /**
   * Database fields
   * @var array
   */
  private static $db = [
    'Title' => 'Varchar(255)',
    'Enabled' => 'Boolean',
    'IsLive' => 'Boolean',
    'IsBasePolicy' => 'Boolean',
    'ReportOnly' => 'Boolean',
    'SendViolationReports' => 'Boolean',
    'EnableNEL' => 'Boolean', // Enable Network Error Logging (for supporting browsers)
    'AlternateReportURI' => 'Varchar(255)',// alternate reporting URI to your own controller/URI
    'DeliveryMethod' => 'Enum(\'Header,MetaTag\')',
    'MinimumCspLevel' => 'Enum(\'1,2,3\')',// CSP level to support, specifically used for reporting, which changed between 2 and 3
  ];

  /**
   * Default field values
   * @var array
   */
  private static $defaults = [
    'Enabled' => 0,
    'IsLive' => 0,
    'MinimumCspLevel' => 1,// CSP Level 1 by default
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
   */
  private static $many_many = [
    'Directives' => CspDirective::class,
  ];

  /**
   * Has_many relationship
   * @var array
   */
  private static $has_many = [
    'Pages' => Page::class
  ];

  /**
   * Default sort ordering
   * @var string
   */
  private static $default_sort = 'IsBasePolicy DESC, Enabled DESC, Title ASC';

  /**
   * Return the default base policy
   * @param boolean $is_live
   * @param string $delivery_method
   */
  public static function getDefaultBasePolicy($is_live = false, $delivery_method = self::POLICY_DELIVERY_METHOD_HEADER) {
    $filter = [ 'Enabled' => 1, 'IsBasePolicy' => 1, 'DeliveryMethod' => $delivery_method ];
    $list = CspPolicy::get()->filter($filter);
    if($is_live) {
      $list = $list->filter('IsLive', 1);
    }
    return $list->first();
  }

  /**
   * Get a page specific policy based on the Page
   * @param Page $page
   * @param boolean $is_live
   * @param string $delivery_method
   */
  public static function getPagePolicy(Page $page, $is_live = false, $delivery_method = self::POLICY_DELIVERY_METHOD_HEADER) {
    if(empty($page->CspPolicyID)) {
      // early return if none linked
      return;
    }
    // Check that the policy is enabled, it's not a base policy..
    $filter = [ 'CspPolicy.Enabled' => 1,  'CspPolicy.IsBasePolicy' => 0, 'CspPolicy.DeliveryMethod' => $delivery_method ];
    $list = CspPolicy::get()->filter( $filter )
              ->innerJoin('Page', "Page.CspPolicyID = CspPolicy.ID AND Page.ID = '" .  Convert::raw2sql($page->ID) . "'");
    // ... and if live, it's available on Live stage
    if($is_live) {
      $list = $list->filter('CspPolicy.IsLive', 1);
    }
    return $list->first();
  }

  /**
   * Handle changes made after write
   */
  public function onAfterWrite() {
    parent::onAfterWrite();
    if($this->exists() && $this->IsBasePolicy == 1) {
      // clear other base policies, without using ORM
      DB::query("UPDATE `CspPolicy` SET IsBasePolicy = 0 WHERE IsBasePolicy = 1 AND ID <> '" . Convert::raw2sql($this->ID) . "'");
    }
  }

  /**
   * Event handler called before writing to the database.
   */
  public function onBeforeWrite()
  {
    parent::onBeforeWrite();
    if($this->EnableNEL == 1) {
      // ensure on if NEL is enabled
      $this->SendViolationReports = 1;
    }
  }

  /**
   * Returns an array of duplicate directive Keys found
   */
  public function DuplicateDirectives() {
    $sql = "SELECT d.`Key`, COUNT(d.`ID`) AS Dupes\n"
        . " FROM `CspDirective` d\n"
        . " JOIN `CspPolicy_Directives` pd ON pd.CspDirectiveID = d.ID\n"
        . " JOIN `CspPolicy` p ON p.ID = pd.CspPolicyID AND p.ID='" . Convert::raw2sql($this->ID) . "'"
        . " GROUP BY d.`Key`"
        . " HAVING Dupes > 1";
    $result = DB::query($sql);
    $records = [];
    foreach($result  as $record) {
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

    // directives grid field
    if($this->exists()) {
      $keys = $this->DuplicateDirectives();
      if(!empty($keys)) {
        $fields->addFieldToTab(
          'Root.Directives',
          LiteralField::create('DuplicateDirectivesWarning', '<p class="message warning">This policy has the following duplicate directives: '
            . htmlspecialchars(implode(", ", $keys))
            . ". Redundant directives should be unlinked or merged.</p>"),
          'Directives'
        );
      }
    }

    $fields->addFieldToTab(
      'Root.Main',
      OptionsetField::create(
        'DeliveryMethod',
        'Delivery Method',
        [ self::POLICY_DELIVERY_METHOD_HEADER => 'Via an HTTP Header',  self::POLICY_DELIVERY_METHOD_METATAG => 'As a meta tag' ]
        )->setDescription( _t('ContentSecurityPolicy.REPORT_VIA_META_TAG', 'Reporting violations is not supported when using the meta tag delivery method') )
    );

    $internal_reporting_url = ReportingEndpoint::getCurrentReportingUrl(false);
    $fields->dataFieldByName('AlternateReportURI')
      ->setTitle( _t('ContentSecurityPolicy.ALTERNATE_REPORT_URI_TITLE', 'Set a reporting URL that will accept violation reports') )
      ->setDescription( sprintf( _t('ContentSecurityPolicy.ALTERNATE_REPORT_URI',
                        'If not set and the sending of violation reports is enabled,'
                        . ' reports will be directed to %s and will appear in the CSP/Reports admin.'
                        . ' <br>Sending reports back to your own website may cause performance degradation.'),
                        $internal_reporting_url
                        ) );

    // display policy
    $policy = $this->HeaderValues(1, true);
    if($policy) {
      $fields->addFieldsToTab(
        'Root.Main',
        [
          HeaderField::create(
            'EnabledDirectivePolicy',
            'Policy (enabled directives)'
          ),
          LiteralField::create(
            'PolicyEnabledDirectives',
            '<p><pre><code>'
              . $policy['header'] . ": \n"
              . $policy['policy_string']
              . '</code></pre></p>'
          ),
          LiteralField::create(
            'PolicyEnabledReportTo',
              '<p>'
              . (!empty($policy['reporting']) ? '<pre><code>'
              . 'Report-To: ' . json_encode($policy['reporting'])
              . (!empty($policy['nel']) ? "\nNEL: " . json_encode($policy['nel']) : "")
              . '</code></pre>' : 'No reporting set')
              . '</p>'
          )
        ]
      );
    }

    $policy = $this->HeaderValues(null, true);
    if($policy) {
      $fields->addFieldsToTab(
        'Root.Main',
        [
          HeaderField::create(
            'AllDirectivePolicy',
            'Policy (all directives)'
          ),
          LiteralField::create(
            'PolicyAllDirectives',
            '<p><pre><code>'
              . $policy['header'] . ": \n"
              . $policy['policy_string']
              . '</code></pre></p>'
          ),
          LiteralField::create(
            'PolicyAllReportTo',
              '<p>'
              . (!empty($policy['reporting']) ? '<pre><code>'
              . 'Report-To: ' . json_encode($policy['reporting'])
              . (!empty($policy['nel']) ? "\nNEL: " . json_encode($policy['nel']) : "")
              . '</code></pre>' : 'No reporting set')
              . '</p>'
          )
        ]
      );
    }

    $fields->dataFieldByName('SendViolationReports')->setDescription( _t('ContentSecurityPolicy.SEND_VIOLATION_REPORTS', 'Send violation reports to a reporting system') );

    $fields->dataFieldByName('EnableNEL')
            ->setTitle( _t('ContentSecurityPolicy.ENABLE_NEL', 'Enable Network Error Logging (NEL)') )
            ->setDescription( _t('ContentSecurityPolicy.ENABLE_NEL_NOTE', 'For supporting browsers. Turning this on will enable \'Send Violation Reports\'') );

    if($this->ReportOnly == 1 && !$this->SendViolationReports) {
      $fields->dataFieldByName('SendViolationReports')->setRightTitle( _t('ContentSecurityPolicy.SEND_VIOLATION_REPORTS_REPORT_ONLY', '\'Report Only\' is on - it is wise to turn on sending violation reports') );
    }

    $fields->dataFieldByName('ReportOnly')
          ->setDescription(  _t('ContentSecurityPolicy.REPORT_ONLY', 'Allows experimenting with the policy by monitoring (but not enforcing) its effects') );

    $fields->dataFieldByName('IsLive')->setTitle('Use on published website')->setDescription( _t('ContentSecurityPolicy.USE_ON_PUBLISHED_SITE', 'When unchecked, this policy will be used on the draft site only') );
    $fields->dataFieldByName('IsBasePolicy')->setTitle('Is Base Policy')->setDescription( _t('ContentSecurityPolicy.IS_BASE_POLICY_NOTE', 'When checked, this policy will be come the base/default policy for the entire site') );

    $fields->dataFieldByName('MinimumCspLevel')
          ->setTitle( _t('ContentSecurityPolicy.MINIMUM_CSP_LEVEL', 'Minimum CSP Level') )
          ->setDescription( _t('ContentSecurityPolicy.MINIMUM_CSP_LEVEL_DESCRIPTION', "Setting a higher level will remove from features deprecated in previous versions, such as the 'report-uri' directive") );

    // default policies aren't linked to any Pages
    if($this->IsBasePolicy == 1) {
      $fields->removeByName('Pages');
    }
    return $fields;
  }

  /**
   * Takes the CspPolicy provided and merges it into this CspPolicy by matching directives
   * According to MDN "Adding additional policies can only further restrict the capabilities of the protected resource"
   * @param CspPolicy the policy to merge directives from, into this Policy
   */
  public function SetMergeFromPolicy(CspPolicy $merge_from_policy) {
    $this->merge_from_policy = $merge_from_policy;
  }

  /**
   * Retrieve the policy in a format for use in the Header or Meta Tag handling
   * @param boolean $enabled filter by Enabled directives only
   * @param boolean $pretty format each policy line on a new line
   * @returns string
   */
  public function getPolicy($enabled = 1, $pretty = false) {
    $directives = $this->Directives();
    if(!is_null($enabled)) {
      $directives = $directives->filter('Enabled', (bool)$enabled);
    }
    $policy = "";

    $merge_from_policy_directives = null;
    if($this->merge_from_policy instanceof CspPolicy) {
      $merge_from_policy_directives = $this->merge_from_policy->Directives();
      if(!is_null($enabled)) {
        $merge_from_policy_directives = $merge_from_policy_directives->filter('Enabled', (bool)$enabled);
      }
    }

    $keys = [];
    foreach($directives as $directive) {
      // get the Directive value
      $value = $directive->getDirectiveValue();
      if($merge_from_policy_directives) {
        // merge a directive from this policy
        $merge_directive = $merge_from_policy_directives->filter('Key', $directive->Key)->first();
        if(!empty($merge_directive->Value)) {
          $merge_directive_value = $merge_directive->getDirectiveValue();
          if($merge_directive_value != "") {
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

    if($merge_from_policy_directives) {
      // find out if there are any directives to add
      $create_directives = $merge_from_policy_directives->exclude('Key', $keys);
      if($create_directives) {
        foreach($create_directives as $create_directive) {
          // get the Directive value
          $value = $directive->getDirectiveValue();
          // add the Key then value to the policy
          $policy .= $this->KeyValue($create_directive, $value, $pretty);
        }
      }
    }
    return $policy;
  }

  /**
   * Form the policy line key/value pairings
   * @param CspDirective $directive
   * @param string $value
   * @param boolean $pretty
   */
  private function KeyValue(CspDirective $directive, $value = "", $pretty = false) {
    $policy_line = $directive->Key . ($value ? " {$value};" : ";");
    // if pretty printing it, add a line break
    $policy_line .= ($pretty ? "\n" : "");
    return $policy_line;
  }

  /**
   * Header values
   * @returns array
   * @param boolean $enabled
   * @param boolean $pretty
   */
  public function HeaderValues($enabled = 1, $pretty = false) {

    $policy_string = trim($this->getPolicy($enabled, $pretty));
    if(!$policy_string) {
      return false;
    }
    $reporting = [];
    $header = 'Content-Security-Policy';
    if($this->ReportOnly == 1) {
      $header = 'Content-Security-Policy-Report-Only';
    }

    if($this->SendViolationReports) {

      // Determine which reporting URI to use, external or internal
      if($this->AlternateReportURI) {
        $reporting_url = $this->AlternateReportURI;
      } else {
        $reporting_url = ReportingEndpoint::getCurrentReportingUrl();
      }

      /**
       * Reporting changed between CSP Level 2 and 3
       * With a min. level of 2, we send report-uri and Report-To headers
       * With a min. level of 3, we send Report-To only
       * @see https://wicg.github.io/reporting/#examples
       * @see https://w3c.github.io/webappsec-csp/#directives-reporting
       * @note the Abort steps here - https://w3c.github.io/reporting/#process-header
       * If you are testing locally with a self signed cert or without a cert, it's possible Report-To will make no difference in supporting Browsers e.g Chrome 70+
       */

      $report_to = "";
      $min_csp_level = $this->MinimumCspLevel;

      /**
       * The REQUIRED max-age member defines the endpoint group’s lifetime, as a non-negative integer number of seconds
       * https://wicg.github.io/reporting/#max-age-member
       */
      $max_age = abs($this->config()->get('max_age'));

      $include_subdomains = (bool)$this->config()->get('include_subdomains');

      $reporting_group = self::DEFAULT_REPORTING_GROUP;

      // 3 only gets Report-To
      $reporting = [
        "group" => $reporting_group,
        "max_age" => $max_age,
        "endpoints" => [
          // an array of URLs, non secure-endpoints should be ignored by the user agent
          [ "url" => $reporting_url ],
        ],
        "include_subdomains" => $include_subdomains
      ];

      if($min_csp_level < 3) {
        // Only 1,2 will add a report-uri, when selecting '3' this is ignored
        $report_to .= "report-uri {$reporting_url};";
      }

      // 1,2,3 use report-to so that UserAgents that support it can use this as they'll ignore report-uri
      $report_to .= "report-to {$reporting_group};";

      // only apply report_to if there is a URL and the
      $policy_string .= $report_to;

      $nel = [];
      if($this->EnableNEL == 1) {
        $nel = [
          "report_to" => $reporting_group,
          "max_age" => $max_age,
          "include_subdomains" => $include_subdomains
        ];
      }
    }

    $response = [
      'header' => $header,
      'policy_string' => $policy_string,
      'reporting' => $reporting,
      'nel' => $nel
    ];

    return $response;
  }


  public function canView($member = null){
      return Permission::check('CSP_POLICY_VIEW');
  }

  public function canEdit($member = null) {
      return Permission::check('CSP_POLICY_EDIT');
  }

  public function canDelete($member = null) {
      return Permission::check('CSPE_POLICY_DELETE');
  }

  public function canCreate($member = null) {
      return Permission::check('CSP_POLICY_EDIT');
  }

  public function providePermissions() {
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

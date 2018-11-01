<?php
/**
 * A Content Security Policy rule record
 * @author james.ellis@dpc.nsw.gov.au
 */
class CspRule extends DataObject {

  private static $singular_name = 'Rule';
  private static $plural_name = 'Rules';

  private static $run_in_modeladmin = false;// whether to set the rule in ModelAdmin and descendants of ModelAdmin
  private static $blacklisted_controllers = [];// do not set rule when current controller is in this list of controllers

  /**
   * Database fields
   * @var array
   */
  private static $db = [
    'Title' => 'Varchar(255)',
    'Enabled' => 'Boolean',
    'IsLive' => 'Boolean',
    'ReportOnly' => 'Boolean',
    'SendViolationReports' => 'Boolean',
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
    'DeliveryMethod' => 'Header',
    'ReportOnly' => 1,
    'SendViolationReports' => 0,
  ];

  /**
   * Defines summary fields commonly used in table columns
   * as a quick overview of the data for this dataobject
   * @var array
   */
  private static $summary_fields = [
    'Title' => 'Title',
    'DeliveryMethod' => 'Method',
    'ReportOnly.Nice' => 'Report Only',
    'SendViolationReports.Nice' => 'Report Violations',
    'Enabled.Nice' => 'Default',
    'IsLive.Nice' => 'Default',
    'RuleItems.Count' => 'Rule count'
  ];

  /**
   * Many_many relationship
   * @var array
   */
  private static $many_many = [
    'RuleItems' => CspRuleItem::class,
  ];

  /**
   * Default sort ordering
   * @var string
   */
  private static $default_sort = 'Enabled DESC, Title ASC';

  public static function getDefaultRecord() {
    return CspRule::get()->filter('Enabled', 1)->first();
  }

  /**
   * CMS Fields
   * @return FieldList
   */
  public function getCMSFields()
  {
    $fields = parent::getCMSFields();
    $fields->addFieldToTab(
      'Root.Main',
      OptionsetField::create(
        'DeliveryMethod',
        'Delivery Method',
        [ 'Header' => 'Via an HTTP Header',  'MetaTag' => 'As a meta tag' ]
        )->setDescription('Reporting violations is not supported when using the meta tag delivery method')
    );
    $fields->dataFieldByName('AlternateReportURI')->setDescription('If not set, the default /csp/vN/report/ path will be used');

    // display policy
    $policy = $this->getPolicy(1, true);
    if($policy) {
      $fields->addFieldsToTab(
        'Root.Main',
        [
          HeaderField::create(
            'EnabledRulesPolicy',
            'Policy (enabled rules)'
          ),
          LiteralField::create('PolicyEnabledRules', '<p><pre>' . $policy . '</pre></p>')
        ]
      );
    }

    $policy = $this->getPolicy(null, true);
    if($policy) {
      $fields->addFieldsToTab(
        'Root.Main',
        [
          HeaderField::create(
            'AllRulesPolicy',
            'Policy (all rules)'
          ),
          LiteralField::create('PolicyAllRules', '<p><pre>' . $policy . '</pre></p>')
        ]
      );
    }

    if($this->ReportOnly == 1 && !$this->SendViolationReports) {
      $fields->dataFieldByName('SendViolationReports')->setDescription("'Report Only' is on -  it is wise to turn on sending violation reports");
    }

    $fields->dataFieldByName('IsLive')->setTitle('Use on published website')->setDescription('When unchecked, this rule will be used on the draft site.');

    return $fields;
  }

  /**
   * TODO: maybe enabled can trigger on draft sites when off ?
   */
  public function getPolicy($enabled = 1, $pretty = false) {
    $items = $this->RuleItems();
    if(!is_null($enabled)) {
      $items = $items->filter('Enabled', (bool)$enabled);
    }
    $policy = "";
    foreach($items as $item) {
      $value = ($item->IncludeSelf == 1 ? "'self'" : "");
      $value .= ($item->UnsafeInline == 1 ? " 'unsafe-inline'" : "");
      $value .= ($item->AllowDataUri == 1 ? " data:" : "");
      $value .= ($item->Value ? " " . trim($item->Value, "; ") : "");

      $value = trim($value);
      //var_dump($value);print "<br>";
      $policy .= $item->Key . ($value ? " {$value};" : ";");
      $policy .= ($pretty ? "\n" : "");
    }
    return $policy;
  }

  /**
   * Header values
   * @returns array
   */
  public function HeaderValues() {

    $policy_string = trim($this->getPolicy());
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
        // TODO ensure URL is not funky e.g including ; characters
        $reporting_url = $this->AlternateReportURI;
      } else {
        $reporting_url = "/csp/v1/report/";
      }

      /**
       * Reporting changed between CSP Level 2 and 3
       * With a min. level of 2, we send report-uri and Report-To headers
       * With a min. level of 3, we send Report-To only
       * @see https://wicg.github.io/reporting/#examples
       * @see https://w3c.github.io/webappsec-csp/#directives-reporting
       */

      $report_to = "";
      $min_csp_level = $this->MinimumCspLevel;

      /**
       * The REQUIRED max-age member defines the endpoint group’s lifetime, as a non-negative integer number of seconds
       * https://wicg.github.io/reporting/#max-age-member
       */
      $max_age = 10886400;// TODO configure

      // 3 only gets Report-To
      $reporting = [
        "group" => "csp-endpoint",
        "max-age" => $max_age,
        "endpoints" => [
          // an array of URLs, non secure-endpoints should be ignored by the user agent
          [ "url" => $reporting_url ],
        ],
      ];

      if($min_csp_level < 3) {
        // Only 1,2 will add a report-uri, when selecting '3' this is ignored
        $report_to .= "report-uri {$reporting_url}";
      }

      // 1,2,3 use report-to so that UserAgents that support it can use this as they'll ignore report-uri
      $report_to .= "; report-to csp-endpoint";

      // only apply report_to if there is a URL and the
      if($reporting_url) {
        $policy_string .= $report_to;
      }
    }

    $response = [
      'header' => $header,
      'policy_string' => $policy_string,
      'reporting' => $reporting,
    ];

    return $response;
  }
}

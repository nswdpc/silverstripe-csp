<?php
use NSWDPC\Utilities\ContentSecurityPolicy\ReportingEndpoint;

/**
 * A Content Security Policy policy record
 * @author james.ellis@dpc.nsw.gov.au
 */
class CspPolicy extends DataObject {

  private static $singular_name = 'Policy';
  private static $plural_name = 'Policies';

  private static $run_in_modeladmin = false;// whether to set the policy in ModelAdmin and descendants of ModelAdmin
  private static $whitelisted_controllers = [];// do not set a policy when current controller is in this list of controllers

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
   * Default sort ordering
   * @var string
   */
  private static $default_sort = 'Enabled DESC, Title ASC';

  public static function getDefaultRecord() {
    return CspPolicy::get()->filter('Enabled', 1)->first();
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
        )->setDescription( _t('ContentSecurityPolicy.REPORT_VIA_META_TAG', 'Reporting violations is not supported when using the meta tag delivery method') )
    );

    $internal_reporting_url = ReportingEndpoint::getCurrentReportingUrl();
    $fields->dataFieldByName('AlternateReportURI')
      ->setTitle( _t('ContentSecurityPolicy.ALTERNATE_REPORT_URI_TITLE', 'Set a reporting URL that will accept violation reports') )
      ->setDescription( sprintf( _t('ContentSecurityPolicy.ALTERNATE_REPORT_URI', 'If not set, and the sending of violation reports is enabled, reports will be directed to %s and will appear in the CSP/Reports admin'), $internal_reporting_url ) );

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
            '<p><pre><code>'
              . 'Report-To: ' . json_encode($policy['reporting'], JSON_UNESCAPED_SLASHES)
              . '</code></pre></p>'
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
            '<p><pre><code>'
              . 'Report-To: ' . json_encode($policy['reporting'], JSON_UNESCAPED_SLASHES)
              . '</code></pre></p>'
          )
        ]
      );
    }

    $fields->dataFieldByName('SendViolationReports')->setDescription( _t('ContentSecurityPolicy.SEND_VIOLATION_REPORTS', 'Send violation reports to a reporting system') );

    if($this->ReportOnly == 1 && !$this->SendViolationReports) {
      $fields->dataFieldByName('SendViolationReports')->setRightTitle( _t('ContentSecurityPolicy.SEND_VIOLATION_REPORTS_REPORT_ONLY', '\'Report Only\' is on - it is wise to turn on sending violation reports') );
    }

    $fields->dataFieldByName('ReportOnly')
          ->setDescription(  _t('ContentSecurityPolicy.REPORT_ONLY', 'Allows experimenting with the policy by monitoring (but not enforcing) its effects') );

    $fields->dataFieldByName('IsLive')->setTitle('Use on published website')->setDescription( _t('ContentSecurityPolicy.USE_ON_PUBLISHED_SITE', 'When unchecked, this policy will be used on the draft site only') );

    $fields->dataFieldByName('MinimumCspLevel')
          ->setTitle( _t('ContentSecurityPolicy.MINIMUM_CSP_LEVEL', 'Minimum CSP Level') )
          ->setDescription( _t('ContentSecurityPolicy.MINIMUM_CSP_LEVEL_DESCRIPTION', "Setting a higher level will remove from features deprecated in previous versions, such as the 'report-uri' directive") );

    return $fields;
  }

  /**
   * TODO: maybe enabled can trigger on draft sites when off ?
   */
  public function getPolicy($enabled = 1, $pretty = false) {
    $items = $this->Directives();
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
      $max_age = abs($this->config()->get('max_age'));

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
      $report_to .= ";" . ($pretty ? "\n" : " ") . "report-to csp-endpoint";

      // only apply report_to if there is a URL and the
      if($reporting_url) {
        $policy_string .= ($pretty ? "\n" : "") . $report_to;
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

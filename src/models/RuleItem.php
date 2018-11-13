<?php
/**
 * A Content Security Policy rule item, can be used by multiple {@link CspRule}
 * @author james.ellis@dpc.nsw.gov.au
 */
class CspRuleItem extends DataObject {

  private static $singular_name = 'Rule item';
  private static $plural_name = 'Rule items';

  /**
   * Database fields
   * @var array
   */
  private static $db = [
    'Key' => 'Varchar(255)',
    'Value' => 'Text',
    'IncludeSelf' => 'Boolean',
    'UnsafeInline' => 'Boolean',
    'AllowDataUri' => 'Boolean',
    'Enabled' => 'Boolean'
  ];

  /**
   * Defines summary fields commonly used in table columns
   * as a quick overview of the data for this dataobject
   * @var array
   */
  private static $summary_fields = [
    'Key' => 'Directive',
    'Value' => 'Value',
    'Enabled.Nice' =>'Enabled',
    'Rules.Count' => 'Rules',
    'IncludeSelf.Nice' =>'Include \'self\'',
    'UnsafeInline.Nice' =>'Unsafe Inline',
    'AllowDataUri.Nice' =>'Allow Data URI',
  ];

  /**
   * Many_many relationship
   * @var array
   */
  private static $belongs_many_many = [
    'Rules' => CspRule::class,
  ];

  public function getTitle() {
    return $this->Key;
  }

  /**
   * The text here is taken from: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
   */
  public function possibleKeys() {
    $keys = [
      'default-src' => 'the fallback for all directives',
      'base-uri' => 'restricts the URLs which can be used in a document\'s <base> element',
      'frame-src' => 'specifies valid sources for nested browsing contexts loading using elements such as <frame> and <iframe>',
      'connect-src' => 'restricts the URLs which can be loaded using script interfaces (Restricted APIs: <a ping>, Fetch,  XHR, WebSocket, EventSource)',
      'font-src' => 'specifies valid sources for fonts loaded using @font-face',
      'form-action' => 'restricts the URLs which can be used as the target of a form submissions from a given context',
      'frame-src' => 'specifies valid sources for nested browsing contexts loading using elements such as <frame> and <iframe>',
      'frame-ancestors' => 'specifies valid parents that may embed a page using <frame>, <iframe>, <object>, <embed>, or <applet>',
      'img-src' => 'specifies valid sources of images and favicons',
      'media-src' => 'specifies valid sources for loading media using the <audio> and <video> elements',
      'object-src' => 'specifies valid sources for the <object>, <embed>, and <applet> elements',
      'script-src' => 'Specifies valid sources for JavaScript',
      'style-src' => 'specifies valid sources for sources for stylesheets',
      'upgrade-insecure-requests' => 'instructs user agents to treat all of a site\'s insecure URLs (those served over HTTP) as though they have been replaced with secure URLs (those served over HTTPS)',
      'worker-src' => 'specifies valid sources for Worker, SharedWorker, or ServiceWorker scripts',
      'prefetch-src' => 'Specifies valid sources to be prefetched or prerendered',
      'webrtc-src' => 'specifies valid sources for WebRTC connections',
      'manifest-src' => 'specifies valid sources of application manifest files',
      'plugin-types' => 'restricts the set of plugins that can be embedded into a document by limiting the types of resources which can be loaded',
      'sandbox' => 'enables a sandbox for the requested resource similar to the <iframe> sandbox attribute',
      'block-all-mixed-content' => 'prevents loading any assets using HTTP when the page is loaded using HTTPS',
      'require-sri-for' => 'requires the use of SRI for scripts or styles on the page'
    ];

    ksort($keys);

    return $keys;
  }

  /**
   * Event handler called before writing to the database.
   */
  public function onBeforeWrite()
  {
    parent::onBeforeWrite();
    if(!$this->Key && $this->KeySelection) {
      $this->Key = $this->KeySelection;
    }

    if($this->Key == 'upgrade-insecure-requests') {
      $this->Value = '';
    } else {
      $this->Value = trim(rtrim($this->Value, ";"));
    }
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
      LiteralField::create('DirectiveHelper', '<p class="message notice">Prior to adding a directive, you should consult the <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy">Content Security Policy MDN documentation</a><p>'),
      'Key'
    );

    $fields->dataFieldByName('IncludeSelf')->setDescription( _t('ContentSecurityPolicy.ADD_SELF_VALUE', "Adds the 'self' value to this rule" ) );
    $fields->dataFieldByName('AllowDataUri')->setDescription( _t('ContentSecurityPolicy.ADD_DATA_VALUE', "Adds the 'data:' value to this rule" ) );
    $fields->dataFieldByName('UnsafeInline')->setDescription( _t('ContentSecurityPolicy.ADD_UNSAFE_INLINE_VALUE', "Adds the 'unsafe-inline' value to this rule" ) );

    $rules = $this->Rules()->count();
    if($rules > 1) {
      $fields->addFieldToTab(
        'Root.Main',
        LiteralField::create('MultipleRules', "<p class=\"message notice\">" . sprintf(_t('ContentSecurityPolicy.USED_IN_MULTIPLE_RULES', 'This record is used in %d policies. Updating it will modify all linked policies'), $rules) . "</p>")
      );
    }

    $keys = $this->possibleKeys();
    $select_keys = [];
    foreach($keys as $key => $value) {
      $select_keys[ $key ] = $key . " - " . $value;
    }
    $fields->removeByName(array(
      'Key'
    ));
    $fields->addFieldToTab('Root.Main',
      CompositeField::create(
        TextField::create('Key','Enter a directive'),
        DropdownField::create(
          'KeySelection',
          _t('ContentSecurityPolicy.SELECT_PREDEFINED_DIRECTIVE', '...or select a pre-defined directive'),
          $select_keys
        )->setEmptyString('')
      ),
      'Value'
    );

    $fields->dataFieldByName('Value')->setDescription('Note that some directives can contain no values');

    return $fields;
  }

}

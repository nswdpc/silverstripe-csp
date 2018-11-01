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
    'Key' => 'Key',
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

  public function possibleKeys() {
    return [
      'default-src',
      'base-uri',
      'frame-src',
      'connect-src',
      'font-src',
      'form-action',
      'frame-ancestors',
      'img-src',
      'object-src',
      'script-src',
      'style-src',
      'upgrade-insecure-requests'
    ];
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
    $this->Value = trim(rtrim($this->Value, ";"));
  }

  /**
   * CMS Fields
   * @return FieldList
   */
  public function getCMSFields()
  {
    $fields = parent::getCMSFields();

    $fields->dataFieldByName('IncludeSelf')->setDescription("Adds the 'self' value to this rule");
    $fields->dataFieldByName('AllowDataUri')->setDescription("Adds the 'data:' value to this rule");
    $fields->dataFieldByName('UnsafeInline')->setDescription("Adds the 'unsafe-inline' value to this rule");

    $rules = $this->Rules()->count();
    if($rules > 1) {
      $fields->addFieldToTab(
        'Root.Main',
        LiteralField::create('MultipleRules', "<p class=\"message notice\">This record is used in {$rules} policies. Updating it will modify all linked policies</p>")
      );
    }

    $keys = $this->possibleKeys();
    $select_keys = [];
    foreach($keys as $key) {
      $select_keys[ $key ] = $key;
    }
    $fields->removeByName(array(
      'Key'
    ));
    $fields->addFieldToTab('Root.Main',
      CompositeField::create(
        TextField::create('Key','Key'),
        DropdownField::create(
          'KeySelection',
          '...or select a pre-defined key',
          $select_keys
        )->setEmptyString('')
      ),
      'Value'
    );

    return $fields;
  }

}

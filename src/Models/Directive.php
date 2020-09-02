<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use Silverstripe\ORM\DataObject;
use Silverstripe\Forms\LiteralField;
use Silverstripe\Forms\CompositeField;
use Silverstripe\Forms\Textfield;
use Silverstripe\Forms\TextareaField;
use Silverstripe\Forms\DropdownField;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use Symbiote\MultiValueField\Fields\KeyValueField;

/**
 * A Content Security Policy directive, can be used by multiple {@link Policy}
 * @author james.ellis@dpc.nsw.gov.au
 */
class Directive extends DataObject implements PermissionProvider
{
    private static $table_name = 'CspDirective';

    private static $singular_name = 'Directive';
    private static $plural_name = 'Directives';

    /**
     * Default sort ordering
     * @var string
     */
    private static $default_sort = 'Key ASC';

    /**
     * Database fields
     * @var array
     */
    private static $db = [
        'Key' => 'Varchar(255)',
        'Rules' => 'MultiValueField',
        'IncludeSelf' => 'Boolean',
        'UnsafeInline' => 'Boolean',
        'AllowDataUri' => 'Boolean',
        'Enabled' => 'Boolean',
        'UseNonce' => 'Boolean'
    ];

    /**
     * Defines summary fields commonly used in table columns
     * as a quick overview of the data for this dataobject
     * @var array
     */
    private static $summary_fields = [
        'ID' => '#',
        'Key' => 'Name',
        'DirectiveValue' => 'Value',
        'Enabled.Nice' =>'Enabled',
        'Policies.Count' => 'Policies',
        'IncludeSelf.Nice' =>'Include \'self\'',
        'UnsafeInline.Nice' =>'Unsafe Inline',
        'AllowDataUri.Nice' =>'Allow Data URI',
        'UseNonce.Nice' => 'Use Nonce'
    ];

    /**
     * Many_many relationship
     * @var array
     */
    private static $belongs_many_many = [
        'Policies' => Policy::class,
    ];

    public function getTitle()
    {
        return substr($this->Key . " " . $this->getDirectiveValue(), 0, 100) . "...";
    }

    /**
     * The text here is taken from: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
     */
    public function possibleKeys()
    {
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

    public static function KeysWithoutValues()
    {
        return [
            'block-all-mixed-content','upgrade-insecure-requests'
        ];
    }

    /**
     * Event handler called before writing to the database.
     */
    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if (!$this->Key && $this->KeySelection) {
            $this->Key = $this->KeySelection;
        }

        if (in_array($this->Key, self::KeysWithoutValues())) {
            // ensure these keys never get values
            $this->Rules = '';// no rules
            $this->RulesValue = '';// no rules value either
            $this->IncludeSelf = 0;
            $this->UnsafeInline = 0;
            $this->AllowDataUri = 0;
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

        $fields->dataFieldByName('IncludeSelf')->setDescription(_t('ContentSecurityPolicy.ADD_SELF_VALUE', "Adds the 'self' value to this directive"));
        $fields->dataFieldByName('AllowDataUri')->setDescription(_t('ContentSecurityPolicy.ADD_DATA_VALUE', "Adds the 'data:' value to this directive"));
        $fields->dataFieldByName('UnsafeInline')->setDescription(_t('ContentSecurityPolicy.ADD_UNSAFE_INLINE_VALUE', "Adds the 'unsafe-inline' value to this directive"));

        $policies = $this->Policies()->count();
        if ($policies > 1) {
            $fields->addFieldToTab(
                'Root.Main',
                LiteralField::create('MultiplePolicies', "<p class=\"message notice\">" . sprintf(_t('ContentSecurityPolicy.USED_IN_MULTIPLE_POLICIES', 'This record is used in %d policies. Updating it will modify all linked policies'), $policies) . "</p>")
            );
        }

        $keys = $this->possibleKeys();
        $select_keys = [];
        foreach ($keys as $key => $value) {
            $select_keys[ $key ] = $key . " - " . $value;
        }
        $fields->removeByName([
            'Key'
        ]);
        $fields->addFieldToTab(
            'Root.Main',
            CompositeField::create(
                    TextField::create('Key', 'Enter a directive'),
                    DropdownField::create(
                    'KeySelection',
                    _t('ContentSecurityPolicy.SELECT_PREDEFINED_DIRECTIVE', '...or select a pre-defined directive'),
                    $select_keys
                )->setEmptyString('')
                ),
            'Rules'
        );

        $fields->addFieldToTab(
            'Root.Main',
            KeyValueField::create('Rules', 'Rules & Restrictions')
                ->setDescription('Add the rule on the left and a reason for adding the rule on the right')
                ->setRightTitle('Some values, such as hashes, must be single-quoted'),
            'IncludeSelf'
        );

        $fields->addFieldToTab(
            'Root.Main',
            TextareaField::create('LiteralRules', 'Current directive value', htmlspecialchars($this->getDirectiveValue())),
            'Rules'
        );

        $fields->makeFieldReadonly('LiteralRules');


        $fields->dataFieldByName('UseNonce')
                ->setDescription(
                    'Add the system generated per-request number-once value to this directive.'
                    . ' Only applicable to certain directives.'
        );

        return $fields;
    }

    /**
     * Rules are stored in a key/value mapping. Return the rules as a value for inclusion in the header
     * @returns string
     */
    public function getValuesFromRules()
    {
        $rules = $this->Rules;
        $values = "";
        if ($rules) {
            $rules = $rules->getValues();
            if (!empty($rules) && is_array($rules)) {
                foreach ($rules as $rule => $optional_reason) {
                    $values .= $rule . " ";
                }
            }
        }
        return trim($values, "; ");
    }

    /**
    * Returns the directive value for use in a header
    * @returns string
    */
    public function getDirectiveValue()
    {
        $value = ($this->IncludeSelf == 1 ? "'self'" : "");
        $value .= ($this->UnsafeInline == 1 ? " 'unsafe-inline'" : "");
        $value .= ($this->AllowDataUri == 1 ? " data:" : "");
        // Add the nonce if available and enabled for this directive
        if($this->UseNonce == 1) {
            $nonce = new Nonce();
            $nonce_value = $nonce->get();
            $value .= " 'nonce-{$nonce_value}'";
        }
        $value .= " " . $this->getValuesFromRules();
        $value = trim($value);
        return $value;
    }

    public function canView($member = null)
    {
        return Permission::check('CSP_DIRECTIVE_VIEW');
    }

    public function canEdit($member = null)
    {
        return Permission::check('CSP_DIRECTIVE_EDIT');
    }

    public function canDelete($member = null)
    {
        return Permission::check('CSPE_DIRECTIVE_DELETE');
    }

    public function canCreate($member = null, $context = [])
    {
        return Permission::check('CSP_DIRECTIVE_EDIT');
    }

    public function providePermissions()
    {
        return [
            'CSP_DIRECTIVE_VIEW' => [
                'name' => 'View directives',
                'category' => 'CSP',
            ],
            'CSP_DIRECTIVE_EDIT' => [
                'name' => 'Edit & Create directives',
                'category' => 'CSP',
            ],
            'CSPE_DIRECTIVE_DELETE' => [
                'name' => 'Delete directives',
                'category' => 'CSP',
            ]
        ];
    }
}

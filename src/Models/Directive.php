<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\ORM\DataObject;
use SilverStripe\Forms\HTMLReadonlyField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\CompositeField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\TextField;
use SilverStripe\Forms\TextareaField;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use Symbiote\MultiValueField\Fields\KeyValueField;

/**
 * A Content Security Policy directive, can be used by multiple {@link Policy}
 */
class Directive extends DataObject implements PermissionProvider
{

    /**
     * @config
     */
    private static $table_name = 'CspDirective';

    /**
     * @config
     */
    private static $singular_name = 'Directive';

    /**
     * @config
     */
    private static $plural_name = 'Directives';

    /**
     * Default sort ordering
     * @var string
     * @config
     */
    private static $default_sort = 'Key ASC';

    /**
     * Database fields
     * @var array
     * @config
     */
    private static $db = [
        'Key' => 'Varchar(255)',
        'Rules' => 'MultiValueField',
        'Enabled' => 'Boolean',
        'IncludeSelf' => 'Boolean',
        'UnsafeInline' => 'Boolean',
        'AllowDataUri' => 'Boolean',
        'UseNonce' => 'Boolean'
    ];

    /**
     * Database indexes
     * @var array
     * @config
     */
    private static $indexes = [
        'Enabled' => true,
        'Key' => true
    ];

    /**
     * Defines summary fields commonly used in table columns
     * as a quick overview of the data for this dataobject
     * @var array
     * @config
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
     * @config
     */
    private static $belongs_many_many = [
        'Policies' => Policy::class,
    ];

    public function getTitle()
    {
        return substr($this->Key . " " . $this->getDirectiveValue(true), 0, 100) . "...";
    }

    /**
     * The text here is taken from: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
     */
    public function possibleKeys()
    {
        $keys = [
            'default-src' => _t('ContentSecurityPolicy.DIRECTIVE_DEFAULT_SRC', 'the fallback for all directives'),
            'base-uri' => _t('ContentSecurityPolicy.DIRECTIVE_BASE_URI', 'restricts the URLs which can be used in a document\'s <base> element'),
            'frame-src' => _t('ContentSecurityPolicy.DIRECTIVE_FRAME_SRC', 'specifies valid sources for nested browsing contexts loading using elements such as <frame> and <iframe>'),
            'connect-src' => _t('ContentSecurityPolicy.DIRECTIVE_CONNECT_SRC', 'restricts the URLs which can be loaded using script interfaces (Restricted APIs: <a ping>, Fetch,  XHR, WebSocket, EventSource)'),
            'font-src' => _t('ContentSecurityPolicy.DIRECTIVE_FONT_SRC', 'specifies valid sources for fonts loaded using @font-face'),
            'form-action' => _t('ContentSecurityPolicy.DIRECTIVE_FORM_ACTION', 'restricts the URLs which can be used as the target of a form submissions from a given context'),
            'frame-ancestors' => _t('ContentSecurityPolicy.DIRECTIVE_FRAME_ANCESTORS', 'specifies valid parents that may embed a page using <frame>, <iframe>, <object>, <embed>, or <applet>'),
            'img-src' => _t('ContentSecurityPolicy.DIRECTIVE_IMG_SRC', 'specifies valid sources of images and favicons'),
            'media-src' => _t('ContentSecurityPolicy.DIRECTIVE_MEDIA_SRC', 'specifies valid sources for loading media using the <audio> and <video> elements'),
            'object-src' => _t('ContentSecurityPolicy.DIRECTIVE_OBJECT_SRC', 'specifies valid sources for the <object>, <embed>, and <applet> elements'),
            'script-src' => _t('ContentSecurityPolicy.DIRECTIVE_SCRIPT_SRC', 'Specifies valid sources for JavaScript'),
            'style-src' => _t('ContentSecurityPolicy.DIRECTIVE_STYLE_SRC', 'specifies valid sources for sources for stylesheets'),
            'upgrade-insecure-requests' => _t('ContentSecurityPolicy.DIRECTIVE_UPGRADE_INSECURE_REQUESTS', 'instructs user agents to treat all of a site\'s insecure URLs (those served over HTTP) as though they have been replaced with secure URLs (those served over HTTPS)'),
            'worker-src' => _t('ContentSecurityPolicy.DIRECTIVE_WORKER_SRC', 'specifies valid sources for Worker, SharedWorker, or ServiceWorker scripts'),
            'prefetch-src' => _t('ContentSecurityPolicy.DIRECTIVE_PREFETCH_SRC', 'Specifies valid sources to be prefetched or prerendered'),
            'webrtc-src' => _t('ContentSecurityPolicy.DIRECTIVE_WEBRTC_SRC', 'specifies valid sources for WebRTC connections'),
            'manifest-src' => _t('ContentSecurityPolicy.DIRECTIVE_MANIFEST_SRC', 'specifies valid sources of application manifest files'),
            'plugin-types' => _t('ContentSecurityPolicy.DIRECTIVE_PLUGIN_TYPES', 'restricts the set of plugins that can be embedded into a document by limiting the types of resources which can be loaded'),
            'sandbox' => _t('ContentSecurityPolicy.DIRECTIVE_SANDBOX', 'enables a sandbox for the requested resource similar to the <iframe> sandbox attribute'),
            'block-all-mixed-content' => _t('ContentSecurityPolicy.DIRECTIVE_BLOCK_ALL_MIXED_CONTENT', 'prevents loading any assets using HTTP when the page is loaded using HTTPS'),
            'require-sri-for' => _t('ContentSecurityPolicy.DIRECTIVE_REQUIRE_SRI_FOR', 'requires the use of Sub-Resource Integrity (SRI) for scripts or styles on the page')
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
            LiteralField::create(
                'DirectiveHelper',
                '<p class="message notice">'
                 . _t('ContentSecurityPolicy.DIRECTIVE_HELPER',
                        'Prior to adding a directive, you should consult the '
                        . 'Content Security Policy MDN documentation at '
                        . 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'
                )
                . '<p>'
            ),
            'Key'
        );

        $fields->dataFieldByName('IncludeSelf')->setDescription(_t('ContentSecurityPolicy.ADD_SELF_VALUE', "Adds the 'self' value to this directive"));
        $fields->dataFieldByName('AllowDataUri')->setDescription(_t('ContentSecurityPolicy.ADD_DATA_VALUE', "Adds the 'data:' value to this directive"));
        $fields->dataFieldByName('UnsafeInline')->setDescription(_t('ContentSecurityPolicy.ADD_UNSAFE_INLINE_VALUE', "Adds the 'unsafe-inline' value to this directive."));
        $fields->dataFieldByName('Enabled')->setDescription(_t('ContentSecurityPolicy.ENABLED_DIRECTIVE', "Enables this directive within linked policies"));

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
                TextField::create(
                    'Key',
                    'Enter a directive'
                ),
                DropdownField::create(
                    'KeySelection',
                    _t('ContentSecurityPolicy.SELECT_PREDEFINED_DIRECTIVE', '...or select a pre-defined directive'),
                    $select_keys
                )->setEmptyString('')
            )->setTitle(
                _t('ContentSecurityPolicy.DIRECTIVE_NAME_LABEL', 'Directive')
            ),
            'Rules'
        );

        $fields->addFieldToTab(
            'Root.Main',
            HTMLReadonlyField::create(
                'LiteralRules',
                'Current directive value',
                htmlspecialchars( $this->getDirectiveValue(true ))
            ),
            'Rules'
        );


        $fields->dataFieldByName('UseNonce')
                ->setDescription(
                    'Add the system generated per-request number-once value to this directive.'
                    . ' Only applicable to certain directives.'
        );

        // Rules field
        $fields->removeByName('Rules');
        $fields->addFieldToTab(
            'Root.Main',
            CompositeField::create(
                KeyValueField::create(
                    'Rules',
                    'Add the rule on the left and a reason for adding the rule on the right'
                )->setDescription(
                    'Some keywords, such as hashes, must be single-quoted'
                ),
                HTMLReadonlyField::create(
                    'RulesExample',
                    'Examples',
                    '<div class="container"><table class="table table-striped table-bordered">'
                    . '<tr><td>https://example.com</td><td>My reason for adding example.com</td></tr>'
                    . '<tr><td>\'report-sample\'</td><td>Send a portion of the violating code to the report endpoint</td></tr>'
                    . '<tr><td>\'sha256-xxxxxx\'</td><td>We need to allow this specific hash to enable an inline style</td></tr>'
                    . '</table></div>'
                )->setDescription(
                    'A good resource for available values and format is https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/Sources'
                )
            )->setTitle(
                'Extra values'
            )
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
    public function getDirectiveValue(bool $useFakeNonce = false)
    {
        $value = ($this->IncludeSelf == 1 ? "'self'" : "");
        $value .= ($this->UnsafeInline == 1 ? " 'unsafe-inline'" : "");
        $value .= ($this->AllowDataUri == 1 ? " data:" : "");
        // Add the nonce if available and enabled for this directive
        if($this->UseNonce == 1) {
            if($useFakeNonce) {
                // for display in CMS or similar
                $nonce = _t(__CLASS__ . ".SAMPLE_NONCE_ONLY", "sampleonly");
            } else {
                // use the nonce init'd in the controller
                $nonce = Nonce::getNonce();
            }
            $value .= " 'nonce-{$nonce}'";
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

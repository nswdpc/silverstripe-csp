<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\DB;
use DateTime;

/**
 *	Remove violation reports older than a set time
 */
class PruneViolationReportsJob extends AbstractQueuedJob
{
    use Configurable;

    // hour
    private static int $age = 1;

    public function __construct($older_than = 0)
    {
        if (!$older_than || $older_than <= 0) {
            $older_than = Config::inst()->get(self::class, 'age');
        }

        $this->older_than = (int)abs($older_than);
    }

    public function getTitle()
    {
        return _t('ContentSecurityPolicy.PRUNE_REPORTS_JOBTITLE', 'Remove CSP violation reports older than {count} hour(s)', ['count' => $this->older_than_hours]);
    }

    #[\Override]
    public function setup()
    {
        parent::setup();
        $this->totalSteps = 1;
    }

    public function getRecordCount()
    {
        $query = 'SELECT COUNT(ID) AS RecordCount FROM "CspViolationReport"';
        if ($result = DB::query($query)) {
            $row = $result->record();
            return $row['RecordCount'] ?? 0;
        }

        return 0;
    }

    public function process()
    {
        $older_than = abs($this->older_than);
        if ($older_than <= 0) {
            $older_than = 1;
        }

        $this->older_than_hours = $older_than;
        $pre_count = $this->getRecordCount();

        $dt = new DateTime();
        $now = $dt->format('Y-m-d H:i:s');

        $query = 'DELETE FROM "CspViolationReport" WHERE "Created" < ? - INTERVAL ? HOUR';
        DB::prepared_query($query, [$now, $this->older_than]);

        $post_count = $this->getRecordCount();

        $removed = $pre_count - $post_count;
        $removed_string = ($removed . '/' . $pre_count);
        $message = _t('ContentSecurityPolicy.REMOVED_COUNT_REPORTS', 'Removed {count} reports(s)', ['count' => $removed_string]);
        $this->addMessage($message);
        $this->currentStep = 1;

        $this->isComplete = true;
    }

    /**
     * Recreate the job
     */
    public function afterComplete()
    {
        $job = new PruneViolationReportsJob($this->older_than_hours);
        $dt = new DateTime();
        $dt->modify('+' . $this->older_than . ' hour');

        singleton(QueuedJobService::class)->queueJob($job, $dt->format('Y-m-d H:i:s'));
    }
}

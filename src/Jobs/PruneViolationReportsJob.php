<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\DB;
use DateTime;

/**
 *	Remove violation reports older than a set time
 */
class PruneViolationReportsJob extends AbstractQueuedJob
{
    private static int $older_than;//hour

    public function __construct($older_than = 0)
    {
        if (!$older_than) {
            $older_than = Config::inst()->get(self::class, 'older_than');
        }

        $this->older_than = (int)abs($older_than);
    }

    public function getTitle()
    {
        return sprintf(_t('ContentSecurityPolicy.PRUNE_REPORTS_JOBTITLE', 'Remove CSP violation reports older than %d hour'), $this->older_than);
    }

    public function getRecordCount()
    {
        $query = 'SELECT COUNT(ID) AS RecordCount FROM "CspViolationReport"';
        if ($result = DB::query($query)) {
            $row = $result->record();
            return $row['RecordCount'] ?? 0;
        } else {
            return 0;
        }
    }

    public function process()
    {
        $older_than = abs($this->older_than);
        if ($older_than === 0) {
            $older_than = 1;
        }

        $this->older_than = $older_than;
        $pre_count = $this->getRecordCount();

        $dt = new DateTime();
        $now = $dt->format('Y-m-d H:i:s');

        $query = 'DELETE FROM "CspViolationReport" WHERE "Created" < ? - INTERVAL ? HOUR';
        DB::prepared_query($query, [$now, $this->older_than]);

        $post_count = $this->getRecordCount();

        $removed = $pre_count - $post_count;
        $removed_string = ($removed . '/' . $pre_count);
        $message = sprintf(_t('ContentSecurityPolicy.REMOVED_COUNT_REPORTS', 'Removed %s reports(s)'), $removed_string);
        $this->addMessage($message);
        $this->totalSteps = $post_count - $pre_count;
        $this->currentStep = $post_count - $pre_count;

        $this->isComplete = true;
    }

    /**
     * Recreate the job
     */
    public function afterComplete()
    {
        $job = new PruneViolationReportsJob($this->older_than);
        $dt = new DateTime();
        $dt->modify('+' . $this->older_than . ' hour');

        singleton(QueuedJobService::class)->queueJob($job, $dt->format('Y-m-d H:i:s'));
    }
}

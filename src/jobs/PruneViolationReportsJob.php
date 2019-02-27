<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use QueuedJob;
use QueuedJobService;
use AbstractQueuedJob;
use Config;
use SS_Log;
use DB;
use DateTime;
use Convert;
use Exception;


/**
 *	Remove violation reports older than a set time
 */
class PruneViolationReportsJob extends AbstractQueuedJob {
  private static $older_than = 1;//hour

  public function __construct($older_than = 0) {
    if(!$older_than) {
      $older_than = Config::inst()->get(self::class, 'older_than');
    }
    $this->older_than = (int)abs($older_than);
  }

  public function getTitle() {
    return sprintf(_t('ContentSecurityPolicy.PRUNE_REPORTS_JOBTITLE', 'Remove CSP violation reports older than %d hour'), $this->older_than);
  }

  public function getRecordCount() {
    $query = "SELECT COUNT(ID) AS RecordCount FROM `CspViolationReport`";
    $result = DB::query($query);
    if($result) {
      $row = $result->nextRecord();
      return isset($row['RecordCount']) ? $row['RecordCount'] : 0;
    }
    return 0;
  }

  public function process() {
    $older_than = (int)abs($this->older_than);
    if(!$older_than) {
      $older_than = 1;
    }

    $this->older_than = $older_than;
    $pre_count = $this->getRecordCount();

    $dt = new DateTime();
    $now = $dt->format('Y-m-d H:i:s');

    $query = "DELETE FROM `CspViolationReport` WHERE `Created` < '" . Convert::raw2sql($now) . "' -  INTERVAL {$this->older_than} HOUR";
    $result = DB::query($query);

    $post_count = $this->getRecordCount();

    $removed = $pre_count - $post_count;
    $removed_string = ($removed . '/' . $pre_count);
    $message = sprintf( _t('ContentSecurityPolicy.REMOVED_COUNT_REPORTS', 'Removed %s reports(s)'), $removed_string );
    //SS_Log::log($message, SS_Log::DEBUG);
    $this->addMessage($message);

    $this->totalSteps = $this->currentStep = $post_count;

    $this->isComplete = true;
    return;

  }

  /**
   * Recreate the job
   */
  public function afterComplete() {
    $job = new PruneViolationReportsJob($this->older_than);
    $dt = new DateTime();
    $dt->modify('+' . $this->older_than . ' hour');
    singleton( QueuedJobService::class )->queueJob($job, $dt->format('Y-m-d H:i:s'));
  }
}

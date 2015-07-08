/*
 * Functions related to setting various queue properties from drivers
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

#include "blk.h"

/*
 * for max sense size
 */
#include <scsi/scsi_cmnd.h>

/**
 * blk_end_sync_rq - executes a completion event on a request
 * @rq: request to complete
 * @error: end I/O status of the request
 */
/**ltl
 * 功能:请求执行完成函数。
 * 参数:
 * 返回值:
 * 说明:只用于执行SCSI命令时使用
 */
static void blk_end_sync_rq(struct request *rq, int error)
{
	struct completion *waiting = rq->end_io_data;

	rq->end_io_data = NULL;
	__blk_put_request(rq->q, rq); /* 释放请求对象空间 */

	/*
	 * complete last, if this is a stack request the process (and thus
	 * the rq pointer) could be invalid right after this complete()
	 */
	complete(waiting); /*  */
}

/**
 * blk_execute_rq_nowait - insert a request into queue for execution
 * @q:		queue to insert the request in
 * @bd_disk:	matching gendisk
 * @rq:		request to insert
 * @at_head:    insert request at head or tail of queue
 * @done:	I/O completion handler
 *
 * Description:
 *    Insert a fully prepared request at the back of the I/O scheduler queue
 *    for execution.  Don't wait for completion.
 */
/**
 * 功能:往派发队列插入，并执行。
 * 参数:
 * 返回值:
 * 说明:
 */
void blk_execute_rq_nowait(struct request_queue *q, struct gendisk *bd_disk,
			   struct request *rq, int at_head,
			   rq_end_io_fn *done)
{
	int where = at_head ? ELEVATOR_INSERT_FRONT : ELEVATOR_INSERT_BACK;

	rq->rq_disk = bd_disk;	/* 通用磁盘对象 */
	rq->end_io = done;	/* 命令完成处理函数 */
	WARN_ON(irqs_disabled());
	spin_lock_irq(q->queue_lock);
	__elv_add_request(q, rq, where, 1); /* 把请求插入到派发队列 */
	__generic_unplug_device(q);	/* "泄流" */
	/* the queue is stopped so it won't be plugged+unplugged */
	if (rq->cmd_type == REQ_TYPE_PM_RESUME)
		q->request_fn(q);
	spin_unlock_irq(q->queue_lock);
}
EXPORT_SYMBOL_GPL(blk_execute_rq_nowait);

/**
 * blk_execute_rq - insert a request into queue for execution
 * @q:		queue to insert the request in
 * @bd_disk:	matching gendisk
 * @rq:		request to insert
 * @at_head:    insert request at head or tail of queue
 *
 * Description:
 *    Insert a fully prepared request at the back of the I/O scheduler queue
 *    for execution and wait for completion.
 */
/**ltl
 * 功能:执行命令
 * 参数:	q		->请求队列对象
 *		bd_disk	->通用磁盘对象
 *		rq		->请求对象
 *		at_head	->是否插入派发队列的队头
 * 返回值:
 * 说明:
 */
int blk_execute_rq(struct request_queue *q, struct gendisk *bd_disk,
		   struct request *rq, int at_head)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	char sense[SCSI_SENSE_BUFFERSIZE];
	int err = 0;

	/*
	 * we need an extra reference to the request, so we can look at
	 * it after io completion
	 */
	rq->ref_count++; /* 递增引用计数器 */

	if (!rq->sense) {
		memset(sense, 0, sizeof(sense));
		rq->sense = sense;
		rq->sense_len = 0;
	}
	/* 请求完成的私有数据 */
	rq->end_io_data = &wait;
	blk_execute_rq_nowait(q, bd_disk, rq, at_head, blk_end_sync_rq);
	wait_for_completion(&wait);

	if (rq->errors)
		err = -EIO;

	return err;
}
EXPORT_SYMBOL(blk_execute_rq);

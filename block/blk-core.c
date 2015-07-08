/*
 * Copyright (C) 1991, 1992 Linus Torvalds
 * Copyright (C) 1994,      Karl Keyte: Added support for disk statistics
 * Elevator latency, (C) 2000  Andrea Arcangeli <andrea@suse.de> SuSE
 * Queue request tables / lock, selectable elevator, Jens Axboe <axboe@suse.de>
 * kernel-doc documentation started by NeilBrown <neilb@cse.unsw.edu.au>
 *	-  July2000
 * bio rewrite, highmem i/o, etc, Jens Axboe <axboe@suse.de> - may 2001
 */

/*
 * This handles all read/write requests to block devices
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/fault-inject.h>

#define CREATE_TRACE_POINTS
#include <trace/events/block.h>

#include "blk.h"

EXPORT_TRACEPOINT_SYMBOL_GPL(block_remap);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_rq_remap);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_bio_complete);

static int __make_request(struct request_queue *q, struct bio *bio);

/*
 * For the allocated request tables
 */
static struct kmem_cache *request_cachep;

/*
 * For queue allocation
 */
struct kmem_cache *blk_requestq_cachep;

/*
 * Controlling structure to kblockd
 */
static struct workqueue_struct *kblockd_workqueue;

static void drive_stat_acct(struct request *rq, int new_io)
{
	struct hd_struct *part;
	int rw = rq_data_dir(rq);
	int cpu;

	if (!blk_do_io_stat(rq))
		return;

	cpu = part_stat_lock();
	part = disk_map_sector_rcu(rq->rq_disk, blk_rq_pos(rq));

	if (!new_io)
		part_stat_inc(cpu, part, merges[rw]);
	else {
		part_round_stats(cpu, part);
		part_inc_in_flight(part, rw);
	}

	part_stat_unlock();
}

void blk_queue_congestion_threshold(struct request_queue *q)
{
	int nr;

	nr = q->nr_requests - (q->nr_requests / 8) + 1;
	if (nr > q->nr_requests)
		nr = q->nr_requests;
	q->nr_congestion_on = nr;

	nr = q->nr_requests - (q->nr_requests / 8) - (q->nr_requests / 16) - 1;
	if (nr < 1)
		nr = 1;
	q->nr_congestion_off = nr;
}

/**
 * blk_get_backing_dev_info - get the address of a queue's backing_dev_info
 * @bdev:	device
 *
 * Locates the passed device's request queue and returns the address of its
 * backing_dev_info
 *
 * Will return NULL if the request queue cannot be located.
 */
/**ltl
 * 功能:获取块设备的后备缓冲区
 * 参数:bdev	->块设备对象
 * 返回值:
 * 说明:
 */
struct backing_dev_info *blk_get_backing_dev_info(struct block_device *bdev)
{
	struct backing_dev_info *ret = NULL;
	struct request_queue *q = bdev_get_queue(bdev);

	if (q)
		ret = &q->backing_dev_info;
	return ret;
}
EXPORT_SYMBOL(blk_get_backing_dev_info);
/**
 * 功能:request请求对象的初始化
 */
void blk_rq_init(struct request_queue *q, struct request *rq)
{
	memset(rq, 0, sizeof(*rq));

	INIT_LIST_HEAD(&rq->queuelist);
	INIT_LIST_HEAD(&rq->timeout_list);
	rq->cpu = -1;
	rq->q = q;
	rq->__sector = (sector_t) -1;
	INIT_HLIST_NODE(&rq->hash);
	RB_CLEAR_NODE(&rq->rb_node);
	rq->cmd = rq->__cmd;
	rq->cmd_len = BLK_MAX_CDB;
	rq->tag = -1;
	rq->ref_count = 1;
	rq->start_time = jiffies;
	set_start_time_ns(rq);
}
EXPORT_SYMBOL(blk_rq_init);
/**ltl
 * 功能:
 * 参数:
 * 返回值:
 * 说明:
 */
static void req_bio_endio(struct request *rq, struct bio *bio,
			  unsigned int nbytes, int error)
{
	struct request_queue *q = rq->q;
	/* 非屏障IO */
	if (&q->bar_rq != rq) {
		if (error)
			clear_bit(BIO_UPTODATE, &bio->bi_flags);
		else if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
			error = -EIO;

		if (unlikely(nbytes > bio->bi_size)) {
			printk(KERN_ERR "%s: want %u bytes done, %u left\n",
			       __func__, nbytes, bio->bi_size);
			nbytes = bio->bi_size;
		}

		if (unlikely(rq->cmd_flags & REQ_QUIET))
			set_bit(BIO_QUIET, &bio->bi_flags);

		bio->bi_size -= nbytes;
		bio->bi_sector += (nbytes >> 9);

		if (bio_integrity(bio))
			bio_integrity_advance(bio, nbytes);
		/* 调用bio层通知FS层 */
		if (bio->bi_size == 0)
			bio_endio(bio, error);
	} else {

		/*
		 * Okay, this is the barrier request in progress, just
		 * record the error;
		 */
		if (error && !q->orderr)
			q->orderr = error;
	}
}

void blk_dump_rq_flags(struct request *rq, char *msg)
{
	int bit;

	printk(KERN_INFO "%s: dev %s: type=%x, flags=%x\n", msg,
		rq->rq_disk ? rq->rq_disk->disk_name : "?", rq->cmd_type,
		rq->cmd_flags);

	printk(KERN_INFO "  sector %llu, nr/cnr %u/%u\n",
	       (unsigned long long)blk_rq_pos(rq),
	       blk_rq_sectors(rq), blk_rq_cur_sectors(rq));
	printk(KERN_INFO "  bio %p, biotail %p, buffer %p, len %u\n",
	       rq->bio, rq->biotail, rq->buffer, blk_rq_bytes(rq));

	if (rq->cmd_type == REQ_TYPE_BLOCK_PC) {
		printk(KERN_INFO "  cdb: ");
		for (bit = 0; bit < BLK_MAX_CDB; bit++)
			printk("%02x ", rq->cmd[bit]);
		printk("\n");
	}
}
EXPORT_SYMBOL(blk_dump_rq_flags);

/*
 * "plug" the device if there are no outstanding requests: this will
 * force the transfer to start only after we have put all the requests
 * on the list.
 *
 * This is called with interrupts off and no requests on the queue and
 * with the queue lock held.
 */
/**ltl
 * 功能:设备"畜流"
 * 参数:
 * 返回值:
 * 说明:1.设备"畜流"标志；2.开启"泄流"定时器
 */
void blk_plug_device(struct request_queue *q)
{
	WARN_ON(!irqs_disabled()); /* 禁用中断处理 */

	/*
	 * don't plug a stopped queue, it must be paired with blk_start_queue()
	 * which will restart the queueing
	 */
	if (blk_queue_stopped(q))
		return;
	/* 如果没有设置QUEUE_FLAG_PLUGGED标志，则设置后，返回0 */
	if (!queue_flag_test_and_set(QUEUE_FLAG_PLUGGED, q)) {
		mod_timer(&q->unplug_timer, jiffies + q->unplug_delay); /* 开启"泄流"定时器 */
		trace_block_plug(q);
	}
}
EXPORT_SYMBOL(blk_plug_device);

/**
 * blk_plug_device_unlocked - plug a device without queue lock held
 * @q:    The &struct request_queue to plug
 *
 * Description:
 *   Like @blk_plug_device(), but grabs the queue lock and disables
 *   interrupts.
 **/
void blk_plug_device_unlocked(struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	blk_plug_device(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
EXPORT_SYMBOL(blk_plug_device_unlocked);

/*
 * remove the queue from the plugged list, if present. called with
 * queue lock held and interrupts disabled.
 */
/**ltl
 * 功能:删除"畜流"
 * 参数:
 * 返回值:
 * 说明:1.删除"畜流"标志；2.删除定时器
 */
int blk_remove_plug(struct request_queue *q)
{
	WARN_ON(!irqs_disabled());

	if (!queue_flag_test_and_clear(QUEUE_FLAG_PLUGGED, q))
		return 0;

	del_timer(&q->unplug_timer);
	return 1;
}
EXPORT_SYMBOL(blk_remove_plug);

/*
 * remove the plug and let it rip..
 */
/**ltl
 * 功能:"泄流"处理函数 
 * 参数:
 * 返回值:
 * 说明:
 */
void __generic_unplug_device(struct request_queue *q)
{
	/* 请求队列是否已经停止 */
	if (unlikely(blk_queue_stopped(q)))
		return;
	/* 请求队列是否已经移除并且设备不是SSD设备(非旋转式设备)
	 * Q:若设备是SSD设备，是怎么请求数据?????
	 */
	if (!blk_remove_plug(q) && !blk_queue_nonrot(q))
		return;
	/* 调用策略处理函数 */
	q->request_fn(q);
}

/**
 * generic_unplug_device - fire a request queue
 * @q:    The &struct request_queue in question
 *
 * Description:
 *   Linux uses plugging to build bigger requests queues before letting
 *   the device have at them. If a queue is plugged, the I/O scheduler
 *   is still adding and merging requests on the queue. Once the queue
 *   gets unplugged, the request_fn defined for the queue is invoked and
 *   transfers started.
 **/
/**ltl
功能:"泄流"处理函数
参数:
说明:
*/
void generic_unplug_device(struct request_queue *q)
{
	if (blk_queue_plugged(q)) {/* 如果"畜流"标志已经设置 */
		spin_lock_irq(q->queue_lock);/* 请求队列加锁 */
		__generic_unplug_device(q); /* 开始"泄流" */
		spin_unlock_irq(q->queue_lock); /* 释放锁 */
	}
}
EXPORT_SYMBOL(generic_unplug_device);

/**ltl
功能:块设备的后备设备信息中的"泄流"处理函数。
参数:
说明:一般用于刷新块设备中的buffer数据用到。MD设备会调用到。
*/
static void blk_backing_dev_unplug(struct backing_dev_info *bdi,
				   struct page *page)
{
	struct request_queue *q = bdi->unplug_io_data;

	blk_unplug(q);
}
/**ltl
功能:"泄流"工作队列处理函数
参数:
说明:"泄流"工作队列由"泄流"定时器blk_unplug_timeout调用。而"泄流"定时器由"蓄流"接口blk_plug_device安装。
*/
void blk_unplug_work(struct work_struct *work)
{
	struct request_queue *q =
		container_of(work, struct request_queue, unplug_work);

	trace_block_unplug_io(q);
	q->unplug_fn(q);
}
/* "泄流"定显示器 */
void blk_unplug_timeout(unsigned long data)
{
	struct request_queue *q = (struct request_queue *)data;

	trace_block_unplug_timer(q);
	kblockd_schedule_work(q, &q->unplug_work); /* 工作队列开始工作 */
}
/**ltl
功能:块设备"泄流"函数
参数:
说明:块设备层向外提供的接口，用于块设备"泄流"
*/
void blk_unplug(struct request_queue *q)
{
	/*
	 * devices don't necessarily have an ->unplug_fn defined
	 */
	if (q->unplug_fn) {
		trace_block_unplug_io(q);
		q->unplug_fn(q);
	}
}
EXPORT_SYMBOL(blk_unplug);

/**
 * blk_start_queue - restart a previously stopped queue
 * @q:    The &struct request_queue in question
 *
 * Description:
 *   blk_start_queue() will clear the stop flag on the queue, and call
 *   the request_fn for the queue if it was in a stopped state when
 *   entered. Also see blk_stop_queue(). Queue lock must be held.
 **/
void blk_start_queue(struct request_queue *q)
{
	WARN_ON(!irqs_disabled());

	queue_flag_clear(QUEUE_FLAG_STOPPED, q);
	__blk_run_queue(q);
}
EXPORT_SYMBOL(blk_start_queue);

/**
 * blk_stop_queue - stop a queue
 * @q:    The &struct request_queue in question
 *
 * Description:
 *   The Linux block layer assumes that a block driver will consume all
 *   entries on the request queue when the request_fn strategy is called.
 *   Often this will not happen, because of hardware limitations (queue
 *   depth settings). If a device driver gets a 'queue full' response,
 *   or if it simply chooses not to queue more I/O at one point, it can
 *   call this function to prevent the request_fn from being called until
 *   the driver has signalled it's ready to go again. This happens by calling
 *   blk_start_queue() to restart queue operations. Queue lock must be held.
 **/
void blk_stop_queue(struct request_queue *q)
{
	blk_remove_plug(q);
	queue_flag_set(QUEUE_FLAG_STOPPED, q);
}
EXPORT_SYMBOL(blk_stop_queue);

/**
 * blk_sync_queue - cancel any pending callbacks on a queue
 * @q: the queue
 *
 * Description:
 *     The block layer may perform asynchronous callback activity
 *     on a queue, such as calling the unplug function after a timeout.
 *     A block device may call blk_sync_queue to ensure that any
 *     such activity is cancelled, thus allowing it to release resources
 *     that the callbacks might use. The caller must already have made sure
 *     that its ->make_request_fn will not re-add plugging prior to calling
 *     this function.
 *
 */
void blk_sync_queue(struct request_queue *q)
{
	del_timer_sync(&q->unplug_timer);
	del_timer_sync(&q->timeout);
	cancel_work_sync(&q->unplug_work);
}
EXPORT_SYMBOL(blk_sync_queue);

/**
 * __blk_run_queue - run a single device queue
 * @q:	The queue to run
 *
 * Description:
 *    See @blk_run_queue. This variant must be called with the queue lock
 *    held and interrupts disabled.
 *
 */
/**ltl
 *功能:运行请求队列
 *参数:
 *返回值:
 *说明:
 */
void __blk_run_queue(struct request_queue *q)
{
	blk_remove_plug(q); /* 结束"泄流"定时器 */
	/* 请求队列已经停止 */
	if (unlikely(blk_queue_stopped(q)))
		return;
	/* 判定派发队列是否有请求 */
	if (elv_queue_empty(q))
		return;

	/*
	 * Only recurse once to avoid overrunning the stack, let the unplug
	 * handling reinvoke the handler shortly if we already got there.
	 */
	if (!queue_flag_test_and_set(QUEUE_FLAG_REENTER, q)) { /*判定并设置重入标志*/
		q->request_fn(q); /* 调用策略处理函数 */
		queue_flag_clear(QUEUE_FLAG_REENTER, q); /* 清除重入标志 */
	} else {
		/* 设置已经"畜流"标志,由于这里设置此标志，会致使scsi_request_fn在没有把派发队列的请求执行完成时，不会将新的请求提交给底层 */
		queue_flag_set(QUEUE_FLAG_PLUGGED, q); 
		kblockd_schedule_work(q, &q->unplug_work); /* 调度"泄流"工作队列 */
	}
}
EXPORT_SYMBOL(__blk_run_queue);

/**
 * blk_run_queue - run a single device queue
 * @q: The queue to run
 *
 * Description:
 *    Invoke request handling on this queue, if it has pending work to do.
 *    May be used to restart queueing when a request has completed.
 */
void blk_run_queue(struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	__blk_run_queue(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
EXPORT_SYMBOL(blk_run_queue);

void blk_put_queue(struct request_queue *q)
{
	kobject_put(&q->kobj);
}

void blk_cleanup_queue(struct request_queue *q)
{
	/*
	 * We know we have process context here, so we can be a little
	 * cautious and ensure that pending block actions on this device
	 * are done before moving on. Going into this function, we should
	 * not have processes doing IO to this device.
	 */
	blk_sync_queue(q);

	del_timer_sync(&q->backing_dev_info.laptop_mode_wb_timer);
	mutex_lock(&q->sysfs_lock);
	queue_flag_set_unlocked(QUEUE_FLAG_DEAD, q);
	mutex_unlock(&q->sysfs_lock);

	if (q->elevator)
		elevator_exit(q->elevator);

	blk_put_queue(q);
}
EXPORT_SYMBOL(blk_cleanup_queue);

static int blk_init_free_list(struct request_queue *q)
{
	struct request_list *rl = &q->rq;

	if (unlikely(rl->rq_pool))
		return 0;

	rl->count[BLK_RW_SYNC] = rl->count[BLK_RW_ASYNC] = 0;
	rl->starved[BLK_RW_SYNC] = rl->starved[BLK_RW_ASYNC] = 0;
	rl->elvpriv = 0;
	init_waitqueue_head(&rl->wait[BLK_RW_SYNC]);
	init_waitqueue_head(&rl->wait[BLK_RW_ASYNC]);

	rl->rq_pool = mempool_create_node(BLKDEV_MIN_RQ, mempool_alloc_slab,
				mempool_free_slab, request_cachep, q->node);

	if (!rl->rq_pool)
		return -ENOMEM;

	return 0;
}
/**ltl
 *功能:分配请求队列的方法二
 *参数:gfp_mask	->
 *返回值:请求队列对象
 *说明:调用此函数分配的请求队列中的make_request_fn还没有值，使用者必须调用blk_queue_make_request函数设置
 */
struct request_queue *blk_alloc_queue(gfp_t gfp_mask)
{
	return blk_alloc_queue_node(gfp_mask, -1);
}
EXPORT_SYMBOL(blk_alloc_queue);

struct request_queue *blk_alloc_queue_node(gfp_t gfp_mask, int node_id)
{
	struct request_queue *q;
	int err;
	/* 分配请求队列对象 */
	q = kmem_cache_alloc_node(blk_requestq_cachep,
				gfp_mask | __GFP_ZERO, node_id);
	if (!q)
		return NULL;
	/* 设置设备备用信息，1.备用信息的"泄流"处理函数和，私有数据(请求队列对象) */
	q->backing_dev_info.unplug_io_fn = blk_backing_dev_unplug;
	q->backing_dev_info.unplug_io_data = q;
	q->backing_dev_info.ra_pages = (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE;
	q->backing_dev_info.state = 0;
	q->backing_dev_info.capabilities = BDI_CAP_MAP_COPY;
	q->backing_dev_info.name = "block";

	err = bdi_init(&q->backing_dev_info);
	if (err) {
		kmem_cache_free(blk_requestq_cachep, q);
		return NULL;
	}

	setup_timer(&q->backing_dev_info.laptop_mode_wb_timer, laptop_mode_timer_fn, (unsigned long) q);
	init_timer(&q->unplug_timer);
	/* 请求超时定时器
	 * 当一个request请求从派发队列取出分发到底层驱动(SCSI子系统)时，都会把此请求插入到超时列表timeout_list中(见blk_add_timer)
	 */
	setup_timer(&q->timeout, blk_rq_timed_out_timer, (unsigned long) q);
	INIT_LIST_HEAD(&q->timeout_list);
	INIT_WORK(&q->unplug_work, blk_unplug_work);/* "泄流"工作队列的初始化 */

	kobject_init(&q->kobj, &blk_queue_ktype);

	mutex_init(&q->sysfs_lock);
	spin_lock_init(&q->__queue_lock);

	return q;
}
EXPORT_SYMBOL(blk_alloc_queue_node);

/**
 * blk_init_queue  - prepare a request queue for use with a block device
 * @rfn:  The function to be called to process requests that have been
 *        placed on the queue.
 * @lock: Request queue spin lock
 *
 * Description:
 *    If a block device wishes to use the standard request handling procedures,
 *    which sorts requests and coalesces adjacent requests, then it must
 *    call blk_init_queue().  The function @rfn will be called when there
 *    are requests on the queue that need to be processed.  If the device
 *    supports plugging, then @rfn may not be called immediately when requests
 *    are available on the queue, but may be called at some time later instead.
 *    Plugged queues are generally unplugged when a buffer belonging to one
 *    of the requests on the queue is needed, or due to memory pressure.
 *
 *    @rfn is not required, or even expected, to remove all requests off the
 *    queue, but only as many as it can handle at a time.  If it does leave
 *    requests on the queue, it is responsible for arranging that the requests
 *    get dealt with eventually.
 *
 *    The queue spin lock must be held while manipulating the requests on the
 *    request queue; this lock will be taken also from interrupt context, so irq
 *    disabling is needed for it.
 *
 *    Function returns a pointer to the initialized request queue, or %NULL if
 *    it didn't succeed.
 *
 * Note:
 *    blk_init_queue() must be paired with a blk_cleanup_queue() call
 *    when the block device is deactivated (such as at module unload).
 **/
/**ltl
 *功能:分配请求队列的方法一
 *参数:rfn	->块设备驱动程序的策略处理例程
 *  	  lock	->
 *返回值:请求队列
 *说明:使用这种访求分配到的请求队列的make_request_fn的具体实现为__make_request();
 */
struct request_queue *blk_init_queue(request_fn_proc *rfn, spinlock_t *lock)
{
	return blk_init_queue_node(rfn, lock, -1);
}
EXPORT_SYMBOL(blk_init_queue);

struct request_queue *
blk_init_queue_node(request_fn_proc *rfn, spinlock_t *lock, int node_id)
{
	struct request_queue *uninit_q, *q;
	/* 分配请求队列 */
	uninit_q = blk_alloc_queue_node(GFP_KERNEL, node_id);
	if (!uninit_q)
		return NULL;
	/* 为请求队列设置"泄流"接口和make_request_fn */
	q = blk_init_allocated_queue_node(uninit_q, rfn, lock, node_id);
	if (!q)
		blk_cleanup_queue(uninit_q);

	return q;
}
EXPORT_SYMBOL(blk_init_queue_node);

struct request_queue *
blk_init_allocated_queue(struct request_queue *q, request_fn_proc *rfn,
			 spinlock_t *lock)
{
	return blk_init_allocated_queue_node(q, rfn, lock, -1);
}
EXPORT_SYMBOL(blk_init_allocated_queue);

/**ltl
 *功能:为已经分配好内存空间的请求队列对象初始化
 *参数:q	->请求队列对象
 *	rfn  ->策略处理例程
 *	lock	->
 *	node_id->
 *返回值:
 *说明:
 */
struct request_queue *blk_init_allocated_queue_node(struct request_queue *q, request_fn_proc *rfn,
			      spinlock_t *lock, int node_id)
{
	if (!q)
		return NULL;

	q->node = node_id;
	/* 初始化request_list对象 */
	if (blk_init_free_list(q))
		return NULL;
	/* 策略处理函数 */
	q->request_fn		= rfn;
	q->prep_rq_fn		= NULL;
	q->unprep_rq_fn		= NULL;
	/* "泄流"处理函数 */
	q->unplug_fn		= generic_unplug_device;
	q->queue_flags		= QUEUE_FLAG_DEFAULT;
	q->queue_lock		= lock;

	/*
	 * This also sets hw/phys segments, boundary and size
	 */
	blk_queue_make_request(q, __make_request);/*设置make_request_fn*/

	q->sg_reserved_size = INT_MAX;

	/*
	 * all done
	 */
	if (!elevator_init(q, NULL)) {/* 绑定调度算法 */
		blk_queue_congestion_threshold(q);
		return q;
	}

	return NULL;
}
EXPORT_SYMBOL(blk_init_allocated_queue_node);

int blk_get_queue(struct request_queue *q)
{
	if (likely(!test_bit(QUEUE_FLAG_DEAD, &q->queue_flags))) {
		kobject_get(&q->kobj);
		return 0;
	}

	return 1;
}
/**ltl
 * 功能:释放与request相的内存空间
 * 参数:
 * 返回值:
 * 说明:
 */
static inline void blk_free_request(struct request_queue *q, struct request *rq)
{
	if (rq->cmd_flags & REQ_ELVPRIV)
		elv_put_request(q, rq); /* 释放设调算法相关的内存空间 */
	mempool_free(rq, q->rq.rq_pool); /* 释放request内存空间 */
}
/**ltl
 *功能:分配request对象
 *参数:q		->请求队列对象
 	  flags	->
 	  priv	->此请求是否有私有数据(与调度算法相关)
 	  gfp_mask->分配标志
 *返回值:
 *说明:
 */
static struct request *
blk_alloc_request(struct request_queue *q, int flags, int priv, gfp_t gfp_mask)
{
	/* 从缓冲区中分配request对象 */
	struct request *rq = mempool_alloc(q->rq.rq_pool, gfp_mask);

	if (!rq)
		return NULL;
	/* 初始化request对象 */
	blk_rq_init(q, rq);
	/* 设置已经分配标志 */
	rq->cmd_flags = flags | REQ_ALLOCED;
	/* 是否有私有数据 */
	if (priv) {
		/* 如果是使用CFQ调度算法，则要设置算法相关的数据成员，如elevator_private、elevator_private2、elevator_private3 */
		if (unlikely(elv_set_request(q, rq, gfp_mask))) {
			mempool_free(rq, q->rq.rq_pool);
			return NULL;
		}
		/* 表示有与调度算法相关的私有数据，则设置REQ_ELVPRIV标志 */
		rq->cmd_flags |= REQ_ELVPRIV;
	}

	return rq;
}

/*
 * ioc_batching returns true if the ioc is a valid batching request and
 * should be given priority access to a request.
 */
static inline int ioc_batching(struct request_queue *q, struct io_context *ioc)
{
	if (!ioc)
		return 0;

	/*
	 * Make sure the process is able to allocate at least 1 request
	 * even if the batch times out, otherwise we could theoretically
	 * lose wakeups.
	 */
	return ioc->nr_batch_requests == q->nr_batching ||
		(ioc->nr_batch_requests > 0
		&& time_before(jiffies, ioc->last_waited + BLK_BATCH_TIME));
}

/*
 * ioc_set_batching sets ioc to be a new "batcher" if it is not one. This
 * will cause the process to be a "batcher" on all queues in the system. This
 * is the behaviour we want though - once it gets a wakeup it should be given
 * a nice run.
 */
static void ioc_set_batching(struct request_queue *q, struct io_context *ioc)
{
	if (!ioc || ioc_batching(q, ioc))
		return;

	ioc->nr_batch_requests = q->nr_batching;
	ioc->last_waited = jiffies;
}

static void __freed_request(struct request_queue *q, int sync)
{
	struct request_list *rl = &q->rq;

	if (rl->count[sync] < queue_congestion_off_threshold(q))
		blk_clear_queue_congested(q, sync);

	if (rl->count[sync] + 1 <= q->nr_requests) {
		if (waitqueue_active(&rl->wait[sync]))
			wake_up(&rl->wait[sync]);

		blk_clear_queue_full(q, sync);
	}
}

/*
 * A request has just been released.  Account for it, update the full and
 * congestion status, wake up any waiters.   Called under q->queue_lock.
 */
static void freed_request(struct request_queue *q, int sync, int priv)
{
	struct request_list *rl = &q->rq;

	rl->count[sync]--;
	if (priv)
		rl->elvpriv--;

	__freed_request(q, sync);

	if (unlikely(rl->starved[sync ^ 1]))
		__freed_request(q, sync ^ 1);
}

/*
 * Get a free request, queue_lock must be held.
 * Returns NULL on failure, with queue_lock held.
 * Returns !NULL on success, with queue_lock *not held*.
 */
/**ltl
 *功能:分配request对象
 *参数:
 *返回值:
 *说明:
 */
static struct request *get_request(struct request_queue *q, int rw_flags,
				   struct bio *bio, gfp_t gfp_mask)
{
	struct request *rq = NULL;
	struct request_list *rl = &q->rq;
	struct io_context *ioc = NULL;
	const bool is_sync = rw_is_sync(rw_flags) != 0;
	int may_queue, priv;
	/* 判定请求队列是否可以执行请求。(判定与调度队列相关的数据结构是否已经建立) */
	may_queue = elv_may_queue(q, rw_flags);
	if (may_queue == ELV_MQUEUE_NO)
		goto rq_starved;

	if (rl->count[is_sync]+1 >= queue_congestion_on_threshold(q)) {
		if (rl->count[is_sync]+1 >= q->nr_requests) {
			ioc = current_io_context(GFP_ATOMIC, q->node);
			/*
			 * The queue will fill after this allocation, so set
			 * it as full, and mark this process as "batching".
			 * This process will be allowed to complete a batch of
			 * requests, others will be blocked.
			 */
			if (!blk_queue_full(q, is_sync)) {
				ioc_set_batching(q, ioc);
				blk_set_queue_full(q, is_sync);
			} else {
				if (may_queue != ELV_MQUEUE_MUST
						&& !ioc_batching(q, ioc)) {
					/*
					 * The queue is full and the allocating
					 * process is not a "batcher", and not
					 * exempted by the IO scheduler
					 */
					goto out;
				}
			}
		}
		blk_set_queue_congested(q, is_sync);
	}

	/*
	 * Only allow batching queuers to allocate up to 50% over the defined
	 * limit of requests, otherwise we could have thousands of requests
	 * allocated with any setting of ->nr_requests
	 */
	if (rl->count[is_sync] >= (3 * q->nr_requests / 2))
		goto out;

	rl->count[is_sync]++;
	rl->starved[is_sync] = 0;

	priv = !test_bit(QUEUE_FLAG_ELVSWITCH, &q->queue_flags);
	if (priv)
		rl->elvpriv++;

	if (blk_queue_io_stat(q))
		rw_flags |= REQ_IO_STAT;
	spin_unlock_irq(q->queue_lock);

	rq = blk_alloc_request(q, rw_flags, priv, gfp_mask);
	if (unlikely(!rq)) {
		/*
		 * Allocation failed presumably due to memory. Undo anything
		 * we might have messed up.
		 *
		 * Allocating task should really be put onto the front of the
		 * wait queue, but this is pretty rare.
		 */
		spin_lock_irq(q->queue_lock);
		freed_request(q, is_sync, priv);

		/*
		 * in the very unlikely event that allocation failed and no
		 * requests for this direction was pending, mark us starved
		 * so that freeing of a request in the other direction will
		 * notice us. another possible fix would be to split the
		 * rq mempool into READ and WRITE
		 */
rq_starved:
		if (unlikely(rl->count[is_sync] == 0))
			rl->starved[is_sync] = 1;

		goto out;
	}

	/*
	 * ioc may be NULL here, and ioc_batching will be false. That's
	 * OK, if the queue is under the request limit then requests need
	 * not count toward the nr_batch_requests limit. There will always
	 * be some limit enforced by BLK_BATCH_TIME.
	 */
	if (ioc_batching(q, ioc))
		ioc->nr_batch_requests--;

	trace_block_getrq(q, bio, rw_flags & 1);
out:
	return rq;
}

/*
 * No available requests for this queue, unplug the device and wait for some
 * requests to become available.
 *
 * Called with q->queue_lock held, and returns with it unlocked.
 */
/**ltl
 *功能:分配新的request对象
 *参数:q			->请求队列
 	  rw_flags	->读写标志
 	  bio		->bio对象
 *返回值:
 *说明:
 */
static struct request *get_request_wait(struct request_queue *q, int rw_flags,
					struct bio *bio)
{
	const bool is_sync = rw_is_sync(rw_flags) != 0;
	struct request *rq;
	/* 分配request对象 */
	rq = get_request(q, rw_flags, bio, GFP_NOIO);
	while (!rq) {/* 分配失败时，先"泄流",等待执行完成，释放内存(执行完成后会释放)，重新分配request对象 */
		DEFINE_WAIT(wait);
		struct io_context *ioc;
		struct request_list *rl = &q->rq;

		prepare_to_wait_exclusive(&rl->wait[is_sync], &wait,
				TASK_UNINTERRUPTIBLE);

		trace_block_sleeprq(q, bio, rw_flags & 1);

		__generic_unplug_device(q); /* "泄流"派发队列 */
		spin_unlock_irq(q->queue_lock);
		io_schedule();

		/*
		 * After sleeping, we become a "batching" process and
		 * will be able to allocate at least one request, and
		 * up to a big batch of them for a small period time.
		 * See ioc_batching, ioc_set_batching
		 */
		ioc = current_io_context(GFP_NOIO, q->node);
		ioc_set_batching(q, ioc);

		spin_lock_irq(q->queue_lock);
		finish_wait(&rl->wait[is_sync], &wait);

		rq = get_request(q, rw_flags, bio, GFP_NOIO);
	};

	return rq;
}

struct request *blk_get_request(struct request_queue *q, int rw, gfp_t gfp_mask)
{
	struct request *rq;

	BUG_ON(rw != READ && rw != WRITE);

	spin_lock_irq(q->queue_lock);
	if (gfp_mask & __GFP_WAIT) {
		rq = get_request_wait(q, rw, NULL);
	} else {
		rq = get_request(q, rw, NULL, gfp_mask);
		if (!rq)
			spin_unlock_irq(q->queue_lock);
	}
	/* q->queue_lock is unlocked at this point */

	return rq;
}
EXPORT_SYMBOL(blk_get_request);

/**
 * blk_make_request - given a bio, allocate a corresponding struct request.
 * @q: target request queue
 * @bio:  The bio describing the memory mappings that will be submitted for IO.
 *        It may be a chained-bio properly constructed by block/bio layer.
 * @gfp_mask: gfp flags to be used for memory allocation
 *
 * blk_make_request is the parallel of generic_make_request for BLOCK_PC
 * type commands. Where the struct request needs to be farther initialized by
 * the caller. It is passed a &struct bio, which describes the memory info of
 * the I/O transfer.
 *
 * The caller of blk_make_request must make sure that bi_io_vec
 * are set to describe the memory buffers. That bio_data_dir() will return
 * the needed direction of the request. (And all bio's in the passed bio-chain
 * are properly set accordingly)
 *
 * If called under none-sleepable conditions, mapped bio buffers must not
 * need bouncing, by calling the appropriate masked or flagged allocator,
 * suitable for the target device. Otherwise the call to blk_queue_bounce will
 * BUG.
 *
 * WARNING: When allocating/cloning a bio-chain, careful consideration should be
 * given to how you allocate bios. In particular, you cannot use __GFP_WAIT for
 * anything but the first bio in the chain. Otherwise you risk waiting for IO
 * completion of a bio that hasn't been submitted yet, thus resulting in a
 * deadlock. Alternatively bios should be allocated using bio_kmalloc() instead
 * of bio_alloc(), as that avoids the mempool deadlock.
 * If possible a big IO should be split into smaller parts when allocation
 * fails. Partial allocation should not be an error, or you risk a live-lock.
 */
struct request *blk_make_request(struct request_queue *q, struct bio *bio,
				 gfp_t gfp_mask)
{
	struct request *rq = blk_get_request(q, bio_data_dir(bio), gfp_mask);

	if (unlikely(!rq))
		return ERR_PTR(-ENOMEM);

	for_each_bio(bio) {
		struct bio *bounce_bio = bio;
		int ret;

		blk_queue_bounce(q, &bounce_bio);
		ret = blk_rq_append_bio(q, rq, bounce_bio);
		if (unlikely(ret)) {
			blk_put_request(rq);
			return ERR_PTR(ret);
		}
	}

	return rq;
}
EXPORT_SYMBOL(blk_make_request);

/**
 * blk_requeue_request - put a request back on queue
 * @q:		request queue where request should be inserted
 * @rq:		request to be inserted
 *
 * Description:
 *    Drivers often keep queueing requests until the hardware cannot accept
 *    more, when that condition happens we need to put the request back
 *    on the queue. Must be called with queue lock held.
 */
/**ltl
 * 功能:将请求对象重新插入到派发队列中
 * 参数:
 * 返回值:
 * 说明:
 */
void blk_requeue_request(struct request_queue *q, struct request *rq)
{
	blk_delete_timer(rq);
	blk_clear_rq_complete(rq);
	trace_block_rq_requeue(q, rq);

	if (blk_rq_tagged(rq))
		blk_queue_end_tag(q, rq);

	BUG_ON(blk_queued_rq(rq));

	elv_requeue_request(q, rq);
}
EXPORT_SYMBOL(blk_requeue_request);

/**
 * blk_insert_request - insert a special request into a request queue
 * @q:		request queue where request should be inserted
 * @rq:		request to be inserted
 * @at_head:	insert request at head or tail of queue
 * @data:	private data
 *
 * Description:
 *    Many block devices need to execute commands asynchronously, so they don't
 *    block the whole kernel from preemption during request execution.  This is
 *    accomplished normally by inserting aritficial requests tagged as
 *    REQ_TYPE_SPECIAL in to the corresponding request queue, and letting them
 *    be scheduled for actual execution by the request queue.
 *
 *    We have the option of inserting the head or the tail of the queue.
 *    Typically we use the tail for new ioctls and so forth.  We use the head
 *    of the queue for things like a QUEUE_FULL message from a device, or a
 *    host that is unable to accept a particular command.
 */
void blk_insert_request(struct request_queue *q, struct request *rq,
			int at_head, void *data)
{
	int where = at_head ? ELEVATOR_INSERT_FRONT : ELEVATOR_INSERT_BACK;
	unsigned long flags;

	/*
	 * tell I/O scheduler that this isn't a regular read/write (ie it
	 * must not attempt merges on this) and that it acts as a soft
	 * barrier
	 */
	rq->cmd_type = REQ_TYPE_SPECIAL;

	rq->special = data;

	spin_lock_irqsave(q->queue_lock, flags);

	/*
	 * If command is tagged, release the tag
	 */
	if (blk_rq_tagged(rq))
		blk_queue_end_tag(q, rq);

	drive_stat_acct(rq, 1);
	__elv_add_request(q, rq, where, 0);
	__blk_run_queue(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
EXPORT_SYMBOL(blk_insert_request);

/*
 * add-request adds a request to the linked list.
 * queue lock is held and interrupts disabled, as we muck with the
 * request queue list.
 */
/**ltl
 *功能:把request请求插入到调度队列
 *参数:q		->请求队列对象
 	  req	->新分配的请求对象
 *返回值:
 *说明:
 */
static inline void add_request(struct request_queue *q, struct request *req)
{
	drive_stat_acct(req, 1);

	/*
	 * elevator indicated where it wants this request to be
	 * inserted at elevator_merge time
	 */
	__elv_add_request(q, req, ELEVATOR_INSERT_SORT, 0); /* 以排序方式插入到调度队列 */
}

static void part_round_stats_single(int cpu, struct hd_struct *part,
				    unsigned long now)
{
	if (now == part->stamp)
		return;

	if (part_in_flight(part)) {
		__part_stat_add(cpu, part, time_in_queue,
				part_in_flight(part) * (now - part->stamp));
		__part_stat_add(cpu, part, io_ticks, (now - part->stamp));
	}
	part->stamp = now;
}

/**
 * part_round_stats() - Round off the performance stats on a struct disk_stats.
 * @cpu: cpu number for stats access
 * @part: target partition
 *
 * The average IO queue length and utilisation statistics are maintained
 * by observing the current state of the queue length and the amount of
 * time it has been in this state for.
 *
 * Normally, that accounting is done on IO completion, but that can result
 * in more than a second's worth of IO being accounted for within any one
 * second, leading to >100% utilisation.  To deal with that, we call this
 * function to do a round-off before returning the results when reading
 * /proc/diskstats.  This accounts immediately for all queue usage up to
 * the current jiffies and restarts the counters again.
 */
void part_round_stats(int cpu, struct hd_struct *part)
{
	unsigned long now = jiffies;

	if (part->partno)
		part_round_stats_single(cpu, &part_to_disk(part)->part0, now);
	part_round_stats_single(cpu, part, now);
}
EXPORT_SYMBOL_GPL(part_round_stats);

/*
 * queue lock must be held
 */
/**ltl
 * 功能:释放request请求的回调函数
 * 参数:
 * 返回值:
 * 说明:
 */
void __blk_put_request(struct request_queue *q, struct request *req)
{
	if (unlikely(!q))
		return;
	if (unlikely(--req->ref_count))
		return;
	/* 释放与调度算法相关的私有数据 */
	elv_completed_request(q, req);

	/* this is a bio leak */
	WARN_ON(req->bio != NULL);

	/*
	 * Request may not have originated from ll_rw_blk. if not,
	 * it didn't come out of our reserved rq pools
	 */
	if (req->cmd_flags & REQ_ALLOCED) {
		int is_sync = rq_is_sync(req) != 0;
		int priv = req->cmd_flags & REQ_ELVPRIV;

		BUG_ON(!list_empty(&req->queuelist));
		BUG_ON(!hlist_unhashed(&req->hash));

		blk_free_request(q, req);
		freed_request(q, is_sync, priv);
	}
}
EXPORT_SYMBOL_GPL(__blk_put_request);

void blk_put_request(struct request *req)
{
	unsigned long flags;
	struct request_queue *q = req->q;

	spin_lock_irqsave(q->queue_lock, flags);
	__blk_put_request(q, req);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
EXPORT_SYMBOL(blk_put_request);

/**
 * blk_add_request_payload - add a payload to a request
 * @rq: request to update
 * @page: page backing the payload
 * @len: length of the payload.
 *
 * This allows to later add a payload to an already submitted request by
 * a block driver.  The driver needs to take care of freeing the payload
 * itself.
 *
 * Note that this is a quite horrible hack and nothing but handling of
 * discard requests should ever use it.
 */
void blk_add_request_payload(struct request *rq, struct page *page,
		unsigned int len)
{
	struct bio *bio = rq->bio;

	bio->bi_io_vec->bv_page = page;
	bio->bi_io_vec->bv_offset = 0;
	bio->bi_io_vec->bv_len = len;

	bio->bi_size = len;
	bio->bi_vcnt = 1;
	bio->bi_phys_segments = 1;

	rq->__data_len = rq->resid_len = len;
	rq->nr_phys_segments = 1;
	rq->buffer = bio_data(bio);
}
EXPORT_SYMBOL_GPL(blk_add_request_payload);
/**ltl
 * 功能:用bio请求去初始化request对象
 * 参数:
 * 返回值:
 * 说明:
 */
void init_request_from_bio(struct request *req, struct bio *bio)
{
	req->cpu = bio->bi_comp_cpu;
	req->cmd_type = REQ_TYPE_FS; /* 来自应用层的请求 */

	req->cmd_flags |= bio->bi_rw & REQ_COMMON_MASK;
	if (bio->bi_rw & REQ_RAHEAD)
		req->cmd_flags |= REQ_FAILFAST_MASK;

	req->errors = 0;
	req->__sector = bio->bi_sector; /* 请求的起始扇区 */
	req->ioprio = bio_prio(bio);	/* IO优先级 */
	blk_rq_bio_prep(req->q, req, bio); /* 把bio插入到request对象中的bio列表中 */ 
}

/*
 * Only disabling plugging for non-rotational devices if it does tagging
 * as well, otherwise we do need the proper merging
 */
static inline bool queue_should_plug(struct request_queue *q)
{	
	/* 不是非旋转磁盘(SSD)并且设置了排队标志 */
	return !(blk_queue_nonrot(q) && blk_queue_tagged(q));
}
/**ltl
 *功能:request构造函数
 *参数:q	->请求队列
 *	  bio->bio请求
 *返回值:
 *说明:对于bio请求要经过调度算法的才调用
 */
static int __make_request(struct request_queue *q, struct bio *bio)
{
	struct request *req;
	int el_ret;
	unsigned int bytes = bio->bi_size;	/*请求大小*/
	const unsigned short prio = bio_prio(bio);/* 请求的优先级 */
	const bool sync = !!(bio->bi_rw & REQ_SYNC); /* 同步标志 */
	const bool unplug = !!(bio->bi_rw & REQ_UNPLUG); /* "泄流"标志 */
	const unsigned long ff = bio->bi_rw & REQ_FAILFAST_MASK; /*  */
	int rw_flags;
	
	if ((bio->bi_rw & REQ_HARDBARRIER) &&
	    (q->next_ordered == QUEUE_ORDERED_NONE)) {
		bio_endio(bio, -EOPNOTSUPP);
		return 0;
	}
	/*
	 * low level driver can indicate that it wants pages above a
	 * certain limit bounced to low memory (ie for highmem, or even
	 * ISA dma in theory)
	 */
	blk_queue_bounce(q, &bio);/* 反弹缓冲区的申请 */

	spin_lock_irq(q->queue_lock);
	/* bio请求设备了硬屏障标志，或者请求队列为空，则把请求插入到派发队列中 */
	if (unlikely((bio->bi_rw & REQ_HARDBARRIER)) || elv_queue_empty(q))
		goto get_rq;
	/* 获取合并的request及其位置 */
	el_ret = elv_merge(q, &req, bio);
	switch (el_ret) {
	case ELEVATOR_BACK_MERGE: /* 在req对象后面的合入bio */
		BUG_ON(!rq_mergeable(req));
		/* 判定是否可以在req之后合并,如果能合并，要更新req的物理段数 */
		if (!ll_back_merge_fn(q, req, bio))
			break;
		/* 记录后合并的时刻 */
		trace_block_bio_backmerge(q, bio);

		if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
			blk_rq_set_mixed_merge(req);
		/* 合并操作 */
		req->biotail->bi_next = bio;
		req->biotail = bio;
		req->__data_len += bytes; /* 数据大小 */
		req->ioprio = ioprio_best(req->ioprio, prio); /* 优先级 */
		if (!blk_rq_cpu_valid(req))
			req->cpu = bio->bi_comp_cpu;
		drive_stat_acct(req, 0);
		elv_bio_merged(q, req, bio); /* 注:此操作只有CFQ调度算法有用 */
		/*如果这次合并可能正好填补request和起始位置上后一个request之间的空洞，则进一步合并这两个request.
			  合完两个request之后，要去合并与IO调度算法相关的私有数据*/
		if (!attempt_back_merge(q, req)) /* 合并req请求和紧接其后的请求 */
			elv_merged_request(q, req, el_ret);/* 合并入的bio不能填补两个request之间的空洞，则单独更新req请求与IO调度算法中的私有数据*/
		goto out;

	case ELEVATOR_FRONT_MERGE: /* 在req对象的前面合入bio */
		BUG_ON(!rq_mergeable(req));
		/* 判定bio能否在req之前合并 */
		if (!ll_front_merge_fn(q, req, bio))
			break;
		/* 记录后合并的时刻 */
		trace_block_bio_frontmerge(q, bio);
		/*  */
		if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff) {
			blk_rq_set_mixed_merge(req);
			req->cmd_flags &= ~REQ_FAILFAST_MASK;
			req->cmd_flags |= ff;
		}
		/* 把bio合并入req的bio链表中 */
		bio->bi_next = req->bio;
		req->bio = bio;

		/*
		 * may not be valid. if the low level driver said
		 * it didn't need a bounce buffer then it better
		 * not touch req->buffer either...
		 */
		req->buffer = bio_data(bio);/* Q:作用? */
		req->__sector = bio->bi_sector; /* req请求的起始扇区 */
		req->__data_len += bytes; /* 更新req请求的数据长度 */
		req->ioprio = ioprio_best(req->ioprio, prio); /* 优先级 */
		if (!blk_rq_cpu_valid(req))
			req->cpu = bio->bi_comp_cpu;
		drive_stat_acct(req, 0);
		elv_bio_merged(q, req, bio);/* 注:此操作只有CFQ调度算法有用 */
		/*如果这次合并可能正好填补request和起始位置上后一个request之间的空洞，则进一步合并这两个request.
			  合完两个request之后，要去合并与IO调度算法相关的私有数据*/
		if (!attempt_front_merge(q, req)) 
			elv_merged_request(q, req, el_ret);/* 合并入的bio不能填补两个request之间的空洞，则单独更新IO调度算法中的私有数据*/
		goto out;

	/* ELV_NO_MERGE: elevator says don't/can't merge. */
	default:
		;
	}

get_rq:
	/*
	 * This sync check and mask will be re-done in init_request_from_bio(),
	 * but we need to set it earlier to expose the sync flag to the
	 * rq allocator and io schedulers.
	 */
	rw_flags = bio_data_dir(bio); /* 请求的方向READ/WRITE */
	if (sync)
		rw_flags |= REQ_SYNC;

	/*
	 * Grab a free request. This is might sleep but can not fail.
	 * Returns with the queue unlocked.
	 */
	req = get_request_wait(q, rw_flags, bio); /* 分配新的request对象req */

	/*
	 * After dropping the lock and possibly sleeping here, our request
	 * may now be mergeable after it had proven unmergeable (above).
	 * We don't worry about that case for efficiency. It won't happen
	 * often, and the elevators are able to handle it.
	 */
	init_request_from_bio(req, bio); /* 把bio转化成req对象 */

	spin_lock_irq(q->queue_lock);
	if (test_bit(QUEUE_FLAG_SAME_COMP, &q->queue_flags) ||
	    bio_flagged(bio, BIO_CPU_AFFINE))
		req->cpu = blk_cpu_to_group(smp_processor_id());
	/* 请求队列可以"畜流"，并且调度队列没有请求 */
	if (queue_should_plug(q) && elv_queue_empty(q))
		blk_plug_device(q); /* "畜流"---开启"泄流"定时器 */
	add_request(q, req); /* 把请求插入到调度队列 */
out:
	if (unplug || !queue_should_plug(q)) /* 不能"畜流" */
		__generic_unplug_device(q);/* 直接把请求派发到底层中 */
	spin_unlock_irq(q->queue_lock);
	return 0;
}

/*
 * If bio->bi_dev is a partition, remap the location
 */
static inline void blk_partition_remap(struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;

	if (bio_sectors(bio) && bdev != bdev->bd_contains) {
		struct hd_struct *p = bdev->bd_part;

		bio->bi_sector += p->start_sect;
		bio->bi_bdev = bdev->bd_contains;

		trace_block_remap(bdev_get_queue(bio->bi_bdev), bio,
				    bdev->bd_dev,
				    bio->bi_sector - p->start_sect);
	}
}

static void handle_bad_sector(struct bio *bio)
{
	char b[BDEVNAME_SIZE];

	printk(KERN_INFO "attempt to access beyond end of device\n");
	printk(KERN_INFO "%s: rw=%ld, want=%Lu, limit=%Lu\n",
			bdevname(bio->bi_bdev, b),
			bio->bi_rw,
			(unsigned long long)bio->bi_sector + bio_sectors(bio),
			(long long)(bio->bi_bdev->bd_inode->i_size >> 9));

	set_bit(BIO_EOF, &bio->bi_flags);
}

#ifdef CONFIG_FAIL_MAKE_REQUEST

static DECLARE_FAULT_ATTR(fail_make_request);

static int __init setup_fail_make_request(char *str)
{
	return setup_fault_attr(&fail_make_request, str);
}
__setup("fail_make_request=", setup_fail_make_request);

static int should_fail_request(struct bio *bio)
{
	struct hd_struct *part = bio->bi_bdev->bd_part;

	if (part_to_disk(part)->part0.make_it_fail || part->make_it_fail)
		return should_fail(&fail_make_request, bio->bi_size);

	return 0;
}

static int __init fail_make_request_debugfs(void)
{
	return init_fault_attr_dentries(&fail_make_request,
					"fail_make_request");
}

late_initcall(fail_make_request_debugfs);

#else /* CONFIG_FAIL_MAKE_REQUEST */

static inline int should_fail_request(struct bio *bio)
{
	return 0;
}

#endif /* CONFIG_FAIL_MAKE_REQUEST */

/*
 * Check whether this bio extends beyond the end of the device.
 */
static inline int bio_check_eod(struct bio *bio, unsigned int nr_sectors)
{
	sector_t maxsector;

	if (!nr_sectors)
		return 0;

	/* Test device or partition size, when known. */
	maxsector = bio->bi_bdev->bd_inode->i_size >> 9;
	if (maxsector) {
		sector_t sector = bio->bi_sector;

		if (maxsector < nr_sectors || maxsector - nr_sectors < sector) {
			/*
			 * This may well happen - the kernel calls bread()
			 * without checking the size of the device, e.g., when
			 * mounting a device.
			 */
			handle_bad_sector(bio);
			return 1;
		}
	}

	return 0;
}

/**
 * generic_make_request - hand a buffer to its device driver for I/O
 * @bio:  The bio describing the location in memory and on the device.
 *
 * generic_make_request() is used to make I/O requests of block
 * devices. It is passed a &struct bio, which describes the I/O that needs
 * to be done.
 *
 * generic_make_request() does not return any status.  The
 * success/failure status of the request, along with notification of
 * completion, is delivered asynchronously through the bio->bi_end_io
 * function described (one day) else where.
 *
 * The caller of generic_make_request must make sure that bi_io_vec
 * are set to describe the memory buffer, and that bi_dev and bi_sector are
 * set to describe the device address, and the
 * bi_end_io and optionally bi_private are set to describe how
 * completion notification should be signaled.
 *
 * generic_make_request and the drivers it calls may use bi_next if this
 * bio happens to be merged with someone else, and may change bi_dev and
 * bi_sector for remaps as it sees fit.  So the values of these fields
 * should NOT be depended on after the call to generic_make_request.
 */
/**ltl
 *功能:构造request请求
 *参数:
 *返回值:
 *说明:
 */
static inline void __generic_make_request(struct bio *bio)
{
	struct request_queue *q;
	sector_t old_sector;
	int ret, nr_sectors = bio_sectors(bio);/*请求的扇区总数*/
	dev_t old_dev;
	int err = -EIO;

	might_sleep();
	/* 检查请求是否超出块设备大小 */
	if (bio_check_eod(bio, nr_sectors))
		goto end_io;

	/*
	 * Resolve the mapping until finished. (drivers are
	 * still free to implement/resolve their own stacking
	 * by explicitly returning 0)
	 *
	 * NOTE: we don't repeat the blk_size check for each new device.
	 * Stacking drivers are expected to know what they are doing.
	 */
	old_sector = -1;
	old_dev = 0;
	do {
		char b[BDEVNAME_SIZE];
		/* 请求队列对象 */
		q = bdev_get_queue(bio->bi_bdev);
		if (unlikely(!q)) {
			printk(KERN_ERR
			       "generic_make_request: Trying to access "
				"nonexistent block-device %s (%Lu)\n",
				bdevname(bio->bi_bdev, b),
				(long long) bio->bi_sector);
			goto end_io;
		}
		/* bio没有设置丢弃标志 并且请求的扇区总数超出请求队列的最大数 */
		if (unlikely(!(bio->bi_rw & REQ_DISCARD) &&
			     nr_sectors > queue_max_hw_sectors(q))) {
			printk(KERN_ERR "bio too big device %s (%u > %u)\n",
			       bdevname(bio->bi_bdev, b),
			       bio_sectors(bio),
			       queue_max_hw_sectors(q));
			goto end_io;
		}
		/* 请求队列已经"杀死" */
		if (unlikely(test_bit(QUEUE_FLAG_DEAD, &q->queue_flags)))
			goto end_io;

		if (should_fail_request(bio))
			goto end_io;

		/*
		 * If this device has partitions, remap block n
		 * of partition p to block n+start(p) of the disk.
		 */
		blk_partition_remap(bio);/* 如果bio是对一个分区的请求，则要地址重映射 */
		/* 完整性的判断 */
		if (bio_integrity_enabled(bio) && bio_integrity_prep(bio))
			goto end_io;

		if (old_sector != -1)/* 数据重新映射过，把bio加入到trace中 */
			trace_block_remap(q, bio, old_dev, old_sector);
		/* 旧的起始扇区编号 */
		old_sector = bio->bi_sector;
		old_dev = bio->bi_bdev->bd_dev; /* 旧的块设备对象 */
		/*  */
		if (bio_check_eod(bio, nr_sectors))
			goto end_io;
		
		if ((bio->bi_rw & REQ_DISCARD) &&
		    (!blk_queue_discard(q) ||
		     ((bio->bi_rw & REQ_SECURE) &&
		      !blk_queue_secdiscard(q)))) {
			err = -EOPNOTSUPP;
			goto end_io;
		}
		/* "Q"状态的开始 */
		trace_block_bio_queue(q, bio);
		/* 把bio请求提交给request构造函数__make_reuqest()，
		 * 或者对于RAID或者DM设备这种虚拟设备，为自定义request构造函数md_make_request */
		ret = q->make_request_fn(q, bio);
	} while (ret);

	return;

end_io:
	bio_endio(bio, err);
}

/*
 * We only want one ->make_request_fn to be active at a time,
 * else stack usage with stacked devices could be a problem.
 * So use current->bio_list to keep a list of requests
 * submited by a make_request_fn function.
 * current->bio_list is also used as a flag to say if
 * generic_make_request is currently active in this task or not.
 * If it is NULL, then no make_request is active.  If it is non-NULL,
 * then a make_request is active, and new requests should be added
 * at the tail
 */
void generic_make_request(struct bio *bio)
{
	struct bio_list bio_list_on_stack;
	/* 如果当前进程已经发起一个bio请求，并且块设备子系统、SCSI子系统、或者更加底层子系统正在处理此请求，
	 * 则把新的请求放入列表中，并直接返回。
	 */
	if (current->bio_list) {
		/* make_request is active */
		bio_list_add(current->bio_list, bio);
		return;
	}
	/* following loop may be a bit non-obvious, and so deserves some
	 * explanation.
	 * Before entering the loop, bio->bi_next is NULL (as all callers
	 * ensure that) so we have a list with a single bio.
	 * We pretend that we have just taken it off a longer list, so
	 * we assign bio_list to a pointer to the bio_list_on_stack,
	 * thus initialising the bio_list of new bios to be
	 * added.  __generic_make_request may indeed add some more bios
	 * through a recursive call to generic_make_request.  If it
	 * did, we find a non-NULL value in bio_list and re-enter the loop
	 * from the top.  In this case we really did just take the bio
	 * of the top of the list (no pretending) and so remove it from
	 * bio_list, and call into __generic_make_request again.
	 *
	 * The loop was structured like this to make only one call to
	 * __generic_make_request (which is important as it is large and
	 * inlined) and to keep the structure simple.
	 */
	BUG_ON(bio->bi_next);
	bio_list_init(&bio_list_on_stack);/* 初始化bio列表 */
	current->bio_list = &bio_list_on_stack; /* 对current中的bio_list赋值 */
	/* 循环处理当前进程中的bio列表。 */
	do {
		/* 构造request请求 */
		__generic_make_request(bio);
		/* 从列表中取出bio请求 */
		bio = bio_list_pop(current->bio_list);
	} while (bio);
	/* 处理完成后，对bio列表置空 */
	current->bio_list = NULL; /* deactivate */
}
EXPORT_SYMBOL(generic_make_request);

/**
 * submit_bio - submit a bio to the block device layer for I/O
 * @rw: whether to %READ or %WRITE, or maybe to %READA (read ahead)
 * @bio: The &struct bio which describes the I/O
 *
 * submit_bio() is very similar in purpose to generic_make_request(), and
 * uses that function to do most of the work. Both are fairly rough
 * interfaces; @bio must be presetup and ready for I/O.
 *
 */
/**ltl
 *功能:向块设备层提交bio请求
 *参数:
 *返回值:
 *说明:这个函数两个地方用到:1.基于缓冲页面构造IO请求，即在buffer层中的submit_bh函数。
 *					   2.直接针对页面构造IO请求，即在文件系统层中的do_mpage_readpage()->mpage_bio_submit()函数
*/
void submit_bio(int rw, struct bio *bio)
{
	/*扇区总数*/
	int count = bio_sectors(bio);
	/*读写方向*/
	bio->bi_rw |= rw;

	/*
	 * If it's a regular read/write or a barrier with data attached,
	 * go through the normal accounting stuff before submission.
	 */
	/* 数据量的统计 */
	if (bio_has_data(bio) && !(rw & REQ_DISCARD)) {
		if (rw & WRITE) {
			count_vm_events(PGPGOUT, count);
		} else {
			task_io_account_read(bio->bi_size);
			count_vm_events(PGPGIN, count);
		}

		if (unlikely(block_dump)) {
			char b[BDEVNAME_SIZE];
			printk(KERN_DEBUG "%s(%d): %s block %Lu on %s\n",
			current->comm, task_pid_nr(current),
				(rw & WRITE) ? "WRITE" : "READ",
				(unsigned long long)bio->bi_sector,
				bdevname(bio->bi_bdev, b));
		}
	}
	/* 构造请求:把bio转化成request对象 */
	generic_make_request(bio);
}
EXPORT_SYMBOL(submit_bio);

/**
 * blk_rq_check_limits - Helper function to check a request for the queue limit
 * @q:  the queue
 * @rq: the request being checked
 *
 * Description:
 *    @rq may have been made based on weaker limitations of upper-level queues
 *    in request stacking drivers, and it may violate the limitation of @q.
 *    Since the block layer and the underlying device driver trust @rq
 *    after it is inserted to @q, it should be checked against @q before
 *    the insertion using this generic function.
 *
 *    This function should also be useful for request stacking drivers
 *    in some cases below, so export this fuction.
 *    Request stacking drivers like request-based dm may change the queue
 *    limits while requests are in the queue (e.g. dm's table swapping).
 *    Such request stacking drivers should check those requests agaist
 *    the new queue limits again when they dispatch those requests,
 *    although such checkings are also done against the old queue limits
 *    when submitting requests.
 */
int blk_rq_check_limits(struct request_queue *q, struct request *rq)
{
	if (rq->cmd_flags & REQ_DISCARD)
		return 0;

	if (blk_rq_sectors(rq) > queue_max_sectors(q) ||
	    blk_rq_bytes(rq) > queue_max_hw_sectors(q) << 9) {
		printk(KERN_ERR "%s: over max size limit.\n", __func__);
		return -EIO;
	}

	/*
	 * queue's settings related to segment counting like q->bounce_pfn
	 * may differ from that of other stacking queues.
	 * Recalculate it to check the request correctly on this queue's
	 * limitation.
	 */
	blk_recalc_rq_segments(rq);
	if (rq->nr_phys_segments > queue_max_segments(q)) {
		printk(KERN_ERR "%s: over max segments limit.\n", __func__);
		return -EIO;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(blk_rq_check_limits);

/**
 * blk_insert_cloned_request - Helper for stacking drivers to submit a request
 * @q:  the queue to submit the request
 * @rq: the request being queued
 */
int blk_insert_cloned_request(struct request_queue *q, struct request *rq)
{
	unsigned long flags;

	if (blk_rq_check_limits(q, rq))
		return -EIO;

#ifdef CONFIG_FAIL_MAKE_REQUEST
	if (rq->rq_disk && rq->rq_disk->part0.make_it_fail &&
	    should_fail(&fail_make_request, blk_rq_bytes(rq)))
		return -EIO;
#endif

	spin_lock_irqsave(q->queue_lock, flags);

	/*
	 * Submitting request must be dequeued before calling this function
	 * because it will be linked to another request_queue
	 */
	BUG_ON(blk_queued_rq(rq));

	drive_stat_acct(rq, 1);
	__elv_add_request(q, rq, ELEVATOR_INSERT_BACK, 0);

	spin_unlock_irqrestore(q->queue_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(blk_insert_cloned_request);

/**
 * blk_rq_err_bytes - determine number of bytes till the next failure boundary
 * @rq: request to examine
 *
 * Description:
 *     A request could be merge of IOs which require different failure
 *     handling.  This function determines the number of bytes which
 *     can be failed from the beginning of the request without
 *     crossing into area which need to be retried further.
 *
 * Return:
 *     The number of bytes to fail.
 *
 * Context:
 *     queue_lock must be held.
 */
unsigned int blk_rq_err_bytes(const struct request *rq)
{
	unsigned int ff = rq->cmd_flags & REQ_FAILFAST_MASK;
	unsigned int bytes = 0;
	struct bio *bio;

	if (!(rq->cmd_flags & REQ_MIXED_MERGE))
		return blk_rq_bytes(rq);

	/*
	 * Currently the only 'mixing' which can happen is between
	 * different fastfail types.  We can safely fail portions
	 * which have all the failfast bits that the first one has -
	 * the ones which are at least as eager to fail as the first
	 * one.
	 */
	for (bio = rq->bio; bio; bio = bio->bi_next) {
		if ((bio->bi_rw & ff) != ff)
			break;
		bytes += bio->bi_size;
	}

	/* this could lead to infinite loop */
	BUG_ON(blk_rq_bytes(rq) && !bytes);
	return bytes;
}
EXPORT_SYMBOL_GPL(blk_rq_err_bytes);

static void blk_account_io_completion(struct request *req, unsigned int bytes)
{
	if (blk_do_io_stat(req)) {
		const int rw = rq_data_dir(req);
		struct hd_struct *part;
		int cpu;

		cpu = part_stat_lock();
		part = disk_map_sector_rcu(req->rq_disk, blk_rq_pos(req));
		part_stat_add(cpu, part, sectors[rw], bytes >> 9);
		part_stat_unlock();
	}
}

static void blk_account_io_done(struct request *req)
{
	/*
	 * Account IO completion.  bar_rq isn't accounted as a normal
	 * IO on queueing nor completion.  Accounting the containing
	 * request is enough.
	 */
	if (blk_do_io_stat(req) && req != &req->q->bar_rq) {
		unsigned long duration = jiffies - req->start_time;
		const int rw = rq_data_dir(req);
		struct hd_struct *part;
		int cpu;

		cpu = part_stat_lock();
		part = disk_map_sector_rcu(req->rq_disk, blk_rq_pos(req));

		part_stat_inc(cpu, part, ios[rw]);
		part_stat_add(cpu, part, ticks[rw], duration);
		part_round_stats(cpu, part);
		part_dec_in_flight(part, rw);

		part_stat_unlock();
	}
}

/**
 * blk_peek_request - peek at the top of a request queue
 * @q: request queue to peek at
 *
 * Description:
 *     Return the request at the top of @q.  The returned request
 *     should be started using blk_start_request() before LLD starts
 *     processing it.
 *
 * Return:
 *     Pointer to the request at the top of @q if available.  Null
 *     otherwise.
 *
 * Context:
 *     queue_lock must be held.
 */
/**ltl
 * 功能:从请求队列中提取request请求
 * 参数:
 * 返回值:
 * 说明: 从这个函数返回的请求还没有离队，即还在派发队列里面。
 */
struct request *blk_peek_request(struct request_queue *q)
{
	struct request *rq;
	int ret;

	while ((rq = __elv_next_request(q)) != NULL) {
		if (!(rq->cmd_flags & REQ_STARTED)) { /* 设置开始执行标志 */
			/*
			 * This is the first time the device driver
			 * sees this request (possibly after
			 * requeueing).  Notify IO scheduler.
			 */
			if (rq->cmd_flags & REQ_SORTED)
				elv_activate_rq(q, rq); /* 激活请求(CFQ算法) */

			/*
			 * just mark as started even if we don't start
			 * it, a request that has been delayed should
			 * not be passed by new incoming requests
			 */
			rq->cmd_flags |= REQ_STARTED; /* 设置开始执行标志 */
			trace_block_rq_issue(q, rq);
		}

		if (!q->boundary_rq || q->boundary_rq == rq) {
			q->end_sector = rq_end_sector(rq);
			q->boundary_rq = NULL;
		}
		/* 表示请求不需要调用命令预前处理函数 */
		if (rq->cmd_flags & REQ_DONTPREP)
			break;

		if (q->dma_drain_size && blk_rq_bytes(rq)) {
			/*
			 * make sure space for the drain appears we
			 * know we can do this because max_hw_segments
			 * has been adjusted to be one fewer than the
			 * device can handle
			 */
			rq->nr_phys_segments++;
		}
		/* 命令预前处理函数不存在 */
		if (!q->prep_rq_fn)
			break;
		/* 命令预前处理函数 */
		ret = q->prep_rq_fn(q, rq);
		if (ret == BLKPREP_OK) { /* 处理成功 */
			break;
		} else if (ret == BLKPREP_DEFER) { /* 命令要迟延处理 */
			/*
			 * the request may have been (partially) prepped.
			 * we need to keep this request in the front to
			 * avoid resource deadlock.  REQ_STARTED will
			 * prevent other fs requests from passing this one.
			 */
			if (q->dma_drain_size && blk_rq_bytes(rq) &&
			    !(rq->cmd_flags & REQ_DONTPREP)) {
				/*
				 * remove the space for the drain we added
				 * so that we don't add it again
				 */
				--rq->nr_phys_segments;
			}

			rq = NULL;
			break;
		} else if (ret == BLKPREP_KILL) { /* 要结束请求 */
			rq->cmd_flags |= REQ_QUIET;
			/*
			 * Mark this request as started so we don't trigger
			 * any debug logic in the end I/O path.
			 */
			blk_start_request(rq); /* 请求离队 */
			__blk_end_request_all(rq, -EIO); /* 请求完成处理函数 */
		} else {
			printk(KERN_ERR "%s: bad return=%d\n", __func__, ret);
			break;
		}
	}

	return rq;
}
EXPORT_SYMBOL(blk_peek_request);
/**ltl
 * 功能:使请求脱离队列
 * 参数:
 * 返回值:
 * 说明:
 */
void blk_dequeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	BUG_ON(list_empty(&rq->queuelist));
	BUG_ON(ELV_ON_HASH(rq));
	/* 从派发队列中脱离 */
	list_del_init(&rq->queuelist);

	/*
	 * the time frame between a request being removed from the lists
	 * and to it is freed is accounted as io that is in progress at
	 * the driver side.
	 */
	if (blk_account_rq(rq)) {
		q->in_flight[rq_is_sync(rq)]++;
		set_io_start_time_ns(rq);
	}
}

/**
 * blk_start_request - start request processing on the driver
 * @req: request to dequeue
 *
 * Description:
 *     Dequeue @req and start timeout timer on it.  This hands off the
 *     request to the driver.
 *
 *     Block internal functions which don't want to start timer should
 *     call blk_dequeue_request().
 *
 * Context:
 *     queue_lock must be held.
 */
/**ltl
 * 功能:请求交给底层驱动(SCSI子系统)之前要调用此函数，表示一个请求的开始
 * 参数:
 * 返回值:
 * 说明:在这个函数主要实现两个功能:1.请求脱离队列；2.插入超时定时器，并开启超时检测定时器。
 */
void blk_start_request(struct request *req)
{
	/* 使请求脱离队列 */
	blk_dequeue_request(req);

	/*
	 * We are now handing the request to the hardware, initialize
	 * resid_len to full count and add the timeout handler.
	 */
	req->resid_len = blk_rq_bytes(req); /* 记录剩余数据长度 */
	if (unlikely(blk_bidi_rq(req)))
		req->next_rq->resid_len = blk_rq_bytes(req->next_rq);
	/* 将请求插入到超时列表 */
	blk_add_timer(req);
}
EXPORT_SYMBOL(blk_start_request);

/**
 * blk_fetch_request - fetch a request from a request queue
 * @q: request queue to fetch a request from
 *
 * Description:
 *     Return the request at the top of @q.  The request is started on
 *     return and LLD can start processing it immediately.
 *
 * Return:
 *     Pointer to the request at the top of @q if available.  Null
 *     otherwise.
 *
 * Context:
 *     queue_lock must be held.
 */
/**ltl
 * 功能:从请求队列中取出一个请求。
 * 参数:
 * 返回值:
 * 说明:调用此函数后，此请求就已经脱离了队列
 */
struct request *blk_fetch_request(struct request_queue *q)
{
	struct request *rq;

	rq = blk_peek_request(q);
	if (rq)
		blk_start_request(rq);
	return rq;
}
EXPORT_SYMBOL(blk_fetch_request);

/**
 * blk_update_request - Special helper function for request stacking drivers
 * @req:      the request being processed
 * @error:    %0 for success, < %0 for error
 * @nr_bytes: number of bytes to complete @req
 *
 * Description:
 *     Ends I/O on a number of bytes attached to @req, but doesn't complete
 *     the request structure even if @req doesn't have leftover.
 *     If @req has leftover, sets it up for the next range of segments.
 *
 *     This special helper function is only for request stacking drivers
 *     (e.g. request-based dm) so that they can handle partial completion.
 *     Actual device drivers should use blk_end_request instead.
 *
 *     Passing the result of blk_rq_bytes() as @nr_bytes guarantees
 *     %false return from this function.
 *
 * Return:
 *     %false - this request doesn't have any more data
 *     %true  - this request has more data
 **/
/**ltl
 * 功能:执行完一个请求后的处理函数
 * 参数:
 * 返回值:false表示传输完成；true表示存在未完成的数据。
 * 说明:调用请求bio链表中的回调函数通知上层。
 *    Q:如果出现部分bio数据没有传输成功，怎么确定是request的bio链表中的哪个bio请求没有传输成功?
 *	 答:是否是底层在DMA操作时，传输scatterlist列表时，先传输scatterlist列表头的数据，如此依次传输，如果中间出现错误，直接返回值。
 */
bool blk_update_request(struct request *req, int error, unsigned int nr_bytes)
{
	/*
	 * total_bytes:对一个request对象，成功传输完成的总字节数
	 * bio_nbytes:如果存在一个bio对象，一部分数据舆完成，另一部分数据没有成功，此值就表示那完成的部分
	 */
	int total_bytes, bio_nbytes, next_idx = 0;
	struct bio *bio;

	if (!req->bio)
		return false;

	trace_block_rq_complete(req->q, req);

	/*
	 * For fs requests, rq is just carrier of independent bio's
	 * and each partial completion should be handled separately.
	 * Reset per-request error on each partial completion.
	 *
	 * TODO: tj: This is too subtle.  It would be better to let
	 * low level drivers do what they see fit.
	 */
	if (req->cmd_type == REQ_TYPE_FS)
		req->errors = 0;
	/* 命令执行出错 */
	if (error && req->cmd_type == REQ_TYPE_FS &&
	    !(req->cmd_flags & REQ_QUIET)) {
		printk(KERN_ERR "end_request: I/O error, dev %s, sector %llu\n",
				req->rq_disk ? req->rq_disk->disk_name : "?",
				(unsigned long long)blk_rq_pos(req));
	}
	/* 更新IO统计信息 */
	blk_account_io_completion(req, nr_bytes);

	total_bytes = bio_nbytes = 0;
	while ((bio = req->bio) != NULL) { /* 遍历request中的bio请求 */
		int nbytes;

		if (nr_bytes >= bio->bi_size) { /* 总的字节数超过一个bio对象的数据长度 */
			req->bio = bio->bi_next;	/* 取出下一个bio请求 */
			nbytes = bio->bi_size;		/* 一个bio字节长度 */
			req_bio_endio(req, bio, nbytes, error); /* 调用bio请求的完成处理函数 */
			next_idx = 0;
			bio_nbytes = 0;
		} else { 
		/* 表示传输成功的字节数小于一个bio的数据长度，这种情况属于执行成功而传输的数据长度与实际长度不符。
		 * Q:为什么会出现这种情况?
		 */
			int idx = bio->bi_idx + next_idx;

			if (unlikely(idx >= bio->bi_vcnt)) {
				blk_dump_rq_flags(req, "__end_that");
				printk(KERN_ERR "%s: bio idx %d >= vcnt %d\n",
				       __func__, idx, bio->bi_vcnt);
				break;
			}
			/* bio_vec的索引号 */
			nbytes = bio_iovec_idx(bio, idx)->bv_len;
			BIO_BUG_ON(nbytes > bio->bi_size);

			/*
			 * not a complete bvec done
			 */
			if (unlikely(nbytes > nr_bytes)) {
				bio_nbytes += nr_bytes; /* 一个bio对象，传输成功的字节数 */
				total_bytes += nr_bytes; /* 对一个request对象，成功传输的字节数 */
				break;
			}

			/*
			 * advance to the next vector
			 */
			next_idx++;
			bio_nbytes += nbytes; /* 对于一个失败的bio对象，成功传输的字节数 */
		}

		total_bytes += nbytes; /*对于一个request对象，成功传输的字节数*/
		nr_bytes -= nbytes;		/* 剩下的成功传输字节数 */
		
		bio = req->bio;
		if (bio) { /* 如果request的bio链表还没有遍历结束，而剩下的成功传输完成的字节数已经为0，直接退出 */
			/*
			 * end more in this run, or just return 'not-done'
			 */
			if (unlikely(nr_bytes <= 0))
				break;
		}
	}

	/*
	 * completely done
	 */
	if (!req->bio) { /* 所有的数据成功传输完成，直接返回值false */
		/*
		 * Reset counters so that the request stacking driver
		 * can find how many bytes remain in the request
		 * later.
		 */
		req->__data_len = 0;
		return false;
	}
	
	/* 以下是对request请求数据没有传输完成的处理 */
	/*
	 * if the request wasn't completed, update state
	 */
	if (bio_nbytes) { /* 对于一个bio，成功传输的节点数 */
		req_bio_endio(req, bio, bio_nbytes, error); /* 更新bio中的剩下的字节数和bio请求的起始地址 */
		bio->bi_idx += next_idx;
		bio_iovec(bio)->bv_offset += nr_bytes;
		bio_iovec(bio)->bv_len -= nr_bytes;
	}
	/* 请求的剩下数据长度 */
	req->__data_len -= total_bytes;
	req->buffer = bio_data(req->bio);

	/* update sector only for requests with clear definition of sector */
	if (req->cmd_type == REQ_TYPE_FS || (req->cmd_flags & REQ_DISCARD))
		req->__sector += total_bytes >> 9;

	/* mixed attributes always follow the first bio */
	if (req->cmd_flags & REQ_MIXED_MERGE) {
		req->cmd_flags &= ~REQ_FAILFAST_MASK;
		req->cmd_flags |= req->bio->bi_rw & REQ_FAILFAST_MASK;
	}

	/*
	 * If total number of sectors is less than the first segment
	 * size, something has gone terribly wrong.
	 */
	if (blk_rq_bytes(req) < blk_rq_cur_bytes(req)) {
		printk(KERN_ERR "blk: request botched\n");
		req->__data_len = blk_rq_cur_bytes(req);
	}
	/* 重新计算request请求的内存段数 */
	/* recalculate the number of segments */
	blk_recalc_rq_segments(req);

	return true;
}
EXPORT_SYMBOL_GPL(blk_update_request);
/**ltl
 * 功能: 更新双向请求。
 * 参数: rq		->请求对象
 *		error	->错误码
 *		nr_bytes	->对request请求，成功传输的字节数
 *		bidi_bytes->对request->next_rq请求，成功传输的字节数。
 * 返回值:false  ->表示两方向的请求的数据都已经传输完成。
 *		true	->表示至少有一个方向的请求数据没有传输完成，此请求要重新插入派发队列中。
 * 说明:	   
 */
static bool blk_update_bidi_request(struct request *rq, int error,
				    unsigned int nr_bytes,
				    unsigned int bidi_bytes)
{
	/* 更新请求的传输字节数 */
	if (blk_update_request(rq, error, nr_bytes))
		return true;
	/* 更新next_rq请求的传输字节数 */
	/* Bidi request must be completed as a whole */
	if (unlikely(blk_bidi_rq(rq)) &&
	    blk_update_request(rq->next_rq, error, bidi_bytes))
		return true;

	if (blk_queue_add_random(rq->q))
		add_disk_randomness(rq->rq_disk);

	return false;
}

/**
 * blk_unprep_request - unprepare a request
 * @req:	the request
 *
 * This function makes a request ready for complete resubmission (or
 * completion).  It happens only after all error handling is complete,
 * so represents the appropriate moment to deallocate any resources
 * that were allocated to the request in the prep_rq_fn.  The queue
 * lock is held when calling this.
 */
void blk_unprep_request(struct request *req)
{
	struct request_queue *q = req->q;

	req->cmd_flags &= ~REQ_DONTPREP;
	if (q->unprep_rq_fn)
		q->unprep_rq_fn(q, req);
}
EXPORT_SYMBOL_GPL(blk_unprep_request);

/*
 * queue lock must be held
 */
/**ltl
 * 功能:调用请求完成处理函数通知上层(FS层，或者通用块层)
 * 参数:
 * 返回值:
 * 说明:
 */
static void blk_finish_request(struct request *req, int error)
{
	if (blk_rq_tagged(req)) /* 如果请求处理排队状态 */
		blk_queue_end_tag(req->q, req); /* 从队列中删除，并清除标志 */

	BUG_ON(blk_queued_rq(req));

	if (unlikely(laptop_mode) && req->cmd_type == REQ_TYPE_FS)
		laptop_io_completion(&req->q->backing_dev_info);
	/* 删除请求的超时定时器 */
	blk_delete_timer(req);

	if (req->cmd_flags & REQ_DONTPREP)
		blk_unprep_request(req);


	blk_account_io_done(req);
	/* 调用request请求的完成回调函数，通知上层 */
	if (req->end_io)
		req->end_io(req, error);
	else {
		if (blk_bidi_rq(req))
			__blk_put_request(req->next_rq->q, req->next_rq);
		/* 释放request对象 */
		__blk_put_request(req->q, req);
	}
}

/**
 * blk_end_bidi_request - Complete a bidi request
 * @rq:         the request to complete
 * @error:      %0 for success, < %0 for error
 * @nr_bytes:   number of bytes to complete @rq
 * @bidi_bytes: number of bytes to complete @rq->next_rq
 *
 * Description:
 *     Ends I/O on a number of bytes attached to @rq and @rq->next_rq.
 *     Drivers that supports bidi can safely call this member for any
 *     type of request, bidi or uni.  In the later case @bidi_bytes is
 *     just ignored.
 *
 * Return:
 *     %false - we are done with this request
 *     %true  - still buffers pending for this request
 **/
/**ltl
 * 功能:请求执行完成后，在通用块层的处理过程
 * 参数:	rq	->请求对象
 *		error->错误码
 *		nr_bytes->成功传输的字节数
 *		bidi_bytes->对于next_rq对象，成功传输的字节数
 * 返回值:false	->表示数据传输完成。true->表示存在未成功传输完成的数据。
 * 说明: 这个函数与__blk_end_bidi_request是区别是在调用blk_finish_request函数时是否持有自旋锁的区别。
 */
static bool blk_end_bidi_request(struct request *rq, int error,
				 unsigned int nr_bytes, unsigned int bidi_bytes)
{
	struct request_queue *q = rq->q;
	unsigned long flags;
	/* 更新请求 */
	if (blk_update_bidi_request(rq, error, nr_bytes, bidi_bytes))
		return true;/* 请求的数据没有全部传输完 */
	
	/* 请求的数据传输成功后的处理 */
	spin_lock_irqsave(q->queue_lock, flags);
	blk_finish_request(rq, error);
	spin_unlock_irqrestore(q->queue_lock, flags);

	return false;
}

/**
 * __blk_end_bidi_request - Complete a bidi request with queue lock held
 * @rq:         the request to complete
 * @error:      %0 for success, < %0 for error
 * @nr_bytes:   number of bytes to complete @rq
 * @bidi_bytes: number of bytes to complete @rq->next_rq
 *
 * Description:
 *     Identical to blk_end_bidi_request() except that queue lock is
 *     assumed to be locked on entry and remains so on return.
 *
 * Return:
 *     %false - we are done with this request
 *     %true  - still buffers pending for this request
 **/
 /**ltl
 * 功能:请求执行完成后，在通用块层的处理过程
 * 参数:	rq	->请求对象
 *		error->错误码
 *		nr_bytes->成功传输的字节数
 *		bidi_bytes->对于next_rq对象，成功传输的字节数
 * 返回值:false	->表示数据传输完成。true->表示存在未成功传输完成的数据。
 * 说明: 这个函数与blk_end_bidi_request是区别是在调用blk_finish_request函数时是否持有自旋锁的区别。
 */
static bool __blk_end_bidi_request(struct request *rq, int error,
				   unsigned int nr_bytes, unsigned int bidi_bytes)
{
	if (blk_update_bidi_request(rq, error, nr_bytes, bidi_bytes))
		return true;

	blk_finish_request(rq, error); /* 这个函数没有持有自旋锁 */

	return false;
}

/**
 * blk_end_request - Helper function for drivers to complete the request.
 * @rq:       the request being processed
 * @error:    %0 for success, < %0 for error
 * @nr_bytes: number of bytes to complete
 *
 * Description:
 *     Ends I/O on a number of bytes attached to @rq.
 *     If @rq has leftover, sets it up for the next range of segments.
 *
 * Return:
 *     %false - we are done with this request
 *     %true  - still buffers pending for this request
 **/
/**ltl
 * 功能: 一个请求执行完成的处理函数
 * 参数:	rq	->请求对象
 *		error->错误码，如果执行成员，此值为0
 *		nr_bytes	->成功传输的字节数
 * 返回值:
 * 说明:
 */
bool blk_end_request(struct request *rq, int error, unsigned int nr_bytes)
{
	return blk_end_bidi_request(rq, error, nr_bytes, 0);
}
EXPORT_SYMBOL(blk_end_request);

/**
 * blk_end_request_all - Helper function for drives to finish the request.
 * @rq: the request to finish
 * @error: %0 for success, < %0 for error
 *
 * Description:
 *     Completely finish @rq.
 */
/**ltl
 * 功能: request请求执行完后的处理
 * 参数:
 * 返回值:
 * 说明:此函数与blk_end_request_cur的区别是完成传输的数据长度不一样
 * 即blk_end_bidi_request的参数nr_bytes的值分别是lk_rq_bytes()和blk_rq_cur_bytes()
 */
void blk_end_request_all(struct request *rq, int error)
{
	bool pending;
	unsigned int bidi_bytes = 0;

	if (unlikely(blk_bidi_rq(rq)))
		bidi_bytes = blk_rq_bytes(rq->next_rq);

	pending = blk_end_bidi_request(rq, error, blk_rq_bytes(rq), bidi_bytes);
	BUG_ON(pending);
}
EXPORT_SYMBOL(blk_end_request_all);

/**
 * blk_end_request_cur - Helper function to finish the current request chunk.
 * @rq: the request to finish the current chunk for
 * @error: %0 for success, < %0 for error
 *
 * Description:
 *     Complete the current consecutively mapped chunk from @rq.
 *
 * Return:
 *     %false - we are done with this request
 *     %true  - still buffers pending for this request
 */
bool blk_end_request_cur(struct request *rq, int error)
{
	return blk_end_request(rq, error, blk_rq_cur_bytes(rq));
}
EXPORT_SYMBOL(blk_end_request_cur);

/**
 * blk_end_request_err - Finish a request till the next failure boundary.
 * @rq: the request to finish till the next failure boundary for
 * @error: must be negative errno
 *
 * Description:
 *     Complete @rq till the next failure boundary.
 *
 * Return:
 *     %false - we are done with this request
 *     %true  - still buffers pending for this request
 */
bool blk_end_request_err(struct request *rq, int error)
{
	WARN_ON(error >= 0);
	return blk_end_request(rq, error, blk_rq_err_bytes(rq));
}
EXPORT_SYMBOL_GPL(blk_end_request_err);

/**
 * __blk_end_request - Helper function for drivers to complete the request.
 * @rq:       the request being processed
 * @error:    %0 for success, < %0 for error
 * @nr_bytes: number of bytes to complete
 *
 * Description:
 *     Must be called with queue lock held unlike blk_end_request().
 *
 * Return:
 *     %false - we are done with this request
 *     %true  - still buffers pending for this request
 **/
bool __blk_end_request(struct request *rq, int error, unsigned int nr_bytes)
{
	return __blk_end_bidi_request(rq, error, nr_bytes, 0);
}
EXPORT_SYMBOL(__blk_end_request);

/**
 * __blk_end_request_all - Helper function for drives to finish the request.
 * @rq: the request to finish
 * @error: %0 for success, < %0 for error
 *
 * Description:
 *     Completely finish @rq.  Must be called with queue lock held.
 */
void __blk_end_request_all(struct request *rq, int error)
{
	bool pending;
	unsigned int bidi_bytes = 0;

	if (unlikely(blk_bidi_rq(rq)))
		bidi_bytes = blk_rq_bytes(rq->next_rq);

	pending = __blk_end_bidi_request(rq, error, blk_rq_bytes(rq), bidi_bytes);
	BUG_ON(pending);
}
EXPORT_SYMBOL(__blk_end_request_all);

/**
 * __blk_end_request_cur - Helper function to finish the current request chunk.
 * @rq: the request to finish the current chunk for
 * @error: %0 for success, < %0 for error
 *
 * Description:
 *     Complete the current consecutively mapped chunk from @rq.  Must
 *     be called with queue lock held.
 *
 * Return:
 *     %false - we are done with this request
 *     %true  - still buffers pending for this request
 */
bool __blk_end_request_cur(struct request *rq, int error)
{
	return __blk_end_request(rq, error, blk_rq_cur_bytes(rq));
}
EXPORT_SYMBOL(__blk_end_request_cur);

/**
 * __blk_end_request_err - Finish a request till the next failure boundary.
 * @rq: the request to finish till the next failure boundary for
 * @error: must be negative errno
 *
 * Description:
 *     Complete @rq till the next failure boundary.  Must be called
 *     with queue lock held.
 *
 * Return:
 *     %false - we are done with this request
 *     %true  - still buffers pending for this request
 */
bool __blk_end_request_err(struct request *rq, int error)
{
	WARN_ON(error >= 0);
	return __blk_end_request(rq, error, blk_rq_err_bytes(rq));
}
EXPORT_SYMBOL_GPL(__blk_end_request_err);

void blk_rq_bio_prep(struct request_queue *q, struct request *rq,
		     struct bio *bio)
{
	/* Bit 0 (R/W) is identical in rq->cmd_flags and bio->bi_rw */
	rq->cmd_flags |= bio->bi_rw & REQ_WRITE;

	if (bio_has_data(bio)) {
		rq->nr_phys_segments = bio_phys_segments(q, bio);
		rq->buffer = bio_data(bio);
	}
	rq->__data_len = bio->bi_size; /* 数据长度 */
	rq->bio = rq->biotail = bio;   /* 链入 */
	/* 设置通用磁盘对象 */
	if (bio->bi_bdev)
		rq->rq_disk = bio->bi_bdev->bd_disk;
}

#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE
/**
 * rq_flush_dcache_pages - Helper function to flush all pages in a request
 * @rq: the request to be flushed
 *
 * Description:
 *     Flush all pages in @rq.
 */
void rq_flush_dcache_pages(struct request *rq)
{
	struct req_iterator iter;
	struct bio_vec *bvec;

	rq_for_each_segment(bvec, rq, iter)
		flush_dcache_page(bvec->bv_page);
}
EXPORT_SYMBOL_GPL(rq_flush_dcache_pages);
#endif

/**
 * blk_lld_busy - Check if underlying low-level drivers of a device are busy
 * @q : the queue of the device being checked
 *
 * Description:
 *    Check if underlying low-level drivers of a device are busy.
 *    If the drivers want to export their busy state, they must set own
 *    exporting function using blk_queue_lld_busy() first.
 *
 *    Basically, this function is used only by request stacking drivers
 *    to stop dispatching requests to underlying devices when underlying
 *    devices are busy.  This behavior helps more I/O merging on the queue
 *    of the request stacking driver and prevents I/O throughput regression
 *    on burst I/O load.
 *
 * Return:
 *    0 - Not busy (The request stacking driver should dispatch request)
 *    1 - Busy (The request stacking driver should stop dispatching request)
 */
int blk_lld_busy(struct request_queue *q)
{
	if (q->lld_busy_fn)
		return q->lld_busy_fn(q);

	return 0;
}
EXPORT_SYMBOL_GPL(blk_lld_busy);

/**
 * blk_rq_unprep_clone - Helper function to free all bios in a cloned request
 * @rq: the clone request to be cleaned up
 *
 * Description:
 *     Free all bios in @rq for a cloned request.
 */
void blk_rq_unprep_clone(struct request *rq)
{
	struct bio *bio;

	while ((bio = rq->bio) != NULL) {
		rq->bio = bio->bi_next;

		bio_put(bio);
	}
}
EXPORT_SYMBOL_GPL(blk_rq_unprep_clone);

/*
 * Copy attributes of the original request to the clone request.
 * The actual data parts (e.g. ->cmd, ->buffer, ->sense) are not copied.
 */
static void __blk_rq_prep_clone(struct request *dst, struct request *src)
{
	dst->cpu = src->cpu;
	dst->cmd_flags = (rq_data_dir(src) | REQ_NOMERGE);
	if (src->cmd_flags & REQ_DISCARD)
		dst->cmd_flags |= REQ_DISCARD;
	dst->cmd_type = src->cmd_type;
	dst->__sector = blk_rq_pos(src);
	dst->__data_len = blk_rq_bytes(src);
	dst->nr_phys_segments = src->nr_phys_segments;
	dst->ioprio = src->ioprio;
	dst->extra_len = src->extra_len;
}

/**
 * blk_rq_prep_clone - Helper function to setup clone request
 * @rq: the request to be setup
 * @rq_src: original request to be cloned
 * @bs: bio_set that bios for clone are allocated from
 * @gfp_mask: memory allocation mask for bio
 * @bio_ctr: setup function to be called for each clone bio.
 *           Returns %0 for success, non %0 for failure.
 * @data: private data to be passed to @bio_ctr
 *
 * Description:
 *     Clones bios in @rq_src to @rq, and copies attributes of @rq_src to @rq.
 *     The actual data parts of @rq_src (e.g. ->cmd, ->buffer, ->sense)
 *     are not copied, and copying such parts is the caller's responsibility.
 *     Also, pages which the original bios are pointing to are not copied
 *     and the cloned bios just point same pages.
 *     So cloned bios must be completed before original bios, which means
 *     the caller must complete @rq before @rq_src.
 */
int blk_rq_prep_clone(struct request *rq, struct request *rq_src,
		      struct bio_set *bs, gfp_t gfp_mask,
		      int (*bio_ctr)(struct bio *, struct bio *, void *),
		      void *data)
{
	struct bio *bio, *bio_src;

	if (!bs)
		bs = fs_bio_set;

	blk_rq_init(NULL, rq);

	__rq_for_each_bio(bio_src, rq_src) {
		bio = bio_alloc_bioset(gfp_mask, bio_src->bi_max_vecs, bs);
		if (!bio)
			goto free_and_out;

		__bio_clone(bio, bio_src);

		if (bio_integrity(bio_src) &&
		    bio_integrity_clone(bio, bio_src, gfp_mask, bs))
			goto free_and_out;

		if (bio_ctr && bio_ctr(bio, bio_src, data))
			goto free_and_out;

		if (rq->bio) {
			rq->biotail->bi_next = bio;
			rq->biotail = bio;
		} else
			rq->bio = rq->biotail = bio;
	}

	__blk_rq_prep_clone(rq, rq_src);

	return 0;

free_and_out:
	if (bio)
		bio_free(bio, bs);
	blk_rq_unprep_clone(rq);

	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(blk_rq_prep_clone);

int kblockd_schedule_work(struct request_queue *q, struct work_struct *work)
{
	return queue_work(kblockd_workqueue, work);
}
EXPORT_SYMBOL(kblockd_schedule_work);

int __init blk_dev_init(void)
{
	BUILD_BUG_ON(__REQ_NR_BITS > 8 *
			sizeof(((struct request *)0)->cmd_flags));

	kblockd_workqueue = create_workqueue("kblockd");
	if (!kblockd_workqueue)
		panic("Failed to create kblockd\n");

	request_cachep = kmem_cache_create("blkdev_requests",
			sizeof(struct request), 0, SLAB_PANIC, NULL);

	blk_requestq_cachep = kmem_cache_create("blkdev_queue",
			sizeof(struct request_queue), 0, SLAB_PANIC, NULL);

	return 0;
}

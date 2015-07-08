#ifndef _RAID5_H
#define _RAID5_H

#include <linux/raid/xor.h>
#include <linux/dmaengine.h>

/*
 *
 * Each stripe contains one buffer per disc.  Each buffer can be in
 * one of a number of states stored in "flags".  Changes between
 * these states happen *almost* exclusively under a per-stripe
 * spinlock.  Some very specific changes can happen in bi_end_io, and
 * these are not protected by the spin lock.
 *
 * The flag bits that are used to represent these states are:
 *   R5_UPTODATE and R5_LOCKED
 *
 * State Empty == !UPTODATE, !LOCK
 *        We have no data, and there is no active request
 * State Want == !UPTODATE, LOCK
 *        A read request is being submitted for this block
 * State Dirty == UPTODATE, LOCK
 *        Some new data is in this buffer, and it is being written out
 * State Clean == UPTODATE, !LOCK
 *        We have valid data which is the same as on disc
 *
 * The possible state transitions are:
 *
 *  Empty -> Want   - on read or write to get old data for  parity calc
 *  Empty -> Dirty  - on compute_parity to satisfy write/sync request.(RECONSTRUCT_WRITE)
 *  Empty -> Clean  - on compute_block when computing a block for failed drive
 *  Want  -> Empty  - on failed read
 *  Want  -> Clean  - on successful completion of read request
 *  Dirty -> Clean  - on successful completion of write request
 *  Dirty -> Clean  - on failed write
 *  Clean -> Dirty  - on compute_parity to satisfy write/sync (RECONSTRUCT or RMW)
 *
 * The Want->Empty, Want->Clean, Dirty->Clean, transitions
 * all happen in b_end_io at interrupt time.
 * Each sets the Uptodate bit before releasing the Lock bit.
 * This leaves one multi-stage transition:
 *    Want->Dirty->Clean
 * This is safe because thinking that a Clean buffer is actually dirty
 * will at worst delay some action, and the stripe will be scheduled
 * for attention after the transition is complete.
 *
 * There is one possibility that is not covered by these states.  That
 * is if one drive has failed and there is a spare being rebuilt.  We
 * can't distinguish between a clean block that has been generated
 * from parity calculations, and a clean block that has been
 * successfully written to the spare ( or to parity when resyncing).
 * To distingush these states we have a stripe bit STRIPE_INSYNC that
 * is set whenever a write is scheduled to the spare, or to the parity
 * disc if there is no spare.  A sync request clears this bit, and
 * when we find it set with no buffers locked, we know the sync is
 * complete.
 *
 * Buffers for the md device that arrive via make_request are attached
 * to the appropriate stripe in one of two lists linked on b_reqnext.
 * One list (bh_read) for read requests, one (bh_write) for write.
 * There should never be more than one buffer on the two lists
 * together, but we are not guaranteed of that so we allow for more.
 *
 * If a buffer is on the read list when the associated cache buffer is
 * Uptodate, the data is copied into the read buffer and it's b_end_io
 * routine is called.  This may happen in the end_request routine only
 * if the buffer has just successfully been read.  end_request should
 * remove the buffers from the list and then set the Uptodate bit on
 * the buffer.  Other threads may do this only if they first check
 * that the Uptodate bit is set.  Once they have checked that they may
 * take buffers off the read queue.
 *
 * When a buffer on the write list is committed for write it is copied
 * into the cache buffer, which is then marked dirty, and moved onto a
 * third list, the written list (bh_written).  Once both the parity
 * block and the cached buffer are successfully written, any buffer on
 * a written list can be returned with b_end_io.
 *
 * The write list and read list both act as fifos.  The read list is
 * protected by the device_lock.  The write and written lists are
 * protected by the stripe lock.  The device_lock, which can be
 * claimed while the stipe lock is held, is only for list
 * manipulations and will only be held for a very short time.  It can
 * be claimed from interrupts.
 *
 *
 * Stripes in the stripe cache can be on one of two lists (or on
 * neither).  The "inactive_list" contains stripes which are not
 * currently being used for any request.  They can freely be reused
 * for another stripe.  The "handle_list" contains stripes that need
 * to be handled in some way.  Both of these are fifo queues.  Each
 * stripe is also (potentially) linked to a hash bucket in the hash
 * table so that it can be found by sector number.  Stripes that are
 * not hashed must be on the inactive_list, and will normally be at
 * the front.  All stripes start life this way.
 *
 * The inactive_list, handle_list and hash bucket lists are all protected by the
 * device_lock.
 *  - stripes on the inactive_list never have their stripe_lock held.
 *  - stripes have a reference counter. If count==0, they are on a list.
 *  - If a stripe might need handling, STRIPE_HANDLE is set.
 *  - When refcount reaches zero, then if STRIPE_HANDLE it is put on
 *    handle_list else inactive_list
 *
 * This, combined with the fact that STRIPE_HANDLE is only ever
 * cleared while a stripe has a non-zero count means that if the
 * refcount is 0 and STRIPE_HANDLE is set, then it is on the
 * handle_list and if recount is 0 and STRIPE_HANDLE is not set, then
 * the stripe is on inactive_list.
 *
 * The possible transitions are:
 *  activate an unhashed/inactive stripe (get_active_stripe())
 *     lockdev check-hash unlink-stripe cnt++ clean-stripe hash-stripe unlockdev
 *  activate a hashed, possibly active stripe (get_active_stripe())
 *     lockdev check-hash if(!cnt++)unlink-stripe unlockdev
 *  attach a request to an active stripe (add_stripe_bh())
 *     lockdev attach-buffer unlockdev
 *  handle a stripe (handle_stripe())
 *     lockstripe clrSTRIPE_HANDLE ...
 *		(lockdev check-buffers unlockdev) ..
 *		change-state ..
 *		record io/ops needed unlockstripe schedule io/ops
 *  release an active stripe (release_stripe())
 *     lockdev if (!--cnt) { if  STRIPE_HANDLE, add to handle_list else add to inactive-list } unlockdev
 *
 * The refcount counts each thread that have activated the stripe,
 * plus raid5d if it is handling it, plus one for each active request
 * on a cached buffer, and plus one if the stripe is undergoing stripe
 * operations.
 *
 * Stripe operations are performed outside the stripe lock,
 * the stripe operations are:
 * -copying data between the stripe cache and user application buffers
 * -computing blocks to save a disk access, or to recover a missing block
 * -updating the parity on a write operation (reconstruct write and
 *  read-modify-write)
 * -checking parity correctness
 * -running i/o to disk
 * These operations are carried out by raid5_run_ops which uses the async_tx
 * api to (optionally) offload operations to dedicated hardware engines.
 * When requesting an operation handle_stripe sets the pending bit for the
 * operation and increments the count.  raid5_run_ops is then run whenever
 * the count is non-zero.
 * There are some critical dependencies between the operations that prevent some
 * from being requested while another is in flight.
 * 1/ Parity check operations destroy the in cache version of the parity block,
 *    so we prevent parity dependent operations like writes and compute_blocks
 *    from starting while a check is in progress.  Some dma engines can perform
 *    the check without damaging the parity block, in these cases the parity
 *    block is re-marked up to date (assuming the check was successful) and is
 *    not re-read from disk.
 * 2/ When a write operation is requested we immediately lock the affected
 *    blocks, and mark them as not up to date.  This causes new read requests
 *    to be held off, as well as parity checks and compute block operations.
 * 3/ Once a compute block operation has been requested handle_stripe treats
 *    that block as if it is up to date.  raid5_run_ops guaruntees that any
 *    operation that is dependent on the compute block result is initiated after
 *    the compute block completes.
 */

/*
 * Operations state - intermediate states that are visible outside of sh->lock
 * In general _idle indicates nothing is running, _run indicates a data
 * processing operation is active, and _result means the data processing result
 * is stable and can be acted upon.  For simple operations like biofill and
 * compute that only have an _idle and _run state they are indicated with
 * sh->state flags (STRIPE_BIOFILL_RUN and STRIPE_COMPUTE_RUN)
 */
/**
 * enum check_states - handles syncing / repairing a stripe
 * @check_state_idle - check operations are quiesced
 * @check_state_run - check operation is running
 * @check_state_result - set outside lock when check result is valid
 * @check_state_compute_run - check failed and we are repairing
 * @check_state_compute_result - set outside lock when compute result is valid
 */
enum check_states {
	check_state_idle = 0,
	check_state_run, /* xor parity check */
	check_state_run_q, /* q-parity check */
	check_state_run_pq, /* pq dual parity check */
	check_state_check_result,
	check_state_compute_run, /* parity repair */
	check_state_compute_result,
};

/**
 * enum reconstruct_states - handles writing or expanding a stripe
 */
enum reconstruct_states {
	reconstruct_state_idle = 0,
	reconstruct_state_prexor_drain_run,	/* prexor-write *///表明此条带是"prexor""抽干"异或的执行系列。
	reconstruct_state_drain_run,		/* write */ //表示先"抽干"，再异或的动作系列
	reconstruct_state_run,			/* expand */
	reconstruct_state_prexor_drain_result,
	reconstruct_state_drain_result,
	reconstruct_state_result,
};

struct stripe_head {
	//链接入所属RAID5私有数据描述符的strip_head哈希表的连接件
	struct hlist_node	hash;
	//链入所属RAID5私有数据描述符的inactive_list、delayed_list、hold_list、bitmap_list或handle_list链表的连接件
	struct list_head	lru;	      /* inactive_list or handle_list */
	//指向raid5私有数据描述符的指针
	struct raid5_private_data *raid_conf;
	//在每次reshape时递增
	short			generation;	/* increments with every reshape */
	//条带编号 (实际为此条带在成员磁盘上的起始扇区编号)
	sector_t		sector;		/* sector of this row */
	//校验磁盘编号(P校验)
	short			pd_idx;		/* parity disk index */
	//校验磁盘编号(Q校验)
	short			qd_idx;		/* 'Q' disk index for raid6 */
	//1:表示使用DDF/RAID6来计算Q校验；0:表示使用MD/RAID6来计算Q校验
	short			ddf_layout;/* use DDF ordering to calculate Q */
	//条带状态
	unsigned long		state;		/* state flags */
	/*条带计数器*/
	atomic_t		count;	      /* nr of active thread/requests */
	spinlock_t		lock;
	//位图冲刷次数
	int			bm_seq;	/* sequence number for bitmap flushes */
	/*条带的成员磁盘数*/
	int			disks;		/* disks in stripe */
	//用于检查校验和的状态
	enum check_states	check_state;
	//用于重构校验和的状态
	enum reconstruct_states reconstruct_state;
	/**
	 * struct stripe_operations
	 * @target - STRIPE_OP_COMPUTE_BLK target
	 * @target2 - 2nd compute target in the raid6 case
	 * @zero_sum_result - P and Q verification flags
	 * @request - async service request flags for raid_run_ops
	 */
	struct stripe_operations {
		int 		     target, target2;//两个校验磁盘的编号
		enum sum_check_flags zero_sum_result;//P和Q校验标志
		#ifdef CONFIG_MULTICORE_RAID456
		unsigned long	     request;//用于raid_run_ops的异步服务请求标志
		wait_queue_head_t    wait_for_ops;//用于异步调度的等待队列
		#endif
	} ops;
	struct r5dev {
		struct bio	req;//读写成员磁盘的通用块层请求描述符
		struct bio_vec	vec;//每个请求只包含一个segment
		struct page	*page;//指向用于读/写的页面缓冲区的指针
		
		/*若toread不为NULL表示需要读取成员磁盘；若read不为NULL表示成员磁盘读取操作已经调度。
		*若towrite不为NULL表示需要写入成员磁盘；若written不为NULL表示成员磁盘写入操作已调度。
		*/
		struct bio	*toread, *read, *towrite, *written;
		//相对RAID设备的起始扇区编号
		sector_t	sector;			/* sector of this page */
		//标志，驱动状态机转换
		unsigned long	flags;
	} dev[1]; /* allocated with extra space depending of RAID geometry */
};

/* stripe_head_state - collects and tracks the dynamic state of a stripe_head
 *     for handle_stripe.  It is only valid under spin_lock(sh->lock);
 */
struct stripe_head_state {
	int syncing, expanding, expanded;
	int locked, uptodate, to_read, to_write, failed, written;
	int to_fill, compute, req_compute, non_overwrite;
	int failed_num;
	unsigned long ops_request;
};

/* r6_state - extra state data only relevant to r6 */
struct r6_state {
	int p_failed, q_failed, failed_num[2];
};

/* Flags */
#define	R5_UPTODATE	0	/* page contains current data */
#define	R5_LOCKED	1	/* IO has been submitted on "req" */
#define	R5_OVERWRITE	2	/* towrite covers whole page */
/* and some that are internal to handle_stripe */
#define	R5_Insync	3	/* rdev && rdev->in_sync at start */
#define	R5_Wantread	4	/* want to schedule a read */
#define	R5_Wantwrite	5
#define	R5_Overlap	7	/* There is a pending overlapping request on this block */
#define	R5_ReadError	8	/* seen a read error here recently */
#define	R5_ReWrite	9	/* have tried to over-write the readerror */

#define	R5_Expanded	10	/* This block now has post-expand data */
#define	R5_Wantcompute	11 /* compute_block in progress treat as
				    * uptodate
				    */
#define	R5_Wantfill	12 /* dev->toread contains a bio that needs
				    * filling
				    */
#define R5_Wantdrain	13 /* dev->towrite needs to be drained */
/*
 * Write method
 */
#define RECONSTRUCT_WRITE	1
#define READ_MODIFY_WRITE	2
/* not a write method, but a compute_parity mode */
#define	CHECK_PARITY		3
/* Additional compute_parity mode -- updates the parity w/o LOCKING */
#define UPDATE_PARITY		4

/*
 * Stripe state
 */
#define STRIPE_HANDLE		2	//表示此条带已经更新标志
#define	STRIPE_SYNCING		3
#define	STRIPE_INSYNC		4
#define	STRIPE_PREREAD_ACTIVE	5
#define	STRIPE_DELAYED		6
#define	STRIPE_DEGRADED		7
#define	STRIPE_BIT_DELAY	8
#define	STRIPE_EXPANDING	9
#define	STRIPE_EXPAND_SOURCE	10
#define	STRIPE_EXPAND_READY	11
#define	STRIPE_IO_STARTED	12 /* do not count towards 'bypass_count' */
#define	STRIPE_FULL_WRITE	13 /* all blocks are set to be overwritten */
#define	STRIPE_BIOFILL_RUN	14
#define	STRIPE_COMPUTE_RUN	15	//条带正在计算校验和
#define	STRIPE_OPS_REQ_PENDING	16 //raid_run_ops处理异步操作挂起。

/*
 * Operation request flags
 */
/*将数据复制到请求缓冲区以便满足读请求*/
#define STRIPE_OP_BIOFILL	0
/*在缓存中从其他块生成丢失块*/
#define STRIPE_OP_COMPUTE_BLK	1
/*作为读-改-写过程的一部分异或存在的数据*/
#define STRIPE_OP_PREXOR	2
/*数据从请求缓冲区拷出以满足写请求*/
#define STRIPE_OP_BIODRAIN	3
/*为进入缓存的新数据重新计算校验和*/
#define STRIPE_OP_RECONSTRUCT	4
/*检察检验和正确性*/
#define STRIPE_OP_CHECK	5

/*
 * Plugging:
 *
 * To improve write throughput, we need to delay the handling of some
 * stripes until there has been a chance that several write requests
 * for the one stripe have all been collected.
 * In particular, any write request that would require pre-reading
 * is put on a "delayed" queue until there are no stripes currently
 * in a pre-read phase.  Further, if the "delayed" queue is empty when
 * a stripe is put on it then we "plug" the queue and do not process it
 * until an unplug call is made. (the unplug_io_fn() is called).
 *
 * When preread is initiated on a stripe, we set PREREAD_ACTIVE and add
 * it to the count of prereading stripes.
 * When write is initiated, or the stripe refcnt == 0 (just in case) we
 * clear the PREREAD_ACTIVE flag and decrement the count
 * Whenever the 'handle' queue is empty and the device is not plugged, we
 * move any strips from delayed to handle and clear the DELAYED flag and set
 * PREREAD_ACTIVE.
 * In stripe_handle, if we find pre-reading is necessary, we do it if
 * PREREAD_ACTIVE is set, else we set DELAYED which will send it to the delayed queue.
 * HANDLE gets cleared if stripe_handle leave nothing locked.
 */


struct disk_info {
	mdk_rdev_t	*rdev;
};

struct raid5_private_data {
	struct hlist_head	*stripe_hashtbl;
	/*指向MD设备描述符*/
	mddev_t			*mddev;
	/*MD的备用设备*/
	struct disk_info	*spare;
	/*一个chunk包括多个扇区，此域记录chunk所包含的扇区数(一条带的扇区数)*/
	int			chunk_sectors;
	/*level:RAID级别；algorithm:当前使用的算法(向左不对称、向右不对称、向左对称、向右对称)*/
	int			level, algorithm;
	/*出现故障的成员磁盘数，对RAID4/5此域为1，对RAID6此域为2*/
	int			max_degraded;
	/*成员磁盘数*/
	int			raid_disks;
	/*最大条带数*/
	int			max_nr_stripes;

	/* reshape_progress is the leading edge of a 'reshape'
	 * It has value MaxSector when no reshape is happening
	 * If delta_disks < 0, it is the last sector we started work on,
	 * else is it the next sector to work on.
	 */
	sector_t		reshape_progress;
	/* reshape_safe is the trailing edge of a reshape.  We know that
	 * before (or after) this address, all reshape has completed.
	 */
	sector_t		reshape_safe;
	int			previous_raid_disks;
	int			prev_chunk_sectors;
	int			prev_algo;
	//每次改造时会递增1
	short			generation; /* increments with every reshape */
	//最后一次更新元数据的时间
	unsigned long		reshape_checkpoint; /* Time we last updated metadata */
	/*空闲的条带列表*/
	struct list_head	inactive_list;
	/*需要处理的条带列表*/						 
	struct list_head	handle_list; /* stripes needing handling */
	/*准备好预读的条带链表*/
	struct list_head	hold_list; /* preread ready stripes */
	/*被延迟处理的条带链表*/
	struct list_head	delayed_list; /* stripes that have plugged requests */
	/*因等待位图更新而延迟的条带链表*/
	struct list_head	bitmap_list; /* stripes delaying awaiting bitmap update */
	//当前正在重试的对齐读
	struct bio		*retry_read_aligned; /* currently retrying aligned bios   */
	//在对齐读失败之后，需要重试，这是对齐读bio的重试链表。raid5d线程会从这个链表中取出bio进行重试。
	struct bio		*retry_read_aligned_list; /* aligned bios retry list  */
	//激活预读，即已调度IO的条带数
	atomic_t		preread_active_stripes; /* stripes with scheduled io */
	//活动的对齐读的数目
	atomic_t		active_aligned_reads;
	//待处理的整条写的数目
	atomic_t		pending_full_writes; /* full write backlog */
	//跳过预读的次数。每在hold_list之前处理一次handle_list链表中的stripe_head,该域就递增
	int			bypass_count; /* bypassed prereads */
	
	//预读阀值。当跳过预读的计数器超过此阀值时，就处理一次hold_list链表中的stripe_head.
	int			bypass_threshold; /* preread nice */
	//记录hold_list链表的表头，用来检测是否有被转移到handle_list
	struct list_head	*last_hold; /* detect hold_list promotions */
	//条带数目，这些条带有用于reshape的待处理请求。
	atomic_t		reshape_stripes; /* stripes with pending writes for reshape */
	/* unfortunately we need two cache names as we temporarily have
	 * two caches.
	 */
	//表示当前正使用的stripe_head高速缓存，值0或1，交替变化
	int			active_name;
	//考虑到在线成员磁盘变更，交替使用两个stripe_head高速缓存。这个数据即保存了两个高速缓存的名字。
	char			cache_name[2][32];	
	//指向用于分配stripe_head的高速缓存的指针，交替指向上面提到的两个高速缓存。
	struct kmem_cache		*slab_cache; /* for allocating stripes */
	
	/*seq_flush:记录上一个已经关闭的批次编号；seq_write:记录上一个被成功写入的批次编号
	*注:当支持位图时，要先把位图写入磁盘，后再把数据写入磁盘。seq_flush是在位图写入时递增1，seq_write是在数据写入磁盘时递增1.
	*/
	int			seq_flush, seq_write;
	/*静默，1->等待，0->等待完成*/
	int			quiesce;
	//如果需要进行完全的同步(比如添加一个新的成员磁盘)，则设置此域为1。在同步完后，清0.
	int			fullsync;  /* set to 1 if a full sync is needed,
					    * (fresh device added).
					    * Cleared when a sync completes.
					    */

	struct plug_handle	plug;

	/* per cpu variables */
	struct raid5_percpu {
		struct page	*spare_page; /* Used when checking P/Q in raid6 */
		void		*scribble;   /* space for constructing buffer
					      * lists and performing address
					      * conversions
					      */
	} __percpu *percpu;
	size_t			scribble_len; /* size of scribble region must be
					       * associated with conf to handle
					       * cpu hotplug while reshaping
					       */
#ifdef CONFIG_HOTPLUG_CPU
	struct notifier_block	cpu_notify;
#endif

	/*
	 * Free stripes pool
	 */
	//活动的条带数
	atomic_t		active_stripes;
	//空闲条带是有限的，一旦使用光，则后续申请空闲条带的进程必须在这个队列上等待。 在活动条带使用完成，被释放后，将唤醒该等待队列上的进程。
	wait_queue_head_t	wait_for_stripe;
	//如果两次访问重叠的扇区，则后续访问的进程要在这个队列上等待。前面访问处理结束后，将唤醒在该等待队列上的进程。
	wait_queue_head_t	wait_for_overlap;
	//非活动(空闲)条带的发放(分配)被阻止，等待25%的空闲
	int			inactive_blocked;	/* release of inactive stripes blocked,
							 * waiting for 25% to be free
							 */
	//在存储池中每个strip_head含有的成员磁盘数目(在grow_stripes中用到)。						
	int			pool_size; /* number of disks in stripeheads in pool */
	spinlock_t		device_lock;
	//成员磁盘数组
	struct disk_info	*disks;

	/* When taking over an array from a different personality, we store
	 * the new thread here until we fully activate the array.
	 */
	struct mdk_thread_s	*thread;
};

typedef struct raid5_private_data raid5_conf_t;

/*
 * Our supported algorithms
 */
#define ALGORITHM_LEFT_ASYMMETRIC	0 /* Rotating Parity N with Data Restart */
#define ALGORITHM_RIGHT_ASYMMETRIC	1 /* Rotating Parity 0 with Data Restart */
#define ALGORITHM_LEFT_SYMMETRIC	2 /* Rotating Parity N with Data Continuation */
#define ALGORITHM_RIGHT_SYMMETRIC	3 /* Rotating Parity 0 with Data Continuation */

/* Define non-rotating (raid4) algorithms.  These allow
 * conversion of raid4 to raid5.
 */
#define ALGORITHM_PARITY_0		4 /* P or P,Q are initial devices */
#define ALGORITHM_PARITY_N		5 /* P or P,Q are final devices. */

/* DDF RAID6 layouts differ from md/raid6 layouts in two ways.
 * Firstly, the exact positioning of the parity block is slightly
 * different between the 'LEFT_*' modes of md and the "_N_*" modes
 * of DDF.
 * Secondly, or order of datablocks over which the Q syndrome is computed
 * is different.
 * Consequently we have different layouts for DDF/raid6 than md/raid6.
 * These layouts are from the DDFv1.2 spec.
 * Interestingly DDFv1.2-Errata-A does not specify N_CONTINUE but
 * leaves RLQ=3 as 'Vendor Specific'
 */

#define ALGORITHM_ROTATING_ZERO_RESTART	8 /* DDF PRL=6 RLQ=1 */
#define ALGORITHM_ROTATING_N_RESTART	9 /* DDF PRL=6 RLQ=2 */
#define ALGORITHM_ROTATING_N_CONTINUE	10 /*DDF PRL=6 RLQ=3 */


/* For every RAID5 algorithm we define a RAID6 algorithm
 * with exactly the same layout for data and parity, and
 * with the Q block always on the last device (N-1).
 * This allows trivial conversion from RAID5 to RAID6
 */
#define ALGORITHM_LEFT_ASYMMETRIC_6	16
#define ALGORITHM_RIGHT_ASYMMETRIC_6	17
#define ALGORITHM_LEFT_SYMMETRIC_6	18
#define ALGORITHM_RIGHT_SYMMETRIC_6	19
#define ALGORITHM_PARITY_0_6		20
#define ALGORITHM_PARITY_N_6		ALGORITHM_PARITY_N

static inline int algorithm_valid_raid5(int layout)
{
	return (layout >= 0) &&
		(layout <= 5);
}
static inline int algorithm_valid_raid6(int layout)
{
	return (layout >= 0 && layout <= 5)
		||
		(layout >= 8 && layout <= 10)
		||
		(layout >= 16 && layout <= 20);
}

static inline int algorithm_is_DDF(int layout)
{
	return layout >= 8 && layout <= 10;
}

extern int md_raid5_congested(mddev_t *mddev, int bits);
extern void md_raid5_unplug_device(raid5_conf_t *conf);
extern int raid5_set_cache_size(mddev_t *mddev, int size);
#endif

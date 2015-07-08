/*
   md_k.h : kernel internal structure of the Linux MD driver
          Copyright (C) 1996-98 Ingo Molnar, Gadi Oxman
	  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.
   
   You should have received a copy of the GNU General Public License
   (for example /usr/src/linux/COPYING); if not, write to the Free
   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
*/

#ifndef _MD_MD_H
#define _MD_MD_H

#include <linux/blkdev.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#define MaxSector (~(sector_t)0)

typedef struct mddev_s mddev_t;
typedef struct mdk_rdev_s mdk_rdev_t;

/* generic plugging support - like that provided with request_queue,
 * but does not require a request_queue
 */
struct plug_handle {
	void			(*unplug_fn)(struct plug_handle *);
	struct timer_list	unplug_timer;
	struct work_struct	unplug_work;
	unsigned long		unplug_flag;
};
#define	PLUGGED_FLAG 1 	//"畜流"标志
void plugger_init(struct plug_handle *plug,
		  void (*unplug_fn)(struct plug_handle *));
void plugger_set_plug(struct plug_handle *plug);
int plugger_remove_plug(struct plug_handle *plug);
static inline void plugger_flush(struct plug_handle *plug)
{
	del_timer_sync(&plug->unplug_timer);
	cancel_work_sync(&plug->unplug_work);
}

#define	Faulty		1		/* device is known to have a fault */
#define	In_sync		2		/* device is in_sync with rest of array */
#define	WriteMostly	4		/* Avoid reading if at all possible */
#define	BarriersNotsupp	5		/* REQ_HARDBARRIER is not supported */
#define	AllReserved	6		/* If whole device is reserved for
					 * one array */
#define	AutoDetected	7		/* added by auto-detect */
#define Blocked		8		/* An error occured on an externally
					 * managed array, don't allow writes
					 * until it is cleared */

/*
 * MD's 'extended' device
 */
/*MD成员磁盘对象*/
struct mdk_rdev_s
{
	//MD设备成员磁盘的连接件，链表头为mddev_s:disks
	struct list_head same_set;	/* RAID devices within the same set */
	//成员磁盘的大小(以扇区为单位)
	sector_t sectors;		/* Device size (in 512bytes sectors) */
	//所属的MD设备对象
	mddev_t *mddev;			/* RAID array if running */
	//IO事件时间戳，用来判断MD设备最近是否空闲，以决定同步是否给正常IO"让路"
	int last_events;		/* IO event timestamp */
	//成员磁盘对应的块设备描述符指针
	struct block_device *bdev;	/* block device handle */
	//存放超级块的页面
	struct page	*sb_page;
	//此成员磁盘的超级块是否已经读入内存
	int		sb_loaded;
	//RAID超级块的更新计数器。此值越大，超级块越新。在装载MD设备时，从所有成员磁盘读取RAID超级块，从中取出最新的作为MD设备的RAID超级块。
	__u64		sb_events;
	//这个成员磁盘的阵列数据的起始位置
	sector_t	data_offset;	/* start of data in array */
	//RAID超级块保存在成员磁盘上的起始扇区编号。
	sector_t 	sb_start;	/* offset of the super block (in 512byte sectors) */
	//超级块的字节数据
	int		sb_size;	/* bytes in the superblock */
	//在自动运行MD设备时采用的次设备号
	int		preferred_minor;	/* autorun support */

	struct kobject	kobj;

	/* A device can be in one of three states based on two flags:
	 * Not working:   faulty==1 in_sync==0
	 * Fully working: faulty==0 in_sync==1
	 * Working, but not
	 * in sync with array
	 *                faulty==0 in_sync==0
	 *
	 * It can never have faulty==1, in_sync==1
	 * This reduces the burden of testing multiple flags in many cases
	 */

	unsigned long	flags;

	wait_queue_head_t blocked_wait;

	int desc_nr;			/* descriptor index in the superblock */
	//成员磁盘在磁盘阵列中的下标
	int raid_disk;			/* role of device in array */
	int new_raid_disk;		/* role that the device will have in
					 * the array after a level-change completes.
					 */
	int saved_raid_disk;		/* role that device used to have in the
					 * array and could again if we did a partial
					 * resync from the bitmap
					 */
	sector_t	recovery_offset;/* If this device has been partially
					 * recovered, this is where we were
					 * up to.
					 */
	//正在处理的请求数目。只为支持热"移除"的阵列维护
	atomic_t	nr_pending;	/* number of pending requests.
					 * only maintained for arrays that
					 * support hot removal
					 */
	//连续读错误的次数。若超过一定阈值时，使该磁盘失效；若有一次成员读取，则清零，重新计数。					 
	atomic_t	read_errors;	/* number of consecutive read errors that we have tried to ignore.	 */
					 	
	//距离上次读操作出错的时间。被RAID10个性用来"修正"读错误。					 	
	struct timespec last_read_error;	/* monotonic time since our last read error */
	//纠正了读错误数目。为了报告到用户空间，并保存到超级块中。
	atomic_t	corrected_errors; /* number of corrected read errors, for reporting to userspace and storing in superblock. */
	//用于销毁此结构时需要延迟。
	struct work_struct del_work;	/* used for delayed sysfs removal */
	
	//用于向用户空间报告成员磁盘持续改变的状态信息。对应sysfs文件系统中中成员磁盘目录下的state文件。
	struct sysfs_dirent *sysfs_state; /* handle for 'state' sysfs entry */
};

#define MD_CHANGE_DEVS	0	/* Some device status has changed */
#define MD_CHANGE_CLEAN 1	/* transition to or from 'clean' */
#define MD_CHANGE_PENDING 2	/* switch from 'clean' to 'active' in progress */

#define	UNTIL_IOCTL	1
#define	UNTIL_STOP	2

	/* recovery/resync flags 
	 * NEEDED:   we might need to start a resync/recover
	 * RUNNING:  a thread is running, or about to be started
	 * SYNC:     actually doing a resync, not a recovery
	 * RECOVER:  doing recovery, or need to try it.
	 * INTR:     resync needs to be aborted for some reason
	 * DONE:     thread is done and is waiting to be reaped
	 * REQUEST:  user-space has requested a sync (used with SYNC)
	 * CHECK:    user-space request for check-only, no repair
	 * RESHAPE:  A reshape is happening
	 *
	 * If neither SYNC or RESHAPE are set, then it is a recovery.
	 */
#define	MD_RECOVERY_RUNNING	0
#define	MD_RECOVERY_SYNC	1
#define	MD_RECOVERY_RECOVER	2
#define	MD_RECOVERY_INTR	3
#define	MD_RECOVERY_DONE	4
#define	MD_RECOVERY_NEEDED	5
#define	MD_RECOVERY_REQUESTED	6
#define	MD_RECOVERY_CHECK	7
#define MD_RECOVERY_RESHAPE	8
#define	MD_RECOVERY_FROZEN	9
struct mddev_s
{
	//私有对象为个性私有数据结构
	void				*private;
	//个性操作对象
	struct mdk_personality		*pers;
	//设备号
	dev_t				unit;
	//MD设备的次设备号
	int				md_minor;
	//MD设备的所有成员设备链表头
	struct list_head 		disks;
	
	unsigned long			flags;


	int				suspended;
	//发给个性处理的IO个数(request个数)，在调用个性make_request前递增，处理完make_request后递减
	atomic_t			active_io;
	/*0:表示可写，1:表示只读，2:表示只读，但在第一次写时自动转为可写，即将数据标记为"脏"*/
	int				ro;
	int				sysfs_active; /* set when sysfs deletes
						       * are happening, so run/
						       * takeover/stop are not safe
						       */
	//MD通用磁盘对象
	struct gendisk			*gendisk;

	struct kobject			kobj;
	//MD对象保持到什么时候可以释放. UNITL_IOCTL:表示保存到IOCTL结束；UNTIL_STOP保持到MD设备停止，为表示可以释放。
	int				hold_active;

	/*超级块的主版本号、次版本号、补丁版本号*/
	/* Superblock information */
	int				major_version,
					minor_version,
					patch_version;
	//是否有持久化的超级块
	int				persistent;
	//external=1表示元数据由外部管理(如用户空间)
	int 				external;	/* metadata is managed externally */
	char				metadata_type[17]; /* externally set*/
	/*一个条带的扇区数*/							 
	int				chunk_sectors;
	//MD设备的创建时间和修改时间
	time_t				ctime, utime;
	/*level:RAID级别，layout:只对部分RAID有效(向左、向右/对称、不对称)*/
	int				level, layout;
	//MD设备的级别(字符串形式)
	char				clevel[16];
	//成员磁盘个数
	int				raid_disks;
	//最大的成员磁盘个数
	int				max_disks;
	
	sector_t			dev_sectors; 	/* used size of component devices */
	//导出的阵列长度
	sector_t			array_sectors; /* exported array size */
	
	int				external_size; /* size managed externally */
	/*
	*events:MD设备的更新计数器，在创建MD设备时清零，每次发生重的事件时，如启动阵列、停止阵列、添加设备、备用激活等，此值都递增1次。
	*记录在MD设备的超级块中，因此比较从各个成员磁盘的超级块的这个计数器可以知道哪个成员磁盘更新。
	*/
	__u64				events;
	/* If the last 'event' was simply a clean->dirty transition, and
	 * we didn't write it to the spares, then it is safe and simple
	 * to just decrement the event count on a dirty->clean transition.
	 * So we record that possibility here.
	 */
	int				can_decrease_events;
	//MD设备的唯一标识
	char				uuid[16];

	/* If the array is being reshaped, we need to record the
	 * new shape and an indication of where we are up to.
	 * This is written to the superblock.
	 * If reshape_position is MaxSector, then no reshape is happening (yet).
	 */
	/*记录上次reshape到的位置，下次启动RAID设备时可以从这个位置开始继续reshape,而无须从头来过。为MaxSector表示没有进行reshape,或reshape已完成*/
	sector_t			reshape_position;
	/*delta_disks:Reshape对成员磁盘改变的个数、new_level:Reshape新的RAID级别、new_layout:Reshape新的布局*/
	int				delta_disks, new_level, new_layout;
	/*Reshape:新的chunk长度(条带的扇区数)*/
	int				new_chunk_sectors;
	//指向管理线程描述符指针。仅适用于某些RAID个性，如RAID5
	struct mdk_thread_s		*thread;	/* management thread */
	//指向同步线程描述符的指针。
	struct mdk_thread_s		*sync_thread;	/* doing resync or reconstruct */
	//最近已经调度的块。
	sector_t			curr_resync;	/* last block scheduled */
	/* As resync requests can complete out of order, we cannot easily track
	 * how much resync has been completed.  So we occasionally pause until
	 * everything completes, then set curr_resync_completed to curr_resync.
	 * As such it may be well behind the real resync mark, but it is a value
	 * we are certain of.
	 */
	sector_t			curr_resync_completed;
	unsigned long			resync_mark;	/* a recent timestamp */
	sector_t			resync_mark_cnt;/* blocks written at resync_mark */
	sector_t			curr_mark_cnt; /* blocks scheduled now */

	sector_t			resync_max_sectors; /* may be set by personality */

	sector_t			resync_mismatches; /* count of sectors where
							    * parity/replica mismatch found
							    */
	/*允许用户空间预留IO的区间*/
	/* allow user-space to request suspension of IO to regions of the array */
	sector_t			suspend_lo;
	sector_t			suspend_hi;
	/* if zero, use the system-wide default */
	int				sync_speed_min;
	int				sync_speed_max;

	/* resync even though the same disks are shared among md-devices */
	int				parallel_resync;

	int				ok_start_degraded;

	//同步/恢复标志
	unsigned long			recovery;
	//当必恢复失败多次后，就把此值设置成1。禁止尝试
	int				recovery_disabled; /* if we detect that recovery
							    * will always fail, set this
							    * so we don't loop trying */
	/*in_sync=1表示RAID处理同步状态，不需要同步了。因为只有写操作才会引起条带不同步的情况(比如没有同时写入数据单元和校验单元时掉电)。
	*因此，在发起写操作时将此值清0，同步完后，置1.
	*/
	int				in_sync;	/* know to not need resync */
	/* 'open_mutex' avoids races between 'md_open' and 'do_md_stop', so
	 * that we are never stopping an array while it is open.
	 * 'reconfig_mutex' protects all other reconfiguration.
	 * These locks are separate due to conflicting interactions
	 * with bdev->bd_mutex.
	 * Lock ordering is:
	 *  reconfig_mutex -> bd_mutex : e.g. do_md_run -> revalidate_disk
	 *  bd_mutex -> open_mutex:  e.g. __blkdev_get -> md_open
	 */
	struct mutex			open_mutex;
	struct mutex			reconfig_mutex;
	//
	atomic_t			active;		/* general refcount */
	//MD设备被打开的次数
	atomic_t			openers;	/* number of active opens */
	//已经出现故障的成员磁盘数目
	int				degraded;	/* whether md should consider adding a spare */
	
	int				barriers_work;	/* initialised to true, cleared as soon
							 * as a barrier request to slave
							 * fails.  Only supported
							 */
	/*对超级块的写最好也以屏障请求实现，但万一低层设备不支持屏障，则将bio添加到此链表中，以便重试*/							
	struct bio			*biolist; 	/* bios that need to be retried because REQ_HARDBARRIER is not supported */
	//已经写入的块数。在提交同步时加1，同步完成减1.
	atomic_t			recovery_active; /* blocks scheduled, but not written */
	//同步/恢复等待队列
	wait_queue_head_t		recovery_wait;
	/*记录上次同步的位置，下次启动RAID设备时可以从这个位置开始继续同步，而无须从头来过。为MaxSector表示没有进行同步，或同步已完成。
	*精确地说，这仅用于同步，恢复的当前位置被记录在要恢复成员磁盘的recovery_offset域。
	*/
	sector_t			recovery_cp;
	//用户请求同步从这里开始
	sector_t			resync_min;	/* user requested sync starts here */
	//用户请求同步到这里结束
	sector_t			resync_max;	/* resync should pause when it gets here */
	//用来向用户空间传递RAID设备的持续改变的状态信息，对就用sysfs文件系统中的RAID设备目录下的array_state文件
	struct sysfs_dirent		*sysfs_state;	/* handle for 'array_state'
							 * file in sysfs.
							 */
	//被用来向用户空间传递RAID设备的持续改变的同步动作，对就用sysfs文件系统中的RAID设备目录下的sync_action文件
	struct sysfs_dirent		*sysfs_action;  /* handle for 'sync_action' */
	//用于延迟销毁MD设备的工作队列
	struct work_struct del_work;	/* used for delayed sysfs removal */

	spinlock_t			write_lock;
	wait_queue_head_t		sb_wait;	/* for waiting on superblock updates */
	//活动的超级块写的数目
	atomic_t			pending_writes;	/* number of active superblock writes */
	/*安全模式 :当MD设备阵列在一段时间没有写请求时，它将被标志为"Clean"。在另一个写请求到来时，在写开始之前阵列被标记为"Dirty"。这就是安全模式。
	*取值为0,1,2。
	*1->表示在一段时间没有待处理的写请求时(一般为几秒)，更新超级块，将它标志为"Clean"，以减少在重启时将阵列被认作"脏"的机会。在超级块更新，
	*设置了"Clean"标志后，又将safemode域清零。
	*2->又称为"立即安全模式"，是上面的超时时间为0的情况，也就是说在没有等待处理的写请求，或所有当前写请求都已经执行完成，就理解将MD阵列记为"Clean"。
	*如果设置为2，表示在没有待处理的写请求时更新"Clean"超级块。
	*/
	unsigned int			safemode;	/* if set, update "clean" superblock
							 * when no writes pending.
							 */ 
	/*安全超时时间*/
	unsigned int			safemode_delay;
	/*安全模式定时器*/							 
	struct timer_list		safemode_timer;
	//正在处理的写请求数目。在开始写请求前的md_write_start函数中递增，在完成写请求后的md_write_end函数递减
	atomic_t			writes_pending; 
	//MD设备的请求队列
	struct request_queue		*queue;	/* for plugging ... */
	//设备的位图描述符对象
	struct bitmap                   *bitmap; /* the bitmap for the device */
	
	struct {
		struct file		*file; /* the bitmap file */
		loff_t			offset; /* offset from superblock of
						 * start of bitmap. May be
						 * negative, but not '0'
						 * For external metadata, offset
						 * from start of device. 
						 */
		loff_t			default_offset; /* this is the offset to use when
							 * hot-adding a bitmap.  It should
							 * eventually be settable by sysfs.
							 */
		/* When md is serving under dm, it might use a
		 * dirty_log to store the bits.
		 */
		struct dm_dirty_log *log;

		struct mutex		mutex;
		unsigned long		chunksize;
		unsigned long		daemon_sleep; /* how many jiffies between updates? */
		unsigned long		max_write_behind; /* write-behind mode */
		int			external;
	} bitmap_info;
	//最大读重试次数
	atomic_t 			max_corr_read_errors; /* max read retries */
	//连接到所有MD设备链表的连接件，链表头为全局变量all_mddevs
	struct list_head		all_mddevs;

	struct attribute_group		*to_remove;
	struct plug_handle		*plug; /* if used by personality */

	/* Generic barrier handling.
	 * If there is a pending barrier request, all other
	 * writes are blocked while the devices are flushed.
	 * The last to finish a flush schedules a worker to
	 * submit the barrier request (without the barrier flag),
	 * then submit more flush requests.
	 */
	struct bio *barrier;
	atomic_t flush_pending;
	struct work_struct barrier_work;
	struct work_struct event_work;	/* used by dm to report failure event */
};


static inline void rdev_dec_pending(mdk_rdev_t *rdev, mddev_t *mddev)
{
	int faulty = test_bit(Faulty, &rdev->flags);
	if (atomic_dec_and_test(&rdev->nr_pending) && faulty)
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
}

static inline void md_sync_acct(struct block_device *bdev, unsigned long nr_sectors)
{
        atomic_add(nr_sectors, &bdev->bd_contains->bd_disk->sync_io);
}
/**ltl
功能:MD个性描述符
*/
struct mdk_personality
{
	char *name;				//MD个性名称
	int level;				//MD个性级别
	struct list_head list;//连接件。用于在注册时将此个性连接到全局变量pers_list链表中
	struct module *owner;
	//MD个性处理请求的特有逻辑
	int (*make_request)(mddev_t *mddev, struct bio *bio);
	//启动MD个性时调用
	int (*run)(mddev_t *mddev);
	int (*stop)(mddev_t *mddev);
	void (*status)(struct seq_file *seq, mddev_t *mddev);
	/* error_handler must set ->faulty and clear ->in_sync
	 * if appropriate, and should abort recovery if needed 
	 */
	void (*error_handler)(mddev_t *mddev, mdk_rdev_t *rdev);
	int (*hot_add_disk) (mddev_t *mddev, mdk_rdev_t *rdev);
	int (*hot_remove_disk) (mddev_t *mddev, int number);
	int (*spare_active) (mddev_t *mddev);
	sector_t (*sync_request)(mddev_t *mddev, sector_t sector_nr, int *skipped, int go_faster);
	int (*resize) (mddev_t *mddev, sector_t sectors);
	sector_t (*size) (mddev_t *mddev, sector_t sectors, int raid_disks);
	int (*check_reshape) (mddev_t *mddev);
	int (*start_reshape) (mddev_t *mddev);
	void (*finish_reshape) (mddev_t *mddev);
	/* quiesce moves between quiescence states
	 * 0 - fully active
	 * 1 - no new requests allowed
	 * others - reserved
	 */
	void (*quiesce) (mddev_t *mddev, int state);
	/* takeover is used to transition an array from one
	 * personality to another.  The new personality must be able
	 * to handle the data in the current layout.
	 * e.g. 2drive raid1 -> 2drive raid5
	 *      ndrive raid5 -> degraded n+1drive raid6 with special layout
	 * If the takeover succeeds, a new 'private' structure is returned.
	 * This needs to be installed and then ->run used to activate the
	 * array.
	 */
	void *(*takeover) (mddev_t *mddev);
};


struct md_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(mddev_t *, char *);
	ssize_t (*store)(mddev_t *, const char *, size_t);
};
extern struct attribute_group md_bitmap_group;

static inline struct sysfs_dirent *sysfs_get_dirent_safe(struct sysfs_dirent *sd, char *name)
{
	if (sd)
		return sysfs_get_dirent(sd, NULL, name);
	return sd;
}
static inline void sysfs_notify_dirent_safe(struct sysfs_dirent *sd)
{
	if (sd)
		sysfs_notify_dirent(sd);
}

static inline char * mdname (mddev_t * mddev)
{
	return mddev->gendisk ? mddev->gendisk->disk_name : "mdX";
}

/*
 * iterates through some rdev ringlist. It's safe to remove the
 * current 'rdev'. Dont touch 'tmp' though.
 */
#define rdev_for_each_list(rdev, tmp, head)				\
	list_for_each_entry_safe(rdev, tmp, head, same_set)

/*
 * iterates through the 'same array disks' ringlist
 */
#define rdev_for_each(rdev, tmp, mddev)				\
	list_for_each_entry_safe(rdev, tmp, &((mddev)->disks), same_set)

#define rdev_for_each_rcu(rdev, mddev)				\
	list_for_each_entry_rcu(rdev, &((mddev)->disks), same_set)

typedef struct mdk_thread_s {
	void			(*run) (mddev_t *mddev);
	mddev_t			*mddev;
	wait_queue_head_t	wqueue;
	unsigned long           flags;
	struct task_struct	*tsk;
	unsigned long		timeout;
} mdk_thread_t;

#define THREAD_WAKEUP  0

#define __wait_event_lock_irq(wq, condition, lock, cmd) 		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_UNINTERRUPTIBLE);		\
		if (condition)						\
			break;						\
		spin_unlock_irq(&lock);					\
		cmd;							\
		schedule();						\
		spin_lock_irq(&lock);					\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

#define wait_event_lock_irq(wq, condition, lock, cmd) 			\
do {									\
	if (condition)	 						\
		break;							\
	__wait_event_lock_irq(wq, condition, lock, cmd);		\
} while (0)

static inline void safe_put_page(struct page *p)
{
	if (p) put_page(p);
}

extern int register_md_personality(struct mdk_personality *p);
extern int unregister_md_personality(struct mdk_personality *p);
extern mdk_thread_t * md_register_thread(void (*run) (mddev_t *mddev),
				mddev_t *mddev, const char *name);
extern void md_unregister_thread(mdk_thread_t *thread);
extern void md_wakeup_thread(mdk_thread_t *thread);
extern void md_check_recovery(mddev_t *mddev);
extern void md_write_start(mddev_t *mddev, struct bio *bi);
extern void md_write_end(mddev_t *mddev);
extern void md_done_sync(mddev_t *mddev, int blocks, int ok);
extern void md_error(mddev_t *mddev, mdk_rdev_t *rdev);

extern int mddev_congested(mddev_t *mddev, int bits);
extern void md_barrier_request(mddev_t *mddev, struct bio *bio);
extern void md_super_write(mddev_t *mddev, mdk_rdev_t *rdev,
			   sector_t sector, int size, struct page *page);
extern void md_super_wait(mddev_t *mddev);
extern int sync_page_io(struct block_device *bdev, sector_t sector, int size,
			struct page *page, int rw);
extern void md_do_sync(mddev_t *mddev);
extern void md_new_event(mddev_t *mddev);
extern int md_allow_write(mddev_t *mddev);
extern void md_wait_for_blocked_rdev(mdk_rdev_t *rdev, mddev_t *mddev);
extern void md_set_array_sectors(mddev_t *mddev, sector_t array_sectors);
extern int md_check_no_bitmap(mddev_t *mddev);
extern int md_integrity_register(mddev_t *mddev);
extern void md_integrity_add_rdev(mdk_rdev_t *rdev, mddev_t *mddev);
extern int strict_strtoul_scaled(const char *cp, unsigned long *res, int scale);
extern void restore_bitmap_write_access(struct file *file);
extern void md_unplug(mddev_t *mddev);

extern void mddev_init(mddev_t *mddev);
extern int md_run(mddev_t *mddev);
extern void md_stop(mddev_t *mddev);
extern void md_stop_writes(mddev_t *mddev);
extern void md_rdev_init(mdk_rdev_t *rdev);

extern void mddev_suspend(mddev_t *mddev);
extern void mddev_resume(mddev_t *mddev);
#endif /* _MD_MD_H */

/*
 * raid5.c : Multiple Devices driver for Linux
 *	   Copyright (C) 1996, 1997 Ingo Molnar, Miguel de Icaza, Gadi Oxman
 *	   Copyright (C) 1999, 2000 Ingo Molnar
 *	   Copyright (C) 2002, 2003 H. Peter Anvin
 *
 * RAID-4/5/6 management functions.
 * Thanks to Penguin Computing for making the RAID-6 development possible
 * by donating a test server!
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * You should have received a copy of the GNU General Public License
 * (for example /usr/src/linux/COPYING); if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * BITMAP UNPLUGGING:
 *
 * The sequencing for updating the bitmap reliably is a little
 * subtle (and I got it wrong the first time) so it deserves some
 * explanation.
 *
 * We group bitmap updates into batches.  Each batch has a number.
 * We may write out several batches at once, but that isn't very important.
 * conf->bm_write is the number of the last batch successfully written.
 * conf->bm_flush is the number of the last batch that was closed to
 *    new additions.
 * When we discover that we will need to write to any block in a stripe
 * (in add_stripe_bio) we update the in-memory bitmap and record in sh->bm_seq
 * the number of the batch it will be in. This is bm_flush+1.
 * When we are ready to do a write, if that batch hasn't been written yet,
 *   we plug the array and queue the stripe for later.
 * When an unplug happens, we increment bm_flush, thus closing the current
 *   batch.
 * When we notice that bm_flush > bm_write, we write out all pending updates
 * to the bitmap, and advance bm_write to where bm_flush was.
 * This may occasionally write a bit out twice, but is sure never to
 * miss any bits.
 */

/*
*RAID5基本原理:奇偶校验可以保证数据运算后的位数不变，而且参加运算中的任何一个数都可以由其它的数异或产生
*/

#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/raid/pq.h>
#include <linux/async_tx.h>
#include <linux/async.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include "md.h"
#include "raid5.h"
#include "raid0.h"
#include "bitmap.h"

/*
 * Stripe cache
 */

#define NR_STRIPES		256
#define STRIPE_SIZE		PAGE_SIZE
#define STRIPE_SHIFT		(PAGE_SHIFT - 9)
#define STRIPE_SECTORS		(STRIPE_SIZE>>9)
#define	IO_THRESHOLD		1
#define BYPASS_THRESHOLD	1
#define NR_HASH			(PAGE_SIZE / sizeof(struct hlist_head))
#define HASH_MASK		(NR_HASH - 1)

#define stripe_hash(conf, sect)	(&((conf)->stripe_hashtbl[((sect) >> STRIPE_SHIFT) & HASH_MASK]))

/* bio's attached to a stripe+device for I/O are linked together in bi_sector
 * order without overlap.  There may be several bio's per stripe+device, and
 * a bio could span several devices.
 * When walking this list for a particular stripe+device, we must never proceed
 * beyond a bio that extends past this device, as the next bio might no longer
 * be valid.
 * This macro is used to determine the 'next' bio in the list, given the sector
 * of the current stripe+device
 */
/*
*给出作用于当前条带/设备的一个bio,以及当前条带/设备的起始扇区编号，返回相关bio链表中作用于当前条带设备的下一个bio.若没有，返回NULL.
*判定条件:输入bio的结束扇区是否已在当前条带/设备之外。
*/
#define r5_next_bio(bio, sect) ( ( (bio)->bi_sector + ((bio)->bi_size>>9) < sect + STRIPE_SECTORS) ? (bio)->bi_next : NULL)
/*
 * The following can be used to debug the driver
 */
#define RAID5_PARANOIA	1
#if RAID5_PARANOIA && defined(CONFIG_SMP)
# define CHECK_DEVLOCK() assert_spin_locked(&conf->device_lock)
#else
# define CHECK_DEVLOCK()
#endif

#ifdef DEBUG
#define inline
#define __inline__
#endif

#define printk_rl(args...) ((void) (printk_ratelimit() && printk(args)))

/*
 * We maintain a biased count of active stripes in the bottom 16 bits of
 * bi_phys_segments, and a count of processed stripes in the upper 16 bits
 */
static inline int raid5_bi_phys_segments(struct bio *bio)
{
	return bio->bi_phys_segments & 0xffff;
}

static inline int raid5_bi_hw_segments(struct bio *bio)
{
	return (bio->bi_phys_segments >> 16) & 0xffff;
}

static inline int raid5_dec_bi_phys_segments(struct bio *bio)
{
	--bio->bi_phys_segments;
	return raid5_bi_phys_segments(bio);
}

static inline int raid5_dec_bi_hw_segments(struct bio *bio)
{
	unsigned short val = raid5_bi_hw_segments(bio);

	--val;
	bio->bi_phys_segments = (val << 16) | raid5_bi_phys_segments(bio);
	return val;
}

static inline void raid5_set_bi_hw_segments(struct bio *bio, unsigned int cnt)
{
	bio->bi_phys_segments = raid5_bi_phys_segments(bio) || (cnt << 16);
}

/* Find first data disk in a raid6 stripe */
static inline int raid6_d0(struct stripe_head *sh)
{
	if (sh->ddf_layout)
		/* ddf always start from first device */
		return 0;
	/* md starts just after Q block */
	if (sh->qd_idx == sh->disks - 1)
		return 0;
	else
		return sh->qd_idx + 1;
}
static inline int raid6_next_disk(int disk, int raid_disks)
{
	disk++;
	return (disk < raid_disks) ? disk : 0;
}

/* When walking through the disks in a raid5, starting at raid6_d0,
 * We need to map each disk to a 'slot', where the data disks are slot
 * 0 .. raid_disks-3, the parity disk is raid_disks-2 and the Q disk
 * is raid_disks-1.  This help does that mapping.
 */
static int raid6_idx_to_slot(int idx, struct stripe_head *sh,
			     int *count, int syndrome_disks)
{
	int slot = *count;

	if (sh->ddf_layout)
		(*count)++;
	if (idx == sh->pd_idx)
		return syndrome_disks;
	if (idx == sh->qd_idx)
		return syndrome_disks + 1;
	if (!sh->ddf_layout)
		(*count)++;
	return slot;
}

static void return_io(struct bio *return_bi)
{
	struct bio *bi = return_bi;
	while (bi) {

		return_bi = bi->bi_next;
		bi->bi_next = NULL;
		bi->bi_size = 0;
		bio_endio(bi, 0);
		bi = return_bi;
	}
}

static void print_raid5_conf (raid5_conf_t *conf);

static int stripe_operations_active(struct stripe_head *sh)
{
	return sh->check_state || sh->reconstruct_state ||
	       test_bit(STRIPE_BIOFILL_RUN, &sh->state) ||
	       test_bit(STRIPE_COMPUTE_RUN, &sh->state);
}

static void __release_stripe(raid5_conf_t *conf, struct stripe_head *sh)
{
	//判定条带的引用记数器，在get_active_stripe和handle_strip对count+1.
	if (atomic_dec_and_test(&sh->count)) 
	{
		BUG_ON(!list_empty(&sh->lru));
		BUG_ON(atomic_read(&conf->active_stripes)==0);
		//设置了STRIPE_HANDLE标志
		if (test_bit(STRIPE_HANDLE, &sh->state)) 
		{
			//在handle_stripe_dirtying5中设置STRIPE_DELAYED标志。
			if (test_bit(STRIPE_DELAYED, &sh->state))
			{
				list_add_tail(&sh->lru, &conf->delayed_list);
				plugger_set_plug(&conf->plug);
			}
			else if (test_bit(STRIPE_BIT_DELAY, &sh->state) &&
				   sh->bm_seq - conf->seq_write > 0)
			{//设置了STRIPE_BIT_DELAY标志，并且它所有批次的位图还没有被冲刷到磁盘。
				list_add_tail(&sh->lru, &conf->bitmap_list);
				plugger_set_plug(&conf->plug);//畜流
			} 
			else 
			{
				clear_bit(STRIPE_BIT_DELAY, &sh->state);
				list_add_tail(&sh->lru, &conf->handle_list);
			}
			//唤醒RAID5守护线程raid5d
			md_wakeup_thread(conf->mddev->thread);
		}
		else 
		{//没有设置STRIPE_HANDLE，说明此条带已经处理完毕。
			BUG_ON(stripe_operations_active(sh));
			if (test_and_clear_bit(STRIPE_PREREAD_ACTIVE, &sh->state)) 
			{
				atomic_dec(&conf->preread_active_stripes);
				if (atomic_read(&conf->preread_active_stripes) < IO_THRESHOLD)
					md_wakeup_thread(conf->mddev->thread);
			}
			atomic_dec(&conf->active_stripes);
			
			//注:在函数grow_one_stripe中分配新的stripe_head对象，走这个流程将其插入到inactive_list链表中。因为在分配时state=0
			if (!test_bit(STRIPE_EXPANDING, &sh->state))
			{
				list_add_tail(&sh->lru, &conf->inactive_list);
				//唤醒等待空闲条带的线程
				wake_up(&conf->wait_for_stripe);
				if (conf->retry_read_aligned)
					md_wakeup_thread(conf->mddev->thread);
			}
		}
	}
}
/**ltl
功能:将处于"游离"状态的条带放入某个链表。
参数:sh	->
说明:函数名有些名不符实，它的代码逻辑和"释放"没有任何关系。
*/
static void release_stripe(struct stripe_head *sh)
{
	raid5_conf_t *conf = sh->raid_conf;
	unsigned long flags;

	spin_lock_irqsave(&conf->device_lock, flags);
	__release_stripe(conf, sh);
	spin_unlock_irqrestore(&conf->device_lock, flags);
}

static inline void remove_hash(struct stripe_head *sh)
{
	pr_debug("remove_hash(), stripe %llu\n",
		(unsigned long long)sh->sector);

	hlist_del_init(&sh->hash);
}

static inline void insert_hash(raid5_conf_t *conf, struct stripe_head *sh)
{
	struct hlist_head *hp = stripe_hash(conf, sh->sector);

	pr_debug("insert_hash(), stripe %llu\n",(unsigned long long)sh->sector);

	CHECK_DEVLOCK();
	hlist_add_head(&sh->hash, hp);
}


/* find an idle stripe, make sure it is unhashed, and return it. */
/**ltl
功能:从inactive_list列表中获取一个空闲的条带对象
参数:
返回值:
说明:得到的对象要处理于"游离"状态，即要脱离列表和Hash
*/
static struct stripe_head *get_free_stripe(raid5_conf_t *conf)
{
	struct stripe_head *sh = NULL;
	struct list_head *first;

	CHECK_DEVLOCK();
	//列表是否为空
	if (list_empty(&conf->inactive_list))
		goto out;
	//获取列表头的对象
	first = conf->inactive_list.next;
	sh = list_entry(first, struct stripe_head, lru);
	list_del_init(first);//从列表中删除
	remove_hash(sh);//从Hash中删除对象
	atomic_inc(&conf->active_stripes);//增加条带引用计数器
out:
	return sh;
}

static void shrink_buffers(struct stripe_head *sh)
{
	struct page *p;
	int i;
	int num = sh->raid_conf->pool_size;

	for (i = 0; i < num ; i++) {
		p = sh->dev[i].page;
		if (!p)
			continue;
		sh->dev[i].page = NULL;
		put_page(p);
	}
}

static int grow_buffers(struct stripe_head *sh)
{
	int i;
	int num = sh->raid_conf->pool_size;

	for (i = 0; i < num; i++) {
		struct page *page;

		if (!(page = alloc_page(GFP_KERNEL))) {
			return 1;
		}
		sh->dev[i].page = page;
	}
	return 0;
}

static void raid5_build_block(struct stripe_head *sh, int i, int previous);
static void stripe_set_idx(sector_t stripe, raid5_conf_t *conf, int previous,
			    struct stripe_head *sh);
/**ltl
功能:初始化条带头。
参数:
说明:
*/
static void init_stripe(struct stripe_head *sh, sector_t sector, int previous)
{
	raid5_conf_t *conf = sh->raid_conf;
	int i;

	BUG_ON(atomic_read(&sh->count) != 0);//条带的使用计数器
	BUG_ON(test_bit(STRIPE_HANDLE, &sh->state));//表示此条带正在处理
	BUG_ON(stripe_operations_active(sh));//条带正处理于被处理状态。

	CHECK_DEVLOCK();
	pr_debug("init_stripe called, stripe %llu\n",(unsigned long long)sh->sector);
	//从hash中移除。
	remove_hash(sh);

	sh->generation = conf->generation - previous;
	//条带成员磁盘数。
	sh->disks = previous ? conf->previous_raid_disks : conf->raid_disks;
	//条带的扇区编号
	sh->sector = sector;
	//条带校验信息
	stripe_set_idx(sector, conf, previous, sh);
	sh->state = 0;

	//
	for (i = sh->disks; i--; ) 
	{
		struct r5dev *dev = &sh->dev[i];

		if (dev->toread || dev->read || dev->towrite || dev->written ||
		    test_bit(R5_LOCKED, &dev->flags))
		{
			printk(KERN_ERR "sector=%llx i=%d %p %p %p %p %d\n",
			       (unsigned long long)sh->sector, i, dev->toread,
			       dev->read, dev->towrite, dev->written,
			       test_bit(R5_LOCKED, &dev->flags));
			BUG();
		}
		dev->flags = 0;
		raid5_build_block(sh, i, previous);
	}
	//条带插入到Hash表中。
	insert_hash(conf, sh);
}
/**ltl
功能:在Hash表中查找条带对象
参数:
返回值:
说明:raid5_conf_t结构中的成员stripe_hashtbl就是此作用，方便找到现存的条带。
*/
static struct stripe_head *__find_stripe(raid5_conf_t *conf, sector_t sector,short generation)
{
	struct stripe_head *sh;
	struct hlist_node *hn;

	CHECK_DEVLOCK();
	pr_debug("__find_stripe, sector %llu\n", (unsigned long long)sector);
	//遍历hash表。
	hlist_for_each_entry(sh, hn, stripe_hash(conf, sector), hash)
		if (sh->sector == sector && sh->generation == generation)
			return sh;
	pr_debug("__stripe %llu not in cache\n", (unsigned long long)sector);
	return NULL;
}

/*
 * Need to check if array has failed when deciding whether to:
 *  - start an array
 *  - remove non-faulty devices
 *  - add a spare
 *  - allow a reshape
 * This determination is simple when no reshape is happening.
 * However if there is a reshape, we need to carefully check
 * both the before and after sections.
 * This is because some failed devices may only affect one
 * of the two sections, and some non-in_sync devices may
 * be insync in the section most affected by failed devices.
 */
static int has_failed(raid5_conf_t *conf)
{
	int degraded;
	int i;
	if (conf->mddev->reshape_position == MaxSector)
		return conf->mddev->degraded > conf->max_degraded;

	rcu_read_lock();
	degraded = 0;
	for (i = 0; i < conf->previous_raid_disks; i++) {
		mdk_rdev_t *rdev = rcu_dereference(conf->disks[i].rdev);
		if (!rdev || test_bit(Faulty, &rdev->flags))
			degraded++;
		else if (test_bit(In_sync, &rdev->flags))
			;
		else
			/* not in-sync or faulty.
			 * If the reshape increases the number of devices,
			 * this is being recovered by the reshape, so
			 * this 'previous' section is not in_sync.
			 * If the number of devices is being reduced however,
			 * the device can only be part of the array if
			 * we are reverting a reshape, so this section will
			 * be in-sync.
			 */
			if (conf->raid_disks >= conf->previous_raid_disks)
				degraded++;
	}
	rcu_read_unlock();
	if (degraded > conf->max_degraded)
		return 1;
	rcu_read_lock();
	degraded = 0;
	for (i = 0; i < conf->raid_disks; i++) {
		mdk_rdev_t *rdev = rcu_dereference(conf->disks[i].rdev);
		if (!rdev || test_bit(Faulty, &rdev->flags))
			degraded++;
		else if (test_bit(In_sync, &rdev->flags))
			;
		else
			/* not in-sync or faulty.
			 * If reshape increases the number of devices, this
			 * section has already been recovered, else it
			 * almost certainly hasn't.
			 */
			if (conf->raid_disks <= conf->previous_raid_disks)
				degraded++;
	}
	rcu_read_unlock();
	if (degraded > conf->max_degraded)
		return 1;
	return 0;
}

static void unplug_slaves(mddev_t *mddev);

static struct stripe_head *
get_active_stripe(raid5_conf_t *conf, sector_t sector,int previous, int noblock, int noquiesce)
{
	struct stripe_head *sh;

	pr_debug("get_stripe, sector %llu\n", (unsigned long long)sector);

	spin_lock_irq(&conf->device_lock);

	do {
		//等待空闲条带
		wait_event_lock_irq(conf->wait_for_stripe,
				    conf->quiesce == 0 || noquiesce,
				    conf->device_lock, /* nothing */);
		//此扇区是否相应的条带
		sh = __find_stripe(conf, sector, conf->generation - previous);
		if (!sh) 
		{
			if (!conf->inactive_blocked)
				sh = get_free_stripe(conf);//从inactive_list列表中获取一个条带对象
			if (noblock && sh == NULL)
				break;
			//inactive_list列表中没有空闲的条带对象。
			if (!sh) 
			{
				//非活动条带标志置1
				conf->inactive_blocked = 1;
				/*
				*等待以下条件都满足:1.非活动条带列表inactive_list非空,则活动条带数不超过总条带数的75%；2.非活动的条带标志为0(没有其它地方置1，因此此条件基本不用考虑)
				*如果活动的条带数超过75%，表明系统正在处理大量的IO，为了平衡IO和CPU使用率，则要限制在75%。
				*md_raid5_unplug_device函数执行成员磁盘的"泄流"操作
				*/
				wait_event_lock_irq(conf->wait_for_stripe,
						    !list_empty(&conf->inactive_list) &&
						    (atomic_read(&conf->active_stripes) < (conf->max_nr_stripes *3/4)
						     || !conf->inactive_blocked),conf->device_lock,
						    md_raid5_unplug_device(conf));
				conf->inactive_blocked = 0;
			} 
			else//从inactive_list列表中取到了一个空闲的条带对象，则对其初始化，并添加Hash表中。
				init_stripe(sh, sector, previous);
		}
		else 
		{//条带已经在hash表中。
			if (atomic_read(&sh->count))//条带引用计数器
			{
				BUG_ON(!list_empty(&sh->lru)
				    && !test_bit(STRIPE_EXPANDING, &sh->state));
			} 
			else 
			{
				if (!test_bit(STRIPE_HANDLE, &sh->state))//条带没有不是正处理状态
					atomic_inc(&conf->active_stripes);//递增活动引用计数器。
				if (list_empty(&sh->lru) && !test_bit(STRIPE_EXPANDING, &sh->state))
					BUG();
				list_del_init(&sh->lru);//使条带"游离"
			}
		}
	} while (sh == NULL);
	/*增加条带引用记数器，在__release_stripe()用到。*/
	if (sh)
		atomic_inc(&sh->count);//递增条带使用的引用计数器。

	spin_unlock_irq(&conf->device_lock);
	return sh;
}

static void
raid5_end_read_request(struct bio *bi, int error);
static void
raid5_end_write_request(struct bio *bi, int error);

/**ltl
功能:看成员磁盘是否有IO需要调度。(把数据写入到成员磁盘中)
参数:sh	->条带描述符
	s	->条带状态指针
说明:1.如果成员磁盘设置了R5_Wantwrite/R5_Wantread标志。则将MD设置的数据写到相应的成员磁盘中。
*/
static void ops_run_io(struct stripe_head *sh, struct stripe_head_state *s)
{
	raid5_conf_t *conf = sh->raid_conf;
	int i, disks = sh->disks;

	might_sleep();

	for (i = disks; i--; ) 
	{
		int rw;
		struct bio *bi;
		mdk_rdev_t *rdev;
		if (test_and_clear_bit(R5_Wantwrite, &sh->dev[i].flags))
			rw = WRITE;		
		else if (test_and_clear_bit(R5_Wantread, &sh->dev[i].flags))//R5_Wantread在函数fetch_block5中设置
			rw = READ;
		else
			continue;

		bi = &sh->dev[i].req;
		//设置读写方向
		bi->bi_rw = rw;
		//设置bio的完成处理函数
		if (rw == WRITE)
			bi->bi_end_io = raid5_end_write_request;
		else
			bi->bi_end_io = raid5_end_read_request;

		rcu_read_lock();
		rdev = rcu_dereference(conf->disks[i].rdev);
		if (rdev && test_bit(Faulty, &rdev->flags))
			rdev = NULL;
		if (rdev)
			atomic_inc(&rdev->nr_pending);
		rcu_read_unlock();

		if (rdev) 
		{
			if (s->syncing || s->expanding || s->expanded)
				md_sync_acct(rdev->bdev, STRIPE_SECTORS);

			set_bit(STRIPE_IO_STARTED, &sh->state);
			//设置bio的成员磁盘block_device对象
			bi->bi_bdev = rdev->bdev;
			pr_debug("%s: for %llu schedule op %ld on disc %d\n",__func__, (unsigned long long)sh->sector,bi->bi_rw, i);
			atomic_inc(&sh->count);
			//数据起始扇区
			bi->bi_sector = sh->sector + rdev->data_offset;
			bi->bi_flags = 1 << BIO_UPTODATE;
			bi->bi_vcnt = 1;
			bi->bi_max_vecs = 1;
			bi->bi_idx = 0;
			bi->bi_io_vec = &sh->dev[i].vec;
			bi->bi_io_vec[0].bv_len = STRIPE_SIZE;
			bi->bi_io_vec[0].bv_offset = 0;
			bi->bi_size = STRIPE_SIZE;
			bi->bi_next = NULL;
			if (rw == WRITE && test_bit(R5_ReWrite, &sh->dev[i].flags))
				atomic_add(STRIPE_SECTORS,&rdev->corrected_errors);
			//提交到块设备层。
			generic_make_request(bi);
		}
		else
		{
			if (rw == WRITE)
				set_bit(STRIPE_DEGRADED, &sh->state);
			pr_debug("skip op %ld on disc %d for sector %llu\n",bi->bi_rw, i, (unsigned long long)sh->sector);
			clear_bit(R5_LOCKED, &sh->dev[i].flags);
			set_bit(STRIPE_HANDLE, &sh->state);
		}
	}
}
/**ltl
功能:采用异步机制，实现数据bio与page之间拷贝
参数:frombio	->1:数据从bio复制到page；0:数据从page复制到bio.
	bio	->bio对象
	page	->page对象
	sector->
	tx	->
返回值:
说明:
*/
static struct dma_async_tx_descriptor *
async_copy_data(int frombio, struct bio *bio, struct page *page,
	sector_t sector, struct dma_async_tx_descriptor *tx)
{
	struct bio_vec *bvl;
	struct page *bio_page;
	int i;
	int page_offset;
	struct async_submit_ctl submit;
	enum async_tx_flags flags = 0;

	if (bio->bi_sector >= sector)
		page_offset = (signed)(bio->bi_sector - sector) * 512;
	else
		page_offset = (signed)(sector - bio->bi_sector) * -512;

	if (frombio)
		flags |= ASYNC_TX_FENCE;
	init_async_submit(&submit, flags, tx, NULL, NULL, NULL);

	bio_for_each_segment(bvl, bio, i) {
		int len = bio_iovec_idx(bio, i)->bv_len;
		int clen;
		int b_offset = 0;

		if (page_offset < 0) {
			b_offset = -page_offset;
			page_offset += b_offset;
			len -= b_offset;
		}

		if (len > 0 && page_offset + len > STRIPE_SIZE)
			clen = STRIPE_SIZE - page_offset;
		else
			clen = len;

		if (clen > 0) {
			b_offset += bio_iovec_idx(bio, i)->bv_offset;
			bio_page = bio_iovec_idx(bio, i)->bv_page;
			if (frombio)
				tx = async_memcpy(page, bio_page, page_offset,
						  b_offset, clen, &submit);
			else
				tx = async_memcpy(bio_page, page, b_offset,
						  page_offset, clen, &submit);
		}
		/* chain the operations */
		submit.depend_tx = tx;

		if (clen < len) /* hit end of page */
			break;
		page_offset +=  len;
	}

	return tx;
}

static void ops_complete_biofill(void *stripe_head_ref)
{
	struct stripe_head *sh = stripe_head_ref;
	struct bio *return_bi = NULL;
	raid5_conf_t *conf = sh->raid_conf;
	int i;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);

	/* clear completed biofills */
	spin_lock_irq(&conf->device_lock);
	for (i = sh->disks; i--; ) 
	{
		struct r5dev *dev = &sh->dev[i];

		/* acknowledge completion of a biofill operation */
		/* and check if we need to reply to a read request,
		 * new R5_Wantfill requests are held off until
		 * !STRIPE_BIOFILL_RUN
		 */
		if (test_and_clear_bit(R5_Wantfill, &dev->flags)) 
		{
			struct bio *rbi, *rbi2;

			BUG_ON(!dev->read);
			rbi = dev->read;
			dev->read = NULL;
			while (rbi && rbi->bi_sector < dev->sector + STRIPE_SECTORS)
			{
				rbi2 = r5_next_bio(rbi, dev->sector);
				if (!raid5_dec_bi_phys_segments(rbi))
				{
					rbi->bi_next = return_bi;
					return_bi = rbi;
				}
				rbi = rbi2;
			}
		}
	}
	spin_unlock_irq(&conf->device_lock);
	clear_bit(STRIPE_BIOFILL_RUN, &sh->state);

	return_io(return_bi);

	set_bit(STRIPE_HANDLE, &sh->state);
	release_stripe(sh);
}

static void ops_run_biofill(struct stripe_head *sh)
{
	struct dma_async_tx_descriptor *tx = NULL;
	raid5_conf_t *conf = sh->raid_conf;
	struct async_submit_ctl submit;
	int i;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);

	for (i = sh->disks; i--; ) {
		struct r5dev *dev = &sh->dev[i];
		if (test_bit(R5_Wantfill, &dev->flags)) {
			struct bio *rbi;
			spin_lock_irq(&conf->device_lock);
			dev->read = rbi = dev->toread;
			dev->toread = NULL;
			spin_unlock_irq(&conf->device_lock);
			while (rbi && rbi->bi_sector <
				dev->sector + STRIPE_SECTORS) {
				tx = async_copy_data(0, rbi, dev->page,
					dev->sector, tx);
				rbi = r5_next_bio(rbi, dev->sector);
			}
		}
	}

	atomic_inc(&sh->count);
	init_async_submit(&submit, ASYNC_TX_ACK, tx, ops_complete_biofill, sh, NULL);
	async_trigger_callback(&submit);
}

static void mark_target_uptodate(struct stripe_head *sh, int target)
{
	struct r5dev *tgt;

	if (target < 0)
		return;

	tgt = &sh->dev[target];
	set_bit(R5_UPTODATE, &tgt->flags);
	BUG_ON(!test_bit(R5_Wantcompute, &tgt->flags));
	clear_bit(R5_Wantcompute, &tgt->flags);
}

static void ops_complete_compute(void *stripe_head_ref)
{
	struct stripe_head *sh = stripe_head_ref;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);

	/* mark the computed target(s) as uptodate */
	mark_target_uptodate(sh, sh->ops.target);//RAID5/RAID6会执行。
	mark_target_uptodate(sh, sh->ops.target2);//RAID6会执行。对RAID5,sh->ops.target2这个值为-1

	clear_bit(STRIPE_COMPUTE_RUN, &sh->state);
	if (sh->check_state == check_state_compute_run)
		sh->check_state = check_state_compute_result;
	set_bit(STRIPE_HANDLE, &sh->state);
	release_stripe(sh);
}

/* return a pointer to the address conversion region of the scribble buffer */
static addr_conv_t *to_addr_conv(struct stripe_head *sh,
				 struct raid5_percpu *percpu)
{
	return percpu->scribble + sizeof(struct page *) * (sh->disks + 2);
}

static struct dma_async_tx_descriptor *
ops_run_compute5(struct stripe_head *sh, struct raid5_percpu *percpu)
{
	int disks = sh->disks;
	struct page **xor_srcs = percpu->scribble;
	int target = sh->ops.target;
	struct r5dev *tgt = &sh->dev[target];
	struct page *xor_dest = tgt->page;
	int count = 0;
	struct dma_async_tx_descriptor *tx;
	struct async_submit_ctl submit;
	int i;

	pr_debug("%s: stripe %llu block: %d\n",
		__func__, (unsigned long long)sh->sector, target);
	BUG_ON(!test_bit(R5_Wantcompute, &tgt->flags));

	for (i = disks; i--; )
		if (i != target)
			xor_srcs[count++] = sh->dev[i].page;

	atomic_inc(&sh->count);

	init_async_submit(&submit, ASYNC_TX_FENCE|ASYNC_TX_XOR_ZERO_DST, NULL,
			  ops_complete_compute, sh, to_addr_conv(sh, percpu));
	if (unlikely(count == 1))
		tx = async_memcpy(xor_dest, xor_srcs[0], 0, 0, STRIPE_SIZE, &submit);
	else
		tx = async_xor(xor_dest, xor_srcs, 0, count, STRIPE_SIZE, &submit);

	return tx;
}

/* set_syndrome_sources - populate source buffers for gen_syndrome
 * @srcs - (struct page *) array of size sh->disks
 * @sh - stripe_head to parse
 *
 * Populates srcs in proper layout order for the stripe and returns the
 * 'count' of sources to be used in a call to async_gen_syndrome.  The P
 * destination buffer is recorded in srcs[count] and the Q destination
 * is recorded in srcs[count+1]].
 */
static int set_syndrome_sources(struct page **srcs, struct stripe_head *sh)
{
	int disks = sh->disks;
	int syndrome_disks = sh->ddf_layout ? disks : (disks - 2);
	int d0_idx = raid6_d0(sh);
	int count;
	int i;

	for (i = 0; i < disks; i++)
		srcs[i] = NULL;

	count = 0;
	i = d0_idx;
	do {
		int slot = raid6_idx_to_slot(i, sh, &count, syndrome_disks);

		srcs[slot] = sh->dev[i].page;
		i = raid6_next_disk(i, disks);
	} while (i != d0_idx);

	return syndrome_disks;
}

static struct dma_async_tx_descriptor *
ops_run_compute6_1(struct stripe_head *sh, struct raid5_percpu *percpu)
{
	int disks = sh->disks;
	struct page **blocks = percpu->scribble;
	int target;
	int qd_idx = sh->qd_idx;
	struct dma_async_tx_descriptor *tx;
	struct async_submit_ctl submit;
	struct r5dev *tgt;
	struct page *dest;
	int i;
	int count;

	if (sh->ops.target < 0)
		target = sh->ops.target2;
	else if (sh->ops.target2 < 0)
		target = sh->ops.target;
	else
		/* we should only have one valid target */
		BUG();
	BUG_ON(target < 0);
	pr_debug("%s: stripe %llu block: %d\n",
		__func__, (unsigned long long)sh->sector, target);

	tgt = &sh->dev[target];
	BUG_ON(!test_bit(R5_Wantcompute, &tgt->flags));
	dest = tgt->page;

	atomic_inc(&sh->count);

	if (target == qd_idx) {
		count = set_syndrome_sources(blocks, sh);
		blocks[count] = NULL; /* regenerating p is not necessary */
		BUG_ON(blocks[count+1] != dest); /* q should already be set */
		init_async_submit(&submit, ASYNC_TX_FENCE, NULL,
				  ops_complete_compute, sh,
				  to_addr_conv(sh, percpu));
		tx = async_gen_syndrome(blocks, 0, count+2, STRIPE_SIZE, &submit);
	} else {
		/* Compute any data- or p-drive using XOR */
		count = 0;
		for (i = disks; i-- ; ) {
			if (i == target || i == qd_idx)
				continue;
			blocks[count++] = sh->dev[i].page;
		}

		init_async_submit(&submit, ASYNC_TX_FENCE|ASYNC_TX_XOR_ZERO_DST,
				  NULL, ops_complete_compute, sh,
				  to_addr_conv(sh, percpu));
		tx = async_xor(dest, blocks, 0, count, STRIPE_SIZE, &submit);
	}

	return tx;
}

static struct dma_async_tx_descriptor *
ops_run_compute6_2(struct stripe_head *sh, struct raid5_percpu *percpu)
{
	int i, count, disks = sh->disks;
	int syndrome_disks = sh->ddf_layout ? disks : disks-2;
	int d0_idx = raid6_d0(sh);
	int faila = -1, failb = -1;
	int target = sh->ops.target;
	int target2 = sh->ops.target2;
	struct r5dev *tgt = &sh->dev[target];
	struct r5dev *tgt2 = &sh->dev[target2];
	struct dma_async_tx_descriptor *tx;
	struct page **blocks = percpu->scribble;
	struct async_submit_ctl submit;

	pr_debug("%s: stripe %llu block1: %d block2: %d\n",
		 __func__, (unsigned long long)sh->sector, target, target2);
	BUG_ON(target < 0 || target2 < 0);
	BUG_ON(!test_bit(R5_Wantcompute, &tgt->flags));
	BUG_ON(!test_bit(R5_Wantcompute, &tgt2->flags));

	/* we need to open-code set_syndrome_sources to handle the
	 * slot number conversion for 'faila' and 'failb'
	 */
	for (i = 0; i < disks ; i++)
		blocks[i] = NULL;
	count = 0;
	i = d0_idx;
	do {
		int slot = raid6_idx_to_slot(i, sh, &count, syndrome_disks);

		blocks[slot] = sh->dev[i].page;

		if (i == target)
			faila = slot;
		if (i == target2)
			failb = slot;
		i = raid6_next_disk(i, disks);
	} while (i != d0_idx);

	BUG_ON(faila == failb);
	if (failb < faila)
		swap(faila, failb);
	pr_debug("%s: stripe: %llu faila: %d failb: %d\n",
		 __func__, (unsigned long long)sh->sector, faila, failb);

	atomic_inc(&sh->count);

	if (failb == syndrome_disks+1) {
		/* Q disk is one of the missing disks */
		if (faila == syndrome_disks) {
			/* Missing P+Q, just recompute */
			init_async_submit(&submit, ASYNC_TX_FENCE, NULL,
					  ops_complete_compute, sh,
					  to_addr_conv(sh, percpu));
			return async_gen_syndrome(blocks, 0, syndrome_disks+2,
						  STRIPE_SIZE, &submit);
		} else {
			struct page *dest;
			int data_target;
			int qd_idx = sh->qd_idx;

			/* Missing D+Q: recompute D from P, then recompute Q */
			if (target == qd_idx)
				data_target = target2;
			else
				data_target = target;

			count = 0;
			for (i = disks; i-- ; ) {
				if (i == data_target || i == qd_idx)
					continue;
				blocks[count++] = sh->dev[i].page;
			}
			dest = sh->dev[data_target].page;
			init_async_submit(&submit,
					  ASYNC_TX_FENCE|ASYNC_TX_XOR_ZERO_DST,
					  NULL, NULL, NULL,
					  to_addr_conv(sh, percpu));
			tx = async_xor(dest, blocks, 0, count, STRIPE_SIZE,
				       &submit);

			count = set_syndrome_sources(blocks, sh);
			init_async_submit(&submit, ASYNC_TX_FENCE, tx,
					  ops_complete_compute, sh,
					  to_addr_conv(sh, percpu));
			return async_gen_syndrome(blocks, 0, count+2,
						  STRIPE_SIZE, &submit);
		}
	} else {
		init_async_submit(&submit, ASYNC_TX_FENCE, NULL,
				  ops_complete_compute, sh,
				  to_addr_conv(sh, percpu));
		if (failb == syndrome_disks) {
			/* We're missing D+P. */
			return async_raid6_datap_recov(syndrome_disks+2,
						       STRIPE_SIZE, faila,
						       blocks, &submit);
		} else {
			/* We're missing D+D. */
			return async_raid6_2data_recov(syndrome_disks+2,
						       STRIPE_SIZE, faila, failb,
						       blocks, &submit);
		}
	}
}


static void ops_complete_prexor(void *stripe_head_ref)
{
	struct stripe_head *sh = stripe_head_ref;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);
}

static struct dma_async_tx_descriptor *
ops_run_prexor(struct stripe_head *sh, struct raid5_percpu *percpu,
	       struct dma_async_tx_descriptor *tx)
{
	int disks = sh->disks;
	struct page **xor_srcs = percpu->scribble;
	int count = 0, pd_idx = sh->pd_idx, i;
	struct async_submit_ctl submit;

	/* existing parity data subtracted */
	struct page *xor_dest = xor_srcs[count++] = sh->dev[pd_idx].page;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);

	for (i = disks; i--; ) {
		struct r5dev *dev = &sh->dev[i];
		/* Only process blocks that are known to be uptodate */
		if (test_bit(R5_Wantdrain, &dev->flags))
			xor_srcs[count++] = dev->page;
	}

	init_async_submit(&submit, ASYNC_TX_FENCE|ASYNC_TX_XOR_DROP_DST, tx,
			  ops_complete_prexor, sh, to_addr_conv(sh, percpu));
	tx = async_xor(xor_dest, xor_srcs, 0, count, STRIPE_SIZE, &submit);

	return tx;
}
/**ltl
功能:处理bio抽干的函数
参数:
返回值:
说明:将bio中要写的数据复制到目标成员设备的页面缓存中。
*/
static struct dma_async_tx_descriptor *
ops_run_biodrain(struct stripe_head *sh, struct dma_async_tx_descriptor *tx)
{
	int disks = sh->disks;
	int i;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);

	for (i = disks; i--; ) 
	{
		struct r5dev *dev = &sh->dev[i];
		struct bio *chosen;
		//抽干已经设置了R5_Wantdrain标志的成员磁盘
		if (test_and_clear_bit(R5_Wantdrain, &dev->flags)) 
		{
			struct bio *wbi;

			spin_lock(&sh->lock);
			//把towrite链表转移到writen链表
			chosen = dev->towrite;
			dev->towrite = NULL;//清空towrite链表
			BUG_ON(dev->written);
			wbi = dev->written = chosen;
			spin_unlock(&sh->lock);

			while (wbi && wbi->bi_sector < dev->sector + STRIPE_SECTORS) 
			{
				//从bio(wbi)复制到page(dev->page)
				tx = async_copy_data(1, wbi, dev->page,dev->sector, tx);
				wbi = r5_next_bio(wbi, dev->sector);
			}
		}
	}

	return tx;
}
/**ltl
功能:计算校验和(异步过程)操作的完成处理函数
参数:
说明:1.将此条带的所有成员磁盘设置成"已更新"，为写入这些磁盘做准备。
	2.修改条带的重构状态。
*/
static void ops_complete_reconstruct(void *stripe_head_ref)
{
	struct stripe_head *sh = stripe_head_ref;
	int disks = sh->disks;
	int pd_idx = sh->pd_idx;
	int qd_idx = sh->qd_idx;
	int i;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);
	//1.将此条带的所有成员磁盘设置成"已更新"，为写入这些磁盘做准备。
	for (i = disks; i--; ) {
		struct r5dev *dev = &sh->dev[i];

		if (dev->written || i == pd_idx || i == qd_idx)
			set_bit(R5_UPTODATE, &dev->flags);
	}
	//2.修改条带的重构状态。
	if (sh->reconstruct_state == reconstruct_state_drain_run)//对"重构写"
		sh->reconstruct_state = reconstruct_state_drain_result;
	else if (sh->reconstruct_state == reconstruct_state_prexor_drain_run)//对"读改写"
		sh->reconstruct_state = reconstruct_state_prexor_drain_result;
	else 
	{//因为扩展而重构
		BUG_ON(sh->reconstruct_state != reconstruct_state_run);
		sh->reconstruct_state = reconstruct_state_result;
	}

	set_bit(STRIPE_HANDLE, &sh->state);
	release_stripe(sh);
}

static void
ops_run_reconstruct5(struct stripe_head *sh, struct raid5_percpu *percpu,
		     struct dma_async_tx_descriptor *tx)
{
	int disks = sh->disks;
	struct page **xor_srcs = percpu->scribble;
	struct async_submit_ctl submit;
	int count = 0, pd_idx = sh->pd_idx, i;
	struct page *xor_dest;
	int prexor = 0;
	unsigned long flags;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);

	/* check if prexor is active which means only process blocks
	 * that are part of a read-modify-write (written)
	 */
	 /*处理"读-改-写"*/
	if (sh->reconstruct_state == reconstruct_state_prexor_drain_run) 
	{
		prexor = 1;
		xor_dest = xor_srcs[count++] = sh->dev[pd_idx].page;
		for (i = disks; i--; ) 
		{
			struct r5dev *dev = &sh->dev[i];
			if (dev->written)
				xor_srcs[count++] = dev->page;
		}
	} 
	else 
	{/*处理"重构写"*/
		xor_dest = sh->dev[pd_idx].page;
		for (i = disks; i--; ) 
		{
			struct r5dev *dev = &sh->dev[i];
			if (i != pd_idx)
				xor_srcs[count++] = dev->page;
		}
	}

	/* 1/ if we prexor'd then the dest is reused as a source
	 * 2/ if we did not prexor then we are redoing the parity
	 * set ASYNC_TX_XOR_DROP_DST and ASYNC_TX_XOR_ZERO_DST
	 * for the synchronous xor case
	 */
	flags = ASYNC_TX_ACK | (prexor ? ASYNC_TX_XOR_DROP_DST : ASYNC_TX_XOR_ZERO_DST);

	atomic_inc(&sh->count);
	//设置async_submit_ctl成员，ops_complete_reconstruct是完成处理函数
	init_async_submit(&submit, flags, tx, ops_complete_reconstruct, sh,to_addr_conv(sh, percpu));
	//计算校验和(异步过程)
	if (unlikely(count == 1))//只有一个数据源(只有一个成员磁盘)
		tx = async_memcpy(xor_dest, xor_srcs[0], 0, 0, STRIPE_SIZE, &submit);
	else//计算校验和
		tx = async_xor(xor_dest, xor_srcs, 0, count, STRIPE_SIZE, &submit);
}

static void
ops_run_reconstruct6(struct stripe_head *sh, struct raid5_percpu *percpu,
		     struct dma_async_tx_descriptor *tx)
{
	struct async_submit_ctl submit;
	struct page **blocks = percpu->scribble;
	int count;

	pr_debug("%s: stripe %llu\n", __func__, (unsigned long long)sh->sector);

	count = set_syndrome_sources(blocks, sh);

	atomic_inc(&sh->count);

	init_async_submit(&submit, ASYNC_TX_ACK, tx, ops_complete_reconstruct,
			  sh, to_addr_conv(sh, percpu));
	async_gen_syndrome(blocks, 0, count+2, STRIPE_SIZE,  &submit);
}

static void ops_complete_check(void *stripe_head_ref)
{
	struct stripe_head *sh = stripe_head_ref;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);

	sh->check_state = check_state_check_result;
	set_bit(STRIPE_HANDLE, &sh->state);
	release_stripe(sh);
}

static void ops_run_check_p(struct stripe_head *sh, struct raid5_percpu *percpu)
{
	int disks = sh->disks;
	int pd_idx = sh->pd_idx;
	int qd_idx = sh->qd_idx;
	struct page *xor_dest;
	struct page **xor_srcs = percpu->scribble;
	struct dma_async_tx_descriptor *tx;
	struct async_submit_ctl submit;
	int count;
	int i;

	pr_debug("%s: stripe %llu\n", __func__,
		(unsigned long long)sh->sector);

	count = 0;
	xor_dest = sh->dev[pd_idx].page;
	xor_srcs[count++] = xor_dest;
	for (i = disks; i--; ) {
		if (i == pd_idx || i == qd_idx)
			continue;
		xor_srcs[count++] = sh->dev[i].page;
	}

	init_async_submit(&submit, 0, NULL, NULL, NULL,
			  to_addr_conv(sh, percpu));
	tx = async_xor_val(xor_dest, xor_srcs, 0, count, STRIPE_SIZE,
			   &sh->ops.zero_sum_result, &submit);

	atomic_inc(&sh->count);
	init_async_submit(&submit, ASYNC_TX_ACK, tx, ops_complete_check, sh, NULL);
	tx = async_trigger_callback(&submit);
}

static void ops_run_check_pq(struct stripe_head *sh, struct raid5_percpu *percpu, int checkp)
{
	struct page **srcs = percpu->scribble;
	struct async_submit_ctl submit;
	int count;

	pr_debug("%s: stripe %llu checkp: %d\n", __func__,
		(unsigned long long)sh->sector, checkp);

	count = set_syndrome_sources(srcs, sh);
	if (!checkp)
		srcs[count] = NULL;

	atomic_inc(&sh->count);
	init_async_submit(&submit, ASYNC_TX_ACK, NULL, ops_complete_check,
			  sh, to_addr_conv(sh, percpu));
	async_syndrome_val(srcs, 0, count+2, STRIPE_SIZE,
			   &sh->ops.zero_sum_result, percpu->spare_page, &submit);
}
/**ltl
功能:
参数:sh	->条带头描述符指针
	ops_request	->操作码
说明:标志STRIPE_OP_BIOFILL、STRIPE_OP_COMPUTE_BLK、STRIPE_OP_PREXOR、STRIPE_OP_BIODRAIN、STRIPE_OP_RECONSTRUCT、STRIPE_OP_CHECK在函数schedule_reconstruction中设置
*/
static void __raid_run_ops(struct stripe_head *sh, unsigned long ops_request)
{
	int overlap_clear = 0, i, disks = sh->disks;
	struct dma_async_tx_descriptor *tx = NULL;
	raid5_conf_t *conf = sh->raid_conf;
	int level = conf->level;
	struct raid5_percpu *percpu;
	unsigned long cpu;

	cpu = get_cpu();
	percpu = per_cpu_ptr(conf->percpu, cpu);
	
	//将数据复制到请求缓冲区以便满足读请求
	if (test_bit(STRIPE_OP_BIOFILL, &ops_request)) 
	{
		ops_run_biofill(sh);
		overlap_clear++;
	}
	/*在缓存中从其他块生成丢失块*/
	if (test_bit(STRIPE_OP_COMPUTE_BLK, &ops_request)) 
	{
		if (level < 6)
			tx = ops_run_compute5(sh, percpu);
		else {
			if (sh->ops.target2 < 0 || sh->ops.target < 0)
				tx = ops_run_compute6_1(sh, percpu);
			else
				tx = ops_run_compute6_2(sh, percpu);
		}
		/* terminate the chain if reconstruct is not set to be run */
		if (tx && !test_bit(STRIPE_OP_RECONSTRUCT, &ops_request))
			async_tx_ack(tx);
	}
	/*作为读-改-写过程的一部分异或存在的数据*/
	if (test_bit(STRIPE_OP_PREXOR, &ops_request))
		tx = ops_run_prexor(sh, percpu, tx);
	/*数据从请求缓冲区拷出以满足写请求(将数据从bio拷贝到page中)*/
	if (test_bit(STRIPE_OP_BIODRAIN, &ops_request)) 
	{
		tx = ops_run_biodrain(sh, tx);
		overlap_clear++;
	}
	/*为进入缓存的新数据重新计算校验和(到这里，此条带成员磁盘数据已经存放到页面缓冲区page中，现在可以对其校验)*/
	if (test_bit(STRIPE_OP_RECONSTRUCT, &ops_request)) 
	{
		if (level < 6)
			ops_run_reconstruct5(sh, percpu, tx);
		else
			ops_run_reconstruct6(sh, percpu, tx);
	}
	/*检察检验和正确性*/
	if (test_bit(STRIPE_OP_CHECK, &ops_request))
	{
		if (sh->check_state == check_state_run)
			ops_run_check_p(sh, percpu);
		else if (sh->check_state == check_state_run_q)
			ops_run_check_pq(sh, percpu, 0);
		else if (sh->check_state == check_state_run_pq)
			ops_run_check_pq(sh, percpu, 1);
		else
			BUG();
	}
	/*overlap_clear不为0，表明towrite和toread链表已经发生改变
	*原来因为和链表中的bio重叠而被迫在队列中等待其他bio可能有机会被执行。
	*/
	if (overlap_clear)
		for (i = disks; i--; ) 
		{
			struct r5dev *dev = &sh->dev[i];
			if (test_and_clear_bit(R5_Overlap, &dev->flags))
				wake_up(&sh->raid_conf->wait_for_overlap);
		}
	put_cpu();
}

#ifdef CONFIG_MULTICORE_RAID456
static void async_run_ops(void *param, async_cookie_t cookie)
{
	struct stripe_head *sh = param;
	unsigned long ops_request = sh->ops.request;
	//异步执行开始，清除STRIPE_OPS_REQ_PENDING，表示可以支持另一个异步操作。
	clear_bit_unlock(STRIPE_OPS_REQ_PENDING, &sh->state);
	//唤醒因操作请求被挂起的进程。
	wake_up(&sh->ops.wait_for_ops);
	//根据请求操作标志处理此条带
	__raid_run_ops(sh, ops_request);
	//把条带重新插入到列表中。
	release_stripe(sh);
}

static void raid_run_ops(struct stripe_head *sh, unsigned long ops_request)
{
	/* since handle_stripe can be called outside of raid5d context
	 * we need to ensure sh->ops.request is de-staged before another
	 * request arrives
	 */
	/*当一个异步调度还没有执行async_run_ops时，就要在此睡眠。
	*实现方式:通过检查条带状态state，如果设置了STRIPE_OPS_REQ_PENDING,说明处于异步挂起状态。此时要进入休眠。
	*若没有设置STRIPE_OPS_REQ_PENDING标志，代码往下执行，同时要设备state的STRIPE_OPS_REQ_PENDING状态。
	*/
	wait_event(sh->ops.wait_for_ops,!test_and_set_bit_lock(STRIPE_OPS_REQ_PENDING, &sh->state));
	sh->ops.request = ops_request;

	atomic_inc(&sh->count);
	//异步操作调度,防止因处理请求操作而阻塞make_request
	//注:Q->直接用同步操作的性能差别?
	async_schedule(async_run_ops, sh);
}
#else
#define raid_run_ops __raid_run_ops
#endif
/**ltl
功能:分配一个条带头描述符stripe_head，并添加到inactive_list链表中
参数:
返回值:
说明:把分配的stripe_head插入到inactive_list链表中。
*/
static int grow_one_stripe(raid5_conf_t *conf)
{
	struct stripe_head *sh;
	//在高速缓冲区分配一个条带头描述符。
	sh = kmem_cache_alloc(conf->slab_cache, GFP_KERNEL);
	if (!sh)
		return 0;
	//置0
	memset(sh, 0, sizeof(*sh) + (conf->pool_size-1)*sizeof(struct r5dev));
	sh->raid_conf = conf;
	spin_lock_init(&sh->lock);
	#ifdef CONFIG_MULTICORE_RAID456
	init_waitqueue_head(&sh->ops.wait_for_ops);
	#endif

	if (grow_buffers(sh)) {
		shrink_buffers(sh);
		kmem_cache_free(conf->slab_cache, sh);
		return 0;
	}
	/* we just created an active stripe so... */
	atomic_set(&sh->count, 1);
	atomic_inc(&conf->active_stripes);
	INIT_LIST_HEAD(&sh->lru);
	release_stripe(sh);
	return 1;
}

static int grow_stripes(raid5_conf_t *conf, int num)
{
	struct kmem_cache *sc;
	int devs = max(conf->raid_disks, conf->previous_raid_disks);

	if (conf->mddev->gendisk)
		sprintf(conf->cache_name[0],
			"raid%d-%s", conf->level, mdname(conf->mddev));
	else
		sprintf(conf->cache_name[0],
			"raid%d-%p", conf->level, conf->mddev);
	sprintf(conf->cache_name[1], "%s-alt", conf->cache_name[0]);

	conf->active_name = 0;
	sc = kmem_cache_create(conf->cache_name[conf->active_name],
			       sizeof(struct stripe_head)+(devs-1)*sizeof(struct r5dev),
			       0, 0, NULL);
	if (!sc)
		return 1;
	conf->slab_cache = sc;
	conf->pool_size = devs;
	while (num--)
		if (!grow_one_stripe(conf))
			return 1;
	return 0;
}

/**
 * scribble_len - return the required size of the scribble region
 * @num - total number of disks in the array
 *
 * The size must be enough to contain:
 * 1/ a struct page pointer for each device in the array +2
 * 2/ room to convert each entry in (1) to its corresponding dma
 *    (dma_map_page()) or page (page_address()) address.
 *
 * Note: the +2 is for the destination buffers of the ddf/raid6 case where we
 * calculate over all devices (not just the data blocks), using zeros in place
 * of the P and Q blocks.
 */
static size_t scribble_len(int num)
{
	size_t len;

	len = sizeof(struct page *) * (num+2) + sizeof(addr_conv_t) * (num+2);

	return len;
}

static int resize_stripes(raid5_conf_t *conf, int newsize)
{
	/* Make all the stripes able to hold 'newsize' devices.
	 * New slots in each stripe get 'page' set to a new page.
	 *
	 * This happens in stages:
	 * 1/ create a new kmem_cache and allocate the required number of
	 *    stripe_heads.
	 * 2/ gather all the old stripe_heads and tranfer the pages across
	 *    to the new stripe_heads.  This will have the side effect of
	 *    freezing the array as once all stripe_heads have been collected,
	 *    no IO will be possible.  Old stripe heads are freed once their
	 *    pages have been transferred over, and the old kmem_cache is
	 *    freed when all stripes are done.
	 * 3/ reallocate conf->disks to be suitable bigger.  If this fails,
	 *    we simple return a failre status - no need to clean anything up.
	 * 4/ allocate new pages for the new slots in the new stripe_heads.
	 *    If this fails, we don't bother trying the shrink the
	 *    stripe_heads down again, we just leave them as they are.
	 *    As each stripe_head is processed the new one is released into
	 *    active service.
	 *
	 * Once step2 is started, we cannot afford to wait for a write,
	 * so we use GFP_NOIO allocations.
	 */
	struct stripe_head *osh, *nsh;
	LIST_HEAD(newstripes);
	struct disk_info *ndisks;
	unsigned long cpu;
	int err;
	struct kmem_cache *sc;
	int i;

	if (newsize <= conf->pool_size)
		return 0; /* never bother to shrink */

	err = md_allow_write(conf->mddev);
	if (err)
		return err;

	/* Step 1 */
	sc = kmem_cache_create(conf->cache_name[1-conf->active_name],
			       sizeof(struct stripe_head)+(newsize-1)*sizeof(struct r5dev),
			       0, 0, NULL);
	if (!sc)
		return -ENOMEM;

	for (i = conf->max_nr_stripes; i; i--) {
		nsh = kmem_cache_alloc(sc, GFP_KERNEL);
		if (!nsh)
			break;

		memset(nsh, 0, sizeof(*nsh) + (newsize-1)*sizeof(struct r5dev));

		nsh->raid_conf = conf;
		spin_lock_init(&nsh->lock);
		#ifdef CONFIG_MULTICORE_RAID456
		init_waitqueue_head(&nsh->ops.wait_for_ops);
		#endif

		list_add(&nsh->lru, &newstripes);
	}
	if (i) {
		/* didn't get enough, give up */
		while (!list_empty(&newstripes)) {
			nsh = list_entry(newstripes.next, struct stripe_head, lru);
			list_del(&nsh->lru);
			kmem_cache_free(sc, nsh);
		}
		kmem_cache_destroy(sc);
		return -ENOMEM;
	}
	/* Step 2 - Must use GFP_NOIO now.
	 * OK, we have enough stripes, start collecting inactive
	 * stripes and copying them over
	 */
	list_for_each_entry(nsh, &newstripes, lru) {
		spin_lock_irq(&conf->device_lock);
		wait_event_lock_irq(conf->wait_for_stripe,
				    !list_empty(&conf->inactive_list),
				    conf->device_lock,
				    unplug_slaves(conf->mddev)
			);
		osh = get_free_stripe(conf);
		spin_unlock_irq(&conf->device_lock);
		atomic_set(&nsh->count, 1);
		for(i=0; i<conf->pool_size; i++)
			nsh->dev[i].page = osh->dev[i].page;
		for( ; i<newsize; i++)
			nsh->dev[i].page = NULL;
		kmem_cache_free(conf->slab_cache, osh);
	}
	kmem_cache_destroy(conf->slab_cache);

	/* Step 3.
	 * At this point, we are holding all the stripes so the array
	 * is completely stalled, so now is a good time to resize
	 * conf->disks and the scribble region
	 */
	ndisks = kzalloc(newsize * sizeof(struct disk_info), GFP_NOIO);
	if (ndisks) {
		for (i=0; i<conf->raid_disks; i++)
			ndisks[i] = conf->disks[i];
		kfree(conf->disks);
		conf->disks = ndisks;
	} else
		err = -ENOMEM;

	get_online_cpus();
	conf->scribble_len = scribble_len(newsize);
	for_each_present_cpu(cpu) {
		struct raid5_percpu *percpu;
		void *scribble;

		percpu = per_cpu_ptr(conf->percpu, cpu);
		scribble = kmalloc(conf->scribble_len, GFP_NOIO);

		if (scribble) {
			kfree(percpu->scribble);
			percpu->scribble = scribble;
		} else {
			err = -ENOMEM;
			break;
		}
	}
	put_online_cpus();

	/* Step 4, return new stripes to service */
	while(!list_empty(&newstripes)) {
		nsh = list_entry(newstripes.next, struct stripe_head, lru);
		list_del_init(&nsh->lru);

		for (i=conf->raid_disks; i < newsize; i++)
			if (nsh->dev[i].page == NULL) {
				struct page *p = alloc_page(GFP_NOIO);
				nsh->dev[i].page = p;
				if (!p)
					err = -ENOMEM;
			}
		release_stripe(nsh);
	}
	/* critical section pass, GFP_NOIO no longer needed */

	conf->slab_cache = sc;
	conf->active_name = 1-conf->active_name;
	conf->pool_size = newsize;
	return err;
}

static int drop_one_stripe(raid5_conf_t *conf)
{
	struct stripe_head *sh;

	spin_lock_irq(&conf->device_lock);
	sh = get_free_stripe(conf);
	spin_unlock_irq(&conf->device_lock);
	if (!sh)
		return 0;
	BUG_ON(atomic_read(&sh->count));
	shrink_buffers(sh);
	kmem_cache_free(conf->slab_cache, sh);
	atomic_dec(&conf->active_stripes);
	return 1;
}
/**ltl
功能:条带资源释放
参数:
说明:
*/
static void shrink_stripes(raid5_conf_t *conf)
{
	while (drop_one_stripe(conf))
		;

	if (conf->slab_cache)
		kmem_cache_destroy(conf->slab_cache);
	conf->slab_cache = NULL;
}
/**ltl
功能:MD设备的读bio的完成处理函数
参数:
说明:
*/
static void raid5_end_read_request(struct bio * bi, int error)
{
	struct stripe_head *sh = bi->bi_private;
	raid5_conf_t *conf = sh->raid_conf;
	int disks = sh->disks, i;
	int uptodate = test_bit(BIO_UPTODATE, &bi->bi_flags);
	char b[BDEVNAME_SIZE];
	mdk_rdev_t *rdev;

	//判定bio是针对哪一个成员磁盘
	for (i=0 ; i<disks; i++)
		if (bi == &sh->dev[i].req)
			break;

	pr_debug("end_read_request %llu/%d, count: %d, uptodate %d.\n",
		(unsigned long long)sh->sector, i, atomic_read(&sh->count),uptodate);
	if (i == disks) {
		BUG();
		return;
	}
	//请求处理成功
	if (uptodate)
	{	//设置"已更新"标志
		set_bit(R5_UPTODATE, &sh->dev[i].flags);
		//表明已经出错过一次，而第二次执行写操作成功，导致此次读取数据成功。
		if (test_bit(R5_ReadError, &sh->dev[i].flags)) 
		{
			rdev = conf->disks[i].rdev;
			printk_rl(KERN_INFO "md/raid:%s: read error corrected (%lu sectors at %llu on %s)\n",
				  mdname(conf->mddev), STRIPE_SECTORS,(unsigned long long)(sh->sector + rdev->data_offset),bdevname(rdev->bdev, b));
			clear_bit(R5_ReadError, &sh->dev[i].flags);
			clear_bit(R5_ReWrite, &sh->dev[i].flags);
		}
		if (atomic_read(&conf->disks[i].rdev->read_errors))
			atomic_set(&conf->disks[i].rdev->read_errors, 0);
	} 
	else 
	{//bio处理失败
		const char *bdn = bdevname(conf->disks[i].rdev->bdev, b);
		int retry = 0;
		rdev = conf->disks[i].rdev;
		//清除"已更新"标志
		clear_bit(R5_UPTODATE, &sh->dev[i].flags);
		//递增它的错误计数器
		atomic_inc(&rdev->read_errors);
		
		if (conf->mddev->degraded >= conf->max_degraded)
		{//MD设备的降级磁盘数已经大于或等于最大允许降级磁盘数；
   			printk_rl(KERN_WARNING "md/raid:%s: read error not correctable (sector %llu on %s).\n",
				  mdname(conf->mddev),(unsigned long long)(sh->sector + rdev->data_offset),bdn);
		}		
		else if (test_bit(R5_ReWrite, &sh->dev[i].flags))
		{//成员磁盘设置了R5_ReWrite重写标志
			/* Oh, no!!! */
			printk_rl(KERN_WARNING "md/raid:%s: read error NOT corrected!! (sector %llu on %s).\n",
				  mdname(conf->mddev),(unsigned long long)(sh->sector + rdev->data_offset), bdn);
		}
		else if (atomic_read(&rdev->read_errors) > conf->max_nr_stripes)
		{//成员磁盘的读错误计数已经太多
			printk(KERN_WARNING"md/raid:%s: Too many read errors, failing device %s.\n",
			       mdname(conf->mddev), bdn);
		}
		else
		{//进行重试
			retry = 1;
		}
		
		if (retry)
			set_bit(R5_ReadError, &sh->dev[i].flags);
		else 
		{//没有必要重试
			clear_bit(R5_ReadError, &sh->dev[i].flags);
			clear_bit(R5_ReWrite, &sh->dev[i].flags);
			//使成员磁盘失效
			md_error(conf->mddev, rdev);
		}
	}
	rdev_dec_pending(conf->disks[i].rdev, conf->mddev);
	//清除成员磁盘已经上锁标志
	clear_bit(R5_LOCKED, &sh->dev[i].flags);
	//设置STRIPE_HANDLE
	set_bit(STRIPE_HANDLE, &sh->state);
	//STRIPE_HANDLE标志使此条带进入新一轮的处理。
	release_stripe(sh);
}

/**ltl
功能:MD设备的写bio的完成处理函数
参数:
说明:
*/
static void raid5_end_write_request(struct bio *bi, int error)
{
	struct stripe_head *sh = bi->bi_private;
	raid5_conf_t *conf = sh->raid_conf;
	int disks = sh->disks, i;
	int uptodate = test_bit(BIO_UPTODATE, &bi->bi_flags);

	for (i=0 ; i<disks; i++)
		if (bi == &sh->dev[i].req)
			break;

	pr_debug("end_write_request %llu/%d, count %d, uptodate: %d.\n",
		(unsigned long long)sh->sector, i, atomic_read(&sh->count),
		uptodate);
	if (i == disks) {
		BUG();
		return;
	}
	//写失败，则使成员磁盘失效
	if (!uptodate)
		md_error(conf->mddev, conf->disks[i].rdev);

	rdev_dec_pending(conf->disks[i].rdev, conf->mddev);
	//清除已经上锁标志
	clear_bit(R5_LOCKED, &sh->dev[i].flags);
	//设置条带已经更新标志
	set_bit(STRIPE_HANDLE, &sh->state);
	release_stripe(sh);
}


static sector_t compute_blocknr(struct stripe_head *sh, int i, int previous);
	
static void raid5_build_block(struct stripe_head *sh, int i, int previous)
{
	struct r5dev *dev = &sh->dev[i];

	bio_init(&dev->req);
	dev->req.bi_io_vec = &dev->vec;
	dev->req.bi_vcnt++;
	dev->req.bi_max_vecs++;
	dev->vec.bv_page = dev->page;
	dev->vec.bv_len = STRIPE_SIZE;
	dev->vec.bv_offset = 0;

	dev->req.bi_sector = sh->sector;
	dev->req.bi_private = sh;

	dev->flags = 0;
	dev->sector = compute_blocknr(sh, i, previous);
}

static void error(mddev_t *mddev, mdk_rdev_t *rdev)
{
	char b[BDEVNAME_SIZE];
	raid5_conf_t *conf = mddev->private;
	pr_debug("raid456: error called\n");

	if (!test_bit(Faulty, &rdev->flags)) {
		set_bit(MD_CHANGE_DEVS, &mddev->flags);
		if (test_and_clear_bit(In_sync, &rdev->flags)) {
			unsigned long flags;
			spin_lock_irqsave(&conf->device_lock, flags);
			mddev->degraded++;
			spin_unlock_irqrestore(&conf->device_lock, flags);
			/*
			 * if recovery was running, make sure it aborts.
			 */
			set_bit(MD_RECOVERY_INTR, &mddev->recovery);
		}
		set_bit(Faulty, &rdev->flags);
		printk(KERN_ALERT
		       "md/raid:%s: Disk failure on %s, disabling device.\n"
		       KERN_ALERT
		       "md/raid:%s: Operation continuing on %d devices.\n",
		       mdname(mddev),
		       bdevname(rdev->bdev, b),
		       mdname(mddev),
		       conf->raid_disks - mddev->degraded);
	}
}

/*
 * Input: a 'big' sector number,
 * Output: index of the data and parity disk, and the sector # in them.
 */
/**ltl
功能:计算P校验单元编号、Q校验单元编号、ddf_layout标志。
参数:conf		->RAID5私有数据
	r_sector	->目标扇区编号
	previous	->1:表示根据变更(reshape)参数进行计算；0:表示根据变更(reshape)后的参数进行计算。
	dd_idx	->[out] 返回数据单元在条带中的编号；
	sh		->指向对应stripe_head描述符指针。
返回值:对应扇区在成员磁盘上的扇区编号。
说明:[IN] 一个相对RAID5设备的"大的"扇区编号。
	[OUT]数据磁盘和校验磁盘的编号，以及其上的扇区编号，即条带编号。
*/
static sector_t raid5_compute_sector(raid5_conf_t *conf, sector_t r_sector,
				     int previous, int *dd_idx,
				     struct stripe_head *sh)
{
	sector_t stripe, stripe2;
	sector_t chunk_number;
	unsigned int chunk_offset;
	int pd_idx, qd_idx;
	int ddf_layout = 0;
	sector_t new_sector;
	//RAID算法
	int algorithm = previous ? conf->prev_algo : conf->algorithm;
	//每个chunk的扇区数
	int sectors_per_chunk = previous ? conf->prev_chunk_sectors : conf->chunk_sectors;
	//raid成员磁盘个数。
	int raid_disks = previous ? conf->previous_raid_disks : conf->raid_disks;
	//数据磁盘个数。
	int data_disks = raid_disks - conf->max_degraded;

	/* First compute the information on this sector */

	/*
	 * Compute the chunk number and the sector offset inside the chunk
	 */
	 //目标扇区在chunk内的扇区偏移(chunk_offset=r_sector%sectors_per_chunk)
	chunk_offset = sector_div(r_sector, sectors_per_chunk);
	//目标扇区在chunk编号(chunk_number=r_sector/sectors_per_chunk)
	chunk_number = r_sector;

	/*
	 * Compute the stripe number
	 */
	stripe = chunk_number;
	*dd_idx = sector_div(stripe, data_disks);
	stripe2 = stripe;
	/*
	 * Select the parity disk based on the user selected algorithm.
	 */
	pd_idx = qd_idx = ~0;
	switch(conf->level)
	{
	case 4:
		pd_idx = data_disks;
		break;
	case 5:
		switch (algorithm) 
		{
		case ALGORITHM_LEFT_ASYMMETRIC://向左不对齐
			pd_idx = data_disks - sector_div(stripe2, raid_disks);
			if (*dd_idx >= pd_idx)
				(*dd_idx)++;
			break;
		case ALGORITHM_RIGHT_ASYMMETRIC://向右不对齐
			pd_idx = sector_div(stripe2, raid_disks);
			if (*dd_idx >= pd_idx)
				(*dd_idx)++;
			break;
		case ALGORITHM_LEFT_SYMMETRIC://向左对齐
			pd_idx = data_disks - sector_div(stripe2, raid_disks);
			*dd_idx = (pd_idx + 1 + *dd_idx) % raid_disks;
			break;
		case ALGORITHM_RIGHT_SYMMETRIC://向右对齐
			pd_idx = sector_div(stripe2, raid_disks);
			*dd_idx = (pd_idx + 1 + *dd_idx) % raid_disks;
			break;
		case ALGORITHM_PARITY_0:
			pd_idx = 0;
			(*dd_idx)++;
			break;
		case ALGORITHM_PARITY_N:
			pd_idx = data_disks;
			break;
		default:
			BUG();
		}
		break;
	case 6:
		switch (algorithm) 
		{
		case ALGORITHM_LEFT_ASYMMETRIC:
			pd_idx = raid_disks - 1 - sector_div(stripe2, raid_disks);
			qd_idx = pd_idx + 1;
			if (pd_idx == raid_disks-1) {
				(*dd_idx)++;	/* Q D D D P */
				qd_idx = 0;
			} else if (*dd_idx >= pd_idx)
				(*dd_idx) += 2; /* D D P Q D */
			break;
		case ALGORITHM_RIGHT_ASYMMETRIC:
			pd_idx = sector_div(stripe2, raid_disks);
			qd_idx = pd_idx + 1;
			if (pd_idx == raid_disks-1) {
				(*dd_idx)++;	/* Q D D D P */
				qd_idx = 0;
			} else if (*dd_idx >= pd_idx)
				(*dd_idx) += 2; /* D D P Q D */
			break;
		case ALGORITHM_LEFT_SYMMETRIC:
			pd_idx = raid_disks - 1 - sector_div(stripe2, raid_disks);
			qd_idx = (pd_idx + 1) % raid_disks;
			*dd_idx = (pd_idx + 2 + *dd_idx) % raid_disks;
			break;
		case ALGORITHM_RIGHT_SYMMETRIC:
			pd_idx = sector_div(stripe2, raid_disks);
			qd_idx = (pd_idx + 1) % raid_disks;
			*dd_idx = (pd_idx + 2 + *dd_idx) % raid_disks;
			break;

		case ALGORITHM_PARITY_0:
			pd_idx = 0;
			qd_idx = 1;
			(*dd_idx) += 2;
			break;
		case ALGORITHM_PARITY_N:
			pd_idx = data_disks;
			qd_idx = data_disks + 1;
			break;

		case ALGORITHM_ROTATING_ZERO_RESTART:
			/* Exactly the same as RIGHT_ASYMMETRIC, but or
			 * of blocks for computing Q is different.
			 */
			pd_idx = sector_div(stripe2, raid_disks);
			qd_idx = pd_idx + 1;
			if (pd_idx == raid_disks-1) {
				(*dd_idx)++;	/* Q D D D P */
				qd_idx = 0;
			} else if (*dd_idx >= pd_idx)
				(*dd_idx) += 2; /* D D P Q D */
			ddf_layout = 1;
			break;

		case ALGORITHM_ROTATING_N_RESTART:
			/* Same a left_asymmetric, by first stripe is
			 * D D D P Q  rather than
			 * Q D D D P
			 */
			stripe2 += 1;
			pd_idx = raid_disks - 1 - sector_div(stripe2, raid_disks);
			qd_idx = pd_idx + 1;
			if (pd_idx == raid_disks-1) {
				(*dd_idx)++;	/* Q D D D P */
				qd_idx = 0;
			} else if (*dd_idx >= pd_idx)
				(*dd_idx) += 2; /* D D P Q D */
			ddf_layout = 1;
			break;

		case ALGORITHM_ROTATING_N_CONTINUE:
			/* Same as left_symmetric but Q is before P */
			pd_idx = raid_disks - 1 - sector_div(stripe2, raid_disks);
			qd_idx = (pd_idx + raid_disks - 1) % raid_disks;
			*dd_idx = (pd_idx + 1 + *dd_idx) % raid_disks;
			ddf_layout = 1;
			break;

		case ALGORITHM_LEFT_ASYMMETRIC_6:
			/* RAID5 left_asymmetric, with Q on last device */
			pd_idx = data_disks - sector_div(stripe2, raid_disks-1);
			if (*dd_idx >= pd_idx)
				(*dd_idx)++;
			qd_idx = raid_disks - 1;
			break;

		case ALGORITHM_RIGHT_ASYMMETRIC_6:
			pd_idx = sector_div(stripe2, raid_disks-1);
			if (*dd_idx >= pd_idx)
				(*dd_idx)++;
			qd_idx = raid_disks - 1;
			break;

		case ALGORITHM_LEFT_SYMMETRIC_6:
			pd_idx = data_disks - sector_div(stripe2, raid_disks-1);
			*dd_idx = (pd_idx + 1 + *dd_idx) % (raid_disks-1);
			qd_idx = raid_disks - 1;
			break;

		case ALGORITHM_RIGHT_SYMMETRIC_6:
			pd_idx = sector_div(stripe2, raid_disks-1);
			*dd_idx = (pd_idx + 1 + *dd_idx) % (raid_disks-1);
			qd_idx = raid_disks - 1;
			break;

		case ALGORITHM_PARITY_0_6:
			pd_idx = 0;
			(*dd_idx)++;
			qd_idx = raid_disks - 1;
			break;

		default:
			BUG();
		}
		break;
	}

	if (sh) 
	{
		sh->pd_idx = pd_idx;
		sh->qd_idx = qd_idx;
		sh->ddf_layout = ddf_layout;
	}
	/*
	 * Finally, compute the new sector number
	 */
	new_sector = (sector_t)stripe * sectors_per_chunk + chunk_offset;
	return new_sector;
}


static sector_t compute_blocknr(struct stripe_head *sh, int i, int previous)
{
	raid5_conf_t *conf = sh->raid_conf;
	int raid_disks = sh->disks;
	int data_disks = raid_disks - conf->max_degraded;
	sector_t new_sector = sh->sector, check;
	int sectors_per_chunk = previous ? conf->prev_chunk_sectors
					 : conf->chunk_sectors;
	int algorithm = previous ? conf->prev_algo
				 : conf->algorithm;
	sector_t stripe;
	int chunk_offset;
	sector_t chunk_number;
	int dummy1, dd_idx = i;
	sector_t r_sector;
	struct stripe_head sh2;


	chunk_offset = sector_div(new_sector, sectors_per_chunk);
	stripe = new_sector;

	if (i == sh->pd_idx)
		return 0;
	switch(conf->level) 
	{
	case 4: break;
	case 5:
		switch (algorithm) 
		{
		case ALGORITHM_LEFT_ASYMMETRIC:
		case ALGORITHM_RIGHT_ASYMMETRIC:
			if (i > sh->pd_idx)
				i--;
			break;
		case ALGORITHM_LEFT_SYMMETRIC:
		case ALGORITHM_RIGHT_SYMMETRIC:
			if (i < sh->pd_idx)
				i += raid_disks;
			i -= (sh->pd_idx + 1);
			break;
		case ALGORITHM_PARITY_0:
			i -= 1;
			break;
		case ALGORITHM_PARITY_N:
			break;
		default:
			BUG();
		}
		break;
	case 6:
		if (i == sh->qd_idx)
			return 0; /* It is the Q disk */
		switch (algorithm) {
		case ALGORITHM_LEFT_ASYMMETRIC:
		case ALGORITHM_RIGHT_ASYMMETRIC:
		case ALGORITHM_ROTATING_ZERO_RESTART:
		case ALGORITHM_ROTATING_N_RESTART:
			if (sh->pd_idx == raid_disks-1)
				i--;	/* Q D D D P */
			else if (i > sh->pd_idx)
				i -= 2; /* D D P Q D */
			break;
		case ALGORITHM_LEFT_SYMMETRIC:
		case ALGORITHM_RIGHT_SYMMETRIC:
			if (sh->pd_idx == raid_disks-1)
				i--; /* Q D D D P */
			else {
				/* D D P Q D */
				if (i < sh->pd_idx)
					i += raid_disks;
				i -= (sh->pd_idx + 2);
			}
			break;
		case ALGORITHM_PARITY_0:
			i -= 2;
			break;
		case ALGORITHM_PARITY_N:
			break;
		case ALGORITHM_ROTATING_N_CONTINUE:
			/* Like left_symmetric, but P is before Q */
			if (sh->pd_idx == 0)
				i--;	/* P D D D Q */
			else {
				/* D D Q P D */
				if (i < sh->pd_idx)
					i += raid_disks;
				i -= (sh->pd_idx + 1);
			}
			break;
		case ALGORITHM_LEFT_ASYMMETRIC_6:
		case ALGORITHM_RIGHT_ASYMMETRIC_6:
			if (i > sh->pd_idx)
				i--;
			break;
		case ALGORITHM_LEFT_SYMMETRIC_6:
		case ALGORITHM_RIGHT_SYMMETRIC_6:
			if (i < sh->pd_idx)
				i += data_disks + 1;
			i -= (sh->pd_idx + 1);
			break;
		case ALGORITHM_PARITY_0_6:
			i -= 1;
			break;
		default:
			BUG();
		}
		break;
	}

	chunk_number = stripe * data_disks + i;
	r_sector = chunk_number * sectors_per_chunk + chunk_offset;

	check = raid5_compute_sector(conf, r_sector,
				     previous, &dummy1, &sh2);
	if (check != sh->sector || dummy1 != dd_idx || sh2.pd_idx != sh->pd_idx
		|| sh2.qd_idx != sh->qd_idx) {
		printk(KERN_ERR "md/raid:%s: compute_blocknr: map not correct\n",
		       mdname(conf->mddev));
		return 0;
	}
	return r_sector;
}

/**ltl
功能:计算校验和(调度数据"重构"):
参数:
说明:
*/
static void
schedule_reconstruction(struct stripe_head *sh, struct stripe_head_state *s,
			 int rcw, int expand)
{
	int i, pd_idx = sh->pd_idx, disks = sh->disks;
	raid5_conf_t *conf = sh->raid_conf;
	int level = conf->level;
	//"重构写"
	if (rcw) 
	{
		/* if we are not expanding this is a proper write request, and
		 * there will be bios with new data to be drained into the
		 * stripe cache
		 */
		if (!expand) //不是扩展
		{
			//reconstruct_state_drain_run表示先"抽干"，再异或的动作系列
			sh->reconstruct_state = reconstruct_state_drain_run;
			set_bit(STRIPE_OP_BIODRAIN, &s->ops_request);
		} else
			sh->reconstruct_state = reconstruct_state_run;
		//设置STRIPE_OP_BIODRAIN和STRIPE_OP_RECONSTRUCT，
		set_bit(STRIPE_OP_RECONSTRUCT, &s->ops_request);

		for (i = disks; i--; ) 
		{
			struct r5dev *dev = &sh->dev[i];

			if (dev->towrite) 
			{
				set_bit(R5_LOCKED, &dev->flags);	
				//表明需要将数据从"bio"抽干到页面缓存。
				set_bit(R5_Wantdrain, &dev->flags);
				if (!expand)
					clear_bit(R5_UPTODATE, &dev->flags);
				s->locked++;
			}
		}
		if (s->locked + conf->max_degraded == disks)
			if (!test_and_set_bit(STRIPE_FULL_WRITE, &sh->state))
				atomic_inc(&conf->pending_full_writes);
	}
	else
	{//在"读改写"条件下
		BUG_ON(level == 6);
		BUG_ON(!(test_bit(R5_UPTODATE, &sh->dev[pd_idx].flags) ||
			test_bit(R5_Wantcompute, &sh->dev[pd_idx].flags)));
		//表明此条带是"prexor""抽干"异或的执行系列。
		sh->reconstruct_state = reconstruct_state_prexor_drain_run;
		set_bit(STRIPE_OP_PREXOR, &s->ops_request);
		set_bit(STRIPE_OP_BIODRAIN, &s->ops_request);
		set_bit(STRIPE_OP_RECONSTRUCT, &s->ops_request);

		for (i = disks; i--; ) 
		{
			struct r5dev *dev = &sh->dev[i];
			if (i == pd_idx)
				continue;

			if (dev->towrite &&
			    (test_bit(R5_UPTODATE, &dev->flags) ||
			     test_bit(R5_Wantcompute, &dev->flags)))
			{
				//设置R5_Wantdrain标志，表明需要将数据从"bio"抽干到页面缓存。
				set_bit(R5_Wantdrain, &dev->flags);
				set_bit(R5_LOCKED, &dev->flags);
				clear_bit(R5_UPTODATE, &dev->flags);
				s->locked++;
			}
		}
	}

	/* keep the parity disk(s) locked while asynchronous operations
	 * are in flight
	 */
	set_bit(R5_LOCKED, &sh->dev[pd_idx].flags);
	clear_bit(R5_UPTODATE, &sh->dev[pd_idx].flags);
	s->locked++;

	if (level == 6) 
	{
		int qd_idx = sh->qd_idx;
		struct r5dev *dev = &sh->dev[qd_idx];

		set_bit(R5_LOCKED, &dev->flags);
		clear_bit(R5_UPTODATE, &dev->flags);
		s->locked++;
	}

	pr_debug("%s: stripe %llu locked: %d ops_request: %lx\n",__func__, (unsigned long long)sh->sector,
		s->locked, s->ops_request);
}

/*
 * Each stripe/dev can have one or more bion attached.
 * toread/towrite point to the first in a chain.
 * The bi_next chain must be in order.
 */
/**ltl
功能:添加请求到条带/设备
参数:sh		->
	bi		->
	dd_idx	->
	forwrite	->
返回值:
说明:
*/
static int add_stripe_bio(struct stripe_head *sh, struct bio *bi, int dd_idx, int forwrite)
{
	struct bio **bip;
	raid5_conf_t *conf = sh->raid_conf;
	int firstwrite=0;

	pr_debug("adding bh b#%llu to stripe s#%llu\n",
		(unsigned long long)bi->bi_sector,
		(unsigned long long)sh->sector);


	spin_lock(&sh->lock);
	spin_lock_irq(&conf->device_lock);
	//找到适当的bio链表:towrite/toread(重构写/重构读)
	if (forwrite) 
	{
		bip = &sh->dev[dd_idx].towrite;
		//是否是第一次写操作(towrite和written两个链表为NULL)。
		if (*bip == NULL && sh->dev[dd_idx].written == NULL)
			firstwrite = 1;
	} 
	else
		bip = &sh->dev[dd_idx].toread;
	//把到bio链表中与要插入bio对象的扇区相近的bio对象。
	while (*bip && (*bip)->bi_sector < bi->bi_sector) 
	{
		//确保不重叠(如果所有的起始扇区小于请求的起始扇区，则所有请求的的结束扇区要小于请求起始扇区，才不会出现重叠)
		if ((*bip)->bi_sector + ((*bip)->bi_size >> 9) > bi->bi_sector)
			goto overlap;
		bip = & (*bip)->bi_next;
	}
	//确保不重叠(如果所有请求的起始扇区大于请求起始扇区，则)所有请求的结束扇区要大于请求的起始扇区，才不会出现重叠)
	if (*bip && (*bip)->bi_sector < bi->bi_sector + ((bi->bi_size)>>9))
		goto overlap;

	BUG_ON(*bip && bi->bi_next && (*bip) != bi->bi_next);

	//把bio对象插入链表
	if (*bip)
		bi->bi_next = *bip;	
	*bip = bi;
	//递增内存段的引用计数器
	bi->bi_phys_segments++;
	spin_unlock_irq(&conf->device_lock);
	spin_unlock(&sh->lock);

	pr_debug("added bi b#%llu to stripe s#%llu, disk %d.\n",(unsigned long long)bi->bi_sector,(unsigned long long)sh->sector, dd_idx);
	//如果设备支持位图，并且是第一次写入，则设置STRIPE_BIT_DELAY标志，使在__release_stripes时，bio首先插入到bitmap_list列表中。
	if (conf->mddev->bitmap && firstwrite) 
	{
		//bitmap_startwrite还没有写入到磁盘的。
		bitmap_startwrite(conf->mddev->bitmap, sh->sector,STRIPE_SECTORS, 0);
		sh->bm_seq = conf->seq_flush+1;//记录位图冲刷次数，但还没有真正写入到磁盘中。
		set_bit(STRIPE_BIT_DELAY, &sh->state);
	}
	//第一次写。
	if (forwrite) 
	{
		/* check if page is covered */
		sector_t sector = sh->dev[dd_idx].sector;
		for (bi=sh->dev[dd_idx].towrite;
		     sector < sh->dev[dd_idx].sector + STRIPE_SECTORS && bi && bi->bi_sector <= sector;
		     bi = r5_next_bio(bi, sh->dev[dd_idx].sector)) 
		{
			if (bi->bi_sector + (bi->bi_size>>9) >= sector)
				sector = bi->bi_sector + (bi->bi_size>>9);
		}
		if (sector >= sh->dev[dd_idx].sector + STRIPE_SECTORS)
			set_bit(R5_OVERWRITE, &sh->dev[dd_idx].flags);
	}
	return 1;

 overlap:
	set_bit(R5_Overlap, &sh->dev[dd_idx].flags);
	spin_unlock_irq(&conf->device_lock);
	spin_unlock(&sh->lock);
	return 0;
}

static void end_reshape(raid5_conf_t *conf);

static void stripe_set_idx(sector_t stripe, raid5_conf_t *conf, int previous,
			    struct stripe_head *sh)
{
	int sectors_per_chunk =
		previous ? conf->prev_chunk_sectors : conf->chunk_sectors;
	int dd_idx;
	int chunk_offset = sector_div(stripe, sectors_per_chunk);
	int disks = previous ? conf->previous_raid_disks : conf->raid_disks;
	/*计算P校验单元编号、Q校验单元编号、ddf_layout标志。*/
	raid5_compute_sector(conf,
			     stripe * (disks - conf->max_degraded)
			     *sectors_per_chunk + chunk_offset,
			     previous,
			     &dd_idx, sh);
}
/**ltl
功能:处理出现错误的条带
参数:
说明:把出错信息发送给上层。
*/
static void handle_failed_stripe(raid5_conf_t *conf, struct stripe_head *sh,
				struct stripe_head_state *s, int disks,
				struct bio **return_bi)
{
	int i;
	for (i = disks; i--; ) {
		struct bio *bi;
		int bitmap_end = 0;

		if (test_bit(R5_ReadError, &sh->dev[i].flags)) {
			mdk_rdev_t *rdev;
			rcu_read_lock();
			rdev = rcu_dereference(conf->disks[i].rdev);
			if (rdev && test_bit(In_sync, &rdev->flags))
				/* multiple read failures in one stripe */
				md_error(conf->mddev, rdev);
			rcu_read_unlock();
		}
		spin_lock_irq(&conf->device_lock);
		/* fail all writes first */
		bi = sh->dev[i].towrite;
		sh->dev[i].towrite = NULL;
		if (bi) {
			s->to_write--;
			bitmap_end = 1;
		}

		if (test_and_clear_bit(R5_Overlap, &sh->dev[i].flags))
			wake_up(&conf->wait_for_overlap);

		while (bi && bi->bi_sector <
			sh->dev[i].sector + STRIPE_SECTORS) {
			struct bio *nextbi = r5_next_bio(bi, sh->dev[i].sector);
			clear_bit(BIO_UPTODATE, &bi->bi_flags);
			if (!raid5_dec_bi_phys_segments(bi)) {
				md_write_end(conf->mddev);
				bi->bi_next = *return_bi;
				*return_bi = bi;
			}
			bi = nextbi;
		}
		/* and fail all 'written' */
		bi = sh->dev[i].written;
		sh->dev[i].written = NULL;
		if (bi) bitmap_end = 1;
		while (bi && bi->bi_sector <
		       sh->dev[i].sector + STRIPE_SECTORS) {
			struct bio *bi2 = r5_next_bio(bi, sh->dev[i].sector);
			clear_bit(BIO_UPTODATE, &bi->bi_flags);
			if (!raid5_dec_bi_phys_segments(bi)) {
				md_write_end(conf->mddev);
				bi->bi_next = *return_bi;
				*return_bi = bi;
			}
			bi = bi2;
		}

		/* fail any reads if this device is non-operational and
		 * the data has not reached the cache yet.
		 */
		if (!test_bit(R5_Wantfill, &sh->dev[i].flags) &&
		    (!test_bit(R5_Insync, &sh->dev[i].flags) ||
		      test_bit(R5_ReadError, &sh->dev[i].flags))) {
			bi = sh->dev[i].toread;
			sh->dev[i].toread = NULL;
			if (test_and_clear_bit(R5_Overlap, &sh->dev[i].flags))
				wake_up(&conf->wait_for_overlap);
			if (bi) s->to_read--;
			while (bi && bi->bi_sector <
			       sh->dev[i].sector + STRIPE_SECTORS) {
				struct bio *nextbi =
					r5_next_bio(bi, sh->dev[i].sector);
				clear_bit(BIO_UPTODATE, &bi->bi_flags);
				if (!raid5_dec_bi_phys_segments(bi)) {
					bi->bi_next = *return_bi;
					*return_bi = bi;
				}
				bi = nextbi;
			}
		}
		spin_unlock_irq(&conf->device_lock);
		if (bitmap_end)
			bitmap_endwrite(conf->mddev->bitmap, sh->sector,
					STRIPE_SECTORS, 0, 0);
	}

	if (test_and_clear_bit(STRIPE_FULL_WRITE, &sh->state))
		if (atomic_dec_and_test(&conf->pending_full_writes))
			md_wakeup_thread(conf->mddev->thread);
}

/* fetch_block5 - checks the given member device to see if its data needs
 * to be read or computed to satisfy a request.
 *
 * Returns 1 when no more member devices need to be checked, otherwise returns
 * 0 to tell the loop in handle_stripe_fill5 to continue
 */
/**ltl
功能:检查给定的成员磁盘，看是否它的数据需要被读取，或计算，以满足请求。
参数:sh		->
	s		->
	disk_idx	->
	disks		->
返回值:1->当没有更多的成员磁盘需要被检查时。
	 0->通知handle_stripe_fill5函数中的循环继续
说明:
*/
static int fetch_block5(struct stripe_head *sh, struct stripe_head_state *s,
			int disk_idx, int disks)
{
	struct r5dev *dev = &sh->dev[disk_idx];
	struct r5dev *failed_dev = &sh->dev[s->failed_num];

	/* is the data in this block needed, and can we get it? */
	/*1.成员磁盘未上锁、非最新；
	*2.要读取成员磁盘、非覆写成员磁盘、条带在同步中、条带在扩展中，有故障磁盘并且要读取或非覆写故障磁盘。
	*/
	if (!test_bit(R5_LOCKED, &dev->flags) &&
	    !test_bit(R5_UPTODATE, &dev->flags) &&
	    (dev->toread ||
	     (dev->towrite && !test_bit(R5_OVERWRITE, &dev->flags)) ||
	     s->syncing || s->expanding ||
	     (s->failed &&
	      (failed_dev->toread ||
	       (failed_dev->towrite &&
		!test_bit(R5_OVERWRITE, &failed_dev->flags))))))
	{
		/* We would like to get this block, possibly by computing it,
		 * otherwise read it if the backing disk is insync
		 */
		/*
		*1.该条带中所有其它成员磁盘的数据都已经读入页面缓存。
		2.条带中有故障磁盘，并且故障磁盘即为该成员磁盘。
		*/
		if ((s->uptodate == disks - 1) &&
		    (s->failed && disk_idx == s->failed_num)) 
		{
			set_bit(STRIPE_COMPUTE_RUN, &sh->state);
			set_bit(STRIPE_OP_COMPUTE_BLK, &s->ops_request);
			set_bit(R5_Wantcompute, &dev->flags);
			sh->ops.target = disk_idx;//设置校验和计算的目标磁盘编号
			sh->ops.target2 = -1;
			s->req_compute = 1;//表示要为条带计算校验和
			/* Careful: from this point on 'uptodate' is in the eye
			 * of raid_run_ops which services 'compute' operations
			 * before writes. R5_Wantcompute flags a block that will
			 * be R5_UPTODATE by the time it is needed for a
			 * subsequent operation.
			 */
			s->uptodate++;
			return 1; /* uptodate + compute == disks */
		} 
		else if (test_bit(R5_Insync, &dev->flags))
		{
			//设置R5_LOCKED和R5_Wantread两个标志。
			set_bit(R5_LOCKED, &dev->flags);
			set_bit(R5_Wantread, &dev->flags);
			s->locked++;
			pr_debug("Reading block %d (sync=%d)\n", disk_idx,s->syncing);
		}
	}

	return 0;
}

/**
 * handle_stripe_fill5 - read or compute data to satisfy pending requests.
 */
static void handle_stripe_fill5(struct stripe_head *sh,
			struct stripe_head_state *s, int disks)
{
	int i;

	/* look for blocks to read/compute, skip this if a compute
	 * is already in flight, or if the stripe contents are in the
	 * midst of changing due to a write
	 */
	/*1.条带不处于计算校验和；2.不处于检查状态；3.不处于重构状态*/
	if (!test_bit(STRIPE_COMPUTE_RUN, &sh->state) && !sh->check_state &&
	    !sh->reconstruct_state)
		for (i = disks; i--; )
			if (fetch_block5(sh, s, i, disks))
				break;
	set_bit(STRIPE_HANDLE, &sh->state);
}

/* fetch_block6 - checks the given member device to see if its data needs
 * to be read or computed to satisfy a request.
 *
 * Returns 1 when no more member devices need to be checked, otherwise returns
 * 0 to tell the loop in handle_stripe_fill6 to continue
 */
static int fetch_block6(struct stripe_head *sh, struct stripe_head_state *s,
			 struct r6_state *r6s, int disk_idx, int disks)
{
	struct r5dev *dev = &sh->dev[disk_idx];
	struct r5dev *fdev[2] = { &sh->dev[r6s->failed_num[0]],
				  &sh->dev[r6s->failed_num[1]] };

	if (!test_bit(R5_LOCKED, &dev->flags) &&
	    !test_bit(R5_UPTODATE, &dev->flags) &&
	    (dev->toread ||
	     (dev->towrite && !test_bit(R5_OVERWRITE, &dev->flags)) ||
	     s->syncing || s->expanding ||
	     (s->failed >= 1 &&
	      (fdev[0]->toread || s->to_write)) ||
	     (s->failed >= 2 &&
	      (fdev[1]->toread || s->to_write)))) {
		/* we would like to get this block, possibly by computing it,
		 * otherwise read it if the backing disk is insync
		 */
		BUG_ON(test_bit(R5_Wantcompute, &dev->flags));
		BUG_ON(test_bit(R5_Wantread, &dev->flags));
		if ((s->uptodate == disks - 1) &&
		    (s->failed && (disk_idx == r6s->failed_num[0] ||
				   disk_idx == r6s->failed_num[1]))) {
			/* have disk failed, and we're requested to fetch it;
			 * do compute it
			 */
			pr_debug("Computing stripe %llu block %d\n",
			       (unsigned long long)sh->sector, disk_idx);
			set_bit(STRIPE_COMPUTE_RUN, &sh->state);
			set_bit(STRIPE_OP_COMPUTE_BLK, &s->ops_request);
			set_bit(R5_Wantcompute, &dev->flags);
			sh->ops.target = disk_idx;
			sh->ops.target2 = -1; /* no 2nd target */
			s->req_compute = 1;
			s->uptodate++;
			return 1;
		} else if (s->uptodate == disks-2 && s->failed >= 2) {
			/* Computing 2-failure is *very* expensive; only
			 * do it if failed >= 2
			 */
			int other;
			for (other = disks; other--; ) {
				if (other == disk_idx)
					continue;
				if (!test_bit(R5_UPTODATE,
				      &sh->dev[other].flags))
					break;
			}
			BUG_ON(other < 0);
			pr_debug("Computing stripe %llu blocks %d,%d\n",
			       (unsigned long long)sh->sector,
			       disk_idx, other);
			set_bit(STRIPE_COMPUTE_RUN, &sh->state);
			set_bit(STRIPE_OP_COMPUTE_BLK, &s->ops_request);
			set_bit(R5_Wantcompute, &sh->dev[disk_idx].flags);
			set_bit(R5_Wantcompute, &sh->dev[other].flags);
			sh->ops.target = disk_idx;
			sh->ops.target2 = other;
			s->uptodate += 2;
			s->req_compute = 1;
			return 1;
		} else if (test_bit(R5_Insync, &dev->flags)) {
			set_bit(R5_LOCKED, &dev->flags);
			set_bit(R5_Wantread, &dev->flags);
			s->locked++;
			pr_debug("Reading block %d (sync=%d)\n",
				disk_idx, s->syncing);
		}
	}

	return 0;
}

/**
 * handle_stripe_fill6 - read or compute data to satisfy pending requests.
 */
static void handle_stripe_fill6(struct stripe_head *sh,
			struct stripe_head_state *s, struct r6_state *r6s,
			int disks)
{
	int i;

	/* look for blocks to read/compute, skip this if a compute
	 * is already in flight, or if the stripe contents are in the
	 * midst of changing due to a write
	 */
	if (!test_bit(STRIPE_COMPUTE_RUN, &sh->state) && !sh->check_state &&
	    !sh->reconstruct_state)
		for (i = disks; i--; )
			if (fetch_block6(sh, s, r6s, i, disks))
				break;
	set_bit(STRIPE_HANDLE, &sh->state);
}


/* handle_stripe_clean_event
 * any written block on an uptodate or failed drive can be returned.
 * Note that if we 'wrote' to a failed drive, it will be UPTODATE, but
 * never LOCKED, so we don't need to test 'failed' directly.
 */
/**ltl
功能:向上层报告写请求执行的结果
参数:conf	->RAID5个性化的私有数据
	sh	->条带对象
	disks	->成员磁盘的数量
	return_bi->返回已经完成的写请求bio对象
说明:并不是调用bio的完成处理函数来通知上层，调用bio完成处理函数的工作由return_io函数完成。
*/
static void handle_stripe_clean_event(raid5_conf_t *conf,
	struct stripe_head *sh, int disks, struct bio **return_bi)
{
	int i;
	struct r5dev *dev;

	for (i = disks; i--; )
		if (sh->dev[i].written) 
		{
			dev = &sh->dev[i];
			//R5_LOCKED标志在bio完成处理函数raid5_end_write_request中清除。
			//R5_UPTODATE标志在ops_complete_reconstruct函数中设置
			if (!test_bit(R5_LOCKED, &dev->flags) &&
				test_bit(R5_UPTODATE, &dev->flags))
			{
				/* We can return any write requests */
				struct bio *wbi, *wbi2;
				int bitmap_end = 0;
				pr_debug("Return write for disc %d\n", i);
				spin_lock_irq(&conf->device_lock);
				wbi = dev->written;
				dev->written = NULL;
				while (wbi && wbi->bi_sector < dev->sector + STRIPE_SECTORS)
				{
					wbi2 = r5_next_bio(wbi, dev->sector);
					if (!raid5_dec_bi_phys_segments(wbi)) 
					{//通知上层已经把数据写入磁盘(为什么要这个步骤通知上层呢?)
						md_write_end(conf->mddev);
						wbi->bi_next = *return_bi;
						*return_bi = wbi;
					}
					wbi = wbi2;
				}
				if (dev->towrite == NULL)
					bitmap_end = 1;
				spin_unlock_irq(&conf->device_lock);
				if (bitmap_end)
					bitmap_endwrite(conf->mddev->bitmap,sh->sector,STRIPE_SECTORS,!test_bit(STRIPE_DEGRADED, &sh->state),0);
			}
		}

	if (test_and_clear_bit(STRIPE_FULL_WRITE, &sh->state))
		if (atomic_dec_and_test(&conf->pending_full_writes))
			md_wakeup_thread(conf->mddev->thread);
}

/**ltl
功能:
参数:
说明:确定写方式，因为是重构写，为所有要覆盖写和校验以外的条带/设备设置已上锁、非最新及R5_Wantread标志。
*/
static void handle_stripe_dirtying5(raid5_conf_t *conf,
		struct stripe_head *sh,	struct stripe_head_state *s, int disks)
{
	int rmw = 0, rcw = 0, i;
	/*确定两种写请求的方式:1.读改写；2.重构写。
	*rmw:反映在"读改写"下应该执行的读操作次数；
	*rcw:反映在"重构写"下应该执行的读操作次数。
	*/
	for (i = disks; i--; ) 
	{
		/* would I have to read this buffer for read_modify_write */
		struct r5dev *dev = &sh->dev[i];
		/*"读改写"的条件:
		*1.成员磁盘有写请求(覆写或者非覆写)，或者为校验盘。
		*2.成员磁盘未上锁、非最新、并且没有表明"希望通过计算得到"
		*/
		if ((dev->towrite || i == sh->pd_idx) &&
		    !test_bit(R5_LOCKED, &dev->flags) &&
		    !(test_bit(R5_UPTODATE, &dev->flags) ||
		      test_bit(R5_Wantcompute, &dev->flags))) 
		{
			if (test_bit(R5_Insync, &dev->flags))
				rmw++;
			else
				rmw += 2*disks;  /* cannot read it */
		}
		/* Would I have to read this buffer for reconstruct_write */

		/*"重构写"的条件:
		*1.成员磁盘非覆写；2.成员磁盘不是校验盘；3.成员磁盘未上锁、非最新、并且没有表明"希望通过计算得到"
		*Q:何谓非覆写?
		*/
		if (!test_bit(R5_OVERWRITE, &dev->flags) && i != sh->pd_idx &&
		    !test_bit(R5_LOCKED, &dev->flags) &&
		    !(test_bit(R5_UPTODATE, &dev->flags) ||
		    test_bit(R5_Wantcompute, &dev->flags))) 
		{
			if (test_bit(R5_Insync, &dev->flags)) 
				rcw++;
			else
				rcw += 2*disks;
		}
	}
	pr_debug("for sector %llu, rmw=%d rcw=%d\n",
		(unsigned long long)sh->sector, rmw, rcw);
	set_bit(STRIPE_HANDLE, &sh->state);
	//采用"读改写"模式
	if (rmw < rcw && rmw > 0)
		/* prefer read-modify-write, but need to get some data */
		for (i = disks; i--; ) 
		{
			struct r5dev *dev = &sh->dev[i];
			if ((dev->towrite || i == sh->pd_idx) &&
			    !test_bit(R5_LOCKED, &dev->flags) &&
			    !(test_bit(R5_UPTODATE, &dev->flags) ||
			    test_bit(R5_Wantcompute, &dev->flags)) &&
			    test_bit(R5_Insync, &dev->flags)) 
			{
				//若条带已经处于"激活预读"状态下
				if (test_bit(STRIPE_PREREAD_ACTIVE, &sh->state)) 
				{
					pr_debug("Read_old block %d for r-m-w\n", i);
					set_bit(R5_LOCKED, &dev->flags);
					set_bit(R5_Wantread, &dev->flags);
					s->locked++;
				} 
				else 
				{
					//设置STRIPE_DELAYED,最终把此条带插入到delayed_list链表。(要注意什么情况下设置STRIPE_DELAYED标志，在P486有解释)
					set_bit(STRIPE_DELAYED, &sh->state);
					set_bit(STRIPE_HANDLE, &sh->state);
				}
			}
		}
	//采用"重构写"模式
	if (rcw <= rmw && rcw > 0)
		/* want reconstruct write, but need to get some data */
		for (i = disks; i--; ) 
		{
			struct r5dev *dev = &sh->dev[i];
			if (!test_bit(R5_OVERWRITE, &dev->flags) &&
			    i != sh->pd_idx &&
			    !test_bit(R5_LOCKED, &dev->flags) &&
			    !(test_bit(R5_UPTODATE, &dev->flags) ||
			    test_bit(R5_Wantcompute, &dev->flags)) &&
			    test_bit(R5_Insync, &dev->flags)) 
			{
				//若条带已经处于"激活预读"状态下
				if (test_bit(STRIPE_PREREAD_ACTIVE, &sh->state))
				{
					pr_debug("Read_old block %d for Reconstruct\n", i);
					set_bit(R5_LOCKED, &dev->flags);
					set_bit(R5_Wantread, &dev->flags);
					s->locked++;
				} 
				else 
				{
					set_bit(STRIPE_DELAYED, &sh->state);
					set_bit(STRIPE_HANDLE, &sh->state);
				}
			}
		}
	/* now if nothing is locked, and if we have enough data,
	 * we can start a write request
	 */
	/* since handle_stripe can be called at any time we need to handle the
	 * case where a compute block operation has been submitted and then a
	 * subsequent call wants to start a write request.  raid_run_ops only
	 * handles the case where compute block and reconstruct are requested
	 * simultaneously.  If this is not the case then new writes need to be
	 * held off until the compute completes.
	 */
	/*计算校验和(调度数据"重构"):
	*1.条带未上锁；
	*2.选定的"重构写"和"读改写"方式已经将所需成员磁盘数据读入内存(rcw==0||rmw==0);
	*3.条带没有设置STRIPE_BIT_DELAY标志(说明必要数据已经读入到内存，可以基于这些数据计算校验和)
	*4.条带的当前状态已经不是STRIPE_COMPUTE_RUN
	*/
	if ((s->req_compute || !test_bit(STRIPE_COMPUTE_RUN, &sh->state)) &&
	    (s->locked == 0 && (rcw == 0 || rmw == 0) &&
	    !test_bit(STRIPE_BIT_DELAY, &sh->state)))
		schedule_reconstruction(sh, s, rcw == 0, 0);
}

static void handle_stripe_dirtying6(raid5_conf_t *conf,
		struct stripe_head *sh,	struct stripe_head_state *s,
		struct r6_state *r6s, int disks)
{
	int rcw = 0, pd_idx = sh->pd_idx, i;
	int qd_idx = sh->qd_idx;

	set_bit(STRIPE_HANDLE, &sh->state);
	for (i = disks; i--; ) {
		struct r5dev *dev = &sh->dev[i];
		/* check if we haven't enough data */
		if (!test_bit(R5_OVERWRITE, &dev->flags) &&
		    i != pd_idx && i != qd_idx &&
		    !test_bit(R5_LOCKED, &dev->flags) &&
		    !(test_bit(R5_UPTODATE, &dev->flags) ||
		      test_bit(R5_Wantcompute, &dev->flags))) {
			rcw++;
			if (!test_bit(R5_Insync, &dev->flags))
				continue; /* it's a failed drive */

			if (
			  test_bit(STRIPE_PREREAD_ACTIVE, &sh->state)) {
				pr_debug("Read_old stripe %llu "
					"block %d for Reconstruct\n",
				     (unsigned long long)sh->sector, i);
				set_bit(R5_LOCKED, &dev->flags);
				set_bit(R5_Wantread, &dev->flags);
				s->locked++;
			} else {
				pr_debug("Request delayed stripe %llu "
					"block %d for Reconstruct\n",
				     (unsigned long long)sh->sector, i);
				set_bit(STRIPE_DELAYED, &sh->state);
				set_bit(STRIPE_HANDLE, &sh->state);
			}
		}
	}
	/* now if nothing is locked, and if we have enough data, we can start a
	 * write request
	 */
	if ((s->req_compute || !test_bit(STRIPE_COMPUTE_RUN, &sh->state)) &&
	    s->locked == 0 && rcw == 0 &&
	    !test_bit(STRIPE_BIT_DELAY, &sh->state)) {
		schedule_reconstruction(sh, s, 1, 0);
	}
}

static void handle_parity_checks5(raid5_conf_t *conf, struct stripe_head *sh,
				struct stripe_head_state *s, int disks)
{
	struct r5dev *dev = NULL;

	set_bit(STRIPE_HANDLE, &sh->state);

	switch (sh->check_state) {
	case check_state_idle:
		/* start a new check operation if there are no failures */
		if (s->failed == 0) {
			BUG_ON(s->uptodate != disks);
			sh->check_state = check_state_run;
			set_bit(STRIPE_OP_CHECK, &s->ops_request);
			clear_bit(R5_UPTODATE, &sh->dev[sh->pd_idx].flags);
			s->uptodate--;
			break;
		}
		dev = &sh->dev[s->failed_num];
		/* fall through */
	case check_state_compute_result:
		sh->check_state = check_state_idle;
		if (!dev)
			dev = &sh->dev[sh->pd_idx];

		/* check that a write has not made the stripe insync */
		if (test_bit(STRIPE_INSYNC, &sh->state))
			break;

		/* either failed parity check, or recovery is happening */
		BUG_ON(!test_bit(R5_UPTODATE, &dev->flags));
		BUG_ON(s->uptodate != disks);

		set_bit(R5_LOCKED, &dev->flags);
		s->locked++;
		set_bit(R5_Wantwrite, &dev->flags);

		clear_bit(STRIPE_DEGRADED, &sh->state);
		set_bit(STRIPE_INSYNC, &sh->state);
		break;
	case check_state_run:
		break; /* we will be called again upon completion */
	case check_state_check_result:
		sh->check_state = check_state_idle;

		/* if a failure occurred during the check operation, leave
		 * STRIPE_INSYNC not set and let the stripe be handled again
		 */
		if (s->failed)
			break;

		/* handle a successful check operation, if parity is correct
		 * we are done.  Otherwise update the mismatch count and repair
		 * parity if !MD_RECOVERY_CHECK
		 */
		if ((sh->ops.zero_sum_result & SUM_CHECK_P_RESULT) == 0)
			/* parity is correct (on disc,
			 * not in buffer any more)
			 */
			set_bit(STRIPE_INSYNC, &sh->state);
		else {
			conf->mddev->resync_mismatches += STRIPE_SECTORS;
			if (test_bit(MD_RECOVERY_CHECK, &conf->mddev->recovery))
				/* don't try to repair!! */
				set_bit(STRIPE_INSYNC, &sh->state);
			else {
				sh->check_state = check_state_compute_run;
				set_bit(STRIPE_COMPUTE_RUN, &sh->state);
				set_bit(STRIPE_OP_COMPUTE_BLK, &s->ops_request);
				set_bit(R5_Wantcompute,
					&sh->dev[sh->pd_idx].flags);
				sh->ops.target = sh->pd_idx;
				sh->ops.target2 = -1;
				s->uptodate++;
			}
		}
		break;
	case check_state_compute_run:
		break;
	default:
		printk(KERN_ERR "%s: unknown check_state: %d sector: %llu\n",
		       __func__, sh->check_state,
		       (unsigned long long) sh->sector);
		BUG();
	}
}


static void handle_parity_checks6(raid5_conf_t *conf, struct stripe_head *sh,
				  struct stripe_head_state *s,
				  struct r6_state *r6s, int disks)
{
	int pd_idx = sh->pd_idx;
	int qd_idx = sh->qd_idx;
	struct r5dev *dev;

	set_bit(STRIPE_HANDLE, &sh->state);

	BUG_ON(s->failed > 2);

	/* Want to check and possibly repair P and Q.
	 * However there could be one 'failed' device, in which
	 * case we can only check one of them, possibly using the
	 * other to generate missing data
	 */

	switch (sh->check_state) {
	case check_state_idle:
		/* start a new check operation if there are < 2 failures */
		if (s->failed == r6s->q_failed) {
			/* The only possible failed device holds Q, so it
			 * makes sense to check P (If anything else were failed,
			 * we would have used P to recreate it).
			 */
			sh->check_state = check_state_run;
		}
		if (!r6s->q_failed && s->failed < 2) {
			/* Q is not failed, and we didn't use it to generate
			 * anything, so it makes sense to check it
			 */
			if (sh->check_state == check_state_run)
				sh->check_state = check_state_run_pq;
			else
				sh->check_state = check_state_run_q;
		}

		/* discard potentially stale zero_sum_result */
		sh->ops.zero_sum_result = 0;

		if (sh->check_state == check_state_run) {
			/* async_xor_zero_sum destroys the contents of P */
			clear_bit(R5_UPTODATE, &sh->dev[pd_idx].flags);
			s->uptodate--;
		}
		if (sh->check_state >= check_state_run &&
		    sh->check_state <= check_state_run_pq) {
			/* async_syndrome_zero_sum preserves P and Q, so
			 * no need to mark them !uptodate here
			 */
			set_bit(STRIPE_OP_CHECK, &s->ops_request);
			break;
		}

		/* we have 2-disk failure */
		BUG_ON(s->failed != 2);
		/* fall through */
	case check_state_compute_result:
		sh->check_state = check_state_idle;

		/* check that a write has not made the stripe insync */
		if (test_bit(STRIPE_INSYNC, &sh->state))
			break;

		/* now write out any block on a failed drive,
		 * or P or Q if they were recomputed
		 */
		BUG_ON(s->uptodate < disks - 1); /* We don't need Q to recover */
		if (s->failed == 2) {
			dev = &sh->dev[r6s->failed_num[1]];
			s->locked++;
			set_bit(R5_LOCKED, &dev->flags);
			set_bit(R5_Wantwrite, &dev->flags);
		}
		if (s->failed >= 1) {
			dev = &sh->dev[r6s->failed_num[0]];
			s->locked++;
			set_bit(R5_LOCKED, &dev->flags);
			set_bit(R5_Wantwrite, &dev->flags);
		}
		if (sh->ops.zero_sum_result & SUM_CHECK_P_RESULT) {
			dev = &sh->dev[pd_idx];
			s->locked++;
			set_bit(R5_LOCKED, &dev->flags);
			set_bit(R5_Wantwrite, &dev->flags);
		}
		if (sh->ops.zero_sum_result & SUM_CHECK_Q_RESULT) {
			dev = &sh->dev[qd_idx];
			s->locked++;
			set_bit(R5_LOCKED, &dev->flags);
			set_bit(R5_Wantwrite, &dev->flags);
		}
		clear_bit(STRIPE_DEGRADED, &sh->state);

		set_bit(STRIPE_INSYNC, &sh->state);
		break;
	case check_state_run:
	case check_state_run_q:
	case check_state_run_pq:
		break; /* we will be called again upon completion */
	case check_state_check_result:
		sh->check_state = check_state_idle;

		/* handle a successful check operation, if parity is correct
		 * we are done.  Otherwise update the mismatch count and repair
		 * parity if !MD_RECOVERY_CHECK
		 */
		if (sh->ops.zero_sum_result == 0) {
			/* both parities are correct */
			if (!s->failed)
				set_bit(STRIPE_INSYNC, &sh->state);
			else {
				/* in contrast to the raid5 case we can validate
				 * parity, but still have a failure to write
				 * back
				 */
				sh->check_state = check_state_compute_result;
				/* Returning at this point means that we may go
				 * off and bring p and/or q uptodate again so
				 * we make sure to check zero_sum_result again
				 * to verify if p or q need writeback
				 */
			}
		} else {
			conf->mddev->resync_mismatches += STRIPE_SECTORS;
			if (test_bit(MD_RECOVERY_CHECK, &conf->mddev->recovery))
				/* don't try to repair!! */
				set_bit(STRIPE_INSYNC, &sh->state);
			else {
				int *target = &sh->ops.target;

				sh->ops.target = -1;
				sh->ops.target2 = -1;
				sh->check_state = check_state_compute_run;
				set_bit(STRIPE_COMPUTE_RUN, &sh->state);
				set_bit(STRIPE_OP_COMPUTE_BLK, &s->ops_request);
				if (sh->ops.zero_sum_result & SUM_CHECK_P_RESULT) {
					set_bit(R5_Wantcompute,
						&sh->dev[pd_idx].flags);
					*target = pd_idx;
					target = &sh->ops.target2;
					s->uptodate++;
				}
				if (sh->ops.zero_sum_result & SUM_CHECK_Q_RESULT) {
					set_bit(R5_Wantcompute,
						&sh->dev[qd_idx].flags);
					*target = qd_idx;
					s->uptodate++;
				}
			}
		}
		break;
	case check_state_compute_run:
		break;
	default:
		printk(KERN_ERR "%s: unknown check_state: %d sector: %llu\n",
		       __func__, sh->check_state,
		       (unsigned long long) sh->sector);
		BUG();
	}
}

static void handle_stripe_expansion(raid5_conf_t *conf, struct stripe_head *sh,
				struct r6_state *r6s)
{
	int i;

	/* We have read all the blocks in this stripe and now we need to
	 * copy some of them into a target stripe for expand.
	 */
	struct dma_async_tx_descriptor *tx = NULL;
	clear_bit(STRIPE_EXPAND_SOURCE, &sh->state);
	for (i = 0; i < sh->disks; i++)
		if (i != sh->pd_idx && i != sh->qd_idx) {
			int dd_idx, j;
			struct stripe_head *sh2;
			struct async_submit_ctl submit;

			sector_t bn = compute_blocknr(sh, i, 1);
			sector_t s = raid5_compute_sector(conf, bn, 0,
							  &dd_idx, NULL);
			sh2 = get_active_stripe(conf, s, 0, 1, 1);
			if (sh2 == NULL)
				/* so far only the early blocks of this stripe
				 * have been requested.  When later blocks
				 * get requested, we will try again
				 */
				continue;
			if (!test_bit(STRIPE_EXPANDING, &sh2->state) ||
			   test_bit(R5_Expanded, &sh2->dev[dd_idx].flags)) {
				/* must have already done this block */
				release_stripe(sh2);
				continue;
			}

			/* place all the copies on one channel */
			init_async_submit(&submit, 0, tx, NULL, NULL, NULL);
			tx = async_memcpy(sh2->dev[dd_idx].page,
					  sh->dev[i].page, 0, 0, STRIPE_SIZE,
					  &submit);

			set_bit(R5_Expanded, &sh2->dev[dd_idx].flags);
			set_bit(R5_UPTODATE, &sh2->dev[dd_idx].flags);
			for (j = 0; j < conf->raid_disks; j++)
				if (j != sh2->pd_idx &&
				    (!r6s || j != sh2->qd_idx) &&
				    !test_bit(R5_Expanded, &sh2->dev[j].flags))
					break;
			if (j == conf->raid_disks) {
				set_bit(STRIPE_EXPAND_READY, &sh2->state);
				set_bit(STRIPE_HANDLE, &sh2->state);
			}
			release_stripe(sh2);

		}
	/* done submitting copies, wait for them to complete */
	if (tx) {
		async_tx_ack(tx);
		dma_wait_for_async_tx(tx);
	}
}


/*
 * handle_stripe - do things to a stripe.
 *
 * We lock the stripe and then examine the state of various bits
 * to see what needs to be done.
 * Possible results:
 *    return some read request which now have data
 *    return some write requests which are safely on disc
 *    schedule a read on some buffers
 *    schedule a write of some buffers
 *    return confirmation of parity correctness
 *
 * buffers are taken off read_list or write_list, and bh_cache buffers
 * get BH_Lock set before the stripe lock is released.
 *
 */
/**ltl
功能:对一个条带的处理函数
参数:
说明:
*/
static void handle_stripe5(struct stripe_head *sh)
{
	raid5_conf_t *conf = sh->raid_conf;
	int disks = sh->disks, i;
	struct bio *return_bi = NULL;
	struct stripe_head_state s;
	struct r5dev *dev;
	mdk_rdev_t *blocked_rdev = NULL;
	int prexor;
	int dec_preread_active = 0;
	//条带状态
	memset(&s, 0, sizeof(s));
	pr_debug("handling stripe %llu, state=%#lx cnt=%d, pd_idx=%d check:%d reconstruct:%d\n", 
		(unsigned long long)sh->sector, sh->state, atomic_read(&sh->count), sh->pd_idx, sh->check_state,sh->reconstruct_state);

	spin_lock(&sh->lock);
	//清除两个标志
	clear_bit(STRIPE_HANDLE, &sh->state);
	clear_bit(STRIPE_DELAYED, &sh->state);

	s.syncing = test_bit(STRIPE_SYNCING, &sh->state);
	s.expanding = test_bit(STRIPE_EXPAND_SOURCE, &sh->state);
	s.expanded = test_bit(STRIPE_EXPAND_READY, &sh->state);

	/* Now to look around and see what can be done */
	rcu_read_lock();
	//统计
	for (i=disks; i--; ) 
	{
		mdk_rdev_t *rdev;

		dev = &sh->dev[i];

		pr_debug("check %d: state 0x%lx toread %p read %p write %p written %p\n",	
			i, dev->flags, dev->toread, dev->read,dev->towrite, dev->written);

		/* maybe we can request a biofill operation
		 *
		 * new wantfill requests are only permitted while
		 * ops_complete_biofill is guaranteed to be inactive
		 */
		/*
		*如果条带/设备已更新，希望有读请求，并且条带当前不在STRIPE_BIOFILL_RUN状态，这种情况表明可以用条带/设备
		*在页面缓存的数据复制到bio中以满足外部读请求，设置成员磁盘的R5_Wantfill标志。
		*/
		if (test_bit(R5_UPTODATE, &dev->flags) && dev->toread && !test_bit(STRIPE_BIOFILL_RUN, &sh->state))
			set_bit(R5_Wantfill, &dev->flags);

		/* now count some things */
		if (test_bit(R5_LOCKED, &dev->flags))//已经上锁的成员磁盘数
			s.locked++;
		if (test_bit(R5_UPTODATE, &dev->flags)) //已经更新的成员磁盘数
			s.uptodate++;
		if (test_bit(R5_Wantcompute, &dev->flags)) //"希望计算"的成员磁盘数。
			s.compute++;

		if (test_bit(R5_Wantfill, &dev->flags))//"希望填充"的成员磁盘数
			s.to_fill++;
		else if (dev->toread)//"有读请求"的成员磁盘数。
			s.to_read++;
		
		if (dev->towrite) //"有写请求"的成员磁盘数。
		{
			s.to_write++;
			if (!test_bit(R5_OVERWRITE, &dev->flags))//"非覆写"的成员磁盘数。
				s.non_overwrite++;
		}
		if (dev->written)//"可以提交写请求"的成员磁盘数。
			s.written++;
		rdev = rcu_dereference(conf->disks[i].rdev);
		/*失效的成员磁盘*/
		if (blocked_rdev == NULL &&
		    rdev && unlikely(test_bit(Blocked, &rdev->flags))) 
		{
			blocked_rdev = rdev;
			atomic_inc(&rdev->nr_pending);
		}
		
		clear_bit(R5_Insync, &dev->flags);
		if (!rdev)
			/* Not in-sync */;
		else if (test_bit(In_sync, &rdev->flags))
			set_bit(R5_Insync, &dev->flags);
		else 
		{
			/* could be in-sync depending on recovery/reshape status */
			if (sh->sector + STRIPE_SECTORS <= rdev->recovery_offset)
				set_bit(R5_Insync, &dev->flags);
		}
		if (!test_bit(R5_Insync, &dev->flags)) 
		{
			/* The ReadError flag will just be confusing now */
			clear_bit(R5_ReadError, &dev->flags);
			clear_bit(R5_ReWrite, &dev->flags);
		}
		if (test_bit(R5_ReadError, &dev->flags))
			clear_bit(R5_Insync, &dev->flags);
		//"失效"的成员磁盘数以及编号
		if (!test_bit(R5_Insync, &dev->flags)) 
		{
			s.failed++;
			s.failed_num = i;
		}
	}
	rcu_read_unlock();
	//有出错的磁盘
	if (unlikely(blocked_rdev)) 
	{
		if (s.syncing || s.expanding || s.expanded || s.to_write || s.written)
		{
			set_bit(STRIPE_HANDLE, &sh->state);
			goto unlock;
		}
		/* There is nothing for the blocked_rdev to block */
		rdev_dec_pending(blocked_rdev, conf->mddev);
		blocked_rdev = NULL;
	}
	//如果有成员磁盘需要填充bio，并且条带当前不在STRIPE_BIOFILL_RUN状态。
	if (s.to_fill && !test_bit(STRIPE_BIOFILL_RUN, &sh->state))
	{
		set_bit(STRIPE_OP_BIOFILL, &s.ops_request);
		set_bit(STRIPE_BIOFILL_RUN, &sh->state);
	}

	pr_debug("locked=%d uptodate=%d to_read=%d to_write=%d failed=%d failed_num=%d\n",
		s.locked, s.uptodate, s.to_read, s.to_write,s.failed, s.failed_num);
	/* check if the array has lost two devices and, if so, some requests might
	 * need to be failed
	 */
	/*
	*如果有两个或者两个以上磁盘故障，并且对该条带有读请求、写请求、调度请求，
	*那么这些请求可以将错误报告给上层。
	*/
	if (s.failed > 1 && s.to_read+s.to_write+s.written)
		handle_failed_stripe(conf, sh, &s, disks, &return_bi);

	//如果此条带到少两个磁盘出错，并且此条带在同步中，则结束同步
	if (s.failed > 1 && s.syncing) 
	{
		md_done_sync(conf->mddev, STRIPE_SECTORS,0);
		clear_bit(STRIPE_SYNCING, &sh->state);
		s.syncing = 0;
	}

	/* might be able to return some write requests if the parity block
	 * is safe, or on a failed drive
	 */
	dev = &sh->dev[sh->pd_idx];
	/*
	*如果条带有调度写，并且校验磁盘处于同步状态，未上锁，已经更新；或者条带有调度写，并且校验盘故障。
	*出现这两种情况都表明写已经完成。这时候调用handle_stripe_clean_event向上层报告写结果。
	*/
	if ( s.written &&
	     ((test_bit(R5_Insync, &dev->flags) &&
	       !test_bit(R5_LOCKED, &dev->flags) &&
	       test_bit(R5_UPTODATE, &dev->flags)) ||
	       (s.failed == 1 && s.failed_num == sh->pd_idx)))
	{//向上层报告写请求执行的结果
		handle_stripe_clean_event(conf, sh, disks, &return_bi);
	}

	/* Now we might consider reading some blocks, either to check/generate
	 * parity, or to satisfy requests
	 * or to load a block that is being partially written.
	 */
	/*
	*考虑读取某些块，或者为检查/生成校验值，或者为满足请求，或者为加载一个正部分写入的块。这些情况:
	*1.条带有读请求；2.条带有非覆盖写请求；3.条带正在同步；且已更新或已计算的磁盘数目小于磁盘数目；
	*4.条带正在扩展。
	*/
	if (s.to_read || s.non_overwrite ||
	    (s.syncing && (s.uptodate + s.compute < disks)) || s.expanding)
		handle_stripe_fill5(sh, &s, disks);

	/* Now we check to see if any write operations have recently
	 * completed
	 */
	/*在ops_complete_reconstruct函数中设置了reconstruct_state值。*/
	prexor = 0;
	if (sh->reconstruct_state == reconstruct_state_prexor_drain_result)
		prexor = 1;
	
	if (sh->reconstruct_state == reconstruct_state_drain_result/*重构写*/ ||
	    sh->reconstruct_state == reconstruct_state_prexor_drain_result/*读改写*/)
	{
		sh->reconstruct_state = reconstruct_state_idle;

		/* All the 'written' buffers and the parity block are ready to
		 * be written back to disk
		 */
		BUG_ON(!test_bit(R5_UPTODATE, &sh->dev[sh->pd_idx].flags));
		/*
		*遍历所有的成员磁盘，对于待定的成员磁盘以及校验磁盘，设置R5_Wantwrite标志，表示希望将它们在页面缓存中的数据写入磁盘中。
		*/
		for (i = disks; i--; ) 
		{
			dev = &sh->dev[i];
			if (test_bit(R5_LOCKED, &dev->flags) &&
				(i == sh->pd_idx || dev->written)) 
			{
				pr_debug("Writing block %d\n", i);
				set_bit(R5_Wantwrite, &dev->flags);
				if (prexor)
					continue;
				if (!test_bit(R5_Insync, &dev->flags) ||
				    (i == sh->pd_idx && s.failed == 0))
					set_bit(STRIPE_INSYNC, &sh->state);//此条带数据要以同步方式写入到成员磁盘中。
			}
		}
		if (test_and_clear_bit(STRIPE_PREREAD_ACTIVE, &sh->state))
			dec_preread_active = 1;
	}

	/* Now to consider new write requests and what else, if anything
	 * should be read.  We do not handle new writes when:
	 * 1/ A 'write' operation (copy+xor) is already in flight.
	 * 2/ A 'check' operation is in flight, as it may clobber the parity
	 *    block.
	 */
	 /*该条带有写请求，且不在重构状态和校验状态。*/
	if (s.to_write && !sh->reconstruct_state && !sh->check_state)
		handle_stripe_dirtying5(conf, sh, &s, disks);

	/* maybe we need to check and possibly fix the parity for this stripe
	 * Any reads will already have been scheduled, so we just see if enough
	 * data is available.  The parity check is held off while parity
	 * dependent operations are in flight.
	 */
	/*
	*如果条带设置了校验状态，或者条带在同步中，未上锁，并且不存在STRIPE_COMPUTE_RUN和STRIPE_INSYNC标志。
	*/
	if (sh->check_state ||
	    (s.syncing && s.locked == 0 &&
	     !test_bit(STRIPE_COMPUTE_RUN, &sh->state) &&
	     !test_bit(STRIPE_INSYNC, &sh->state)))
		handle_parity_checks5(conf, sh, &s, disks);
	/*
	*如果条带在同步中，未上锁，并且设置了STRIPE_INSYNC标志。
	*/
	if (s.syncing && s.locked == 0 && test_bit(STRIPE_INSYNC, &sh->state)) 
	{
		//结束同步
		md_done_sync(conf->mddev, STRIPE_SECTORS,1);
		//清除同步标志
		clear_bit(STRIPE_SYNCING, &sh->state);
	}

	/* If the failed drive is just a ReadError, then we might need to progress
	 * the repair/check process
	 */
	/*
	*可能需要进入"坏扇区修复"的过程，条件是条带的故障磁盘数为1，MD设备不是只读的，故障磁盘设置R5_ReadError标志，
	*磁盘未上锁，已更新。
	*"坏扇区修复"分两步骤:1.先尝试写回计算好的数据；2.读回数据。
	*/
	if (s.failed == 1 && !conf->mddev->ro &&
	    test_bit(R5_ReadError, &sh->dev[s.failed_num].flags)
	    && !test_bit(R5_LOCKED, &sh->dev[s.failed_num].flags)
	    && test_bit(R5_UPTODATE, &sh->dev[s.failed_num].flags)) 
	{
		dev = &sh->dev[s.failed_num];
		if (!test_bit(R5_ReWrite, &dev->flags)) 
		{
			set_bit(R5_Wantwrite, &dev->flags);
			set_bit(R5_ReWrite, &dev->flags);
			set_bit(R5_LOCKED, &dev->flags);
			s.locked++;
		} 
		else 
		{
			/* let's read it back */
			set_bit(R5_Wantread, &dev->flags);
			set_bit(R5_LOCKED, &dev->flags);
			s.locked++;
		}
	}
	//以下代码与扩展有关。。。。。。
	/* Finish reconstruct operations initiated by the expansion process */
	if (sh->reconstruct_state == reconstruct_state_result) 
	{
		struct stripe_head *sh2	= get_active_stripe(conf, sh->sector, 1, 1, 1);
		if (sh2 && test_bit(STRIPE_EXPAND_SOURCE, &sh2->state)) 
		{
			/* sh cannot be written until sh2 has been read.
			 * so arrange for sh to be delayed a little
			 */
			set_bit(STRIPE_DELAYED, &sh->state);
			set_bit(STRIPE_HANDLE, &sh->state);
			if (!test_and_set_bit(STRIPE_PREREAD_ACTIVE,&sh2->state))
				atomic_inc(&conf->preread_active_stripes);
			release_stripe(sh2);
			goto unlock;
		}
		if (sh2)
			release_stripe(sh2);

		sh->reconstruct_state = reconstruct_state_idle;
		clear_bit(STRIPE_EXPANDING, &sh->state);
		for (i = conf->raid_disks; i--; ) 
		{
			set_bit(R5_Wantwrite, &sh->dev[i].flags);
			set_bit(R5_LOCKED, &sh->dev[i].flags);
			s.locked++;
		}
	}

	if (s.expanded && test_bit(STRIPE_EXPANDING, &sh->state) &&
	    !sh->reconstruct_state) 
	{
		/* Need to write out all blocks after computing parity */
		sh->disks = conf->raid_disks;
		stripe_set_idx(sh->sector, conf, 0, sh);
		schedule_reconstruction(sh, &s, 1, 1);
	} 
	else if (s.expanded && !sh->reconstruct_state && s.locked == 0) 
	{
		clear_bit(STRIPE_EXPAND_READY, &sh->state);
		atomic_dec(&conf->reshape_stripes);
		wake_up(&conf->wait_for_overlap);
		md_done_sync(conf->mddev, STRIPE_SECTORS, 1);
	}

	if (s.expanding && s.locked == 0 &&
	    !test_bit(STRIPE_COMPUTE_RUN, &sh->state))
		handle_stripe_expansion(conf, sh, NULL);

 unlock:
	spin_unlock(&sh->lock);

	/* wait for this device to become unblocked */
	if (unlikely(blocked_rdev))
		md_wait_for_blocked_rdev(blocked_rdev, conf->mddev);
	//有异步操作要执行。
	if (s.ops_request)
		raid_run_ops(sh, s.ops_request);
	//是否有IO需要调度
	ops_run_io(sh, &s);

	if (dec_preread_active) 
	{
		/* We delay this until after ops_run_io so that if make_request
		 * is waiting on a barrier, it won't continue until the writes
		 * have actually been submitted.
		 */
		atomic_dec(&conf->preread_active_stripes);
		if (atomic_read(&conf->preread_active_stripes) < IO_THRESHOLD)
			md_wakeup_thread(conf->mddev->thread);
	}
	//前面的代码已经把完成的bio放在以return_bi为表头的链表，以下会依顺序结束链表中的bio，向上层报告结果。
	return_io(return_bi);
}

static void handle_stripe6(struct stripe_head *sh)
{
	raid5_conf_t *conf = sh->raid_conf;
	int disks = sh->disks;
	struct bio *return_bi = NULL;
	int i, pd_idx = sh->pd_idx, qd_idx = sh->qd_idx;
	struct stripe_head_state s;
	struct r6_state r6s;
	struct r5dev *dev, *pdev, *qdev;
	mdk_rdev_t *blocked_rdev = NULL;
	int dec_preread_active = 0;

	pr_debug("handling stripe %llu, state=%#lx cnt=%d, "
		"pd_idx=%d, qd_idx=%d\n, check:%d, reconstruct:%d\n",
	       (unsigned long long)sh->sector, sh->state,
	       atomic_read(&sh->count), pd_idx, qd_idx,
	       sh->check_state, sh->reconstruct_state);
	memset(&s, 0, sizeof(s));

	spin_lock(&sh->lock);
	clear_bit(STRIPE_HANDLE, &sh->state);
	clear_bit(STRIPE_DELAYED, &sh->state);

	s.syncing = test_bit(STRIPE_SYNCING, &sh->state);
	s.expanding = test_bit(STRIPE_EXPAND_SOURCE, &sh->state);
	s.expanded = test_bit(STRIPE_EXPAND_READY, &sh->state);
	/* Now to look around and see what can be done */

	rcu_read_lock();
	for (i=disks; i--; ) {
		mdk_rdev_t *rdev;
		dev = &sh->dev[i];

		pr_debug("check %d: state 0x%lx read %p write %p written %p\n",
			i, dev->flags, dev->toread, dev->towrite, dev->written);
		/* maybe we can reply to a read
		 *
		 * new wantfill requests are only permitted while
		 * ops_complete_biofill is guaranteed to be inactive
		 */
		if (test_bit(R5_UPTODATE, &dev->flags) && dev->toread &&
		    !test_bit(STRIPE_BIOFILL_RUN, &sh->state))
			set_bit(R5_Wantfill, &dev->flags);

		/* now count some things */
		if (test_bit(R5_LOCKED, &dev->flags)) s.locked++;
		if (test_bit(R5_UPTODATE, &dev->flags)) s.uptodate++;
		if (test_bit(R5_Wantcompute, &dev->flags)) {
			s.compute++;
			BUG_ON(s.compute > 2);
		}

		if (test_bit(R5_Wantfill, &dev->flags)) {
			s.to_fill++;
		} else if (dev->toread)
			s.to_read++;
		if (dev->towrite) {
			s.to_write++;
			if (!test_bit(R5_OVERWRITE, &dev->flags))
				s.non_overwrite++;
		}
		if (dev->written)
			s.written++;
		rdev = rcu_dereference(conf->disks[i].rdev);
		if (blocked_rdev == NULL &&
		    rdev && unlikely(test_bit(Blocked, &rdev->flags))) {
			blocked_rdev = rdev;
			atomic_inc(&rdev->nr_pending);
		}
		clear_bit(R5_Insync, &dev->flags);
		if (!rdev)
			/* Not in-sync */;
		else if (test_bit(In_sync, &rdev->flags))
			set_bit(R5_Insync, &dev->flags);
		else {
			/* in sync if before recovery_offset */
			if (sh->sector + STRIPE_SECTORS <= rdev->recovery_offset)
				set_bit(R5_Insync, &dev->flags);
		}
		if (!test_bit(R5_Insync, &dev->flags)) {
			/* The ReadError flag will just be confusing now */
			clear_bit(R5_ReadError, &dev->flags);
			clear_bit(R5_ReWrite, &dev->flags);
		}
		if (test_bit(R5_ReadError, &dev->flags))
			clear_bit(R5_Insync, &dev->flags);
		if (!test_bit(R5_Insync, &dev->flags)) {
			if (s.failed < 2)
				r6s.failed_num[s.failed] = i;
			s.failed++;
		}
	}
	rcu_read_unlock();

	if (unlikely(blocked_rdev)) {
		if (s.syncing || s.expanding || s.expanded ||
		    s.to_write || s.written) {
			set_bit(STRIPE_HANDLE, &sh->state);
			goto unlock;
		}
		/* There is nothing for the blocked_rdev to block */
		rdev_dec_pending(blocked_rdev, conf->mddev);
		blocked_rdev = NULL;
	}

	if (s.to_fill && !test_bit(STRIPE_BIOFILL_RUN, &sh->state)) {
		set_bit(STRIPE_OP_BIOFILL, &s.ops_request);
		set_bit(STRIPE_BIOFILL_RUN, &sh->state);
	}

	pr_debug("locked=%d uptodate=%d to_read=%d"
	       " to_write=%d failed=%d failed_num=%d,%d\n",
	       s.locked, s.uptodate, s.to_read, s.to_write, s.failed,
	       r6s.failed_num[0], r6s.failed_num[1]);
	/* check if the array has lost >2 devices and, if so, some requests
	 * might need to be failed
	 */
	if (s.failed > 2 && s.to_read+s.to_write+s.written)
		handle_failed_stripe(conf, sh, &s, disks, &return_bi);
	if (s.failed > 2 && s.syncing) {
		md_done_sync(conf->mddev, STRIPE_SECTORS,0);
		clear_bit(STRIPE_SYNCING, &sh->state);
		s.syncing = 0;
	}

	/*
	 * might be able to return some write requests if the parity blocks
	 * are safe, or on a failed drive
	 */
	pdev = &sh->dev[pd_idx];
	r6s.p_failed = (s.failed >= 1 && r6s.failed_num[0] == pd_idx)
		|| (s.failed >= 2 && r6s.failed_num[1] == pd_idx);
	qdev = &sh->dev[qd_idx];
	r6s.q_failed = (s.failed >= 1 && r6s.failed_num[0] == qd_idx)
		|| (s.failed >= 2 && r6s.failed_num[1] == qd_idx);

	if ( s.written &&
	     ( r6s.p_failed || ((test_bit(R5_Insync, &pdev->flags)
			     && !test_bit(R5_LOCKED, &pdev->flags)
			     && test_bit(R5_UPTODATE, &pdev->flags)))) &&
	     ( r6s.q_failed || ((test_bit(R5_Insync, &qdev->flags)
			     && !test_bit(R5_LOCKED, &qdev->flags)
			     && test_bit(R5_UPTODATE, &qdev->flags)))))
		handle_stripe_clean_event(conf, sh, disks, &return_bi);

	/* Now we might consider reading some blocks, either to check/generate
	 * parity, or to satisfy requests
	 * or to load a block that is being partially written.
	 */
	if (s.to_read || s.non_overwrite || (s.to_write && s.failed) ||
	    (s.syncing && (s.uptodate + s.compute < disks)) || s.expanding)
		handle_stripe_fill6(sh, &s, &r6s, disks);

	/* Now we check to see if any write operations have recently
	 * completed
	 */
	if (sh->reconstruct_state == reconstruct_state_drain_result) {

		sh->reconstruct_state = reconstruct_state_idle;
		/* All the 'written' buffers and the parity blocks are ready to
		 * be written back to disk
		 */
		BUG_ON(!test_bit(R5_UPTODATE, &sh->dev[sh->pd_idx].flags));
		BUG_ON(!test_bit(R5_UPTODATE, &sh->dev[qd_idx].flags));
		for (i = disks; i--; ) {
			dev = &sh->dev[i];
			if (test_bit(R5_LOCKED, &dev->flags) &&
			    (i == sh->pd_idx || i == qd_idx ||
			     dev->written)) {
				pr_debug("Writing block %d\n", i);
				BUG_ON(!test_bit(R5_UPTODATE, &dev->flags));
				set_bit(R5_Wantwrite, &dev->flags);
				if (!test_bit(R5_Insync, &dev->flags) ||
				    ((i == sh->pd_idx || i == qd_idx) &&
				      s.failed == 0))
					set_bit(STRIPE_INSYNC, &sh->state);
			}
		}
		if (test_and_clear_bit(STRIPE_PREREAD_ACTIVE, &sh->state))
			dec_preread_active = 1;
	}

	/* Now to consider new write requests and what else, if anything
	 * should be read.  We do not handle new writes when:
	 * 1/ A 'write' operation (copy+gen_syndrome) is already in flight.
	 * 2/ A 'check' operation is in flight, as it may clobber the parity
	 *    block.
	 */
	if (s.to_write && !sh->reconstruct_state && !sh->check_state)
		handle_stripe_dirtying6(conf, sh, &s, &r6s, disks);

	/* maybe we need to check and possibly fix the parity for this stripe
	 * Any reads will already have been scheduled, so we just see if enough
	 * data is available.  The parity check is held off while parity
	 * dependent operations are in flight.
	 */
	if (sh->check_state ||
	    (s.syncing && s.locked == 0 &&
	     !test_bit(STRIPE_COMPUTE_RUN, &sh->state) &&
	     !test_bit(STRIPE_INSYNC, &sh->state)))
		handle_parity_checks6(conf, sh, &s, &r6s, disks);

	if (s.syncing && s.locked == 0 && test_bit(STRIPE_INSYNC, &sh->state)) {
		md_done_sync(conf->mddev, STRIPE_SECTORS,1);
		clear_bit(STRIPE_SYNCING, &sh->state);
	}

	/* If the failed drives are just a ReadError, then we might need
	 * to progress the repair/check process
	 */
	if (s.failed <= 2 && !conf->mddev->ro)
		for (i = 0; i < s.failed; i++) {
			dev = &sh->dev[r6s.failed_num[i]];
			if (test_bit(R5_ReadError, &dev->flags)
			    && !test_bit(R5_LOCKED, &dev->flags)
			    && test_bit(R5_UPTODATE, &dev->flags)
				) {
				if (!test_bit(R5_ReWrite, &dev->flags)) {
					set_bit(R5_Wantwrite, &dev->flags);
					set_bit(R5_ReWrite, &dev->flags);
					set_bit(R5_LOCKED, &dev->flags);
					s.locked++;
				} else {
					/* let's read it back */
					set_bit(R5_Wantread, &dev->flags);
					set_bit(R5_LOCKED, &dev->flags);
					s.locked++;
				}
			}
		}

	/* Finish reconstruct operations initiated by the expansion process */
	if (sh->reconstruct_state == reconstruct_state_result) {
		sh->reconstruct_state = reconstruct_state_idle;
		clear_bit(STRIPE_EXPANDING, &sh->state);
		for (i = conf->raid_disks; i--; ) {
			set_bit(R5_Wantwrite, &sh->dev[i].flags);
			set_bit(R5_LOCKED, &sh->dev[i].flags);
			s.locked++;
		}
	}

	if (s.expanded && test_bit(STRIPE_EXPANDING, &sh->state) &&
	    !sh->reconstruct_state) {
		struct stripe_head *sh2
			= get_active_stripe(conf, sh->sector, 1, 1, 1);
		if (sh2 && test_bit(STRIPE_EXPAND_SOURCE, &sh2->state)) {
			/* sh cannot be written until sh2 has been read.
			 * so arrange for sh to be delayed a little
			 */
			set_bit(STRIPE_DELAYED, &sh->state);
			set_bit(STRIPE_HANDLE, &sh->state);
			if (!test_and_set_bit(STRIPE_PREREAD_ACTIVE,
					      &sh2->state))
				atomic_inc(&conf->preread_active_stripes);
			release_stripe(sh2);
			goto unlock;
		}
		if (sh2)
			release_stripe(sh2);

		/* Need to write out all blocks after computing P&Q */
		sh->disks = conf->raid_disks;
		stripe_set_idx(sh->sector, conf, 0, sh);
		schedule_reconstruction(sh, &s, 1, 1);
	} else if (s.expanded && !sh->reconstruct_state && s.locked == 0) {
		clear_bit(STRIPE_EXPAND_READY, &sh->state);
		atomic_dec(&conf->reshape_stripes);
		wake_up(&conf->wait_for_overlap);
		md_done_sync(conf->mddev, STRIPE_SECTORS, 1);
	}

	if (s.expanding && s.locked == 0 &&
	    !test_bit(STRIPE_COMPUTE_RUN, &sh->state))
		handle_stripe_expansion(conf, sh, &r6s);

 unlock:
	spin_unlock(&sh->lock);

	/* wait for this device to become unblocked */
	if (unlikely(blocked_rdev))
		md_wait_for_blocked_rdev(blocked_rdev, conf->mddev);

	if (s.ops_request)
		raid_run_ops(sh, s.ops_request);

	ops_run_io(sh, &s);


	if (dec_preread_active) {
		/* We delay this until after ops_run_io so that if make_request
		 * is waiting on a barrier, it won't continue until the writes
		 * have actually been submitted.
		 */
		atomic_dec(&conf->preread_active_stripes);
		if (atomic_read(&conf->preread_active_stripes) <
		    IO_THRESHOLD)
			md_wakeup_thread(conf->mddev->thread);
	}

	return_io(return_bi);
}

static void handle_stripe(struct stripe_head *sh)
{
	if (sh->raid_conf->level == 6)
		handle_stripe6(sh);
	else
		handle_stripe5(sh);
}

static void raid5_activate_delayed(raid5_conf_t *conf)
{
	/*超过了阀值，开启"畜流"写显示器。*/
	if (atomic_read(&conf->preread_active_stripes) < IO_THRESHOLD) {
		while (!list_empty(&conf->delayed_list)) {
			struct list_head *l = conf->delayed_list.next;
			struct stripe_head *sh;
			sh = list_entry(l, struct stripe_head, lru);
			list_del_init(l);
			clear_bit(STRIPE_DELAYED, &sh->state);
			if (!test_and_set_bit(STRIPE_PREREAD_ACTIVE, &sh->state))
				atomic_inc(&conf->preread_active_stripes);
			list_add_tail(&sh->lru, &conf->hold_list);
		}
	} else
		plugger_set_plug(&conf->plug);
}

static void activate_bit_delay(raid5_conf_t *conf)
{
	/* device_lock is held */
	struct list_head head;
	list_add(&head, &conf->bitmap_list);
	list_del_init(&conf->bitmap_list);
	while (!list_empty(&head)) {
		struct stripe_head *sh = list_entry(head.next, struct stripe_head, lru);
		list_del_init(&sh->lru);
		atomic_inc(&sh->count);
		__release_stripe(conf, sh);
	}
}
/**ltl
功能:"冲刷"成员磁盘
参数:
说明:
*/
static void unplug_slaves(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;
	int i;
	int devs = max(conf->raid_disks, conf->previous_raid_disks);

	rcu_read_lock();
	for (i = 0; i < devs; i++)
	{
		mdk_rdev_t *rdev = rcu_dereference(conf->disks[i].rdev);
		if (rdev && !test_bit(Faulty, &rdev->flags) && atomic_read(&rdev->nr_pending))
		{
			struct request_queue *r_queue = bdev_get_queue(rdev->bdev);

			atomic_inc(&rdev->nr_pending);
			rcu_read_unlock();
			//"泄流"成员磁盘
			blk_unplug(r_queue);

			rdev_dec_pending(rdev, mddev);
			rcu_read_lock();
		}
	}
	rcu_read_unlock();
}
/**ltl
功能:"冲刷"成员磁盘
参数:
说明:
*/
void md_raid5_unplug_device(raid5_conf_t *conf)
{
	unsigned long flags;

	spin_lock_irqsave(&conf->device_lock, flags);
	//清除"畜流"标志，并删除"排流"定时器。
	if (plugger_remove_plug(&conf->plug)) 
	{
		conf->seq_flush++;
		//把条带从delayed_list列表移动到hold_list列表中。
		raid5_activate_delayed(conf);
	}
	//唤醒守护线程
	md_wakeup_thread(conf->mddev->thread);

	spin_unlock_irqrestore(&conf->device_lock, flags);
	//"泄流"成员磁盘。
	unplug_slaves(conf->mddev);
}
EXPORT_SYMBOL_GPL(md_raid5_unplug_device);

static void raid5_unplug(struct plug_handle *plug)
{
	raid5_conf_t *conf = container_of(plug, raid5_conf_t, plug);
	md_raid5_unplug_device(conf);
}

static void raid5_unplug_queue(struct request_queue *q)
{
	mddev_t *mddev = q->queuedata;
	md_raid5_unplug_device(mddev->private);
}

int md_raid5_congested(mddev_t *mddev, int bits)
{
	raid5_conf_t *conf = mddev->private;

	/* No difference between reads and writes.  Just check
	 * how busy the stripe_cache is
	 */

	if (conf->inactive_blocked)
		return 1;
	if (conf->quiesce)
		return 1;
	if (list_empty_careful(&conf->inactive_list))
		return 1;

	return 0;
}
EXPORT_SYMBOL_GPL(md_raid5_congested);

static int raid5_congested(void *data, int bits)
{
	mddev_t *mddev = data;

	return mddev_congested(mddev, bits) ||
		md_raid5_congested(mddev, bits);
}

/* We want read requests to align with chunks where possible,
 * but write requests don't need to.
 */
static int raid5_mergeable_bvec(struct request_queue *q,
				struct bvec_merge_data *bvm,
				struct bio_vec *biovec)
{
	mddev_t *mddev = q->queuedata;
	sector_t sector = bvm->bi_sector + get_start_sect(bvm->bi_bdev);
	int max;
	unsigned int chunk_sectors = mddev->chunk_sectors;
	unsigned int bio_sectors = bvm->bi_size >> 9;

	if ((bvm->bi_rw & 1) == WRITE)
		return biovec->bv_len; /* always allow writes to be mergeable */

	if (mddev->new_chunk_sectors < mddev->chunk_sectors)
		chunk_sectors = mddev->new_chunk_sectors;
	max =  (chunk_sectors - ((sector & (chunk_sectors - 1)) + bio_sectors)) << 9;
	if (max < 0) max = 0;
	if (max <= biovec->bv_len && bio_sectors == 0)
		return biovec->bv_len;
	else
		return max;
}


static int in_chunk_boundary(mddev_t *mddev, struct bio *bio)
{
	//bio起始扇区
	sector_t sector = bio->bi_sector + get_start_sect(bio->bi_bdev);
	//一个chunk的扇区数
	unsigned int chunk_sectors = mddev->chunk_sectors;
	//bio的扇区数
	unsigned int bio_sectors = bio->bi_size >> 9;
	//reshape后，chunk长度
	if (mddev->new_chunk_sectors < mddev->chunk_sectors)
		chunk_sectors = mddev->new_chunk_sectors;
	//chunk长度大于bio请求的最后一个扇区。注:(sector & (chunk_sectors - 1))的作用!!
	return  chunk_sectors >= ((sector & (chunk_sectors - 1)) + bio_sectors);
}

/*
 *  add bio to the retry LIFO  ( in O(1) ... we are in interrupt )
 *  later sampled by raid5d.
 */
/**ltl
功能:将对齐读失败的bio对象添加到链表retry_read_aligned_list中，并唤醒守护线程处理。
参数:
说明:
*/
static void add_bio_to_retry(struct bio *bi,raid5_conf_t *conf)
{
	unsigned long flags;

	spin_lock_irqsave(&conf->device_lock, flags);
	//插入到对齐读重试链表中。
	bi->bi_next = conf->retry_read_aligned_list;
	conf->retry_read_aligned_list = bi;

	spin_unlock_irqrestore(&conf->device_lock, flags);
	//唤醒守护线程。
	md_wakeup_thread(conf->mddev->thread);
}

/**ltl
功能:从对齐读重试链表中获取一个bio对象。
参数:
返回值:
说明:
*/
static struct bio *remove_bio_from_retry(raid5_conf_t *conf)
{
	struct bio *bi;

	bi = conf->retry_read_aligned;
	if (bi) {
		conf->retry_read_aligned = NULL;
		return bi;
	}
	bi = conf->retry_read_aligned_list;
	if(bi) {
		conf->retry_read_aligned_list = bi->bi_next;
		bi->bi_next = NULL;
		/*
		 * this sets the active strip count to 1 and the processed
		 * strip count to zero (upper 8 bits)
		 */
		bi->bi_phys_segments = 1; /* biased count of active stripes */
	}

	return bi;
}


/*
 *  The "raid5_align_endio" should check if the read succeeded and if it
 *  did, call bio_endio on the original bio (having bio_put the new bio
 *  first).
 *  If the read failed..
 */
/**ltl
功能:对齐读请求完成处理函数。
参数:
说明:要重定向把完成处理传递给raid设备的上层，而非成员磁盘的上层处理。
*/
static void raid5_align_endio(struct bio *bi, int error)
{
	struct bio* raid_bi  = bi->bi_private;
	mddev_t *mddev;
	raid5_conf_t *conf;
	int uptodate = test_bit(BIO_UPTODATE, &bi->bi_flags);
	mdk_rdev_t *rdev;

	bio_put(bi);

	rdev = (void*)raid_bi->bi_next;
	raid_bi->bi_next = NULL;
	mddev = rdev->mddev;
	conf = mddev->private;
	//递减nr_pending
	rdev_dec_pending(rdev, conf->mddev);
	//对齐读请求成功处理
	if (!error && uptodate) 
	{
		bio_endio(raid_bi, 0);//调用bio完成处理函数通知上层
		//先判定活动对齐读引用计数器是否为1，如果为1则递减
		if (atomic_dec_and_test(&conf->active_aligned_reads))
			wake_up(&conf->wait_for_stripe);//唤醒因请求不到条带而睡眠的进程。
		return;
	}


	pr_debug("raid5_align_endio : io error...handing IO for a retry\n");
	//对齐读请求处理失败，把bio放入retry_read_aligned_list列表中
	add_bio_to_retry(raid_bi, conf);
}

static int bio_fits_rdev(struct bio *bi)
{
	struct request_queue *q = bdev_get_queue(bi->bi_bdev);

	if ((bi->bi_size>>9) > queue_max_sectors(q))
		return 0;
	blk_recount_segments(q, bi);
	if (bi->bi_phys_segments > queue_max_segments(q))
		return 0;

	if (q->merge_bvec_fn)
		/* it's too hard to apply the merge_bvec_fn at this stage,
		 * just just give up
		 */
		return 0;

	return 1;
}

/**ltl
功能:对齐读
参数:
返回值:
说明:一个chunk由多个扇区构成，这些扇区在同一个磁盘上。
*/
static int chunk_aligned_read(mddev_t *mddev, struct bio * raid_bio)
{
	raid5_conf_t *conf = mddev->private;
	int dd_idx;
	struct bio* align_bi;
	mdk_rdev_t *rdev;
	//不可以按对齐读处理，bio请求不在一个chunk边界内
	if (!in_chunk_boundary(mddev, raid_bio))
	{
		pr_debug("chunk_aligned_read : non aligned\n");
		return 0;
	}
	/*
	 * use bio_clone to make a copy of the bio
	 */
	//拷贝一份bio
	align_bi = bio_clone(raid_bio, GFP_NOIO);
	if (!align_bi)
		return 0;
	/*
	 *   set bi_end_io to a new function, and set bi_private to the
	 *     original bio.
	 */
	align_bi->bi_end_io  = raid5_align_endio;
	align_bi->bi_private = raid_bio;
	/*
	 *	compute position
	 */
	// 重定位起始扇区号
	align_bi->bi_sector =  raid5_compute_sector(conf, raid_bio->bi_sector, 0,&dd_idx, NULL);

	rcu_read_lock();
	//获取成员磁盘对象
	rdev = rcu_dereference(conf->disks[dd_idx].rdev);
	if (rdev && test_bit(In_sync, &rdev->flags)) 
	{
		//正在处理的请求数目递增，在raid5_align_endio中递减
		atomic_inc(&rdev->nr_pending);
		rcu_read_unlock();
		raid_bio->bi_next = (void*)rdev;
		align_bi->bi_bdev =  rdev->bdev;
		align_bi->bi_flags &= ~(1 << BIO_SEG_VALID);
		align_bi->bi_sector += rdev->data_offset;

		if (!bio_fits_rdev(align_bi)) 
		{
			/* too big in some way */
			bio_put(align_bi);
			rdev_dec_pending(rdev, mddev);
			return 0;
		}

		spin_lock_irq(&conf->device_lock);
		wait_event_lock_irq(conf->wait_for_stripe,
				    conf->quiesce == 0,
				    conf->device_lock, /* nothing */);
		//增加活动读计数器
		atomic_inc(&conf->active_aligned_reads);
		spin_unlock_irq(&conf->device_lock);
		//发送bio请求到具体的成员磁盘。
		generic_make_request(align_bi);
		return 1;
	}
	else 
	{
		rcu_read_unlock();
		bio_put(align_bi);
		return 0;
	}
}

/* __get_priority_stripe - get the next stripe to process
 *
 * Full stripe writes are allowed to pass preread active stripes up until
 * the bypass_threshold is exceeded.  In general the bypass_count
 * increments when the handle_list is handled before the hold_list; however, it
 * will not be incremented when STRIPE_IO_STARTED is sampled set signifying a
 * stripe with in flight i/o.  The bypass_count will be reset when the
 * head of the hold_list has changed, i.e. the head was promoted to the
 * handle_list.
 */
/**ltl
功能:获取下一个要处理的条带
参数:
返回值:
说明:首先从handle_list列表中获取；若handle_list为NULL,从hold_list列表中获取。
*/
static struct stripe_head *__get_priority_stripe(raid5_conf_t *conf)
{
	struct stripe_head *sh;

	pr_debug("%s: handle: %s hold: %s full_writes: %d bypass_count: %d\n",
		  __func__,
		  list_empty(&conf->handle_list) ? "empty" : "busy",
		  list_empty(&conf->hold_list) ? "empty" : "busy",
		  atomic_read(&conf->pending_full_writes), conf->bypass_count);
	//从handle_list列表中获取条带对象
	if (!list_empty(&conf->handle_list)) 
	{
		sh = list_entry(conf->handle_list.next, typeof(*sh), lru);

		if (list_empty(&conf->hold_list))
			conf->bypass_count = 0;
		else if (!test_bit(STRIPE_IO_STARTED, &sh->state))
		{
			if (conf->hold_list.next == conf->last_hold)
				conf->bypass_count++;
			else 
			{
				conf->last_hold = conf->hold_list.next;
				conf->bypass_count -= conf->bypass_threshold;
				if (conf->bypass_count < 0)
					conf->bypass_count = 0;
			}
		}
	}//从hold_list列表中获取条带对象
	else if (!list_empty(&conf->hold_list) &&
		   ((conf->bypass_threshold &&
		     conf->bypass_count > conf->bypass_threshold) ||
		    atomic_read(&conf->pending_full_writes) == 0)) 
	{
		sh = list_entry(conf->hold_list.next,
				typeof(*sh), lru);
		conf->bypass_count -= conf->bypass_threshold;
		if (conf->bypass_count < 0)
			conf->bypass_count = 0;
	} else
		return NULL;

	list_del_init(&sh->lru);
	atomic_inc(&sh->count);
	BUG_ON(atomic_read(&sh->count) != 1);
	return sh;
}

static int make_request(mddev_t *mddev, struct bio * bi)
{
	//RAID个性私有数据
	raid5_conf_t *conf = mddev->private;
	int dd_idx;
	sector_t new_sector;
	sector_t logical_sector, last_sector;
	struct stripe_head *sh;
	const int rw = bio_data_dir(bi);
	int remaining;
	//此bio是一个屏障IO,抽干所有待处理的写。
	if (unlikely(bi->bi_rw & REQ_HARDBARRIER)) 
	{
		/* Drain all pending writes.  We only really need
		 * to ensure they have been submitted, but this is
		 * easier.
		 */
		mddev->pers->quiesce(mddev, 1);
		mddev->pers->quiesce(mddev, 0);
		md_barrier_request(mddev, bi);
		return 0;
	}

	md_write_start(mddev, bi);
	
	/*对齐读请求的处理。所谓对齐读，是指要读的数据在一个Chunk边界内(chunk的所有扇区在同一个成员磁盘中)，因此只需要从某个成员磁盘读取即可，不涉及整个条带的配合。
	*换言之，可以不需要用到strip_head，直接在成员磁盘上调度读请求。
	*/
	if (rw == READ &&
	     mddev->reshape_position == MaxSector &&
	     chunk_aligned_read(mddev,bi))
		return 0;

	logical_sector = bi->bi_sector & ~((sector_t)STRIPE_SECTORS-1);
	last_sector = bi->bi_sector + (bi->bi_size>>9);
	bi->bi_next = NULL;
	bi->bi_phys_segments = 1;	/* over-loaded to count active stripes */
	//一次处理一条带(一次多个条带，一条带4K)
	//把一个bio请求分割成以条带为单位分别插入到hadle_list链表中。插入后，在md.c/md_make_request函数唤醒处理线程raid5d.
	for (;logical_sector < last_sector; logical_sector += STRIPE_SECTORS) 
	{
		DEFINE_WAIT(w);
		int disks, data_disks;
		int previous;

	retry:
		previous = 0;
		disks = conf->raid_disks;
		prepare_to_wait(&conf->wait_for_overlap, &w, TASK_UNINTERRUPTIBLE);
		if (unlikely(conf->reshape_progress != MaxSector)) 
		{
			/* spinlock is needed as reshape_progress may be
			 * 64bit on a 32bit platform, and so it might be
			 * possible to see a half-updated value
			 * Ofcourse reshape_progress could change after
			 * the lock is dropped, so once we get a reference
			 * to the stripe that we think it is, we will have
			 * to check again.
			 */
			spin_lock_irq(&conf->device_lock);
			if (mddev->delta_disks < 0 ? logical_sector < conf->reshape_progress : logical_sector >= conf->reshape_progress)
			{
				disks = conf->previous_raid_disks;
				previous = 1;
			} 
			else 
			{
				if (mddev->delta_disks < 0 ? logical_sector < conf->reshape_safe : logical_sector >= conf->reshape_safe) 
				{
					spin_unlock_irq(&conf->device_lock);
					schedule();
					goto retry;
				}
			}
			spin_unlock_irq(&conf->device_lock);
		}
		/*数据盘数量*/	
		data_disks = disks - conf->max_degraded;
		/*计算目标扇区在成员磁盘的具体位置*/
		new_sector = raid5_compute_sector(conf, logical_sector,previous,&dd_idx, NULL);
		pr_debug("raid456: make_request, sector %llu logical %llu\n",(unsigned long long)new_sector, (unsigned long long)logical_sector);
		/*获取活动条带:1.从hash表中查找；2.从inactive_list表中查找。参数previous表示是否需要预读，如果预读就不要阻塞，否则就要阻塞*/
		sh = get_active_stripe(conf, new_sector, previous,(bi->bi_rw & RWA_MASK), 0);
		if (sh) 
		{
			if (unlikely(previous)) 
			{// Q:这段代码的作用?
				/* expansion might have moved on while waiting for a
				 * stripe, so we must do the range check again.
				 * Expansion could still move past after this
				 * test, but as we are holding a reference to
				 * 'sh', we know that if that happens,
				 *  STRIPE_EXPANDING will get set and the expansion
				 * won't proceed until we finish with the stripe.
				 */
				int must_retry = 0;
				spin_lock_irq(&conf->device_lock);
				if (mddev->delta_disks < 0
				    ? logical_sector >= conf->reshape_progress
				    : logical_sector < conf->reshape_progress)
					/* mismatch, need to try again */
					must_retry = 1;
				spin_unlock_irq(&conf->device_lock);
				if (must_retry) 
				{
					release_stripe(sh);
					schedule();
					goto retry;
				}
			}
			//bio为写请求。但是落在用户空间预留的IO空间内
			if (bio_data_dir(bi) == WRITE &&
			    logical_sector >= mddev->suspend_lo &&
			    logical_sector < mddev->suspend_hi) 
			{
				//Q:把条带重新插入inactive_list列表中，下面是开始睡眠进程
				release_stripe(sh);
				/* As the suspend_* range is controlled by
				 * userspace, we want an interruptible
				 * wait.
				 */
				flush_signals(current);
				prepare_to_wait(&conf->wait_for_overlap,&w, TASK_INTERRUPTIBLE);
				if (logical_sector >= mddev->suspend_lo &&
				    logical_sector < mddev->suspend_hi)
					schedule();
				goto retry;
			}
			//
			if (test_bit(STRIPE_EXPANDING, &sh->state) ||
			    !add_stripe_bio(sh, bi, dd_idx, (bi->bi_rw&RW_MASK)))
			{
				/* Stripe is busy expanding or
				 * add failed due to overlap.  Flush everything
				 * and wait a while
				 */
				md_raid5_unplug_device(conf);
				release_stripe(sh);
				schedule();
				goto retry;
			}
			finish_wait(&conf->wait_for_overlap, &w);
			//为调用release_stripe做准备。
			set_bit(STRIPE_HANDLE, &sh->state);
			clear_bit(STRIPE_DELAYED, &sh->state);
			if (mddev->barrier && !test_and_set_bit(STRIPE_PREREAD_ACTIVE, &sh->state))
				atomic_inc(&conf->preread_active_stripes);
			//把条带对象sh插入到handle_list列表或者是hold_list列表中。同时唤醒守护线程。
			release_stripe(sh);
		}
		else 
		{
			/* cannot get stripe for read-ahead, just give-up */
			clear_bit(BIO_UPTODATE, &bi->bi_flags);
			finish_wait(&conf->wait_for_overlap, &w);
			break;
		}
			
	}
	spin_lock_irq(&conf->device_lock);
	remaining = raid5_dec_bi_phys_segments(bi);
	spin_unlock_irq(&conf->device_lock);
	if (remaining == 0) 
	{
		if ( rw == WRITE )
			md_write_end(mddev);

		bio_endio(bi, 0);
	}

	if (mddev->barrier)
	{
		/* We need to wait for the stripes to all be handled.
		 * So: wait for preread_active_stripes to drop to 0.
		 */
		wait_event(mddev->thread->wqueue,
			   atomic_read(&conf->preread_active_stripes) == 0);
	}
	return 0;
}

static sector_t raid5_size(mddev_t *mddev, sector_t sectors, int raid_disks);

static sector_t reshape_request(mddev_t *mddev, sector_t sector_nr, int *skipped)
{
	/* reshaping is quite different to recovery/resync so it is
	 * handled quite separately ... here.
	 *
	 * On each call to sync_request, we gather one chunk worth of
	 * destination stripes and flag them as expanding.
	 * Then we find all the source stripes and request reads.
	 * As the reads complete, handle_stripe will copy the data
	 * into the destination stripe and release that stripe.
	 */
	raid5_conf_t *conf = mddev->private;
	struct stripe_head *sh;
	sector_t first_sector, last_sector;
	int raid_disks = conf->previous_raid_disks;
	int data_disks = raid_disks - conf->max_degraded;
	int new_data_disks = conf->raid_disks - conf->max_degraded;
	int i;
	int dd_idx;
	sector_t writepos, readpos, safepos;
	sector_t stripe_addr;
	int reshape_sectors;
	struct list_head stripes;

	if (sector_nr == 0) {
		/* If restarting in the middle, skip the initial sectors */
		if (mddev->delta_disks < 0 &&
		    conf->reshape_progress < raid5_size(mddev, 0, 0)) {
			sector_nr = raid5_size(mddev, 0, 0)
				- conf->reshape_progress;
		} else if (mddev->delta_disks >= 0 &&
			   conf->reshape_progress > 0)
			sector_nr = conf->reshape_progress;
		sector_div(sector_nr, new_data_disks);
		if (sector_nr) {
			mddev->curr_resync_completed = sector_nr;
			sysfs_notify(&mddev->kobj, NULL, "sync_completed");
			*skipped = 1;
			return sector_nr;
		}
	}

	/* We need to process a full chunk at a time.
	 * If old and new chunk sizes differ, we need to process the
	 * largest of these
	 */
	if (mddev->new_chunk_sectors > mddev->chunk_sectors)
		reshape_sectors = mddev->new_chunk_sectors;
	else
		reshape_sectors = mddev->chunk_sectors;

	/* we update the metadata when there is more than 3Meg
	 * in the block range (that is rather arbitrary, should
	 * probably be time based) or when the data about to be
	 * copied would over-write the source of the data at
	 * the front of the range.
	 * i.e. one new_stripe along from reshape_progress new_maps
	 * to after where reshape_safe old_maps to
	 */
	writepos = conf->reshape_progress;
	sector_div(writepos, new_data_disks);
	readpos = conf->reshape_progress;
	sector_div(readpos, data_disks);
	safepos = conf->reshape_safe;
	sector_div(safepos, data_disks);
	if (mddev->delta_disks < 0) {
		writepos -= min_t(sector_t, reshape_sectors, writepos);
		readpos += reshape_sectors;
		safepos += reshape_sectors;
	} else {
		writepos += reshape_sectors;
		readpos -= min_t(sector_t, reshape_sectors, readpos);
		safepos -= min_t(sector_t, reshape_sectors, safepos);
	}

	/* 'writepos' is the most advanced device address we might write.
	 * 'readpos' is the least advanced device address we might read.
	 * 'safepos' is the least address recorded in the metadata as having
	 *     been reshaped.
	 * If 'readpos' is behind 'writepos', then there is no way that we can
	 * ensure safety in the face of a crash - that must be done by userspace
	 * making a backup of the data.  So in that case there is no particular
	 * rush to update metadata.
	 * Otherwise if 'safepos' is behind 'writepos', then we really need to
	 * update the metadata to advance 'safepos' to match 'readpos' so that
	 * we can be safe in the event of a crash.
	 * So we insist on updating metadata if safepos is behind writepos and
	 * readpos is beyond writepos.
	 * In any case, update the metadata every 10 seconds.
	 * Maybe that number should be configurable, but I'm not sure it is
	 * worth it.... maybe it could be a multiple of safemode_delay???
	 */
	if ((mddev->delta_disks < 0
	     ? (safepos > writepos && readpos < writepos)
	     : (safepos < writepos && readpos > writepos)) ||
	    time_after(jiffies, conf->reshape_checkpoint + 10*HZ)) {
		/* Cannot proceed until we've updated the superblock... */
		wait_event(conf->wait_for_overlap,
			   atomic_read(&conf->reshape_stripes)==0);
		mddev->reshape_position = conf->reshape_progress;
		mddev->curr_resync_completed = mddev->curr_resync;
		conf->reshape_checkpoint = jiffies;
		set_bit(MD_CHANGE_DEVS, &mddev->flags);
		md_wakeup_thread(mddev->thread);
		wait_event(mddev->sb_wait, mddev->flags == 0 ||
			   kthread_should_stop());
		spin_lock_irq(&conf->device_lock);
		conf->reshape_safe = mddev->reshape_position;
		spin_unlock_irq(&conf->device_lock);
		wake_up(&conf->wait_for_overlap);
		sysfs_notify(&mddev->kobj, NULL, "sync_completed");
	}

	if (mddev->delta_disks < 0) {
		BUG_ON(conf->reshape_progress == 0);
		stripe_addr = writepos;
		BUG_ON((mddev->dev_sectors &
			~((sector_t)reshape_sectors - 1))
		       - reshape_sectors - stripe_addr
		       != sector_nr);
	} else {
		BUG_ON(writepos != sector_nr + reshape_sectors);
		stripe_addr = sector_nr;
	}
	INIT_LIST_HEAD(&stripes);
	for (i = 0; i < reshape_sectors; i += STRIPE_SECTORS) {
		int j;
		int skipped_disk = 0;
		sh = get_active_stripe(conf, stripe_addr+i, 0, 0, 1);
		set_bit(STRIPE_EXPANDING, &sh->state);
		atomic_inc(&conf->reshape_stripes);
		/* If any of this stripe is beyond the end of the old
		 * array, then we need to zero those blocks
		 */
		for (j=sh->disks; j--;) {
			sector_t s;
			if (j == sh->pd_idx)
				continue;
			if (conf->level == 6 &&
			    j == sh->qd_idx)
				continue;
			s = compute_blocknr(sh, j, 0);
			if (s < raid5_size(mddev, 0, 0)) {
				skipped_disk = 1;
				continue;
			}
			memset(page_address(sh->dev[j].page), 0, STRIPE_SIZE);
			set_bit(R5_Expanded, &sh->dev[j].flags);
			set_bit(R5_UPTODATE, &sh->dev[j].flags);
		}
		if (!skipped_disk) {
			set_bit(STRIPE_EXPAND_READY, &sh->state);
			set_bit(STRIPE_HANDLE, &sh->state);
		}
		list_add(&sh->lru, &stripes);
	}
	spin_lock_irq(&conf->device_lock);
	if (mddev->delta_disks < 0)
		conf->reshape_progress -= reshape_sectors * new_data_disks;
	else
		conf->reshape_progress += reshape_sectors * new_data_disks;
	spin_unlock_irq(&conf->device_lock);
	/* Ok, those stripe are ready. We can start scheduling
	 * reads on the source stripes.
	 * The source stripes are determined by mapping the first and last
	 * block on the destination stripes.
	 */
	first_sector =
		raid5_compute_sector(conf, stripe_addr*(new_data_disks),
				     1, &dd_idx, NULL);
	last_sector =
		raid5_compute_sector(conf, ((stripe_addr+reshape_sectors)
					    * new_data_disks - 1),
				     1, &dd_idx, NULL);
	if (last_sector >= mddev->dev_sectors)
		last_sector = mddev->dev_sectors - 1;
	while (first_sector <= last_sector) {
		sh = get_active_stripe(conf, first_sector, 1, 0, 1);
		set_bit(STRIPE_EXPAND_SOURCE, &sh->state);
		set_bit(STRIPE_HANDLE, &sh->state);
		release_stripe(sh);
		first_sector += STRIPE_SECTORS;
	}
	/* Now that the sources are clearly marked, we can release
	 * the destination stripes
	 */
	while (!list_empty(&stripes)) {
		sh = list_entry(stripes.next, struct stripe_head, lru);
		list_del_init(&sh->lru);
		release_stripe(sh);
	}
	/* If this takes us to the resync_max point where we have to pause,
	 * then we need to write out the superblock.
	 */
	sector_nr += reshape_sectors;
	if ((sector_nr - mddev->curr_resync_completed) * 2
	    >= mddev->resync_max - mddev->curr_resync_completed) {
		/* Cannot proceed until we've updated the superblock... */
		wait_event(conf->wait_for_overlap,
			   atomic_read(&conf->reshape_stripes) == 0);
		mddev->reshape_position = conf->reshape_progress;
		mddev->curr_resync_completed = mddev->curr_resync + reshape_sectors;
		conf->reshape_checkpoint = jiffies;
		set_bit(MD_CHANGE_DEVS, &mddev->flags);
		md_wakeup_thread(mddev->thread);
		wait_event(mddev->sb_wait,
			   !test_bit(MD_CHANGE_DEVS, &mddev->flags)
			   || kthread_should_stop());
		spin_lock_irq(&conf->device_lock);
		conf->reshape_safe = mddev->reshape_position;
		spin_unlock_irq(&conf->device_lock);
		wake_up(&conf->wait_for_overlap);
		sysfs_notify(&mddev->kobj, NULL, "sync_completed");
	}
	return reshape_sectors;
}

/* FIXME go_faster isn't used */
static inline sector_t sync_request(mddev_t *mddev, sector_t sector_nr, int *skipped, int go_faster)
{
	raid5_conf_t *conf = mddev->private;
	struct stripe_head *sh;
	sector_t max_sector = mddev->dev_sectors;
	int sync_blocks;
	int still_degraded = 0;
	int i;

	if (sector_nr >= max_sector) {
		/* just being told to finish up .. nothing much to do */
		unplug_slaves(mddev);

		if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery)) {
			end_reshape(conf);
			return 0;
		}

		if (mddev->curr_resync < max_sector) /* aborted */
			bitmap_end_sync(mddev->bitmap, mddev->curr_resync,&sync_blocks, 1);
		else /* completed sync */
			conf->fullsync = 0;
		bitmap_close_sync(mddev->bitmap);

		return 0;
	}

	/* Allow raid5_quiesce to complete */
	wait_event(conf->wait_for_overlap, conf->quiesce != 2);

	if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery))
		return reshape_request(mddev, sector_nr, skipped);

	/* No need to check resync_max as we never do more than one
	 * stripe, and as resync_max will always be on a chunk boundary,
	 * if the check in md_do_sync didn't fire, there is no chance
	 * of overstepping resync_max here
	 */

	/* if there is too many failed drives and we are trying
	 * to resync, then assert that we are finished, because there is
	 * nothing we can do.
	 */
	if (mddev->degraded >= conf->max_degraded &&
	    test_bit(MD_RECOVERY_SYNC, &mddev->recovery)) {
		sector_t rv = mddev->dev_sectors - sector_nr;
		*skipped = 1;
		return rv;
	}
	if (!bitmap_start_sync(mddev->bitmap, sector_nr, &sync_blocks, 1) &&
	    !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery) &&
	    !conf->fullsync && sync_blocks >= STRIPE_SECTORS) {
		/* we can skip this block, and probably more */
		sync_blocks /= STRIPE_SECTORS;
		*skipped = 1;
		return sync_blocks * STRIPE_SECTORS; /* keep things rounded to whole stripes */
	}


	bitmap_cond_end_sync(mddev->bitmap, sector_nr);

	sh = get_active_stripe(conf, sector_nr, 0, 1, 0);
	if (sh == NULL) {
		sh = get_active_stripe(conf, sector_nr, 0, 0, 0);
		/* make sure we don't swamp the stripe cache if someone else
		 * is trying to get access
		 */
		schedule_timeout_uninterruptible(1);
	}
	/* Need to check if array will still be degraded after recovery/resync
	 * We don't need to check the 'failed' flag as when that gets set,
	 * recovery aborts.
	 */
	for (i = 0; i < conf->raid_disks; i++)
		if (conf->disks[i].rdev == NULL)
			still_degraded = 1;

	bitmap_start_sync(mddev->bitmap, sector_nr, &sync_blocks, still_degraded);

	spin_lock(&sh->lock);
	set_bit(STRIPE_SYNCING, &sh->state);
	clear_bit(STRIPE_INSYNC, &sh->state);
	spin_unlock(&sh->lock);

	handle_stripe(sh);
	release_stripe(sh);

	return STRIPE_SECTORS;
}
/**ltl
功能:重试对齐读请求
参数:
返回值:
说明:
*/
static int  retry_aligned_read(raid5_conf_t *conf, struct bio *raid_bio)
{
	/* We may not be able to submit a whole bio at once as there
	 * may not be enough stripe_heads available.
	 * We cannot pre-allocate enough stripe_heads as we may need
	 * more than exist in the cache (if we allow ever large chunks).
	 * So we do one stripe head at a time and record in
	 * ->bi_hw_segments how many have been done.
	 *
	 * We *know* that this entire raid_bio is in one chunk, so
	 * it will be only one 'dd_idx' and only need one call to raid5_compute_sector.
	 */
	struct stripe_head *sh;
	int dd_idx;
	sector_t sector, logical_sector, last_sector;
	int scnt = 0;
	int remaining;
	int handled = 0;

	logical_sector = raid_bio->bi_sector & ~((sector_t)STRIPE_SECTORS-1);
	sector = raid5_compute_sector(conf, logical_sector, 0, &dd_idx, NULL);
	last_sector = raid_bio->bi_sector + (raid_bio->bi_size>>9);

	for (; logical_sector < last_sector;
	     logical_sector += STRIPE_SECTORS,sector += STRIPE_SECTORS,scnt++) 
	{

		if (scnt < raid5_bi_hw_segments(raid_bio))
			/* already done this stripe */
			continue;

		sh = get_active_stripe(conf, sector, 0, 1, 0);

		if (!sh) {
			/* failed to get a stripe - must wait */
			raid5_set_bi_hw_segments(raid_bio, scnt);
			conf->retry_read_aligned = raid_bio;
			return handled;
		}
		//设置读失败标志
		set_bit(R5_ReadError, &sh->dev[dd_idx].flags);
		if (!add_stripe_bio(sh, raid_bio, dd_idx, 0)) {
			release_stripe(sh);
			raid5_set_bi_hw_segments(raid_bio, scnt);
			conf->retry_read_aligned = raid_bio;
			return handled;
		}
		//处理此请求。
		handle_stripe(sh);
		release_stripe(sh);
		handled++;
	}
	spin_lock_irq(&conf->device_lock);
	remaining = raid5_dec_bi_phys_segments(raid_bio);
	spin_unlock_irq(&conf->device_lock);
	if (remaining == 0)
		bio_endio(raid_bio, 0);
	if (atomic_dec_and_test(&conf->active_aligned_reads))
		wake_up(&conf->wait_for_stripe);
	return handled;
}


/*
 * This is our raid5 kernel thread.
 *
 * We scan the hash table for stripes which can be handled now.
 * During the scan, completed stripes are saved for us by the interrupt
 * handler, so that they will not have to wait for our next wakeup.
 */
static void raid5d(mddev_t *mddev)
{
	struct stripe_head *sh;
	raid5_conf_t *conf = mddev->private;
	int handled;

	pr_debug("+++ raid5d active\n");
	//检查是否有同步工作要做，同时更新RAID超级块。
	md_check_recovery(mddev);

	handled = 0;
	spin_lock_irq(&conf->device_lock);
	while (1) 
	{
		struct bio *bio;
		//MD设备位图处理。
		if (conf->seq_flush != conf->seq_write) 
		{
			int seq = conf->seq_flush;
			spin_unlock_irq(&conf->device_lock);
			//如果MD设备支持位图，则涉及写操作的条带将被首先链入MD设备bitmap_list链表。
			bitmap_unplug(mddev->bitmap);
			spin_lock_irq(&conf->device_lock);
			//上一次成功写入的批次编号
			conf->seq_write = seq;
			//处理bitmap_list列表中的条带  
			activate_bit_delay(conf);
		}
		//处理对齐读请求处理失败的bio(make_request->chunk_aligned_read()中处理)，先从列表retry_read_aligned_list读取bio，然后重新读取数据。
		while ((bio = remove_bio_from_retry(conf))) 
		{
			int ok;
			spin_unlock_irq(&conf->device_lock);
			//处理对齐读请求失败的bio.
			ok = retry_aligned_read(conf, bio);
			spin_lock_irq(&conf->device_lock);
			if (!ok)
				break;
			handled++;
		}
		//获取下一个应该处理的条带，首先取自handle_list列表，如果handle_list为NULL，则从hold_list列表中获取。
		sh = __get_priority_stripe(conf);
		if (!sh)
			break;
		
		spin_unlock_irq(&conf->device_lock);
		
		handled++;
		//处理条带对象
		handle_stripe(sh);
		//将处理于"游离"状态的条带放入链表中。
		release_stripe(sh);
		cond_resched();

		spin_lock_irq(&conf->device_lock);
	}
	pr_debug("%d stripes handled\n", handled);

	spin_unlock_irq(&conf->device_lock);

	async_tx_issue_pending_all();
	//使每个成员磁盘馬上处理已经分发给它的请求。
	unplug_slaves(mddev);

	pr_debug("--- raid5d inactive\n");
}

static ssize_t
raid5_show_stripe_cache_size(mddev_t *mddev, char *page)
{
	raid5_conf_t *conf = mddev->private;
	if (conf)
		return sprintf(page, "%d\n", conf->max_nr_stripes);
	else
		return 0;
}

int
raid5_set_cache_size(mddev_t *mddev, int size)
{
	raid5_conf_t *conf = mddev->private;
	int err;

	if (size <= 16 || size > 32768)
		return -EINVAL;
	while (size < conf->max_nr_stripes) {
		if (drop_one_stripe(conf))
			conf->max_nr_stripes--;
		else
			break;
	}
	err = md_allow_write(mddev);
	if (err)
		return err;
	while (size > conf->max_nr_stripes) {
		if (grow_one_stripe(conf))
			conf->max_nr_stripes++;
		else break;
	}
	return 0;
}
EXPORT_SYMBOL(raid5_set_cache_size);

static ssize_t
raid5_store_stripe_cache_size(mddev_t *mddev, const char *page, size_t len)
{
	raid5_conf_t *conf = mddev->private;
	unsigned long new;
	int err;

	if (len >= PAGE_SIZE)
		return -EINVAL;
	if (!conf)
		return -ENODEV;

	if (strict_strtoul(page, 10, &new))
		return -EINVAL;
	err = raid5_set_cache_size(mddev, new);
	if (err)
		return err;
	return len;
}

static struct md_sysfs_entry
raid5_stripecache_size = __ATTR(stripe_cache_size, S_IRUGO | S_IWUSR,
				raid5_show_stripe_cache_size,
				raid5_store_stripe_cache_size);

static ssize_t
raid5_show_preread_threshold(mddev_t *mddev, char *page)
{
	raid5_conf_t *conf = mddev->private;
	if (conf)
		return sprintf(page, "%d\n", conf->bypass_threshold);
	else
		return 0;
}

static ssize_t
raid5_store_preread_threshold(mddev_t *mddev, const char *page, size_t len)
{
	raid5_conf_t *conf = mddev->private;
	unsigned long new;
	if (len >= PAGE_SIZE)
		return -EINVAL;
	if (!conf)
		return -ENODEV;

	if (strict_strtoul(page, 10, &new))
		return -EINVAL;
	if (new > conf->max_nr_stripes)
		return -EINVAL;
	conf->bypass_threshold = new;
	return len;
}

static struct md_sysfs_entry
raid5_preread_bypass_threshold = __ATTR(preread_bypass_threshold,
					S_IRUGO | S_IWUSR,
					raid5_show_preread_threshold,
					raid5_store_preread_threshold);

static ssize_t
stripe_cache_active_show(mddev_t *mddev, char *page)
{
	raid5_conf_t *conf = mddev->private;
	if (conf)
		return sprintf(page, "%d\n", atomic_read(&conf->active_stripes));
	else
		return 0;
}

static struct md_sysfs_entry
raid5_stripecache_active = __ATTR_RO(stripe_cache_active);

static struct attribute *raid5_attrs[] =  {
	&raid5_stripecache_size.attr,
	&raid5_stripecache_active.attr,
	&raid5_preread_bypass_threshold.attr,
	NULL,
};
static struct attribute_group raid5_attrs_group = {
	.name = NULL,
	.attrs = raid5_attrs,
};

static sector_t
raid5_size(mddev_t *mddev, sector_t sectors, int raid_disks)
{
	raid5_conf_t *conf = mddev->private;

	if (!sectors)
		sectors = mddev->dev_sectors;
	if (!raid_disks)
		/* size is defined by the smallest of previous and new size */
		raid_disks = min(conf->raid_disks, conf->previous_raid_disks);

	sectors &= ~((sector_t)mddev->chunk_sectors - 1);
	sectors &= ~((sector_t)mddev->new_chunk_sectors - 1);
	return sectors * (raid_disks - conf->max_degraded);
}

static void raid5_free_percpu(raid5_conf_t *conf)
{
	struct raid5_percpu *percpu;
	unsigned long cpu;

	if (!conf->percpu)
		return;

	get_online_cpus();
	for_each_possible_cpu(cpu) {
		percpu = per_cpu_ptr(conf->percpu, cpu);
		safe_put_page(percpu->spare_page);
		kfree(percpu->scribble);
	}
#ifdef CONFIG_HOTPLUG_CPU
	unregister_cpu_notifier(&conf->cpu_notify);
#endif
	put_online_cpus();

	free_percpu(conf->percpu);
}

static void free_conf(raid5_conf_t *conf)
{
	shrink_stripes(conf);
	raid5_free_percpu(conf);
	kfree(conf->disks);
	kfree(conf->stripe_hashtbl);
	kfree(conf);
}

#ifdef CONFIG_HOTPLUG_CPU
static int raid456_cpu_notify(struct notifier_block *nfb, unsigned long action,
			      void *hcpu)
{
	raid5_conf_t *conf = container_of(nfb, raid5_conf_t, cpu_notify);
	long cpu = (long)hcpu;
	struct raid5_percpu *percpu = per_cpu_ptr(conf->percpu, cpu);

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		if (conf->level == 6 && !percpu->spare_page)
			percpu->spare_page = alloc_page(GFP_KERNEL);
		if (!percpu->scribble)
			percpu->scribble = kmalloc(conf->scribble_len, GFP_KERNEL);

		if (!percpu->scribble ||
		    (conf->level == 6 && !percpu->spare_page)) {
			safe_put_page(percpu->spare_page);
			kfree(percpu->scribble);
			pr_err("%s: failed memory allocation for cpu%ld\n",
			       __func__, cpu);
			return notifier_from_errno(-ENOMEM);
		}
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		safe_put_page(percpu->spare_page);
		kfree(percpu->scribble);
		percpu->spare_page = NULL;
		percpu->scribble = NULL;
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}
#endif

static int raid5_alloc_percpu(raid5_conf_t *conf)
{
	unsigned long cpu;
	struct page *spare_page;
	struct raid5_percpu __percpu *allcpus;
	void *scribble;
	int err;

	allcpus = alloc_percpu(struct raid5_percpu);
	if (!allcpus)
		return -ENOMEM;
	conf->percpu = allcpus;

	get_online_cpus();
	err = 0;
	for_each_present_cpu(cpu) {
		if (conf->level == 6) {
			spare_page = alloc_page(GFP_KERNEL);
			if (!spare_page) {
				err = -ENOMEM;
				break;
			}
			per_cpu_ptr(conf->percpu, cpu)->spare_page = spare_page;
		}
		scribble = kmalloc(conf->scribble_len, GFP_KERNEL);
		if (!scribble) {
			err = -ENOMEM;
			break;
		}
		per_cpu_ptr(conf->percpu, cpu)->scribble = scribble;
	}
#ifdef CONFIG_HOTPLUG_CPU
	conf->cpu_notify.notifier_call = raid456_cpu_notify;
	conf->cpu_notify.priority = 0;
	if (err == 0)
		err = register_cpu_notifier(&conf->cpu_notify);
#endif
	put_online_cpus();

	return err;
}

static raid5_conf_t *setup_conf(mddev_t *mddev)
{
	raid5_conf_t *conf;
	int raid_disk, memory, max_disks;
	mdk_rdev_t *rdev;
	struct disk_info *disk;

	if (mddev->new_level != 5
	    && mddev->new_level != 4
	    && mddev->new_level != 6) {
		printk(KERN_ERR "md/raid:%s: raid level not set to 4/5/6 (%d)\n",mdname(mddev), mddev->new_level);
		return ERR_PTR(-EIO);
	}
	if ((mddev->new_level == 5 && !algorithm_valid_raid5(mddev->new_layout)) ||
	    (mddev->new_level == 6 && !algorithm_valid_raid6(mddev->new_layout))) {
		printk(KERN_ERR "md/raid:%s: layout %d not supported\n",mdname(mddev), mddev->new_layout);
		return ERR_PTR(-EIO);
	}
	//如果是RAID6,而成员磁盘个数少于4，则退出。即RAID6至少4个成员磁盘。
	if (mddev->new_level == 6 && mddev->raid_disks < 4) {
		printk(KERN_ERR "md/raid:%s: not enough configured devices (%d, minimum 4)\n",mdname(mddev), mddev->raid_disks);
		return ERR_PTR(-EINVAL);
	}

	if (!mddev->new_chunk_sectors ||
	    (mddev->new_chunk_sectors << 9) % PAGE_SIZE ||
	    !is_power_of_2(mddev->new_chunk_sectors)) 
	{
		printk(KERN_ERR "md/raid:%s: invalid chunk size %d\n",mdname(mddev), mddev->new_chunk_sectors << 9);
		return ERR_PTR(-EINVAL);
	}

	conf = kzalloc(sizeof(raid5_conf_t), GFP_KERNEL);
	if (conf == NULL)
		goto abort;
	spin_lock_init(&conf->device_lock);
	init_waitqueue_head(&conf->wait_for_stripe);
	init_waitqueue_head(&conf->wait_for_overlap);
	INIT_LIST_HEAD(&conf->handle_list);
	INIT_LIST_HEAD(&conf->hold_list);
	INIT_LIST_HEAD(&conf->delayed_list);
	INIT_LIST_HEAD(&conf->bitmap_list);
	INIT_LIST_HEAD(&conf->inactive_list);
	atomic_set(&conf->active_stripes, 0);
	atomic_set(&conf->preread_active_stripes, 0);
	atomic_set(&conf->active_aligned_reads, 0);
	conf->bypass_threshold = BYPASS_THRESHOLD;
	//成员磁盘个数
	conf->raid_disks = mddev->raid_disks;
	if (mddev->reshape_position == MaxSector)
		conf->previous_raid_disks = mddev->raid_disks;//Reshape前的成员磁盘数。
	else
		conf->previous_raid_disks = mddev->raid_disks - mddev->delta_disks;//Reshape中有成员磁盘数
		
	max_disks = max(conf->raid_disks, conf->previous_raid_disks);
	//Q:why?
	conf->scribble_len = scribble_len(max_disks);
	//成员磁盘链表
	conf->disks = kzalloc(max_disks * sizeof(struct disk_info),GFP_KERNEL);
	if (!conf->disks)
		goto abort;

	conf->mddev = mddev;

	if ((conf->stripe_hashtbl = kzalloc(PAGE_SIZE, GFP_KERNEL)) == NULL)
		goto abort;

	conf->level = mddev->new_level;
	if (raid5_alloc_percpu(conf) != 0)
		goto abort;

	pr_debug("raid456: run(%s) called.\n", mdname(mddev));
	//给成员磁盘赋值
	list_for_each_entry(rdev, &mddev->disks, same_set) 
	{
		raid_disk = rdev->raid_disk;
		if (raid_disk >= max_disks || raid_disk < 0)
			continue;
		disk = conf->disks + raid_disk;

		disk->rdev = rdev;

		if (test_bit(In_sync, &rdev->flags))
		{
			char b[BDEVNAME_SIZE];
			printk(KERN_INFO "md/raid:%s: device %s operational as raid disk %d\n",
			       mdname(mddev), bdevname(rdev->bdev, b), raid_disk);
		} else
			/* Cannot rely on bitmap to complete recovery */
			conf->fullsync = 1;
	}
	//一个条带的扇区数
	conf->chunk_sectors = mddev->new_chunk_sectors;
	//RAID级别
	conf->level = mddev->new_level;
	//最多允许的故障成员磁盘数目
	if (conf->level == 6)
		conf->max_degraded = 2;//RAID6允许2个成员磁盘出错
	else
		conf->max_degraded = 1;//RAID5允许1个成员磁盘出错
	//向左不对称、向右不对称、向左对称、向右对称算法
	conf->algorithm = mddev->new_layout;
	conf->max_nr_stripes = NR_STRIPES;//最大的条带数目
	conf->reshape_progress = mddev->reshape_position;
	if (conf->reshape_progress != MaxSector)
	{
		conf->prev_chunk_sectors = mddev->chunk_sectors;
		conf->prev_algo = mddev->layout;
	}

	memory = conf->max_nr_stripes * (sizeof(struct stripe_head) +
		 max_disks * ((sizeof(struct bio) + PAGE_SIZE))) / 1024;

	//分配max_nr_stripes(256)个stripe_head对象,并把条带头对象插入到inactive_list中。
	if (grow_stripes(conf, conf->max_nr_stripes)) 
	{
		printk(KERN_ERR"md/raid:%s: couldn't allocate %dkB for buffers\n", mdname(mddev), memory);
		goto abort;
	} else
		printk(KERN_INFO "md/raid:%s: allocated %dkB\n",mdname(mddev), memory);
	//创建raid5守护线程
	conf->thread = md_register_thread(raid5d, mddev, NULL);
	if (!conf->thread) {
		printk(KERN_ERR"md/raid:%s: couldn't allocate thread.\n",mdname(mddev));
		goto abort;
	}

	return conf;

 abort:
	if (conf) {
		free_conf(conf);
		return ERR_PTR(-EIO);
	} else
		return ERR_PTR(-ENOMEM);
}


static int only_parity(int raid_disk, int algo, int raid_disks, int max_degraded)
{
	switch (algo) {
	case ALGORITHM_PARITY_0:
		if (raid_disk < max_degraded)
			return 1;
		break;
	case ALGORITHM_PARITY_N:
		if (raid_disk >= raid_disks - max_degraded)
			return 1;
		break;
	case ALGORITHM_PARITY_0_6:
		if (raid_disk == 0 || 
		    raid_disk == raid_disks - 1)
			return 1;
		break;
	case ALGORITHM_LEFT_ASYMMETRIC_6:
	case ALGORITHM_RIGHT_ASYMMETRIC_6:
	case ALGORITHM_LEFT_SYMMETRIC_6:
	case ALGORITHM_RIGHT_SYMMETRIC_6:
		if (raid_disk == raid_disks - 1)
			return 1;
	}
	return 0;
}

static int run(mddev_t *mddev)
{
	raid5_conf_t *conf;
	int working_disks = 0;
	int dirty_parity_disks = 0;
	mdk_rdev_t *rdev;
	sector_t reshape_offset = 0;

	if (mddev->recovery_cp != MaxSector)
		printk(KERN_NOTICE "md/raid:%s: not clean -- starting background reconstruction\n",mdname(mddev));
	//上次reshapge还没有完成
	if (mddev->reshape_position != MaxSector) 
	{
		/* Check that we can continue the reshape.
		 * Currently only disks can change, it must
		 * increase, and we must be past the point where
		 * a stripe over-writes itself
		 */
		sector_t here_new, here_old;
		int old_disks;
		int max_degraded = (mddev->level == 6 ? 2 : 1);

		if (mddev->new_level != mddev->level)
		{
			printk(KERN_ERR "md/raid:%s: unsupported reshape required - aborting.\n",mdname(mddev));
			return -EINVAL;
		}
		 //没有reshape磁盘个数
		old_disks = mddev->raid_disks - mddev->delta_disks;
		/* reshape_position must be on a new-stripe boundary, and one
		 * further up in new geometry must map after here in old
		 * geometry.
		 */
		here_new = mddev->reshape_position;
		if (sector_div(here_new, mddev->new_chunk_sectors * (mddev->raid_disks - max_degraded)))
		{
			printk(KERN_ERR "md/raid:%s: reshape_position not on a stripe boundary\n", mdname(mddev));
			return -EINVAL;
		}
		reshape_offset = here_new * mddev->new_chunk_sectors;
		/* here_new is the stripe we will write to */
		here_old = mddev->reshape_position;
		sector_div(here_old, mddev->chunk_sectors * (old_disks-max_degraded));
		/* here_old is the first stripe that we might need to read from */
		if (mddev->delta_disks == 0) 
		{
			/* We cannot be sure it is safe to start an in-place
			 * reshape.  It is only safe if user-space if monitoring
			 * and taking constant backups.
			 * mdadm always starts a situation like this in
			 * readonly mode so it can take control before
			 * allowing any writes.  So just check for that.
			 */
			if ((here_new * mddev->new_chunk_sectors != here_old * mddev->chunk_sectors) || mddev->ro == 0) 
			{
				printk(KERN_ERR "md/raid:%s: in-place reshape must be started in read-only mode - aborting\n",mdname(mddev));
				return -EINVAL;
			}
		} else if (mddev->delta_disks < 0
		    ? (here_new * mddev->new_chunk_sectors <=
		       here_old * mddev->chunk_sectors)
		    : (here_new * mddev->new_chunk_sectors >=
		       here_old * mddev->chunk_sectors)) 
		{
			/* Reading from the same stripe as writing to - bad */
			printk(KERN_ERR "md/raid:%s: reshape_position too early for auto-recovery - aborting.\n",mdname(mddev));
			return -EINVAL;
		}
		printk(KERN_INFO "md/raid:%s: reshape will continue\n",mdname(mddev));
		/* OK, we should be able to continue; */
	}
	else 
	{
		BUG_ON(mddev->level != mddev->new_level);
		BUG_ON(mddev->layout != mddev->new_layout);
		BUG_ON(mddev->chunk_sectors != mddev->new_chunk_sectors);
		BUG_ON(mddev->delta_disks != 0);
	}
	//构建RAID5私有数据
	if (mddev->private == NULL)
		conf = setup_conf(mddev);
	else
		conf = mddev->private;

	if (IS_ERR(conf))
		return PTR_ERR(conf);
	//MD设备的线程。循环处理strip_head
	mddev->thread = conf->thread;
	//Q:为什么要把这个置NULL
	conf->thread = NULL;
	//设置私有数据
	mddev->private = conf;

	/*
	 * 0 for a fully functional array, 1 or 2 for a degraded array.
	 */
	list_for_each_entry(rdev, &mddev->disks, same_set)
	{
		if (rdev->raid_disk < 0)
			continue;
		if (test_bit(In_sync, &rdev->flags))
		{
			working_disks++;
			continue;
		}
		/* This disc is not fully in-sync.  However if it
		 * just stored parity (beyond the recovery_offset),
		 * when we don't need to be concerned about the
		 * array being dirty.
		 * When reshape goes 'backwards', we never have
		 * partially completed devices, so we only need
		 * to worry about reshape going forwards.
		 */
		/* Hack because v0.91 doesn't store recovery_offset properly. */
		if (mddev->major_version == 0 &&
		    mddev->minor_version > 90)
			rdev->recovery_offset = reshape_offset;
			
		if (rdev->recovery_offset < reshape_offset)
		{
			/* We need to check old and new layout */
			if (!only_parity(rdev->raid_disk,
					 conf->algorithm,
					 conf->raid_disks,
					 conf->max_degraded))
				continue;
		}
		if (!only_parity(rdev->raid_disk,
				 conf->prev_algo,
				 conf->previous_raid_disks,
				 conf->max_degraded))
			continue;
		dirty_parity_disks++;
	}

	mddev->degraded = (max(conf->raid_disks, conf->previous_raid_disks) - working_disks);

	if (has_failed(conf))
	{
		printk(KERN_ERR "md/raid:%s: not enough operational devices(%d/%d failed)\n",
			mdname(mddev), mddev->degraded, conf->raid_disks);
		goto abort;
	}

	/* device size must be a multiple of chunk size */
	mddev->dev_sectors &= ~(mddev->chunk_sectors - 1);
	mddev->resync_max_sectors = mddev->dev_sectors;

	if (mddev->degraded > dirty_parity_disks &&
	    mddev->recovery_cp != MaxSector) 
	{
		if (mddev->ok_start_degraded)
			printk(KERN_WARNING"md/raid:%s: starting dirty degraded array - data corruption possible.\n",mdname(mddev));
		else 
		{
			printk(KERN_ERR"md/raid:%s: cannot start dirty degraded array.\n",mdname(mddev));
			goto abort;
		}
	}

	if (mddev->degraded == 0)
		printk(KERN_INFO "md/raid:%s: raid level %d active with %d out of %d"
		       " devices, algorithm %d\n", mdname(mddev), conf->level,
		       mddev->raid_disks-mddev->degraded, mddev->raid_disks,
		       mddev->new_layout);
	else
		printk(KERN_ALERT "md/raid:%s: raid level %d active with %d"
		       " out of %d devices, algorithm %d\n",
		       mdname(mddev), conf->level,
		       mddev->raid_disks - mddev->degraded,
		       mddev->raid_disks, mddev->new_layout);

	print_raid5_conf(conf);

	if (conf->reshape_progress != MaxSector) 
	{
		conf->reshape_safe = conf->reshape_progress;
		atomic_set(&conf->reshape_stripes, 0);
		clear_bit(MD_RECOVERY_SYNC, &mddev->recovery);
		clear_bit(MD_RECOVERY_CHECK, &mddev->recovery);
		set_bit(MD_RECOVERY_RESHAPE, &mddev->recovery);
		set_bit(MD_RECOVERY_RUNNING, &mddev->recovery);
		mddev->sync_thread = md_register_thread(md_do_sync, mddev,"reshape");
	}


	/* Ok, everything is just fine now */
	if (mddev->to_remove == &raid5_attrs_group)
		mddev->to_remove = NULL;
	else if (mddev->kobj.sd &&
	    sysfs_create_group(&mddev->kobj, &raid5_attrs_group))
		printk(KERN_WARNING"raid5: failed to create sysfs attributes for %s\n",mdname(mddev));
	md_set_array_sectors(mddev, raid5_size(mddev, 0, 0));

	plugger_init(&conf->plug, raid5_unplug);
	mddev->plug = &conf->plug;
	if (mddev->queue) 
	{
		int chunk_size;
		/* read-ahead size must cover two whole stripes, which
		 * is 2 * (datadisks) * chunksize where 'n' is the
		 * number of raid devices
		 */
		int data_disks = conf->previous_raid_disks - conf->max_degraded;
		int stripe = data_disks * ((mddev->chunk_sectors << 9) / PAGE_SIZE);
		if (mddev->queue->backing_dev_info.ra_pages < 2 * stripe)
			mddev->queue->backing_dev_info.ra_pages = 2 * stripe;

		blk_queue_merge_bvec(mddev->queue, raid5_mergeable_bvec);

		mddev->queue->backing_dev_info.congested_data = mddev;
		mddev->queue->backing_dev_info.congested_fn = raid5_congested;
		mddev->queue->queue_lock = &conf->device_lock;
		mddev->queue->unplug_fn = raid5_unplug_queue;

		chunk_size = mddev->chunk_sectors << 9;
		blk_queue_io_min(mddev->queue, chunk_size);
		blk_queue_io_opt(mddev->queue, chunk_size * (conf->raid_disks - conf->max_degraded));

		list_for_each_entry(rdev, &mddev->disks, same_set)
			disk_stack_limits(mddev->gendisk, rdev->bdev,rdev->data_offset << 9);
	}

	return 0;
abort:
	md_unregister_thread(mddev->thread);
	mddev->thread = NULL;
	if (conf) {
		print_raid5_conf(conf);
		free_conf(conf);
	}
	mddev->private = NULL;
	printk(KERN_ALERT "md/raid:%s: failed to run raid set.\n", mdname(mddev));
	return -EIO;
}

static int stop(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;

	md_unregister_thread(mddev->thread);
	mddev->thread = NULL;
	if (mddev->queue)
		mddev->queue->backing_dev_info.congested_fn = NULL;
	plugger_flush(&conf->plug); /* the unplug fn references 'conf'*/
	free_conf(conf);
	mddev->private = NULL;
	mddev->to_remove = &raid5_attrs_group;
	return 0;
}

#ifdef DEBUG
static void print_sh(struct seq_file *seq, struct stripe_head *sh)
{
	int i;

	seq_printf(seq, "sh %llu, pd_idx %d, state %ld.\n",
		   (unsigned long long)sh->sector, sh->pd_idx, sh->state);
	seq_printf(seq, "sh %llu,  count %d.\n",
		   (unsigned long long)sh->sector, atomic_read(&sh->count));
	seq_printf(seq, "sh %llu, ", (unsigned long long)sh->sector);
	for (i = 0; i < sh->disks; i++) {
		seq_printf(seq, "(cache%d: %p %ld) ",
			   i, sh->dev[i].page, sh->dev[i].flags);
	}
	seq_printf(seq, "\n");
}

static void printall(struct seq_file *seq, raid5_conf_t *conf)
{
	struct stripe_head *sh;
	struct hlist_node *hn;
	int i;

	spin_lock_irq(&conf->device_lock);
	for (i = 0; i < NR_HASH; i++) {
		hlist_for_each_entry(sh, hn, &conf->stripe_hashtbl[i], hash) {
			if (sh->raid_conf != conf)
				continue;
			print_sh(seq, sh);
		}
	}
	spin_unlock_irq(&conf->device_lock);
}
#endif

static void status(struct seq_file *seq, mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;
	int i;

	seq_printf(seq, " level %d, %dk chunk, algorithm %d", mddev->level,
		mddev->chunk_sectors / 2, mddev->layout);
	seq_printf (seq, " [%d/%d] [", conf->raid_disks, conf->raid_disks - mddev->degraded);
	for (i = 0; i < conf->raid_disks; i++)
		seq_printf (seq, "%s",
			       conf->disks[i].rdev &&
			       test_bit(In_sync, &conf->disks[i].rdev->flags) ? "U" : "_");
	seq_printf (seq, "]");
#ifdef DEBUG
	seq_printf (seq, "\n");
	printall(seq, conf);
#endif
}

static void print_raid5_conf (raid5_conf_t *conf)
{
	int i;
	struct disk_info *tmp;

	printk(KERN_DEBUG "RAID conf printout:\n");
	if (!conf) {
		printk("(conf==NULL)\n");
		return;
	}
	printk(KERN_DEBUG " --- level:%d rd:%d wd:%d\n", conf->level,
	       conf->raid_disks,
	       conf->raid_disks - conf->mddev->degraded);

	for (i = 0; i < conf->raid_disks; i++) {
		char b[BDEVNAME_SIZE];
		tmp = conf->disks + i;
		if (tmp->rdev)
			printk(KERN_DEBUG " disk %d, o:%d, dev:%s\n",
			       i, !test_bit(Faulty, &tmp->rdev->flags),
			       bdevname(tmp->rdev->bdev, b));
	}
}

static int raid5_spare_active(mddev_t *mddev)
{
	int i;
	raid5_conf_t *conf = mddev->private;
	struct disk_info *tmp;
	int count = 0;
	unsigned long flags;

	for (i = 0; i < conf->raid_disks; i++) {
		tmp = conf->disks + i;
		if (tmp->rdev
		    && tmp->rdev->recovery_offset == MaxSector
		    && !test_bit(Faulty, &tmp->rdev->flags)
		    && !test_and_set_bit(In_sync, &tmp->rdev->flags)) {
			count++;
			sysfs_notify_dirent(tmp->rdev->sysfs_state);
		}
	}
	spin_lock_irqsave(&conf->device_lock, flags);
	mddev->degraded -= count;
	spin_unlock_irqrestore(&conf->device_lock, flags);
	print_raid5_conf(conf);
	return count;
}

static int raid5_remove_disk(mddev_t *mddev, int number)
{
	raid5_conf_t *conf = mddev->private;
	int err = 0;
	mdk_rdev_t *rdev;
	struct disk_info *p = conf->disks + number;

	print_raid5_conf(conf);
	rdev = p->rdev;
	if (rdev) {
		if (number >= conf->raid_disks &&
		    conf->reshape_progress == MaxSector)
			clear_bit(In_sync, &rdev->flags);

		if (test_bit(In_sync, &rdev->flags) ||
		    atomic_read(&rdev->nr_pending)) {
			err = -EBUSY;
			goto abort;
		}
		/* Only remove non-faulty devices if recovery
		 * isn't possible.
		 */
		if (!test_bit(Faulty, &rdev->flags) &&
		    !has_failed(conf) &&
		    number < conf->raid_disks) {
			err = -EBUSY;
			goto abort;
		}
		p->rdev = NULL;
		synchronize_rcu();
		if (atomic_read(&rdev->nr_pending)) {
			/* lost the race, try later */
			err = -EBUSY;
			p->rdev = rdev;
		}
	}
abort:

	print_raid5_conf(conf);
	return err;
}

static int raid5_add_disk(mddev_t *mddev, mdk_rdev_t *rdev)
{
	raid5_conf_t *conf = mddev->private;
	int err = -EEXIST;
	int disk;
	struct disk_info *p;
	int first = 0;
	int last = conf->raid_disks - 1;

	if (has_failed(conf))
		/* no point adding a device */
		return -EINVAL;

	if (rdev->raid_disk >= 0)
		first = last = rdev->raid_disk;

	/*
	 * find the disk ... but prefer rdev->saved_raid_disk
	 * if possible.
	 */
	if (rdev->saved_raid_disk >= 0 &&
	    rdev->saved_raid_disk >= first &&
	    conf->disks[rdev->saved_raid_disk].rdev == NULL)
		disk = rdev->saved_raid_disk;
	else
		disk = first;
	for ( ; disk <= last ; disk++)
		if ((p=conf->disks + disk)->rdev == NULL) {
			clear_bit(In_sync, &rdev->flags);
			rdev->raid_disk = disk;
			err = 0;
			if (rdev->saved_raid_disk != disk)
				conf->fullsync = 1;
			rcu_assign_pointer(p->rdev, rdev);
			break;
		}
	print_raid5_conf(conf);
	return err;
}

static int raid5_resize(mddev_t *mddev, sector_t sectors)
{
	/* no resync is happening, and there is enough space
	 * on all devices, so we can resize.
	 * We need to make sure resync covers any new space.
	 * If the array is shrinking we should possibly wait until
	 * any io in the removed space completes, but it hardly seems
	 * worth it.
	 */
	sectors &= ~((sector_t)mddev->chunk_sectors - 1);
	md_set_array_sectors(mddev, raid5_size(mddev, sectors,
					       mddev->raid_disks));
	if (mddev->array_sectors >
	    raid5_size(mddev, sectors, mddev->raid_disks))
		return -EINVAL;
	set_capacity(mddev->gendisk, mddev->array_sectors);
	revalidate_disk(mddev->gendisk);
	if (sectors > mddev->dev_sectors && mddev->recovery_cp == MaxSector) {
		mddev->recovery_cp = mddev->dev_sectors;
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	}
	mddev->dev_sectors = sectors;
	mddev->resync_max_sectors = sectors;
	return 0;
}

static int check_stripe_cache(mddev_t *mddev)
{
	/* Can only proceed if there are plenty of stripe_heads.
	 * We need a minimum of one full stripe,, and for sensible progress
	 * it is best to have about 4 times that.
	 * If we require 4 times, then the default 256 4K stripe_heads will
	 * allow for chunk sizes up to 256K, which is probably OK.
	 * If the chunk size is greater, user-space should request more
	 * stripe_heads first.
	 */
	raid5_conf_t *conf = mddev->private;
	if (((mddev->chunk_sectors << 9) / STRIPE_SIZE) * 4
	    > conf->max_nr_stripes ||
	    ((mddev->new_chunk_sectors << 9) / STRIPE_SIZE) * 4
	    > conf->max_nr_stripes) {
		printk(KERN_WARNING "md/raid:%s: reshape: not enough stripes.  Needed %lu\n",
		       mdname(mddev),
		       ((max(mddev->chunk_sectors, mddev->new_chunk_sectors) << 9)
			/ STRIPE_SIZE)*4);
		return 0;
	}
	return 1;
}

static int check_reshape(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;

	if (mddev->delta_disks == 0 &&
	    mddev->new_layout == mddev->layout &&
	    mddev->new_chunk_sectors == mddev->chunk_sectors)
		return 0; /* nothing to do */
	if (mddev->bitmap)
		/* Cannot grow a bitmap yet */
		return -EBUSY;
	if (has_failed(conf))
		return -EINVAL;
	if (mddev->delta_disks < 0) {
		/* We might be able to shrink, but the devices must
		 * be made bigger first.
		 * For raid6, 4 is the minimum size.
		 * Otherwise 2 is the minimum
		 */
		int min = 2;
		if (mddev->level == 6)
			min = 4;
		if (mddev->raid_disks + mddev->delta_disks < min)
			return -EINVAL;
	}

	if (!check_stripe_cache(mddev))
		return -ENOSPC;

	return resize_stripes(conf, conf->raid_disks + mddev->delta_disks);
}

static int raid5_start_reshape(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;
	mdk_rdev_t *rdev;
	int spares = 0;
	int added_devices = 0;
	unsigned long flags;

	if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
		return -EBUSY;

	if (!check_stripe_cache(mddev))
		return -ENOSPC;

	list_for_each_entry(rdev, &mddev->disks, same_set)
		if (rdev->raid_disk < 0 &&
		    !test_bit(Faulty, &rdev->flags))
			spares++;

	if (spares - mddev->degraded < mddev->delta_disks - conf->max_degraded)
		/* Not enough devices even to make a degraded array
		 * of that size
		 */
		return -EINVAL;

	/* Refuse to reduce size of the array.  Any reductions in
	 * array size must be through explicit setting of array_size
	 * attribute.
	 */
	if (raid5_size(mddev, 0, conf->raid_disks + mddev->delta_disks)
	    < mddev->array_sectors) {
		printk(KERN_ERR "md/raid:%s: array size must be reduced "
		       "before number of disks\n", mdname(mddev));
		return -EINVAL;
	}

	atomic_set(&conf->reshape_stripes, 0);
	spin_lock_irq(&conf->device_lock);
	conf->previous_raid_disks = conf->raid_disks;
	conf->raid_disks += mddev->delta_disks;
	conf->prev_chunk_sectors = conf->chunk_sectors;
	conf->chunk_sectors = mddev->new_chunk_sectors;
	conf->prev_algo = conf->algorithm;
	conf->algorithm = mddev->new_layout;
	if (mddev->delta_disks < 0)
		conf->reshape_progress = raid5_size(mddev, 0, 0);
	else
		conf->reshape_progress = 0;
	conf->reshape_safe = conf->reshape_progress;
	conf->generation++;
	spin_unlock_irq(&conf->device_lock);

	/* Add some new drives, as many as will fit.
	 * We know there are enough to make the newly sized array work.
	 * Don't add devices if we are reducing the number of
	 * devices in the array.  This is because it is not possible
	 * to correctly record the "partially reconstructed" state of
	 * such devices during the reshape and confusion could result.
	 */
	if (mddev->delta_disks >= 0)
	    list_for_each_entry(rdev, &mddev->disks, same_set)
		if (rdev->raid_disk < 0 &&
		    !test_bit(Faulty, &rdev->flags)) {
			if (raid5_add_disk(mddev, rdev) == 0) {
				char nm[20];
				if (rdev->raid_disk >= conf->previous_raid_disks) {
					set_bit(In_sync, &rdev->flags);
					added_devices++;
				} else
					rdev->recovery_offset = 0;
				sprintf(nm, "rd%d", rdev->raid_disk);
				if (sysfs_create_link(&mddev->kobj,
						      &rdev->kobj, nm))
					/* Failure here is OK */;
			} else
				break;
		}

	/* When a reshape changes the number of devices, ->degraded
	 * is measured against the larger of the pre and post number of
	 * devices.*/
	if (mddev->delta_disks > 0) {
		spin_lock_irqsave(&conf->device_lock, flags);
		mddev->degraded += (conf->raid_disks - conf->previous_raid_disks)
			- added_devices;
		spin_unlock_irqrestore(&conf->device_lock, flags);
	}
	mddev->raid_disks = conf->raid_disks;
	mddev->reshape_position = conf->reshape_progress;
	set_bit(MD_CHANGE_DEVS, &mddev->flags);

	clear_bit(MD_RECOVERY_SYNC, &mddev->recovery);
	clear_bit(MD_RECOVERY_CHECK, &mddev->recovery);
	set_bit(MD_RECOVERY_RESHAPE, &mddev->recovery);
	set_bit(MD_RECOVERY_RUNNING, &mddev->recovery);
	mddev->sync_thread = md_register_thread(md_do_sync, mddev,
						"reshape");
	if (!mddev->sync_thread) {
		mddev->recovery = 0;
		spin_lock_irq(&conf->device_lock);
		mddev->raid_disks = conf->raid_disks = conf->previous_raid_disks;
		conf->reshape_progress = MaxSector;
		spin_unlock_irq(&conf->device_lock);
		return -EAGAIN;
	}
	conf->reshape_checkpoint = jiffies;
	md_wakeup_thread(mddev->sync_thread);
	md_new_event(mddev);
	return 0;
}

/* This is called from the reshape thread and should make any
 * changes needed in 'conf'
 */
static void end_reshape(raid5_conf_t *conf)
{

	if (!test_bit(MD_RECOVERY_INTR, &conf->mddev->recovery)) {

		spin_lock_irq(&conf->device_lock);
		conf->previous_raid_disks = conf->raid_disks;
		conf->reshape_progress = MaxSector;
		spin_unlock_irq(&conf->device_lock);
		wake_up(&conf->wait_for_overlap);

		/* read-ahead size must cover two whole stripes, which is
		 * 2 * (datadisks) * chunksize where 'n' is the number of raid devices
		 */
		if (conf->mddev->queue) {
			int data_disks = conf->raid_disks - conf->max_degraded;
			int stripe = data_disks * ((conf->chunk_sectors << 9)
						   / PAGE_SIZE);
			if (conf->mddev->queue->backing_dev_info.ra_pages < 2 * stripe)
				conf->mddev->queue->backing_dev_info.ra_pages = 2 * stripe;
		}
	}
}

/* This is called from the raid5d thread with mddev_lock held.
 * It makes config changes to the device.
 */
static void raid5_finish_reshape(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;

	if (!test_bit(MD_RECOVERY_INTR, &mddev->recovery)) {

		if (mddev->delta_disks > 0) {
			md_set_array_sectors(mddev, raid5_size(mddev, 0, 0));
			set_capacity(mddev->gendisk, mddev->array_sectors);
			revalidate_disk(mddev->gendisk);
		} else {
			int d;
			mddev->degraded = conf->raid_disks;
			for (d = 0; d < conf->raid_disks ; d++)
				if (conf->disks[d].rdev &&
				    test_bit(In_sync,
					     &conf->disks[d].rdev->flags))
					mddev->degraded--;
			for (d = conf->raid_disks ;
			     d < conf->raid_disks - mddev->delta_disks;
			     d++) {
				mdk_rdev_t *rdev = conf->disks[d].rdev;
				if (rdev && raid5_remove_disk(mddev, d) == 0) {
					char nm[20];
					sprintf(nm, "rd%d", rdev->raid_disk);
					sysfs_remove_link(&mddev->kobj, nm);
					rdev->raid_disk = -1;
				}
			}
		}
		mddev->layout = conf->algorithm;
		mddev->chunk_sectors = conf->chunk_sectors;
		mddev->reshape_position = MaxSector;
		mddev->delta_disks = 0;
	}
}

static void raid5_quiesce(mddev_t *mddev, int state)
{
	raid5_conf_t *conf = mddev->private;

	switch(state) {
	case 2: /* resume for a suspend */
		wake_up(&conf->wait_for_overlap);
		break;

	case 1: /* stop all writes */
		spin_lock_irq(&conf->device_lock);
		/* '2' tells resync/reshape to pause so that all
		 * active stripes can drain
		 */
		conf->quiesce = 2;
		wait_event_lock_irq(conf->wait_for_stripe,
				    atomic_read(&conf->active_stripes) == 0 &&
				    atomic_read(&conf->active_aligned_reads) == 0,
				    conf->device_lock, /* nothing */);
		conf->quiesce = 1;
		spin_unlock_irq(&conf->device_lock);
		/* allow reshape to continue */
		wake_up(&conf->wait_for_overlap);
		break;

	case 0: /* re-enable writes */
		spin_lock_irq(&conf->device_lock);
		conf->quiesce = 0;
		wake_up(&conf->wait_for_stripe);
		wake_up(&conf->wait_for_overlap);
		spin_unlock_irq(&conf->device_lock);
		break;
	}
}


static void *raid45_takeover_raid0(mddev_t *mddev, int level)
{
	struct raid0_private_data *raid0_priv = mddev->private;

	/* for raid0 takeover only one zone is supported */
	if (raid0_priv->nr_strip_zones > 1) {
		printk(KERN_ERR "md/raid:%s: cannot takeover raid0 with more than one zone.\n",
		       mdname(mddev));
		return ERR_PTR(-EINVAL);
	}

	mddev->new_level = level;
	mddev->new_layout = ALGORITHM_PARITY_N;
	mddev->new_chunk_sectors = mddev->chunk_sectors;
	mddev->raid_disks += 1;
	mddev->delta_disks = 1;
	/* make sure it will be not marked as dirty */
	mddev->recovery_cp = MaxSector;

	return setup_conf(mddev);
}


static void *raid5_takeover_raid1(mddev_t *mddev)
{
	int chunksect;

	if (mddev->raid_disks != 2 ||
	    mddev->degraded > 1)
		return ERR_PTR(-EINVAL);

	/* Should check if there are write-behind devices? */

	chunksect = 64*2; /* 64K by default */

	/* The array must be an exact multiple of chunksize */
	while (chunksect && (mddev->array_sectors & (chunksect-1)))
		chunksect >>= 1;

	if ((chunksect<<9) < STRIPE_SIZE)
		/* array size does not allow a suitable chunk size */
		return ERR_PTR(-EINVAL);

	mddev->new_level = 5;
	mddev->new_layout = ALGORITHM_LEFT_SYMMETRIC;
	mddev->new_chunk_sectors = chunksect;

	return setup_conf(mddev);
}

static void *raid5_takeover_raid6(mddev_t *mddev)
{
	int new_layout;

	switch (mddev->layout) {
	case ALGORITHM_LEFT_ASYMMETRIC_6:
		new_layout = ALGORITHM_LEFT_ASYMMETRIC;
		break;
	case ALGORITHM_RIGHT_ASYMMETRIC_6:
		new_layout = ALGORITHM_RIGHT_ASYMMETRIC;
		break;
	case ALGORITHM_LEFT_SYMMETRIC_6:
		new_layout = ALGORITHM_LEFT_SYMMETRIC;
		break;
	case ALGORITHM_RIGHT_SYMMETRIC_6:
		new_layout = ALGORITHM_RIGHT_SYMMETRIC;
		break;
	case ALGORITHM_PARITY_0_6:
		new_layout = ALGORITHM_PARITY_0;
		break;
	case ALGORITHM_PARITY_N:
		new_layout = ALGORITHM_PARITY_N;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}
	mddev->new_level = 5;
	mddev->new_layout = new_layout;
	mddev->delta_disks = -1;
	mddev->raid_disks -= 1;
	return setup_conf(mddev);
}


static int raid5_check_reshape(mddev_t *mddev)
{
	/* For a 2-drive array, the layout and chunk size can be changed
	 * immediately as not restriping is needed.
	 * For larger arrays we record the new value - after validation
	 * to be used by a reshape pass.
	 */
	raid5_conf_t *conf = mddev->private;
	int new_chunk = mddev->new_chunk_sectors;

	if (mddev->new_layout >= 0 && !algorithm_valid_raid5(mddev->new_layout))
		return -EINVAL;
	if (new_chunk > 0) {
		if (!is_power_of_2(new_chunk))
			return -EINVAL;
		if (new_chunk < (PAGE_SIZE>>9))
			return -EINVAL;
		if (mddev->array_sectors & (new_chunk-1))
			/* not factor of array size */
			return -EINVAL;
	}

	/* They look valid */

	if (mddev->raid_disks == 2) {
		/* can make the change immediately */
		if (mddev->new_layout >= 0) {
			conf->algorithm = mddev->new_layout;
			mddev->layout = mddev->new_layout;
		}
		if (new_chunk > 0) {
			conf->chunk_sectors = new_chunk ;
			mddev->chunk_sectors = new_chunk;
		}
		set_bit(MD_CHANGE_DEVS, &mddev->flags);
		md_wakeup_thread(mddev->thread);
	}
	return check_reshape(mddev);
}

static int raid6_check_reshape(mddev_t *mddev)
{
	int new_chunk = mddev->new_chunk_sectors;

	if (mddev->new_layout >= 0 && !algorithm_valid_raid6(mddev->new_layout))
		return -EINVAL;
	if (new_chunk > 0) {
		if (!is_power_of_2(new_chunk))
			return -EINVAL;
		if (new_chunk < (PAGE_SIZE >> 9))
			return -EINVAL;
		if (mddev->array_sectors & (new_chunk-1))
			/* not factor of array size */
			return -EINVAL;
	}

	/* They look valid */
	return check_reshape(mddev);
}

static void *raid5_takeover(mddev_t *mddev)
{
	/* raid5 can take over:
	 *  raid0 - if there is only one strip zone - make it a raid4 layout
	 *  raid1 - if there are two drives.  We need to know the chunk size
	 *  raid4 - trivial - just use a raid4 layout.
	 *  raid6 - Providing it is a *_6 layout
	 */
	if (mddev->level == 0)
		return raid45_takeover_raid0(mddev, 5);
	if (mddev->level == 1)
		return raid5_takeover_raid1(mddev);
	if (mddev->level == 4) {
		mddev->new_layout = ALGORITHM_PARITY_N;
		mddev->new_level = 5;
		return setup_conf(mddev);
	}
	if (mddev->level == 6)
		return raid5_takeover_raid6(mddev);

	return ERR_PTR(-EINVAL);
}

static void *raid4_takeover(mddev_t *mddev)
{
	/* raid4 can take over:
	 *  raid0 - if there is only one strip zone
	 *  raid5 - if layout is right
	 */
	if (mddev->level == 0)
		return raid45_takeover_raid0(mddev, 4);
	if (mddev->level == 5 &&
	    mddev->layout == ALGORITHM_PARITY_N) {
		mddev->new_layout = 0;
		mddev->new_level = 4;
		return setup_conf(mddev);
	}
	return ERR_PTR(-EINVAL);
}

static struct mdk_personality raid5_personality;

static void *raid6_takeover(mddev_t *mddev)
{
	/* Currently can only take over a raid5.  We map the
	 * personality to an equivalent raid6 personality
	 * with the Q block at the end.
	 */
	int new_layout;

	if (mddev->pers != &raid5_personality)
		return ERR_PTR(-EINVAL);
	if (mddev->degraded > 1)
		return ERR_PTR(-EINVAL);
	if (mddev->raid_disks > 253)
		return ERR_PTR(-EINVAL);
	if (mddev->raid_disks < 3)
		return ERR_PTR(-EINVAL);

	switch (mddev->layout) {
	case ALGORITHM_LEFT_ASYMMETRIC:
		new_layout = ALGORITHM_LEFT_ASYMMETRIC_6;
		break;
	case ALGORITHM_RIGHT_ASYMMETRIC:
		new_layout = ALGORITHM_RIGHT_ASYMMETRIC_6;
		break;
	case ALGORITHM_LEFT_SYMMETRIC:
		new_layout = ALGORITHM_LEFT_SYMMETRIC_6;
		break;
	case ALGORITHM_RIGHT_SYMMETRIC:
		new_layout = ALGORITHM_RIGHT_SYMMETRIC_6;
		break;
	case ALGORITHM_PARITY_0:
		new_layout = ALGORITHM_PARITY_0_6;
		break;
	case ALGORITHM_PARITY_N:
		new_layout = ALGORITHM_PARITY_N;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}
	mddev->new_level = 6;
	mddev->new_layout = new_layout;
	mddev->delta_disks = 1;
	mddev->raid_disks += 1;
	return setup_conf(mddev);
}


static struct mdk_personality raid6_personality =
{
	.name		= "raid6",
	.level		= 6,
	.owner		= THIS_MODULE,
	.make_request	= make_request,
	.run		= run,
	.stop		= stop,
	.status		= status,
	.error_handler	= error,
	.hot_add_disk	= raid5_add_disk,
	.hot_remove_disk= raid5_remove_disk,
	.spare_active	= raid5_spare_active,
	.sync_request	= sync_request,
	.resize		= raid5_resize,
	.size		= raid5_size,
	.check_reshape	= raid6_check_reshape,
	.start_reshape  = raid5_start_reshape,
	.finish_reshape = raid5_finish_reshape,
	.quiesce	= raid5_quiesce,
	.takeover	= raid6_takeover,
};
static struct mdk_personality raid5_personality =
{
	.name		= "raid5",
	.level		= 5,
	.owner		= THIS_MODULE,
	.make_request	= make_request,
	.run		= run,
	.stop		= stop,
	.status		= status,
	.error_handler	= error,
	.hot_add_disk	= raid5_add_disk,
	.hot_remove_disk= raid5_remove_disk,
	.spare_active	= raid5_spare_active,
	.sync_request	= sync_request,
	.resize		= raid5_resize,
	.size		= raid5_size,
	.check_reshape	= raid5_check_reshape,
	.start_reshape  = raid5_start_reshape,
	.finish_reshape = raid5_finish_reshape,
	.quiesce	= raid5_quiesce,
	.takeover	= raid5_takeover,
};

static struct mdk_personality raid4_personality =
{
	.name		= "raid4",
	.level		= 4,
	.owner		= THIS_MODULE,
	.make_request	= make_request,
	.run		= run,
	.stop		= stop,
	.status		= status,
	.error_handler	= error,
	.hot_add_disk	= raid5_add_disk,
	.hot_remove_disk= raid5_remove_disk,
	.spare_active	= raid5_spare_active,
	.sync_request	= sync_request,
	.resize		= raid5_resize,
	.size		= raid5_size,
	.check_reshape	= raid5_check_reshape,
	.start_reshape  = raid5_start_reshape,
	.finish_reshape = raid5_finish_reshape,
	.quiesce	= raid5_quiesce,
	.takeover	= raid4_takeover,
};

static int __init raid5_init(void)
{
	register_md_personality(&raid6_personality);
	register_md_personality(&raid5_personality);
	register_md_personality(&raid4_personality);
	return 0;
}

static void raid5_exit(void)
{
	unregister_md_personality(&raid6_personality);
	unregister_md_personality(&raid5_personality);
	unregister_md_personality(&raid4_personality);
}

module_init(raid5_init);
module_exit(raid5_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RAID4/5/6 (striping with parity) personality for MD");
MODULE_ALIAS("md-personality-4"); /* RAID5 */
MODULE_ALIAS("md-raid5");
MODULE_ALIAS("md-raid4");
MODULE_ALIAS("md-level-5");
MODULE_ALIAS("md-level-4");
MODULE_ALIAS("md-personality-8"); /* RAID6 */
MODULE_ALIAS("md-raid6");
MODULE_ALIAS("md-level-6");

/* This used to be two separate modules, they were: */
MODULE_ALIAS("raid5");
MODULE_ALIAS("raid6");

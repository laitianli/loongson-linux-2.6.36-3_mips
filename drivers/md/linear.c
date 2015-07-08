/*
   linear.c : Multiple Devices driver for Linux
	      Copyright (C) 1994-96 Marc ZYNGIER
	      <zyngier@ufr-info-p7.ibp.fr> or
	      <maz@gloups.fdn.fr>

   Linear mode management functions.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.
   
   You should have received a copy of the GNU General Public License
   (for example /usr/src/linux/COPYING); if not, write to the Free
   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
*/
/**ltl
*算法描述:1.把各个成员磁盘串连起来，组成一个大磁盘。数据首先往第一个磁盘存储，然后第二个，依此类推。
*	    2.linear不存在冗余信息，存储设备利用率100%。
*	    3.当一个成员磁盘出现错误时，则可能导致此磁盘的大部分数据丢失。	
*/

#include <linux/blkdev.h>
#include <linux/raid/md_u.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include "md.h"
#include "linear.h"

/*
 * find which device holds a particular offset 
 */
/**ltl
功能:通过分二查找方法找到请求扇区所属的设备。
参数:mddev	->MD设备对象
	sector	->起始扇区
返回值:成员磁盘的信息。
说明:
*/
static inline dev_info_t *which_dev(mddev_t *mddev, sector_t sector)
{
	int lo, mid, hi;
	linear_conf_t *conf;

	lo = 0;
	hi = mddev->raid_disks - 1;
	conf = rcu_dereference(mddev->private);

	/*
	 * Binary Search
	 */

	while (hi > lo) {

		mid = (hi + lo) / 2;
		if (sector < conf->disks[mid].end_sector)
			hi = mid;
		else
			lo = mid + 1;
	}

	return conf->disks + lo;
}

/**
 *	linear_mergeable_bvec -- tell bio layer if two requests can be merged
 *	@q: request queue
 *	@bvm: properties of new bio
 *	@biovec: the request that could be merged to it.
 *
 *	Return amount of bytes we can take at this offset
 */
static int linear_mergeable_bvec(struct request_queue *q,
				 struct bvec_merge_data *bvm,
				 struct bio_vec *biovec)
{
	mddev_t *mddev = q->queuedata;
	dev_info_t *dev0;
	unsigned long maxsectors, bio_sectors = bvm->bi_size >> 9;
	sector_t sector = bvm->bi_sector + get_start_sect(bvm->bi_bdev);

	rcu_read_lock();
	dev0 = which_dev(mddev, sector);
	maxsectors = dev0->end_sector - sector;
	rcu_read_unlock();

	if (maxsectors < bio_sectors)
		maxsectors = 0;
	else
		maxsectors -= bio_sectors;

	if (maxsectors <= (PAGE_SIZE >> 9 ) && bio_sectors == 0)
		return biovec->bv_len;
	/* The bytes available at this offset could be really big,
	 * so we cap at 2^31 to avoid overflow */
	if (maxsectors > (1 << (31-9)))
		return 1<<31;
	return maxsectors << 9;
}
/**ltl
功能:linear个性化的"泄流"处理函数
参数:
返回值:
说明:这个函数被"泄流"工作队列blk_unplug_work调用。Q:什么时候被调用?答:在MD设备刷新时blk_backing_dev_unplug,
	而不是通过blk_plug_device，因为对MD设备并没有走这个流程。
*/
static void linear_unplug(struct request_queue *q)
{
	mddev_t *mddev = q->queuedata;
	linear_conf_t *conf;
	int i;

	rcu_read_lock();
	conf = rcu_dereference(mddev->private);
	//调用各个成员设备的"泄流"处理函数。
	for (i=0; i < mddev->raid_disks; i++) {
		//成员磁盘的请求队列
		struct request_queue *r_queue = bdev_get_queue(conf->disks[i].rdev->bdev);
		//泄流
		blk_unplug(r_queue);
	}
	rcu_read_unlock();
}

static int linear_congested(void *data, int bits)
{
	mddev_t *mddev = data;
	linear_conf_t *conf;
	int i, ret = 0;

	if (mddev_congested(mddev, bits))
		return 1;

	rcu_read_lock();
	conf = rcu_dereference(mddev->private);

	for (i = 0; i < mddev->raid_disks && !ret ; i++) {
		struct request_queue *q = bdev_get_queue(conf->disks[i].rdev->bdev);
		ret |= bdi_congested(&q->backing_dev_info, bits);
	}

	rcu_read_unlock();
	return ret;
}
/**ltl
功能:linear个性化的磁盘容量。
参数:
返回值:
说明:
*/
static sector_t linear_size(mddev_t *mddev, sector_t sectors, int raid_disks)
{
	linear_conf_t *conf;
	sector_t array_sectors;

	rcu_read_lock();
	conf = rcu_dereference(mddev->private);
	WARN_ONCE(sectors || raid_disks,
		  "%s does not support generic reshape\n", __func__);
	array_sectors = conf->array_sectors;
	rcu_read_unlock();

	return array_sectors;
}
/**ltl
功能:分配linear个性化数据结构。
参数
返回值:
说明:为成员磁盘分配个性数据。
*/
static linear_conf_t *linear_conf(mddev_t *mddev, int raid_disks)
{
	linear_conf_t *conf;
	mdk_rdev_t *rdev;
	int i, cnt;
	//根据成员磁盘的个数分配空间。
	conf = kzalloc (sizeof (*conf) + raid_disks*sizeof(dev_info_t),
			GFP_KERNEL);
	if (!conf)
		return NULL;

	cnt = 0;
	conf->array_sectors = 0;
	//遍历成员磁盘链表。
	list_for_each_entry(rdev, &mddev->disks, same_set) 
	{
		int j = rdev->raid_disk;
		dev_info_t *disk = conf->disks + j;
		sector_t sectors;

		if (j < 0 || j >= raid_disks || disk->rdev) 
		{
			printk(KERN_ERR "md/linear:%s: disk numbering problem. Aborting!\n",
			       mdname(mddev));
			goto out;
		}

		disk->rdev = rdev;
		if (mddev->chunk_sectors) 
		{//Q:why?
			sectors = rdev->sectors;
			sector_div(sectors, mddev->chunk_sectors);
			rdev->sectors = sectors * mddev->chunk_sectors;
		}

		disk_stack_limits(mddev->gendisk, rdev->bdev,rdev->data_offset << 9);
		/* as we don't honour merge_bvec_fn, we must never risk
		 * violating it, so limit max_segments to 1 lying within
		 * a single page.
		 */
		if (rdev->bdev->bd_disk->queue->merge_bvec_fn) 
		{
			blk_queue_max_segments(mddev->queue, 1);
			blk_queue_segment_boundary(mddev->queue,PAGE_CACHE_SIZE - 1);
		}
		//计算总的大小。
		conf->array_sectors += rdev->sectors;
		cnt++;

	}
	if (cnt != raid_disks)
	{
		printk(KERN_ERR "md/linear:%s: not enough drives present. Aborting!\n",
		       mdname(mddev));
		goto out;
	}

	/*
	 * Here we calculate the device offsets.
	 */
	conf->disks[0].end_sector = conf->disks[0].rdev->sectors;

	for (i = 1; i < raid_disks; i++)
		conf->disks[i].end_sector =	conf->disks[i-1].end_sector + conf->disks[i].rdev->sectors;

	return conf;

out:
	kfree(conf);
	return NULL;
}
/**ltl
功能:个性运行接口
参数:
返回值:
说明:主要目的是建立个性化数据结构，为后续对MD设备的请求处理做准备。
*/
static int linear_run (mddev_t *mddev)
{
	linear_conf_t *conf;

	if (md_check_no_bitmap(mddev))
		return -EINVAL;
	mddev->queue->queue_lock = &mddev->queue->__queue_lock;
	//分配个性化数据结构
	conf = linear_conf(mddev, mddev->raid_disks);

	if (!conf)
		return 1;
	mddev->private = conf;
	md_set_array_sectors(mddev, linear_size(mddev, 0, 0));
	//设置判定bio是否可以合并的函数。
	blk_queue_merge_bvec(mddev->queue, linear_mergeable_bvec);
	//设置MD设备"泄流"处理函数。
	mddev->queue->unplug_fn = linear_unplug;
	//拥塞控制。
	mddev->queue->backing_dev_info.congested_fn = linear_congested;
	mddev->queue->backing_dev_info.congested_data = mddev;
	//完整性。
	md_integrity_register(mddev);
	return 0;
}

static void free_conf(struct rcu_head *head)
{
	linear_conf_t *conf = container_of(head, linear_conf_t, rcu);
	kfree(conf);
}
/**ltl
功能:向MD设备添加新成员磁盘。
参数:mddev	->MD设备对象
	rdev	->成员磁盘对象
返回值:
说明:MD设备已经建立起，向新的设备添加成员磁盘
*/
static int linear_add(mddev_t *mddev, mdk_rdev_t *rdev)
{
	/* Adding a drive to a linear array allows the array to grow.
	 * It is permitted if the new drive has a matching superblock
	 * already on it, with raid_disk equal to raid_disks.
	 * It is achieved by creating a new linear_private_data structure
	 * and swapping it in in-place of the current one.
	 * The current one is never freed until the array is stopped.
	 * This avoids races.
	 */
	linear_conf_t *newconf, *oldconf;

	if (rdev->saved_raid_disk != mddev->raid_disks)
		return -EINVAL;

	rdev->raid_disk = rdev->saved_raid_disk;
	//
	newconf = linear_conf(mddev,mddev->raid_disks+1);

	if (!newconf)
		return -ENOMEM;

	oldconf = rcu_dereference(mddev->private);
	mddev->raid_disks++;
	rcu_assign_pointer(mddev->private, newconf);
	md_set_array_sectors(mddev, linear_size(mddev, 0, 0));
	set_capacity(mddev->gendisk, mddev->array_sectors);
	revalidate_disk(mddev->gendisk);
	call_rcu(&oldconf->rcu, free_conf);
	return 0;
}

static int linear_stop (mddev_t *mddev)
{
	linear_conf_t *conf = mddev->private;

	/*
	 * We do not require rcu protection here since
	 * we hold reconfig_mutex for both linear_add and
	 * linear_stop, so they cannot race.
	 * We should make sure any old 'conf's are properly
	 * freed though.
	 */
	rcu_barrier();
	blk_sync_queue(mddev->queue); /* the unplug fn references 'conf'*/
	kfree(conf);
	mddev->private = NULL;

	return 0;
}

static int linear_make_request (mddev_t *mddev, struct bio *bio)
{
	dev_info_t *tmp_dev;
	sector_t start_sector;
	//如果bio是一个屏障IO(如:超级块)
	if (unlikely(bio->bi_rw & REQ_HARDBARRIER)) {
		md_barrier_request(mddev, bio);
		return 0;
	}
	
	rcu_read_lock();
	//判定bio请求所属的成员磁盘。
	tmp_dev = which_dev(mddev, bio->bi_sector);
	//成员磁盘起始扇区
	start_sector = tmp_dev->end_sector - tmp_dev->rdev->sectors;

	//bio请求的起始扇区号大于设备的最后扇区，或者小于开始扇区。
	if (unlikely(bio->bi_sector >= (tmp_dev->end_sector)
		     || (bio->bi_sector < start_sector))) {
		char b[BDEVNAME_SIZE];

		printk(KERN_ERR
		       "md/linear:%s: make_request: Sector %llu out of bounds on "
		       "dev %s: %llu sectors, offset %llu\n",
		       mdname(mddev),
		       (unsigned long long)bio->bi_sector,
		       bdevname(tmp_dev->rdev->bdev, b),
		       (unsigned long long)tmp_dev->rdev->sectors,
		       (unsigned long long)start_sector);
		rcu_read_unlock();
		bio_io_error(bio);
		return 0;
	}
	//请求的扇区超出成员磁盘的最后扇区，则要对其进行分割。
	if (unlikely(bio->bi_sector + (bio->bi_size >> 9) >
		     tmp_dev->end_sector)) {
		/* This bio crosses a device boundary, so we have to
		 * split it.
		 */
		struct bio_pair *bp;
		//成员磁盘的最后一个扇区
		sector_t end_sector = tmp_dev->end_sector;

		rcu_read_unlock();
		//把bio分片处理
		bp = bio_split(bio, end_sector - bio->bi_sector);
		//递归处理分片后的bio
		if (linear_make_request(mddev, &bp->bio1))
			generic_make_request(&bp->bio1);
		if (linear_make_request(mddev, &bp->bio2))
			generic_make_request(&bp->bio2);
		bio_pair_release(bp);
		return 0;
	}
	//重定向bio所属的设备(定位到成员磁盘)		    
	bio->bi_bdev = tmp_dev->rdev->bdev;
	/*假如:bio请求的是第二个成员磁盘的数据:
	*重定向bio起始扇区=相对MD设备的bio请求起始扇区-第二个成员磁盘的起始扇区+第二个成员磁盘的数据区的偏移地址。
	*/
	bio->bi_sector = bio->bi_sector - start_sector + tmp_dev->rdev->data_offset;
	rcu_read_unlock();
	//返回1，使得__generic_make_request中的do{}while(ret)循环重新执行，把请求重定向到成员磁盘的请求处理函数。
	return 1;
}

static void linear_status (struct seq_file *seq, mddev_t *mddev)
{

	seq_printf(seq, " %dk rounding", mddev->chunk_sectors / 2);
}


static struct mdk_personality linear_personality =
{
	.name		= "linear",
	.level		= LEVEL_LINEAR,
	.owner		= THIS_MODULE,
	.make_request	= linear_make_request,
	.run		= linear_run,
	.stop		= linear_stop,
	.status		= linear_status,
	.hot_add_disk	= linear_add,
	.size		= linear_size,
};
/**ltl
功能:
*/
static int __init linear_init (void)
{
	return register_md_personality (&linear_personality);
}

static void linear_exit (void)
{
	unregister_md_personality (&linear_personality);
}


module_init(linear_init);
module_exit(linear_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linear device concatenation personality for MD");
MODULE_ALIAS("md-personality-1"); /* LINEAR - deprecated*/
MODULE_ALIAS("md-linear");
MODULE_ALIAS("md-level--1");

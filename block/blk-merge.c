/*
 * Functions related to segment and merge handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>

#include "blk.h"
/**ltl
 *功能:计算bio中包括的内存段数
 *参数:
 *返回值:
 *说明:
 */
static unsigned int __blk_recalc_rq_segments(struct request_queue *q,
					     struct bio *bio)
{
	struct bio_vec *bv, *bvprv = NULL;
	int cluster, i, high, highprv = 1;
	unsigned int seg_size, nr_phys_segs;
	struct bio *fbio, *bbio;

	if (!bio)
		return 0;

	fbio = bio;
	cluster = blk_queue_cluster(q);
	seg_size = 0;
	nr_phys_segs = 0;
	for_each_bio(bio) {
		bio_for_each_segment(bv, bio, i) {
			/*
			 * the trick here is making sure that a high page is
			 * never considered part of another segment, since that
			 * might change with the bounce page.
			 */
			high = page_to_pfn(bv->bv_page) > queue_bounce_pfn(q);
			if (high || highprv)
				goto new_segment;
			if (cluster) {
				if (seg_size + bv->bv_len > queue_max_segment_size(q))
					goto new_segment;
				if (!BIOVEC_PHYS_MERGEABLE(bvprv, bv))/* 两段是否可能合并 */
					goto new_segment;
				if (!BIOVEC_SEG_BOUNDARY(q, bvprv, bv))/*  */
					goto new_segment;

				seg_size += bv->bv_len;
				bvprv = bv;
				continue;
			}
new_segment:
			if (nr_phys_segs == 1 && seg_size > fbio->bi_seg_front_size)
				fbio->bi_seg_front_size = seg_size;

			nr_phys_segs++;
			bvprv = bv;
			seg_size = bv->bv_len;
			highprv = high;
		}
		bbio = bio;
	}

	if (nr_phys_segs == 1 && seg_size > fbio->bi_seg_front_size)
		fbio->bi_seg_front_size = seg_size;
	if (seg_size > bbio->bi_seg_back_size)
		bbio->bi_seg_back_size = seg_size;

	return nr_phys_segs;
}

void blk_recalc_rq_segments(struct request *rq)
{
	rq->nr_phys_segments = __blk_recalc_rq_segments(rq->q, rq->bio);
}
/**ltl
 *功能:计算bio包括的物理内在段数。
 *参数:q	->请求队列对象
 *     bio->bio对象
 *返回值:
 *说明:
 */
void blk_recount_segments(struct request_queue *q, struct bio *bio)
{
	struct bio *nxt = bio->bi_next;

	bio->bi_next = NULL; /* 把此域置空主要目的是:在函数__blk_recalc_rq_segments使用for_each_bio循环时能结束循环 */
	bio->bi_phys_segments = __blk_recalc_rq_segments(q, bio);
	bio->bi_next = nxt;/* 重新赋值 */
	bio->bi_flags |= (1 << BIO_SEG_VALID); /* 设置段数有效标志 */
}
EXPORT_SYMBOL(blk_recount_segments);

static int blk_phys_contig_segment(struct request_queue *q, struct bio *bio,
				   struct bio *nxt)
{
	if (!blk_queue_cluster(q))
		return 0;

	if (bio->bi_seg_back_size + nxt->bi_seg_front_size >
	    queue_max_segment_size(q))
		return 0;

	if (!bio_has_data(bio))
		return 1;

	if (!BIOVEC_PHYS_MERGEABLE(__BVEC_END(bio), __BVEC_START(nxt)))
		return 0;

	/*
	 * bio and nxt are contiguous in memory; check if the queue allows
	 * these two to be merged into one
	 */
	if (BIO_SEG_BOUNDARY(q, bio, nxt))
		return 1;

	return 0;
}

/*
 * map a request to scatterlist, return number of sg entries setup. Caller
 * must make sure sg can hold rq->nr_phys_segments entries
 */
int blk_rq_map_sg(struct request_queue *q, struct request *rq,
		  struct scatterlist *sglist)
{
	struct bio_vec *bvec, *bvprv;
	struct req_iterator iter;
	struct scatterlist *sg;
	int nsegs, cluster;

	nsegs = 0;
	cluster = blk_queue_cluster(q);

	/*
	 * for each bio in rq
	 */
	bvprv = NULL;
	sg = NULL;
	rq_for_each_segment(bvec, rq, iter) {
		int nbytes = bvec->bv_len;

		if (bvprv && cluster) {
			if (sg->length + nbytes > queue_max_segment_size(q))
				goto new_segment;

			if (!BIOVEC_PHYS_MERGEABLE(bvprv, bvec))
				goto new_segment;
			if (!BIOVEC_SEG_BOUNDARY(q, bvprv, bvec))
				goto new_segment;

			sg->length += nbytes;
		} else {
new_segment:
			if (!sg)
				sg = sglist;
			else {
				/*
				 * If the driver previously mapped a shorter
				 * list, we could see a termination bit
				 * prematurely unless it fully inits the sg
				 * table on each mapping. We KNOW that there
				 * must be more entries here or the driver
				 * would be buggy, so force clear the
				 * termination bit to avoid doing a full
				 * sg_init_table() in drivers for each command.
				 */
				sg->page_link &= ~0x02;
				sg = sg_next(sg);
			}

			sg_set_page(sg, bvec->bv_page, nbytes, bvec->bv_offset);
			nsegs++;
		}
		bvprv = bvec;
	} /* segments in rq */


	if (unlikely(rq->cmd_flags & REQ_COPY_USER) &&
	    (blk_rq_bytes(rq) & q->dma_pad_mask)) {
		unsigned int pad_len =
			(q->dma_pad_mask & ~blk_rq_bytes(rq)) + 1;

		sg->length += pad_len;
		rq->extra_len += pad_len;
	}

	if (q->dma_drain_size && q->dma_drain_needed(rq)) {
		if (rq->cmd_flags & REQ_WRITE)
			memset(q->dma_drain_buffer, 0, q->dma_drain_size);

		sg->page_link &= ~0x02;
		sg = sg_next(sg);
		sg_set_page(sg, virt_to_page(q->dma_drain_buffer),
			    q->dma_drain_size,
			    ((unsigned long)q->dma_drain_buffer) &
			    (PAGE_SIZE - 1));
		nsegs++;
		rq->extra_len += q->dma_drain_size;
	}

	if (sg)
		sg_mark_end(sg);

	return nsegs;
}
EXPORT_SYMBOL(blk_rq_map_sg);
/**ltl
 *功能:更新请求req的物理段数
 *参数:
 *返回值:
 *说明:
 */
static inline int ll_new_hw_segment(struct request_queue *q,
				    struct request *req,
				    struct bio *bio)
{
 	/* bio的物理段数 */	
	int nr_phys_segs = bio_phys_segments(q, bio);
	/* 请求的物理段数与bio的物理段时是否超出请求队列的最大物理段数 */
	if (req->nr_phys_segments + nr_phys_segs > queue_max_segments(q)) {
		req->cmd_flags |= REQ_NOMERGE;/* 设置不能合并标志 */
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}

	/*
	 * This will form the start of a new hw segment.  Bump both
	 * counters.
	 */
	req->nr_phys_segments += nr_phys_segs; /* 累加物理段数 */
	return 1;
}
/**ltl
 *功能:判定req是否能与bio合并
 *参数:
 *返回值:
 *说明:这个主要是从两方面判定bio能否合并到request请求中:1.两请求是否超出请求队列的最大扇区数；
 *										      2.两请求的物理段数(内存块数)是否超出请求队列的限制。
 */
int ll_back_merge_fn(struct request_queue *q, struct request *req,
		     struct bio *bio)
{
	unsigned short max_sectors;
	/* 请求队列的最大扇区数 */
	if (unlikely(req->cmd_type == REQ_TYPE_BLOCK_PC))
		max_sectors = queue_max_hw_sectors(q);
	else
		max_sectors = queue_max_sectors(q);
	/* req与bio的扇区数总和超过最大扇区数 */
	if (blk_rq_sectors(req) + bio_sectors(bio) > max_sectors) {
		req->cmd_flags |= REQ_NOMERGE; /* 设置不能合并标志 */
		if (req == q->last_merge) /* 如果上一次合并的request就是此req，则把last_merge置空 */
			q->last_merge = NULL;
		return 0;
	}
	if (!bio_flagged(req->biotail, BIO_SEG_VALID)) /* 表示biotail->bi_phys_segments无效 */
		blk_recount_segments(q, req->biotail); /* 计算biotail的物理段数 */
	if (!bio_flagged(bio, BIO_SEG_VALID)) /* bio->bi_phys_segments物理段数值无效 */
		blk_recount_segments(q, bio); /* 计算bio的物理段数 */

	return ll_new_hw_segment(q, req, bio);
}

int ll_front_merge_fn(struct request_queue *q, struct request *req,
		      struct bio *bio)
{
	unsigned short max_sectors;

	if (unlikely(req->cmd_type == REQ_TYPE_BLOCK_PC))
		max_sectors = queue_max_hw_sectors(q);
	else
		max_sectors = queue_max_sectors(q);


	if (blk_rq_sectors(req) + bio_sectors(bio) > max_sectors) {
		req->cmd_flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}
	if (!bio_flagged(bio, BIO_SEG_VALID))
		blk_recount_segments(q, bio);
	if (!bio_flagged(req->bio, BIO_SEG_VALID))
		blk_recount_segments(q, req->bio);

	return ll_new_hw_segment(q, req, bio);
}
/**ltl
 *功能:判定两个请求是否能够合并
 *参数:	q	->请求队列对象
 *		req	->请求1
 *		next ->请求2
 *返回值:
 *说明:
 */
static int ll_merge_requests_fn(struct request_queue *q, struct request *req,
				struct request *next)
{
	int total_phys_segments;
	unsigned int seg_size =  /* 两个请求的总的段数 */
		req->biotail->bi_seg_back_size + next->bio->bi_seg_front_size;

	/*
	 * First check if the either of the requests are re-queued
	 * requests.  Can't merge them if they are.
	 */
	if (req->special || next->special) /* 至少一个请求已经提交给底层(scsi子系统层) */
		return 0;

	/*
	 * Will it become too large?
	 */
	/* 判定两个请求的扇区总数是否超出请求队列的限制 */
	if ((blk_rq_sectors(req) + blk_rq_sectors(next)) > queue_max_sectors(q))
		return 0;
	/* 两个请求的物理段数和 */
	total_phys_segments = req->nr_phys_segments + next->nr_phys_segments;

	/* Why? */
	if (blk_phys_contig_segment(q, req->biotail, next->bio)) {
		if (req->nr_phys_segments == 1)
			req->bio->bi_seg_front_size = seg_size;
		if (next->nr_phys_segments == 1)
			next->biotail->bi_seg_back_size = seg_size;
		total_phys_segments--;
	}
	/* 两请求的物理段数超出了请求队列的限制 */
	if (total_phys_segments > queue_max_segments(q))
		return 0;
	/* 可以合并，更新请求的物理段数 */
	/* Merge is OK... */
	req->nr_phys_segments = total_phys_segments;
	return 1;
}

/**
 * blk_rq_set_mixed_merge - mark a request as mixed merge
 * @rq: request to mark as mixed merge
 *
 * Description:
 *     @rq is about to be mixed merged.  Make sure the attributes
 *     which can be mixed are set in each bio and mark @rq as mixed
 *     merged.
 */
void blk_rq_set_mixed_merge(struct request *rq)
{
	unsigned int ff = rq->cmd_flags & REQ_FAILFAST_MASK;
	struct bio *bio;

	if (rq->cmd_flags & REQ_MIXED_MERGE)
		return;

	/*
	 * @rq will no longer represent mixable attributes for all the
	 * contained bios.  It will just track those of the first one.
	 * Distributes the attributs to each bio.
	 */
	for (bio = rq->bio; bio; bio = bio->bi_next) {
		WARN_ON_ONCE((bio->bi_rw & REQ_FAILFAST_MASK) &&
			     (bio->bi_rw & REQ_FAILFAST_MASK) != ff);
		bio->bi_rw |= ff;
	}
	rq->cmd_flags |= REQ_MIXED_MERGE;
}

static void blk_account_io_merge(struct request *req)
{
	if (blk_do_io_stat(req)) {
		struct hd_struct *part;
		int cpu;

		cpu = part_stat_lock();
		part = disk_map_sector_rcu(req->rq_disk, blk_rq_pos(req));

		part_round_stats(cpu, part);
		part_dec_in_flight(part, rq_data_dir(req));

		part_stat_unlock();
	}
}

/*
 * Has to be called with the request spinlock acquired
 */
/**ltl
 *功能:合并两个请求
 *参数:	q	->请求队列对象
 *		req	->请求1
 *		next ->请求2
 *返回值:
 *说明:req和next两个请求本来存在空洞，在把bio合入时，刚好填充的此空洞。
 */
static int attempt_merge(struct request_queue *q, struct request *req,
			  struct request *next)
{
	/* 请求是否能够合并 */
	if (!rq_mergeable(req) || !rq_mergeable(next))
		return 0;

	/*
	 * Don't merge file system requests and discard requests
	 */
	if ((req->cmd_flags & REQ_DISCARD) != (next->cmd_flags & REQ_DISCARD))
		return 0;

	/*
	 * Don't merge discard requests and secure discard requests
	 */
	if ((req->cmd_flags & REQ_SECURE) != (next->cmd_flags & REQ_SECURE))
		return 0;

	/*
	 * not contiguous
	 */
	/* 两个请求的扇区并不相临 */
	if (blk_rq_pos(req) + blk_rq_sectors(req) != blk_rq_pos(next))
		return 0;
	/* 两个请求的方向不一致，或者不同的通用磁盘；或者请求已经派发到scsi层之下 */
	if (rq_data_dir(req) != rq_data_dir(next)
	    || req->rq_disk != next->rq_disk
	    || next->special)
		return 0;
	/* 数据完整性的考虑 */
	if (blk_integrity_rq(req) != blk_integrity_rq(next))
		return 0;

	/*
	 * If we are allowed to merge, then append bio list
	 * from next to rq and release next. merge_requests_fn
	 * will have updated segment counts, update sector
	 * counts here.
	 */
	/* 从扇区总数的限制和物理段数的限制来判定两个请求是否能合并 */
	if (!ll_merge_requests_fn(q, req, next))
		return 0;

	/*
	 * If failfast settings disagree or any of the two is already
	 * a mixed merge, mark both as mixed before proceeding.  This
	 * makes sure that all involved bios have mixable attributes
	 * set properly.
	 */
	if ((req->cmd_flags | next->cmd_flags) & REQ_MIXED_MERGE ||
	    (req->cmd_flags & REQ_FAILFAST_MASK) !=
	    (next->cmd_flags & REQ_FAILFAST_MASK)) {
		blk_rq_set_mixed_merge(req);
		blk_rq_set_mixed_merge(next);
	}

	/*
	 * At this point we have either done a back merge
	 * or front merge. We need the smaller start_time of
	 * the merged requests to be the current request
	 * for accounting purposes.
	 */
	/* 被合并的请求next的开始请求时间比请求req的请求还早的话，则要更改req的请求开始时间 */
	if (time_after(req->start_time, next->start_time))
		req->start_time = next->start_time;
	/* 合并两个request的bio链表 */
	req->biotail->bi_next = next->bio;
	req->biotail = next->biotail;
	/* 更改请求的数据长度 */
	req->__data_len += blk_rq_bytes(next);
	/* 合并请求的调度算法数据 */
	elv_merge_requests(q, req, next);

	/*
	 * 'next' is going away, so update stats accordingly
	 */
	blk_account_io_merge(next);
	/* 更新优先级 */
	req->ioprio = ioprio_best(req->ioprio, next->ioprio);
	if (blk_rq_cpu_valid(next))
		req->cpu = next->cpu;

	/* owner-ship of bio passed from next to req */
	next->bio = NULL;
	__blk_put_request(q, next);
	return 1;
}
/**ltl
 *功能:向后合并rq请求
 *参数:q	->请求队列
 	  rq	->请求
 *返回值:
 *说明:找到请求的起始扇区号是rq的后一个request对象，试图把它们两合并
 */
int attempt_back_merge(struct request_queue *q, struct request *rq)
{
	struct request *next = elv_latter_request(q, rq); /* 获取调度队列rq之后的请求 */

	if (next)
		return attempt_merge(q, rq, next); /* 合并两个请求 */

	return 0;
}
/**ltl
 *功能:向前合并rq请求
 *参数:q	->请求队列
 	  rq	->请求
 *返回值:
 *说明:找到请求的起始扇区号是rq的前一个request对象，试图把它们两合并
 */
int attempt_front_merge(struct request_queue *q, struct request *rq)
{
	struct request *prev = elv_former_request(q, rq);

	if (prev)
		return attempt_merge(q, prev, rq);

	return 0;
}

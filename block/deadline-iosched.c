/*
 *  Deadline i/o scheduler.
 *
 *  Copyright (C) 2002 Jens Axboe <axboe@kernel.dk>
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/rbtree.h>

/*
 * See Documentation/block/deadline-iosched.txt
 */
static const int read_expire = HZ / 2;  /* max time before a read is submitted. */
static const int write_expire = 5 * HZ; /* ditto for writes, these limits are SOFT! */
static const int writes_starved = 2;    /* max times reads can starve a write */
static const int fifo_batch = 16;       /* # of sequential requests treated as one
				     by the above parameters. For throughput. */
/* 最后期限调度算法数据对象 */
struct deadline_data {
	/*
	 * run time data
	 */

	/*
	 * requests (deadline_rq s) are present on both sort_list and fifo_list
	 */
	struct rb_root sort_list[2]; /* READ/WRITE请求的红黑树头 */	
	struct list_head fifo_list[2]; /* READ/WRITE请求的FIFO队列头 */

	/*
	 * next in sort order. read, write or both are NULL
	 */
	struct request *next_rq[2]; /* 记录下一次请求对象地址，每次请求从调度队列转移到派发队列时都会记录这个值 */
	unsigned int batching;		/* number of sequential requests made */
	sector_t last_sector;		/* head position */
	unsigned int starved;		/* times reads have starved writes */

	/*
	 * settings that change how the i/o scheduler behaves
	 */
	int fifo_expire[2]; /* READ/WRITE请求的最大期限 */
	int fifo_batch;
	int writes_starved; /* 写请求的最大饥饿时间 */
	int front_merges;
};

static void deadline_move_request(struct deadline_data *, struct request *);
/* 红黑树根 */
static inline struct rb_root *
deadline_rb_root(struct deadline_data *dd, struct request *rq)
{
	return &dd->sort_list[rq_data_dir(rq)];
}

/*
 * get the request after `rq' in sector-sorted order
 */
/**ltl
 *功能:获取rq的下一请求
 *参数:
 *返回值:
 *说明:
 */
static inline struct request *
deadline_latter_request(struct request *rq)
{
	struct rb_node *node = rb_next(&rq->rb_node);

	if (node)
		return rb_entry_rq(node);

	return NULL;
}
/**ltl
 *功能:将请求插入到红黑树中
 *参数:
 *返回值:
 *说明:
 */
static void
deadline_add_rq_rb(struct deadline_data *dd, struct request *rq)
{
	struct rb_root *root = deadline_rb_root(dd, rq);
	struct request *__alias;
	/* 将请求插入到红黑树中，如果请求已经在树中，则要把此请求移到派发队列中 */
	while (unlikely(__alias = elv_rb_add(root, rq)))
		deadline_move_request(dd, __alias);
}
/**ltl
 *功能:从红黑树中删除请求 
 *参数:
 *返回值:
 *说明:
 */
static inline void
deadline_del_rq_rb(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);
	/* 重置下一请求对象 */
	if (dd->next_rq[data_dir] == rq)
		dd->next_rq[data_dir] = deadline_latter_request(rq); 
	/* 从红黑树中删除请求 */
	elv_rb_del(deadline_rb_root(dd, rq), rq);
}

/*
 * add rq to rbtree and fifo
 */
/**ltl
 *功能:将请求插入到调度队列中
 *参数:
 *返回值:
 *说明:对最后期限算法，请求要插入到两个队列中:1.FIFO队列；2.红黑树中
 */
static void
deadline_add_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	const int data_dir = rq_data_dir(rq);
	/* 将请求插入到红黑树中 */
	deadline_add_rq_rb(dd, rq);

	/*
	 * set expire time and add to fifo list
	 */
	/* 设置请求的最后服务时间 */
	rq_set_fifo_time(rq, jiffies + dd->fifo_expire[data_dir]);
	/* 将请求插入到FIFO队列中 */
	list_add_tail(&rq->queuelist, &dd->fifo_list[data_dir]);
}

/*
 * remove rq from rbtree and fifo.
 */
/**ltl
 *功能:把请求req从最后期限的调度队列中删除
 *参数:
 *返回值:
 *说明:
 */
static void deadline_remove_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	rq_fifo_clear(rq);  /* 从先进先出队列(FIFO)中删除请求 */
	deadline_del_rq_rb(dd, rq); /* 从红黑树中删除请求 */
}

/**ltl
 *功能:从最后期限算法的调度队列中获取与bio合并的request对象及其合并位置
 *参数:q	->请求对象
 *	  req->[out]可以与bio合并的对象
 *	  bio->要合并的bio对象
 *返回值:合并位置
 *说明:这里只要考虑向前合并，因为向后的合并的情况已经在elv_merge中提前考虑(在调度算法层中有Hash表用来考虑向后合并的情况)
 *		这也是elevator_queue:hash的作用。
 */
static int
deadline_merge(struct request_queue *q, struct request **req, struct bio *bio)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	struct request *__rq;
	int ret;

	/*
	 * check for front merge
	 */
	if (dd->front_merges) { /* 允许向前合并 */
		sector_t sector = bio->bi_sector + bio_sectors(bio); /* bio的最后一个扇区 */
		/* 在红黑树中查找 */
		__rq = elv_rb_find(&dd->sort_list[bio_data_dir(bio)], sector);
		if (__rq) {
			BUG_ON(sector != blk_rq_pos(__rq));

			if (elv_rq_merge_ok(__rq, bio)) { /* 达到合并的基本要求 */
				ret = ELEVATOR_FRONT_MERGE;
				goto out;
			}
		}
	}

	return ELEVATOR_NO_MERGE;
out:
	*req = __rq;
	return ret;
}

/**ltl 
 *功能:更改req请求与最后期限算法相关的数据信息
 *参数:
 *返回值:
 *说明:
 */
static void deadline_merged_request(struct request_queue *q,
				    struct request *req, int type)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	/*
	 * if the merge was a front merge, we need to reposition request
	 */
	/* 为什么要先删除再插入呢? 因为req已经合并新的bio，致使req在红黑树的位置发生改变 */
	if (type == ELEVATOR_FRONT_MERGE) {/* 如果是向前合并 */
		elv_rb_del(deadline_rb_root(dd, req), req);/* 先把请求从红黑树中删除 */
		deadline_add_rq_rb(dd, req);	/* 把新的请求插入到红黑树中 */
	}
}
/**ltl
 *功能:合并两请求的与最后期限调度算法有关的数据。
 *参数:
 *返回值:
 *说明: 主要是释放被合并请求的与最后期限调度算法有关的内存空间
 */
static void
deadline_merged_requests(struct request_queue *q, struct request *req,
			 struct request *next)
{
	/*
	 * if next expires before rq, assign its expire time to rq
	 * and move into next position (next will be deleted) in fifo
	 */
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {/* 两请求都在FIFO队列中，且是同一个FIFO队列中 */
		if (time_before(rq_fifo_time(next), rq_fifo_time(req))) { /* 如果next的最后期限时间比req早 */
			list_move(&req->queuelist, &next->queuelist); /* 把req请求移到next请求列表中，即把req插入到next之后 */
			rq_set_fifo_time(req, rq_fifo_time(next)); /* 用next请求的最后期限时间更新req的最后期限时间 */
		}
	}

	/*
	 * kill knowledge of next, this one is a goner
	 */
	deadline_remove_request(q, next);/* 把请求req从最后期限的调度队列中删除 */
}

/*
 * move request from sort list to dispatch queue.
 */
/**ltl
 *功能:将请求从调度队列移动派发队列
 *参数:
 *返回值:
 *说明:
 */
static inline void
deadline_move_to_dispatch(struct deadline_data *dd, struct request *rq)
{
	struct request_queue *q = rq->q;
	/* 将请求从调度队列中移除。注:释放请求的私有数据在哪里做呢? */
	deadline_remove_request(q, rq);
	/* 将请求尾入到派发队列 */
	elv_dispatch_add_tail(q, rq);
}

/*
 * move an entry to dispatch queue
 */
/**ltl
 *功能:将请求从调度队列转移到派发队列中
 *参数:dd	->最后期限的数据对象
 *	  rq	->请求对象
 *返回值:
 *说明:
 */
static void
deadline_move_request(struct deadline_data *dd, struct request *rq)
{
	/* 请求的方向 */
	const int data_dir = rq_data_dir(rq);
	/* 先将下一请求对象置空 */
	dd->next_rq[READ] = NULL;
	dd->next_rq[WRITE] = NULL;
	/* 记录下一请求对象 */
	dd->next_rq[data_dir] = deadline_latter_request(rq);
	/* 记录最后一扇区 */
	dd->last_sector = rq_end_sector(rq);

	/*
	 * take it off the sort and fifo list, move
	 * to dispatch queue
	 */
	deadline_move_to_dispatch(dd, rq); /* 将请求移到派发队列 */
}

/*
 * deadline_check_fifo returns 0 if there are no expired requests on the fifo,
 * 1 otherwise. Requires !list_empty(&dd->fifo_list[data_dir])
 */
/**ltl
 *功能:检查请求是否超时。
 *参数:
 *返回值:
 *说明:
 */
static inline int deadline_check_fifo(struct deadline_data *dd, int ddir)
{
	struct request *rq = rq_entry_fifo(dd->fifo_list[ddir].next);

	/*
	 * rq is expired!
	 */
	if (time_after(jiffies, rq_fifo_time(rq)))
		return 1;

	return 0;
}

/*
 * deadline_dispatch_requests selects the best request according to
 * read/write expire, fifo_batch, etc
 */
/**ltl
 *功能:根据最后期限调度算法，从调度队列选择一个最佳的请求，并转移到派发队列中去。
 *参数:
 *返回值:
 *说明:
 */
static int deadline_dispatch_requests(struct request_queue *q, int force)
{
	/* 最后期限的数据对象 */
	struct deadline_data *dd = q->elevator->elevator_data;
	const int reads = !list_empty(&dd->fifo_list[READ]); /* READ请求FIFO队列是否为NULL */
	const int writes = !list_empty(&dd->fifo_list[WRITE]); /* WRITE请求FIFO队列是否为NULL */
	struct request *rq;
	int data_dir;

	/*
	 * batches are currently reads XOR writes
	 */
	if (dd->next_rq[WRITE]) /* 下一写请求 */ 
		rq = dd->next_rq[WRITE];
	else
		rq = dd->next_rq[READ]; /* 下一读请求 */

	if (rq && dd->batching < dd->fifo_batch)
		/* we have a next request are still entitled to batch */
		goto dispatch_request;

	/*
	 * at this point we are not running a batch. select the appropriate
	 * data direction (read / write)
	 */
	/* FIFO列表中有读请求 */
	if (reads) {
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[READ])); /* READ红黑树中没有读请求 */
		/* FIFO队列中有读请求，并且饥饿次数已经超过写饥饿阀值 */
		if (writes && (dd->starved++ >= dd->writes_starved))
			goto dispatch_writes;/* 执行写请求 */
		/* 执行读 */
		data_dir = READ;

		goto dispatch_find_request;
	}

	/*
	 * there are either no reads or writes have been starved
	 */
	/* 写FIFO列表中有写请求 */
	if (writes) {
dispatch_writes:
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[WRITE])); /* WRITE红黑树中没有写请求 */
		/* 饥饿计数要置0 */
		dd->starved = 0;
		/* 执行写 */
		data_dir = WRITE;

		goto dispatch_find_request;
	}

	return 0;

dispatch_find_request:
	/*
	 * we are not running a batch, find best request for selected data_dir
	 */
	/* 请求是否超时，或者下一请求是否为NULL */
	if (deadline_check_fifo(dd, data_dir) || !dd->next_rq[data_dir]) {
		/*
		 * A deadline has expired, the last request was in the other
		 * direction, or we have run out of higher-sectored requests.
		 * Start again from the request with the earliest expiry time.
		 */
		rq = rq_entry_fifo(dd->fifo_list[data_dir].next); /* 从FIFO列表中取出一请求 */
	} else {
		/*
		 * The last req was the same dir and we have a next request in
		 * sort order. No expired requests so continue on from here.
		 */
		rq = dd->next_rq[data_dir];
	}

	dd->batching = 0;

dispatch_request:
	/*
	 * rq is the selected appropriate request.
	 */
	dd->batching++;
	deadline_move_request(dd, rq); /* 将请求从调度队列移动到派发队列 */

	return 1;
}
/**ltl
 *功能:判定调度队列是否有请求
 *参数:
 *返回值:
 *说明:
 */
static int deadline_queue_empty(struct request_queue *q)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	return list_empty(&dd->fifo_list[WRITE])
		&& list_empty(&dd->fifo_list[READ]);
}
/**ltl 
 *功能:最后期限的退出接口。
 *参数:
 *返回值:
 *说明:
 */
static void deadline_exit_queue(struct elevator_queue *e)
{
	struct deadline_data *dd = e->elevator_data;

	BUG_ON(!list_empty(&dd->fifo_list[READ]));
	BUG_ON(!list_empty(&dd->fifo_list[WRITE]));

	kfree(dd);
}

/*
 * initialize elevator private data (deadline_data).
 */
/**ltl
 *功能:最后期限调度算法的初始化
 *参数:q	->请求队列对象
 *返回值:最后期限高度算法的数据对象
 *说明:
 */
static void *deadline_init_queue(struct request_queue *q)
{
	struct deadline_data *dd;
	/* 分配内存空间 */
	dd = kmalloc_node(sizeof(*dd), GFP_KERNEL | __GFP_ZERO, q->node);
	if (!dd)
		return NULL;
	/* 初始化READ FIFO队列头 */
	INIT_LIST_HEAD(&dd->fifo_list[READ]);
	/* 初始化WRITE FIFO队列头 */
	INIT_LIST_HEAD(&dd->fifo_list[WRITE]);
	dd->sort_list[READ] = RB_ROOT; /* 初始化READ红黑树头 */
	dd->sort_list[WRITE] = RB_ROOT; /* 初始化WRITE红黑树头 */
	dd->fifo_expire[READ] = read_expire; /* READ请求在FIFO的最大期限 */
	dd->fifo_expire[WRITE] = write_expire; /* WRITE请求在FIFO的最大期限 */
	dd->writes_starved = writes_starved; /* 写请求的饥饿的最长时间 */
	dd->front_merges = 1;
	dd->fifo_batch = fifo_batch;
	return dd;
}

/*
 * sysfs parts below
 */

static ssize_t
deadline_var_show(int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static ssize_t
deadline_var_store(int *var, const char *page, size_t count)
{
	char *p = (char *) page;

	*var = simple_strtol(p, &p, 10);
	return count;
}

#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	struct deadline_data *dd = e->elevator_data;			\
	int __data = __VAR;						\
	if (__CONV)							\
		__data = jiffies_to_msecs(__data);			\
	return deadline_var_show(__data, (page));			\
}
SHOW_FUNCTION(deadline_read_expire_show, dd->fifo_expire[READ], 1);
SHOW_FUNCTION(deadline_write_expire_show, dd->fifo_expire[WRITE], 1);
SHOW_FUNCTION(deadline_writes_starved_show, dd->writes_starved, 0);
SHOW_FUNCTION(deadline_front_merges_show, dd->front_merges, 0);
SHOW_FUNCTION(deadline_fifo_batch_show, dd->fifo_batch, 0);
#undef SHOW_FUNCTION

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct deadline_data *dd = e->elevator_data;			\
	int __data;							\
	int ret = deadline_var_store(&__data, (page), count);		\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	if (__CONV)							\
		*(__PTR) = msecs_to_jiffies(__data);			\
	else								\
		*(__PTR) = __data;					\
	return ret;							\
}
STORE_FUNCTION(deadline_read_expire_store, &dd->fifo_expire[READ], 0, INT_MAX, 1);
STORE_FUNCTION(deadline_write_expire_store, &dd->fifo_expire[WRITE], 0, INT_MAX, 1);
STORE_FUNCTION(deadline_writes_starved_store, &dd->writes_starved, INT_MIN, INT_MAX, 0);
STORE_FUNCTION(deadline_front_merges_store, &dd->front_merges, 0, 1, 0);
STORE_FUNCTION(deadline_fifo_batch_store, &dd->fifo_batch, 0, INT_MAX, 0);
#undef STORE_FUNCTION

#define DD_ATTR(name) \
	__ATTR(name, S_IRUGO|S_IWUSR, deadline_##name##_show, \
				      deadline_##name##_store)

static struct elv_fs_entry deadline_attrs[] = {
	DD_ATTR(read_expire),
	DD_ATTR(write_expire),
	DD_ATTR(writes_starved),
	DD_ATTR(front_merges),
	DD_ATTR(fifo_batch),
	__ATTR_NULL
};
/* 最后期限调度算法对象 */
static struct elevator_type iosched_deadline = {
	.ops = {
		.elevator_merge_fn = 		deadline_merge, 		/* 获取可以与bio合并的request请求及合并的位置 */
		.elevator_merged_fn =		deadline_merged_request, /* 调整一个请求的私有数据 */
		.elevator_merge_req_fn =	deadline_merged_requests, /* 合并两请求的私有数据 */
		.elevator_dispatch_fn =		deadline_dispatch_requests, /* 把请求从调度队列分发到派发队列中 */
		.elevator_add_req_fn =		deadline_add_request,  /* 把请求添加到调度队列中 */
		.elevator_queue_empty_fn =	deadline_queue_empty,  /* 判定调度队列是否有请求 */
		.elevator_former_req_fn =	elv_rb_former_request, /* 获取与request相临的上一个request */
		.elevator_latter_req_fn =	elv_rb_latter_request, /* 获取与request相临的下一个request */
		.elevator_init_fn =		deadline_init_queue, /* 初始化函数 */
		.elevator_exit_fn =		deadline_exit_queue, /* 反初始化函数 */
	},

	.elevator_attrs = deadline_attrs,
	.elevator_name = "deadline",
	.elevator_owner = THIS_MODULE,
};
/**ltl
 *功能:初始化函数
 *参数:
 *返回值:
 *说明:
 */
static int __init deadline_init(void)
{
	elv_register(&iosched_deadline);

	return 0;
}
/**ltl
 *功能:反初始化函数
 *参数:
 *返回值:
 *说明:
 */
static void __exit deadline_exit(void)
{
	elv_unregister(&iosched_deadline);
}

module_init(deadline_init);
module_exit(deadline_exit);

MODULE_AUTHOR("Jens Axboe");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("deadline IO scheduler");

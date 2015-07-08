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
/* ������޵����㷨���ݶ��� */
struct deadline_data {
	/*
	 * run time data
	 */

	/*
	 * requests (deadline_rq s) are present on both sort_list and fifo_list
	 */
	struct rb_root sort_list[2]; /* READ/WRITE����ĺ����ͷ */	
	struct list_head fifo_list[2]; /* READ/WRITE�����FIFO����ͷ */

	/*
	 * next in sort order. read, write or both are NULL
	 */
	struct request *next_rq[2]; /* ��¼��һ����������ַ��ÿ������ӵ��ȶ���ת�Ƶ��ɷ�����ʱ�����¼���ֵ */
	unsigned int batching;		/* number of sequential requests made */
	sector_t last_sector;		/* head position */
	unsigned int starved;		/* times reads have starved writes */

	/*
	 * settings that change how the i/o scheduler behaves
	 */
	int fifo_expire[2]; /* READ/WRITE������������ */
	int fifo_batch;
	int writes_starved; /* д�������󼢶�ʱ�� */
	int front_merges;
};

static void deadline_move_request(struct deadline_data *, struct request *);
/* ������� */
static inline struct rb_root *
deadline_rb_root(struct deadline_data *dd, struct request *rq)
{
	return &dd->sort_list[rq_data_dir(rq)];
}

/*
 * get the request after `rq' in sector-sorted order
 */
/**ltl
 *����:��ȡrq����һ����
 *����:
 *����ֵ:
 *˵��:
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
 *����:��������뵽�������
 *����:
 *����ֵ:
 *˵��:
 */
static void
deadline_add_rq_rb(struct deadline_data *dd, struct request *rq)
{
	struct rb_root *root = deadline_rb_root(dd, rq);
	struct request *__alias;
	/* ��������뵽������У���������Ѿ������У���Ҫ�Ѵ������Ƶ��ɷ������� */
	while (unlikely(__alias = elv_rb_add(root, rq)))
		deadline_move_request(dd, __alias);
}
/**ltl
 *����:�Ӻ������ɾ������ 
 *����:
 *����ֵ:
 *˵��:
 */
static inline void
deadline_del_rq_rb(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);
	/* ������һ������� */
	if (dd->next_rq[data_dir] == rq)
		dd->next_rq[data_dir] = deadline_latter_request(rq); 
	/* �Ӻ������ɾ������ */
	elv_rb_del(deadline_rb_root(dd, rq), rq);
}

/*
 * add rq to rbtree and fifo
 */
/**ltl
 *����:��������뵽���ȶ�����
 *����:
 *����ֵ:
 *˵��:����������㷨������Ҫ���뵽����������:1.FIFO���У�2.�������
 */
static void
deadline_add_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	const int data_dir = rq_data_dir(rq);
	/* ��������뵽������� */
	deadline_add_rq_rb(dd, rq);

	/*
	 * set expire time and add to fifo list
	 */
	/* ���������������ʱ�� */
	rq_set_fifo_time(rq, jiffies + dd->fifo_expire[data_dir]);
	/* ��������뵽FIFO������ */
	list_add_tail(&rq->queuelist, &dd->fifo_list[data_dir]);
}

/*
 * remove rq from rbtree and fifo.
 */
/**ltl
 *����:������req��������޵ĵ��ȶ�����ɾ��
 *����:
 *����ֵ:
 *˵��:
 */
static void deadline_remove_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	rq_fifo_clear(rq);  /* ���Ƚ��ȳ�����(FIFO)��ɾ������ */
	deadline_del_rq_rb(dd, rq); /* �Ӻ������ɾ������ */
}

/**ltl
 *����:����������㷨�ĵ��ȶ����л�ȡ��bio�ϲ���request������ϲ�λ��
 *����:q	->�������
 *	  req->[out]������bio�ϲ��Ķ���
 *	  bio->Ҫ�ϲ���bio����
 *����ֵ:�ϲ�λ��
 *˵��:����ֻҪ������ǰ�ϲ�����Ϊ���ĺϲ�������Ѿ���elv_merge����ǰ����(�ڵ����㷨������Hash�������������ϲ������)
 *		��Ҳ��elevator_queue:hash�����á�
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
	if (dd->front_merges) { /* ������ǰ�ϲ� */
		sector_t sector = bio->bi_sector + bio_sectors(bio); /* bio�����һ������ */
		/* �ں�����в��� */
		__rq = elv_rb_find(&dd->sort_list[bio_data_dir(bio)], sector);
		if (__rq) {
			BUG_ON(sector != blk_rq_pos(__rq));

			if (elv_rq_merge_ok(__rq, bio)) { /* �ﵽ�ϲ��Ļ���Ҫ�� */
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
 *����:����req��������������㷨��ص�������Ϣ
 *����:
 *����ֵ:
 *˵��:
 */
static void deadline_merged_request(struct request_queue *q,
				    struct request *req, int type)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	/*
	 * if the merge was a front merge, we need to reposition request
	 */
	/* ΪʲôҪ��ɾ���ٲ�����? ��Ϊreq�Ѿ��ϲ��µ�bio����ʹreq�ں������λ�÷����ı� */
	if (type == ELEVATOR_FRONT_MERGE) {/* �������ǰ�ϲ� */
		elv_rb_del(deadline_rb_root(dd, req), req);/* �Ȱ�����Ӻ������ɾ�� */
		deadline_add_rq_rb(dd, req);	/* ���µ�������뵽������� */
	}
}
/**ltl
 *����:�ϲ����������������޵����㷨�йص����ݡ�
 *����:
 *����ֵ:
 *˵��: ��Ҫ���ͷű��ϲ��������������޵����㷨�йص��ڴ�ռ�
 */
static void
deadline_merged_requests(struct request_queue *q, struct request *req,
			 struct request *next)
{
	/*
	 * if next expires before rq, assign its expire time to rq
	 * and move into next position (next will be deleted) in fifo
	 */
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {/* ��������FIFO�����У�����ͬһ��FIFO������ */
		if (time_before(rq_fifo_time(next), rq_fifo_time(req))) { /* ���next���������ʱ���req�� */
			list_move(&req->queuelist, &next->queuelist); /* ��req�����Ƶ�next�����б��У�����req���뵽next֮�� */
			rq_set_fifo_time(req, rq_fifo_time(next)); /* ��next������������ʱ�����req���������ʱ�� */
		}
	}

	/*
	 * kill knowledge of next, this one is a goner
	 */
	deadline_remove_request(q, next);/* ������req��������޵ĵ��ȶ�����ɾ�� */
}

/*
 * move request from sort list to dispatch queue.
 */
/**ltl
 *����:������ӵ��ȶ����ƶ��ɷ�����
 *����:
 *����ֵ:
 *˵��:
 */
static inline void
deadline_move_to_dispatch(struct deadline_data *dd, struct request *rq)
{
	struct request_queue *q = rq->q;
	/* ������ӵ��ȶ������Ƴ���ע:�ͷ������˽����������������? */
	deadline_remove_request(q, rq);
	/* ������β�뵽�ɷ����� */
	elv_dispatch_add_tail(q, rq);
}

/*
 * move an entry to dispatch queue
 */
/**ltl
 *����:������ӵ��ȶ���ת�Ƶ��ɷ�������
 *����:dd	->������޵����ݶ���
 *	  rq	->�������
 *����ֵ:
 *˵��:
 */
static void
deadline_move_request(struct deadline_data *dd, struct request *rq)
{
	/* ����ķ��� */
	const int data_dir = rq_data_dir(rq);
	/* �Ƚ���һ��������ÿ� */
	dd->next_rq[READ] = NULL;
	dd->next_rq[WRITE] = NULL;
	/* ��¼��һ������� */
	dd->next_rq[data_dir] = deadline_latter_request(rq);
	/* ��¼���һ���� */
	dd->last_sector = rq_end_sector(rq);

	/*
	 * take it off the sort and fifo list, move
	 * to dispatch queue
	 */
	deadline_move_to_dispatch(dd, rq); /* �������Ƶ��ɷ����� */
}

/*
 * deadline_check_fifo returns 0 if there are no expired requests on the fifo,
 * 1 otherwise. Requires !list_empty(&dd->fifo_list[data_dir])
 */
/**ltl
 *����:��������Ƿ�ʱ��
 *����:
 *����ֵ:
 *˵��:
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
 *����:����������޵����㷨���ӵ��ȶ���ѡ��һ����ѵ����󣬲�ת�Ƶ��ɷ�������ȥ��
 *����:
 *����ֵ:
 *˵��:
 */
static int deadline_dispatch_requests(struct request_queue *q, int force)
{
	/* ������޵����ݶ��� */
	struct deadline_data *dd = q->elevator->elevator_data;
	const int reads = !list_empty(&dd->fifo_list[READ]); /* READ����FIFO�����Ƿ�ΪNULL */
	const int writes = !list_empty(&dd->fifo_list[WRITE]); /* WRITE����FIFO�����Ƿ�ΪNULL */
	struct request *rq;
	int data_dir;

	/*
	 * batches are currently reads XOR writes
	 */
	if (dd->next_rq[WRITE]) /* ��һд���� */ 
		rq = dd->next_rq[WRITE];
	else
		rq = dd->next_rq[READ]; /* ��һ������ */

	if (rq && dd->batching < dd->fifo_batch)
		/* we have a next request are still entitled to batch */
		goto dispatch_request;

	/*
	 * at this point we are not running a batch. select the appropriate
	 * data direction (read / write)
	 */
	/* FIFO�б����ж����� */
	if (reads) {
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[READ])); /* READ�������û�ж����� */
		/* FIFO�������ж����󣬲��Ҽ��������Ѿ�����д������ֵ */
		if (writes && (dd->starved++ >= dd->writes_starved))
			goto dispatch_writes;/* ִ��д���� */
		/* ִ�ж� */
		data_dir = READ;

		goto dispatch_find_request;
	}

	/*
	 * there are either no reads or writes have been starved
	 */
	/* дFIFO�б�����д���� */
	if (writes) {
dispatch_writes:
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[WRITE])); /* WRITE�������û��д���� */
		/* ��������Ҫ��0 */
		dd->starved = 0;
		/* ִ��д */
		data_dir = WRITE;

		goto dispatch_find_request;
	}

	return 0;

dispatch_find_request:
	/*
	 * we are not running a batch, find best request for selected data_dir
	 */
	/* �����Ƿ�ʱ��������һ�����Ƿ�ΪNULL */
	if (deadline_check_fifo(dd, data_dir) || !dd->next_rq[data_dir]) {
		/*
		 * A deadline has expired, the last request was in the other
		 * direction, or we have run out of higher-sectored requests.
		 * Start again from the request with the earliest expiry time.
		 */
		rq = rq_entry_fifo(dd->fifo_list[data_dir].next); /* ��FIFO�б���ȡ��һ���� */
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
	deadline_move_request(dd, rq); /* ������ӵ��ȶ����ƶ����ɷ����� */

	return 1;
}
/**ltl
 *����:�ж����ȶ����Ƿ�������
 *����:
 *����ֵ:
 *˵��:
 */
static int deadline_queue_empty(struct request_queue *q)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	return list_empty(&dd->fifo_list[WRITE])
		&& list_empty(&dd->fifo_list[READ]);
}
/**ltl 
 *����:������޵��˳��ӿڡ�
 *����:
 *����ֵ:
 *˵��:
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
 *����:������޵����㷨�ĳ�ʼ��
 *����:q	->������ж���
 *����ֵ:������޸߶��㷨�����ݶ���
 *˵��:
 */
static void *deadline_init_queue(struct request_queue *q)
{
	struct deadline_data *dd;
	/* �����ڴ�ռ� */
	dd = kmalloc_node(sizeof(*dd), GFP_KERNEL | __GFP_ZERO, q->node);
	if (!dd)
		return NULL;
	/* ��ʼ��READ FIFO����ͷ */
	INIT_LIST_HEAD(&dd->fifo_list[READ]);
	/* ��ʼ��WRITE FIFO����ͷ */
	INIT_LIST_HEAD(&dd->fifo_list[WRITE]);
	dd->sort_list[READ] = RB_ROOT; /* ��ʼ��READ�����ͷ */
	dd->sort_list[WRITE] = RB_ROOT; /* ��ʼ��WRITE�����ͷ */
	dd->fifo_expire[READ] = read_expire; /* READ������FIFO��������� */
	dd->fifo_expire[WRITE] = write_expire; /* WRITE������FIFO��������� */
	dd->writes_starved = writes_starved; /* д����ļ������ʱ�� */
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
/* ������޵����㷨���� */
static struct elevator_type iosched_deadline = {
	.ops = {
		.elevator_merge_fn = 		deadline_merge, 		/* ��ȡ������bio�ϲ���request���󼰺ϲ���λ�� */
		.elevator_merged_fn =		deadline_merged_request, /* ����һ�������˽������ */
		.elevator_merge_req_fn =	deadline_merged_requests, /* �ϲ��������˽������ */
		.elevator_dispatch_fn =		deadline_dispatch_requests, /* ������ӵ��ȶ��зַ����ɷ������� */
		.elevator_add_req_fn =		deadline_add_request,  /* ��������ӵ����ȶ����� */
		.elevator_queue_empty_fn =	deadline_queue_empty,  /* �ж����ȶ����Ƿ������� */
		.elevator_former_req_fn =	elv_rb_former_request, /* ��ȡ��request���ٵ���һ��request */
		.elevator_latter_req_fn =	elv_rb_latter_request, /* ��ȡ��request���ٵ���һ��request */
		.elevator_init_fn =		deadline_init_queue, /* ��ʼ������ */
		.elevator_exit_fn =		deadline_exit_queue, /* ����ʼ������ */
	},

	.elevator_attrs = deadline_attrs,
	.elevator_name = "deadline",
	.elevator_owner = THIS_MODULE,
};
/**ltl
 *����:��ʼ������
 *����:
 *����ֵ:
 *˵��:
 */
static int __init deadline_init(void)
{
	elv_register(&iosched_deadline);

	return 0;
}
/**ltl
 *����:����ʼ������
 *����:
 *����ֵ:
 *˵��:
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

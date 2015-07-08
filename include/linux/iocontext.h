#ifndef IOCONTEXT_H
#define IOCONTEXT_H

#include <linux/radix-tree.h>
#include <linux/rcupdate.h>

struct cfq_queue;

/**ltl
 * Q:io_context和cfq_io_context之前是什么关系呢?
 * A:cfq_io_context表示一个磁盘采用CFQ调度算法时的CFQ IO上下文，因为一个磁盘可以被多个进程访问，因此一个磁盘有多个cfq_io_context对象(与访问此磁盘的进程数一样)，
 *   这些cfq_io_context对象以queue_list为链接件组成一个链表，链表头为cfq_data:cic_list。
 *   io_context表示一个进程的IO上下文，因为一个进程可以访问到多个磁盘，因此一个进程对应着多个cfq_io_context对象，以cic_list为连接件组成一个链表，链表头为io_context:cic_list
 *   同时，io_context存在一棵基树，树根为radix_root，节点为cfq_data对象
 */
struct cfq_io_context {
	void *key;

	struct cfq_queue *cfqq[2]; /*0:异步cfq队列(BLK_RW_ASYNC)，1:同步cfq队列(BLK_RW_SYNC)*/

	struct io_context *ioc;

	unsigned long last_end_request;

	unsigned long ttime_total;
	unsigned long ttime_samples;
	unsigned long ttime_mean;

	struct list_head queue_list; /* 连接件，链表头为cfq_data:cic_list */
	struct hlist_node cic_list;  /* 连接件，链表头为io_context:cic_list */

	void (*dtor)(struct io_context *); /* destructor */
	void (*exit)(struct io_context *); /* called on task exit */

	struct rcu_head rcu_head;
};

/*
 * I/O subsystem state of the associated processes.  It is refcounted
 * and kmalloc'ed. These could be shared between processes.
 */
struct io_context {
	atomic_long_t refcount;
	atomic_t nr_tasks;

	/* all the fields below are protected by this lock */
	spinlock_t lock;

	unsigned short ioprio;
	unsigned short ioprio_changed;

#if defined(CONFIG_BLK_CGROUP) || defined(CONFIG_BLK_CGROUP_MODULE)
	unsigned short cgroup_changed;
#endif

	/*
	 * For request batching
	 */
	int nr_batch_requests;     /* Number of requests left in the batch */
	unsigned long last_waited; /* Time last woken after wait for request */
	/* 因为一个进程可以访问多个磁盘，每个磁盘用一个cfq IO上下文对象(cfq_io_context)，这些对象组成一棵基树，radix_root就是此树的树根。节点为cfq_io_context */
	struct radix_tree_root radix_root;
	struct hlist_head cic_list;  /* 此列表头，用来链接此进程所访问的cfq io上下文对象(cfq_io_context)。 */
	void *ioc_data;
};

static inline struct io_context *ioc_task_link(struct io_context *ioc)
{
	/*
	 * if ref count is zero, don't allow sharing (ioc is going away, it's
	 * a race).
	 */
	if (ioc && atomic_long_inc_not_zero(&ioc->refcount)) {
		atomic_inc(&ioc->nr_tasks);
		return ioc;
	}

	return NULL;
}

struct task_struct;
#ifdef CONFIG_BLOCK
int put_io_context(struct io_context *ioc);
void exit_io_context(struct task_struct *task);
struct io_context *get_io_context(gfp_t gfp_flags, int node);
struct io_context *alloc_io_context(gfp_t gfp_flags, int node);
void copy_io_context(struct io_context **pdst, struct io_context **psrc);
#else
static inline void exit_io_context(struct task_struct *task)
{
}

struct io_context;
static inline int put_io_context(struct io_context *ioc)
{
	return 1;
}
#endif

#endif

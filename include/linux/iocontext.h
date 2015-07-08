#ifndef IOCONTEXT_H
#define IOCONTEXT_H

#include <linux/radix-tree.h>
#include <linux/rcupdate.h>

struct cfq_queue;

/**ltl
 * Q:io_context��cfq_io_context֮ǰ��ʲô��ϵ��?
 * A:cfq_io_context��ʾһ�����̲���CFQ�����㷨ʱ��CFQ IO�����ģ���Ϊһ�����̿��Ա�������̷��ʣ����һ�������ж��cfq_io_context����(����ʴ˴��̵Ľ�����һ��)��
 *   ��Щcfq_io_context������queue_listΪ���Ӽ����һ����������ͷΪcfq_data:cic_list��
 *   io_context��ʾһ�����̵�IO�����ģ���Ϊһ�����̿��Է��ʵ�������̣����һ�����̶�Ӧ�Ŷ��cfq_io_context������cic_listΪ���Ӽ����һ����������ͷΪio_context:cic_list
 *   ͬʱ��io_context����һ�û���������Ϊradix_root���ڵ�Ϊcfq_data����
 */
struct cfq_io_context {
	void *key;

	struct cfq_queue *cfqq[2]; /*0:�첽cfq����(BLK_RW_ASYNC)��1:ͬ��cfq����(BLK_RW_SYNC)*/

	struct io_context *ioc;

	unsigned long last_end_request;

	unsigned long ttime_total;
	unsigned long ttime_samples;
	unsigned long ttime_mean;

	struct list_head queue_list; /* ���Ӽ�������ͷΪcfq_data:cic_list */
	struct hlist_node cic_list;  /* ���Ӽ�������ͷΪio_context:cic_list */

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
	/* ��Ϊһ�����̿��Է��ʶ�����̣�ÿ��������һ��cfq IO�����Ķ���(cfq_io_context)����Щ�������һ�û�����radix_root���Ǵ������������ڵ�Ϊcfq_io_context */
	struct radix_tree_root radix_root;
	struct hlist_head cic_list;  /* ���б�ͷ���������Ӵ˽��������ʵ�cfq io�����Ķ���(cfq_io_context)�� */
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

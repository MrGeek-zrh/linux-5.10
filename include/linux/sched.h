/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

/*
 * Define 'struct task_struct' and provide the main scheduler
 * APIs (schedule(), wakeup variants, etc.)
 */

#include <uapi/linux/sched.h>

#include <asm/current.h>

#include <linux/pid.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/kcov.h>
#include <linux/mutex.h>
#include <linux/plist.h>
#include <linux/hrtimer.h>
#include <linux/irqflags.h>
#include <linux/seccomp.h>
#include <linux/nodemask.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/resource.h>
#include <linux/latencytop.h>
#include <linux/sched/prio.h>
#include <linux/sched/types.h>
#include <linux/signal_types.h>
#include <linux/mm_types_task.h>
#include <linux/task_io_accounting.h>
#include <linux/posix-timers.h>
#include <linux/rseq.h>
#include <linux/seqlock.h>
#include <linux/kcsan.h>

/* task_struct member predeclarations (sorted alphabetically): */
struct audit_context;
struct backing_dev_info;
struct bio_list;
struct blk_plug;
struct capture_control;
struct cfs_rq;
struct fs_struct;
struct futex_pi_state;
struct io_context;
struct mempolicy;
struct nameidata;
struct nsproxy;
struct perf_event_context;
struct pid_namespace;
struct pipe_inode_info;
struct rcu_node;
struct reclaim_state;
struct robust_list_head;
struct root_domain;
struct rq;
struct sched_attr;
struct sched_param;
struct seq_file;
struct sighand_struct;
struct signal_struct;
struct task_delay_info;
struct task_group;
struct io_uring_task;

/*
 * Task state bitmask. NOTE! These bits are also
 * encoded in fs/proc/array.c: get_task_state().
 *
 * We have two separate sets of flags: task->state
 * is about runnability, while task->exit_state are
 * about the task exiting. Confusing, but this way
 * modifying one set can't modify the other one by
 * mistake.
 */

/**
 * Linux 进程主要状态切换
 *
 *                           +--------------+
 *           +-------------->| TASK_RUNNING |<-----------+-----------------------+
 *        (1)|               +--------------+            |                       |                Ready
 *           |               (2) ^    |(3)               |(4)                    |(5)
 * __________|___________________|____|__________________|_______________________|_______________
 *           |                   |    |                  |                       |
 *           |                   |    |                  |                       |
 * +--------------------+        |    |           +---------------+      +----------------------+
 * | TASK_INTERRUPTIBLE |        |    |           | TASK_KILLABLE |      | TASK_UNINTERRUPTIBLE |
 * +--------------------+        |    |           +---------------+      +----------------------+ Blocked
 *           ^                   |    |                  ^                       ^
 *           |                   |    |                  |                       |
 *           |                   |    |                  |                       |
 * __________|___________________|____|__________________|_______________________|______________
 *           |                   |    |                  |                       |
 *           |(6)                |    |/                 |                       |
 *           |               +--------------+            |(7)                    |
 *           +---------------| TASK_RUNNING |------------+-----------------------+               Running
 *                           +--------------+
 *                                  |
 * _________________________________|___________________________________________________________
 *                                  |
 *              +-------------------+-----------------+
 *              |(8)                                  |(9)
 *             \|                                    \|
 *       +-------------+                        +-----------+
 *       | TASK_ZOMBIE |----------------------->| TASK_DEAD |
 *       +-------------+          (10)          +-----------+
 *
 * 以上状态转移条件：
 * 1. 事件发生或收到信号
 * 2. 让出 CPU 或抢占
 * 3. 调度
 * 4. 事件发生或收到致命信号
 * 5. 事件发生，不能被信号唤醒
 * 6. 等待事件
 * 7. 等待事件
 * 8. 进程退出，并关注子进程退出事件
 * 9. 进程退出，不关注子进程退出事件
 * 10. 父进程查询子进程退出原因
 */



/* Used in tsk->state: */
/**
 *  正在运行或处于就绪状态
 *  就绪状态是指进程申请到了CPU以外的其他所有资源，正所谓：万事俱备，只欠东风;
 *  提醒：一般的操作系统教科书将正在CPU上执 行的进程定义为RUNNING状态、
 *      而将可执行但是尚未被调度执行的进程定义为READY状态，这两种状态在Linux下统一为 TASK_RUNNING状态.
 */
#define TASK_RUNNING			0x0000

/**
 *  处于等待队伍中，等待资源有效时唤醒（比如等待键盘输入、socket连接、信号等等），但可以被中断唤醒;
 *  一般情况下，进程列表中的绝大多数进程都处于 TASK_INTERRUPTIBLE状态.
 *  毕竟皇帝只有一个（单个CPU时），后宫佳丽几千；如果不是绝大多数进程都在睡眠，CPU又怎么响应得过来.
 *  TASK_INTERRUPTIBLE 是可以被信号和 wake_up() 唤醒的，当信号到来时，进程会被设置为可运行。
 */
#define TASK_INTERRUPTIBLE		0x0001

/**
 *  TASK_UNINTERRUPTIBLE状态是一种不可中断的睡眠状态，不可以被信号打断，必须等到等待的条件满足时才被唤醒。
 *  这个状态通常在进程必须等待时不受干扰或所等待的事件很快发生时使用。
 *
 *  处于等待队伍中，等待资源有效时唤醒（比如等待键盘输入、socket连接、信号等等），但不可以被中断唤醒.
 *  TASK_UNINTERRUPTIBLE只能被 wake_up() 唤醒.
 *
 *  在终端中输入命令：
 *  ```
 *  $ ps aux
 *  ```
 *  在出来的信息中有一列STAT状态，如果出现D状态就是TASK_UNINTERRUPTIBLE，出现这种状态时，
 *  你会发现你杀不死这种进程，但是linux内核已经想好了办法，对于这种情况，内核有专门的内核
 *  线程来过一段时间来处理一次这种状态的进程，所以当出现这种状态的进程时，我们只需等待一会
 *  就会由内核线程来处理掉这种进程。
 *
 *  hang_task 回收这些 D 进程?
 */
#define TASK_UNINTERRUPTIBLE		0x0002

/**
 *  进程被外部程序暂停（如收到SIGSTOP信号，进程会进入到TASK_STOPPED状态）
 *  当再次允许时继续执行（进程收到SIGCONT信号，进入TASK_RUNNING状态）
 *  因此处于这一状态的进程可以被唤醒.
 */
#define __TASK_STOPPED			0x0004

/**
 *
 *
 */
#define __TASK_TRACED			0x0008


/* Used in tsk->exit_state: */
#define EXIT_DEAD			0x0010
#define EXIT_ZOMBIE			0x0020
#define EXIT_TRACE			(EXIT_ZOMBIE | EXIT_DEAD)

/* Used in tsk->state again: */
#define TASK_PARKED			0x0040
#define TASK_DEAD			0x0080
#define TASK_WAKEKILL			0x0100
#define TASK_WAKING			0x0200
/**
 * 以往系统设计，使用 TASK_INTERRUPTIBLE 来使 kthreads 空闲并等待“工作”，
 * 因为 TASK_UNINTERRUPTIBLE 会导致负载增加。但让所有空闲的 kthread 都也
 * 接入负载计算，这显得不合理。
 *
 * 因为空闲时 kthreads 的所有信号都被屏蔽，大多数情况下这样的设计及工作机
 * 制是没有问题的。但是有一些站点会导致此问题，必须使用
 * TASK_UNINTERRUPTIBLE，除了 loadavg 负载计算。
 *
 * 所以在后面较新版本的内核中，新增了一补丁，提供了 TASK_NOLOAD ，与
 * TASK_UNINTERRUPTIBLE 结合使用时，避免了 loadavg 清算。在实际的使用场景中，
 * 大多数站点会存在 kthreads 想要闲置，等待工作的循环，因此也引入了TASK_IDLE.
 */
#define TASK_NOLOAD			0x0400
#define TASK_NEW			0x0800  /* linux-4.8添加 保证进程不会被运行 */
#define TASK_STATE_MAX			0x1000

/* Convenience macros for the sake of set_current_state: */
#define TASK_KILLABLE			(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED			(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED			(TASK_WAKEKILL | __TASK_TRACED)
/**
 * See TASK_NOLOAD
 */
#define TASK_IDLE			(TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

/* Convenience macros for the sake of wake_up(): */
#define TASK_NORMAL			(TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)

/* get_task_state(): */
#define TASK_REPORT			(TASK_RUNNING | TASK_INTERRUPTIBLE | \
					 TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
					 __TASK_TRACED | EXIT_DEAD | EXIT_ZOMBIE | \
					 TASK_PARKED)

#define task_is_traced(task)		((task->state & __TASK_TRACED) != 0)

#define task_is_stopped(task)		((task->state & __TASK_STOPPED) != 0)

#define task_is_stopped_or_traced(task)	((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)

#ifdef CONFIG_DEBUG_ATOMIC_SLEEP

/*
 * Special states are those that do not use the normal wait-loop pattern. See
 * the comment with set_special_state().
 */
//#define is_special_task_state(state)				\
//	((state) & (__TASK_STOPPED | __TASK_TRACED | TASK_PARKED | TASK_DEAD))
//
//#define __set_current_state(state_value)			\
//	do {							\
//		WARN_ON_ONCE(is_special_task_state(state_value));\
//		current->task_state_change = _THIS_IP_;		\
//		current->state = (state_value);			\
//	} while (0)
//
//#define set_current_state(state_value)				\
//	do {							\
//		WARN_ON_ONCE(is_special_task_state(state_value));\
//		current->task_state_change = _THIS_IP_;		\
//		smp_store_mb(current->state, (state_value));	\
//	} while (0)
//
//#define set_special_state(state_value)					\
//	do {								\
//		unsigned long flags; /* may shadow */			\
//		WARN_ON_ONCE(!is_special_task_state(state_value));	\
//		raw_spin_lock_irqsave(&current->pi_lock, flags);	\
//		current->task_state_change = _THIS_IP_;			\
//		current->state = (state_value);				\
//		raw_spin_unlock_irqrestore(&current->pi_lock, flags);	\
//	} while (0)
#else
/*
 * set_current_state() includes a barrier so that the write of current->state
 * is correctly serialised wrt the caller's subsequent test of whether to
 * actually sleep:
 *
 *   for (;;) {
 *	set_current_state(TASK_UNINTERRUPTIBLE);
 *	if (CONDITION)
 *	   break;
 *
 *	schedule();
 *   }
 *   __set_current_state(TASK_RUNNING);
 *
 * If the caller does not need such serialisation (because, for instance, the
 * CONDITION test and condition change and wakeup are under the same lock) then
 * use __set_current_state().
 *
 * The above is typically ordered against the wakeup, which does:
 *
 *   CONDITION = 1;
 *   wake_up_state(p, TASK_UNINTERRUPTIBLE);
 *
 * where wake_up_state()/try_to_wake_up() executes a full memory barrier before
 * accessing p->state.
 *
 * Wakeup will do: if (@state & p->state) p->state = TASK_RUNNING, that is,
 * once it observes the TASK_UNINTERRUPTIBLE store the waking CPU can issue a
 * TASK_RUNNING store which can collide with __set_current_state(TASK_RUNNING).
 *
 * However, with slightly different timing the wakeup TASK_RUNNING store can
 * also collide with the TASK_UNINTERRUPTIBLE store. Losing that store is not
 * a problem either because that will result in one extra go around the loop
 * and our @cond test will save the day.
 *
 * Also see the comments of try_to_wake_up().
 */
#define __set_current_state(state_value)				\
	current->state = (state_value)

#define set_current_state(state_value)					\
	smp_store_mb(current->state, (state_value))

/*
 * set_special_state() should be used for those states when the blocking task
 * can not use the regular condition based wait-loop. In that case we must
 * serialize against wakeups such that any possible in-flight TASK_RUNNING stores
 * will not collide with our state change.
 */
#define set_special_state(state_value)					\
	do {								\
		unsigned long flags; /* may shadow */			\
		raw_spin_lock_irqsave(&current->pi_lock, flags);	\
		current->state = (state_value);				\
		raw_spin_unlock_irqrestore(&current->pi_lock, flags);	\
	} while (0)

#endif

/* Task command name length: */
#define TASK_COMM_LEN			16

extern void scheduler_tick(void);

#define	MAX_SCHEDULE_TIMEOUT		LONG_MAX

extern long schedule_timeout(long timeout);
extern long schedule_timeout_interruptible(long timeout);
extern long schedule_timeout_killable(long timeout);
extern long schedule_timeout_uninterruptible(long timeout);
extern long schedule_timeout_idle(long timeout);
asmlinkage void schedule(void);
extern void schedule_preempt_disabled(void);
asmlinkage void preempt_schedule_irq(void);

extern int __must_check io_schedule_prepare(void);
extern void io_schedule_finish(int token);
extern long io_schedule_timeout(long timeout);
extern void io_schedule(void);

/**
 * struct prev_cputime - snapshot of system and user cputime
 * @utime: time spent in user mode
 * @stime: time spent in system mode
 * @lock: protects the above two fields
 *
 * Stores previous user/system time values such that we can guarantee
 * monotonicity.
 */
struct prev_cputime {
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
	u64				utime;
	u64				stime;
	raw_spinlock_t			lock;
#endif
};

enum vtime_state {
	/* Task is sleeping or running in a CPU with VTIME inactive: */
	VTIME_INACTIVE = 0,
	/* Task is idle */
	VTIME_IDLE,
	/* Task runs in kernelspace in a CPU with VTIME active: */
	VTIME_SYS,
	/* Task runs in userspace in a CPU with VTIME active: */
	VTIME_USER,
	/* Task runs as guests in a CPU with VTIME active: */
	VTIME_GUEST,
};

struct vtime {
	seqcount_t		seqcount;
	unsigned long long	starttime;
	enum vtime_state	state;
	unsigned int		cpu;
	u64			utime;
	u64			stime;
	u64			gtime;
};

/*
 * Utilization clamp constraints.
 * @UCLAMP_MIN:	Minimum utilization
 * @UCLAMP_MAX:	Maximum utilization
 * @UCLAMP_CNT:	Utilization clamp constraints count
 */
enum uclamp_id {
	UCLAMP_MIN = 0,
	UCLAMP_MAX,
	UCLAMP_CNT
};

#ifdef CONFIG_SMP
extern struct root_domain def_root_domain;
extern struct mutex sched_domains_mutex;
#endif

/**
 *  调度信息
 */
struct sched_info {
#ifdef CONFIG_SCHED_INFO
	/* Cumulative counters: */

	/* # of times we have run on this CPU: */
	unsigned long			pcount;

	/**
	 * Time spent waiting on a runqueue:
	 *
	 * task等待的时间，也就是没有执行的时间
	 * 例如：
	 *  1. Guest的qemu被切换走的时间
	 */
	unsigned long long		run_delay;

	/* Timestamps: */

	/* When did we last run on a CPU? */
	unsigned long long		last_arrival;

	/* When were we last queued to run? */
	unsigned long long		last_queued;

#endif /* CONFIG_SCHED_INFO */
};

/*
 * Integer metrics need fixed point arithmetic, e.g., sched/fair
 * has a few: load, load_avg, util_avg, freq, and capacity.
 *
 * We define a basic fixed point arithmetic range, and then formalize
 * all these metrics based on that basic range.
 */
# define SCHED_FIXEDPOINT_SHIFT		10
# define SCHED_FIXEDPOINT_SCALE		(1L << SCHED_FIXEDPOINT_SHIFT)

/* Increase resolution of cpu_capacity calculations */
# define SCHED_CAPACITY_SHIFT		SCHED_FIXEDPOINT_SHIFT

/**
 *  处理器的额定算力 默认值 1024
 */
# define SCHED_CAPACITY_SCALE		(1L << SCHED_CAPACITY_SHIFT)

//represent actual load weight of a scheduler entity and its invariant(不变量) value
//The higher priority allows to get more time to run.
//A `load weight` of a process is a relation between priority of this process and timeslices of this process.
/**
 *  记录调度实体的权重
 *
 * @weight      调度实体的权重
 * @inv_weight  inverse weight，它是权重的一个中间计算结果
 *              见`sched_prio_to_wmult[]`
 *
 * CFS调度策略就是青天大老爷，它来到linux内核，只做三件事：
 *
 *     公平！公平！还是公平！
 *
 * 其公平规则紧紧围绕权重展开，理解了权重的作用，也就掌握了该调度策略的核心。
 */
struct load_weight {    /* 负载权重 */
	unsigned long   weight;
	u32				inv_weight; //不变量 见`sched_prio_to_wmult[]`
};

/**
 * struct util_est - Estimation utilization of FAIR tasks
 * @enqueued: instantaneous estimated utilization of a task/cpu
 * @ewma:     the Exponential Weighted Moving Average (EWMA)
 *            utilization of a task
 *
 * Support data structure to track an Exponential Weighted Moving Average
 * (EWMA) of a FAIR task's utilization. New samples are added to the moving
 * average each time a task completes an activation. Sample's weight is chosen
 * so that the EWMA will be relatively insensitive to transient changes to the
 * task's workload.
 *
 * The enqueued attribute has a slightly different meaning for tasks and cpus:
 * - task:   the task's util_avg at last task dequeue time
 * - cfs_rq: the sum of util_est.enqueued for each RUNNABLE task on that CPU
 * Thus, the util_est.enqueued of a task represents the contribution on the
 * estimated utilization of the CPU where that task is currently enqueued.
 *
 * Only for tasks we track a moving average of the past instantaneous
 * estimated utilization. This allows to absorb sporadic drops in utilization
 * of an otherwise almost periodic task.
 */
struct util_est {   /* 评估利用率 */
	unsigned int			enqueued;   /* 任务/ CPU的瞬时估计利用率 */
	unsigned int			ewma;       /* 任务的指数加权移动平均（EWMA）利用率 */
#define UTIL_EST_WEIGHT_SHIFT		2
} __attribute__((__aligned__(sizeof(u64))));

/*
 * The load/runnable/util_avg accumulates an infinite geometric series
 * (see __update_load_avg_cfs_rq() in kernel/sched/pelt.c).
 *
 * [load_avg definition]
 *
 *   load_avg = runnable% * scale_load_down(load)
 *
 * [runnable_avg definition]
 *
 *   runnable_avg = runnable% * SCHED_CAPACITY_SCALE
 *
 * [util_avg definition]
 *
 *   util_avg = running% * SCHED_CAPACITY_SCALE
 *
 * where runnable% is the time ratio that a sched_entity is runnable and
 * running% the time ratio that a sched_entity is running.
 *
 * For cfs_rq, they are the aggregated values of all runnable and blocked
 * sched_entities.
 *
 * The load/runnable/util_avg doesn't directly factor frequency scaling and CPU
 * capacity scaling. The scaling is done through the rq_clock_pelt that is used
 * for computing those signals (see update_rq_clock_pelt())
 *
 * N.B., the above ratios (runnable% and running%) themselves are in the
 * range of [0, 1]. To do fixed point arithmetics, we therefore scale them
 * to as large a range as necessary. This is for example reflected by
 * util_avg's SCHED_CAPACITY_SCALE.
 *
 * [Overflow issue]
 *
 * The 64-bit load_sum can have 4353082796 (=2^64/47742/88761) entities
 * with the highest load (=88761), always runnable on a single cfs_rq,
 * and should not overflow as the number already hits PID_MAX_LIMIT.
 *
 * For all other cases (including 32-bit kernels), struct load_weight's
 * weight will overflow first before we do, because:
 *
 *    Max(load_avg) <= Max(load.weight)
 *
 * Then it is the load_weight's responsibility to consider overflow
 * issues.
 *
 * 抽象一个se或者cfs rq的平均负载信息
 */
struct sched_avg {

	/**
	 *  上一次 更新 时间点，用于计算时间间隔
	 *
	 *      d0   d1          d2           d3
	 *       ^   ^           ^            ^
	 *       |   |           |            |
	 *     |<->|<->|<----------------->|<--->|
	 * ... |---x---|------| ... |------|-----x (now)
	 *         ^
	 *        last_update_time
	 */
	u64				last_update_time;

	/**
	 *  可运行时间带来的负载贡献总和，包括等待调度时间和正在运行时间；
	 *
	 *  对于调度实体和调度队列来说，这个数值是有区别的
	 *  对于调度实体：它统计的仅仅是时间；
	 *  对于调度队列：它统计的是工作负载，即 时间 * 权重
	 */
	u64				load_sum;

	/**
	 *  对于调度实体：它是在就绪队列里可运行状态下的累计衰减总时间
	 *  对于调度队列：它统计就绪队列里所有可运行状态下进程的累计工作总负载
	 */
	u64				runnable_sum;

	/**
	 *  正在运行时间带来的负载贡献总和
	 *
	 *  调度实体：正在运行状态下的累计衰减总时间，使用 cfs_rq->curr == se 判断
	 *              当前进程是否正在运行
	 *  调度队列：整个就绪队列中所有处于运行状态进程的累计衰减总时间，
	 *              只要就绪队列里有正在运行的进程，他就会计算和累加
	 */
	u32				util_sum;

	/**
	 *  存放 上一次时间采样时，不能凑成一个 周期 1024us 的剩余时间 `d0`
	 *
	 *  假设一个调度实体被调度运行，运行时间段可以分成三个段 d1/d2/d3 ，这三个段是被
	 *  1024us 的计算周期分割而成，period_contrib 是调度实体 last_update_time
	 *  时在计算周期间的贡献值，也就是这里的 d0.
	 *
	 *  见 `accumulate_sum()` 中的 `d0`/`d0`
	 *
	 *      d0   d1          d2           d3
	 *       ^   ^           ^            ^
	 *       |   |           |            |
	 *     |<->|<->|<----------------->|<--->|
	 * ... |---x---|------| ... |------|-----x (now)
	 */
	u32				period_contrib;

	/**
	 *  可运行时间的平均负载贡献
	 *
	 *  对于调度实体来说：它是可运行状态下的量化负载。在负载均衡算法中，使用该成员来衡
	 *                  量一个进程的负载共享值，如衡量迁移进程的负载量
	 *  对于调度队列来说：它是调度队列中总的量化负载
	 */
	unsigned long			load_avg;       /* runnable% * scale_load_down(load) */

	/**
	 *  对于调度实体来说：它是可运行状态下的量化负载，等于 load_avg
	 *  对于调度队列来说：它统计就绪队列里所有可运行状态下进程的总量化负载，在 SMP 负
	 *                  载均衡算法中，该成员来比较CPU 的负载大小(用于衡量 CPU 是否繁忙)
	 */
	unsigned long			runnable_avg;   /* runnable% * SCHED_CAPACITY_SCALE */

	/**
	 *  正在运行时间的平均负载贡献
	 *
	 *  实际算力
	 *  通常用于体现一个调度实体或者 CPU 的实际算力需求，类似于 CPU 使用率的概念。
	 */
	unsigned long			util_avg;       /* running% * SCHED_CAPACITY_SCALE */
	struct util_est			util_est;   /* 评估利用率 */
} ____cacheline_aligned;


/**
 *
 */
struct sched_statistics {   /* 调度统计 */
#ifdef CONFIG_SCHEDSTATS
	u64				wait_start;
	u64				wait_max;
	u64				wait_count;
	u64				wait_sum;
	u64				iowait_count;
	u64				iowait_sum;

	u64				sleep_start;
	u64				sleep_max;
	s64				sum_sleep_runtime;

	u64				block_start;
	u64				block_max;
	u64				exec_max;
	u64				slice_max;

	u64				nr_migrations_cold;
	u64				nr_failed_migrations_affine;
	u64				nr_failed_migrations_running;
	u64				nr_failed_migrations_hot;
	u64				nr_forced_migrations;

	u64				nr_wakeups;
	u64				nr_wakeups_sync;
	u64				nr_wakeups_migrate;
	u64				nr_wakeups_local;
	u64				nr_wakeups_remote;
	u64				nr_wakeups_affine;
	u64				nr_wakeups_affine_attempts;
	u64				nr_wakeups_passive;
	u64				nr_wakeups_idle;
#endif
};

/**
 * 调度实体
 *
 *  采用CFS算法调度的普通非实时进程的调度实体
 *
 * 时间片（sched slice）：
 *   线程单次执行的时长。CFS调度策略存在调度周期，理想情况下，调度周期内运行
 *   队列的每个线程都将执行一次，当运行队列中只有一个线程时，将总是由该线程分
 *   得全部时间片。
 */
struct sched_entity {
	/**
	 *  For load-balancing:
	 *  记录调度实体的权重
	 */
	struct load_weight		load;

	/**
	 *  cfs_rq.tasks_timeline , 标识该调度实体在红黑树中的节点
	 */
	struct rb_node			run_node;

	/**
	 *  在就绪队列中有个链表， rq.cfs_tasks
	 *  调度实体添加到就绪队列后，会添加到该链表中
	 */
	struct list_head		group_node;

	/**
	 * 是否在运行队列中
	 *
	 *  进程进入就绪队列时(调用`enqueue_entity()`), on_rq 会被 设置为 1；
	 *  当该进程处于睡眠等原因退出就绪队列时(调用`dequeue_entity()`), on_rq 会被清 0
	 */
	unsigned int			on_rq;

	/**
	 *  计算 调度实体 虚拟时间 的起始时间
	 */
	u64				exec_start;
	/**
	 *  调度实体的总运行时间，这是真实时间
	 */
	u64				sum_exec_runtime;

	/**
	 *  调度实体的 虚拟运行时间
	 *
	 *  权重不同的2个进程的实际执行时间是不相等的，但是 CFS 想保证每个进程运行时间相等，
	 *  因此 CFS 引入了虚拟时间的概念。虚拟时间(vriture_runtime)和实际时间(wall_time)
	 *  转换公式如下：
	 *
	 *  vriturl_runtime = (wall_time * NICE0_TO_weight) / weight
	 *
	 *  NICE0_TO_weight 代表的是 nice 值等于0对应的权重，即1024，weight 是该任务对应的权重。
	 *  权重越大的进程获得的虚拟运行时间越小，那么它将被调度器所调度的机会就越大，
	 *  所以，CFS 每次调度原则是：总是选择 vriture_runtime 最小的任务来调度。
	 *
	 *  见 `calc_delta_fair()`
	 *
	 * 1. NICE = 0， vruntime 和真实时间过得一样快
	 *                         真实时间
	 *  -----------------###################--------------------------> 时间轴
	 *                         vruntime
	 *  -----------------*******************--------------------------> 时间轴
	 *
	 * 2. NICE < 0， 优先级高，vruntime 比真实时间过得一样慢
	 *                         真实时间
	 *  -----------------###################--------------------------> 时间轴
	 *                     vruntime
	 *  -----------------************---------------------------------> 时间轴
	 *
	 * 3. NICE > 0， 优先级低，vruntime 比真实时间过得一样快
	 *                         真实时间
	 *  -----------------###################--------------------------> 时间轴
	 *                     vruntime
	 *  -----------------**************************-------------------> 时间轴
	 */
	u64				vruntime;

	/**
	 *  上一次统计调度实体 运行的总时间
	 */
	u64				prev_sum_exec_runtime;

	/**
	 *  该调度实体发生迁移的次数，用于 负载均衡
	 */
	u64				nr_migrations;

	/**
	 *  调度统计
	 */
	struct sched_statistics		statistics;

	/**
	 *
	 */
#ifdef CONFIG_FAIR_GROUP_SCHED
	/**
	 * 任务组的深度，其中根任务组的深度为0，逐级往下增加
	 */
	int				depth;
	/**
	 * 指向调度实体的父对象
	 */
	struct sched_entity		*parent;
	/**
	 * rq on which this entity is (to be) queued:
	 * 指向调度实体归属的CFS队列，也就是需要入列的CFS队列
	 */
	struct cfs_rq			*cfs_rq;
	/**
	 * rq "owned" by this entity/group:
	 * 指向归属于当前调度实体的CFS队列，用于包含子任务或子的任务组
	 */
	struct cfs_rq			*my_q;
	/**
	 *  cached value of my_q->h_nr_running
	 *
	 *  标识 进程在可运行(runable)状态的权重，这个值等于进程的权重
	 */
	unsigned long			runnable_weight;
#endif

#ifdef CONFIG_SMP
	/**
	 * 与负载相关的信息，用于调度实体的负载计算（`PELT`）
	 *
	 * Per entity load average tracking.
	 * 每个实体的平均负载跟踪
	 *
	 * Put into separate cache line so it does not
	 * collide with read-mostly values above.
	 */
	struct sched_avg		avg;
#endif
};

/**
 *  采用Roound-Robin或者FIFO算法调度的实时调度实体。
 */
struct sched_rt_entity {

	/**
	 *  链表头 rt_rq.active.queue[MAX_RT_PRIO]
	 *  用于加入到优先级队列中
	 */
	struct list_head		run_list;

	/**
	 * 设置的时间超时
	 */
	unsigned long			timeout;
	/**
	 * 用于记录jiffies值
	 */
	unsigned long			watchdog_stamp;
	/**
	 * 时间片，100ms，
	 */
	unsigned int			time_slice;
	unsigned short			on_rq;
	unsigned short			on_list;

	/**
	 * 临时用于从上往下连接RT调度实体时使用
	 */
	struct sched_rt_entity		*back;

#ifdef CONFIG_RT_GROUP_SCHED
	/**
	 * 指向父RT调度实体
	 */
	struct sched_rt_entity		*parent;
	/**
	 * rq on which this entity is (to be) queued:
	 * RT调度实体所属的实时运行队列，被调度
	 */
	struct rt_rq			*rt_rq;
	/**
	 * rq "owned" by this entity/group:
	 * RT调度实体所拥有的实时运行队列，用于管理子任务或子组任务
	 */
	struct rt_rq			*my_q;
#endif
} __randomize_layout;

/**
 *  采用EDF算法调度的实时调度实体
 */
struct sched_dl_entity {

	/**
	 *  树根为 dl_rq.root
	 */
	struct rb_node			rb_node;

	/*
	 * Original scheduling parameters. Copied here from sched_attr
	 * during sched_setattr(), they will remain the same until
	 * the next sched_setattr().
	 */
	u64				dl_runtime;	/* Maximum runtime for each instance	*/
	u64				dl_deadline;	/* Relative deadline of each instance	*/
	u64				dl_period;	/* Separation of two instances (period) */
	u64				dl_bw;		/* dl_runtime / dl_period		*/
	u64				dl_density;	/* dl_runtime / dl_deadline		*/

	/*
	 * Actual scheduling parameters. Initialized with the values above,
	 * they are continuously updated during task execution. Note that
	 * the remaining runtime could be < 0 in case we are in overrun.
	 */
	s64				runtime;	/* Remaining runtime for this instance	*/
	u64				deadline;	/* Absolute deadline for this instance	*/
	unsigned int			flags;		/* Specifying the scheduler behaviour	*/

	/*
	 * Some bool flags:
	 *
	 * @dl_throttled tells if we exhausted the runtime. If so, the
	 * task has to wait for a replenishment to be performed at the
	 * next firing of dl_timer.
	 *
	 * @dl_boosted tells if we are boosted due to DI. If so we are
	 * outside bandwidth enforcement mechanism (but only until we
	 * exit the critical section);
	 *
	 * @dl_yielded tells if task gave up the CPU before consuming
	 * all its available runtime during the last job.
	 *
	 * @dl_non_contending tells if the task is inactive while still
	 * contributing to the active utilization. In other words, it
	 * indicates if the inactive timer has been armed and its handler
	 * has not been executed yet. This flag is useful to avoid race
	 * conditions between the inactive timer handler and the wakeup
	 * code.
	 *
	 * @dl_overrun tells if the task asked to be informed about runtime
	 * overruns.
	 */
	unsigned int			dl_throttled      : 1;
	unsigned int			dl_yielded        : 1;
	unsigned int			dl_non_contending : 1;
	unsigned int			dl_overrun	  : 1;

	/*
	 * Bandwidth enforcement timer. Each -deadline task has its
	 * own bandwidth to be enforced, thus we need one timer per task.
	 */
	struct hrtimer			dl_timer;

	/*
	 * Inactive timer, responsible for decreasing the active utilization
	 * at the "0-lag time". When a -deadline task blocks, it contributes
	 * to GRUB's active utilization until the "0-lag time", hence a
	 * timer is needed to decrease the active utilization at the correct
	 * time.
	 */
	struct hrtimer inactive_timer;

#ifdef CONFIG_RT_MUTEXES
	/*
	 * Priority Inheritance. When a DEADLINE scheduling entity is boosted
	 * pi_se points to the donor, otherwise points to the dl_se it belongs
	 * to (the original one/itself).
	 */
	struct sched_dl_entity *pi_se;
#endif
};

#ifdef CONFIG_UCLAMP_TASK
/* Number of utilization clamp buckets (shorter alias) */
#define UCLAMP_BUCKETS CONFIG_UCLAMP_BUCKETS_COUNT

/*
 * Utilization clamp for a scheduling entity    调度实体的利用率钳制
 * @value:		clamp value "assigned" to a se
 * @bucket_id:		bucket index corresponding to the "assigned" value
 * @active:		the se is currently refcounted in a rq's bucket
 * @user_defined:	the requested clamp value comes from user-space
 *
 * The bucket_id is the index of the clamp bucket matching the clamp value
 * which is pre-computed and stored to avoid expensive integer divisions from
 * the fast path.
 *
 * The active bit is set whenever a task has got an "effective" value assigned,
 * which can be different from the clamp value "requested" from user-space.
 * This allows to know a task is refcounted in the rq's bucket corresponding
 * to the "effective" bucket_id.
 *
 * The user_defined bit is set whenever a task has got a task-specific clamp
 * value requested from userspace, i.e. the system defaults apply to this task
 * just as a restriction. This allows to relax default clamps when a less
 * restrictive task-specific value has been requested, thus allowing to
 * implement a "nice" semantic. For example, a task running with a 20%
 * default boost can still drop its own boosting to 0%.
 */
struct uclamp_se {  /* 调度实体的利用率管制 */
	unsigned int value		: bits_per(SCHED_CAPACITY_SCALE);
	unsigned int bucket_id		: bits_per(UCLAMP_BUCKETS);
	unsigned int active		: 1;
	unsigned int user_defined	: 1;
};
#endif /* CONFIG_UCLAMP_TASK */

union rcu_special {
	struct {
		u8			blocked;
		u8			need_qs;
		u8			exp_hint; /* Hint for performance. */
		u8			need_mb; /* Readers need smp_mb(). */
	} b; /* Bits. */
	u32 s; /* Set of bits. */
};

enum perf_event_task_context {  /* perf_event task 上下文 */
	perf_invalid_context = -1,
	perf_hw_context = 0,    /* 硬件 */
	perf_sw_context,        /* 软件 */
	perf_nr_task_contexts,
};

struct wake_q_node {
	struct wake_q_node *next;
};
//+-----------------------+
//|        stack          |
//|_______________________|
//|          |            |
//|__________↓____________|             +--------------------+
//|                       |             |                    |
//|      thread_info      |<----------->|     task_struct    |
//+-----------------------+             +--------------------+
struct task_struct {    /* PCB */
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/*
	 * For reasons of header soup (see current_thread_info()), this
	 * must be the first element of task_struct.
	 */
	struct thread_info		thread_info;
#endif
	/* -1 unrunnable, 0 runnable, >0 stopped: */
	volatile long			state;

	/*
	 * This begins the randomizable portion of task_struct. Only
	 * scheduling-critical items should be added above here.
	 */
	randomized_struct_fields_start

	void				*stack; /* thread_union */
	refcount_t			usage;
	/* Per task flags (PF_*), defined further below: 例如: PF_IDLE */
	unsigned int			flags;
	/**
	 *
	 */
	unsigned int			ptrace;

#ifdef CONFIG_SMP
	/**
	 *  标识进程正处于运行状态
	 */
	int				on_cpu;
	/**
	 *
	 */
	struct __call_single_node	wake_entry;

#ifdef CONFIG_THREAD_INFO_IN_TASK
	/* Current CPU: */
	/**
	 *  正运行在哪个CPU上
	 *  __set_task_cpu()
	 */
	unsigned int			cpu;
#endif
	/**
	 *  flips: 翻转
	 *
	 *  用于 wake affine 特性 , 见 `record_wakee()`
	 */
	unsigned int			wakee_flips;
	/**
	 *  记录上一次 wakee_flips 的时间
	 */
	unsigned long			wakee_flip_decay_ts;
	/**
	 *  标识上一次唤醒哪个进程
	 */
	struct task_struct		*last_wakee;

	/*
	 * recent_used_cpu is initially set as the last CPU used by a task
	 * that wakes affine another task. Waker/wakee relationships can
	 * push tasks around a CPU where each wakeup moves to the next one.
	 * Tracking a recently used CPU allows a quick search for a recently
	 * used CPU that may be idle.
	 *
	 * 记录进程最长运行的 CPU，见 `select_idle_sibling()`
	 */
	int				recent_used_cpu;
	/**
	 *  表示进程上一次运行在哪个 CPU上
	 */
	int				wake_cpu;
#endif

	/**
	 *  是否在运行队列里，用于设置进程的状态，标识调度实体是否在就绪队列中接收调度。
	 *  支持的状态如下：
	 *
	 *  TASK_ON_RQ_QUEUED       进程正在就绪队列中运行
	 *  TASK_ON_RQ_MIGRATING    处于迁移过程中的进程，它可能不在就绪队列里
	 */
	int				on_rq;

	/**
	 *  MAX_PRIO:140
	 *  MAX_RT_PRIO:100
	 *  nice:[-20,19]
	 *
	 *  初始状态，这三个数值都相等，
	 *  见 `sched_fork()`=>> p->prio = p->normal_prio = __normal_prio(p);
	 *
	 *                  SCHED_FIFO                        SCHED_NORMAL
	 *                  SCHED_RR                          SCHED_BATCH
	 *                                                    SCHED_IDLE
	 *  +-------------------------------------------+---------------------+
	 *  |                  0 - 99                   |       100 - 139     |
	 *  |                                           |  nice(-20 ~ 19)     |
	 *  +-------------------------------------------+---------------------+
	 *                     实时进程                           普通进程
	 */
	/**
	 *  The higher priority allows to get more time to run.
	 *  `dynamic priority` which can't be changed during lifetime of
	 *  a process based on its static priority and interactivity(交互性) of the process.
	 *
	 *  prio: 动态优先级：是调度类考虑的优先级，有些时候需要临时提高进程优先级(如 实时互斥锁)
	 *
	 *  取值范围: [0, MAX_PRIO-1], 即[0, 139]
	 *  实时进程: [0, MAX_RT_PRIO-1], 即[0, 99]
	 *           计算方法: prio = MAX_RT_PRIO - 1 - rt_priority
	 *  普通进程: [MAX_RT_PRIO, MAX_PRIO], 即[100, 139]
	 *
	 */
	int				prio;
	/**
	 *  static_prio: 静态优先级
	 *  initial priority most likely well-known to you `nice value`
	 *  This value does not changed by the kernel if a user will not change it.
	 *
	 *  通过系统调用nice去修改static_prio, 见 `nice(2)->set_user_nice()`
	 *  调度程序通过或减少进程静态优先级来奖励IO消耗型进程或惩罚CPU消耗进程,
	 *  调整后的优先级为动态优先级(prio)
	 *
	 *  计算方法: 静态优先级与进程交互性函数计算出来的,随任务的实际运行情况调整
	 *  静态优先级与nice 关系: static_prio = MAX_RT_PRIO(100) + nice + 20
	 */
	int				static_prio;
	/**
	 *  normal_prio: 归一化优先级
	 *  based on the value of the `static_prio` too,
	 *  but also it depends on the scheduling policy of a process.
	 *
	 *  根据 static_prio 和 调度策略计算出来的优先级，在创建进程时，会继承父进程 的
	 *  normal_prio.
	 *  对普通进程来说， normal_prio == static_prio
	 *  对实时进程来说， 会根据 rt_priority 重新计算 normal_prio
	 */
	int				normal_prio;

	/**
	 *  rt_priority: 实时优先级: 实时优先级只对实时进程有效
	 *  实时进程的优先级与动态优先级成线性关系,不随时程运行而改变。也就是说,如果一个
	 *  进程是实时进程即在 [0，99] 之间优先级 prio 与 rt_priority 之间的关系是固定的
	 */
	unsigned int			rt_priority;

	/**
	 *  操作函数 - 调度类
	 *
	 *  rt_sched_class
	 *  fair_sched_class
	 */
	const struct sched_class	*sched_class;

	/**
	 *  调度实体
	 */
	struct sched_entity		se;
	/**
	 *  实时调度实体
	 */
	struct sched_rt_entity		rt;

#ifdef CONFIG_CGROUP_SCHED
	/**
	 *  组调度
	 */
	struct task_group		*sched_task_group;
#endif
	/**
	 *
	 */
	struct sched_dl_entity		dl;

#ifdef CONFIG_UCLAMP_TASK
	/*
	 * Clamp values requested for a scheduling entity.
	 * Must be updated with task_rq_lock() held.
	 */
	struct uclamp_se		uclamp_req[UCLAMP_CNT];
	/*
	 * Effective clamp values used for a scheduling entity.
	 * Must be updated with task_rq_lock() held.
	 */
	struct uclamp_se		uclamp[UCLAMP_CNT];
#endif

#ifdef CONFIG_PREEMPT_NOTIFIERS
	/* List of struct preempt_notifier: */
	struct hlist_head		preempt_notifiers;
#endif

#ifdef CONFIG_BLK_DEV_IO_TRACE
	unsigned int			btrace_seq;
#endif
	/**
	 * 调度策略
	 */
	unsigned int			policy;

	/**
	 *  CPU 亲和性
	 *  进程允许运行 CPU 的个数
	 */
	int				nr_cpus_allowed;
	const cpumask_t			*cpus_ptr;
	/**
	 *  允许运行的 CPU 位图 - sched_getaffinity()
	 */
	cpumask_t			cpus_mask;

#ifdef CONFIG_PREEMPT_RCU
	int				rcu_read_lock_nesting;
	union rcu_special		rcu_read_unlock_special;
	struct list_head		rcu_node_entry;
	struct rcu_node			*rcu_blocked_node;
#endif /* #ifdef CONFIG_PREEMPT_RCU */

#ifdef CONFIG_TASKS_RCU
	unsigned long			rcu_tasks_nvcsw;
	u8				rcu_tasks_holdout;
	u8				rcu_tasks_idx;
	int				rcu_tasks_idle_cpu;
	struct list_head		rcu_tasks_holdout_list;
#endif /* #ifdef CONFIG_TASKS_RCU */

#ifdef CONFIG_TASKS_TRACE_RCU
	int				trc_reader_nesting;
	int				trc_ipi_to_cpu;
	union rcu_special		trc_reader_special;
	bool				trc_reader_checked;
	struct list_head		trc_holdout_list;
#endif /* #ifdef CONFIG_TASKS_TRACE_RCU */

	/**
	 *  调度相关信息
	 */
	struct sched_info		sched_info;

	/**
	 *  任务链表
	 */
	struct list_head		tasks;

#ifdef CONFIG_SMP
	/* 优先级队列 */
	struct plist_node		pushable_tasks;
	/* deadline 任务 */
	struct rb_node			pushable_dl_tasks;
#endif

	/**
	 *  `mm` 指向进程地址空间
	 *  内核线程的 mm 为空，见 context_switch() 中的判断
	 */
	struct mm_struct		*mm;

	/**
	 *  `active_mm` 指向像 内核线程 这样不存在地址空间的有效地址空间
	 *  见 context_switch()
	 */
	struct mm_struct		*active_mm;

	/* Per-thread vma caching: */
	struct vmacache			vmacache;   /* vma 缓存 */

#ifdef SPLIT_RSS_COUNTING
	/**
	 *  对不同页面的统计计数
	 *  文件映射、匿名映射、交换
	 */
	struct task_rss_stat		rss_stat;
#endif
	/**
	 *
	 */
	int				exit_state;
	/**
	 *
	 */
	int				exit_code;

	/**
	 *  领头进程的判断标志，如`thread_group_leader()`
	 * The exit_signal the parent process will be sent when the child exits.
	 * parent 退出时，会将 exit_signal 发给 child
	 */
	int				exit_signal;
	/* The signal sent when the parent dies: */
	int				pdeath_signal;
	/* JOBCTL_*, siglock protected: */
	unsigned long			jobctl;

	/**
	 *  Used for emulating ABI behavior of previous Linux versions:
	 *  可能为 `ADDR_COMPAT_LAYOUT`
	 */
	unsigned int			personality;

	/* Scheduler bits, serialized by scheduler locks: */
	unsigned			sched_reset_on_fork:1;
	/**
	 * /proc/loadavg 计算会不会记录这个进程
	 */
	unsigned			sched_contributes_to_load:1;
	unsigned			sched_migrated:1;
	/**
	 * https://lkml.kernel.org/lkml/20201123121844.330555813@linuxfoundation.org/
	 *
	 * unsigned			sched_remote_wakeup:1;
	 *
	 * 移动到下面
	 */

#ifdef CONFIG_PSI   //PSI (Pressure Stall Information)评估系统资源压力
	unsigned			sched_psi_wake_requeue:1;
#endif

	/* Force alignment to the next boundary: */
	unsigned			:0;

	/* Unserialized, strictly 'current' */

	/*
	 * This field must not be in the scheduler word above due to wakelist
	 * queueing no longer being serialized by p->on_cpu. However:
	 *
	 * p->XXX = X;			ttwu()
	 * schedule()			  if (p->on_rq && ..) // false
	 *   smp_mb__after_spinlock();	  if (smp_load_acquire(&p->on_cpu) && //true
	 *   deactivate_task()		      ttwu_queue_wakelist())
	 *     p->on_rq = 0;			p->sched_remote_wakeup = Y;
	 *
	 * guarantees all stores of 'current' are visible before
	 * ->sched_remote_wakeup gets used, so it can be in this word.
	 *
	 * 是否发生迁移了，从一个 CPU 转到 另一个 CPU
	 *
	 * https://lkml.kernel.org/lkml/20201123121844.330555813@linuxfoundation.org/
	 */
	unsigned			sched_remote_wakeup:1;

	/* Bit to tell LSMs we're in execve(): */
	unsigned			in_execve:1;
	unsigned			in_iowait:1;

#ifndef TIF_RESTORE_SIGMASK
	unsigned			restore_sigmask:1;
#endif
#ifdef CONFIG_MEMCG
	unsigned			in_user_fault:1;
#endif
#ifdef CONFIG_COMPAT_BRK
	unsigned			brk_randomized:1;
#endif
#ifdef CONFIG_CGROUPS
	/* disallow userland-initiated cgroup migration */
	unsigned			no_cgroup_migration:1;
	/* task is frozen/stopped (used by the cgroup freezer) */
	unsigned			frozen:1;
#endif
#ifdef CONFIG_BLK_CGROUP
	unsigned			use_memdelay:1;
#endif
#ifdef CONFIG_PSI
	/* Stalled due to lack of memory */
	unsigned			in_memstall:1;
#endif

	unsigned long			atomic_flags; /* Flags requiring atomic access. */

	struct restart_block		restart_block;/* system call restart block */

	/**
	 * 实际上的 线程ID，top -Hp [tgid] 后显示的 pid
	 */
	pid_t				pid;

	/**
	 * 实际上的 进程ID， 线程组 ID， top -Hp [tgid]
	 */
	pid_t				tgid;

#ifdef CONFIG_STACKPROTECTOR
	/**
	 * Canary(金丝雀) value for the -fstack-protector GCC feature:
	 * 栈 金丝雀 保护
	 */
	unsigned long			stack_canary;
#endif

	/*
	 * Pointers to the (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with
	 * p->real_parent->pid)
	 */

	/* Real parent process: */
	struct task_struct __rcu	*real_parent;

	/* Recipient of SIGCHLD, wait4() reports: */
	struct task_struct __rcu	*parent;

	/*
	 * Children/sibling form the list of natural children:
	 */
	struct list_head		children;
	struct list_head		sibling;

	/* 线程组 领头 ,见`copy_process()` */
	struct task_struct		*group_leader;

	/*
	 * 'ptraced' is the list of tasks this task is using ptrace() on.
	 *
	 * This includes both natural children and PTRACE_ATTACH targets.
	 * 'ptrace_entry' is this task's link on the p->parent->ptraced list.
	 *
	 * task_struct->ptrace_entry 的链表头，见 `__ptrace_link()`
	 */
	struct list_head		ptraced;/* 使用了 ptrace() 的 task */
	/**
	 * task_struct->ptraced 链表的节点，见 `__ptrace_link()`
	 *
	 * 当然，也可能到另一个链表中，见 `reparent_leader()`
	 *
	 */
	struct list_head		ptrace_entry;/* 在 parent 中的 link */

	/**
	 * PID/PID hash table linkage.
	 * pid_namespace 也在这里
	 *
	 *  init_task.thread_pid = &init_struct_pid
	 */
	struct pid			*thread_pid;/* PID的哈希表 /include/linux/pid.h*/

	/**
	 *	链表头为 struct pid->tasks[PIDTYPE_MAX];
	 */
	struct hlist_node		pid_links[PIDTYPE_MAX];
	struct list_head		thread_group;/* 组 */
	struct list_head		thread_node;
	/**
	 *  vfork()
	 */
	struct completion		*vfork_done;/* 等待vfork系统调用结束 */

	/* CLONE_CHILD_SETTID: */
	int __user			*set_child_tid;

	/* CLONE_CHILD_CLEARTID: */
	int __user			*clear_child_tid;
	/**
	 *
	 */
	u64				utime;
	u64				stime;
#ifdef CONFIG_ARCH_HAS_SCALED_CPUTIME
	u64				utimescaled;
	u64				stimescaled;
#endif
	u64				gtime;
	struct prev_cputime		prev_cputime;
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	struct vtime			vtime;
#endif

#ifdef CONFIG_NO_HZ_FULL
	atomic_t			tick_dep_mask;
#endif
	/* Context switch counts: */
	unsigned long			nvcsw;
	unsigned long			nivcsw;

	/* Monotonic time in nsecs: */
	u64				start_time;

	/* Boot based time in nsecs: */
	u64				start_boottime;

	/* MM fault and swap info: this can arguably be seen as either mm-specific or thread-specific: */
	unsigned long			min_flt;
	unsigned long			maj_flt;

	/* Empty if CONFIG_POSIX_CPUTIMERS=n */
	struct posix_cputimers		posix_cputimers;/* 定时器 */

#ifdef CONFIG_POSIX_CPU_TIMERS_TASK_WORK
	struct posix_cputimers_work	posix_cputimers_work;   /* 任务工作 */
#endif

	/**
	 *  Process credentials:
	 */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;/* 任务凭证 */

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;/* 有效的可重载的 任务凭证， 用户 ID 等信息 */

#ifdef CONFIG_KEYS
	/* Cached requested key. */
	struct key			*cached_requested_key;
#endif

	/*
	 * executable name, excluding path.
	 *
	 * - normally initialized setup_new_exec()
	 * - access it with [gs]et_task_comm()
	 * - lock it with task_lock()
	 *
	 * 线程名
	 */
	char				comm[TASK_COMM_LEN];
	/**
	 *
	 */
	struct nameidata		*nameidata;

#ifdef CONFIG_SYSVIPC
	struct sysv_sem			sysvsem;    /* SysV 信号量 */
	struct sysv_shm			sysvshm;    /* SysV 共享内存 */
#endif

#ifdef CONFIG_DETECT_HUNG_TASK
	unsigned long			last_switch_count;
	unsigned long			last_switch_time;
#endif

	/* Filesystem information: */
	struct fs_struct		*fs;/* 文件系统 */

	/**
	 *  打开的文件
	 */
	/* Open file information: */
	struct files_struct		*files;/* 打开的文件 */

#ifdef CONFIG_IO_URING
	/**
	 *  io_uring_setup(2)
	 */
	struct io_uring_task		*io_uring;  /* AIO 异步IO */
#endif

	/**
	 *  Namespaces:
	 */
	struct nsproxy			*nsproxy;

	/* Signal handlers: */
	struct signal_struct		*signal;/* 进程信号 */
	struct sighand_struct __rcu		*sighand;

	/**
	 *
	 */
	sigset_t			blocked;
	sigset_t			real_blocked;
	/* Restored if set_restore_sigmask() was used: */
	sigset_t			saved_sigmask;

	/**
	 *  挂起的信号链表
	 */
	struct sigpending		pending;
	/**
	 *
	 */
	unsigned long			sas_ss_sp;
	size_t				sas_ss_size;
	unsigned int			sas_ss_flags;

	/**
	 *
	 */
	struct callback_head		*task_works;

#ifdef CONFIG_AUDIT
#ifdef CONFIG_AUDITSYSCALL
	struct audit_context		*audit_context;
#endif
	kuid_t				loginuid;
	unsigned int			sessionid;
#endif
	/**
	 *
	 */
	struct seccomp			seccomp;    /* 限制系统调用 */

	/* Thread group tracking: */
	u64				parent_exec_id;
	u64				self_exec_id;

	/* Protection against (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed, mempolicy: */
	spinlock_t			alloc_lock;

	/* Protection of the PI data structures: */
	raw_spinlock_t			pi_lock;

	/**
	 *  mutex 中 unlock 时会用到
	 */
	struct wake_q_node		wake_q;

#ifdef CONFIG_RT_MUTEXES
	/* PI waiters blocked on a rt_mutex held by this task: */
	struct rb_root_cached		pi_waiters;
	/* Updated under owner's pi_lock and rq lock */
	struct task_struct		*pi_top_task;
	/* Deadlock detection and priority inheritance handling: */
	struct rt_mutex_waiter		*pi_blocked_on;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	/* Mutex deadlock detection: */
	struct mutex_waiter		*blocked_on;
#endif

#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
	int				non_block_count;
#endif

#ifdef CONFIG_TRACE_IRQFLAGS
	struct irqtrace_events		irqtrace;
	unsigned int			hardirq_threaded;
	u64				hardirq_chain_key;
	int				softirqs_enabled;
	int				softirq_context;
	int				irq_config;
#endif

#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH			48UL
	u64				curr_chain_key;
	int				lockdep_depth;
	unsigned int			lockdep_recursion;
	struct held_lock		held_locks[MAX_LOCK_DEPTH];
#endif

#if defined(CONFIG_UBSAN) && !defined(CONFIG_UBSAN_TRAP)
	/**
	 * @brief Undefined Behavior Sanitizer，用于运行时未定义行为检测
	 *
	 */
	unsigned int			in_ubsan;
#endif

	/* Journalling filesystem info: */
	void				*journal_info;

	/* Stacked block device info: */
	struct bio_list			*bio_list;

#ifdef CONFIG_BLOCK
	/* Stack plugging: */
	struct blk_plug			*plug;
#endif

	/* VM state: */
	struct reclaim_state		*reclaim_state;

	struct backing_dev_info		*backing_dev_info;

	struct io_context		*io_context;

#ifdef CONFIG_COMPACTION    /* 紧致机制 */
	struct capture_control		*capture_control;
#endif
	/* Ptrace state: */
	unsigned long			ptrace_message;
	kernel_siginfo_t		*last_siginfo;

	/**
	 *  IO统计信息
	 */
	struct task_io_accounting	ioac;   /* IO 统计信息 */

#ifdef CONFIG_PSI
	/* Pressure stall state */
	unsigned int			psi_flags;
#endif
#ifdef CONFIG_TASK_XACCT
	/* Accumulated RSS usage: */
	u64				acct_rss_mem1;
	/* Accumulated virtual memory usage: */
	u64				acct_vm_mem1;
	/* stime + utime since last update: */
	u64				acct_timexpd;
#endif
#ifdef CONFIG_CPUSETS
	/* Protected by ->alloc_lock: */
	nodemask_t			mems_allowed;   /* 允许在哪个 NODE 上分配内存 */
	/* Seqence number to catch updates: */
	seqcount_spinlock_t		mems_allowed_seq;
	int				cpuset_mem_spread_rotor;
	int				cpuset_slab_spread_rotor;
#endif

#ifdef CONFIG_CGROUPS
	/**
	 *  Control Group info protected by css_set_lock:
	 *  通过 `cgroup_subsys_state` 结构体，一个进程可以找到其所属的 所有 `cgroup` 子系统
	 */
	struct css_set __rcu		*cgroups;

	/**
	 *  cg_list protected by css_set_lock and tsk->alloc_lock:
	 *
	 *  该链表的头为 struct css_set.mg_tasks
	 */
	struct list_head		cg_list;

#endif
#ifdef CONFIG_X86_CPU_RESCTRL
	u32				closid;
	u32				rmid;
#endif
#ifdef CONFIG_FUTEX
	struct robust_list_head __user	*robust_list;
#ifdef CONFIG_COMPAT
	struct compat_robust_list_head __user *compat_robust_list;
#endif
	struct list_head		pi_state_list;
	struct futex_pi_state		*pi_state_cache;
	struct mutex			futex_exit_mutex;
	unsigned int			futex_state;
#endif
#ifdef CONFIG_PERF_EVENTS
	/**
	 * perf events task维度上下文, 软件+硬件 perf_event
	 * 使用perf_event_context类型的链表来连接本task的相关perf_event。
	 * 这样的链表共有两条(perf_hw_context = 0, perf_sw_context = 1)
	 */
	struct perf_event_context	*perf_event_ctxp[perf_nr_task_contexts];
	/* 保护链表 `perf_event_list` */
	struct mutex			perf_event_mutex;

	/**
	 *  链表头，链表节点为 `perf_event.owner_entry`
	 *  该链表使用 `perf_event_mutex` 保护
	 *
	 * perf_event_open: perf_event->->owner_entry 链表头
	 */
	struct list_head		perf_event_list;
#endif
#ifdef CONFIG_DEBUG_PREEMPT
	unsigned long			preempt_disable_ip;
#endif
#ifdef CONFIG_NUMA
	/* Protected by alloc_lock: */
	struct mempolicy		*mempolicy; /* 内存策略 */
	short				il_prev;    /* 指向上一次使用的 node */
	short				pref_node_fork;
#endif
#ifdef CONFIG_NUMA_BALANCING
	int				numa_scan_seq;
	/**
	 * 扫描 周期
	 */
	unsigned int			numa_scan_period;
	unsigned int			numa_scan_period_max;
	int				numa_preferred_nid;
	unsigned long			numa_migrate_retry;
	/* Migration stamp: */
	u64				node_stamp;
	u64				last_task_numa_placement;
	u64				last_sum_exec_runtime;
	/**
	 * 函数调用：
	 * init_numa_balancing()->init_task_work() (回调: task_numa_work())
	 * task_tick_numa()->task_work_add()
	 */
	struct callback_head		numa_work;

	/*
	 * This pointer is only modified for current in syscall and
	 * pagefault context (and for tasks being destroyed), so it can be read
	 * from any of the following contexts:
	 *  - RCU read-side critical section
	 *  - current->numa_group from everywhere
	 *  - task's runqueue locked, task not running
	 */
	struct numa_group __rcu		*numa_group;

	/*
	 * numa_faults is an array split into four regions:
	 * faults_memory, faults_cpu, faults_memory_buffer, faults_cpu_buffer
	 * in this precise order.
	 *
	 * faults_memory: Exponential decaying average of faults on a per-node
	 * basis. Scheduling placement decisions are made based on these
	 * counts. The values remain static for the duration of a PTE scan.
	 * faults_cpu: Track the nodes the process was running on when a NUMA
	 * hinting fault was incurred.
	 * faults_memory_buffer and faults_cpu_buffer: Record faults per node
	 * during the current scan window. When the scan completes, the counts
	 * in faults_memory and faults_cpu decay and these values are copied.
	 *
	 * 在 task_numa_fault() 分配内存
	 */
	unsigned long			*numa_faults;
	unsigned long			total_numa_faults;

	/*
	 * numa_faults_locality tracks if faults recorded during the last
	 * scan window were remote/local or failed to migrate. The task scan
	 * period is adapted based on the locality of the faults with different
	 * weights depending on whether they were shared or private faults
	 */
	unsigned long			numa_faults_locality[3];

	unsigned long			numa_pages_migrated;
#endif /* CONFIG_NUMA_BALANCING */

#ifdef CONFIG_RSEQ
	struct rseq __user *rseq;
	u32 rseq_sig;
	/*
	 * RmW on rseq_event_mask must be performed atomically
	 * with respect to preemption.
	 */
	unsigned long rseq_event_mask;
#endif

	struct tlbflush_unmap_batch	tlb_ubc;

	union {
		refcount_t		rcu_users;
		struct rcu_head		rcu;
	};

	/* Cache last used pipe for splice(): */
	struct pipe_inode_info		*splice_pipe;

	struct page_frag		task_frag;

#ifdef CONFIG_TASK_DELAY_ACCT
	struct task_delay_info		*delays;
#endif

#ifdef CONFIG_FAULT_INJECTION
	int				make_it_fail;
	unsigned int			fail_nth;
#endif
	/*
	 * When (nr_dirtied >= nr_dirtied_pause), it's time to call
	 * balance_dirty_pages() for a dirty throttling pause:
	 *
	 * 当 nr_dirtied >= nr_dirtied_pause 那么就可以调用 balance_dirty_pages() 了
	 *
	 * balance_dirty_pages_ratelimited()
	 */
	int				nr_dirtied;
	int				nr_dirtied_pause;

	/* Start of a write-and-pause period: */
	unsigned long			dirty_paused_when;

#ifdef CONFIG_LATENCYTOP
	int				latency_record_count;
	struct latency_record		latency_record[LT_SAVECOUNT];
#endif
	/*
	 * Time slack values; these are used to round up poll() and
	 * select() etc timeout values. These are in nanoseconds.
	 */
	u64				timer_slack_ns;/* 用于 poll 和   select */
	u64				default_timer_slack_ns;

#ifdef CONFIG_KASAN /* Kernel Address Sanitizer,动态检测内存错误 */
	unsigned int			kasan_depth;
#endif

#ifdef CONFIG_KCSAN /* Kernel Concurrency Sanitizer,并发性检测 */
	struct kcsan_ctx		kcsan_ctx;
#ifdef CONFIG_TRACE_IRQFLAGS
	struct irqtrace_events		kcsan_save_irqtrace;
#endif
#endif

#if IS_ENABLED(CONFIG_KUNIT/* 测试 运行实例 */)
	struct kunit			*kunit_test;
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/* Index of current stored address in ret_stack: */
	int				curr_ret_stack;
	int				curr_ret_depth;

	/**
	 *  Stack of return addresses for return function tracing:
	 *
	 */
	struct ftrace_ret_stack		*ret_stack; /* 在 alloc_retstack_tasklist() 中使用*/

	/* Timestamp for last schedule: */
	unsigned long long		ftrace_timestamp;

	/*
	 * Number of functions that haven't been traced
	 * because of depth overrun:
	 */
	atomic_t			trace_overrun;

	/* Pause tracing: */
	atomic_t			tracing_graph_pause;
#endif

#ifdef CONFIG_TRACING
	/* State flags for use by tracers: */
	unsigned long			trace;

	/* Bitmask and counter of trace recursion: */
	unsigned long			trace_recursion;
#endif /* CONFIG_TRACING */

#ifdef CONFIG_KCOV  /* 代码覆盖测试 */
	/* See kernel/kcov.c for more details. */

	/* Coverage collection mode enabled for this task (0 if disabled): */
	unsigned int			kcov_mode;

	/* Size of the kcov_area: */
	unsigned int			kcov_size;

	/* Buffer for coverage collection: */
	void				*kcov_area;

	/* KCOV descriptor wired with this task or NULL: */
	struct kcov			*kcov;

	/* KCOV common handle for remote coverage collection: */
	u64				kcov_handle;

	/* KCOV sequence number: */
	int				kcov_sequence;  /* 顺序号 */

	/* Collect coverage from softirq context: */
	unsigned int			kcov_softirq;
#endif

#ifdef CONFIG_MEMCG
	struct mem_cgroup		*memcg_in_oom;
	gfp_t				memcg_oom_gfp_mask;
	int				memcg_oom_order;

	/* Number of pages to reclaim on returning to userland: */
	unsigned int			memcg_nr_pages_over_high;

	/* Used by memcontrol for targeted memcg charge: */
	struct mem_cgroup		*active_memcg;
#endif

#ifdef CONFIG_BLK_CGROUP
	struct request_queue		*throttle_queue;
#endif

#ifdef CONFIG_UPROBES
	struct uprobe_task		*utask;
#endif
#if defined(CONFIG_BCACHE) || defined(CONFIG_BCACHE_MODULE)
	unsigned int			sequential_io;
	unsigned int			sequential_io_avg;
#endif
#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
	unsigned long			task_state_change;
#endif

	/**
	 *  当前进程是否能触发 page-fault，使用这个变量
	 *  接口函数为
	 *  pagefault_disable()
	 *      -> pagefault_disabled_inc()
	 *  pagefault_enable()
	 *      -> pagefault_disabled_dec()
	 */
	int				pagefault_disabled; //

#ifdef CONFIG_MMU
	struct task_struct		*oom_reaper_list;
#endif
#ifdef CONFIG_VMAP_STACK
	struct vm_struct		*stack_vm_area;
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/* A live task holds one reference: */
	refcount_t			stack_refcount;
#endif
#ifdef CONFIG_LIVEPATCH
	int patch_state;
#endif
#ifdef CONFIG_SECURITY
	/* Used by LSM modules for access restriction: */
	void				*security;
#endif

#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
	unsigned long			lowest_stack;
	unsigned long			prev_lowest_stack;
#endif

#ifdef CONFIG_X86_MCE   /* Machine Check Exception */
	void __user			*mce_vaddr;
	__u64				mce_kflags;
	u64				mce_addr;
	__u64				mce_ripv : 1,
					mce_whole_page : 1,
					__mce_reserved : 62;
	struct callback_head		mce_kill_me;
#endif

#ifdef CONFIG_RETHOOK
	struct llist_head               rethooks;
#endif

	/*
	 * New fields for task_struct should be added above here, so that
	 * they are included in the randomized portion of task_struct.
	 */
	randomized_struct_fields_end

	/**
	 *  硬件上下文
	 */
	/* CPU-specific state of this task: */
	struct thread_struct		thread;/* 硬件上下文: 任务的 CPU 状态， 寄存器等信息 */

	/*
	 * WARNING: on x86, 'thread_struct' contains a variable-sized
	 * structure.  It *MUST* be at the end of 'task_struct'.
	 *
	 * Do not put anything below here!
	 */
};
typedef struct task_struct * p_task_struct;

/**
 *  保存所有 进程 pid 的哈希表
 */
static inline struct pid *task_pid(struct task_struct *task)
{
	return task->thread_pid;
}

/*
 * the helpers to get the task's different pids as they are seen
 * from various namespaces
 *
 * task_xid_nr()     : global id, i.e. the id seen from the init namespace;
 * task_xid_vnr()    : virtual id, i.e. the id seen from the pid namespace of
 *                     current.
 * task_xid_nr_ns()  : id seen from the ns specified;
 *
 * see also pid_nr() etc in include/linux/pid.h
 */
pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type, struct pid_namespace *ns);

static inline pid_t task_pid_nr(struct task_struct *tsk)
{
	return tsk->pid;
}

static inline pid_t task_pid_nr_ns(struct task_struct *tsk, struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PID, ns);
}

static inline pid_t task_pid_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PID, NULL);
}


static inline pid_t task_tgid_nr(struct task_struct *tsk)
{
	return tsk->tgid;
}

/**
 * pid_alive - check that a task structure is not stale
 * @p: Task structure to be checked.
 *
 * Test if a process is not yet dead (at most zombie state)
 * If pid_alive fails, then pointers within the task structure
 * can be stale and must not be dereferenced.
 *
 * Return: 1 if the process is alive. 0 otherwise.
 */
static inline int pid_alive(const struct task_struct *p)
{
	return p->thread_pid != NULL;
}

/**
 * @brief
 *
 * @param tsk
 * @param ns
 * @return pid_t
 */
static inline pid_t task_pgrp_nr_ns(struct task_struct *tsk, struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PGID, ns);
}

static inline pid_t task_pgrp_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PGID, NULL);
}


static inline pid_t task_session_nr_ns(struct task_struct *tsk, struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_SID, ns);
}

static inline pid_t task_session_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_SID, NULL);
}

static inline pid_t task_tgid_nr_ns(struct task_struct *tsk, struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_TGID, ns);
}

static inline pid_t task_tgid_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_TGID, NULL);
}

static inline pid_t task_ppid_nr_ns(const struct task_struct *tsk, struct pid_namespace *ns)
{
	pid_t pid = 0;

	rcu_read_lock();
	if (pid_alive(tsk))
		pid = task_tgid_nr_ns(rcu_dereference(tsk->real_parent), ns);
	rcu_read_unlock();

	return pid;
}

static inline pid_t task_ppid_nr(const struct task_struct *tsk)
{
	return task_ppid_nr_ns(tsk, &init_pid_ns);
}

/* Obsolete, do not use: */
static inline pid_t task_pgrp_nr(struct task_struct *tsk)
{
	return task_pgrp_nr_ns(tsk, &init_pid_ns);
}

#define TASK_REPORT_IDLE	(TASK_REPORT + 1)
#define TASK_REPORT_MAX		(TASK_REPORT_IDLE << 1)

static inline unsigned int task_state_index(struct task_struct *tsk)
{
	unsigned int tsk_state = READ_ONCE(tsk->state);
	unsigned int state = (tsk_state | tsk->exit_state) & TASK_REPORT;

	BUILD_BUG_ON_NOT_POWER_OF_2(TASK_REPORT_MAX);

	/**
	 *
	 */
	if (tsk_state == TASK_IDLE)
		state = TASK_REPORT_IDLE;

	return fls(state);
}

static inline char task_index_to_char(unsigned int state)
{
	static const char state_char[] = "RSDTtXZPI";

	BUILD_BUG_ON(1 + ilog2(TASK_REPORT_MAX) != sizeof(state_char) - 1);

	return state_char[state];
}

static inline char task_state_to_char(struct task_struct *tsk)
{
	return task_index_to_char(task_state_index(tsk));
}

/**
 * is_global_init - check if a task structure is init. Since init
 * is free to have sub-threads we need to check tgid.
 * @tsk: Task structure to be checked.
 *
 * Check if a task structure is the first user space task the kernel created.
 *
 * Return: 1 if the task structure is init. 0 otherwise.
 */
static inline int is_global_init(struct task_struct *tsk)
{
	return task_tgid_nr(tsk) == 1;
}

extern struct pid *cad_pid;

/*
 * Per process flags
 */
#define PF_VCPU			0x00000001	/* 虚拟CPU标志,表示该进程是一个虚拟CPU */
#define PF_IDLE			0x00000002	/* 空闲线程标志,Linux-4.10引入,用于解决空闲注入驱动问题 */
#define PF_EXITING		0x00000004	/* 进程正在退出标志 */
#define PF_IO_WORKER		0x00000010	/* IO工作线程标志,表示该进程是一个IO工作线程 */
#define PF_WQ_WORKER		0x00000020	/* 工作队列线程标志,表示该进程是工作队列创建的线程 */
#define PF_FORKNOEXEC		0x00000040	/* fork后尚未exec的进程标志,此时进程暂时不能运行 */
#define PF_MCE_PROCESS		0x00000080      /* MCE错误处理进程标志,用于机器检查错误策略 */
#define PF_SUPERPRIV		0x00000100	/* 超级用户权限标志,表示进程使用过超级用户权限 */
#define PF_DUMPCORE		0x00000200	/* core dump标志,表示进程已经生成了core dump */
#define PF_SIGNALED		0x00000400	/* 信号终止标志,表示进程被信号杀死 */
#define PF_MEMALLOC		0x00000800	/* 内存分配标志,允许进程使用系统预留内存,忽略内存域水位 */
#define PF_NPROC_EXCEEDED	0x00001000	/* 进程数超限标志,表示已超出RLIMIT_NPROC限制 */
#define PF_USED_MATH		0x00002000	/* FPU使用标志,若未设置则在使用前必须初始化FPU */
#define PF_USED_ASYNC		0x00004000	/* 异步调度标志,用于模块初始化时的异步调度 */
#define PF_NOFREEZE		0x00008000	/* 禁止冻结标志,标记该线程不应被冻结 */
#define PF_FROZEN		0x00010000	/* 已冻结标志,表示进程已被系统挂起冻结 */
#define PF_KSWAPD		0x00020000	/* kswapd标志,表示这是内存回收的kswapd内核线程 */
#define PF_MEMALLOC_NOFS	0x00040000	/* 无文件系统分配标志,所有内存分配请求将继承GFP_NOFS标志 */
#define PF_MEMALLOC_NOIO	0x00080000	/* 无IO分配标志,所有内存分配请求将继承GFP_NOIO标志 */ 
#define PF_LOCAL_THROTTLE	0x00100000	/* 本地写限流标志,仅对当前正在写入的块设备进行限流,
                                                   * 表示正在清理其他块设备的脏页 */
#define PF_KTHREAD		0x00200000	/* 内核线程标志,表示这是一个内核线程 */
#define PF_RANDOMIZE		0x00400000	/* 地址空间随机化标志,启用虚拟地址空间随机化 */
#define PF_SWAPWRITE		0x00800000	/* 交换分区写入标志,允许进程写入交换分区 */
#define PF_NO_SETAFFINITY	0x04000000	/* CPU亲和性保护标志,禁止用户空间修改进程的CPU亲和性掩码 */
#define PF_MCE_EARLY		0x08000000      /* MCE提前终止标志,用于MCE进程的提前终止策略 */
#define PF_MEMALLOC_NOCMA	0x10000000	/* 禁用CMA分配标志,所有内存分配请求将清除_GFP_MOVABLE标志 */  
#define PF_FREEZER_SKIP		0x40000000	/* 跳过冻结标志,冻结器不应将该进程计入可冻结对象 */
#define PF_SUSPEND_TASK		0x80000000      /* 挂起任务标志,表示该线程调用了freeze_processes()因此不应被冻结 */

/*
 * Only the _current_ task can read/write to tsk->flags, but other
 * tasks can access tsk->flags in readonly mode for example
 * with tsk_used_math (like during threaded core dumping).
 * There is however an exception to this rule during ptrace
 * or during fork: the ptracer task is allowed to write to the
 * child->flags of its traced child (same goes for fork, the parent
 * can write to the child->flags), because we're guaranteed the
 * child is not running and in turn not changing child->flags
 * at the same time the parent does it.
 */
#define clear_stopped_child_used_math(child)	do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define set_stopped_child_used_math(child)	do { (child)->flags |= PF_USED_MATH; } while (0)
#define clear_used_math()			clear_stopped_child_used_math(current)
#define set_used_math()				set_stopped_child_used_math(current)

#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)

#define conditional_used_math(condition)	conditional_stopped_child_used_math(condition, current)

#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)

/* NOTE: this will return 0 or PF_USED_MATH, it will never return 1 */
#define tsk_used_math(p)			((p)->flags & PF_USED_MATH)
#define used_math()				tsk_used_math(current)

static inline bool is_percpu_thread(void)
{
#ifdef CONFIG_SMP
	return (current->flags & PF_NO_SETAFFINITY) &&
		(current->nr_cpus_allowed  == 1);
#else
	return true;
#endif
}

/* Per-process atomic flags. */
#define PFA_NO_NEW_PRIVS		0	/* May not gain new privileges. */
#define PFA_SPREAD_PAGE			1	/* Spread page cache over cpuset */
#define PFA_SPREAD_SLAB			2	/* Spread some slab caches over cpuset */
#define PFA_SPEC_SSB_DISABLE		3	/* Speculative Store Bypass disabled */
#define PFA_SPEC_SSB_FORCE_DISABLE	4	/* Speculative Store Bypass force disabled*/
#define PFA_SPEC_IB_DISABLE		5	/* Indirect branch speculation restricted */
#define PFA_SPEC_IB_FORCE_DISABLE	6	/* Indirect branch speculation permanently restricted */
#define PFA_SPEC_SSB_NOEXEC		7	/* Speculative Store Bypass clear on execve() */

#define TASK_PFA_TEST(name, func)					\
	static inline bool task_##func(struct task_struct *p)		\
	{ return test_bit(PFA_##name, &p->atomic_flags); }

#define TASK_PFA_SET(name, func)					\
	static inline void task_set_##func(struct task_struct *p)	\
	{ set_bit(PFA_##name, &p->atomic_flags); }

#define TASK_PFA_CLEAR(name, func)					\
	static inline void task_clear_##func(struct task_struct *p)	\
	{ clear_bit(PFA_##name, &p->atomic_flags); }

TASK_PFA_TEST(NO_NEW_PRIVS, no_new_privs)
TASK_PFA_SET(NO_NEW_PRIVS, no_new_privs)

TASK_PFA_TEST(SPREAD_PAGE, spread_page)
TASK_PFA_SET(SPREAD_PAGE, spread_page)
TASK_PFA_CLEAR(SPREAD_PAGE, spread_page)

TASK_PFA_TEST(SPREAD_SLAB, spread_slab)
TASK_PFA_SET(SPREAD_SLAB, spread_slab)
TASK_PFA_CLEAR(SPREAD_SLAB, spread_slab)

TASK_PFA_TEST(SPEC_SSB_DISABLE, spec_ssb_disable)
TASK_PFA_SET(SPEC_SSB_DISABLE, spec_ssb_disable)
TASK_PFA_CLEAR(SPEC_SSB_DISABLE, spec_ssb_disable)

TASK_PFA_TEST(SPEC_SSB_NOEXEC, spec_ssb_noexec)
TASK_PFA_SET(SPEC_SSB_NOEXEC, spec_ssb_noexec)
TASK_PFA_CLEAR(SPEC_SSB_NOEXEC, spec_ssb_noexec)

TASK_PFA_TEST(SPEC_SSB_FORCE_DISABLE, spec_ssb_force_disable)
TASK_PFA_SET(SPEC_SSB_FORCE_DISABLE, spec_ssb_force_disable)

TASK_PFA_TEST(SPEC_IB_DISABLE, spec_ib_disable)
TASK_PFA_SET(SPEC_IB_DISABLE, spec_ib_disable)
TASK_PFA_CLEAR(SPEC_IB_DISABLE, spec_ib_disable)

TASK_PFA_TEST(SPEC_IB_FORCE_DISABLE, spec_ib_force_disable)
TASK_PFA_SET(SPEC_IB_FORCE_DISABLE, spec_ib_force_disable)
	{} /* ++++ */
static inline void
current_restore_flags(unsigned long orig_flags, unsigned long flags)
{
	current->flags &= ~flags;
	current->flags |= orig_flags & flags;
}

extern int cpuset_cpumask_can_shrink(const struct cpumask *cur, const struct cpumask *trial);
extern int task_can_attach(struct task_struct *p, const struct cpumask *cs_cpus_allowed);
#ifdef CONFIG_SMP
extern void do_set_cpus_allowed(struct task_struct *p, const struct cpumask *new_mask);
extern int set_cpus_allowed_ptr(struct task_struct *p, const struct cpumask *new_mask);
#else

#endif

extern int yield_to(struct task_struct *p, bool preempt);
extern void set_user_nice(struct task_struct *p, long nice);
extern int task_prio(const struct task_struct *p);

/**
 * task_nice - return the nice value of a given task.
 * @p: the task in question.
 *
 * Return: The nice value [ -20 ... 0 ... 19 ].
 */
static inline int task_nice(const struct task_struct *p)
{
	return PRIO_TO_NICE((p)->static_prio);
}

extern int can_nice(const struct task_struct *p, const int nice);
extern int task_curr(const struct task_struct *p);
extern int idle_cpu(int cpu);
extern int available_idle_cpu(int cpu);
extern int sched_setscheduler(struct task_struct *, int, const struct sched_param *);
extern int sched_setscheduler_nocheck(struct task_struct *, int, const struct sched_param *);
extern void sched_set_fifo(struct task_struct *p);
extern void sched_set_fifo_low(struct task_struct *p);
extern void sched_set_normal(struct task_struct *p, int nice);
extern int sched_setattr(struct task_struct *, const struct sched_attr *);
extern int sched_setattr_nocheck(struct task_struct *, const struct sched_attr *);
extern struct task_struct *idle_task(int cpu);

/**
 * is_idle_task - is the specified task an idle task?
 * @p: the task in question.
 *
 * Return: 1 if @p is an idle task. 0 otherwise.
 */
static __always_inline bool is_idle_task(const struct task_struct *p)
{
	return !!(p->flags & PF_IDLE);
}

extern struct task_struct *curr_task(int cpu);
extern void ia64_set_curr_task(int cpu, struct task_struct *p);

void yield(void);

/**
 * @brief 内核栈
 *
 * +-----------------------+
 * |        stack          |
 * |_______________________|
 * |          |            |
 * |__________↓____________|             +--------------------+
 * |                       |             |                    |
 * |      thread_info      |<----------->|     task_struct    |
 * +-----------------------+             +--------------------+
 *
 * 参见 INIT_TASK_DATA/init_thread_union
 */
union thread_union {
#ifndef CONFIG_ARCH_TASK_STRUCT_ON_STACK
	struct task_struct task;
#endif
#ifndef CONFIG_THREAD_INFO_IN_TASK
	struct thread_info thread_info;
#endif
	/**
	 * THREAD_SIZE : 32K
	 *
	 * arch/x86/include/asm/page_64_types.h
	 * ----------------------------------------
	 * #ifdef CONFIG_KASAN
	 * #define KASAN_STACK_ORDER 1
	 * #else
	 * #define KASAN_STACK_ORDER 0
	 * #endif
	 * #define THREAD_SIZE_ORDER       (2 + KASAN_STACK_ORDER)
	 * #define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
	 */
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

#ifndef CONFIG_THREAD_INFO_IN_TASK
extern struct thread_info init_thread_info;
#endif

extern unsigned long init_stack[THREAD_SIZE / sizeof(unsigned long)];/* 进程栈， 16K 或 32K */

#ifdef CONFIG_THREAD_INFO_IN_TASK
static inline struct thread_info *task_thread_info(struct task_struct *task)
{
	return &task->thread_info;
}
#elif !defined(__HAVE_THREAD_FUNCTIONS)
# define task_thread_info(task)	((struct thread_info *)(task)->stack)
#endif

/*
 * find a task by one of its numerical ids
 *
 * find_task_by_pid_ns():
 *      finds a task by its pid in the specified namespace
 * find_task_by_vpid():
 *      finds a task by its virtual pid
 *
 * see also find_vpid() etc in include/linux/pid.h
 */

extern struct task_struct *find_task_by_vpid(pid_t nr);
extern struct task_struct *find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns);

/*
 * find a task by its virtual pid and get the task struct
 */
extern struct task_struct *find_get_task_by_vpid(pid_t nr);

extern int wake_up_state(struct task_struct *tsk, unsigned int state);
extern int wake_up_process(struct task_struct *tsk);
extern void wake_up_new_task(struct task_struct *tsk);

#ifdef CONFIG_SMP
extern void kick_process(struct task_struct *tsk);
#else
static inline void kick_process(struct task_struct *tsk) { }
#endif

extern void __set_task_comm(struct task_struct *tsk, const char *from, bool exec);

static inline void set_task_comm(struct task_struct *tsk, const char *from)
{
	__set_task_comm(tsk, from, false);
}

extern char *__get_task_comm(char *to, size_t len, struct task_struct *tsk);
#define get_task_comm(buf, tsk) ({			\
	BUILD_BUG_ON(sizeof(buf) != TASK_COMM_LEN);	\
	__get_task_comm(buf, sizeof(buf), tsk);		\
})

#ifdef CONFIG_SMP
static __always_inline void scheduler_ipi(void)
{
	/*
	 * Fold TIF_NEED_RESCHED into the preempt_count; anybody setting
	 * TIF_NEED_RESCHED remotely (for the first time) will also send
	 * this IPI.
	 */
	preempt_fold_need_resched();
}
extern unsigned long wait_task_inactive(struct task_struct *, long match_state);
#else
static inline void scheduler_ipi(void) { }
#endif

/*
 * Set thread flags in other task's structures.
 * See asm/thread_info.h for TIF_xxxx flags available:
 */
static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void update_tsk_thread_flag(struct task_struct *tsk, int flag,
					  bool value)
{
	update_ti_thread_flag(task_thread_info(tsk), flag, value);
}

static inline int test_and_set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_and_clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_ti_thread_flag(task_thread_info(tsk), flag);
}

/**
 * 设置 需要调度标志位
 *
 * TIF_NEED_RESCHED 调度前需要设置的调度标记
 * 设置了 TIF_NEED_RESCHED 标志，表明需要发生抢占调度；
 *
 * 当前进程的 thread_info 结构中的 flags TIF_NEED_RESCHED 标志被设置，以便时钟中断处理
 * 程序终止时调度程序被调用。
 *
 * 注意：
 * Linux 的进程是抢占式的。如果进程进入 TASK_RUNNING 状态，内核检查他的动态优先级是否大于
 * 当前正在运行的进程的优先级，如果是，current 的执行被中断，并调用调度程序选择另一个进程
 * 运行（通常是刚刚变为可运行的进程）。当然，进程在他的时间片到期时，也可以被抢占。此时，当前
 * 进程的 thread_info 结构中的 flags TIF_NEED_RESCHED 标志被设置，以便时钟中断处理
 * 程序终止时调度程序被调用。
 *
 * 在 resched_curr() 函数中调用了这个函数用于设置 TIF_NEED_RESCHED 标志位。
 */
static inline void set_tsk_need_resched(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}
/* 清理：不需要重新调度 */
static inline void clear_tsk_need_resched(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline int test_tsk_need_resched(struct task_struct *tsk)
{
	return unlikely(test_tsk_thread_flag(tsk,TIF_NEED_RESCHED));
}

/*
 * cond_resched() and cond_resched_lock(): latency reduction via
 * explicit rescheduling in places that are safe. The return
 * value indicates whether a reschedule was done in fact.
 * cond_resched_lock() will drop the spinlock before scheduling,
 *
 * cond_resched() 和 cond_resched_lock()：通过在安全的地方显式重新调度来减少延迟。
 * 返回值指示是否确实执行了重新计划。cond_resched_lock() 将在调度之前丢弃自旋锁，
 */
#ifndef CONFIG_PREEMPTION
extern int _cond_resched(void);
#else

#endif

/**
 *  cond_resched 主动让出cpu . why??
 *
 *  在可抢占内核中，在内核态有很多抢占点，在有高优先级的进程需要运行时，
 *  就会在抢占点到来时执行抢占；而在内核不可抢占系统中(如centos系统)，
 *  在内核态运行的程序可调用 cond_resched 主动让出cpu，防止其在内核态执行
 *  时间过长导致可能发生的soft lockup或者造成较大的调度延迟。
 */
#define cond_resched() ({			\
	___might_sleep(__FILE__, __LINE__, 0);	\
	_cond_resched();			\
})

extern int __cond_resched_lock(spinlock_t *lock);

#define cond_resched_lock(lock) ({				\
	___might_sleep(__FILE__, __LINE__, PREEMPT_LOCK_OFFSET);\
	__cond_resched_lock(lock);				\
})

static inline void cond_resched_rcu(void)
{
#if defined(CONFIG_DEBUG_ATOMIC_SLEEP) || !defined(CONFIG_PREEMPT_RCU)
	rcu_read_unlock();
	cond_resched();
	rcu_read_lock();
#endif
}

/*
 * Does a critical section need to be broken due to another
 * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
 * but a general need for low latency)
 */
static inline int spin_needbreak(spinlock_t *lock)
{
#ifdef CONFIG_PREEMPTION
	return spin_is_contended(lock);
#else
	return 0;
#endif
}

/**
 * 检查是否需要继续调用 schedule(), 见 schedule()
 */
static __always_inline bool need_resched(void)
{
	/* tif_need_resched() == test_thread_flag(TIF_NEED_RESCHED) */
	return unlikely(tif_need_resched());
}

/*
 * Wrappers for p->thread_info->cpu access. No-op on UP.
 */
#ifdef CONFIG_SMP

/**
 *
 */
static inline unsigned int task_cpu(const struct task_struct *p)
{
#ifdef CONFIG_THREAD_INFO_IN_TASK
	return READ_ONCE(p->cpu);
#else
	return READ_ONCE(task_thread_info(p)->cpu);
#endif
}

extern void set_task_cpu(struct task_struct *p, unsigned int cpu);

#else
/**/
#endif /* CONFIG_SMP */

/*
 * In order to reduce various lock holder preemption latencies provide an
 * interface to see if a vCPU is currently running or not.
 *
 * This allows us to terminate optimistic spin loops and block, analogous to
 * the native optimistic spin heuristic of testing if the lock owner task is
 * running or not.
 */
#ifndef vcpu_is_preempted
static inline bool vcpu_is_preempted(int cpu)
{
	return false;
}
#endif

extern long sched_setaffinity(pid_t pid, const struct cpumask *new_mask);
extern long sched_getaffinity(pid_t pid, struct cpumask *mask);

#ifndef TASK_SIZE_OF
#define TASK_SIZE_OF(tsk)	TASK_SIZE
#endif

#ifdef CONFIG_RSEQ

/*
 * Map the event mask on the user-space ABI enum rseq_cs_flags
 * for direct mask checks.
 */
enum rseq_event_mask_bits {
	RSEQ_EVENT_PREEMPT_BIT	= RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT,
	RSEQ_EVENT_SIGNAL_BIT	= RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT,
	RSEQ_EVENT_MIGRATE_BIT	= RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT,
};

enum rseq_event_mask {
	RSEQ_EVENT_PREEMPT	= (1U << RSEQ_EVENT_PREEMPT_BIT),
	RSEQ_EVENT_SIGNAL	= (1U << RSEQ_EVENT_SIGNAL_BIT),
	RSEQ_EVENT_MIGRATE	= (1U << RSEQ_EVENT_MIGRATE_BIT),
};

static inline void rseq_set_notify_resume(struct task_struct *t)
{
	if (t->rseq)
		set_tsk_thread_flag(t, TIF_NOTIFY_RESUME);
}

void __rseq_handle_notify_resume(struct ksignal *sig, struct pt_regs *regs);

static inline void rseq_handle_notify_resume(struct ksignal *ksig,
					     struct pt_regs *regs)
{
	if (current->rseq)
		__rseq_handle_notify_resume(ksig, regs);
}

static inline void rseq_signal_deliver(struct ksignal *ksig,
				       struct pt_regs *regs)
{
	preempt_disable();
	__set_bit(RSEQ_EVENT_SIGNAL_BIT, &current->rseq_event_mask);
	preempt_enable();
	rseq_handle_notify_resume(ksig, regs);
}

/* rseq_preempt() requires preemption to be disabled. */
static inline void rseq_preempt(struct task_struct *t)
{
	__set_bit(RSEQ_EVENT_PREEMPT_BIT, &t->rseq_event_mask);
	rseq_set_notify_resume(t);
}

/* rseq_migrate() requires preemption to be disabled. */
static inline void rseq_migrate(struct task_struct *t)
{
	__set_bit(RSEQ_EVENT_MIGRATE_BIT, &t->rseq_event_mask);
	rseq_set_notify_resume(t);
}

/*
 * If parent process has a registered restartable sequences area, the
 * child inherits. Unregister rseq for a clone with CLONE_VM set.
 */
static inline void rseq_fork(struct task_struct *t, unsigned long clone_flags)
{
	if (clone_flags & CLONE_VM) {
		t->rseq = NULL;
		t->rseq_sig = 0;
		t->rseq_event_mask = 0;
	} else {
		t->rseq = current->rseq;
		t->rseq_sig = current->rseq_sig;
		t->rseq_event_mask = current->rseq_event_mask;
	}
}

static inline void rseq_execve(struct task_struct *t)
{
	t->rseq = NULL;
	t->rseq_sig = 0;
	t->rseq_event_mask = 0;
}

#else
/**/
#endif

#ifdef CONFIG_DEBUG_RSEQ

void rseq_syscall(struct pt_regs *regs);

#else
/**/
#endif

const struct sched_avg *sched_trace_cfs_rq_avg(struct cfs_rq *cfs_rq);
char *sched_trace_cfs_rq_path(struct cfs_rq *cfs_rq, char *str, int len);
int sched_trace_cfs_rq_cpu(struct cfs_rq *cfs_rq);

const struct sched_avg *sched_trace_rq_avg_rt(struct rq *rq);
const struct sched_avg *sched_trace_rq_avg_dl(struct rq *rq);
const struct sched_avg *sched_trace_rq_avg_irq(struct rq *rq);

int sched_trace_rq_cpu(struct rq *rq);
int sched_trace_rq_cpu_capacity(struct rq *rq);
int sched_trace_rq_nr_running(struct rq *rq);

const struct cpumask *sched_trace_rd_span(struct root_domain *rd);

#endif

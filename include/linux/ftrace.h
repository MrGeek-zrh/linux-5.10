/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ftrace header.  For implementation details beyond the random comments
 * scattered below, see: Documentation/trace/ftrace-design.rst
 */

#ifndef _LINUX_FTRACE_H
#define _LINUX_FTRACE_H

#include <linux/trace_clock.h>
#include <linux/kallsyms.h>
#include <linux/linkage.h>
#include <linux/bitops.h>
#include <linux/ptrace.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/fs.h>

#include <asm/ftrace.h>

/*
 * If the arch supports passing the variable contents of
 * function_trace_op as the third parameter back from the
 * mcount call, then the arch should define this as 1.
 */
//#ifndef ARCH_SUPPORTS_FTRACE_OPS
//#define ARCH_SUPPORTS_FTRACE_OPS 0
//#endif

/*
 * If the arch's mcount caller does not support all of ftrace's
 * features, then it must call an indirect function that
 * does. Or at least does enough to prevent any unwelcomed side effects.
 */
#if !ARCH_SUPPORTS_FTRACE_OPS
# define FTRACE_FORCE_LIST_FUNC 1
#else
# define FTRACE_FORCE_LIST_FUNC 0
#endif

/* Main tracing buffer and events set up */
#ifdef CONFIG_TRACING
void trace_init(void);
void early_trace_init(void);
#else

#endif

struct module;
struct ftrace_hash;
struct ftrace_direct_func;

#if defined(CONFIG_FUNCTION_TRACER) && defined(CONFIG_MODULES) && \
	defined(CONFIG_DYNAMIC_FTRACE)
const char *
ftrace_mod_address_lookup(unsigned long addr, unsigned long *size,
		   unsigned long *off, char **modname, char *sym);
#else

#endif

#if defined(CONFIG_FUNCTION_TRACER) && defined(CONFIG_DYNAMIC_FTRACE)
int ftrace_mod_get_kallsym(unsigned int symnum, unsigned long *value,
			   char *type, char *name,
			   char *module_name, int *exported);
#else

#endif

#ifdef CONFIG_FUNCTION_TRACER

extern int ftrace_enabled;
extern int
ftrace_enable_sysctl(struct ctl_table *table, int write,
		     void *buffer, size_t *lenp, loff_t *ppos);

struct ftrace_ops;
 /**
 *  一个跳板函数
 *  ------------------------
 *  schedule
 *    push %rbp
 *    mov %rsp,%rbp
 *    call ftrace_caller -----> ftrace_caller: (mcount)
 *                                save regs
 *                                load args
 *                              ftrace_call:
 *                                call ftrace_stub <--> ftrace_ops.func
 *                                restore regs
 *                              ftrace_stub:
 *                                retq
 *
 *
 *  可能等于 `klp_ftrace_handler()`,在 `klp_patch_func()` 中赋值
 */
typedef void (*ftrace_func_t)(unsigned long ip, unsigned long parent_ip,
			      struct ftrace_ops *op, struct pt_regs *regs);

ftrace_func_t ftrace_ops_get_func(struct ftrace_ops *ops);

/*
 * FTRACE_OPS_FL_* bits denote the state of ftrace_ops struct and are
 * set in the flags member.
 * CONTROL, SAVE_REGS, SAVE_REGS_IF_SUPPORTED, RECURSION_SAFE, STUB and
 * IPMODIFY are a kind of attribute flags which can be set only before
 * registering the ftrace_ops, and can not be modified while registered.
 * Changing those attribute flags after registering ftrace_ops will
 * cause unexpected results.
 *
 * ENABLED - set/unset when ftrace_ops is registered/unregistered
 * DYNAMIC - set when ftrace_ops is registered to denote dynamically
 *           allocated ftrace_ops which need special care
 * SAVE_REGS - The ftrace_ops wants regs saved at each function called
 *            and passed to the callback. If this flag is set, but the
 *            architecture does not support passing regs
 *            (CONFIG_DYNAMIC_FTRACE_WITH_REGS is not defined), then the
 *            ftrace_ops will fail to register, unless the next flag
 *            is set.
 * SAVE_REGS_IF_SUPPORTED - This is the same as SAVE_REGS, but if the
 *            handler can handle an arch that does not save regs
 *            (the handler tests if regs == NULL), then it can set
 *            this flag instead. It will not fail registering the ftrace_ops
 *            but, the regs field will be NULL if the arch does not support
 *            passing regs to the handler.
 *            Note, if this flag is set, the SAVE_REGS flag will automatically
 *            get set upon registering the ftrace_ops, if the arch supports it.
 * RECURSION_SAFE - The ftrace_ops can set this to tell the ftrace infrastructure
 *            that the call back has its own recursion protection. If it does
 *            not set this, then the ftrace infrastructure will add recursion
 *            protection for the caller.
 * STUB   - The ftrace_ops is just a place holder.
 * INITIALIZED - The ftrace_ops has already been initialized (first use time
 *            register_ftrace_function() is called, it will initialized the ops)
 * DELETED - The ops are being deleted, do not let them be registered again.
 * ADDING  - The ops is in the process of being added.
 * REMOVING - The ops is in the process of being removed.
 * MODIFYING - The ops is in the process of changing its filter functions.
 * ALLOC_TRAMP - A dynamic trampoline was allocated by the core code.
 *            The arch specific code sets this flag when it allocated a
 *            trampoline. This lets the arch know that it can update the
 *            trampoline in case the callback function changes.
 *            The ftrace_ops trampoline can be set by the ftrace users, and
 *            in such cases the arch must not modify it. Only the arch ftrace
 *            core code should set this flag.
 * IPMODIFY - The ops can modify the IP register. This can only be set with
 *            SAVE_REGS. If another ops with this flag set is already registered
 *            for any of the functions that this ops will be registered for, then
 *            this ops will fail to register or set_filter_ip.
 * PID     - Is affected by set_ftrace_pid (allows filtering on those pids)
 * RCU     - Set when the ops can only be called when RCU is watching.
 * TRACE_ARRAY - The ops->private points to a trace_array descriptor.
 * PERMANENT - Set when the ops is permanent and should not be affected by
 *             ftrace_enabled.
 * DIRECT - Used by the direct ftrace_ops helper for direct functions
 *            (internal ftrace only, should not be used by others)
 *
 * -------------------------------
 * struct ftrace_ops.flags
 */
enum {
    /**
     *  set by ftrace, when ops is recording
     */
	FTRACE_OPS_FL_ENABLED			= BIT(0),
	/**
     *  set by ftrace when ops is dynamically allocated
     */
	FTRACE_OPS_FL_DYNAMIC			= BIT(1),
    /**
     *  set by caller, to record regs
     *  fails if saving regs is not supported
     */
	FTRACE_OPS_FL_SAVE_REGS			= BIT(2),
    /**
     *  set by caller, save regs if supported
     *  doesn’t fail register if not supported
     */
	FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED	= BIT(3),
    /**
     *  If ftrace_ops.func handles recursion
     *  Otherwise, ftrace will handle it
     */
	FTRACE_OPS_FL_RECURSION_SAFE		= BIT(4),
    /**
     *  used by ftrace for stub functions
     *  ftrace 用于存根函数
     */
	FTRACE_OPS_FL_STUB			= BIT(5),
    /**
     *  used by ftrace when ftrace_ops is first used
     */
	FTRACE_OPS_FL_INITIALIZED		= BIT(6),
    /**
     *  ftrace_ops has been deleted
     *  used by ftrace buffer instances
     */
	FTRACE_OPS_FL_DELETED			= BIT(7),
    /**
     *
     */
	FTRACE_OPS_FL_ADDING			= BIT(8),
    /**
     *
     */
	FTRACE_OPS_FL_REMOVING			= BIT(9),
    /**
     *
     */
	FTRACE_OPS_FL_MODIFYING			= BIT(10),
    /**
     *
     */
	FTRACE_OPS_FL_ALLOC_TRAMP		= BIT(11),
    /**
     *  ops可以修改IP寄存器。 这只能用 SAVE_REGS 设置。
	 *  如果另一个具有此标志集的操作已注册此操作将注册的任何功能，
	 *  则此操作将无法注册或 set_filter_ip。
     */
	FTRACE_OPS_FL_IPMODIFY			= BIT(12),
    /**
     *
     */
	FTRACE_OPS_FL_PID			= BIT(13),
    /**
     *
     */
	FTRACE_OPS_FL_RCU			= BIT(14),
    /**
     *
     */
	FTRACE_OPS_FL_TRACE_ARRAY		= BIT(15),
    /**
     *	Set when the ops is permanent and should not be affected by
 	 *  ftrace_enabled.
     */
	FTRACE_OPS_FL_PERMANENT                 = BIT(16),
    /**
     *
     */
	FTRACE_OPS_FL_DIRECT			= BIT(17),
};

#ifdef CONFIG_DYNAMIC_FTRACE
/* The hash used to know what functions callbacks trace */
struct ftrace_ops_hash {
	struct ftrace_hash __rcu	*notrace_hash;  /*Functions in notrace_hash will not be traced
                                                  even if they exist in filter_hash.
                                                  empty means OK to trace all */
	struct ftrace_hash __rcu	*filter_hash;   /* what functions to trace
                                                  empty means to trace all */
	struct mutex			regex_lock;         /* used to protect the hashes */
};

void ftrace_free_init_mem(void);
void ftrace_free_mem(struct module *mod, void *start, void *end);
#else

#endif

/*
 * Note, ftrace_ops can be referenced outside of RCU protection, unless
 * the RCU flag is set. If ftrace_ops is allocated and not part of kernel
 * core data, the unregistering of it will perform a scheduling on all CPUs
 * to make sure that there are no more users. Depending on the load of the
 * system that may take a bit of time.
 *
 * Any private data added must also take care not to be freed and if private
 * data is added to a ftrace_ops that is in core code, the user of the
 * ftrace_ops must perform a schedule_on_each_cpu() before freeing it.
 *
 * Static ftrace_ops
 * ------------------------
 * 1. function and function_graph
 * 2. function probes (schedule:traceoff)
 * 3. stack tracer
 * 4. latency tracers
 *
 * Dynamic ftrace_ops
 * -------------------------
 * 1. perf
 * 2. kprobes
 */
struct ftrace_ops {
    /**
     *  将替换 `ftrace_stub()`
     *  ------------------------
     *  schedule
     *    push %rbp
     *    mov %rsp,%rbp
     *    call ftrace_caller -----> ftrace_caller: (mcount)
     *                                save regs
     *                                load args
     *                              ftrace_call:
     *                                call ftrace_stub <--> ftrace_ops.func
     *                                restore regs
     *                              ftrace_stub:
     *                                retq
     *
     *
     *  可能等于 `klp_ftrace_handler()`,在 `klp_patch_func()` 中赋值
     */
	ftrace_func_t			func;
	struct ftrace_ops __rcu		*next;
    /**
     *	标志
     */
	unsigned long			flags;  /* FTRACE_OPS_FL_ENABLED ... */
	/**
	 * 私有变量
	 *
	 */
	void				*private;
    /**
     *
     */
	ftrace_func_t			saved_func;
    /**
     *
     */
#ifdef CONFIG_DYNAMIC_FTRACE
	struct ftrace_ops_hash		local_hash;
	struct ftrace_ops_hash		*func_hash;
	struct ftrace_ops_hash		old_hash;
    /**
     * 对比 mcount()
     */
	unsigned long			trampoline; /* 跳板 */
	unsigned long			trampoline_size;
	struct list_head		list;
#endif
};

extern struct ftrace_ops __rcu *ftrace_ops_list;
extern struct ftrace_ops ftrace_list_end;

/*
 * Traverse the ftrace_ops_list, invoking all entries.  The reason that we
 * can use rcu_dereference_raw_check() is that elements removed from this list
 * are simply leaked, so there is no need to interact with a grace-period
 * mechanism.  The rcu_dereference_raw_check() calls are needed to handle
 * concurrent insertions into the ftrace_ops_list.
 *
 * Silly Alpha and silly pointer-speculation compiler optimizations!
 */
#define do_for_each_ftrace_op(op, list)			\
	op = rcu_dereference_raw_check(list);			\
	do

/*
 * Optimized for just a single item in the list (as that is the normal case).
 */
#define while_for_each_ftrace_op(op)				\
	while (likely(op = rcu_dereference_raw_check((op)->next)) &&	\
	       unlikely((op) != &ftrace_list_end))

/*
 * Type of the current tracing.
 */
enum ftrace_tracing_type_t {
	FTRACE_TYPE_ENTER = 0, /* Hook the call of the function */
	FTRACE_TYPE_RETURN,	/* Hook the return of the function */
};

/* Current tracing type, default is FTRACE_TYPE_ENTER */
extern enum ftrace_tracing_type_t ftrace_tracing_type;

/*
 * The ftrace_ops must be a static and should also
 * be read_mostly.  These functions do modify read_mostly variables
 * so use them sparely. Never free an ftrace_op or modify the
 * next pointer after it has been registered. Even after unregistering
 * it, the next pointer may still be used internally.
 */
int register_ftrace_function(struct ftrace_ops *ops);
int unregister_ftrace_function(struct ftrace_ops *ops);

/**
 *  arch/x86/kernel/ftrace_64.S
 *      SYM_INNER_LABEL(ftrace_stub, SYM_L_GLOBAL)
 *      	retq
 *  arch/arm64/kernel/entry-ftrace.S
 *      SYM_FUNC_START(ftrace_stub)
 *      	ret
 *      SYM_FUNC_END(ftrace_stub)
 *
 */
extern void ftrace_stub(unsigned long a0, unsigned long a1,
			struct ftrace_ops *op, struct pt_regs *regs);

#else /* !CONFIG_FUNCTION_TRACER */

#endif /* CONFIG_FUNCTION_TRACER */

/**
 * 可能在如下函数中分配
 * 每次注册 ftrace 都会分配一个新的 struct ftrace_func_entry {}
 * ---------------------------------
 * 1. register_ftrace_direct()
 *
 */
struct ftrace_func_entry {
	/**
	 * hash table 为`struct ftrace_hash`
	 *
	 * 可能的头为：
	 * ----------------------------
	 * 1. direct_functions
	 */
	struct hlist_node hlist;

	// ip - 被跟踪的函数地址
	unsigned long ip;
	// 如 mcount() 要被执行的函数地址
	unsigned long direct; /* for direct lookup only */
};

struct dyn_ftrace;

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
extern int ftrace_direct_func_count;
int register_ftrace_direct(unsigned long ip, unsigned long addr);
int unregister_ftrace_direct(unsigned long ip, unsigned long addr);
int modify_ftrace_direct(unsigned long ip, unsigned long old_addr, unsigned long new_addr);
struct ftrace_direct_func *ftrace_find_direct_func(unsigned long addr);
int ftrace_modify_direct_caller(struct ftrace_func_entry *entry,
				struct dyn_ftrace *rec,
				unsigned long old_addr,
				unsigned long new_addr);
unsigned long ftrace_find_rec_direct(unsigned long ip);
#else

#endif /* CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS */

#ifndef CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
/*
 * This must be implemented by the architecture.
 * It is the way the ftrace direct_ops helper, when called
 * via ftrace (because there's other callbacks besides the
 * direct call), can inform the architecture's trampoline that this
 * routine has a direct caller, and what the caller is.
 *
 * For example, in x86, it returns the direct caller
 * callback function via the regs->orig_ax parameter.
 * Then in the ftrace trampoline, if this is set, it makes
 * the return from the trampoline jump to the direct caller
 * instead of going back to the function it just traced.
 */
//static inline void arch_ftrace_set_direct_caller(struct pt_regs *regs,
//						 unsigned long addr) { }
#endif /* CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS */

#ifdef CONFIG_STACK_TRACER

extern int stack_tracer_enabled;

int stack_trace_sysctl(struct ctl_table *table, int write, void *buffer,
		       size_t *lenp, loff_t *ppos);

/* DO NOT MODIFY THIS VARIABLE DIRECTLY! */
DECLARE_PER_CPU(int, disable_stack_tracer);

/**
 * stack_tracer_disable - temporarily disable the stack tracer
 *
 * There's a few locations (namely in RCU) where stack tracing
 * cannot be executed. This function is used to disable stack
 * tracing during those critical sections.
 *
 * This function must be called with preemption or interrupts
 * disabled and stack_tracer_enable() must be called shortly after
 * while preemption or interrupts are still disabled.
 */
static inline void stack_tracer_disable(void)
{
	/* Preemption or interupts must be disabled */
	if (IS_ENABLED(CONFIG_DEBUG_PREEMPT))
		WARN_ON_ONCE(!preempt_count() || !irqs_disabled());
	this_cpu_inc(disable_stack_tracer);
}

/**
 * stack_tracer_enable - re-enable the stack tracer
 *
 * After stack_tracer_disable() is called, stack_tracer_enable()
 * must be called shortly afterward.
 */
static inline void stack_tracer_enable(void)
{
	if (IS_ENABLED(CONFIG_DEBUG_PREEMPT))
		WARN_ON_ONCE(!preempt_count() || !irqs_disabled());
	this_cpu_dec(disable_stack_tracer);
}
#else


#endif

#ifdef CONFIG_DYNAMIC_FTRACE

int ftrace_arch_code_modify_prepare(void);
int ftrace_arch_code_modify_post_process(void);

enum ftrace_bug_type {
	FTRACE_BUG_UNKNOWN,
	FTRACE_BUG_INIT,
	FTRACE_BUG_NOP,
	FTRACE_BUG_CALL,
	FTRACE_BUG_UPDATE,
};
extern enum ftrace_bug_type ftrace_bug_type;

/*
 * Archs can set this to point to a variable that holds the value that was
 * expected at the call site before calling ftrace_bug().
 */
extern const void *ftrace_expected;

void ftrace_bug(int err, struct dyn_ftrace *rec);

struct seq_file;

extern int ftrace_text_reserved(const void *start, const void *end);

struct ftrace_ops *ftrace_ops_trampoline(unsigned long addr);

bool is_ftrace_trampoline(unsigned long addr);

/*
 * The dyn_ftrace record's flags field is split into two parts.
 * the first part which is '0-FTRACE_REF_MAX' is a counter of
 * the number of callbacks that have registered the function that
 * the dyn_ftrace descriptor represents.
 *
 * The second part is a mask:
 *  ENABLED - the function is being traced
 *  REGS    - the record wants the function to save regs
 *  REGS_EN - the function is set up to save regs.
 *  IPMODIFY - the record allows for the IP address to be changed.
 *  DISABLED - the record is not ready to be touched yet
 *  DIRECT   - there is a direct function to call
 *
 * When a new ftrace_ops is registered and wants a function to save
 * pt_regs, the rec->flags REGS is set. When the function has been
 * set up to save regs, the REG_EN flag is set. Once a function
 * starts saving regs it will do so until all ftrace_ops are removed
 * from tracing that function.
 *
 * struct dyn_ftrace.flags
 */
enum {
    /**
     *  函数 正在被追踪
     */
	FTRACE_FL_ENABLED	= (1UL << 31),
    /**
     *
     */
	FTRACE_FL_REGS		= (1UL << 30),
	/**
     *
     */
	FTRACE_FL_REGS_EN	= (1UL << 29),
	FTRACE_FL_TRAMP		= (1UL << 28),
	FTRACE_FL_TRAMP_EN	= (1UL << 27),
	FTRACE_FL_IPMODIFY	= (1UL << 26),
	FTRACE_FL_DISABLED	= (1UL << 25),
	FTRACE_FL_DIRECT	= (1UL << 24),
	FTRACE_FL_DIRECT_EN	= (1UL << 23),
};

#define FTRACE_REF_MAX_SHIFT	23
#define FTRACE_REF_MAX		((1UL << FTRACE_REF_MAX_SHIFT) - 1)

// 0-23 bits is a counter
#define ftrace_rec_count(rec)	((rec)->flags & FTRACE_REF_MAX)

/**
 *  ftrace
 */
struct dyn_ftrace {
    /**
     *  指向 函数地址 address of mcount call-site
	 *  也就是每个函数开头 mcount()/_mcount() 的地址, 在 ftrace_process_locs() 赋值
	 *  或者说是 函数本身的地址
     */
	unsigned long		ip; /* address of mcount call-site */
    /**
     *  FTRACE_FL_XXX
	 *
	 *  0-23 bits is a counter
	 *  23-..
     */
	unsigned long		flags;

    /**
     *  x86 和 arm64 均为空
     */
	struct dyn_arch_ftrace	arch;
};

int ftrace_force_update(void);
int ftrace_set_filter_ip(struct ftrace_ops *ops, unsigned long ip,
			 int remove, int reset);
int ftrace_set_filter(struct ftrace_ops *ops, unsigned char *buf,
		       int len, int reset);
int ftrace_set_notrace(struct ftrace_ops *ops, unsigned char *buf,
			int len, int reset);
void ftrace_set_global_filter(unsigned char *buf, int len, int reset);
void ftrace_set_global_notrace(unsigned char *buf, int len, int reset);
void ftrace_free_filter(struct ftrace_ops *ops);
void ftrace_ops_set_global_filter(struct ftrace_ops *ops);

enum {
	FTRACE_UPDATE_CALLS		= (1 << 0),
	FTRACE_DISABLE_CALLS		= (1 << 1),
	FTRACE_UPDATE_TRACE_FUNC	= (1 << 2),
	FTRACE_START_FUNC_RET		= (1 << 3),
	FTRACE_STOP_FUNC_RET		= (1 << 4),
	FTRACE_MAY_SLEEP		= (1 << 5),
};

/*
 * The FTRACE_UPDATE_* enum is used to pass information back
 * from the ftrace_update_record() and ftrace_test_record()
 * functions. These are called by the code update routines
 * to find out what is to be done for a given function.
 *
 *  IGNORE           - The function is already what we want it to be
 *  MAKE_CALL        - Start tracing the function
 *  MODIFY_CALL      - Stop saving regs for the function
 *  MAKE_NOP         - Stop tracing the function
 */
enum {
	FTRACE_UPDATE_IGNORE, //已经处理：已经被追踪或者已经去除追踪
	/*开始追踪*/
	FTRACE_UPDATE_MAKE_CALL,
	FTRACE_UPDATE_MODIFY_CALL, //
	FTRACE_UPDATE_MAKE_NOP, // 停止追踪
};

enum {
	FTRACE_ITER_FILTER	= (1 << 0),
	FTRACE_ITER_NOTRACE	= (1 << 1),
	FTRACE_ITER_PRINTALL	= (1 << 2),
	FTRACE_ITER_DO_PROBES	= (1 << 3),
	FTRACE_ITER_PROBE	= (1 << 4),
	FTRACE_ITER_MOD		= (1 << 5),
	FTRACE_ITER_ENABLED	= (1 << 6),
};

void arch_ftrace_update_code(int command);
void arch_ftrace_update_trampoline(struct ftrace_ops *ops);
void *arch_ftrace_trampoline_func(struct ftrace_ops *ops, struct dyn_ftrace *rec);
void arch_ftrace_trampoline_free(struct ftrace_ops *ops);

struct ftrace_rec_iter;

struct ftrace_rec_iter *ftrace_rec_iter_start(void);
struct ftrace_rec_iter *ftrace_rec_iter_next(struct ftrace_rec_iter *iter);
struct dyn_ftrace *ftrace_rec_iter_record(struct ftrace_rec_iter *iter);

#define for_ftrace_rec_iter(iter)		\
	for (iter = ftrace_rec_iter_start();	\
	     iter;				\
	     iter = ftrace_rec_iter_next(iter))


int ftrace_update_record(struct dyn_ftrace *rec, bool enable);
int ftrace_test_record(struct dyn_ftrace *rec, bool enable);
void ftrace_run_stop_machine(int command);
unsigned long ftrace_location(unsigned long ip);
unsigned long ftrace_location_range(unsigned long start, unsigned long end);
unsigned long ftrace_get_addr_new(struct dyn_ftrace *rec);
unsigned long ftrace_get_addr_curr(struct dyn_ftrace *rec);

extern ftrace_func_t ftrace_trace_function;

int ftrace_regex_open(struct ftrace_ops *ops, int flag,
		  struct inode *inode, struct file *file);
ssize_t ftrace_filter_write(struct file *file, const char __user *ubuf,
			    size_t cnt, loff_t *ppos);
ssize_t ftrace_notrace_write(struct file *file, const char __user *ubuf,
			     size_t cnt, loff_t *ppos);
int ftrace_regex_release(struct inode *inode, struct file *file);

void __init
ftrace_set_early_filter(struct ftrace_ops *ops, char *buf, int enable);

/* defined in arch */
extern int ftrace_ip_converted(unsigned long ip);
extern int ftrace_dyn_arch_init(void);
extern void ftrace_replace_code(int enable);
extern int ftrace_update_ftrace_func(ftrace_func_t func);
extern void ftrace_caller(void);    /* arch/x86/kernel/ftrace_64.S */
#if RTOAX/* arch/x86/kernel/ftrace_64.S */
SYM_FUNC_START(ftrace_caller)
	/* save_mcount_regs fills in first two parameters */
	save_mcount_regs

SYM_INNER_LABEL(ftrace_caller_op_ptr, SYM_L_GLOBAL)
	/* Load the ftrace_ops into the 3rd parameter */
	movq function_trace_op(%rip), %rdx

	/* regs go into 4th parameter (but make it NULL) */
	movq $0, %rcx

SYM_INNER_LABEL(ftrace_call, SYM_L_GLOBAL)
    /**
     *  ftrace注册后，这个函数将被替换为 ftrace_ops.func
     */
	call ftrace_stub

	restore_mcount_regs

	/*
	 * The code up to this label is copied into trampolines so
	 * think twice before adding any new code or changing the
	 * layout here.
	 */
SYM_INNER_LABEL(ftrace_caller_end, SYM_L_GLOBAL)

	jmp ftrace_epilogue
SYM_FUNC_END(ftrace_caller);
#endif
extern void ftrace_regs_caller(void);   /* arch/x86/kernel/ftrace_64.S */
extern void ftrace_call(void);  /* arch/x86/kernel/ftrace_64.S, is inner label */
extern void ftrace_regs_call(void); /* arch/x86/kernel/ftrace_64.S */
extern void mcount_call(void);

void ftrace_modify_all_code(int command);

#ifndef FTRACE_ADDR
#define FTRACE_ADDR ((unsigned long)ftrace_caller)
#endif

#ifndef FTRACE_GRAPH_ADDR
#define FTRACE_GRAPH_ADDR ((unsigned long)ftrace_graph_caller)  /* arch/x86/kernel/ftrace_64.S */
#endif

#ifndef FTRACE_REGS_ADDR
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
# define FTRACE_REGS_ADDR ((unsigned long)ftrace_regs_caller)   /* arch/x86/kernel/ftrace_64.S */
#else
# define FTRACE_REGS_ADDR FTRACE_ADDR
#endif
#endif


/*
 * If an arch would like functions that are only traced
 * by the function graph tracer to jump directly to its own
 * trampoline, then they can define FTRACE_GRAPH_TRAMP_ADDR
 * to be that address to jump to.
 */
#ifndef FTRACE_GRAPH_TRAMP_ADDR
#define FTRACE_GRAPH_TRAMP_ADDR ((unsigned long) 0)
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
extern void ftrace_graph_caller(void);
extern int ftrace_enable_ftrace_graph_caller(void);
extern int ftrace_disable_ftrace_graph_caller(void);
#else
static inline int ftrace_enable_ftrace_graph_caller(void) { return 0; }
static inline int ftrace_disable_ftrace_graph_caller(void) { return 0; }
#endif

/**
 * ftrace_make_nop - convert code into nop
 * @mod: module structure if called by module load initialization
 * @rec: the call site record (e.g. mcount/fentry)
 * @addr: the address that the call site should be calling
 *
 * This is a very sensitive operation and great care needs
 * to be taken by the arch.  The operation should carefully
 * read the location, check to see if what is read is indeed
 * what we expect it to be, and then on success of the compare,
 * it should write to the location.
 *
 * The code segment at @rec->ip should be a caller to @addr
 *
 * Return must be:
 *  0 on success
 *  -EFAULT on error reading the location
 *  -EINVAL on a failed compare of the contents
 *  -EPERM  on error writing to the location
 * Any other value will be considered a failure.
 */
extern int ftrace_make_nop(struct module *mod,
			   struct dyn_ftrace *rec, unsigned long addr);


/**
 * ftrace_init_nop - initialize a nop call site
 * @mod: module structure if called by module load initialization
 * @rec: the call site record (e.g. mcount/fentry)
 *
 * This is a very sensitive operation and great care needs
 * to be taken by the arch.  The operation should carefully
 * read the location, check to see if what is read is indeed
 * what we expect it to be, and then on success of the compare,
 * it should write to the location.
 *
 * The code segment at @rec->ip should contain the contents created by
 * the compiler
 *
 * Return must be:
 *  0 on success
 *  -EFAULT on error reading the location
 *  -EINVAL on a failed compare of the contents
 *  -EPERM  on error writing to the location
 * Any other value will be considered a failure.
 */
#ifndef ftrace_init_nop
static inline int ftrace_init_nop(struct module *mod, struct dyn_ftrace *rec)
{
	return ftrace_make_nop(mod, rec, MCOUNT_ADDR);
}
#endif

/**
 * ftrace_make_call - convert a nop call site into a call to addr
 * @rec: the call site record (e.g. mcount/fentry)
 * @addr: the address that the call site should call
 *
 * This is a very sensitive operation and great care needs
 * to be taken by the arch.  The operation should carefully
 * read the location, check to see if what is read is indeed
 * what we expect it to be, and then on success of the compare,
 * it should write to the location.
 *
 * The code segment at @rec->ip should be a nop
 *
 * Return must be:
 *  0 on success
 *  -EFAULT on error reading the location
 *  -EINVAL on a failed compare of the contents
 *  -EPERM  on error writing to the location
 * Any other value will be considered a failure.
 */
extern int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr);

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
/**
 * ftrace_modify_call - convert from one addr to another (no nop)
 * @rec: the call site record (e.g. mcount/fentry)
 * @old_addr: the address expected to be currently called to
 * @addr: the address to change to
 *
 * This is a very sensitive operation and great care needs
 * to be taken by the arch.  The operation should carefully
 * read the location, check to see if what is read is indeed
 * what we expect it to be, and then on success of the compare,
 * it should write to the location.
 *
 * The code segment at @rec->ip should be a caller to @old_addr
 *
 * Return must be:
 *  0 on success
 *  -EFAULT on error reading the location
 *  -EINVAL on a failed compare of the contents
 *  -EPERM  on error writing to the location
 * Any other value will be considered a failure.
 */
extern int ftrace_modify_call(struct dyn_ftrace *rec, unsigned long old_addr,
			      unsigned long addr);
#else
/* Should never be called */
static inline int ftrace_modify_call(struct dyn_ftrace *rec, unsigned long old_addr,
				     unsigned long addr)
{
	return -EINVAL;
}
#endif

/* May be defined in arch */
extern int ftrace_arch_read_dyn_info(char *buf, int size);

extern int skip_trace(unsigned long ip);
extern void ftrace_module_init(struct module *mod);
extern void ftrace_module_enable(struct module *mod);
extern void ftrace_release_mod(struct module *mod);

extern void ftrace_disable_daemon(void);
extern void ftrace_enable_daemon(void);
#else /* CONFIG_DYNAMIC_FTRACE */


#endif /* CONFIG_DYNAMIC_FTRACE */

/* totally disable ftrace - can not re-enable after this */
void ftrace_kill(void);

static inline void tracer_disable(void)
{
#ifdef CONFIG_FUNCTION_TRACER
	ftrace_enabled = 0;
#endif
}

/*
 * Ftrace disable/restore without lock. Some synchronization mechanism
 * must be used to prevent ftrace_enabled to be changed between
 * disable/restore.
 */
static inline int __ftrace_enabled_save(void)
{
#ifdef CONFIG_FUNCTION_TRACER
	int saved_ftrace_enabled = ftrace_enabled;
	ftrace_enabled = 0;
	return saved_ftrace_enabled;
#else
	return 0;
#endif
}

static inline void __ftrace_enabled_restore(int enabled)
{
#ifdef CONFIG_FUNCTION_TRACER
	ftrace_enabled = enabled;
#endif
}

/* All archs should have this, but we define it for consistency */
#ifndef ftrace_return_address0
# define ftrace_return_address0 __builtin_return_address(0)
#endif

/* Archs may use other ways for ADDR1 and beyond */
#ifndef ftrace_return_address
# ifdef CONFIG_FRAME_POINTER
#  define ftrace_return_address(n) __builtin_return_address(n)
# else
#  define ftrace_return_address(n) 0UL
# endif
#endif

#define CALLER_ADDR0 ((unsigned long)ftrace_return_address0)
#define CALLER_ADDR1 ((unsigned long)ftrace_return_address(1))
#define CALLER_ADDR2 ((unsigned long)ftrace_return_address(2))
#define CALLER_ADDR3 ((unsigned long)ftrace_return_address(3))
#define CALLER_ADDR4 ((unsigned long)ftrace_return_address(4))
#define CALLER_ADDR5 ((unsigned long)ftrace_return_address(5))
#define CALLER_ADDR6 ((unsigned long)ftrace_return_address(6))

static inline unsigned long get_lock_parent_ip(void)
{
	unsigned long addr = CALLER_ADDR0;

	if (!in_lock_functions(addr))
		return addr;
	addr = CALLER_ADDR1;
	if (!in_lock_functions(addr))
		return addr;
	return CALLER_ADDR2;
}

#ifdef CONFIG_TRACE_PREEMPT_TOGGLE
  extern void trace_preempt_on(unsigned long a0, unsigned long a1);
  extern void trace_preempt_off(unsigned long a0, unsigned long a1);
#else
/*
 * Use defines instead of static inlines because some arches will make code out
 * of the CALLER_ADDR, when we really want these to be a real nop.
 */
//# define trace_preempt_on(a0, a1) do { } while (0)
//# define trace_preempt_off(a0, a1) do { } while (0)
#endif

#ifdef CONFIG_FTRACE_MCOUNT_RECORD
/**
 *
 */
extern void ftrace_init(void);
#ifdef CC_USING_PATCHABLE_FUNCTION_ENTRY
//#define FTRACE_CALLSITE_SECTION	"__patchable_function_entries"
#else
#define FTRACE_CALLSITE_SECTION	"__mcount_loc"
#endif
#else

#endif

/*
 * Structure that defines an entry function trace.
 * It's already packed but the attribute "packed" is needed
 * to remove extra padding at the end.
 */
struct ftrace_graph_ent {
	unsigned long func; /* Current function */
	int depth;
} __packed;

/*
 * Structure that defines a return function trace.
 * It's already packed but the attribute "packed" is needed
 * to remove extra padding at the end.
 */
struct ftrace_graph_ret {
	unsigned long func; /* Current function */
	/* Number of functions that overran the depth limit for current task */
	unsigned long overrun;
	unsigned long long calltime;
	unsigned long long rettime;
	int depth;
} __packed;

/* Type of the callback handlers for tracing function graph*/
typedef void (*trace_func_graph_ret_t)(struct ftrace_graph_ret *); /* return */
typedef int (*trace_func_graph_ent_t)(struct ftrace_graph_ent *); /* entry */

extern int ftrace_graph_entry_stub(struct ftrace_graph_ent *trace);

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

struct fgraph_ops {
	trace_func_graph_ent_t		entryfunc;
	trace_func_graph_ret_t		retfunc;
};

/*
 * Stack of return addresses for functions
 * of a thread.
 * Used in struct thread_info
 */
struct ftrace_ret_stack {
	unsigned long ret;
	unsigned long func;
	unsigned long long calltime;
#ifdef CONFIG_FUNCTION_PROFILER
	unsigned long long subtime;
#endif
#ifdef HAVE_FUNCTION_GRAPH_FP_TEST
	unsigned long fp;
#endif
#ifdef HAVE_FUNCTION_GRAPH_RET_ADDR_PTR
	unsigned long *retp;
#endif
};

/*
 * Primary handler of a function return.
 * It relays on ftrace_return_to_handler.
 * Defined in entry_32/64.S
 */
extern void return_to_handler(void);

extern int
function_graph_enter(unsigned long ret, unsigned long func,
		     unsigned long frame_pointer, unsigned long *retp);

struct ftrace_ret_stack *
ftrace_graph_get_ret_stack(struct task_struct *task, int idx);

unsigned long ftrace_graph_ret_addr(struct task_struct *task, int *idx,
				    unsigned long ret, unsigned long *retp);

/*
 * Sometimes we don't want to trace a function with the function
 * graph tracer but we want them to keep traced by the usual function
 * tracer if the function graph tracer is not configured.
 */
#define __notrace_funcgraph		notrace

#define FTRACE_RETFUNC_DEPTH 50
#define FTRACE_RETSTACK_ALLOC_SIZE 32

extern int register_ftrace_graph(struct fgraph_ops *ops);
extern void unregister_ftrace_graph(struct fgraph_ops *ops);

extern bool ftrace_graph_is_dead(void);
extern void ftrace_graph_stop(void);

/* The current handlers in use */
extern trace_func_graph_ret_t ftrace_graph_return;
extern trace_func_graph_ent_t ftrace_graph_entry;

extern void ftrace_graph_init_task(struct task_struct *t);
extern void ftrace_graph_exit_task(struct task_struct *t);
extern void ftrace_graph_init_idle_task(struct task_struct *t, int cpu);

static inline void pause_graph_tracing(void)
{
	atomic_inc(&current->tracing_graph_pause);
}

static inline void unpause_graph_tracing(void)
{
	atomic_dec(&current->tracing_graph_pause);
}
#else /* !CONFIG_FUNCTION_GRAPH_TRACER */


#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

#ifdef CONFIG_TRACING

/* flags for current->trace */
enum {
	TSK_TRACE_FL_TRACE_BIT	= 0,
	TSK_TRACE_FL_GRAPH_BIT	= 1,
};
enum {
	TSK_TRACE_FL_TRACE	= 1 << TSK_TRACE_FL_TRACE_BIT,
	TSK_TRACE_FL_GRAPH	= 1 << TSK_TRACE_FL_GRAPH_BIT,
};

static inline void set_tsk_trace_trace(struct task_struct *tsk)
{
	set_bit(TSK_TRACE_FL_TRACE_BIT, &tsk->trace);
}

static inline void clear_tsk_trace_trace(struct task_struct *tsk)
{
	clear_bit(TSK_TRACE_FL_TRACE_BIT, &tsk->trace);
}

static inline int test_tsk_trace_trace(struct task_struct *tsk)
{
	return tsk->trace & TSK_TRACE_FL_TRACE;
}

static inline void set_tsk_trace_graph(struct task_struct *tsk)
{
	set_bit(TSK_TRACE_FL_GRAPH_BIT, &tsk->trace);
}

static inline void clear_tsk_trace_graph(struct task_struct *tsk)
{
	clear_bit(TSK_TRACE_FL_GRAPH_BIT, &tsk->trace);
}

static inline int test_tsk_trace_graph(struct task_struct *tsk)
{
	return tsk->trace & TSK_TRACE_FL_GRAPH;
}

enum ftrace_dump_mode;

extern enum ftrace_dump_mode ftrace_dump_on_oops;
extern int tracepoint_printk;

extern void disable_trace_on_warning(void);
extern int __disable_trace_on_warning;

int tracepoint_printk_sysctl(struct ctl_table *table, int write,
			     void *buffer, size_t *lenp, loff_t *ppos);

#else /* CONFIG_TRACING */

#endif /* CONFIG_TRACING */

#ifdef CONFIG_FTRACE_SYSCALLS

unsigned long arch_syscall_addr(int nr);

#endif /* CONFIG_FTRACE_SYSCALLS */

#endif /* _LINUX_FTRACE_H */

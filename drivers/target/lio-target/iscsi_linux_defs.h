#ifndef ISCSI_LINUX_DEFS_H
#define ISCSI_LINUX_DEFS_H

#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
/*
 * Used for utsname()-> access
 */
#include <linux/syscalls.h>
#include <linux/highmem.h>

/*
 * Threads.
 */
#define iscsi_daemon(thread, name, sigs)		\
do {							\
	daemonize(name);				\
	current->policy = SCHED_NORMAL;			\
	set_user_nice(current, -20);			\
	spin_lock_irq(&current->sighand->siglock);	\
	siginitsetinv(&current->blocked, (sigs));	\
	recalc_sigpending();				\
	(thread) = current;				\
	spin_unlock_irq(&current->sighand->siglock);	\
} while (0);

/*
 * Timers and Time
 */
#define MOD_TIMER(t, exp) mod_timer(t, (get_jiffies_64() + exp * HZ))
#define SETUP_TIMER(timer, t, d, func)			\
	timer.expires	= (get_jiffies_64() + t * HZ);	\
	timer.data	= (unsigned long) d;		\
	timer.function	= func;

#endif    /*** ISCSI_LINUX_DEFS_H ***/

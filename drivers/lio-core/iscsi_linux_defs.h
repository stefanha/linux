/*********************************************************************************
 * Filename:  iscsi_linux_defs.h
 *
 * This file contains wrapper definies related to LINUX functions.
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_linux_defs.h $
 *   $LastChangedRevision: 7131 $
 *   $LastChangedBy: nab $
 *   $LastChangedDate: 2007-08-25 17:03:55 -0700 (Sat, 25 Aug 2007) $
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


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
 * Userspace access.
 */
#define CALL_USERMODEHELPER(a, b, c)   call_usermodehelper(a, b, c, 1)


/*
 * kernel -- userspace copy commands
 */
#define COPY_FROM_USER(dest, src, len)		\
	copy_from_user((void *)(dest), (void *)(src), (len))
#define COPY_TO_USER(dest, src, len)		\
	copy_to_user((void *)(dest), (void *)(src), (len))

/*
 * Sockets.
 */
#define iscsi_sock_create(sock, f, t, p, uc, td) sock_create(f, t, p, sock)
#define iscsi_sock_connect(sock, s_in, size, td) sock->ops->connect(sock, s_in, size, 0)
#define iscsi_sock_bind(sock, s_in, size, td) sock->ops->bind(sock, s_in, size)
#define iscsi_sock_listen(sock, backlog, td) sock->ops->listen(sock, backlog)
#define iscsi_sock_accept(sock, newsock, td) sock->ops->accept(sock, newsock, 0)
#define iscsi_sock_sockopt_off(sock, p, o) \
	{ \
	int value = 0; \
	sock->ops->setsockopt(sock, p, o, (char *)&value, sizeof(value)); \
	}
#define iscsi_sock_sockopt_on(sock, p, o) \
	{ \
	int value = 1; \
	sock->ops->setsockopt(sock, p, o, (char *)&value, sizeof(value)); \
	}
#define iscsi_sock_sockopt_bindtodev(sock, dev) \
	{ \
	sock->ops->setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)); \
	}

/*
 * Threads.
 */
#define iscsi_daemon(thread, name, sigs) \
	daemonize(name); \
	current->policy = SCHED_NORMAL; \
	set_user_nice(current, -20); \
	spin_lock_irq(&current->sighand->siglock); \
	siginitsetinv(&current->blocked, (sigs)); \
	recalc_sigpending(); \
	(thread) = current; \
	spin_unlock_irq(&current->sighand->siglock);

/*
 * Timers and Time
 */
#define MOD_TIMER(timer, expires)	mod_timer(timer, (get_jiffies_64() + expires * HZ))
#define SETUP_TIMER(timer, t, d, func) \
	timer.expires	= (get_jiffies_64() + t * HZ); \
	timer.data	= (unsigned long) d; \
	timer.function	= func;

#endif    /*** ISCSI_LINUX_DEFS_H ***/

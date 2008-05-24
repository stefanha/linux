/*********************************************************************************
 * Filename:  iscsi_thread_queue.h
 *
 * This file contains the iSCSI Login Thread and Thread Queue definitions.
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_thread_queue.h $
 *   $LastChangedRevision: 7131 $
 *   $LastChangedBy: nab $
 *   $LastChangedDate: 2007-08-25 17:03:55 -0700 (Sat, 25 Aug 2007) $
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_THREAD_QUEUE_H
#define ISCSI_THREAD_QUEUE_H

/*
 * Defines for thread sets.
 */
extern int iscsi_thread_set_force_reinstatement (iscsi_conn_t *);
extern void iscsi_add_ts_to_inactive_list (struct se_thread_set_s *);
extern int iscsi_allocate_thread_sets (u32, int);
extern void iscsi_deallocate_thread_sets (int);
extern void iscsi_activate_thread_set (iscsi_conn_t *, struct se_thread_set_s *);
extern struct se_thread_set_s *iscsi_get_thread_set (int);
extern void iscsi_set_thread_clear (iscsi_conn_t *, u8);
extern void iscsi_set_thread_set_signal (iscsi_conn_t *, u8);
extern int iscsi_release_thread_set (iscsi_conn_t *, int);
extern iscsi_conn_t *iscsi_rx_thread_pre_handler (struct se_thread_set_s *, int);
extern iscsi_conn_t *iscsi_tx_thread_pre_handler (struct se_thread_set_s *, int);

#define INITIATOR_THREAD_SET_COUNT		4
#define TARGET_THREAD_SET_COUNT			4

#define ISCSI_RX_THREAD                         1
#define ISCSI_TX_THREAD                         2
#define ISCSI_RX_THREAD_NAME			"iscsi_trx"
#define ISCSI_TX_THREAD_NAME			"iscsi_ttx"
#define ISCSI_BLOCK_RX_THREAD			0x1
#define ISCSI_BLOCK_TX_THREAD			0x2
#define ISCSI_CLEAR_RX_THREAD			0x1
#define ISCSI_CLEAR_TX_THREAD			0x2
#define ISCSI_SIGNAL_RX_THREAD			0x1
#define ISCSI_SIGNAL_TX_THREAD			0x2

/* se_thread_set_t->status */
#define ISCSI_THREAD_SET_FREE			1
#define ISCSI_THREAD_SET_ACTIVE			2
#define ISCSI_THREAD_SET_DIE			3
#define ISCSI_THREAD_SET_RESET			4
#define ISCSI_THREAD_SET_DEALLOCATE_THREADS	5

typedef struct se_thread_set_s {
	u8			blocked_threads; /* flags used for blocking and restarting sets */
	u8			create_threads;	/* flag for creating threads */
	u8			delay_inactive; /* flag for delaying readding to inactive list */
	u8			status;		/* status for thread set */
	u8			signal_sent;	/* which threads have had signals sent */
	u8			stop_active;	/* used for stopping active sets during shutdown */
	u8			thread_clear;	/* flag for which threads exited first */
	u8			thread_count;	/* Active threads in the thread set */
	u32			thread_id;	/* Unique thread ID */
	iscsi_conn_t		*conn;		/* pointer to connection if set is active */
	spinlock_t		ts_state_lock;	/* used for controlling ts state accesses */
	struct semaphore		stop_active_sem; /* used for stopping active sets during shutdown */
	struct semaphore		rx_create_sem;	/* used for controlling thread creation */
	struct semaphore		tx_create_sem;	/* used for controlling thread creation */
	struct semaphore		rx_done_sem;	/* used for controlling killing */
	struct semaphore		tx_done_sem;	/* used for controlling killing */
	struct semaphore		rx_post_start_sem;
	struct semaphore		tx_post_start_sem;
	struct semaphore		rx_restart_sem; /* used for restarting thread queue */
	struct semaphore		tx_restart_sem; /* used for restarting thread queue */
	struct semaphore		rx_start_sem; 	/* used for normal unused blocking */
	struct semaphore		tx_start_sem;	/* used for normal unused blocking */
	struct task_struct		*rx_thread;	/* OS descriptor for rx thread */
	struct task_struct		*tx_thread;	/* OS descriptor for tx thread */
	struct se_thread_set_s *next;	/* next se_thread_set_t in list */
	struct se_thread_set_s *prev;	/* previous se_thread_set_t in list */
} se_thread_set_t;

#endif   /*** ISCSI_THREAD_QUEUE_H ***/


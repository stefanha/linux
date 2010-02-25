#ifndef ISCSI_THREAD_QUEUE_H
#define ISCSI_THREAD_QUEUE_H

/*
 * Defines for thread sets.
 */
extern int iscsi_thread_set_force_reinstatement(iscsi_conn_t *);
extern void iscsi_add_ts_to_inactive_list(struct se_thread_set_s *);
extern int iscsi_allocate_thread_sets(u32, int);
extern void iscsi_deallocate_thread_sets(int);
extern void iscsi_activate_thread_set(iscsi_conn_t *, struct se_thread_set_s *);
extern struct se_thread_set_s *iscsi_get_thread_set(int);
extern void iscsi_set_thread_clear(iscsi_conn_t *, u8);
extern void iscsi_set_thread_set_signal(iscsi_conn_t *, u8);
extern int iscsi_release_thread_set(iscsi_conn_t *, int);
extern iscsi_conn_t *iscsi_rx_thread_pre_handler(struct se_thread_set_s *, int);
extern iscsi_conn_t *iscsi_tx_thread_pre_handler(struct se_thread_set_s *, int);

extern int iscsi_target_tx_thread(void *);
extern int iscsi_target_rx_thread(void *);
extern struct iscsi_global_s *iscsi_global;

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
	/* flags used for blocking and restarting sets */
	u8	blocked_threads;
	/* flag for creating threads */
	u8	create_threads;
	/* flag for delaying readding to inactive list */
	u8	delay_inactive;
	/* status for thread set */
	u8	status;
	/* which threads have had signals sent */
	u8	signal_sent;
	/* used for stopping active sets during shutdown */
	u8	stop_active;
	/* flag for which threads exited first */
	u8	thread_clear;
	/* Active threads in the thread set */
	u8	thread_count;
	/* Unique thread ID */
	u32	thread_id;
	/* pointer to connection if set is active */
	iscsi_conn_t	*conn;
	/* used for controlling ts state accesses */
	spinlock_t	ts_state_lock;
	/* used for stopping active sets during shutdown */
	struct semaphore	stop_active_sem;
	/* used for controlling thread creation */
	struct semaphore	rx_create_sem;
	/* used for controlling thread creation */
	struct semaphore	tx_create_sem;
	/* used for controlling killing */
	struct semaphore	rx_done_sem;
	/* used for controlling killing */
	struct semaphore	tx_done_sem;
	/* Used for rx side post startup */
	struct semaphore	rx_post_start_sem;
	/* Used for tx side post startup */
	struct semaphore	tx_post_start_sem;
	/* used for restarting thread queue */
	struct semaphore	rx_restart_sem;
	/* used for restarting thread queue */
	struct semaphore	tx_restart_sem;
	/* used for normal unused blocking */
	struct semaphore	rx_start_sem;
	/* used for normal unused blocking */
	struct semaphore	tx_start_sem;
	/* OS descriptor for rx thread */
	struct task_struct	*rx_thread;
	/* OS descriptor for tx thread */
	struct task_struct	*tx_thread;
	/* se_thread_set_t in list list head*/
	struct list_head	ts_list;
} ____cacheline_aligned se_thread_set_t;

#endif   /*** ISCSI_THREAD_QUEUE_H ***/


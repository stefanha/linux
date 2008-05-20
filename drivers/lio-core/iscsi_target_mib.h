/*********************************************************************************
 * Filename:  iscsi_target_mib.h
 *
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007 Rising Tide Software, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *********************************************************************************/


#ifndef ISCSI_TARGET_MIB_H
#define ISCSI_TARGET_MIB_H

/* iSCSI session error types */
#define ISCSI_SESS_ERR_UNKNOWN		0
#define ISCSI_SESS_ERR_DIGEST		1
#define ISCSI_SESS_ERR_CXN_TIMEOUT	2
#define ISCSI_SESS_ERR_PDU_FORMAT	3

/* iSCSI session error stats */
typedef struct iscsi_sess_err_stats_s {
	spinlock_t	lock;
	u32		digest_errors;
	u32		cxn_timeout_errors;
	u32		pdu_format_errors;
	u32		last_sess_failure_type;
	char		last_sess_fail_rem_name[224];
} iscsi_sess_err_stats_t;

/* iSCSI login failure types (sub oids) */
#define ISCSI_LOGIN_FAIL_OTHER		2
#define ISCSI_LOGIN_FAIL_REDIRECT	3
#define ISCSI_LOGIN_FAIL_AUTHORIZE	4
#define ISCSI_LOGIN_FAIL_AUTHENTICATE	5
#define ISCSI_LOGIN_FAIL_NEGOTIATE	6

/* iSCSI login stats */
typedef struct iscsi_login_stats_s {
	spinlock_t	lock;
	u32		accepts;
	u32		other_fails;
	u32		redirects;
	u32		authorize_fails;
	u32		authenticate_fails;
	u32		negotiate_fails;	/* used for notifications */
	u64		last_fail_time;		/* time stamp (jiffies) */
	u32		last_fail_type;
	u32		last_intr_fail_addr;
	char		last_intr_fail_name[224];
} iscsi_login_stats_t;

/* iSCSI logout stats */
typedef struct iscsi_logout_stats_s {
	spinlock_t	lock;
	u32		normal_logouts;
	u32		abnormal_logouts;
} iscsi_logout_stats_t;

/* Structures for table index support */
typedef enum {
	ISCSI_INST_INDEX,
	ISCSI_PORTAL_INDEX,
	ISCSI_TARGET_AUTH_INDEX,
	ISCSI_SESSION_INDEX,
	ISCSI_CONNECTION_INDEX,
	SCSI_INST_INDEX,
	SCSI_DEVICE_INDEX,
	SCSI_PORT_INDEX,
	SCSI_AUTH_INTR_INDEX,
	INDEX_TYPE_MAX
} iscsi_index_t;

typedef struct iscsi_index_table_s {
	spinlock_t	lock;	
	u32 		iscsi_mib_index[INDEX_TYPE_MAX];
} iscsi_index_table_t;

/* Structure for table row iteration with seq_file */
typedef struct table_iter_s {
	int	ti_skip_body;
	u32	count_max;
	u32	count_cur;
	u32	ti_offset;
	u32	ti_header;
	void	*ti_ptr;
} table_iter_t;

/* Portal data */
typedef struct portal_data_s {
	u32	index;
	u32	ipaddr;
} portal_data_t;

/* SCSI Port stats */
typedef struct scsi_port_stats_s {
	u64	cmd_pdus;
	u64	tx_data_octets;
	u64	rx_data_octets;
} scsi_port_stats_t;

extern int init_iscsi_target_mib(void);
extern void remove_iscsi_target_mib(void);
extern void init_iscsi_index_table(void);
extern u32 get_new_index(iscsi_index_t);

#endif   /*** ISCSI_TARGET_MIB_H ***/


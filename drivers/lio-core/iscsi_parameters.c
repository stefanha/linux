/*********************************************************************************
 * Filename:  iscsi_parameters.c
 *
 * This file contains main functions related to iSCSI Parameter negotiation.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc. 
 * Copyright (c) 2007 Rising Tide Software, Inc.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
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


#ifdef LINUX
#include <linux/slab.h>
#include <iscsi_linux_defs.h>
#endif /* LINUX */

#include <iscsi_protocol.h>
#include <iscsi_debug.h>
#include <iscsi_debug_opcodes.h>
#ifdef _INITIATOR
#include <iscsi_initiator_core.h>
#include <iscsi_initiator_util.h>
#elif _TARGET
#include <iscsi_target_core.h>
#include <iscsi_target_util.h>
#else
#error Neither _INITIATOR or _TARGET defined!
#endif
#include <iscsi_parameters.h>

#define ISCSI_PARAMETER_C

extern iscsi_global_t *iscsi_global;

#ifdef LINUX_KERNEL_22
extern char * strstr(const char * s1,const char * s2)
{
	int l1, l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *) s1;

	l1 = strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1,s2,l2))
			return (char *) s1;
		s1++;
	}
	return NULL;
}
#endif

/*	iscsi_login_rx_data():
 *
 *
 */
extern int iscsi_login_rx_data(
	iscsi_conn_t *conn,
	char *buf,
	int length,
	int role)
{
	int rx_got;
	struct iovec iov;
	
	TRACE_ENTER

	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_len	= length;
	iov.iov_base	= buf;

	/*
	 * Initial Marker-less Interval.
	 * Add the values regardless of IFMarker/OFMarker, considering
	 * it may not be negoitated yet.
	 */
	if (role == INITIATOR)
		conn->if_marker += length;
	else if (role == TARGET)
		conn->of_marker += length;
	else {
		TRACE_ERROR("Unknown role: 0x%02x.\n", role);
		return(-1);
	}

	rx_got = rx_data(conn, &iov, 1, length);
	if (rx_got != length) {
		TRACE_ERROR("rx_data returned %d, expecting %d.\n",
				rx_got, length);
		return(-1);
	}
		
	TRACE_LEAVE
	return(0);
}

/*	iscsi_login_tx_data():
 *
 *
 */
extern int iscsi_login_tx_data(
	iscsi_conn_t *conn,
	char *pdu_buf,
	char *text_buf,
	int text_length,
	int role)
{
	int length, tx_sent;
	struct iovec iov[2];
	
	TRACE_ENTER

	length = (ISCSI_HDR_LEN + text_length);
	
	memset(&iov[0], 0, 2 * sizeof(struct iovec));
	iov[0].iov_len		= ISCSI_HDR_LEN;
	iov[0].iov_base		= pdu_buf;
	iov[1].iov_len		= text_length;
	iov[1].iov_base		= text_buf;

	/*
	 * Initial Marker-less Interval.
	 * Add the values regardless of IFMarker/OFMarker, considering
	 * it may not be negoitated yet.
	 */
	if (role == INITIATOR)
		conn->of_marker += length;
	else if (role == TARGET)
		conn->if_marker += length;
	else {
		TRACE_ERROR("Unknown role: 0x%02x.\n", role);
		return(-1);
	}
		
	tx_sent = tx_data(conn, &iov[0], 2, length);
	if (tx_sent != length) {
		TRACE_ERROR("tx_data returned %d, expecting %d.\n",
				tx_sent, length);
		return(-1);
	}
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_dump_connection_ops():
 *
 *
 */
extern void iscsi_dump_conn_ops(iscsi_conn_ops_t *conn_ops)
{
	PYXPRINT("HeaderDigest: %s\n", (conn_ops->HeaderDigest) ? "CRC32C" : "None");
	PYXPRINT("DataDigest: %s\n", (conn_ops->DataDigest) ? "CRC32C" : "None");
	PYXPRINT("MaxRecvDataSegmentLength: %u\n", conn_ops->MaxRecvDataSegmentLength);
	PYXPRINT("OFMarker: %s\n", (conn_ops->OFMarker) ? "Yes" : "No");
	PYXPRINT("IFMarker: %s\n", (conn_ops->IFMarker) ? "Yes" : "No");
	if (conn_ops->OFMarker)
		PYXPRINT("OFMarkInt: %u\n", conn_ops->OFMarkInt);
	if (conn_ops->IFMarker)
		PYXPRINT("IFMarkInt: %u\n", conn_ops->IFMarkInt);
}
	
/*	iscsi_dump_session_ops():
 *
 *
 */
extern void iscsi_dump_sess_ops(iscsi_sess_ops_t *sess_ops)
{
	PYXPRINT("InitiatorName: %s\n", sess_ops->InitiatorName);
	PYXPRINT("InitiatorAlias: %s\n", sess_ops->InitiatorAlias);
	PYXPRINT("TargetName: %s\n", sess_ops->TargetName);
	PYXPRINT("TargetAlias: %s\n", sess_ops->TargetAlias);
	PYXPRINT("TargetPortalGroupTag: %hu\n", sess_ops->TargetPortalGroupTag);
	PYXPRINT("MaxConnections: %hu\n", sess_ops->MaxConnections);
	PYXPRINT("InitialR2T: %s\n", (sess_ops->InitialR2T) ? "Yes" : "No");
	PYXPRINT("ImmediateData: %s\n", (sess_ops->ImmediateData) ? "Yes" : "No");
	PYXPRINT("MaxBurstLength: %u\n", sess_ops->MaxBurstLength);
	PYXPRINT("FirstBurstLength: %u\n", sess_ops->FirstBurstLength);
	PYXPRINT("DefaultTime2Wait: %hu\n", sess_ops->DefaultTime2Wait);
	PYXPRINT("DefaultTime2Retain: %hu\n", sess_ops->DefaultTime2Retain);
	PYXPRINT("MaxOutstandingR2T: %hu\n", sess_ops->MaxOutstandingR2T);
	PYXPRINT("DataPDUInOrder: %s\n", (sess_ops->DataPDUInOrder) ? "Yes" : "No");
	PYXPRINT("DataSequenceInOrder: %s\n", (sess_ops->DataSequenceInOrder) ? "Yes" : "No");
	PYXPRINT("ErrorRecoveryLevel: %hu\n", sess_ops->ErrorRecoveryLevel);
	PYXPRINT("SessionType: %s\n", (sess_ops->SessionType) ? "Discovery" : "Normal");
}

/*	iscsi_print_params():
 *
 *
 */
extern void iscsi_print_params(iscsi_param_list_t *param_list)
{
	iscsi_param_t *param;
	
	TRACE_ENTER

	for (param = param_list->param_start; param; param = param->next) {
		PYXPRINT("%s: %s\n", param->name, param->value);
	}
		
	TRACE_LEAVE
}

/*	iscsi_set_default_param():
 *
 *
 */
static iscsi_param_t *iscsi_set_default_param(char *name, char *value, u8 phase,
		u8 scope,  u8 sender, u16 type_range, u8 use)
{
	iscsi_param_t *param = NULL;

	TRACE_ENTER

	if (!(param = (iscsi_param_t *) kmalloc(sizeof(iscsi_param_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for parameter.\n");
		goto out;
	}
	memset(param, 0, sizeof(iscsi_param_t));
		
	if (!(param->name = (char *) kmalloc(strlen(name) + 1, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for parameter name.\n");
		goto out;
	}
	memset(param->name, 0, strlen(name) + 1);
	
	if (!(param->value = (char *) kmalloc(strlen(value) + 1, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for parameter value.\n");
		goto out;
	}
	memset(param->value, 0, strlen(value) + 1);
	
	memcpy(param->name, name, strlen(name));
	param->name[strlen(name)] = '\0';
	memcpy(param->value, value, strlen(value));
	param->value[strlen(value)] = '\0';
	param->phase		= phase;
	param->scope		= scope;
	param->sender		= sender;
	param->use		= use;
	param->type_range	= type_range;

	switch (param->type_range) {
		case TYPERANGE_BOOL_AND:
			param->type = TYPE_BOOL_AND;
			break;
		case TYPERANGE_BOOL_OR:
			param->type = TYPE_BOOL_OR;
			break;
		case TYPERANGE_0_TO_2:
		case TYPERANGE_0_TO_3600:
		case TYPERANGE_0_TO_32767:
		case TYPERANGE_0_TO_65535:
		case TYPERANGE_1_TO_65535:
		case TYPERANGE_2_TO_3600:
		case TYPERANGE_512_TO_16777215:
			param->type = TYPE_NUMBER;
			break;
		case TYPERANGE_AUTH:
		case TYPERANGE_DIGEST:
			param->type = TYPE_VALUE_LIST | TYPE_STRING;
			break;
		case TYPERANGE_MARKINT:
			param->type = TYPE_NUMBER_RANGE;
			param->type_range |= TYPERANGE_1_TO_65535;
			break;
		case TYPERANGE_ISCSINAME:
		case TYPERANGE_SESSIONTYPE:
		case TYPERANGE_TARGETADDRESS:
		case TYPERANGE_UTF8:
			param->type = TYPE_STRING;
			break;
		default:
			TRACE_ERROR("Unknown type_range 0x%02x\n",
					param->type_range);
			goto out;
	}
	
	TRACE_LEAVE
	return(param);
out:
	if (param) {
		kfree(param->value);
		kfree(param->name);
		kfree(param);
	}

	return(NULL);
}

#define ADD_PARAM_TO_LIST(list, param)			\
	if (!list)					\
		list = param;				\
	else {						\
		iscsi_param_t *tmp_param = NULL;	\
		tmp_param = list;			\
		while (tmp_param && tmp_param->next)	\
			tmp_param = tmp_param->next;	\
		tmp_param->next = param;		\
	}

/*	iscsi_set_default_params():
 *
 *
 */
//#warning Add extension keys
extern int iscsi_create_default_params(iscsi_param_list_t **param_list_ptr)
{
	iscsi_param_t *param = NULL;
	iscsi_param_list_t *param_list;
	
	TRACE_ENTER

	if (!(param_list = (iscsi_param_list_t *)
			kmalloc(sizeof(iscsi_param_list_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for"
				" iscsi_param_list_t.\n");
		return(-1);
	}
	memset(param_list, 0, sizeof(iscsi_param_list_t));
		
	/*
	 * The format for setting the initial parameter definitions are:
	 *
	 * Parameter name:
	 * Initial value:
	 * Allowable phase:
	 * Scope:
	 * Allowable senders:
	 * Typerange:
	 * Use:
	 */
	if (!(param = iscsi_set_default_param(AUTHMETHOD, INITIAL_AUTHMETHOD,
			PHASE_SECURITY, SCOPE_CONNECTION_ONLY, SENDER_BOTH,
			TYPERANGE_AUTH, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);	
	if (!(param = iscsi_set_default_param(HEADERDIGEST, INITIAL_HEADERDIGEST,
			PHASE_OPERATIONAL, SCOPE_CONNECTION_ONLY, SENDER_BOTH,
			TYPERANGE_DIGEST, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(DATADIGEST, INITIAL_DATADIGEST,
			PHASE_OPERATIONAL, SCOPE_CONNECTION_ONLY, SENDER_BOTH,
			TYPERANGE_DIGEST, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(MAXCONNECTIONS, INITIAL_MAXCONNECTIONS,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_1_TO_65535, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(SENDTARGETS, INITIAL_SENDTARGETS,
			PHASE_FFP0, SCOPE_SESSION_WIDE, SENDER_INITIATOR,
			TYPERANGE_UTF8, 0)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(TARGETNAME, INITIAL_TARGETNAME,
			PHASE_DECLARATIVE, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_ISCSINAME, USE_ALL)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(INITIATORNAME, INITIAL_INITIATORNAME,
			PHASE_DECLARATIVE, SCOPE_SESSION_WIDE, SENDER_INITIATOR,
			TYPERANGE_ISCSINAME, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(TARGETALIAS, INITIAL_TARGETALIAS,
			PHASE_DECLARATIVE, SCOPE_SESSION_WIDE, SENDER_TARGET,
			TYPERANGE_UTF8, USE_ALL)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(INITIATORALIAS, INITIAL_INITIATORALIAS,
			PHASE_DECLARATIVE, SCOPE_SESSION_WIDE, SENDER_INITIATOR,
			TYPERANGE_UTF8, USE_ALL)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(TARGETADDRESS, INITIAL_TARGETADDRESS,
			PHASE_DECLARATIVE, SCOPE_SESSION_WIDE, SENDER_TARGET,
			TYPERANGE_TARGETADDRESS, USE_ALL)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(TARGETPORTALGROUPTAG, INITIAL_TARGETPORTALGROUPTAG,
			PHASE_DECLARATIVE, SCOPE_SESSION_WIDE, SENDER_TARGET,
			TYPERANGE_0_TO_65535, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(INITIALR2T, INITIAL_INITIALR2T,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_BOOL_OR, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(IMMEDIATEDATA, INITIAL_IMMEDIATEDATA,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_BOOL_AND, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(MAXRECVDATASEGMENTLENGTH, INITIAL_MAXRECVDATASEGMENTLENGTH,
			PHASE_OPERATIONAL, SCOPE_CONNECTION_ONLY, SENDER_BOTH,
			TYPERANGE_512_TO_16777215, USE_ALL)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(MAXBURSTLENGTH, INITIAL_MAXBURSTLENGTH,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_512_TO_16777215, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(FIRSTBURSTLENGTH, INITIAL_FIRSTBURSTLENGTH,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_512_TO_16777215, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(DEFAULTTIME2WAIT, INITIAL_DEFAULTTIME2WAIT,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_0_TO_3600, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(DEFAULTTIME2RETAIN, INITIAL_DEFAULTTIME2RETAIN,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_0_TO_3600, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(MAXOUTSTANDINGR2T, INITIAL_MAXOUTSTANDINGR2T,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_1_TO_65535, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(DATAPDUINORDER, INITIAL_DATAPDUINORDER,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_BOOL_OR, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(DATASEQUENCEINORDER, INITIAL_DATASEQUENCEINORDER,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_BOOL_OR, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(ERRORRECOVERYLEVEL, INITIAL_ERRORRECOVERYLEVEL,
			PHASE_OPERATIONAL, SCOPE_SESSION_WIDE, SENDER_BOTH,
			TYPERANGE_0_TO_2, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(SESSIONTYPE, INITIAL_SESSIONTYPE,
			PHASE_DECLARATIVE, SCOPE_SESSION_WIDE, SENDER_INITIATOR,
			TYPERANGE_SESSIONTYPE, USE_LEADING_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(IFMARKER, INITIAL_IFMARKER,
			PHASE_OPERATIONAL, SCOPE_CONNECTION_ONLY, SENDER_BOTH,
			TYPERANGE_BOOL_AND, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(OFMARKER, INITIAL_OFMARKER,
			PHASE_OPERATIONAL, SCOPE_CONNECTION_ONLY, SENDER_BOTH,
			TYPERANGE_BOOL_AND, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(IFMARKINT, INITIAL_IFMARKINT,
			PHASE_OPERATIONAL, SCOPE_CONNECTION_ONLY, SENDER_BOTH,
			TYPERANGE_MARKINT, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);
	if (!(param = iscsi_set_default_param(OFMARKINT, INITIAL_OFMARKINT,
			PHASE_OPERATIONAL, SCOPE_CONNECTION_ONLY, SENDER_BOTH,
			TYPERANGE_MARKINT, USE_INITIAL_ONLY)))
		goto out;
	ADD_PARAM_TO_LIST(param_list->param_start, param);

	*param_list_ptr = param_list;
	
	TRACE_LEAVE
	return(0);
out:
	iscsi_release_param_list(param_list);
	TRACE_LEAVE
	return(-1);
}

/*	iscsi_set_keys_to_negotiate():
 *
 *
 */
extern int iscsi_set_keys_to_negotiate(int role, int sessiontype, iscsi_param_list_t *param_list)
{
	iscsi_param_t *param;
	
	TRACE_ENTER

	for (param = param_list->param_start; param; param = param->next) {
		param->state = 0;
		if (!strcmp(param->name, AUTHMETHOD)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, HEADERDIGEST)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, DATADIGEST)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, MAXCONNECTIONS)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, TARGETNAME)) {
			if ((role == INITIATOR) && (sessiontype)) {
				SET_PSTATE_NEGOTIATE(param);
				SET_USE_INITIAL_ONLY(param);
			}
		} else if (!strcmp(param->name, INITIATORNAME)) {
			if (role == INITIATOR)
				SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, TARGETALIAS)) {
			if ((role == TARGET) && (param->value))
				SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, INITIATORALIAS)) {
			if ((role == INITIATOR) && (param->value))
				SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, TARGETPORTALGROUPTAG)) {
			if (role == TARGET)
				SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, INITIALR2T)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, IMMEDIATEDATA)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, MAXRECVDATASEGMENTLENGTH)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, MAXBURSTLENGTH)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, FIRSTBURSTLENGTH)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, DEFAULTTIME2WAIT)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, DEFAULTTIME2RETAIN)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, MAXOUTSTANDINGR2T)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, DATAPDUINORDER)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, DATASEQUENCEINORDER)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, ERRORRECOVERYLEVEL)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, SESSIONTYPE)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, IFMARKER)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, OFMARKER)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, IFMARKINT)) {
			SET_PSTATE_NEGOTIATE(param);
		} else if (!strcmp(param->name, OFMARKINT)) {
			SET_PSTATE_NEGOTIATE(param);
		}	
	}
			
	TRACE_LEAVE
	return(0);
}

/*	iscsi_set_keys_irrelevant_for_discovery():
 *
 *
 */
extern int iscsi_set_keys_irrelevant_for_discovery(iscsi_param_list_t *param_list)
{
	iscsi_param_t *param;

	TRACE_ENTER

	for (param = param_list->param_start; param; param = param->next) {
		if (!strcmp(param->name, MAXCONNECTIONS))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, INITIALR2T))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, IMMEDIATEDATA))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, MAXBURSTLENGTH))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, FIRSTBURSTLENGTH))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, MAXOUTSTANDINGR2T))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, DATAPDUINORDER))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, DATASEQUENCEINORDER))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, ERRORRECOVERYLEVEL))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, DEFAULTTIME2WAIT))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, DEFAULTTIME2RETAIN))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, IFMARKER))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, OFMARKER))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, IFMARKINT))
			param->state &= ~PSTATE_NEGOTIATE;
		else if (!strcmp(param->name, OFMARKINT))
			param->state &= ~PSTATE_NEGOTIATE;
	}
		
	TRACE_LEAVE
	return(0);
}

/*	iscsi_copy_param_list():
 *
 *
 */
extern int iscsi_copy_param_list(
	iscsi_param_list_t **dst_param_list,
	iscsi_param_list_t *src_param_list,
	int leading)
{
	iscsi_param_t *new_param = NULL, *param = NULL;
	iscsi_param_list_t *param_list = NULL;
	
	TRACE_ENTER

	if (!(param_list = (iscsi_param_list_t *)
	      kmalloc(sizeof(iscsi_param_list_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for"
				" iscsi_param_list_t.\n");
		goto err_out;
	}
	memset(param_list, 0, sizeof(iscsi_param_list_t));
		
	for (param = src_param_list->param_start; param; param = param->next) {
		if (!leading && (param->scope & SCOPE_SESSION_WIDE)) {
			if ((strcmp(param->name, "TargetName") != 0) &&
			    (strcmp(param->name, "InitiatorName") != 0) &&
			    (strcmp(param->name, "TargetPortalGroupTag") != 0))
				continue;
		}

		if (!(new_param = (iscsi_param_t *)
		      kmalloc(sizeof(iscsi_param_t), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate memory for"
				" iscsi_param_t.\n");
			goto err_out;
		}
		memset(new_param, 0, sizeof(iscsi_param_t));

		new_param->set_param = param->set_param;
		new_param->phase = param->phase;
		new_param->scope = param->scope;
		new_param->sender = param->sender;
		new_param->type = param->type;
		new_param->use = param->use;
		new_param->type_range = param->type_range;
		
		if (!(new_param->name = (char *)
		      kmalloc(strlen(param->name) + 1, GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate memory for"
				" parameter name.\n");
			goto err_out;
		}
	        memset(new_param->name, 0, strlen(param->name) + 1);

		if (!(new_param->value = (char *)
		      kmalloc(strlen(param->value) + 1, GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate memory for"
				" parameter value.\n");
			goto err_out;
		}
		memset(new_param->value, 0, strlen(param->value) + 1);

		memcpy(new_param->name, param->name, strlen(param->name));
		new_param->name[strlen(param->name)] = '\0';
		memcpy(new_param->value, param->value, strlen(param->value));
		new_param->value[strlen(param->value)] = '\0';

		ADD_PARAM_TO_LIST(param_list->param_start, new_param);
	}

	if (param_list->param_start)
		*dst_param_list = param_list;
	else {
		TRACE_ERROR("No parameters allocated.\n");
		goto err_out;
	}	
	
	TRACE_LEAVE
	return(0);

err_out:
	iscsi_release_param_list(param_list);
	TRACE_LEAVE
	return(-1);
}

/*	iscsi_release_extra_responses():
 *
 *
 */
static void iscsi_release_extra_responses(iscsi_param_list_t *param_list)
{
	iscsi_extra_response_t *extra_response, *extra_response_prev = NULL;

	TRACE_ENTER

	for (extra_response = param_list->extra_response_start; extra_response;
	     extra_response = extra_response->next) {
		if (extra_response_prev)
			kfree(extra_response_prev);
		extra_response_prev = extra_response;
	}
	if (extra_response_prev)
		kfree(extra_response_prev);

	param_list->extra_response_start = NULL;
			
	TRACE_LEAVE
}

/*	iscsi_release_param_list():
 *
 *
 */
extern void iscsi_release_param_list(iscsi_param_list_t *param_list)
{
	iscsi_param_t *param = NULL, *param_next = NULL;
	
	TRACE_ENTER

	param = param_list->param_start;
	while (param) {
		param_next = param->next;

		if (param->name) {
			kfree(param->name);
			param->name = NULL;
		}
		if (param->value) {
			kfree(param->value);
			param->value = NULL;
		}
		kfree(param);
		param = NULL;

		param = param_next;
	}
		
	iscsi_release_extra_responses(param_list);
	
	kfree(param_list);
	
	TRACE_LEAVE
	return;
}

/*	iscsi_find_param_from_key():
 *
 *
 */
extern iscsi_param_t *iscsi_find_param_from_key(char *key, iscsi_param_list_t *param_list)
{
	iscsi_param_t *param;

	TRACE_ENTER

	if (!key || !param_list) {
		TRACE_ERROR("Key or parameter list pointer is NULL.\n");
		return(NULL);
	}

	for (param = param_list->param_start; param; param = param->next) {
		if (!strcmp(key, param->name))
			break;
	}

	if (!param) {
		TRACE_ERROR("Unable to locate key \"%s\".\n", key);
		return(NULL);
	}

	TRACE_LEAVE
	return(param);
}

/*	iscsi_extract_key_value():
 *
 *
 */
extern int iscsi_extract_key_value(char *textbuf, char **key, char **value)
{
	TRACE_ENTER

	if (!(*value = strchr(textbuf, '='))) {
		TRACE_ERROR("Unable to locate \"=\" seperator for key,"
				" ignoring request.\n");
		return(-1);
	}

	*key = textbuf;
	**value = '\0';
	*value = *value + 1;

	TRACE_LEAVE
	return(0);
}

/*	iscsi_update_param_value():
 *
 *
 */
extern int iscsi_update_param_value(iscsi_param_t *param, char *value)
{
	TRACE_ENTER

#ifndef ERLTWO
	if (!strncmp(param->name, ERRORRECOVERYLEVEL, sizeof(param->name)) &&
	    !strncmp(value, "2", 1)) {
		TRACE_ERROR("ErrorRecoveryLevel=2 not supported in this release.\n");
		return(-1);
	}
#endif
#ifndef ERLONE
	if (!strncmp(param->name, ERRORRECOVERYLEVEL, sizeof(param->name)) &&
	    !strncmp(value, "1", 1)) {
		TRACE_ERROR("ErrorRecoveryLevel=1 not supported in this release.\n");
		return(-1);
	}
#endif

	kfree(param->value);
	if (!(param->value = kmalloc(strlen(value) + 1, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for value.\n");
		return(-1);
	}

	memset(param->value, 0, strlen(value) + 1);
	memcpy(param->value, value, strlen(value));
	param->value[strlen(value)] = '\0';

	TRACE(TRACE_PARAM, "iSCSI Parameter updated to %s=%s\n", param->name, param->value);

	TRACE_LEAVE
	return(0);
}

/*	iscsi_add_notunderstood_response():
 *
 *
 */
static int iscsi_add_notunderstood_response(char *key, char *value, iscsi_param_list_t *param_list)
{
	iscsi_extra_response_t *extra_response, *extra_response_ptr = NULL;
	
	TRACE_ENTER
	
	if (strlen(value) > MAX_KEY_VALUE_LENGTH) {
		TRACE_ERROR("Value for notunderstood key \"%s\" exceeds %d,"
			" protocol error.\n", key, MAX_KEY_VALUE_LENGTH);
		return(-1);
	}
	
	if (!(extra_response = (iscsi_extra_response_t *)
	      kmalloc(sizeof(iscsi_extra_response_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for"
			" iscsi_extra_response_t.\n");
		return(-1);
	}
	memset(extra_response, 0, sizeof(iscsi_extra_response_t));

	strncpy(extra_response->key, key, strlen(key) + 1);
	strncpy(extra_response->value, NOTUNDERSTOOD, strlen(NOTUNDERSTOOD) + 1);

	if (!param_list->extra_response_start)
		param_list->extra_response_start = extra_response;
	else {
		extra_response_ptr = param_list->extra_response_start;
		while (extra_response_ptr && extra_response_ptr->next)
			extra_response_ptr = extra_response_ptr->next;
		extra_response_ptr->next = extra_response;
	}
	
	TRACE_LEAVE
	return(0);
}
	
/*	iscsi_check_for_auth_key():
 *
 *
 */
static int iscsi_check_for_auth_key(char *key)
{
	TRACE_ENTER
	
	/*
	 * RFC 1994
	 */
	if (!strcmp(key, "CHAP_A") || !strcmp(key, "CHAP_I") ||
	    !strcmp(key, "CHAP_C") || !strcmp(key, "CHAP_N") ||
	    !strcmp(key, "CHAP_R"))
		return(1);

	/*
	 * RFC 2945
	 */
	if (!strcmp(key, "SRP_U") || !strcmp(key, "SRP_N") ||
	    !strcmp(key, "SRP_g") || !strcmp(key, "SRP_s") ||
	    !strcmp(key, "SRP_A") || !strcmp(key, "SRP_B") ||
	    !strcmp(key, "SRP_M") || !strcmp(key, "SRP_HM"))
		return(1);
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_check_proposer_for_optional_reply():
 *
 *
 */
static void iscsi_check_proposer_for_optional_reply(iscsi_param_t *param)
{
	TRACE_ENTER
	
	if (IS_TYPE_BOOL_AND(param)) {
		if (!strcmp(param->value, NO))
			SET_PSTATE_REPLY_OPTIONAL(param);
	} else if (IS_TYPE_BOOL_OR(param)) {
		if (!strcmp(param->value, YES))
			SET_PSTATE_REPLY_OPTIONAL(param);
	} else if (IS_TYPE_NUMBER(param)) {
		if (!strcmp(param->name, MAXRECVDATASEGMENTLENGTH))
			SET_PSTATE_REPLY_OPTIONAL(param);
	} else if (IS_PHASE_DECLARATIVE(param))
		SET_PSTATE_REPLY_OPTIONAL(param);
	
	TRACE_LEAVE
}	
    	
/*	iscsi_check_boolean_value():
 *
 *
 */
static int iscsi_check_boolean_value(iscsi_param_t *param, char *value)
{
	TRACE_ENTER
	
	if (strcmp(value, YES) && strcmp(value, NO)) {
		TRACE_ERROR("Illegal value for \"%s\", must be either"
			" \"%s\" or \"%s\".\n", param->name, YES, NO);
		return(-1);
	}

	TRACE_LEAVE
	return(0);
}

/*	iscsi_check_numerical_value():
 *
 *
 */
static int iscsi_check_numerical_value(iscsi_param_t *param, char *value_ptr)
{
	char *tmpptr;
	int value = 0;
	
	TRACE_ENTER

	value = simple_strtoul(value_ptr, &tmpptr, 0);
		
//#warning FIXME: Fix this
#if 0
	if (strspn(endptr, WHITE_SPACE) != strlen(endptr)) {
		TRACE_ERROR("Illegal value \"%s\" for \"%s\".\n",
			value, param->name);
		return(-1);
	}
#endif
	if (IS_TYPERANGE_0_TO_2(param)) {
		if ((value < 0) || (value > 2)) {
			TRACE_ERROR("Illegal value for \"%s\", must be between"
				" 0 and 2.\n", param->name);
			return(-1);
		}
		return(0);
	}
	if (IS_TYPERANGE_0_TO_3600(param)) {
		if ((value < 0) || (value > 3600)) {
			TRACE_ERROR("Illegal value for \"%s\", must be between"
				" 0 and 3600.\n", param->name);
			return(-1);
		}
		return(0);
	}
	if (IS_TYPERANGE_0_TO_32767(param)) {
		if ((value < 0) || (value > 32767)) {
			TRACE_ERROR("Illegal value for \"%s\", must be between"
				" 0 and 32767.\n", param->name);
			return(-1);
		}
		return(0);
	}
	if (IS_TYPERANGE_0_TO_65535(param)) {
		if ((value < 0) || (value > 65535)) {
			TRACE_ERROR("Illegal value for \"%s\", must be between"
				" 0 and 65535.\n", param->name);
			return(-1);
		}
		return(0);
	}
	if (IS_TYPERANGE_1_TO_65535(param)) {
		if ((value < 1) || (value > 65535)) {
			TRACE_ERROR("Illegal value for \"%s\", must be between"
				" 1 and 65535.\n", param->name);
			return(-1);
		}
		return(0);
	}
	if (IS_TYPERANGE_2_TO_3600(param)) {
		if ((value < 2) || (value > 3600)) {
			TRACE_ERROR("Illegal value for \"%s\", must be between"
				" 2 and 3600.\n", param->name);
			return(-1);
		}
		return(0);
	}
	if (IS_TYPERANGE_512_TO_16777215(param)) {
		if ((value < 512) || (value > 16777215)) {
			TRACE_ERROR("Illegal value for \"%s\", must be between"
				" 512 and 16777215.\n", param->name);
			return(-1);
		}
		return(0);
	}
					
	TRACE_LEAVE
	return(0);
}

/*	iscsi_check_numerical_range_value():
 *
 *
 */
static int iscsi_check_numerical_range_value(iscsi_param_t *param, char *value)
{
	char *left_val_ptr = NULL, *right_val_ptr = NULL;
	char *tilde_ptr = NULL, *tmp_ptr = NULL;
	u32 left_val, right_val, local_left_val, local_right_val;
	
	TRACE_ENTER

	if (strcmp(param->name, IFMARKINT) &&
	    strcmp(param->name, OFMARKINT)) {
	       TRACE_ERROR("Only parameters \"%s\" or \"%s\" may contain a"
			" numerical range value.\n", IFMARKINT, OFMARKINT);
		return(-1);
	}		

	if (IS_PSTATE_PROPOSER(param))
		return(0);

	if (!(tilde_ptr = strchr(value, '~'))) {
		TRACE_ERROR("Unable to locate numerical range indicator"
			" \"~\" for \"%s\".\n", param->name);
		return(-1);
	}
	*tilde_ptr = '\0';
	
	left_val_ptr = value;
	right_val_ptr = value + strlen(left_val_ptr) + 1;

	if (iscsi_check_numerical_value(param, left_val_ptr) < 0)
		return(-1);
	if (iscsi_check_numerical_value(param, right_val_ptr) < 0)
		return(-1);

	left_val = simple_strtoul(left_val_ptr, &tmp_ptr, 0);
	right_val = simple_strtoul(right_val_ptr, &tmp_ptr, 0);
	*tilde_ptr = '~';
	
	if (right_val < left_val) {
		TRACE_ERROR("Numerical range for parameter \"%s\" contains"
			" a right value which is less than the left.\n",
				param->name);
		return(-1);
	}

	/*
	 * For now,  enforce reasonable defaults for [I,O]FMarkInt.
	 */
	if (!(tilde_ptr = strchr(param->value, '~'))) {
		TRACE_ERROR("Unable to locate numerical range indicator"
			" \"~\" for \"%s\".\n", param->name);
		return(-1);
	}
	*tilde_ptr = '\0';

	left_val_ptr = param->value;
	right_val_ptr = param->value + strlen(left_val_ptr) + 1;	
	
	local_left_val = simple_strtoul(left_val_ptr, &tmp_ptr, 0);
	local_right_val = simple_strtoul(right_val_ptr, &tmp_ptr, 0);
	*tilde_ptr = '~';

	if (param->set_param) {
		if ((left_val < local_left_val) || (right_val < local_left_val)) {
			TRACE_ERROR("Passed value range \"%u~%u\" is below minimum"
				" left value \"%u\" for key \"%s\", rejecting.\n",
				left_val, right_val, local_left_val, param->name);
			return(-1);
		}
	} else {
		if ((left_val < local_left_val) && (right_val < local_left_val)) {
			TRACE_ERROR("Received value range \"%u~%u\" is below minimum"
				" left value \"%u\" for key \"%s\", rejecting.\n",
				left_val, right_val, local_left_val, param->name);
			SET_PSTATE_REJECT(param);
			if (iscsi_update_param_value(param, REJECT) < 0)
				return(-1);
		}
	}
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_check_string_or_list_value():
 *
 *
 */
static int iscsi_check_string_or_list_value(iscsi_param_t *param, char *value)
{
	TRACE_ENTER

	if (IS_PSTATE_PROPOSER(param))
		return(0);

	if (IS_TYPERANGE_AUTH_PARAM(param)) {
		if (strcmp(value, KRB5) && strcmp(value, SPKM1) &&
		    strcmp(value, SPKM2) && strcmp(value, SRP) &&
		    strcmp(value, CHAP) && strcmp(value, NONE)) {
			TRACE_ERROR("Illegal value for \"%s\", must be"
				" \"%s\", \"%s\", \"%s\", \"%s\", \"%s\""
				" or \"%s\".\n", param->name, KRB5,
					SPKM1, SPKM2, SRP, CHAP, NONE);
			return(-1);
		}
	}
	if (IS_TYPERANGE_DIGEST_PARAM(param)) {
		if (strcmp(value, CRC32C) && strcmp(value, NONE)) {
			TRACE_ERROR("Illegal value for \"%s\", must be"
				" \"%s\" or \"%s\".\n", param->name,
					CRC32C, NONE);
			return(-1);
		}
	}
	if (IS_TYPERANGE_SESSIONTYPE(param)) {
		if (strcmp(value, DISCOVERY) && strcmp(value, NORMAL)) {
			TRACE_ERROR("Illegal value for \"%s\", must be"
				" \"%s\" or \"%s\".\n", param->name,
					DISCOVERY, NORMAL);
			return(-1);
		}
	}

	TRACE_LEAVE
	return(0);
}

/*	iscsi_get_value_from_number_range():
 *
 *	This function is used to pick a value range number,  currently just
 *	returns the lesser of both right values.
 */
static char *iscsi_get_value_from_number_range(iscsi_param_t *param, char *value)
{
	char *end_ptr, *tilde_ptr1 = NULL, *tilde_ptr2 = NULL;
	u32 acceptor_right_value, proposer_right_value;
	
	TRACE_ENTER

	if (!(tilde_ptr1 = strchr(value, '~')))
		return(NULL);
	*tilde_ptr1++ = '\0';	
	proposer_right_value = simple_strtoul(tilde_ptr1, &end_ptr, 0);
	
	if (!(tilde_ptr2 = strchr(param->value, '~')))
		return(NULL);
	*tilde_ptr2++ = '\0';
	acceptor_right_value = simple_strtoul(tilde_ptr2, &end_ptr, 0);
	
	TRACE_LEAVE
	return((acceptor_right_value >= proposer_right_value) ? tilde_ptr1 : tilde_ptr2);
}

/*	iscsi_check_valuelist_for_support():
 *
 *
 */
static char *iscsi_check_valuelist_for_support(iscsi_param_t *param, char *value)
{
	char *tmp1 = NULL, *tmp2 = NULL;
	char *acceptor_values = NULL, *proposer_values = NULL;
	
	TRACE_ENTER

	acceptor_values = param->value;
	proposer_values = value;
	
	do {
		if (!proposer_values)
			return(NULL);
		if ((tmp1 = strchr(proposer_values, ',')))
			*tmp1 = '\0';
		acceptor_values = param->value;
		do {
			if (!acceptor_values) {
				if (tmp1)
					*tmp1 = ',';
				return(NULL);
			}
			if ((tmp2 = strchr(acceptor_values, ',')))
				*tmp2 = '\0';
			if (!acceptor_values || !proposer_values) {
				if (tmp1)
					*tmp1 = ',';
				if (tmp2)
					*tmp2 = ',';
				return(NULL);
			}
			if (!strcmp(acceptor_values, proposer_values)) {
				if (tmp2)
					*tmp2 = ',';
				goto out;
			}
			if (tmp2)
				*tmp2++ = ',';

			acceptor_values = tmp2;
			if (!acceptor_values)
				break;
		} while (acceptor_values);
		if (tmp1)
			*tmp1++ = ',';
		proposer_values = tmp1;
	} while (proposer_values);

out:	
	TRACE_LEAVE
	return(proposer_values);
}

/*	iscsi_check_acceptor_state():
 *
 *
 */
static int iscsi_check_acceptor_state(iscsi_param_t *param, char *value)
{
	u8 acceptor_boolean_value = 0, proposer_boolean_value = 0;
	char *negoitated_value = NULL;
	
	TRACE_ENTER

	if (IS_PSTATE_ACCEPTOR(param)) {
		TRACE_ERROR("Received key \"%s\" twice, protocol error.\n",
				param->name);
		return(-1);
	}

	if (IS_PSTATE_REJECT(param))
		return(0);
		
	if (IS_TYPE_BOOL_AND(param)) {
		if (!strcmp(value, YES))
			proposer_boolean_value = 1;
		if (!strcmp(param->value, YES))
			acceptor_boolean_value = 1;
		if (acceptor_boolean_value && proposer_boolean_value)
			do {} while(0);
		else {
			if (iscsi_update_param_value(param, NO) < 0)
				return(-1);
			if (!proposer_boolean_value)
				SET_PSTATE_REPLY_OPTIONAL(param);
		}		
	} else if (IS_TYPE_BOOL_OR(param)) {
		if (!strcmp(value, YES))
			proposer_boolean_value = 1;
		if (!strcmp(param->value, YES))
			acceptor_boolean_value = 1;
		if (acceptor_boolean_value || proposer_boolean_value) {
			if (iscsi_update_param_value(param, YES) < 0)
				return(-1);
			if (proposer_boolean_value)
				SET_PSTATE_REPLY_OPTIONAL(param);
		}
	} else if (IS_TYPE_NUMBER(param)) {
		char *tmpptr, buf[10];
		u32 acceptor_value = simple_strtoul(param->value, &tmpptr, 0);
		u32 proposer_value = simple_strtoul(value, &tmpptr, 0);

		memset(buf, 0, 10);

		if (!strcmp(param->name, MAXCONNECTIONS) ||
		    !strcmp(param->name, MAXBURSTLENGTH) ||
		    !strcmp(param->name, FIRSTBURSTLENGTH) ||
		    !strcmp(param->name, MAXOUTSTANDINGR2T) ||
		    !strcmp(param->name, DEFAULTTIME2RETAIN) ||
		    !strcmp(param->name, ERRORRECOVERYLEVEL)) {
			if (proposer_value > acceptor_value) {
				sprintf(buf, "%u", acceptor_value);
				if (iscsi_update_param_value(param, &buf[0]) < 0)
					return(-1);
			} else {
				if (iscsi_update_param_value(param, value) < 0)
					return(-1);
			}
		} else if (!strcmp(param->name, DEFAULTTIME2WAIT)) {
			if (acceptor_value > proposer_value) {
				sprintf(buf, "%u", acceptor_value);
				if (iscsi_update_param_value(param, &buf[0]) < 0)
					return(-1);
			} else {
				if (iscsi_update_param_value(param, value) < 0)
					return(-1);
			}
		} else {
			if (iscsi_update_param_value(param, value) < 0)
				return(-1);
		}
		
		if (!strcmp(param->name, MAXRECVDATASEGMENTLENGTH))
			SET_PSTATE_REPLY_OPTIONAL(param);
	} else if (IS_TYPE_NUMBER_RANGE(param)) {
		if (!(negoitated_value = iscsi_get_value_from_number_range
					(param, value)))
			return(-1);
		if (iscsi_update_param_value(param, negoitated_value) < 0)
			return(-1);
	} else if (IS_TYPE_VALUE_LIST(param)) {
		if (!(negoitated_value = iscsi_check_valuelist_for_support
					(param, value))) {
			TRACE_ERROR("Proposer's value list \"%s\" contains no"
				" valid values from Acceptor's value list \"%s\".\n",
					value, param->value);
			return(-1);
		}
		if (iscsi_update_param_value(param, negoitated_value) < 0)
			return(-1);
	} else if (IS_PHASE_DECLARATIVE(param)) {
		if (iscsi_update_param_value(param, value) < 0)
			return(-1);
		SET_PSTATE_REPLY_OPTIONAL(param);
	}
	
		
	TRACE_LEAVE
	return(0);
}

/*	iscsi_check_proposer_state():
 *
 *
 */
static int iscsi_check_proposer_state(iscsi_param_t *param, char *value)
{
	TRACE_ENTER

	if (IS_PSTATE_RESPONSE_GOT(param)) {
		TRACE_ERROR("Received key \"%s\" twice, protocol error.\n",
				param->name);
		return(-1);
	}
		
	if (IS_TYPE_NUMBER_RANGE(param)) {
		u32 left_val = 0, right_val = 0, recieved_value = 0;
		char *left_val_ptr = NULL, *right_val_ptr = NULL;
		char *tilde_ptr = NULL, *tmp_ptr = NULL;

		if (!strcmp(value, IRRELEVANT) || !strcmp(value, REJECT)) {
			if (iscsi_update_param_value(param, value) < 0)
				return(-1);
			return(0);
		}

		if ((tilde_ptr = strchr(value, '~'))) {
			TRACE_ERROR("Illegal \"~\" in response for \"%s\".\n",
					param->name);
			return(-1);
		}
		if (!(tilde_ptr = strchr(param->value, '~'))) {
			TRACE_ERROR("Unable to locate numerical range indicator"
				" \"~\" for \"%s\".\n", param->name);
			return(-1);
		}
		*tilde_ptr = '\0';
		
		left_val_ptr = param->value;
		right_val_ptr = param->value + strlen(left_val_ptr) + 1;
		left_val = simple_strtoul(left_val_ptr, &tmp_ptr, 0);
		right_val = simple_strtoul(right_val_ptr, &tmp_ptr, 0);
		recieved_value = simple_strtoul(value, &tmp_ptr, 0);

		*tilde_ptr = '~';
		
		if ((recieved_value < left_val) ||
		    (recieved_value > right_val)) {
			TRACE_ERROR("Illegal response \"%s=%u\", value must be"
				" between %u and %u.\n", param->name,
				recieved_value, left_val, right_val);
			return(-1);
		}
	} else if (IS_TYPE_VALUE_LIST(param)) {
		char *comma_ptr = NULL, *tmp_ptr = NULL;
		
		if ((comma_ptr = strchr(value, ','))) {
			TRACE_ERROR("Illegal \",\" in response for \"%s\".\n",
					param->name);
			return(-1);
		}

		if (!(tmp_ptr = iscsi_check_valuelist_for_support(param, value)))
			return(-1);
	}		

	if (iscsi_update_param_value(param, value) < 0)
		return(-1);
	
	TRACE_LEAVE
	return(0);
}
	
/*	iscsi_check_value():
 *
 *
 */
static int iscsi_check_value(iscsi_param_t *param, char *value)
{
	char *comma_ptr = NULL;
	
	TRACE_ENTER

	if (!strcmp(value, REJECT)) {
		if (!strcmp(param->name, IFMARKINT) ||
		    !strcmp(param->name, OFMARKINT)) {
			/*
			 * Reject is not fatal for [I,O]FMarkInt,  and causes
			 * [I,O]FMarker to be reset to No. (See iSCSI v20 A.3.2)
			 */
			SET_PSTATE_REJECT(param);
			return(0);
		}
		TRACE_ERROR("Received %s=%s\n", param->name, value);
		return(-1);
	}
	if (!strcmp(value, IRRELEVANT)) {
		TRACE(TRACE_LOGIN, "Received %s=%s\n", param->name, value);
		SET_PSTATE_IRRELEVANT(param);
		return(0);
	}
	if (!strcmp(value, NOTUNDERSTOOD)) {
		if (!IS_PSTATE_PROPOSER(param)) {
			TRACE_ERROR("Received illegal offer %s=%s\n",
				param->name, value);
			return(-1);
		}

//#warning FIXME: Add check for X-ExtensionKey here
		TRACE_ERROR("Standard iSCSI key \"%s\" cannot be answered with"
			" \"%s\", protocol error.\n", param->name, value);
		return(-1);
	}

	do {
		comma_ptr = NULL;
		comma_ptr = strchr(value, ',');

		if (comma_ptr && !IS_TYPE_VALUE_LIST(param)) {
			TRACE_ERROR("Detected value seperator \",\", but key"
				" \"%s\" does not allow a value list,"
				" protocol error.\n", param->name);
			return(-1);
		}
		if (comma_ptr)
			*comma_ptr = '\0';

		if (strlen(value) > MAX_KEY_VALUE_LENGTH) {
			TRACE_ERROR("Value for key \"%s\" exceeds %d, protocol"
				" error.\n", param->name, MAX_KEY_VALUE_LENGTH);
			return(-1);
		}

		if (IS_TYPE_BOOL_AND(param) || IS_TYPE_BOOL_OR(param)) {
			if (iscsi_check_boolean_value(param, value) < 0)
				return(-1);
		} else if (IS_TYPE_NUMBER(param)) {
			if (iscsi_check_numerical_value(param, value) < 0)
				return(-1);
		} else if (IS_TYPE_NUMBER_RANGE(param)) {
			if (iscsi_check_numerical_range_value(param, value) < 0)
				return(-1);
		} else if (IS_TYPE_STRING(param) || IS_TYPE_VALUE_LIST(param)) {
			if (iscsi_check_string_or_list_value(param, value) < 0)
				return(-1);
		} else {
			TRACE_ERROR("Huh? 0x%02x\n", param->type);
			return(-1);
		}	
			
		if (comma_ptr)
			*comma_ptr++ = ',';

		value = comma_ptr;
	} while (value);
	
	TRACE_LEAVE
	return(0);
}

/*	__iscsi_check_key()
 *
 *
 */
static iscsi_param_t *__iscsi_check_key(char *key, int sender, iscsi_param_list_t *param_list)
{
	iscsi_param_t *param;
	
	if (strlen(key) > MAX_KEY_NAME_LENGTH) {
		TRACE_ERROR("Length of key name \"%s\" exceeds %d.\n",
			key, MAX_KEY_NAME_LENGTH);
		return(NULL);
	}

	if (!(param = iscsi_find_param_from_key(key, param_list)))
		return(NULL);

	if ((sender & SENDER_INITIATOR) && !IS_SENDER_INITIATOR(param)) {
		TRACE_ERROR("Key \"%s\" may not be sent to %s,"
			" protocol error.\n", param->name,
			(sender & SENDER_RECEIVER) ? "target" : "initiator");
		return(NULL);
	}

	if ((sender & SENDER_TARGET) && !IS_SENDER_TARGET(param)) {
		TRACE_ERROR("Key \"%s\" may not be sent to %s,"
			" protocol error.\n", param->name,
			(sender & SENDER_RECEIVER) ? "initiator" : "target");
		return(NULL);
	}

	return(param);
}

/*	iscsi_check_key():
 *
 *
 */
static iscsi_param_t *iscsi_check_key(char *key, int phase, int sender, iscsi_param_list_t *param_list)
{
	iscsi_param_t *param;
	
	TRACE_ENTER

	/*
	 * Key name length must not exceed 63 bytes. (See iSCSI v20 5.1)
	 */
	if (strlen(key) > MAX_KEY_NAME_LENGTH) {
		TRACE_ERROR("Length of key name \"%s\" exceeds %d.\n",
			key, MAX_KEY_NAME_LENGTH);
		return(NULL);
	}

	if (!(param = iscsi_find_param_from_key(key, param_list)))
		return(NULL);
	
	if ((sender & SENDER_INITIATOR) && !IS_SENDER_INITIATOR(param)) {
		TRACE_ERROR("Key \"%s\" may not be sent to %s,"
			" protocol error.\n", param->name,
			(sender & SENDER_RECEIVER) ? "target" : "initiator");
		return(NULL);
	}
	if ((sender & SENDER_TARGET) && !IS_SENDER_TARGET(param)) {
		TRACE_ERROR("Key \"%s\" may not be sent to %s,"
				" protocol error.\n", param->name,
			(sender & SENDER_RECEIVER) ? "initiator" : "target");
		return(NULL);
	}
	
	if (IS_PSTATE_ACCEPTOR(param)) {
		TRACE_ERROR("Key \"%s\" received twice, protocol error.\n", key);
		return(NULL);
	}

	if (!phase)
		return(param);

	if (!(param->phase & phase)) {
		TRACE_ERROR("Key \"%s\" may not be negotiated during ", param->name);
		switch (phase) {
			case PHASE_SECURITY:
				PYXPRINT("Security phase.\n");
				break;
			case PHASE_OPERATIONAL:
				PYXPRINT("Operational phase.\n");
			default:
				PYXPRINT("Unknown phase.\n");
		}
		return(NULL);
	}
	
	TRACE_LEAVE
	return(param);
}

/*	iscsi_enforce_integrity_rules():
 *
 *
 */
static int iscsi_enforce_integrity_rules(u8 phase, iscsi_param_list_t *param_list)
{
	char *tmpptr;
	u8 DataSequenceInOrder = 0;
	u8 ErrorRecoveryLevel = 0, SessionType = 0;
	u8 IFMarker = 0, OFMarker = 0;
	u8 IFMarkInt_Reject = 0, OFMarkInt_Reject = 0;
	u32 FirstBurstLength = 0, MaxBurstLength = 0;
	iscsi_param_t *param = NULL;
	
	TRACE_ENTER

	for (param = param_list->param_start; param; param = param->next) {
		if (!(param->phase & phase))
			continue;
		if (!strcmp(param->name, SESSIONTYPE))
			if (!strcmp(param->value, NORMAL))
				SessionType = 1;
		if (!strcmp(param->name, ERRORRECOVERYLEVEL))
			ErrorRecoveryLevel = simple_strtoul(param->value, &tmpptr, 0);
		if (!strcmp(param->name, DATASEQUENCEINORDER))
			if (!strcmp(param->value, YES))
				DataSequenceInOrder = 1;
		if (!strcmp(param->name, MAXBURSTLENGTH))
			MaxBurstLength = simple_strtoul(param->value, &tmpptr, 0);	
		if (!strcmp(param->name, IFMARKER))
			if (!strcmp(param->value, YES))
				IFMarker = 1;
		if (!strcmp(param->name, OFMARKER))
			if (!strcmp(param->value, YES))
				OFMarker = 1;
		if (!strcmp(param->name, IFMARKINT))
			if (!strcmp(param->value, REJECT))
				IFMarkInt_Reject = 1;
		if (!strcmp(param->name, OFMARKINT))
			if (!strcmp(param->value, REJECT))
				OFMarkInt_Reject = 1;
	}

	for (param = param_list->param_start; param; param = param->next) {
		if (!(param->phase & phase))
		       continue;
		if (!SessionType && (!IS_PSTATE_ACCEPTOR(param) &&
		     (strcmp(param->name, IFMARKER) && strcmp(param->name, OFMARKER) &&
		      strcmp(param->name, IFMARKINT) && strcmp(param->name, OFMARKINT))))
			continue;
		if (!strcmp(param->name, MAXOUTSTANDINGR2T) && DataSequenceInOrder &&
		   (ErrorRecoveryLevel > 0)) {
			if (strcmp(param->value, "1")) {
				if (iscsi_update_param_value(param, "1") < 0)
					return(-1);
				TRACE(TRACE_PARAM, "Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
			}
		}
		if (!strcmp(param->name, MAXCONNECTIONS) && !SessionType) {
			if (strcmp(param->value, "1")) {
				if (iscsi_update_param_value(param, "1") < 0)
					 return(-1);
				TRACE(TRACE_PARAM, "Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
			}
		}
		if (!strcmp(param->name, FIRSTBURSTLENGTH)) {
			FirstBurstLength = simple_strtoul(param->value, &tmpptr, 0);
			if (FirstBurstLength > MaxBurstLength) {
				char tmpbuf[10];
				memset(tmpbuf, 0, 10);
				sprintf(tmpbuf, "%u", MaxBurstLength);
				if (iscsi_update_param_value(param, tmpbuf))
					return(-1);
				TRACE(TRACE_PARAM, "Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
			}
		}
		if (!strcmp(param->name, IFMARKER) && IFMarkInt_Reject) {
			if (iscsi_update_param_value(param, NO) < 0)
				return(-1);
			IFMarker = 0;
			TRACE(TRACE_PARAM, "Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
		}
		if (!strcmp(param->name, OFMARKER) && OFMarkInt_Reject) {
			if (iscsi_update_param_value(param, NO) < 0)
				return(-1);
			OFMarker = 0;
			TRACE(TRACE_PARAM, "Reset \"%s\" to \"%s\".\n",
					 param->name, param->value);
		}
		if (!strcmp(param->name, IFMARKINT) && !IFMarker) {	
			if (!strcmp(param->value, REJECT))
				continue;
			param->state &= ~PSTATE_NEGOTIATE;
			if (iscsi_update_param_value(param, IRRELEVANT) < 0)
				return(-1);
			TRACE(TRACE_PARAM, "Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
		}
		if (!strcmp(param->name, OFMARKINT) && !OFMarker) {
			if (!strcmp(param->value, REJECT))
				continue;
			param->state &= ~PSTATE_NEGOTIATE;
			if (iscsi_update_param_value(param, IRRELEVANT) < 0)
				 return(-1);
			TRACE(TRACE_PARAM, "Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
		}
	}
	
	TRACE_LEAVE
	return (0);
}

/*	iscsi_decode_text_input():
 *
 *
 */
extern int iscsi_decode_text_input(
	u8 phase,
	u8 sender,
	char *textbuf,
	u32 length,
	iscsi_param_list_t *param_list)
{
	char *tmpbuf, *start = NULL, *end = NULL;
	
	TRACE_ENTER

	if (!(tmpbuf = (char *) kmalloc(length + 1, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for tmpbuf.\n");
		return(-1);
	}
	memset(tmpbuf, 0, length + 1);

	memcpy(tmpbuf, textbuf, length);
	tmpbuf[length] = '\0';	
	start = tmpbuf;
	end = (start + length);
	
	while (start < end) {
		char *key, *value;
		iscsi_param_t *param;

		if (iscsi_extract_key_value(start, &key, &value) < 0) {
			kfree(tmpbuf);
			return(-1);
		}
		
		TRACE(TRACE_PARAM, "Got key: %s=%s\n", key, value);		

		if (phase & PHASE_SECURITY) {
			if (iscsi_check_for_auth_key(key) > 0) {
				char *tmpptr = key + strlen(key);
				*tmpptr = '=';	
				kfree(tmpbuf);
				return(1);
			}
		}
		
		if (!(param = iscsi_check_key(key, phase, sender, param_list))) {
			if (iscsi_add_notunderstood_response(key,
					value, param_list) < 0) {
				kfree(tmpbuf);
				return(-1);
			}
			start += strlen(key) + strlen(value) + 2;
			continue;
		}
		if (iscsi_check_value(param, value) < 0) {
			kfree(tmpbuf);
			return(-1);
		}
		
		start += strlen(key) + strlen(value) + 2;
		
		if (IS_PSTATE_PROPOSER(param)) {
			if (iscsi_check_proposer_state(param, value) < 0) {
				kfree(tmpbuf);
				return(-1);
			}
			SET_PSTATE_RESPONSE_GOT(param);
		} else {
			if (iscsi_check_acceptor_state(param, value) < 0) {
				kfree(tmpbuf);
				return(-1);
			}
			SET_PSTATE_ACCEPTOR(param);
		}
	}
		
	kfree(tmpbuf);

	TRACE_LEAVE
	return(0);
}

/*	iscsi_encode_text_output():
 *
 *
 */
extern int iscsi_encode_text_output(
	u8 phase,
	u8 sender,
	char *textbuf,
	u32 *length,
	iscsi_param_list_t *param_list)
{
	char *output_buf = NULL;
	iscsi_extra_response_t *extra_response;
	iscsi_param_t *param;
	
	TRACE_ENTER

	output_buf = textbuf + *length;

	if (iscsi_enforce_integrity_rules(phase, param_list) < 0)
		return(-1);
	
	for (param = param_list->param_start; param; param = param->next) {
		if (!(param->sender & sender))
			continue;
		if (IS_PSTATE_ACCEPTOR(param) &&
		    !IS_PSTATE_RESPONSE_SENT(param) &&
		    !IS_PSTATE_REPLY_OPTIONAL(param) &&
		    (param->phase & phase)) {
			*length += sprintf(output_buf, "%s=%s",
				param->name, param->value);
			*length += 1;
			output_buf = textbuf + *length;
			SET_PSTATE_RESPONSE_SENT(param);
			TRACE(TRACE_PARAM, "Sending key: %s=%s\n",
				param->name, param->value);
			continue;
		}
		if (IS_PSTATE_NEGOTIATE(param) &&
		    !IS_PSTATE_ACCEPTOR(param) &&
		    !IS_PSTATE_PROPOSER(param) &&
		    (param->phase & phase)) {
			*length += sprintf(output_buf, "%s=%s",
				param->name, param->value);
			*length += 1;
			output_buf = textbuf + *length;
			SET_PSTATE_PROPOSER(param);
			iscsi_check_proposer_for_optional_reply(param);
			TRACE(TRACE_PARAM, "Sending key: %s=%s\n",
				param->name, param->value);
		}
	}
	
	for (extra_response = param_list->extra_response_start; extra_response;
	     extra_response = extra_response->next) {
		*length += sprintf(output_buf, "%s=%s",
			extra_response->key, extra_response->value);
		*length += 1;
		output_buf = textbuf + *length;
		TRACE(TRACE_PARAM, "Sending key: %s=%s\n",
			extra_response->key, extra_response->value);
	}
	iscsi_release_extra_responses(param_list);
	
		
	TRACE_LEAVE
	return(0);
}

/*	iscsi_check_negotiated_keys():
 *
 *
 */
extern int iscsi_check_negotiated_keys(iscsi_param_list_t *param_list)
{
	int ret = 0;
	iscsi_param_t *param;
	
	TRACE_ENTER

	for (param = param_list->param_start; param; param = param->next) {
		if (IS_PSTATE_NEGOTIATE(param) &&
		    IS_PSTATE_PROPOSER(param) &&
		    !IS_PSTATE_RESPONSE_GOT(param) &&
		    !IS_PSTATE_REPLY_OPTIONAL(param) &&
		    !IS_PHASE_DECLARATIVE(param)) {
			TRACE_ERROR("No response for proposed key \"%s\".\n",
					param->name);
			ret = -1;
		}
	}
		
	TRACE_LEAVE
	return(ret);
}

/*	iscsi_set_param_value():
 *
 *
 */
extern int iscsi_change_param_value(char *keyvalue, int sender, iscsi_param_list_t *param_list, int check_key)
{
	char *key = NULL, *value = NULL;
	iscsi_param_t *param;
	
	TRACE_ENTER
	
	if (iscsi_extract_key_value(keyvalue, &key, &value) < 0)
		return(-1);

	if (!check_key) {
		if (!(param = __iscsi_check_key(keyvalue, sender, param_list)))
			return(-1);
	} else {
		if (!(param = iscsi_check_key(keyvalue, 0, sender, param_list)))
			return(-1);

		param->set_param = 1;
		if (iscsi_check_value(param, value) < 0) {
			param->set_param = 0;
			return(-1);
		}
		param->set_param = 0;
	}

	if (iscsi_update_param_value(param, value) < 0)
		return(-1);
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_set_connection_parameters():
 *
 *
 */
extern void iscsi_set_connection_parameters(
	iscsi_conn_ops_t *ops,
	iscsi_param_list_t *param_list)
{
	char *tmpptr;
	iscsi_param_t *param;
	
	TRACE_ENTER

	PYXPRINT("------------------------------------------------------------------\n");
	for (param = param_list->param_start; param; param = param->next) {
		if (!IS_PSTATE_ACCEPTOR(param) && !IS_PSTATE_PROPOSER(param))
			continue;
		if (!strcmp(param->name, AUTHMETHOD)) {
			PYXPRINT("AuthMethod:                   %s\n", param->value);
		} else if (!strcmp(param->name, HEADERDIGEST)) {
			ops->HeaderDigest = !strcmp(param->value, CRC32C);
			PYXPRINT("HeaderDigest:                 %s\n", param->value);
		} else if (!strcmp(param->name, DATADIGEST)) {
			ops->DataDigest = !strcmp(param->value, CRC32C);
			PYXPRINT("DataDigest:                   %s\n", param->value);
		} else if (!strcmp(param->name, MAXRECVDATASEGMENTLENGTH)) {
			ops->MaxRecvDataSegmentLength =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("MaxRecvDataSegmentLength:     %s\n", param->value);
		} else if (!strcmp(param->name, OFMARKER)) {
			ops->OFMarker = !strcmp(param->value, YES);
			PYXPRINT("OFMarker:                     %s\n", param->value);
		} else if (!strcmp(param->name, IFMARKER)) {
			ops->IFMarker = !strcmp(param->value, YES);
			PYXPRINT("IFMarker:                     %s\n", param->value);
		} else if (!strcmp(param->name, OFMARKINT)) {
			ops->OFMarkInt =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("OFMarkInt:                    %s\n", param->value);
		} else if (!strcmp(param->name, IFMARKINT)) {
			ops->IFMarkInt =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("IFMarkInt:                    %s\n", param->value);
		}	
	}
	PYXPRINT("------------------------------------------------------------------\n");
		
	TRACE_LEAVE
}

/*	iscsi_set_session_parameters():
 *
 *
 */
extern void iscsi_set_session_parameters(
	iscsi_sess_ops_t *ops,
	iscsi_param_list_t *param_list,
	int leading)
{
	char *tmpptr;
	iscsi_param_t *param;

	TRACE_ENTER

	PYXPRINT("------------------------------------------------------------------\n");
	for (param = param_list->param_start; param; param = param->next) {
		if (!IS_PSTATE_ACCEPTOR(param) && !IS_PSTATE_PROPOSER(param))
			continue;
		if (!strcmp(param->name, INITIATORNAME)) {
			if (!param->value)
				continue;
			if (leading)
				snprintf(ops->InitiatorName, sizeof(ops->InitiatorName),
						"%s", param->value);
			PYXPRINT("InitiatorName:                %s\n", param->value);
		} else if (!strcmp(param->name, INITIATORALIAS)) {
			if (!param->value)
				continue;
			snprintf(ops->InitiatorAlias, sizeof(ops->InitiatorAlias),
						"%s", param->value);
			PYXPRINT("InitiatorAlias:               %s\n", param->value);
		} else if (!strcmp(param->name, TARGETNAME)) {
			if (!param->value)
				continue;
			if (leading)
				snprintf(ops->TargetName, sizeof(ops->TargetName),
						"%s", param->value);
			PYXPRINT("TargetName:                   %s\n", param->value);
		} else if (!strcmp(param->name, TARGETALIAS)) {
			if (!param->value)
				continue;
			snprintf(ops->TargetAlias, sizeof(ops->TargetAlias),
					"%s", param->value);
			PYXPRINT("TargetAlias:                  %s\n", param->value);
		} else if (!strcmp(param->name, TARGETPORTALGROUPTAG)) {
			ops->TargetPortalGroupTag =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("TargetPortalGroupTag:         %s\n", param->value);
		} else if (!strcmp(param->name, MAXCONNECTIONS)) {
			ops->MaxConnections =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("MaxConnections:               %s\n", param->value);
		} else if (!strcmp(param->name, INITIALR2T)) {
			ops->InitialR2T = !strcmp(param->value, YES);
			 PYXPRINT("InitialR2T:                   %s\n", param->value);
		} else if (!strcmp(param->name, IMMEDIATEDATA)) {
	       		ops->ImmediateData = !strcmp(param->value, YES);
			PYXPRINT("ImmediateData:                %s\n", param->value);
		} else if (!strcmp(param->name, MAXBURSTLENGTH)) {
			ops->MaxBurstLength =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("MaxBurstLength:               %s\n", param->value);
		} else if (!strcmp(param->name, FIRSTBURSTLENGTH)) {
			ops->FirstBurstLength =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("FirstBurstLength:             %s\n", param->value);
		} else if (!strcmp(param->name, DEFAULTTIME2WAIT)) {
			ops->DefaultTime2Wait =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("DefaultTime2Wait:             %s\n", param->value);
		} else if (!strcmp(param->name, DEFAULTTIME2RETAIN)) {
			ops->DefaultTime2Retain =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("DefaultTime2Retain:           %s\n", param->value);
		} else if (!strcmp(param->name, MAXOUTSTANDINGR2T)) {
			ops->MaxOutstandingR2T =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("MaxOutstandingR2T:            %s\n", param->value);
		} else if (!strcmp(param->name, DATAPDUINORDER)) {
			ops->DataPDUInOrder = !strcmp(param->value, YES);
			PYXPRINT("DataPDUInOrder:               %s\n", param->value);
		} else if (!strcmp(param->name, DATASEQUENCEINORDER)) {
			ops->DataSequenceInOrder = !strcmp(param->value, YES);
			PYXPRINT("DataSequenceInOrder:          %s\n", param->value);
		} else if (!strcmp(param->name, ERRORRECOVERYLEVEL)) {
			ops->ErrorRecoveryLevel =
				simple_strtoul(param->value, &tmpptr, 0);
			PYXPRINT("ErrorRecoveryLevel:           %s\n", param->value);
		} else if (!strcmp(param->name, SESSIONTYPE)) {
			ops->SessionType = !strcmp(param->value, DISCOVERY);
			PYXPRINT("SessionType:                  %s\n", param->value);
		}
	}
	PYXPRINT("------------------------------------------------------------------\n");

	TRACE_LEAVE
}


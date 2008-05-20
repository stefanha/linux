/*********************************************************************************
 * Filename:  iscsi_parameters.h
 *
 * This file contains definitions related to the iSCSI Parameter Negotiation.
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_parameters.h $
 *   $LastChangedRevision: 7071 $
 *   $LastChangedBy: nab $
 *   $LastChangedDate: 2007-07-25 14:44:38 -0700 (Wed, 25 Jul 2007) $
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


#ifndef ISCSI_PARAMETERS_H
#define ISCSI_PARAMETERS_H

typedef struct iscsi_extra_response_s {
	char key[64];
	char value[32];
	struct iscsi_extra_response_s *next;
} iscsi_extra_response_t;

typedef struct iscsi_param_s {
	char *name;
	char *value;
	u8 set_param;
	u8 phase;
	u8 scope;
	u8 sender;
	u8 type;
	u8 use;
	u16 type_range;
	u32 state;
	struct iscsi_param_s *next;
} iscsi_param_t;

#if 0
typedef struct iscsi_param_list_s {
	iscsi_param_t *param_start;
	iscsi_extra_response_t *extra_response_start;
} iscsi_param_list_t;
#endif

extern int iscsi_login_rx_data(iscsi_conn_t *, char *, int, int);
extern int iscsi_login_tx_data(iscsi_conn_t *, char *, char *, int, int);
extern void iscsi_dump_conn_ops(iscsi_conn_ops_t *);
extern void iscsi_dump_sess_ops(iscsi_sess_ops_t *);
extern void iscsi_print_params(iscsi_param_list_t *);
extern int iscsi_create_default_params(iscsi_param_list_t **);
extern int iscsi_set_keys_to_negotiate(int, int, iscsi_param_list_t *);
extern int iscsi_set_keys_irrelevant_for_discovery(iscsi_param_list_t *);
extern int iscsi_copy_param_list(iscsi_param_list_t **, iscsi_param_list_t *, int);
extern int iscsi_change_param_value(char *, int, iscsi_param_list_t *, int);
extern void iscsi_release_param_list(iscsi_param_list_t *);
extern iscsi_param_t *iscsi_find_param_from_key(char *, iscsi_param_list_t *);
extern int iscsi_extract_key_value (char *, char **, char **);
extern int iscsi_update_param_value(iscsi_param_t *, char *);
extern int iscsi_decode_text_input(u8, u8, char *, u32, iscsi_param_list_t *);
extern int iscsi_encode_text_output(u8, u8, char *, u32 *, iscsi_param_list_t *);
extern int iscsi_check_negotiated_keys(iscsi_param_list_t *);
extern void iscsi_set_connection_parameters(iscsi_conn_ops_t *, iscsi_param_list_t *);
extern void iscsi_set_session_parameters(iscsi_sess_ops_t *, iscsi_param_list_t *, int);

#define YES					"Yes"
#define NO					"No"
#define ALL					"All"
#define IRRELEVANT				"Irrelevant"
#define NONE					"None"
#define NOTUNDERSTOOD				"NotUnderstood"
#define REJECT					"Reject"

/*
 * The Parameter Names.
 */
#define AUTHMETHOD				"AuthMethod"
#define HEADERDIGEST				"HeaderDigest"
#define DATADIGEST				"DataDigest"
#define MAXCONNECTIONS				"MaxConnections"
#define SENDTARGETS				"SendTargets"
#define TARGETNAME				"TargetName"
#define INITIATORNAME				"InitiatorName"
#define TARGETALIAS				"TargetAlias"
#define INITIATORALIAS				"InitiatorAlias"
#define TARGETADDRESS				"TargetAddress"
#define TARGETPORTALGROUPTAG			"TargetPortalGroupTag"
#define INITIALR2T				"InitialR2T"
#define IMMEDIATEDATA				"ImmediateData"
#define MAXRECVDATASEGMENTLENGTH		"MaxRecvDataSegmentLength"
#define MAXBURSTLENGTH				"MaxBurstLength"
#define FIRSTBURSTLENGTH			"FirstBurstLength"
#define DEFAULTTIME2WAIT			"DefaultTime2Wait"
#define DEFAULTTIME2RETAIN			"DefaultTime2Retain"
#define MAXOUTSTANDINGR2T			"MaxOutstandingR2T"
#define DATAPDUINORDER  			"DataPDUInOrder"
#define DATASEQUENCEINORDER			"DataSequenceInOrder"
#define ERRORRECOVERYLEVEL			"ErrorRecoveryLevel"
#define SESSIONTYPE				"SessionType"
#define IFMARKER				"IFMarker"
#define OFMARKER				"OFMarker"
#define IFMARKINT				"IFMarkInt"
#define OFMARKINT				"OFMarkInt"
#define X_EXTENSIONKEY				"X-com.sbei.version"
#define X_EXTENSIONKEY_CISCO_NEW		"X-com.cisco.protocol"
#define X_EXTENSIONKEY_CISCO_OLD		"X-com.cisco.iscsi.draft"

/*
 * For AuthMethod.
 */
#define KRB5					"KRB5"
#define SPKM1					"SPKM1"
#define SPKM2					"SPKM2"
#define SRP					"SRP"
#define CHAP					"CHAP"

/*
 * Initial values for Parameter Negotiation.
 */
#define INITIAL_AUTHMETHOD			CHAP
#define INITIAL_HEADERDIGEST			NONE
#define INITIAL_DATADIGEST			NONE
#define INITIAL_MAXCONNECTIONS			"1"
#define INITIAL_SENDTARGETS			ALL
#define INITIAL_TARGETNAME			"iSBE.Target"
#define INITIAL_INITIATORNAME			"iSBE.Initiator"
#define INITIAL_TARGETALIAS			"iSBE Target"
#define INITIAL_INITIATORALIAS			"iSBE Initiator"
#define INITIAL_TARGETADDRESS			"0.0.0.0:0000,0"
#define INITIAL_TARGETPORTALGROUPTAG		"1"
#define INITIAL_INITIALR2T			YES
#define INITIAL_IMMEDIATEDATA			YES
#define INITIAL_MAXRECVDATASEGMENTLENGTH	"8192"
#define INITIAL_MAXBURSTLENGTH			"262144"
#define INITIAL_FIRSTBURSTLENGTH		"65536"
#define INITIAL_DEFAULTTIME2WAIT		"2"
#define INITIAL_DEFAULTTIME2RETAIN		"20"
#define INITIAL_MAXOUTSTANDINGR2T		"1"
#define INITIAL_DATAPDUINORDER			YES
#define INITIAL_DATASEQUENCEINORDER		YES
#define INITIAL_ERRORRECOVERYLEVEL		"0"
#define INITIAL_SESSIONTYPE			NORMAL
#define INITIAL_IFMARKER			NO
#define INITIAL_OFMARKER			NO
#define INITIAL_IFMARKINT			"2048~65535"
#define INITIAL_OFMARKINT			"2048~65535"

/*
 * For [Header,Data]Digests.
 */
#define CRC32C					"CRC32C"

/*
 * For SessionType.
 */
#define DISCOVERY				"Discovery"
#define NORMAL					"Normal"

/*
 * iscsi_param_t->use
 */
#define USE_LEADING_ONLY			0x01
#define USE_INITIAL_ONLY			0x02
#define USE_ALL					0x04

#define IS_USE_LEADING_ONLY(p)			((p)->use & USE_LEADING_ONLY)
#define IS_USE_INITIAL_ONLY(p)			((p)->use & USE_INITIAL_ONLY)
#define IS_USE_ALL(p)				((p)->use & USE_ALL)

#define SET_USE_INITIAL_ONLY(p)			((p)->use |= USE_INITIAL_ONLY)

/*
 * iscsi_param_t->sender
 */
#define	SENDER_INITIATOR			0x01
#define SENDER_TARGET				0x02
#define SENDER_BOTH				0x03
#define SENDER_RECEIVER				0x04	/* Used in iscsi_check_key() */

#define IS_SENDER_INITIATOR(p)			((p)->sender & SENDER_INITIATOR)
#define IS_SENDER_TARGET(p)			((p)->sender & SENDER_TARGET)
#define IS_SENDER_BOTH(p)			((p)->sender & SENDER_BOTH)

/*
 * iscsi_param_t->scope
 */
#define SCOPE_CONNECTION_ONLY			0x01
#define SCOPE_SESSION_WIDE			0x02

#define IS_SCOPE_CONNECTION_ONLY(p)		((p)->scope & SCOPE_CONNECTION_ONLY)
#define IS_SCOPE_SESSION_WIDE(p)		((p)->scope & SCOPE_SESSION_WIDE)

/*
 * iscsi_param_t->phase
 */
#define PHASE_SECURITY				0x01
#define PHASE_OPERATIONAL			0x02
#define PHASE_DECLARATIVE			0x04
#define PHASE_FFP0				0x08

#define IS_PHASE_SECURITY(p)			((p)->phase & PHASE_SECURITY)
#define IS_PHASE_OPERATIONAL(p)			((p)->phase & PHASE_OPERATIONAL)
#define IS_PHASE_DECLARATIVE(p)			((p)->phase & PHASE_DECLARATIVE)
#define IS_PHASE_FFP0(p)			((p)->phase & PHASE_FFP0)

/*
 * iscsi_param_t->type
 */
#define TYPE_BOOL_AND				0x01
#define TYPE_BOOL_OR				0x02
#define TYPE_NUMBER				0x04
#define TYPE_NUMBER_RANGE			0x08
#define TYPE_STRING				0x10
#define TYPE_VALUE_LIST				0x20

#define IS_TYPE_BOOL_AND(p)			((p)->type & TYPE_BOOL_AND)
#define IS_TYPE_BOOL_OR(p)			((p)->type & TYPE_BOOL_OR)
#define IS_TYPE_NUMBER(p)			((p)->type & TYPE_NUMBER)
#define IS_TYPE_NUMBER_RANGE(p)			((p)->type & TYPE_NUMBER_RANGE)
#define IS_TYPE_STRING(p)			((p)->type & TYPE_STRING)
#define IS_TYPE_VALUE_LIST(p)			((p)->type & TYPE_VALUE_LIST)

/*
 * iscsi_param_t->type_range
 */
#define TYPERANGE_BOOL_AND			0x0001
#define TYPERANGE_BOOL_OR			0x0002
#define TYPERANGE_0_TO_2			0x0004                      
#define TYPERANGE_0_TO_3600			0x0008
#define TYPERANGE_0_TO_32767			0x0010
#define TYPERANGE_0_TO_65535			0x0020
#define TYPERANGE_1_TO_65535			0x0040
#define TYPERANGE_2_TO_3600			0x0080
#define TYPERANGE_512_TO_16777215		0x0100
#define TYPERANGE_AUTH				0x0200
#define TYPERANGE_DIGEST			0x0400
#define TYPERANGE_ISCSINAME			0x0800
#define TYPERANGE_MARKINT			0x1000
#define TYPERANGE_SESSIONTYPE			0x2000
#define TYPERANGE_TARGETADDRESS			0x4000
#define TYPERANGE_UTF8				0x8000

#define IS_TYPERANGE_0_TO_2(p)			((p)->type_range & TYPERANGE_0_TO_2)
#define IS_TYPERANGE_0_TO_3600(p)		((p)->type_range & TYPERANGE_0_TO_3600)
#define IS_TYPERANGE_0_TO_32767(p)		((p)->type_range & TYPERANGE_0_TO_32767)
#define IS_TYPERANGE_0_TO_65535(p)		((p)->type_range & TYPERANGE_0_TO_65535)
#define IS_TYPERANGE_1_TO_65535(p)		((p)->type_range & TYPERANGE_1_TO_65535)
#define IS_TYPERANGE_2_TO_3600(p)		((p)->type_range & TYPERANGE_2_TO_3600)
#define IS_TYPERANGE_512_TO_16777215(p)		((p)->type_range & TYPERANGE_512_TO_16777215)
#define IS_TYPERANGE_AUTH_PARAM(p)		((p)->type_range & TYPERANGE_AUTH)
#define IS_TYPERANGE_DIGEST_PARAM(p)		((p)->type_range & TYPERANGE_DIGEST)
#define IS_TYPERANGE_SESSIONTYPE(p)		((p)->type_range & TYPERANGE_SESSIONTYPE)

/*
 * iscsi_param_t->state
 */
#define PSTATE_ACCEPTOR				0x01
#define PSTATE_NEGOTIATE			0x02
#define PSTATE_PROPOSER				0x04
#define PSTATE_IRRELEVANT			0x08
#define PSTATE_REJECT				0x10
#define PSTATE_REPLY_OPTIONAL			0x20
#define PSTATE_RESPONSE_GOT			0x40
#define PSTATE_RESPONSE_SENT			0x80

#define IS_PSTATE_ACCEPTOR(p)			((p)->state & PSTATE_ACCEPTOR)
#define IS_PSTATE_NEGOTIATE(p)			((p)->state & PSTATE_NEGOTIATE)
#define IS_PSTATE_PROPOSER(p)			((p)->state & PSTATE_PROPOSER)
#define IS_PSTATE_IRRELEVANT(p)			((p)->state & PSTATE_IRRELEVANT)
#define IS_PSTATE_REJECT(p)			((p)->state & PSTATE_REJECT)
#define IS_PSTATE_REPLY_OPTIONAL(p)		((p)->state & PSTATE_REPLY_OPTIONAL)
#define IS_PSTATE_RESPONSE_GOT(p)		((p)->state & PSTATE_RESPONSE_GOT)
#define IS_PSTATE_RESPONSE_SENT(p)		((p)->state & PSTATE_RESPONSE_SENT)

#define SET_PSTATE_ACCEPTOR(p)			((p)->state |= PSTATE_ACCEPTOR)
#define SET_PSTATE_NEGOTIATE(p)			((p)->state |= PSTATE_NEGOTIATE)
#define SET_PSTATE_PROPOSER(p)			((p)->state |= PSTATE_PROPOSER)
#define SET_PSTATE_IRRELEVANT(p)		((p)->state |= PSTATE_IRRELEVANT)
#define SET_PSTATE_REJECT(p)			((p)->state |= PSTATE_REJECT)
#define SET_PSTATE_REPLY_OPTIONAL(p)		((p)->state |= PSTATE_REPLY_OPTIONAL)
#define SET_PSTATE_RESPONSE_GOT(p)		((p)->state |= PSTATE_RESPONSE_GOT)
#define SET_PSTATE_RESPONSE_SENT(p)		((p)->state |= PSTATE_RESPONSE_SENT)

#endif /* ISCSI_PARAMETERS_H */

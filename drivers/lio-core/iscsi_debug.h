/*********************************************************************************
 * Filename:  iscsi_debug.h
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_debug.h $
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


#ifndef ISCSI_DEBUG_H
#define ISCSI_DEBUG_H

/*
 * Debugging Support
 */

#define TRACE_DEBUG		0x00000001	/* Verbose debugging */
#define TRACE_SCSI		0x00000002	/* Stuff related to the SCSI Mid-layer */
#define TRACE_ISCSI		0x00000004	/* Stuff related to iSCSI */
#define TRACE_NET		0x00000008	/* Stuff related to network code */
#define TRACE_BUFF		0x00000010	/* For dumping raw data */
#define TRACE_FILE		0x00000020	/* Used for __FILE__ */
#define TRACE_LINE		0x00000040	/* Used for __LINE__ */
#define TRACE_FUNCTION		0x00000080	/* Used for __FUNCTION__ */	
#define TRACE_SEM		0x00000100	/* Stuff related to semaphores */
#define TRACE_ENTER_LEAVE	0x00000200	/* For entering/leaving functions */
#define TRACE_DIGEST		0x00000400	/* For Header/Data Digests */
#define TRACE_PARAM		0x00000800	/* For parameters in parameters.c */
#define TRACE_LOGIN		0x00001000	/* For login related code */
#define TRACE_STATE		0x00002000	/* For conn/sess/cleanup states */
#define TRACE_ERL0		0x00004000	/* For ErrorRecoveryLevel=0 */
#define TRACE_ERL1		0x00008000	/* For ErrorRecoveryLevel=1 */
#define TRACE_ERL2		0x00010000	/* For ErrorRecoveryLevel=2 */
#define TRACE_TIMER		0x00020000	/* For various ERL timers */
#define TRACE_R2T		0x00040000	/* For R2T callers */
#define TRACE_SPINDLE		0x00080000	/* For Spindle callers */
#define TRACE_SSLR		0x00100000	/* For SyncNSteering RX */
#define TRACE_SSLT		0x00200000	/* For SyncNSteering TX */
#define TRACE_CHANNEL		0x00400000	/* For SCSI Channels */
#define TRACE_CMDSN		0x00800000	/* For Out of Order CmdSN execution */
#define TRACE_NODEATTRIB	0x01000000	/* For Initiator Nodes */
#define TRACE_SNAPSHOT	        0x02000000	/* For Initiator Nodes */

#define TRACE_VANITY		0x80000000	/* For all Vanity Noise */
#define TRACE_ALL		0xffffffff	/* Turn on all flags */
#define TRACE_ENDING		0x00000000	/* foo */

#if defined(LINUX) && defined(__KERNEL__)
#define PRINT printk
#else
#define PRINT printf
#endif

#define PYX_NOISE

#ifdef PYX_NOISE
#define PYXPRINT(x...) PRINT(x)
#else
#define PYXPRINT(x...)
#endif

#ifdef CONFIG_ISCSI_DEBUG
/*
 * TRACE_VANITY, is always last!
 */
static unsigned int iscsi_trace = 
//		TRACE_DEBUG |
//		TRACE_SCSI |
//		TRACE_ISCSI |
//		TRACE_NET |
//		TRACE_BUFF |
//		TRACE_FILE | 
//		TRACE_LINE |
//       	TRACE_FUNCTION |
//		TRACE_SEM |
//		TRACE_ENTER_LEAVE |
//		TRACE_DIGEST |
//		TRACE_PARAM |
//		TRACE_LOGIN |
//		TRACE_STATE |
		TRACE_ERL0 |
		TRACE_ERL1 |
		TRACE_ERL2 |
//		TRACE_TIMER |
//		TRACE_R2T |
//		TRACE_SPINDLE |
//		TRACE_SSLR |
//		TRACE_SSLT |
//		TRACE_CHANNEL |
//		TRACE_CMDSN |
//		TRACE_NODEATTRIB |
//              TRACE_SNAPSHOT |
		TRACE_VANITY |	
		TRACE_ENDING;

#define TRACE(trace, args...)					\
{								\
static char iscsi_trace_buff[256];				\
if (iscsi_trace&trace) {					\
    sprintf(iscsi_trace_buff, args);				\
  if (iscsi_trace&TRACE_FUNCTION) {				\
    PRINT("%s:%d: %s",  __FUNCTION__, __LINE__,			\
          iscsi_trace_buff);					\
  } else if (iscsi_trace&TRACE_FILE) {				\
    PRINT("%s::%d: %s", __FILE__, __LINE__,			\
          iscsi_trace_buff);					\
  } else if (iscsi_trace & TRACE_LINE) {			\
    PRINT("%d: %s", __LINE__, iscsi_trace_buff);		\
  } else {							\
    PRINT("%s", iscsi_trace_buff);				\
  }								\
}								\
}

#define PRINT_BUFF(buff, len)					\
  if(iscsi_trace&TRACE_BUFF) {					\
    int zzz;							\
								\
    PRINT("%d: \n", __LINE__);					\
    for (zzz=0;zzz<len;zzz++) {					\
      if (zzz%16==0) {						\
        if (zzz) PRINT("\n");					\
        PRINT("%4i: ", zzz);					\
      }								\
      PRINT("%02x ", (unsigned char) (buff)[zzz]);		\
    }								\
    if ((len+1)%16)  PRINT("\n");				\
  }

#define TRACE_ENTER						\
  if (iscsi_trace&TRACE_ENTER_LEAVE) {				\
								\
    PRINT("%s:%d Entering %s on %s:%d\n", __FILE__, __LINE__, 	\
	__FUNCTION__, current->comm, current->pid);		\
								\
  }

#define TRACE_LEAVE						\
  if (iscsi_trace&TRACE_ENTER_LEAVE) {				\
								\
     PRINT("%s:%d Leaving %s on %s:%d\n", __FILE__, __LINE__,	\
	__FUNCTION__, current->comm, current->pid);		\
								\
  }						

#else /* !CONFIG_ISCSI_DEBUG */
#define TRACE(trace, args...)
#define PRINT_BUFF(buff, len)
#define TRACE_ENTER ;
#define TRACE_LEAVE ;
#endif /* CONFIG_ISCSI_DEBUG */

#ifndef __ISCSI_DEBUG_OPCODES_C

static char iscsi_trace_err[256];

#define TRACE_ERROR(args...)			\
({sprintf(iscsi_trace_err, args);		\
PRINT("%s:%i: ***ERROR*** %s",			\
       __FUNCTION__, __LINE__,			\
       iscsi_trace_err);})

#define TRACE_RETURN(ret, args...)		\
({sprintf(iscsi_trace_err, args);		\
PRINT("%s:%i: ***ERROR*** %s",			\
	__FUNCTION__, __LINE__,			\
	iscsi_trace_err);			\
	return(ret);})				\
	
#define TRACE_OPS(args...)			\
({sprintf(iscsi_trace_err, args);		\
PRINT("%s:%i: ***OPS*** %s",			\
	__FUNCTION__, __LINE__,			\
	iscsi_trace_err);})

#endif /* __ISCSI_DEBUG_OPCODES_C */

#if 0
me getting stupid!

#define RETURN_ERROR(ret, args...)					\
({	printk("caller: %p, %s", __builtin_return_address(0), msg);	\
	return(ret);							\
	})							\

#endif

#endif   /*** ISCSI_DEBUG_H ***/

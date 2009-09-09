#ifndef ISCSI_DEBUG_H
#define ISCSI_DEBUG_H

/*
 * Debugging Support
 */

#define TRACE_DEBUG	0x00000001	/* Verbose debugging */
#define TRACE_SCSI	0x00000002	/* Stuff related to SCSI Mid-layer */
#define TRACE_ISCSI	0x00000004	/* Stuff related to iSCSI */
#define TRACE_NET	0x00000008	/* Stuff related to network code */
#define TRACE_BUFF	0x00000010	/* For dumping raw data */
#define TRACE_FILE	0x00000020	/* Used for __FILE__ */
#define TRACE_LINE	0x00000040	/* Used for __LINE__ */
#define TRACE_FUNCTION	0x00000080	/* Used for __FUNCTION__ */
#define TRACE_SEM	0x00000100	/* Stuff related to semaphores */
#define TRACE_ENTER_LEAVE 0x00000200	/* For entering/leaving functions */
#define TRACE_DIGEST	0x00000400	/* For Header/Data Digests */
#define TRACE_PARAM	0x00000800	/* For parameters in parameters.c */
#define TRACE_LOGIN	0x00001000	/* For login related code */
#define TRACE_STATE	0x00002000	/* For conn/sess/cleanup states */
#define TRACE_ERL0	0x00004000	/* For ErrorRecoveryLevel=0 */
#define TRACE_ERL1	0x00008000	/* For ErrorRecoveryLevel=1 */
#define TRACE_ERL2	0x00010000	/* For ErrorRecoveryLevel=2 */
#define TRACE_TIMER	0x00020000	/* For various ERL timers */
#define TRACE_R2T	0x00040000	/* For R2T callers */
#define TRACE_SPINDLE	0x00080000	/* For Spindle callers */
#define TRACE_SSLR	0x00100000	/* For SyncNSteering RX */
#define TRACE_SSLT	0x00200000	/* For SyncNSteering TX */
#define TRACE_CHANNEL	0x00400000	/* For SCSI Channels */
#define TRACE_CMDSN	0x00800000	/* For Out of Order CmdSN execution */
#define TRACE_NODEATTRIB 0x01000000	/* For Initiator Nodes */

#define TRACE_VANITY		0x80000000	/* For all Vanity Noise */
#define TRACE_ALL		0xffffffff	/* Turn on all flags */
#define TRACE_ENDING		0x00000000	/* foo */

#ifdef CONFIG_ISCSI_DEBUG
/*
 * TRACE_VANITY, is always last!
 */
static unsigned int iscsi_trace =
/*		TRACE_DEBUG | */
/*		TRACE_SCSI | */
/*		TRACE_ISCSI | */
/*		TRACE_NET | */
/*		TRACE_BUFF | */
/*		TRACE_FILE | */
/*		TRACE_LINE | */
/*       	TRACE_FUNCTION | */
/*		TRACE_SEM | */
/*		TRACE_ENTER_LEAVE | */
/*		TRACE_DIGEST | */
/*		TRACE_PARAM | */
/*		TRACE_LOGIN | */
/*		TRACE_STATE | */
		TRACE_ERL0 |
		TRACE_ERL1 |
		TRACE_ERL2 |
/*		TRACE_TIMER | */
/*		TRACE_R2T | */
/*		TRACE_SPINDLE | */
/*		TRACE_SSLR | */
/*		TRACE_SSLT | */
/*		TRACE_CHANNEL | */
/*		TRACE_CMDSN | */
/*		TRACE_NODEATTRIB | */
		TRACE_VANITY |
		TRACE_ENDING;

#define TRACE(trace, args...)					\
{								\
static char iscsi_trace_buff[256];				\
								\
if (iscsi_trace & trace) {					\
	sprintf(iscsi_trace_buff, args);			\
	if (iscsi_trace & TRACE_FUNCTION) {			\
		printk(KERN_INFO "%s:%d: %s",  __func__, __LINE__, \
			iscsi_trace_buff);			\
	} else if (iscsi_trace&TRACE_FILE) {			\
		printk(KERN_INFO "%s::%d: %s", __FILE__, __LINE__, \
			iscsi_trace_buff);			\
	} else if (iscsi_trace & TRACE_LINE) {			\
		printk(KERN_INFO "%d: %s", __LINE__, iscsi_trace_buff);	\
	} else {						\
		printk(KERN_INFO "%s", iscsi_trace_buff);	\
	}							\
}								\
}

#define PRINT_BUFF(buff, len)					\
if (iscsi_trace & TRACE_BUFF) {					\
	int zzz;						\
								\
	printk(KERN_INFO "%d: \n", __LINE__);			\
	for (zzz = 0; zzz < len; zzz++) {			\
		if (zzz % 16 == 0) {				\
			if (zzz)				\
				printk(KERN_INFO "\n");		\
			printk(KERN_INFO "%4i: ", zzz);		\
		}						\
		printk(KERN_INFO "%02x ", (unsigned char) (buff)[zzz]);	\
	}							\
	if ((len + 1) % 16)					\
		printk(KERN_INFO "\n");				\
}

#else /* !CONFIG_ISCSI_DEBUG */
#define TRACE(trace, args...)
#define PRINT_BUFF(buff, len)
#endif /* CONFIG_ISCSI_DEBUG */

#endif   /*** ISCSI_DEBUG_H ***/

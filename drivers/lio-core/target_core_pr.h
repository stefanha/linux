/*
 * PERSISTENT_RESERVE_OUT service action codes
 *
 * spc4r17 section 6.14.2 Table 171
 */
#define PRO_REGISTER				0x00
#define PRO_RESERVE				0x01
#define PRO_RELEASE				0x02
#define PRO_CLEAR				0x03
#define PRO_PREEMPT				0x04
#define PRO_PREEMPT_AND_ABORT			0x05
#define PRO_REGISTER_AND_IGNORE_EXISTING_KEY	0x06
#define PRO_REGISTER_AND_MOVE			0x07
/*
 * PERSISTENT_RESERVE_IN service action codes
 *
 * spc4r17 section 6.13.1 Table 159
 */
#define PRI_READ_KEYS				0x00
#define PRI_READ_RESERVATION			0x01
#define PRI_REPORT_CAPABILITIES			0x02
#define PRI_READ_FULL_STATUS			0x03

extern int core_scsi3_emulate_pr (struct se_cmd_s *);
extern int core_setup_reservations (struct se_device_s *);

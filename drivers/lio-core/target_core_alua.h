#ifndef TARGET_CORE_ALUA_H
#define TARGET_CORE_ALUA_H

/*
 * INQUIRY response data, TPGS Field
 *
 * from spc4r17 section 6.4.2 Table 135
 */
#define TPGS_NO_ALUA				0x00
#define TPGS_IMPLICT_ALUA			0x10
#define TPGS_EXPLICT_ALUA			0x20
#define TPGS_EXPLICT_AND_IMPLICT_ALUA		0x40
 
/*
 * ASYMMETRIC ACCESS STATE field
 *
 * from spc4r17 section 6.27 Table 245
 */
#define ALUA_ACCESS_STATE_ACTIVE_OPTMIZED	0x0
#define ALUA_ACCESS_STATE_ACTIVE_NON_OPTIMIZED	0x1
#define ALUA_ACCESS_STATE_STANDBY		0x2
#define ALUA_ACCESS_STATE_UNAVAILABLE		0x3
#define ALUA_ACCESS_STATE_OFFLINE		0xe
#define ALUA_ACCESS_STATE_TRANSITION		0xf

/*
 * REPORT_TARGET_PORT_GROUP STATUS CODE
 *
 * from spc4r17 section 6.27 Table 246
 */
#define ALUA_STATUS_NONE				0x00
#define ALUA_STATUS_ALTERED_BY_EXPLICT_STPG		0x01
#define ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA		0x02

extern int core_scsi3_emulate_report_target_port_groups (struct se_cmd_s *);
extern int core_setup_alua (struct se_device_s *);

#endif // TARGET_CORE_ALUA_H

#ifndef ISCSI_TARGET_DEVICE_H
#define ISCSI_TARGET_DEVICE_H

extern int iscsi_get_lun_for_tmr(iscsi_cmd_t *, u64);
extern int iscsi_get_lun_for_cmd(iscsi_cmd_t *, unsigned char *, u64);
extern void iscsi_determine_maxcmdsn(iscsi_session_t *);
extern void iscsi_increment_maxcmdsn(iscsi_cmd_t *, iscsi_session_t *);

#endif /* ISCSI_TARGET_DEVICE_H */

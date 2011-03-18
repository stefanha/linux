#ifndef ISCSI_TARGET_DEVICE_H
#define ISCSI_TARGET_DEVICE_H

extern int iscsi_get_lun_for_tmr(struct iscsi_cmd *, u64);
extern int iscsi_get_lun_for_cmd(struct iscsi_cmd *, unsigned char *, u64);
extern void iscsi_determine_maxcmdsn(struct iscsi_session *);
extern void iscsi_increment_maxcmdsn(struct iscsi_cmd *, struct iscsi_session *);

#endif /* ISCSI_TARGET_DEVICE_H */

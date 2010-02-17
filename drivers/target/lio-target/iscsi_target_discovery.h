#ifndef ISCSI_TARGET_DISCOVERY_H
#define ISCSI_TARGET_DISCOVERY_H

extern int iscsi_build_sendtargets_response(iscsi_cmd_t *);

extern iscsi_global_t *iscsi_global;
extern void iscsi_ntoa2(unsigned char *, __u32);

#endif /* ISCSI_TARGET_DISCOVERY_H */

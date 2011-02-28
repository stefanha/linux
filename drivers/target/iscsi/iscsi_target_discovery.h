#ifndef ISCSI_TARGET_DISCOVERY_H
#define ISCSI_TARGET_DISCOVERY_H

extern int iscsi_build_sendtargets_response(struct iscsi_cmd *);

extern struct iscsi_global *iscsi_global;
extern void iscsi_ntoa2(unsigned char *, __u32);

#endif /* ISCSI_TARGET_DISCOVERY_H */

#ifndef ISCSI_TARGET_NEGO_H
#define ISCSI_TARGET_NEGO_H

extern struct iscsi_login *iscsi_target_init_negotiation(
		struct iscsi_np *, struct iscsi_conn *, char *);
extern int iscsi_target_start_negotiation(
		struct iscsi_login *, struct iscsi_conn *);
extern void iscsi_target_nego_release(
		struct iscsi_login *, struct iscsi_conn *);

extern struct iscsi_global *iscsi_global;

#endif /* ISCSI_TARGET_NEGO_H */


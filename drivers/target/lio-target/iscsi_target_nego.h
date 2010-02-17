#ifndef ISCSI_TARGET_NEGO_H
#define ISCSI_TARGET_NEGO_H

extern struct iscsi_login_s *iscsi_target_init_negotiation(
		struct iscsi_np_s *, struct iscsi_conn_s *, char *);
extern int iscsi_target_start_negotiation(
		struct iscsi_login_s *, struct iscsi_conn_s *);
extern void iscsi_target_nego_release(
		struct iscsi_login_s *, struct iscsi_conn_s *);

extern struct iscsi_global_s *iscsi_global;

#endif /* ISCSI_TARGET_NEGO_H */


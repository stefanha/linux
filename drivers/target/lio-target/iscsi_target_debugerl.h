#ifndef ISCSI_TARGET_DEBUGERL_H
#define ISCSI_TARGET_DEBUGERL_H

extern int iscsi_target_debugerl_tx_thread(struct iscsi_conn *);
extern int iscsi_target_debugerl_rx_thread0(struct iscsi_conn *);
extern int iscsi_target_debugerl_rx_thread1(struct iscsi_conn *);
extern int iscsi_target_debugerl_data_out_0(struct iscsi_conn *, unsigned char *);
extern int iscsi_target_debugerl_data_out_1(struct iscsi_conn *, unsigned char *);
extern int iscsi_target_debugerl_immeidate_data(struct iscsi_conn *, u32);
extern int iscsi_target_debugerl_cmdsn(struct iscsi_conn *, u32);

extern struct iscsi_global *iscsi_global;

#endif /* ISCSI_TARGET_DEBUGERL_H */

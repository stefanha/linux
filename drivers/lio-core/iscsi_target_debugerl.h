#ifndef ISCSI_TARGET_DEBUGERL_H
#define ISCSI_TARGET_DEBUGERL_H

extern int iscsi_target_debugerl_tx_thread(iscsi_conn_t *);
extern int iscsi_target_debugerl_rx_thread0(iscsi_conn_t *);
extern int iscsi_target_debugerl_rx_thread1(iscsi_conn_t *);
extern int iscsi_target_debugerl_data_out_0(iscsi_conn_t *, unsigned char *);
extern int iscsi_target_debugerl_data_out_1(iscsi_conn_t *, unsigned char *);
extern int iscsi_target_debugerl_immeidate_data(iscsi_conn_t *, u32);
extern int iscsi_target_debugerl_cmdsn(iscsi_conn_t *, u32);

extern iscsi_global_t *iscsi_global;

#endif /* ISCSI_TARGET_DEBUGERL_H */

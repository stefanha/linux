#ifndef ISCSI_TARGET_NODEATTRIB_H
#define ISCSI_TARGET_NODEATTRIB_H

extern void iscsi_set_default_node_attribues(iscsi_node_acl_t *);
extern int iscsi_na_dataout_timeout(iscsi_node_acl_t *, u32);
extern int iscsi_na_dataout_timeout_retries(iscsi_node_acl_t *, u32);
extern int iscsi_na_nopin_timeout(iscsi_node_acl_t *, u32);
extern int iscsi_na_nopin_response_timeout(iscsi_node_acl_t *, u32);
extern int iscsi_na_random_datain_pdu_offsets(iscsi_node_acl_t *, u32);
extern int iscsi_na_random_datain_seq_offsets(iscsi_node_acl_t *, u32);
extern int iscsi_na_random_r2t_offsets(iscsi_node_acl_t *, u32);
extern int iscsi_na_default_erl(iscsi_node_acl_t *, u32);

#endif /* ISCSI_TARGET_NODEATTRIB_H */

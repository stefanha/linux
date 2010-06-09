#ifndef TARGET_CORE_FABRIC_LIB_H
#define TARGET_CORE_FABRIC_LIB_H

extern u8 sas_get_fabric_proto_ident(se_portal_group_t *);
extern u32 sas_get_pr_transport_id(se_portal_group_t *, se_node_acl_t *,
			t10_pr_registration_t *, int *, unsigned char *);
extern u32 sas_get_pr_transport_id_len(se_portal_group_t *, se_node_acl_t *,
			t10_pr_registration_t *, int *);
extern char *sas_parse_pr_out_transport_id(se_portal_group_t *,
			const char *, u32 *, char **);

extern u8 fc_get_fabric_proto_ident(se_portal_group_t *);
extern u32 fc_get_pr_transport_id(se_portal_group_t *, se_node_acl_t *,
			t10_pr_registration_t *, int *, unsigned char *);
extern u32 fc_get_pr_transport_id_len(se_portal_group_t *, se_node_acl_t *,
			t10_pr_registration_t *, int *);
extern char *fc_parse_pr_out_transport_id(se_portal_group_t *,
			const char *, u32 *, char **);

extern u8 iscsi_get_fabric_proto_ident(se_portal_group_t *);
extern u32 iscsi_get_pr_transport_id(se_portal_group_t *, se_node_acl_t *,
			t10_pr_registration_t *, int *, unsigned char *);
extern u32 iscsi_get_pr_transport_id_len(se_portal_group_t *, se_node_acl_t *,
			t10_pr_registration_t *, int *);
extern char *iscsi_parse_pr_out_transport_id(se_portal_group_t *,
			const char *, u32 *, char **);

#endif /* TARGET_CORE_FABRIC_LIB_H */

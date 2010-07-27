#ifndef ISCSI_TARGET_TPG_H
#define ISCSI_TARGET_TPG_H

extern char *lio_tpg_get_endpoint_wwn(struct se_portal_group *);
extern u16 lio_tpg_get_tag(struct se_portal_group *);
extern u32 lio_tpg_get_default_depth(struct se_portal_group *);
extern int lio_tpg_check_demo_mode(struct se_portal_group *);
extern int lio_tpg_check_demo_mode_cache(struct se_portal_group *);
extern int lio_tpg_check_demo_mode_write_protect(struct se_portal_group *);
extern int lio_tpg_check_prod_mode_write_protect(struct se_portal_group *);
extern struct se_node_acl *lio_tpg_alloc_fabric_acl(struct se_portal_group *);
extern void lio_tpg_release_fabric_acl(struct se_portal_group *,
			struct se_node_acl *);
extern int lio_tpg_shutdown_session(struct se_session *);
extern void lio_tpg_close_session(struct se_session *);
extern void lio_tpg_stop_session(struct se_session *, int, int);
extern void lio_tpg_fall_back_to_erl0(struct se_session *);
#ifdef SNMP_SUPPORT
extern u32 lio_tpg_get_inst_index(struct se_portal_group *);
#endif /* SNMP_SUPPORT */
extern void lio_set_default_node_attributes(struct se_node_acl *);

extern struct iscsi_portal_group *core_alloc_portal_group(struct iscsi_tiqn *, u16);
extern int core_load_discovery_tpg(void);
extern void core_release_discovery_tpg(void);
extern struct iscsi_portal_group *core_get_tpg_from_np(struct iscsi_tiqn *,
			struct iscsi_np *);
extern int iscsi_get_tpg(struct iscsi_portal_group *);
extern void iscsi_put_tpg(struct iscsi_portal_group *);
extern void iscsi_clear_tpg_np_login_threads(struct iscsi_portal_group *, int);
extern void iscsi_tpg_dump_params(struct iscsi_portal_group *);
extern int iscsi_tpg_add_portal_group(struct iscsi_tiqn *, struct iscsi_portal_group *);
extern int iscsi_tpg_del_portal_group(struct iscsi_tiqn *, struct iscsi_portal_group *,
			int);
extern int iscsi_tpg_enable_portal_group(struct iscsi_portal_group *);
extern int iscsi_tpg_disable_portal_group(struct iscsi_portal_group *, int);
extern struct iscsi_node_acl *iscsi_tpg_add_initiator_node_acl(
			struct iscsi_portal_group *, const char *, u32);
extern void iscsi_tpg_del_initiator_node_acl(struct iscsi_portal_group *,
			struct se_node_acl *);
extern struct iscsi_node_attrib *iscsi_tpg_get_node_attrib(struct iscsi_session *);
extern void iscsi_tpg_del_external_nps(struct iscsi_tpg_np *);
extern struct iscsi_tpg_np *iscsi_tpg_locate_child_np(struct iscsi_tpg_np *, int);
extern struct iscsi_tpg_np *iscsi_tpg_add_network_portal(struct iscsi_portal_group *,
			struct iscsi_np_addr *, struct iscsi_tpg_np *, int);
extern int iscsi_tpg_del_network_portal(struct iscsi_portal_group *,
			struct iscsi_tpg_np *);
extern int iscsi_tpg_set_initiator_node_queue_depth(struct iscsi_portal_group *,
			unsigned char *, u32, int);
extern int iscsi_ta_authentication(struct iscsi_portal_group *, u32);
extern int iscsi_ta_login_timeout(struct iscsi_portal_group *, u32);
extern int iscsi_ta_netif_timeout(struct iscsi_portal_group *, u32);
extern int iscsi_ta_generate_node_acls(struct iscsi_portal_group *, u32);
extern int iscsi_ta_default_cmdsn_depth(struct iscsi_portal_group *, u32);
extern int iscsi_ta_cache_dynamic_acls(struct iscsi_portal_group *, u32);
extern int iscsi_ta_demo_mode_write_protect(struct iscsi_portal_group *, u32);
extern int iscsi_ta_prod_mode_write_protect(struct iscsi_portal_group *, u32);
extern void iscsi_disable_tpgs(struct iscsi_tiqn *);
extern void iscsi_disable_all_tpgs(void);
extern void iscsi_remove_tpgs(struct iscsi_tiqn *);
extern void iscsi_remove_all_tpgs(void);

extern struct iscsi_global *iscsi_global;
extern struct target_fabric_configfs *lio_target_fabric_configfs;
extern struct kmem_cache *lio_tpg_cache;

extern int iscsi_close_session(struct iscsi_session *);
extern int iscsi_free_session(struct iscsi_session *);
extern int iscsi_release_sessions_for_tpg(struct iscsi_portal_group *, int);
extern int iscsi_ta_authentication(struct iscsi_portal_group *, __u32);

#endif /* ISCSI_TARGET_TPG_H */

#ifndef TARGET_CORE_ALUA_H
#define TARGET_CORE_ALUA_H

/*
 * INQUIRY response data, TPGS Field
 *
 * from spc4r17 section 6.4.2 Table 135
 */
#define TPGS_NO_ALUA				0x00
#define TPGS_IMPLICT_ALUA			0x10
#define TPGS_EXPLICT_ALUA			0x20
#define TPGS_EXPLICT_AND_IMPLICT_ALUA		0x40

/*
 * ASYMMETRIC ACCESS STATE field
 *
 * from spc4r17 section 6.27 Table 245
 */
#define ALUA_ACCESS_STATE_ACTIVE_OPTMIZED	0x0
#define ALUA_ACCESS_STATE_ACTIVE_NON_OPTIMIZED	0x1
#define ALUA_ACCESS_STATE_STANDBY		0x2
#define ALUA_ACCESS_STATE_UNAVAILABLE		0x3
#define ALUA_ACCESS_STATE_OFFLINE		0xe
#define ALUA_ACCESS_STATE_TRANSITION		0xf

/*
 * REPORT_TARGET_PORT_GROUP STATUS CODE
 *
 * from spc4r17 section 6.27 Table 246
 */
#define ALUA_STATUS_NONE				0x00
#define ALUA_STATUS_ALTERED_BY_EXPLICT_STPG		0x01
#define ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA		0x02

extern se_global_t *se_global;

extern struct kmem_cache *t10_alua_lu_gp_cache;
extern struct kmem_cache *t10_alua_lu_gp_mem_cache;
extern struct kmem_cache *t10_alua_tg_pt_gp_cache;
extern struct kmem_cache *t10_alua_tg_pt_gp_mem_cache;

extern int core_scsi3_emulate_report_target_port_groups(struct se_cmd_s *);
extern struct t10_alua_lu_gp_s *core_alua_allocate_lu_gp(const char *, int);
extern int core_alua_set_lu_gp_id(struct t10_alua_lu_gp_s *, u16);
extern struct t10_alua_lu_gp_member_s *core_alua_allocate_lu_gp_mem(
					struct se_device_s *);
extern void core_alua_free_lu_gp(struct t10_alua_lu_gp_s *);
extern void core_alua_free_lu_gp_mem(struct se_device_s *);
extern struct t10_alua_lu_gp_s *core_alua_get_lu_gp_by_name(const char *);
extern void core_alua_put_lu_gp_from_name(struct t10_alua_lu_gp_s *);
extern void __core_alua_attach_lu_gp_mem(struct t10_alua_lu_gp_member_s *,
					struct t10_alua_lu_gp_s *);
extern void __core_alua_drop_lu_gp_mem(struct t10_alua_lu_gp_member_s *,
					struct t10_alua_lu_gp_s *);
extern void core_alua_drop_lu_gp_dev(struct se_device_s *);
extern struct t10_alua_tg_pt_gp_s *core_alua_allocate_tg_pt_gp(const char *, int);
extern int core_alua_set_tg_pt_gp_id(struct t10_alua_tg_pt_gp_s *, u16);
extern struct t10_alua_tg_pt_gp_member_s *core_alua_allocate_tg_pt_gp_mem(
					struct se_port_s *);
extern void core_alua_free_tg_pt_gp(struct t10_alua_tg_pt_gp_s *);
extern void core_alua_free_tg_pt_gp_mem(struct se_port_s *);
extern struct t10_alua_tg_pt_gp_s *core_alua_get_tg_pt_gp_by_name(const char *);
extern void core_alua_put_tg_pt_gp_from_name(struct t10_alua_tg_pt_gp_s *);
extern void __core_alua_attach_tg_pt_gp_mem(struct t10_alua_tg_pt_gp_member_s *,
					struct t10_alua_tg_pt_gp_s *);
extern void __core_alua_drop_tg_pt_gp_mem(struct t10_alua_tg_pt_gp_member_s *,
					struct t10_alua_tg_pt_gp_s *);
extern ssize_t core_alua_show_tg_pt_gp_info(struct se_port_s *, char *);
extern ssize_t core_alua_store_tg_pt_gp_info(struct se_port_s *, const char *,
						size_t);
extern int core_setup_alua(struct se_device_s *);

#endif /* TARGET_CORE_ALUA_H */

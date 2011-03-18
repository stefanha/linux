#ifndef ISCSI_TARGET_DATAIN_VALUES_H
#define ISCSI_TARGET_DATAIN_VALUES_H

extern struct iscsi_datain_req *iscsi_allocate_datain_req(void);
extern void iscsi_attach_datain_req(struct iscsi_cmd *, struct iscsi_datain_req *);
extern void iscsi_free_datain_req(struct iscsi_cmd *, struct iscsi_datain_req *);
extern void iscsi_free_all_datain_reqs(struct iscsi_cmd *);
extern struct iscsi_datain_req *iscsi_get_datain_req(struct iscsi_cmd *);
extern struct iscsi_datain_req *iscsi_get_datain_values(struct iscsi_cmd *,
			struct iscsi_datain *);

extern struct iscsi_global *iscsi_global;
extern struct kmem_cache *lio_dr_cache;

#endif   /*** ISCSI_TARGET_DATAIN_VALUES_H ***/


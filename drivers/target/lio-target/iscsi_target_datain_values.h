#ifndef ISCSI_TARGET_DATAIN_VALUES_H
#define ISCSI_TARGET_DATAIN_VALUES_H

extern iscsi_datain_req_t *iscsi_allocate_datain_req(void);
extern void iscsi_attach_datain_req(iscsi_cmd_t *, iscsi_datain_req_t *);
extern void iscsi_free_datain_req(iscsi_cmd_t *, iscsi_datain_req_t *);
extern void iscsi_free_all_datain_reqs(iscsi_cmd_t *);
extern iscsi_datain_req_t *iscsi_get_datain_req(iscsi_cmd_t *);
extern iscsi_datain_req_t *iscsi_get_datain_values(iscsi_cmd_t *,
			iscsi_datain_t *);

extern iscsi_global_t *iscsi_global;
extern struct kmem_cache *lio_dr_cache;

#endif   /*** ISCSI_TARGET_DATAIN_VALUES_H ***/


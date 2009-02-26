#ifndef TARGET_CORE_TMR_H
#define TARGET_CORE_TMR_H

extern struct kmem_cache *se_tmr_req_cache;

extern struct se_tmr_req_s *core_tmr_alloc_req(void *, u8);
extern void core_tmr_release_req(struct se_tmr_req_s *);
extern int core_tmr_lun_reset(struct se_device_s *, struct se_tmr_req_s *);

#endif /* TARGET_CORE_TMR_H */

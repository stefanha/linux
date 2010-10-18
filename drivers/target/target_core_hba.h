#ifndef TARGET_CORE_HBA_H
#define TARGET_CORE_HBA_H

extern struct se_global *se_global;

extern struct kmem_cache *se_hba_cache;

extern int core_get_hba(struct se_hba *);
extern struct se_hba *core_alloc_hba(void);
extern void core_put_hba(struct se_hba *);
extern int se_core_add_hba(struct se_hba *, const char *, u32);
extern int se_core_del_hba(struct se_hba *);

#endif /* TARGET_CORE_HBA_H */

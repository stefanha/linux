#ifndef TARGET_CORE_SCDB_H
#define TARGET_CORE_SCDB_H

extern void split_cdb_XX_6(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_6(unsigned long long, u32 *, unsigned char *, int);
extern void split_cdb_XX_10(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_10(unsigned long long, u32 *, unsigned char *, int);
extern void split_cdb_XX_12(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_12(unsigned long long, u32 *, unsigned char *, int);
extern void split_cdb_XX_16(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_16(unsigned long long, u32 *, unsigned char *, int);
extern void split_cdb_XX_32(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_32(unsigned long long, u32 *, unsigned char *, int);

#endif /* TARGET_CORE_SCDB_H */

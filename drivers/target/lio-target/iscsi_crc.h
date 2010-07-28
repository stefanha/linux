#ifndef _ISCSI_CRC_H_
#define _ISCSI_CRC_H_

/*	calculate a 32-bit crc	*/
/*	if restart has 0x01 set, initialize the accumulator */
/*	if restart has 0x02 set, save result in network byte order */
extern void do_crc(__u8 *data, __u32 len, int restart, __u32 *result);

#endif /*** _ISCSI_CRC_H_ ***/

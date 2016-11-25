#ifndef __LINUX_EVENTFD_H
#define __LINUX_EVENTFD_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define EVENTFDIO 0xB5

#define EVENTFD_SET_POLL_INFO _IOW(EVENTFDIO, 0x00, struct eventfd_poll_info)

/* struct eventfd_poll_info::flags */
#define EVENTFD_POLL_INFO_U8           0x0
#define EVENTFD_POLL_INFO_U16          0x1
#define EVENTFD_POLL_INFO_U32          0x2
#define EVENTFD_POLL_INFO_U64          0x3
#define EVENTFD_POLL_INFO_SIZE_MASK    0x3

/* struct eventfd_poll_info::op */
#define EVENTFD_POLL_INFO_OP_NOP       0x00 /* false */
#define EVENTFD_POLL_INFO_OP_EQUAL     0x01 /* *addr == value */
#define EVENTFD_POLL_INFO_OP_NOT_EQUAL 0x02 /* *addr != value */
#define EVENTFD_POLL_INFO_OP_AND       0x03 /* (*addr & value) != 0 */
#define EVENTFD_POLL_INFO_OP_MAX       0x03

struct eventfd_poll_info {
	__u64 addr;
	__u64 value;
	__u32 flags;
	__u32 op;
};

#endif /* __LINUX_EVENTFD_H */

/*
 *  linux/include/linux/sunrpc/xprtsock.h
 *
 *  Declarations for the RPC transport socket provider.
 */

#ifndef _LINUX_SUNRPC_XPRTSOCK_H
#define _LINUX_SUNRPC_XPRTSOCK_H

#ifdef __KERNEL__

/* TODO why does this header have no includes? */
#include <net/tcp.h> /* for sk_read_actor_t */

int		init_socket_xprt(void);
void		cleanup_socket_xprt(void);

#define RPC_MIN_RESVPORT	(1U)
#define RPC_MAX_RESVPORT	(65535U)
#define RPC_DEF_MIN_RESVPORT	(665U)
#define RPC_DEF_MAX_RESVPORT	(1023U)

struct sock_xprt {
	struct rpc_xprt		xprt;

	/*
	 * Network layer
	 */
	struct socket *		sock;
	struct sock *		inet;

	/*
	 * State of SOCK_STREAM reply receive
	 */
	__be32			stream_fraghdr,
				stream_xid,
				stream_calldir;

	u32			stream_offset,
				stream_reclen;

	unsigned long		stream_copied,
				stream_flags;

	int			(*stream_read_sock)(struct sock *,
						    read_descriptor_t *,
						    sk_read_actor_t);

	/*
	 * Connection of transports
	 */
	unsigned long		sock_state;
	struct delayed_work	connect_worker;
	struct work_struct	recv_worker;
	struct mutex		recv_mutex;
	struct sockaddr_storage	srcaddr;
	unsigned short		srcport;

	/*
	 * UDP socket buffer size parameters
	 */
	size_t			rcvsize,
				sndsize;

	/*
	 * Saved socket callback addresses
	 */
	void			(*old_data_ready)(struct sock *);
	void			(*old_state_change)(struct sock *);
	void			(*old_write_space)(struct sock *);
	void			(*old_error_report)(struct sock *);
};

/*
 * TCP receive state flags
 */
#define STREAM_RCV_LAST_FRAG	(1UL << 0)
#define STREAM_RCV_COPY_FRAGHDR	(1UL << 1)
#define STREAM_RCV_COPY_XID	(1UL << 2)
#define STREAM_RCV_COPY_DATA	(1UL << 3)
#define STREAM_RCV_READ_CALLDIR	(1UL << 4)
#define STREAM_RCV_COPY_CALLDIR	(1UL << 5)

/*
 * TCP RPC flags
 */
#define STREAM_RPC_REPLY	(1UL << 6)

#define XPRT_SOCK_CONNECTING	1U

#endif /* __KERNEL__ */

#endif /* _LINUX_SUNRPC_XPRTSOCK_H */

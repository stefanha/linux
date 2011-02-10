#define TCM_VHOST_VERSION  "v0.1"
#define TCM_VHOST_NAMELEN 256

struct tcm_vhost_nacl {
	/* Binary World Wide unique Port Name for Vhost Initiator port */
	u64 iport_wwpn;
	/* ASCII formatted WWPN for Sas Initiator port */
	char iport_name[TCM_VHOST_NAMELEN];
	/* Returned by tcm_vhost_make_nodeacl() */
	struct se_node_acl se_node_acl;
};

struct tcm_vhost_tpg {
	/* Vhost port target portal group tag for TCM */
	u16 tport_tpgt;
	/* Pointer back to tcm_vhost_tport */
	struct tcm_vhost_tport *tport;
	/* Returned by tcm_vhost_make_tpg() */
	struct se_portal_group se_tpg;
};

struct tcm_vhost_tport {
	/* SCSI protocol the tport is providing */
	u8 tport_proto_id;
	/* Binary World Wide unique Port Name for Vhost Target port */
	u64 tport_wwpn;
	/* ASCII formatted WWPN for Vhost Target port */
	char tport_name[TCM_VHOST_NAMELEN];
	/* Returned by tcm_vhost_make_tport() */
	struct se_wwn tport_wwn;
};

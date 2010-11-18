#include <target/target_core_base.h>

#define TCM_QLA2XXX_VERSION	"v0.1"
/* length of ASCII WWPNs including pad */
#define TCM_QLA2XXX_NAMELEN	32
/* lenth of ASCII NPIV 'WWPN+WWNN' including pad */
#define TCM_QLA2XXX_NPIV_NAMELEN 66

struct tcm_qla2xxx_cmd {
	struct se_cmd se_cmd;
};

struct tcm_qla2xxx_nacl {
	/* Binary World Wide unique Port Name for FC Initiator Nport */
	u64 nport_wwpn;
	/* ASCII formatted WWPN for FC Initiator Nport */
	char nport_name[TCM_QLA2XXX_NAMELEN];
	/* Returned by tcm_qla2xxx_make_nodeacl() */
	struct se_node_acl se_node_acl;
};

struct tcm_qla2xxx_tpg {
	/* FC lport target portal group tag for TCM */
	u16 lport_tpgt;
	/* Pointer back to tcm_qla2xxx_lport */
	struct tcm_qla2xxx_lport *lport;
	/* Returned by tcm_qla2xxx_make_tpg() */
	struct se_portal_group se_tpg;
};

struct tcm_qla2xxx_lport {
	/* SCSI protocol the lport is providing */
	u8 lport_proto_id;
	/* Binary World Wide unique Port Name for FC Target Lport */
	u64 lport_wwpn;
	/* Binary World Wide unique Port Name for FC NPIV Target Lport */
	u64 lport_npiv_wwpn;
	/* Binary World Wide unique Node Name for FC NPIV Target Lport */
	u64 lport_npiv_wwnn;
	/* ASCII formatted WWPN for FC Target Lport */
	char lport_name[TCM_QLA2XXX_NAMELEN];
	/* ASCII formatted WWPN+WWNN for NPIV FC Target Lport */
	char lport_npiv_name[TCM_QLA2XXX_NPIV_NAMELEN];
	/* Pointer to struct scsi_qla_host from qla2xxx LLD */
	struct scsi_qla_host *qla_vha;
	/* Pointer to struct scsi_qla_host for NPIV VP from qla2xxx LLD */
	struct scsi_qla_host *qla_npiv_vp;
	/* Pointer to struct fc_vport for NPIV vport from libfc */
	struct fc_vport *npiv_vport;
	/* Returned by tcm_qla2xxx_make_lport() */
	struct se_wwn lport_wwn;
};

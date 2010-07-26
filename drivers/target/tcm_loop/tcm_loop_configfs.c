/*******************************************************************************
 * Filename:  tcm_loop_configfs.c
 *
 * This file contains configfs implemenation for initiator and target
 * side CDB level emulation of SAS, FC and iSCSI ports to Linux/SCSI LUNs.
 *
 * Copyright (c) 2009, 2010 Rising Tide, Inc.
 * Copyright (c) 2009, 2010 Linux-iSCSI.org
 *
 * Copyright (c) 2009, 2010 Nicholas A. Bellinger <nab@linux-iscsi.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 ****************************************************************************/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/configfs.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_fabric_lib.h>
#include <target/target_core_device.h>
#include <target/target_core_tpg.h>
#include <target/target_core_configfs.h>
#include <target/target_core_alua.h>
#include <target/target_core_base.h>
#include <target/target_core_seobj.h>
#include <target/configfs_macros.h>

#include <tcm_loop_core.h>
#include <tcm_loop_configfs.h>
#include <tcm_loop_fabric.h>
#include <tcm_loop_fabric_scsi.h>

/* Local pointer to allocated TCM configfs fabric module */
struct target_fabric_configfs *tcm_loop_fabric_configfs;

static int tcm_loop_hba_no_cnt;

static char *tcm_loop_dump_proto_id(struct tcm_loop_hba *tl_hba)
{
	switch (tl_hba->tl_proto_id) {
	case SCSI_PROTOCOL_SAS:
		return "SAS";
	case SCSI_PROTOCOL_FCP:
		return "FCP";
	case SCSI_PROTOCOL_ISCSI:
		return "iSCSI";
	default:
		break;
	}

	return "Unknown";
}

/* Start items for tcm_loop_port_cit */

int tcm_loop_port_link(
	struct se_portal_group *se_tpg,
	struct se_lun *lun)
{
	struct tcm_loop_tpg *tl_tpg = container_of(se_tpg,
				struct tcm_loop_tpg, tl_se_tpg);
	struct tcm_loop_hba *tl_hba = tl_tpg->tl_hba;

	atomic_inc(&tl_tpg->tl_tpg_port_count);
	smp_mb__after_atomic_inc();
	/*
	 * Add Linux/SCSI struct scsi_device by HCTL
	 */
	scsi_add_device(tl_hba->sh, 0, tl_tpg->tl_tpgt, lun->unpacked_lun);

	printk(KERN_INFO "TCM_Loop_ConfigFS: Port Link Successful\n");
	return 0;
}

void tcm_loop_port_unlink(
	struct se_portal_group *se_tpg,
	struct se_lun *se_lun)
{
	struct scsi_device *sd;
	struct tcm_loop_hba *tl_hba;
	struct tcm_loop_tpg *tl_tpg;

	tl_tpg = container_of(se_tpg, struct tcm_loop_tpg, tl_se_tpg);
	tl_hba = tl_tpg->tl_hba;	

	sd = scsi_device_lookup(tl_hba->sh, 0, tl_tpg->tl_tpgt,
				se_lun->unpacked_lun);
	if (!(sd)) {
		printk(KERN_ERR "Unable to locate struct scsi_device for %d:%d:"
			"%d\n", 0, tl_tpg->tl_tpgt, se_lun->unpacked_lun);
		return;
	}
	/*
	 * Remove Linux/SCSI struct scsi_device by HCTL
	 */
	scsi_remove_device(sd);	
	scsi_device_put(sd);
	
	atomic_dec(&tl_tpg->tl_tpg_port_count);
	smp_mb__after_atomic_dec();

	printk(KERN_INFO "TCM_Loop_ConfigFS: Port Unlink Successful\n");
}

/* End items for tcm_loop_port_cit */

/* Start items for tcm_loop_nexus_cit */

static int tcm_loop_make_nexus(
	struct tcm_loop_tpg *tl_tpg,
	const char *name)
{
	struct se_portal_group *se_tpg;
	struct tcm_loop_hba *tl_hba = tl_tpg->tl_hba;
	struct tcm_loop_nexus *tl_nexus;

	if (tl_tpg->tl_hba->tl_nexus) {
		printk(KERN_INFO "tl_tpg->tl_hba->tl_nexus already exists\n");
		return -EEXIST;
	}
	se_tpg = &tl_tpg->tl_se_tpg;

	tl_nexus = kzalloc(sizeof(struct tcm_loop_nexus), GFP_KERNEL);
	if (!(tl_nexus)) {
		printk(KERN_ERR "Unable to allocate struct tcm_loop_nexus\n");
		return -ENOMEM;
	}
	/*
	 * Initialize the struct se_session pointer
	 */
	tl_nexus->se_sess = transport_init_session();
	if (!(tl_nexus->se_sess))
		goto out;
	/*
	 * Since we are running in 'demo mode' this call with generate a
	 * struct se_node_acl for the tcm_loop struct se_portal_group with the SCSI
	 * Initiator port name of the passed configfs group 'name'.
	 */	
	tl_nexus->se_sess->se_node_acl = core_tpg_check_initiator_node_acl(
				se_tpg, (unsigned char *)name);
	if (!(tl_nexus->se_sess->se_node_acl)) {
		transport_free_session(tl_nexus->se_sess);
		goto out;
	}
	/*
	 * Now, register the SAS I_T Nexus as active with the call to
	 * transport_register_session()
	 */
	__transport_register_session(se_tpg, tl_nexus->se_sess->se_node_acl,
			tl_nexus->se_sess, (void *)tl_nexus);
	tl_tpg->tl_hba->tl_nexus = tl_nexus;
	printk(KERN_INFO "TCM_Loop_ConfigFS: Established I_T Nexus to emulated"
		" %s Initiator Port: %s\n", tcm_loop_dump_proto_id(tl_hba),
		name);
	return 0;

out:
	kfree(tl_nexus);	
	return -ENOMEM;
}

static int tcm_loop_drop_nexus(
	struct tcm_loop_tpg *tpg)
{
	struct se_session *se_sess;
	struct tcm_loop_nexus *tl_nexus;
	struct tcm_loop_hba *tl_hba = tpg->tl_hba;

	tl_nexus = tpg->tl_hba->tl_nexus;
	if (!(tl_nexus))
		return -ENODEV;

	se_sess = tl_nexus->se_sess;
	if (!(se_sess))
		return -ENODEV;

	if (atomic_read(&tpg->tl_tpg_port_count)) {
		printk(KERN_ERR "Unable to remove TCM_Loop I_T Nexus with"
			" active TPG port count: %d\n",
			atomic_read(&tpg->tl_tpg_port_count));
		return -EPERM;
	}

	printk(KERN_INFO "TCM_Loop_ConfigFS: Removing I_T Nexus to emulated"
		" %s Initiator Port: %s\n", tcm_loop_dump_proto_id(tl_hba),
		tl_nexus->se_sess->se_node_acl->initiatorname);
	/*
	 * Release the SCSI I_T Nexus to the emulated SAS Target Port
	 */
	transport_deregister_session(tl_nexus->se_sess);
	tpg->tl_hba->tl_nexus = NULL;
	kfree(tl_nexus);
	return 0;
}

/* End items for tcm_loop_nexus_cit */

static ssize_t tcm_loop_tpg_show_nexus(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct tcm_loop_tpg *tl_tpg = container_of(se_tpg,
			struct tcm_loop_tpg, tl_se_tpg);
	struct tcm_loop_nexus *tl_nexus;
	ssize_t ret;

	tl_nexus = tl_tpg->tl_hba->tl_nexus;
	if (!(tl_nexus))
		return -ENODEV;

	ret = snprintf(page, PAGE_SIZE, "%s\n",
		tl_nexus->se_sess->se_node_acl->initiatorname);

	return ret;
}

static ssize_t tcm_loop_tpg_store_nexus(
	struct se_portal_group *se_tpg,
	const char *page,
	size_t count)
{
	struct tcm_loop_tpg *tl_tpg = container_of(se_tpg,
			struct tcm_loop_tpg, tl_se_tpg);
	struct tcm_loop_hba *tl_hba = tl_tpg->tl_hba;
	unsigned char i_port[TL_WWN_ADDR_LEN], *ptr, *port_ptr;
	int ret;
	/*
	 * Shutdown the active I_T nexus if 'NULL' is passed..
	 */
	if (!(strncmp(page, "NULL", 4))) {
		ret = tcm_loop_drop_nexus(tl_tpg);
		return (!ret) ? count : ret;
	}
	/*
	 * Otherwise make sure the passed virtual Initiator port WWN matches
	 * the fabric protocol_id set in tcm_loop_make_scsi_hba(), and call
	 * tcm_loop_make_nexus()
	 */
	if (strlen(page) > TL_WWN_ADDR_LEN) {
		printk(KERN_ERR "Emulated NAA Sas Address: %s, exceeds"
				" max: %d\n", page, TL_WWN_ADDR_LEN);
		return -EINVAL;
	}
	snprintf(&i_port[0], TL_WWN_ADDR_LEN, "%s", page);

	ptr = strstr(i_port, "naa.");
	if (ptr) {
		if (tl_hba->tl_proto_id != SCSI_PROTOCOL_SAS) {
			printk(KERN_ERR "Passed SAS Initiator Port %s does not"
				" match target port protoid: %s\n", i_port,
				tcm_loop_dump_proto_id(tl_hba));
			return -EINVAL;
		}
		port_ptr = &i_port[0];
		goto check_newline;
	}
	ptr = strstr(i_port, "fc.");
	if (ptr) {
		if (tl_hba->tl_proto_id != SCSI_PROTOCOL_FCP) {
			printk(KERN_ERR "Passed FCP Initiator Port %s does not"
				" match target port protoid: %s\n", i_port,
				tcm_loop_dump_proto_id(tl_hba));
			return -EINVAL;
		}
		port_ptr = &i_port[3]; /* Skip over "fc." */
		goto check_newline;
	}
	ptr = strstr(i_port, "iqn.");
	if (ptr) {
		if (tl_hba->tl_proto_id != SCSI_PROTOCOL_ISCSI) {
			printk(KERN_ERR "Passed iSCSI Initiator Port %s does not"
				" match target port protoid: %s\n", i_port,
				tcm_loop_dump_proto_id(tl_hba));
			return -EINVAL;
		}
		port_ptr = &i_port[0];
		goto check_newline;
	}
	printk(KERN_ERR "Unable to locate prefix for emulated Initiator Port:"
			" %s\n", i_port);
	return -EINVAL;
	/*
	 * Clear any trailing newline for the NAA WWN
	 */
check_newline:
	if (i_port[strlen(i_port)-1] == '\n')
		i_port[strlen(i_port)-1] = '\0';
		
	ret = tcm_loop_make_nexus(tl_tpg, port_ptr);
	if (ret < 0)
		return ret;

	return count;
}

TF_TPG_BASE_ATTR(tcm_loop, nexus, S_IRUGO | S_IWUSR);

static struct configfs_attribute *tcm_loop_tpg_attrs[] = {
	&tcm_loop_tpg_nexus.attr,
	NULL,
};

/* Start items for tcm_loop_naa_cit */

struct se_portal_group *tcm_loop_make_naa_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct tcm_loop_hba *tl_hba = container_of(wwn,
			struct tcm_loop_hba, tl_hba_wwn);
	struct tcm_loop_tpg *tl_tpg;
	char *tpgt_str, *end_ptr;
	int ret;
	unsigned short int tpgt;

	tpgt_str = strstr(name, "tpgt_");
	if (!(tpgt_str)) {
		printk(KERN_ERR "Unable to locate \"tpgt_#\" directory"
				" group\n");
		return ERR_PTR(-EINVAL);
	}
	tpgt_str += 5; /* Skip ahead of "tpgt_" */
	tpgt = (unsigned short int) simple_strtoul(tpgt_str, &end_ptr, 0);

	if (tpgt > TL_TPGS_PER_HBA) {
		printk(KERN_ERR "Passed tpgt: %hu exceeds TL_TPGS_PER_HBA:"
				" %u\n", tpgt, TL_TPGS_PER_HBA);
		return ERR_PTR(-EINVAL);
	}
	tl_tpg = &tl_hba->tl_hba_tpgs[tpgt];
	tl_tpg->tl_hba = tl_hba;
	tl_tpg->tl_tpgt = tpgt;
	/*
	 * Register the tl_tpg as a emulated SAS TCM Target Endpoint
	 */
	ret = core_tpg_register(&tcm_loop_fabric_configfs->tf_ops,
			wwn, &tl_tpg->tl_se_tpg, (void *)tl_tpg,
			TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0)
		return ERR_PTR(-ENOMEM);

	printk(KERN_INFO "TCM_Loop_ConfigFS: Allocated Emulated %s"
		" Target Port %s,t,0x%04x\n", tcm_loop_dump_proto_id(tl_hba),
		config_item_name(&wwn->wwn_group.cg_item), tpgt);

	return &tl_tpg->tl_se_tpg;
}

void tcm_loop_drop_naa_tpg(
	struct se_portal_group *se_tpg)
{
	struct se_wwn *wwn = se_tpg->se_tpg_wwn;
	struct tcm_loop_tpg *tl_tpg = container_of(se_tpg,
				struct tcm_loop_tpg, tl_se_tpg);
	struct tcm_loop_hba *tl_hba;
	unsigned short tpgt;

	tl_hba = tl_tpg->tl_hba;
	tpgt = tl_tpg->tl_tpgt;
	/*
	 * Release the I_T Nexus for the Virtual SAS link if present
	 */
	tcm_loop_drop_nexus(tl_tpg);
	/*
	 * Deregister the tl_tpg as a emulated SAS TCM Target Endpoint
	 */
	core_tpg_deregister(se_tpg);

	printk(KERN_INFO "TCM_Loop_ConfigFS: Deallocated Emulated %s"
		" Target Port %s,t,0x%04x\n", tcm_loop_dump_proto_id(tl_hba),
		config_item_name(&wwn->wwn_group.cg_item), tpgt);
}

/* End items for tcm_loop_naa_cit */

/* Start items for tcm_loop_cit */

struct se_wwn *tcm_loop_make_scsi_hba(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct tcm_loop_hba *tl_hba;
	struct Scsi_Host *sh;
	char *ptr;
	int ret, off = 0;

	tl_hba = kzalloc(sizeof(struct tcm_loop_hba), GFP_KERNEL);
	if (!(tl_hba)) {
		printk(KERN_ERR "Unable to allocate struct tcm_loop_hba\n");
                return ERR_PTR(-ENOMEM);
        }
	/*
	 * Determine the emulated Protocol Identifier and Target Port Name
	 * based on the incoming configfs directory name.
	 */
	ptr = strstr(name, "naa.");
	if (ptr) {
		tl_hba->tl_proto_id = SCSI_PROTOCOL_SAS;
		goto check_len;
	}
	ptr = strstr(name, "fc.");      
	if (ptr) {
		tl_hba->tl_proto_id = SCSI_PROTOCOL_FCP;
		off = 3; /* Skip over "fc." */
		goto check_len;
	}
	ptr = strstr(name, "iqn.");
	if (ptr) {
		tl_hba->tl_proto_id = SCSI_PROTOCOL_ISCSI;
		goto check_len;
	}

	printk(KERN_ERR "Unable to locate prefix for emulated Target Port:"
			" %s\n", name);
	return ERR_PTR(-EINVAL);

check_len:
	if (strlen(name) > TL_WWN_ADDR_LEN) {
		printk(KERN_ERR "Emulated NAA %s Address: %s, exceeds"
			" max: %d\n", name, tcm_loop_dump_proto_id(tl_hba),
			TL_WWN_ADDR_LEN);
		kfree(tl_hba);
		return ERR_PTR(-EINVAL);
	}
	snprintf(&tl_hba->tl_wwn_address[0], TL_WWN_ADDR_LEN, "%s", &name[off]);

	/*
	 * Setup the tl_hba->tl_hba_qobj
	 */
	tl_hba->tl_hba_qobj = kzalloc(sizeof(struct se_queue_obj), GFP_KERNEL);
	if (!(tl_hba->tl_hba_qobj)) {
		kfree(tl_hba);
		printk("Unable to allocate tl_hba->tl_hba_qobj\n");
		return ERR_PTR(-ENOMEM);
	}
	transport_init_queue_obj(tl_hba->tl_hba_qobj);

	/*
	 * Call device_register(tl_hba->dev) to register the emulated
	 * Linux/SCSI LLD of type struct Scsi_Host at tl_hba->sh after
	 * device_register() callbacks in tcm_loop_driver_probe()
	 */
	ret = tcm_loop_setup_hba_bus(tl_hba, tcm_loop_hba_no_cnt);
	if (ret) 
		goto out;

	sh = tl_hba->sh;
	/*
	 * Start up the per struct Scsi_Host tcm_loop processing thread
	 */
	tl_hba->tl_kthread = kthread_run(tcm_loop_processing_thread,
			(void *)tl_hba, "tcm_loop_%d", sh->host_no);
	if (IS_ERR(tl_hba->tl_kthread)) {
		printk(KERN_ERR "Unable to start tcm_loop kthread\n");
		device_unregister(&tl_hba->dev);
		ret = -ENOMEM;
		goto out;
	}
	wait_for_completion(&tl_hba->tl_hba_qobj->thread_create_comp);

	tcm_loop_hba_no_cnt++;
	printk(KERN_INFO "TCM_Loop_ConfigFS: Allocated emulated Target"
		" %s Address: %s at Linux/SCSI Host ID: %d\n",
		tcm_loop_dump_proto_id(tl_hba), name, sh->host_no);

	return &tl_hba->tl_hba_wwn;
out:
	kfree(tl_hba->tl_hba_qobj);
	kfree(tl_hba);
	return ERR_PTR(ret);
}

void tcm_loop_drop_scsi_hba(
	struct se_wwn *wwn)
{
	struct tcm_loop_hba *tl_hba = container_of(wwn,
				struct tcm_loop_hba, tl_hba_wwn);
	int host_no = tl_hba->sh->host_no;

	/*
	 * Shutdown the per HBA tcm_loop processing kthread
	 */
	kthread_stop(tl_hba->tl_kthread);
	wait_for_completion(&tl_hba->tl_hba_qobj->thread_done_comp);
	/*
	 * Call device_unregister() on the original tl_hba->dev.
	 * tcm_loop_fabric_scsi.c:tcm_loop_release_adapter() will
	 * release *tl_hba;
	 */
	device_unregister(&tl_hba->dev);

	printk(KERN_INFO "TCM_Loop_ConfigFS: Deallocated emulated Target"
		" SAS Address: %s at Linux/SCSI Host ID: %d\n",
		config_item_name(&wwn->wwn_group.cg_item), host_no);
}

/* Start items for tcm_loop_cit */
static ssize_t tcm_loop_wwn_show_attr_version(
	struct target_fabric_configfs *tf,
	char *page)
{
	return sprintf(page, "TCM Loopback Fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n", TCM_LOOP_VERSION, utsname()->sysname,
		utsname()->machine);
}

TF_WWN_ATTR_RO(tcm_loop, version);

static struct configfs_attribute *tcm_loop_wwn_attrs[] = {
	&tcm_loop_wwn_version.attr,
	NULL,
};

/* End items for tcm_loop_cit */

int tcm_loop_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	struct config_group *tf_cg;
	int ret;
	/*
	 * Set the TCM Loop HBA counter to zero
	 */
	tcm_loop_hba_no_cnt = 0;
	/*
	 * Register the top level struct config_item_type with TCM core
	 */
	fabric = target_fabric_configfs_init(THIS_MODULE, "loopback");
	if (!(fabric)) {
		printk(KERN_ERR "tcm_loop_register_configfs() failed!\n");
		return -1;
	}
	/*
	 * Setup the fabric API of function pointers used by target_core_mod
	 */
	fabric->tf_ops.get_fabric_name = &tcm_loop_get_fabric_name;
	fabric->tf_ops.get_fabric_proto_ident = &tcm_loop_get_fabric_proto_ident;
	fabric->tf_ops.tpg_get_wwn = &tcm_loop_get_endpoint_wwn;
	fabric->tf_ops.tpg_get_tag = &tcm_loop_get_tag;
	fabric->tf_ops.tpg_get_default_depth = &tcm_loop_get_default_depth;
	fabric->tf_ops.tpg_get_pr_transport_id = &tcm_loop_get_pr_transport_id;
	fabric->tf_ops.tpg_get_pr_transport_id_len =
					&tcm_loop_get_pr_transport_id_len;
	fabric->tf_ops.tpg_parse_pr_out_transport_id =
					&tcm_loop_parse_pr_out_transport_id;
	fabric->tf_ops.tpg_check_demo_mode = &tcm_loop_check_demo_mode;
	fabric->tf_ops.tpg_check_demo_mode_cache =
					&tcm_loop_check_demo_mode_cache;
	fabric->tf_ops.tpg_check_demo_mode_write_protect =
					&tcm_loop_check_demo_mode_write_protect;
	/*
	 * The TCM loopback fabric module runs in demo-mode to a local
	 * virtual SCSI device, so fabric dependent initator ACLs are
	 * not required.
	 */
	fabric->tf_ops.tpg_alloc_fabric_acl = &tcm_loop_tpg_alloc_fabric_acl;
	fabric->tf_ops.tpg_release_fabric_acl =
					&tcm_loop_tpg_release_fabric_acl;
#ifdef SNMP_SUPPORT
	fabric->tf_ops.tpg_get_inst_index = &tcm_loop_get_inst_index;
#endif /* SNMP_SUPPORT */
	/*
	 * Since tcm_loop is mapping physical memory from Linux/SCSI
	 * struct scatterlist arrays for each struct scsi_cmnd I/O,
	 * we do not need TCM to allocate a iovec array for
	 * virtual memory address mappings
	 */
	fabric->tf_ops.alloc_cmd_iovecs = NULL;
	fabric->tf_ops.check_stop_free = &tcm_loop_check_stop_free;
	fabric->tf_ops.release_cmd_to_pool = &tcm_loop_deallocate_core_cmd;
	fabric->tf_ops.release_cmd_direct = &tcm_loop_deallocate_core_cmd;
	fabric->tf_ops.shutdown_session = &tcm_loop_shutdown_session; 
	fabric->tf_ops.close_session = &tcm_loop_close_session;
	fabric->tf_ops.stop_session = &tcm_loop_stop_session;
	fabric->tf_ops.fall_back_to_erl0 = &tcm_loop_fall_back_to_erl0;
	fabric->tf_ops.sess_logged_in = &tcm_loop_sess_logged_in;
#ifdef SNMP_SUPPORT
	fabric->tf_ops.sess_get_index = &tpg_loop_sess_get_index:
#endif /* SNMP_SUPPORT */
	fabric->tf_ops.sess_get_initiator_sid = NULL;
	fabric->tf_ops.write_pending = &tcm_loop_write_pending;
	fabric->tf_ops.write_pending_status = &tcm_loop_write_pending_status;
	/*
	 * Not used for TCM loopback
	 */
	fabric->tf_ops.set_default_node_attributes =
					&tcm_loop_set_default_node_attributes;
	fabric->tf_ops.get_task_tag = &tcm_loop_get_task_tag;
	fabric->tf_ops.get_cmd_state = &tcm_loop_get_cmd_state;
	fabric->tf_ops.new_cmd_failure = &tcm_loop_new_cmd_failure;
	fabric->tf_ops.queue_data_in = &tcm_loop_queue_data_in;
	fabric->tf_ops.queue_status = &tcm_loop_queue_status;
	fabric->tf_ops.queue_tm_rsp = &tcm_loop_queue_tm_rsp;
	fabric->tf_ops.set_fabric_sense_len = &tcm_loop_set_fabric_sense_len;
	fabric->tf_ops.get_fabric_sense_len = &tcm_loop_get_fabric_sense_len;
	fabric->tf_ops.is_state_remove = &tcm_loop_is_state_remove;
	fabric->tf_ops.pack_lun = &tcm_loop_pack_lun;

	tf_cg = &fabric->tf_group;
	/*
	 * Setup function pointers for generic logic in target_core_fabric_configfs.c
	 */
	fabric->tf_ops.fabric_make_wwn = &tcm_loop_make_scsi_hba;
	fabric->tf_ops.fabric_drop_wwn = &tcm_loop_drop_scsi_hba;
	fabric->tf_ops.fabric_make_tpg = &tcm_loop_make_naa_tpg;
	fabric->tf_ops.fabric_drop_tpg = &tcm_loop_drop_naa_tpg;
	/*
	 * fabric_post_link() and fabric_pre_unlink() are used for
	 * registration and release of TCM Loop Virtual SCSI LUNs.
	 */
	fabric->tf_ops.fabric_post_link = &tcm_loop_port_link;
	fabric->tf_ops.fabric_pre_unlink = &tcm_loop_port_unlink;
	fabric->tf_ops.fabric_make_np = NULL;
	fabric->tf_ops.fabric_drop_np = NULL;
	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 */
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = tcm_loop_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = tcm_loop_tpg_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_param_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_np_base_cit.ct_attrs = NULL;
	/*
	 * Once fabric->tf_ops has been setup, now register the fabric for
	 * use within TCM
	 */
	ret = target_fabric_configfs_register(fabric);
	if (ret < 0) {
		printk(KERN_ERR "target_fabric_configfs_register() for"
				" LIO-Target failed!\n");
		target_fabric_configfs_free(fabric);
		return -1;
	}
	/*
	 * Setup our local pointer to *fabric.
	 */
	tcm_loop_fabric_configfs = fabric;
	printk(KERN_INFO "TCM_LOOP[0] - Set fabric ->"
			" tcm_loop_fabric_configfs\n");
	return 0;
}

void tcm_loop_deregister_configfs(void)
{
	if (!(tcm_loop_fabric_configfs))
		return;

	target_fabric_configfs_deregister(tcm_loop_fabric_configfs);
	tcm_loop_fabric_configfs = NULL;
	printk(KERN_INFO "TCM_LOOP[0] - Cleared"
				" tcm_loop_fabric_configfs\n");
}	

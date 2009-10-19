/*******************************************************************************
 * Filename:  tcm_loop_configfs.c
 *
 * This file contains the configfs implementation for TCM_Loop Virtual SAS
 * target to Linux/SCSI SAS initiator node
 *
 * Copyright (c) 2009 Rising Tide, Inc.
 * Copyright (c) 2009 Linux-iSCSI.org
 *
 * Copyright (c) 2009 Nicholas A. Bellinger <nab@linux-iscsi.org>
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
#include <linux/utsrelease.h>
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

/* Start items for tcm_loop_port_cit */

static int tcm_loop_port_link(
	struct config_item *tl_lun_ci,
	struct config_item *se_dev_ci)
{
	se_lun_t *lun = container_of(to_config_group(tl_lun_ci),
				se_lun_t, lun_group);
	se_lun_t *lun_p;
	se_portal_group_t *se_tpg;
	struct config_item *tpg_ci;
	struct tcm_loop_hba *tl_hba;
	struct tcm_loop_tpg *tl_tpg;
	se_subsystem_dev_t *se_sub_dev = container_of(
		to_config_group(se_dev_ci), se_subsystem_dev_t, se_dev_group);

	tpg_ci = &tl_lun_ci->ci_parent->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return -EINVAL;
	}
	se_tpg = container_of(to_config_group(tpg_ci),
				se_portal_group_t, tpg_group);
	tl_tpg = (struct tcm_loop_tpg *)se_tpg->se_tpg_fabric_ptr;
	tl_hba = tl_tpg->tl_hba;

	lun_p = core_dev_add_lun(se_tpg,
			se_sub_dev->se_dev_hba,
			se_sub_dev->se_dev_ptr, lun->unpacked_lun);
	if (IS_ERR(lun_p) || !(lun_p)) {
		printk(KERN_ERR "core_dev_add_lun() failed\n");
		return -EINVAL;
	}
	printk(KERN_INFO "TCM_Loop_ConfigFS: Port Link Successful\n");
	/*
	 * Add Linux/SCSI struct scsi_device by HCTL
	 */
	scsi_add_device(tl_hba->sh, 0, tl_tpg->tl_tpgt, lun->unpacked_lun);
	return 0;
}

static int tcm_loop_port_unlink(
	struct config_item *tl_lun_ci,
	struct config_item *se_dev_ci)
{
	se_lun_t *se_lun;
	se_portal_group_t *se_tpg;
	struct config_item *tpg_ci;
	struct scsi_device *sd;
	struct tcm_loop_hba *tl_hba;
	struct tcm_loop_tpg *tl_tpg;

	se_lun = container_of(to_config_group(tl_lun_ci), struct se_lun_s,
			lun_group);

	tpg_ci = &tl_lun_ci->ci_parent->ci_group->cg_item;
	se_tpg = container_of(to_config_group(tpg_ci),
				se_portal_group_t, tpg_group);
	tl_tpg = (struct tcm_loop_tpg *)se_tpg->se_tpg_fabric_ptr;
	tl_hba = tl_tpg->tl_hba;	

	sd = scsi_device_lookup(tl_hba->sh, 0, tl_tpg->tl_tpgt,
				se_lun->unpacked_lun);
	if (!(sd)) {
		printk(KERN_ERR "Unable to locate struct scsi_device for %d:%d:"
			"%d\n", 0, tl_tpg->tl_tpgt, se_lun->unpacked_lun);
		return -EINVAL;	
	}
	/*
	 * Remove Linux/SCSI struct scsi_device by HCTL
	 */
	scsi_remove_device(sd);	
	scsi_device_put(sd);

	core_dev_del_lun(se_tpg, se_lun->unpacked_lun);
	printk(KERN_INFO "TCM_Loop_ConfigFS: Port Unlink Successful\n");
	return 0;
}

static struct configfs_item_operations tcm_loop_port_item_ops = {
	.allow_link		= &tcm_loop_port_link,
	.drop_link		= &tcm_loop_port_unlink,
};

static struct config_item_type tcm_loop_port_cit = {
	.ct_item_ops		= &tcm_loop_port_item_ops,
	.ct_group_ops		= NULL,
	.ct_attrs		= NULL,
	.ct_owner		= THIS_MODULE,			
};

/* End items for tcm_loop_port_cit */

/* Start items for tcm_loop_lun_cit */

static struct config_group *tcm_loop_make_lun(
	struct config_group *group,
	const char *name)
{
	se_lun_t *lun;
	struct tcm_loop_tpg *tl_tpg;	
	char *str, *endptr;
	u32 lun_id;

	str = strstr(name, "_");
	if (!(str)) {
		printk(KERN_ERR "Unable to locate \'_\" in"
				" \"lun_$LUN_NUMBER\"\n");
		return ERR_PTR(-EINVAL);
	}
	str++; /* Advance over _ delim.. */
	lun_id = simple_strtoul(str, &endptr, 0);
	tl_tpg = container_of(group, struct tcm_loop_tpg,
			tl_tpg_lun_group);

	lun = core_get_lun_from_tpg(tl_tpg->tl_se_tpg, lun_id);
	if (!(lun))
		return ERR_PTR(-EINVAL);

	config_group_init_type_name(&lun->lun_group, name,
			&tcm_loop_port_cit);

	return &lun->lun_group;
}

static void tcm_loop_drop_lun(
	struct config_group *group,
	struct config_item *item)
{
	config_item_put(item);
	return;
}

static struct configfs_group_operations tcm_loop_lun_group_ops = {
	.make_group		= &tcm_loop_make_lun,
	.drop_item		= &tcm_loop_drop_lun,
};

static struct config_item_type tcm_loop_lun_cit = {
	.ct_item_ops		= NULL,
	.ct_group_ops		= &tcm_loop_lun_group_ops,
	.ct_attrs		= NULL,
	.ct_owner		= THIS_MODULE,
};

/* End items for tcm_loop_lun_cit */

/* Start items for tcm_loop_iport_cit */

static struct config_item_type tcm_loop_iport_cit = {
	.ct_item_ops		= NULL,
	.ct_group_ops		= NULL,
	.ct_attrs		= NULL,
	.ct_owner		= THIS_MODULE,
};

/* End items for tcm_loop_iport_cit */

/* Start items for tcm_loop_nexus_cit */

static struct config_group *tcm_loop_make_nexus(
	struct config_group *group,
	const char *name)
{
	se_portal_group_t *se_tpg;
	struct tcm_loop_nexus *tl_nexus;
	struct tcm_loop_tpg *tl_tpg;

	tl_tpg = container_of(group, struct tcm_loop_tpg,
			tl_tpg_nexus_group);
	se_tpg = tl_tpg->tl_se_tpg;

	tl_nexus = kzalloc(sizeof(struct tcm_loop_nexus), GFP_KERNEL);
	if (!(tl_nexus)) {
		printk(KERN_ERR "Unable to allocate struct tcm_loop_nexus\n");
		return NULL;
	}
	tl_tpg->tl_hba->tl_nexus = tl_nexus;
	/*
	 * Initialize the se_session_t pointer
	 */
	tl_nexus->se_sess = transport_init_session();
	if (!(tl_nexus->se_sess))
		goto out;
	/*
	 * Since we are running in 'demo mode' this call with generate a
	 * se_node_acl_t for the tcm_loop se_portal_group_t with the SCSI
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

	config_group_init_type_name(&tl_nexus->tl_iport_group, name,
				&tcm_loop_iport_cit);

	printk(KERN_INFO "TCM_Loop_ConfigFS: Established I_T Nexus to emulated"
			" SAS Initiator Port: %s\n", name);
	return &tl_nexus->tl_iport_group;

out:
	kfree(tl_nexus);	
	return NULL;
}

static void tcm_loop_drop_nexus(
	struct config_group *group,
	struct config_item *item)
{
	struct tcm_loop_nexus *tl_nexus;
	struct config_item *tcm_loop_dev_ci;

	tcm_loop_dev_ci = &group->cg_item;
	tl_nexus = container_of(to_config_group(item),
			struct tcm_loop_nexus, tl_iport_group);

	printk(KERN_INFO "TCM_Loop_ConfigFS: Removing I_T Nexus to emulated"
		" SAS Initiator Port: %s\n", config_item_name(item));
	/*
	 * Release the SCSI I_T Nexus to the emulated SAS Target Port
	 */
	transport_deregister_session(tl_nexus->se_sess);
	kfree(tl_nexus);

	config_item_put(item);
}

static struct configfs_group_operations tcm_loop_nexus_group_ops = {
	.make_group		= &tcm_loop_make_nexus,
	.drop_item		= &tcm_loop_drop_nexus,
};

static struct config_item_type tcm_loop_nexus_cit = {
	.ct_item_ops		= NULL,
	.ct_group_ops		= &tcm_loop_nexus_group_ops,
	.ct_attrs		= NULL,
	.ct_owner		= THIS_MODULE,
};

/* End items for tcm_loop_nexus_cit */

/* Start items for tcm_loop_tpg_cit */

static struct config_item_type tcm_loop_tpg_cit = {
	.ct_item_ops		= NULL,
	.ct_group_ops		= NULL,
	.ct_attrs		= NULL,
	.ct_owner		= THIS_MODULE,
};

/* End items for tcm_loop_tpg_cit */

/* Start items for tcm_loop_naa_cit */

static struct config_group *tcm_loop_make_naa_tpg(
	struct config_group *group,
	const char *name)
{
	struct config_group *tpg_cg;
	struct tcm_loop_hba *tl_hba = container_of(group,
			struct tcm_loop_hba, tl_hba_group);
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
	tl_tpg->tl_se_tpg = core_tpg_register(&tcm_loop_fabric_configfs->tf_ops,
			(void *)tl_tpg, TRANSPORT_TPG_TYPE_NORMAL);
	if (IS_ERR(tl_tpg->tl_se_tpg) || !(tl_tpg->tl_se_tpg)) {
		ret = -ENOMEM;
		goto out;
	}
	/*
	 * Locate the pointer to the struct config_group that will be
	 * registered below in order to setup the default groups.
	 */
	tpg_cg = &tl_tpg->tl_se_tpg->tpg_group;

	tpg_cg->default_groups = kzalloc(sizeof(struct config_group) * 3,
			GFP_KERNEL);
	if (!(tpg_cg->default_groups)) {
		ret = -ENOMEM;
		goto out;
	}

	config_group_init_type_name(&tl_tpg->tl_tpg_lun_group, "lun",
			&tcm_loop_lun_cit);
	config_group_init_type_name(&tl_tpg->tl_tpg_nexus_group, "nexus",
			&tcm_loop_nexus_cit);
	tpg_cg->default_groups[0] = &tl_tpg->tl_tpg_lun_group;
	tpg_cg->default_groups[1] = &tl_tpg->tl_tpg_nexus_group;
	tpg_cg->default_groups[2] = NULL;
	
	config_group_init_type_name(tpg_cg, name, &tcm_loop_tpg_cit);
	printk(KERN_INFO "TCM_Loop_ConfigFS: Allocated Emulated SAS"
		" Target Port %s,t,0x%04x\n",
		config_item_name(&tl_hba->tl_hba_group.cg_item), tpgt);

	return tpg_cg;

out:
	if (tl_tpg->tl_se_tpg)
		core_tpg_deregister(tl_tpg->tl_se_tpg);
	return ERR_PTR(ret);
}

static void tcm_loop_drop_naa_tpg(
	struct config_group *group,
	struct config_item *item)
{
	se_portal_group_t *se_tpg = container_of(to_config_group(item),
				struct se_portal_group_s, tpg_group);
	struct tcm_loop_tpg *tl_tpg;
	struct tcm_loop_hba *tl_hba;
	unsigned short tpgt;

	tl_tpg = (struct tcm_loop_tpg *)se_tpg->se_tpg_fabric_ptr;
	tl_hba = tl_tpg->tl_hba;
	tpgt = tl_tpg->tl_tpgt;
	/*
	 * Deregister the tl_tpg as a emulated SAS TCM Target Endpoint
	 */
	core_tpg_deregister(se_tpg);

	printk(KERN_INFO "TCM_Loop_ConfigFS: Deallocated Emulated SAS"
		" Target Port %s,t,0x%04x\n",
		config_item_name(&tl_hba->tl_hba_group.cg_item), tpgt);

	config_item_put(item);
}

static struct configfs_group_operations tcm_loop_naa_group_ops = {
	.make_group		= &tcm_loop_make_naa_tpg,
	.drop_item		= &tcm_loop_drop_naa_tpg,
};

static struct config_item_type tcm_loop_naa_cit = {
	.ct_item_ops		= NULL,
	.ct_group_ops		= &tcm_loop_naa_group_ops,
	.ct_attrs		= NULL,
	.ct_owner		= THIS_MODULE,
};

/* End items for tcm_loop_naa_cit */

/* Start items for tcm_loop_cit */

static struct config_group *tcm_loop_make_scsi_hba(
	struct config_group *group,
	const char *name)
{
	struct tcm_loop_hba *tl_hba;
	struct config_item *tl_hba_ci;
	struct Scsi_Host *sh;
	char *ptr;
	int ret;

	tl_hba = kzalloc(sizeof(struct tcm_loop_hba), GFP_KERNEL);
	if (!(tl_hba)) {
		printk(KERN_ERR "Unable to allocate struct tcm_loop_hba\n");
                return ERR_PTR(-ENOMEM);
        }
	/*
	 * Locate the emulated SAS Target Port name in NAA IEEE Registered
	 * Extended DESIGNATOR field format with the 'naa.' string prefix from
	 * the passed configfs directory name.
	 *
	 * This code assume the actual NAA identifier is parsed to follow spc4
	 * in userspace.,
	 */
	ptr = strstr(name, "naa.");
	if (!(ptr)) {
		printk(KERN_ERR "Unable to locate \"naa.\" prefix for emulated"
			" SAS Target Port\n");
		return ERR_PTR(-EINVAL);
	}
	ptr++;

	if (strlen(name) > TL_NAA_SAS_ADDR_LEN) {
		printk(KERN_ERR "Emulated NAA Sas Address: %s, exceeds"
			" max: %d\n", name, TL_NAA_SAS_ADDR_LEN);
		kfree(tl_hba);
		return ERR_PTR(-EINVAL);
	}
	snprintf(&tl_hba->naa_sas_address[0], TL_NAA_SAS_ADDR_LEN, "%s", name);

	/*
	 * Setup the tl_hba->tl_hba_qobj
	 */
	tl_hba->tl_hba_qobj = kzalloc(sizeof(se_queue_obj_t), GFP_KERNEL);
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

	tl_hba_ci = &tl_hba->tl_hba_group.cg_item;
	config_group_init_type_name(&tl_hba->tl_hba_group, name,
				&tcm_loop_naa_cit);

	tcm_loop_hba_no_cnt++;
	printk(KERN_INFO "TCM_Loop_ConfigFS: Allocated emulated Target"
		" SAS Address: %s at Linux/SCSI Host ID: %d\n",
			config_item_name(tl_hba_ci), sh->host_no);

	return &tl_hba->tl_hba_group;

out:
	kfree(tl_hba->tl_hba_qobj);
	kfree(tl_hba);
	return ERR_PTR(ret);
}

static void tcm_loop_drop_scsi_hba(
	struct config_group *group,
	struct config_item *item)
{
	struct tcm_loop_hba *tl_hba;
	int host_no;

	tl_hba = container_of(to_config_group(item),
			struct tcm_loop_hba, tl_hba_group);
	if (!(tl_hba)) {
		printk(KERN_ERR "Unable to locate struct tcm_loop_hba\n");
		return;
	}
	host_no = tl_hba->sh->host_no;

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
			config_item_name(item), host_no);
	/*
	 * Make last configfs callback to release struct config_item
	 */
	config_item_put(item);
}

/* Start items for tcm_loop_cit */
static ssize_t tcm_loop_attr_version(
	struct config_item *item,
	struct configfs_attribute *attr,
	char *page)
{
	return sprintf(page, "TCM Loopback Fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n", TCM_LOOP_VERSION, utsname()->sysname,
		utsname()->machine);
}

static struct configfs_item_operations tcm_loop_item_ops = {
	.show_attribute	= &tcm_loop_attr_version,
};

static struct configfs_attribute tcm_loop_item_attr_version = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "version",
	.ca_mode	= S_IRUGO,
};

static struct configfs_group_operations tcm_loop_hba_group_ops = {
	.make_group	= &tcm_loop_make_scsi_hba,
	.drop_item	= &tcm_loop_drop_scsi_hba,
};

static struct configfs_attribute *tcm_loop_attrs[] = {
	&tcm_loop_item_attr_version,
	NULL,
};

static struct config_item_type tcm_loop_cit = {
	.ct_item_ops	= &tcm_loop_item_ops,
	.ct_group_ops	= &tcm_loop_hba_group_ops,
	.ct_attrs	= tcm_loop_attrs,
	.ct_owner	= THIS_MODULE,
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
	fabric = target_fabric_configfs_init(&tcm_loop_cit, "loopback");
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
	fabric->tf_ops.sess_get_initiator_wwn = &tcm_loop_get_initiator_wwn;
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
	/*
	 *  TCM_Loop does not currently register any default configfs group(s)
	 */
	fabric->reg_default_groups_callback = NULL;
	tf_cg = &fabric->tf_group;
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

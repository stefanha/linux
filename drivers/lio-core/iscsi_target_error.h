/*********************************************************************************
 * Filename:  iscsi_target_error.h
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_target_error.h $
 *   $LastChangedRevision: 6914 $
 *   $LastChangedBy: nab $
 *   $LastChangedDate: 2007-04-11 13:01:59 -0700 (Wed, 11 Apr 2007) $
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef _ISCSI_TARGET_ERROR_H_
#define _ISCSI_TARGET_ERROR_H_

#define ERR_UNKNOWN_ERROR                      	-1
#define ERR_IN_SHUTDOWN				-2	
#define ERR_TARGETNAME_NOT_SET                  -10
#define ERR_TARGETNAME_ALREADY_SET              -11
#define ERR_SERIAL_NUMBER_INVALID               -12
#define ERR_TPG_DOES_NOT_EXIST                  -13
#define ERR_TPG_NOT_ACTIVE                      -14
#define ERR_NO_MEMORY                           -15
#define ERR_HBA_CANNOT_LOCATE                   -16
#define ERR_HBA_MISSING_PARAMS                  -17
#define ERR_HBA_MISSING_PLUGIN                  -18
#define ERR_HBA_UNKNOWN_TYPE                    -19
#define ERR_LUN_DOES_NOT_EXIST                  -20
#define ERR_LUN_EXCEEDS_MAX                     -21
#define ERR_LUN_NOT_ACTIVE                      -22
#define ERR_VIRTDEV_MISSING_PARAMS              -23
#define ERR_INITIATORNAME_TOO_LARGE             -24
#define ERR_CHECK_VIRTUAL_DEVICE_FAILED         -25
#define ERR_INITIATORACL_SESSION_EXISTS         -26
#define ERR_INITIATORACL_DOES_NOT_EXIST         -27
#define ERR_RAID_DOES_NOT_EXIST                 -28
#define ERR_GET_DEVT_FAILED                     -29
#define ERR_CANNOT_LOCATE_BUFFER                -30
#define ERR_DEV_PT_FAILURE                      -31
#define ERR_RAID_PT_FAILURE                     -32
#define ERR_LUN_DEV_COUNT                       -33
#define ERR_RAID_DEV_COUNT                      -34
#define ERR_LUN_RAID_COUNT                      -35
#define ERR_BLOCKDEV_CLAIMED                    -36
#define ERR_OBJ_ACCESS_COUNT			-37
#define ERR_OBJ_EXPORT_COUNT			-38
#define ERR_OBJ_FEATURE_COUNT			-39
#define ERR_NO_OBJ_API				-40
#define ERR_NO_FEATURE_API			-41
#define ERR_EXPORT_FAILED			-42
#define ERR_CLEAR_METADATA_FAILED		-43
#define ERR_FEATURE_ADD_OBJ_FAILED		-44
#define ERR_FEATURE_OBJ_OFFLINE			-45

/* iscsi_tpg_add_portal_group addtpg */
#define ERR_ADDTPG_ALREADY_EXISTS               -50

/* iscsi_tpg_del_portal_group deltpg */
#define ERR_DELTPG_SESSIONS_ACTIVE              -55

/* iscsi_tpg_enable_portal_group() enabletpg */
#define ERR_ENABLETPG_ALREADY_ACTIVE            -56
#define ERR_ENABLETPG_NO_NPS                    -57

/* iscsi_tpg_disable_portal_group() disabletpg */
#define ERR_DISABLETPG_NOT_ACTIVE               -58
#define ERR_DISABLETPG_SESSIONS_ACTIVE          -59

/* iscsi_tpg_add_initiator_node_acl() addnodetotpg */
#define ERR_ADDINITACL_ACL_EXISTS               -60
#define ERR_ADDINITACL_QUEUE_SET_FAILED         -61

/* iscsi_tpg_add_network_portal() addnptotpg */
#define ERR_ADDNPTOTPG_ALREADY_EXISTS           -80
#define ERR_ADDNPTOTPG_NO_LOGIN_THREAD          -81

/* iscsi_tpg_del_network_portal() */
#define ERR_DELNP_DOES_NOT_EXIST                -90

/* iscsi_tpg_set_initiator_node_queue_depth() */
#define ERR_SETINITCQ_SET_FAILED                -100

/* iscsi_tpg_add_hba() */
#define ERR_ADDTHBA_ALREADY_ACTIVE              -110
#define ERR_ADDTHBA_TPG_ALREADY_ACTIVE          -111
#define ERR_ADDTHBA_HBA_ALREADY_ACTIVE          -112
#define ERR_ADDTHBA_CHECK_PHY_LOCATION          -113
#define ERR_ADDTHBA_ATTACH_HBA                  -114

/* iscsi_tpg_shutdown_hba() */
#define ERR_SHUTDOWN_CHECK_PHY_LOCATION         -120
#define ERR_SHUTDOWN_DETACH_HBA                 -121

/* iscsi_tpg_del_hba() */
#define ERR_DELHBA_NOT_ACTIVE                   -130
#define ERR_DELHBA_SESSIONS_EXIST               -131
#define ERR_DELHBA_SHUTDOWN_FAILED              -132

/* iscsi_dev_add_lun()    */
#define ERR_ADDLUN_ALREADY_ACTIVE               -140
#define ERR_ADDLUN_GET_DEVICE_FAILED            -141
#define ERR_ADDLUN_ACCESS_COUNT_EXISTS   	-142
#define ERR_ADDLUN_CHECK_TCQ_FAILED             -143

/* iscsi_dev_del_lun() */
#define ERR_DELLUN_NOT_ACTIVE                   -150
#define ERR_DELLUN_NO_DEVICE                    -151
#define ERR_DELLUN_ACCESS_COUNT                 -152
#define ERR_DELLUN_TYPE_MISMATCH                -153

/* iscsi_dev_add_initiator_node_lun_acl() */
#define ERR_ADDLUNACL_ALREADY_EXISTS            -160
#define ERR_ADDLUNACL_NODE_ACL_MISSING          -161

/* iscsi_dev_del_initiator_node_lun_acl() */
#define ERR_DELLUNACL_DOES_NOT_EXIST            -170
#define ERR_DELLUNACL_NODE_ACL_MISSING          -171

/* iscsi_create_virtual_device() */
#define ERR_CREATE_VIRTDEV_HBA_NOT_ACTIVE       -180
#define ERR_CREATE_VIRTDEV_FAILED               -181
#define ERR_CREATE_VIRTDEV_PHYSICAL_HBA         -182

/* iscsi_free_virtual_device() */
#define ERR_FREE_VIRTDEV_HBA_NOT_ACTIVE         -190
#define ERR_FREE_VIRTDEV_FAILED                 -191
#define ERR_FREE_VIRTDEV_PHYSICAL_HBA           -192

/* Reserve -230 to -239 */
#define ERR_EZLICENSE_GRACE                     -230
#define ERR_EZLICENSE_END_GRACE                 -231
#define ERR_EZLICENSE_BLOCK                     -232
#define ERR_EZLICENSE_BLOCK_ALL                 -233
#define ERR_EZLICENSE_UNLOAD                    -234
#define ERR_EZLICENSE_HALT                      -235

/* iscsi_vendor_error_list, Reserve -240 to -255 */
#define ERR_VENDOR_NO_HBA_FOUND                 -240
#define ERR_VENDOR_SERIAL_NUMBER                -241
#define ERR_VENDOR_HBA_INVALID                  -242
#define ERR_VENDOR_PCI_NOSCAN                   -243
#define ERR_VENDOR_PCI_MISMATCH                 -244
#define ERR_VENDOR_EEPROM_IS_SET                -245
#define ERR_VENDOR_EEPROM_IS_NOT_SET            -246
#define ERR_VENDOR_EEPROM_INVALID               -247

/* iscsi_set_initiator_node_attribute() */
#define ERR_NODEATTRIB_INITIATOR_DOES_NOT_EXIST -260
#define ERR_NODEATTRIB_UNKNOWN_ATTRIB           -261
#define ERR_NODEATTRIB_TOO_LARGE                -262
#define ERR_NODEATTRIB_TOO_SMALL                -263
#define ERR_NODEATTRIB_BOOLEAN_ONLY             -264

/* iSCSI RAID generic errors */
#define ERR_RAID_GET_SIG_FAILED                 -270
#define ERR_RAID_SET_SIG_FAILED                 -271
#define ERR_RAID_SIGNATURE_MISSING              -272
#define ERR_RAID_NO_RESOURCES                   -273
#define ERR_RAID_NOT_ACTIVE                     -274
#define ERR_RAID_CANNOT_LOCATE                  -275
#define ERR_RAID_NO_ELEMENTS                    -276
#define ERR_RAID_ACTIVE_LUNS                    -277
#define ERR_RAID_SIGNATURE_EXISTS               -278
#define ERR_RAIDVOL_DOES_NOT_EXIST              -279
#define ERR_RAIDDEV_DOES_NOT_EXIST              -280

/* iscsi_raid_init() */
#define ERR_INITRAID_NOT_FREE                   -282
#define ERR_INITRAID_UUID_FAILED 		-283

/* iscsi_raid_create() */
#define ERR_CREATERAID_NOT_READY                -285
#define ERR_CREATERAID_NO_MEMORY                -286
#define ERR_CREATERAID_UNSUPPORTED_RAID         -287

/* iscsi_raid_start() */
#define ERR_STARTRAID_NOT_READY                 -290
#define ERR_STARTRAID_MISSING_DEVICES           -291
#define ERR_STARTRAID_NO_MEMORY                 -292
#define ERR_STARTRAID_WRITE_SIG_FAILED          -293
#define ERR_STARTRAID_READ_SIG_FAILED           -294
#define ERR_STARTRAID_ELEMENT_MISMATCH          -295
#define ERR_STARTRAID_READCAP_FAILED            -296
#define ERR_STARTRAID_NO_SECTOR_COUNT		-297

/* iscsi_raid_add_dev() */
#define ERR_RAIDADDDEV_NOT_INIT                 -300
#define ERR_RAIDADDDEV_GETDEV_FAILED            -301
#define ERR_RAIDADDDEV_ACCESS_COUNT_EXISTS      -302
#define ERR_RAIDADDDEV_DEVNO_TOO_LARGE          -303
#define ERR_RAIDADDDEV_NOT_FREE                 -304
#define ERR_RAIDADDDEV_ELEMENT_TOO_SMALL        -305
#define ERR_RAIDADDDEV_ELEMENT_NOT_DA           -306
#define ERR_RAIDADDDEV_PLUGIC_DMA_HANDLER       -307
#define ERR_RAIDADDDEV_TUN_FAILED               -308
#define ERR_RAIDADDDEV_READ_CAP_FAILED          -309

/* iscsi_raid_del_dev() */
#define ERR_RAIDDELDEV_NOT_INIT                 -310
#define ERR_RAIDDELDEV_DEVNO_TOO_LARGE          -311
#define ERR_RAIDDELDEV_NOT_EXIST                -312
#define ERR_RAIDDELDEV_LUN_ACCESS_COUNT         -313
#define ERR_RAIDDELDEV_LAST_ONLINE_ELEMENT      -314

#define ERR_ADDLUN_RAIDVOL_ACCESS_COUNT_EXISTS  -320

/* iscsi_raid_create_vol() */
#define ERR_RAIDCREATEVOL_NOT_FREE              -330

/* iscsi_raid_del_vol() */
#define ERR_RAIDDELVOL_NOT_ASSIGNED             -340

#define ERR_VOL_DOES_NOT_EXIST                  -350
#define ERR_VOL_ALREADY_ALLOCATED               -351
#define ERR_VOL_NO_HEADER_SIG                   -352
#define ERR_VOL_SIGNATURE_EXISTS                -353
#define ERR_VOLUME_NOTPRESENT                   -354
#define ERR_VOLUME_FREE                         -355
#define ERR_VOLUME_EXPORTED                     -356

#define ERR_VOLCREATE_NO_SPACE                  -360
#define ERR_VOLCREATE_ALLOC_FAILURE             -361
#define ERR_VOLCREATE_SIG_FAILURE               -362
#define ERR_VOLCREATE_ZERO_SECTORS              -363
#define ERR_VOLCREATE_MAX_VOLS                  -364
#define ERR_VOLCREATE_MISSING_SIG               -365

#define ERR_VOLRESIZE_ALLOC_FAILURE             -370
#define ERR_VOLRESIZE_NO_SPACE                  -371

#define ERR_PLUGIN_UNKNOWN_HBATYPE              -375
#define ERR_PLUGIN_ALREADY_REGISTERED           -376
#define ERR_PLUGIN_NOT_REGISTERED               -377
#define ERR_PLUGIN_DOES_NOT_EXIST               -378

/* Ref: iscsi_target_repl.c - Replication Request */
#define ERR_REPL_COPY_FAILURE                   -380
#define ERR_REPL_CREATEREQ_NO_MEMORY            -381
#define ERR_REPL_DEV_NOT_AVAILABLE              -382
#define ERR_REPL_DUPLICATE_REQ_ID               -383
#define ERR_REPL_ID_NOT_FOUND                   -384
#define ERR_REPL_INCORRECT_STATE                -385
#define ERR_REPL_MISSING_PARAMS                 -386
#define ERR_REPL_MUST_BE_INACTIVE               -387
#define ERR_REPL_MUST_BE_REGISTERED             -388
#define ERR_REPL_NO_PRIMARY_FOUND               -389

#define ERR_SNAP_TIMESTAMP_REQUIRED             -400
#define ERR_SNAP_INVALID_VOLUME                 -401

#define ERR_CHECK_PHYSICAL_DEVICE_FAILED        -410


#endif   /*** _ISCSI_TARGET_ERROR_H_ ***/


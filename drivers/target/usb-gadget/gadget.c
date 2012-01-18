/*
 * Target based USB-Gadget, BBB (USB Mass Storage Class Bulk-Only (BBB)
 * Transport protocol handling.
 * Author: Sebastian Andrzej Siewior <bigeasy at linutronix dot de>
 * License: GPLv2 as published by FSF.
 */

#include <linux/kernel.h>
#include <linux/usb/ch9.h>
#include <linux/usb/composite.h>
#include <linux/usb/gadget.h>

#include "usbg.h"

#include "usbstring.c"
#include "epautoconf.c"
#include "config.c"
#include "composite.c"

#define USB_G_STR_MANUFACTOR	1
#define USB_G_STR_PRODUCT	2
#define USB_G_STR_SERIAL	3
#define USB_G_STR_CONFIG	4
#define USB_G_STR_INT_UAS	5
#define USB_G_STR_INT_BBB	6

#define USB_G_ALT_INT_BBB	0
#define USB_G_ALT_INT_UAS	1

static struct usb_interface_descriptor bot_intf_desc = {
	.bLength =              sizeof(bot_intf_desc),
	.bDescriptorType =      USB_DT_INTERFACE,
	.bAlternateSetting =	0,
	.bNumEndpoints =        2,
	.bAlternateSetting =	USB_G_ALT_INT_BBB,
	.bInterfaceClass =      USB_CLASS_MASS_STORAGE,
	.bInterfaceSubClass =   USB_SC_SCSI,
	.bInterfaceProtocol =   USB_PR_BULK,
	.iInterface =           USB_G_STR_INT_UAS,
};

static struct usb_interface_descriptor uasp_intf_desc = {
	.bLength =		sizeof(uasp_intf_desc),
	.bDescriptorType =	USB_DT_INTERFACE,
	.bNumEndpoints =	4,
	.bAlternateSetting =	USB_G_ALT_INT_UAS,
	.bInterfaceClass =	USB_CLASS_MASS_STORAGE,
	.bInterfaceSubClass =	USB_SC_SCSI,
	.bInterfaceProtocol =	USB_PR_UAS,
	.iInterface =		USB_G_STR_INT_BBB,
};

static struct usb_endpoint_descriptor uasp_bi_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_endpoint_descriptor uasp_fs_bi_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_pipe_usage_descriptor uasp_bi_pipe_desc = {
	.bLength =		sizeof(uasp_bi_pipe_desc),
	.bDescriptorType =	USB_DT_PIPE_USAGE,
	.bPipeID =		DATA_IN_PIPE_ID,
};

static struct usb_endpoint_descriptor uasp_ss_bi_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor uasp_bi_ep_comp_desc = {
	.bLength =		sizeof(uasp_bi_ep_comp_desc),
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
	.bmAttributes =		UASP_SS_EP_COMP_LOG_STREAMS,
	.wBytesPerInterval =	0,
};

static struct usb_ss_ep_comp_descriptor bot_bi_ep_comp_desc = {
	.bLength =		sizeof(bot_bi_ep_comp_desc),
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
};

static struct usb_endpoint_descriptor uasp_bo_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_endpoint_descriptor uasp_fs_bo_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_pipe_usage_descriptor uasp_bo_pipe_desc = {
	.bLength =		sizeof(uasp_bo_pipe_desc),
	.bDescriptorType =	USB_DT_PIPE_USAGE,
	.bPipeID =		DATA_OUT_PIPE_ID,
};

static struct usb_endpoint_descriptor uasp_ss_bo_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(0x400),
};

static struct usb_ss_ep_comp_descriptor uasp_bo_ep_comp_desc = {
	.bLength =		sizeof(uasp_bo_ep_comp_desc),
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bmAttributes =		UASP_SS_EP_COMP_LOG_STREAMS,
};

static struct usb_ss_ep_comp_descriptor bot_bo_ep_comp_desc = {
	.bLength =		sizeof(bot_bo_ep_comp_desc),
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
};

static struct usb_endpoint_descriptor uasp_status_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_endpoint_descriptor uasp_fs_status_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_pipe_usage_descriptor uasp_status_pipe_desc = {
	.bLength =		sizeof(uasp_status_pipe_desc),
	.bDescriptorType =	USB_DT_PIPE_USAGE,
	.bPipeID =		STATUS_PIPE_ID,
};

static struct usb_endpoint_descriptor uasp_ss_status_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor uasp_status_in_ep_comp_desc = {
	.bLength =		sizeof(uasp_status_in_ep_comp_desc),
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bmAttributes =		UASP_SS_EP_COMP_LOG_STREAMS,
};

static struct usb_endpoint_descriptor uasp_cmd_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_endpoint_descriptor uasp_fs_cmd_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_pipe_usage_descriptor uasp_cmd_pipe_desc = {
	.bLength =		sizeof(uasp_cmd_pipe_desc),
	.bDescriptorType =	USB_DT_PIPE_USAGE,
	.bPipeID =		CMD_PIPE_ID,
};

static struct usb_endpoint_descriptor uasp_ss_cmd_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor uasp_cmd_comp_desc = {
	.bLength =		sizeof(uasp_cmd_comp_desc),
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
};

static struct usb_descriptor_header *uasp_fs_function_desc[] = {
	(struct usb_descriptor_header *) &bot_intf_desc,
	(struct usb_descriptor_header *) &uasp_fs_bi_desc,
	(struct usb_descriptor_header *) &uasp_fs_bo_desc,

	(struct usb_descriptor_header *) &uasp_intf_desc,
	(struct usb_descriptor_header *) &uasp_fs_bi_desc,
	(struct usb_descriptor_header *) &uasp_bi_pipe_desc,
	(struct usb_descriptor_header *) &uasp_fs_bo_desc,
	(struct usb_descriptor_header *) &uasp_bo_pipe_desc,
	(struct usb_descriptor_header *) &uasp_fs_status_desc,
	(struct usb_descriptor_header *) &uasp_status_pipe_desc,
	(struct usb_descriptor_header *) &uasp_fs_cmd_desc,
	(struct usb_descriptor_header *) &uasp_cmd_pipe_desc,
};

static struct usb_descriptor_header *uasp_hs_function_desc[] = {
	(struct usb_descriptor_header *) &bot_intf_desc,
	(struct usb_descriptor_header *) &uasp_bi_desc,
	(struct usb_descriptor_header *) &uasp_bo_desc,

	(struct usb_descriptor_header *) &uasp_intf_desc,
	(struct usb_descriptor_header *) &uasp_bi_desc,
	(struct usb_descriptor_header *) &uasp_bi_pipe_desc,
	(struct usb_descriptor_header *) &uasp_bo_desc,
	(struct usb_descriptor_header *) &uasp_bo_pipe_desc,
	(struct usb_descriptor_header *) &uasp_status_desc,
	(struct usb_descriptor_header *) &uasp_status_pipe_desc,
	(struct usb_descriptor_header *) &uasp_cmd_desc,
	(struct usb_descriptor_header *) &uasp_cmd_pipe_desc,
	NULL,
};

static struct usb_descriptor_header *uasp_ss_function_desc[] = {
	(struct usb_descriptor_header *) &bot_intf_desc,
	(struct usb_descriptor_header *) &uasp_ss_bi_desc,
	(struct usb_descriptor_header *) &bot_bi_ep_comp_desc,
	(struct usb_descriptor_header *) &uasp_ss_bo_desc,
	(struct usb_descriptor_header *) &bot_bo_ep_comp_desc,

	(struct usb_descriptor_header *) &uasp_intf_desc,
	(struct usb_descriptor_header *) &uasp_ss_bi_desc,
	(struct usb_descriptor_header *) &uasp_bi_ep_comp_desc,
	(struct usb_descriptor_header *) &uasp_bi_pipe_desc,
	(struct usb_descriptor_header *) &uasp_ss_bo_desc,
	(struct usb_descriptor_header *) &uasp_bo_ep_comp_desc,
	(struct usb_descriptor_header *) &uasp_bo_pipe_desc,
	(struct usb_descriptor_header *) &uasp_ss_status_desc,
	(struct usb_descriptor_header *) &uasp_status_in_ep_comp_desc,
	(struct usb_descriptor_header *) &uasp_status_pipe_desc,
	(struct usb_descriptor_header *) &uasp_ss_cmd_desc,
	(struct usb_descriptor_header *) &uasp_cmd_comp_desc,
	(struct usb_descriptor_header *) &uasp_cmd_pipe_desc,
	NULL,
};

#define UAS_VENDOR_ID	0x0525	/* NetChip */
#define UAS_PRODUCT_ID	0xa4a5	/* Linux-USB File-backed Storage Gadget */

static struct usb_device_descriptor usbg_device_desc = {
	.bLength =		sizeof(usbg_device_desc),
	.bDescriptorType =	USB_DT_DEVICE,
	.bcdUSB =		cpu_to_le16(0x0200),
	.bDeviceClass =		USB_CLASS_PER_INTERFACE,
	.idVendor =		cpu_to_le16(UAS_VENDOR_ID),
	.idProduct =		cpu_to_le16(UAS_PRODUCT_ID),
	.iManufacturer =	USB_G_STR_MANUFACTOR,
	.iProduct =		USB_G_STR_PRODUCT,
	.iSerialNumber =	USB_G_STR_SERIAL,

	.bNumConfigurations =   1,
};

static struct usb_string	usbg_us_strings[] = {
	{ USB_G_STR_MANUFACTOR,	"Target Manufactor"},
	{ USB_G_STR_PRODUCT,	"Target Product"},
	{ USB_G_STR_SERIAL,	"000000000001"},
	{ USB_G_STR_CONFIG,	"default config"},
	{ USB_G_STR_INT_UAS,	"USB Attached SCSI"},
	{ USB_G_STR_INT_BBB,	"Bulk Only Transport"},
	{ },
};

static struct usb_gadget_strings usbg_stringtab = {
	.language = 0x0409,
	.strings = usbg_us_strings,
};

static struct usb_gadget_strings *usbg_strings[] = {
	&usbg_stringtab,
	NULL,
};

static int guas_unbind(struct usb_composite_dev *cdev)
{
	return 0;
}

static struct usb_configuration usbg_config_driver = {
	.label                  = "Linux Target",
	.bConfigurationValue    = 1,
	.iConfiguration		= USB_G_STR_CONFIG,
	.bmAttributes           = USB_CONFIG_ATT_SELFPOWER,
};

static void give_back_ep(struct usb_ep **pep)
{
	struct usb_ep *ep = *pep;
	if (!ep)
		return;
	ep->driver_data = NULL;
}

static int usbg_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct f_uas		*fu = to_f_uas(f);
	struct usb_gadget	*gadget = c->cdev->gadget;
	struct usb_ep		*ep;
	int			iface;

	iface = usb_interface_id(c, f);
	if (iface < 0)
		return iface;

	bot_intf_desc.bInterfaceNumber = iface;
	uasp_intf_desc.bInterfaceNumber = iface;
	fu->iface = iface;
	ep = usb_ep_autoconfig_ss(gadget, &uasp_ss_bi_desc,
			&uasp_bi_ep_comp_desc);
	if (!ep)
		goto ep_fail;

	ep->driver_data = fu;
	fu->ep_in = ep;

	ep = usb_ep_autoconfig_ss(gadget, &uasp_ss_bo_desc,
			&uasp_bo_ep_comp_desc);
	if (!ep)
		goto ep_fail;
	ep->driver_data = fu;
	fu->ep_out = ep;

	ep = usb_ep_autoconfig_ss(gadget, &uasp_ss_status_desc,
			&uasp_status_in_ep_comp_desc);
	if (!ep)
		goto ep_fail;
	ep->driver_data = fu;
	fu->ep_status = ep;

	ep = usb_ep_autoconfig_ss(gadget, &uasp_ss_cmd_desc,
			&uasp_cmd_comp_desc);
	if (!ep)
		goto ep_fail;
	ep->driver_data = fu;
	fu->ep_cmd = ep;

	/* Assume endpoint addresses are the same for both speeds */
	uasp_bi_desc.bEndpointAddress =	uasp_ss_bi_desc.bEndpointAddress;
	uasp_bo_desc.bEndpointAddress = uasp_ss_bo_desc.bEndpointAddress;
	uasp_status_desc.bEndpointAddress =
		uasp_ss_status_desc.bEndpointAddress;
	uasp_cmd_desc.bEndpointAddress = uasp_ss_cmd_desc.bEndpointAddress;

	uasp_fs_bi_desc.bEndpointAddress = uasp_ss_bi_desc.bEndpointAddress;
	uasp_fs_bo_desc.bEndpointAddress = uasp_ss_bo_desc.bEndpointAddress;
	uasp_fs_status_desc.bEndpointAddress =
		uasp_ss_status_desc.bEndpointAddress;
	uasp_fs_cmd_desc.bEndpointAddress = uasp_ss_cmd_desc.bEndpointAddress;

	return 0;
ep_fail:
	pr_err("Can't claim all required eps\n");

	give_back_ep(&fu->ep_in);
	give_back_ep(&fu->ep_out);
	give_back_ep(&fu->ep_status);
	give_back_ep(&fu->ep_cmd);
	return -ENOTSUPP;
}

static void usbg_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct f_uas *fu = to_f_uas(f);

	kfree(fu);
}

struct guas_setup_wq {
	struct work_struct work;
	struct f_uas *fu;
	unsigned int alt;
};

static void usbg_delayed_set_alt(struct work_struct *wq)
{
	struct guas_setup_wq *work = container_of(wq, struct guas_setup_wq,
			work);
	struct f_uas *fu = work->fu;
	int alt = work->alt;

	kfree(work);

	if (fu->flags & USBG_IS_BOT)
		bot_cleanup_old_alt(fu);
	if (fu->flags & USBG_IS_UAS)
		uasp_cleanup_old_alt(fu);

	if (alt == USB_G_ALT_INT_BBB)
		bot_set_alt(fu);
	else if (alt == USB_G_ALT_INT_UAS)
		uasp_set_alt(fu);
	usb_composite_setup_continue(fu->function.config->cdev);
}

static int usbg_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct f_uas *fu = to_f_uas(f);

	if ((alt == USB_G_ALT_INT_BBB) || (alt == USB_G_ALT_INT_UAS)) {
		struct guas_setup_wq *work;

		work = kmalloc(sizeof(*work), GFP_ATOMIC);
		if (!work)
			return -ENOMEM;
		INIT_WORK(&work->work, usbg_delayed_set_alt);
		work->fu = fu;
		work->alt = alt;
		schedule_work(&work->work);
		return USB_GADGET_DELAYED_STATUS;
	}
	return -EOPNOTSUPP;
}

static void usbg_disable(struct usb_function *f)
{
	struct f_uas *fu = to_f_uas(f);

	if (fu->flags & USBG_IS_UAS)
		uasp_cleanup_old_alt(fu);
	else if (fu->flags & USBG_IS_BOT)
		bot_cleanup_old_alt(fu);
	fu->flags = 0;
}

static int usbg_setup(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl)
{
	struct f_uas *fu = to_f_uas(f);

	if (!(fu->flags & USBG_IS_BOT))
		return -EOPNOTSUPP;

	return usbg_bot_setup(f, ctrl);
}

static int usbg_cfg_bind(struct usb_configuration *c)
{
	struct f_uas *fu;
	int ret;

	fu = kzalloc(sizeof(*fu), GFP_KERNEL);
	if (!fu)
		return -ENOMEM;
	fu->function.name = "Target Function";
	fu->function.descriptors = uasp_fs_function_desc;
	fu->function.hs_descriptors = uasp_hs_function_desc;
	fu->function.ss_descriptors = uasp_ss_function_desc;
	fu->function.bind = usbg_bind;
	fu->function.unbind = usbg_unbind;
	fu->function.set_alt = usbg_set_alt;
	fu->function.setup = usbg_setup;
	fu->function.disable = usbg_disable;
	fu->tpg = the_only_tpg_I_currently_have;

	ret = usb_add_function(c, &fu->function);
	if (ret)
		goto err;

	return 0;
err:
	kfree(fu);
	return ret;
}

static int usb_target_bind(struct usb_composite_dev *cdev)
{
	int ret;

	ret = usb_add_config(cdev, &usbg_config_driver,
			usbg_cfg_bind);
	return 0;
}

static struct usb_composite_driver usbg_driver = {
	.name           = "g_target",
	.dev            = &usbg_device_desc,
	.strings        = usbg_strings,
	.max_speed      = USB_SPEED_SUPER,
	.unbind         = guas_unbind,
};

int usbg_attach(struct usbg_tpg *tpg)
{
	return usb_composite_probe(&usbg_driver, usb_target_bind);
}

void usbg_detach(struct usbg_tpg *tpg)
{
	usb_composite_unregister(&usbg_driver);
}

static int __init usb_target_gadget_init(void)
{
	int ret;

	ret = usbg_register_configfs();
	return ret;
}
module_init(usb_target_gadget_init);

static void __exit usb_target_gadget_exit(void)
{
	usbg_deregister_configfs();
}
module_exit(usb_target_gadget_exit);

MODULE_AUTHOR("Sebastian Andrzej Siewior <bigeasy@linutronix.de>");
MODULE_DESCRIPTION("usb-gadget fabric");
MODULE_LICENSE("GPL v2");

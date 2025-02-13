#include "aic_types.h"
#include "aic_fw.h"
#include "aic_bsp_driver.h"
#include "rwnx_msg_tx.h"
#include "rwnx_utils.h"
#include "rtos_al.h"
//#include "log.h"
#include "wifi.h"
#include <string.h>

static int rwnx_load_firmware(uint32_t **fw_buf, enum aic_fw name)
{
    int size = 0;

    *fw_buf = aic_fw_ptr_get(name);
    size = aic_fw_size_get(name);

    return size;
}

int rwnx_plat_bin_fw_upload_android(struct rwnx_hw *rwnx_hw, uint32_t fw_addr,
							   const enum aic_fw name)
{
	unsigned int i = 0;
	int size;
	uint32_t *dst = NULL;
	int err = 0;

	printk("%s\n",__func__);

	/* load aic firmware */
	size = rwnx_load_firmware(&dst, name);
	if (size <= 0) {
		printk("wrong size of firmware file\n");
		dst = NULL;
		return -1;
	}

	/* Copy the file on the Embedded side */
	if (size > 1024) {// > 1KB data
		for (i = 0; i < (size - 1024); i += 1024) {//each time write 1KB
			//printk("wr blk 0: %p -> %x\r\n", dst + i / 4, fw_addr + i);
			err = rwnx_send_dbg_mem_block_write_req(rwnx_hw, fw_addr + i, 1024, dst + i / 4);
			if (err) {
				printk("bin upload fail: %x, err:%d\r\n", fw_addr + i, err);
				break;
			}
		}
	}

	if (!err && (i < size)) {// <1KB data
		//printk("wr blk 1: %p -> %x\r\n", dst + i / 4, fw_addr + i);
		err = rwnx_send_dbg_mem_block_write_req(rwnx_hw, fw_addr + i, size - i, dst + i / 4);
		if (err) {
			printk("bin upload fail: %x, err:%d\r\n", fw_addr + i, err);
		}
	}

	if (dst) {
		dst = NULL;
	}

	return err;
}

int aicbt_patch_table_free(struct aicbt_patch_table **head)
{
	struct aicbt_patch_table *p = *head, *n = NULL;
	while (p) {
		n = p->next;
		rtos_free(p->name);
		rtos_free(p->data);
		rtos_free(p);
		p = n;
	}
	*head = NULL;
	return 0;
}

struct aicbt_patch_table *aicbt_patch_table_alloc(enum aic_fw name)
{
	RWNX_DBG(RWNX_FN_ENTRY_STR);

	uint8_t *rawdata = NULL, *p;
	int size;
	struct aicbt_patch_table *head = NULL, *new = NULL, *cur = NULL;

	/* load aic firmware */
	size = rwnx_load_firmware((uint32_t **)&rawdata, name);
	if (size <= 0) {
		printk("wrong size of firmware file\n");
		goto err;
	}

	p = rawdata;
	if (memcmp(p, AICBT_PT_TAG, sizeof(AICBT_PT_TAG) < 16 ? sizeof(AICBT_PT_TAG) : 16)) {
		printk("TAG err\n");
		goto err;
	}
	p += 16;

	while (p - rawdata < size) {
		new = (struct aicbt_patch_table *)rtos_malloc(sizeof(struct aicbt_patch_table));
		memset(new, 0, sizeof(struct aicbt_patch_table));
		if (head == NULL) {
			head = new;
			cur  = new;
		} else {
			cur->next = new;
			cur = cur->next;
		}

		cur->name = (char *)rtos_malloc(sizeof(char) * 16);
		memset(cur->name, 0, sizeof(char) * 16);
		memcpy(cur->name, p, 16);
		p += 16;

		cur->type = *(uint32_t *)p;
		p += 4;

		cur->len = *(uint32_t *)p;
		p += 4;

		if((cur->type )  >= 1000 ) {//Temp Workaround
			cur->len = 0;
		}else{
			if(cur->len > 0){
				cur->data = (uint32_t *)rtos_malloc(sizeof(uint8_t) * cur->len * 8);
				memset(cur->data, 0, sizeof(uint8_t) * cur->len * 8);
				memcpy(cur->data, p, cur->len * 8);
				p += cur->len * 8;
			}
		}
	}
	return head;

err:
	aicbt_patch_table_free(&head);
	return NULL;
}
int aicbt_patch_info_unpack(struct aicbt_patch_info_t *patch_info, struct aicbt_patch_table *head_t)
{
    if (AICBT_PT_INF == head_t->type) {
        patch_info->info_len = head_t->len;
        if(patch_info->info_len == 0)
            return 0;
        memcpy(&patch_info->adid_addrinf, head_t->data, patch_info->info_len);
    }
    return 0;
}
int aicbt_patch_trap_data_load(struct rwnx_hw *rwnx_hw, struct aicbt_patch_table *head)
{
	RWNX_DBG(RWNX_FN_ENTRY_STR);

	struct aicbt_patch_info_t patch_info = {
		.info_len          = 0,
		.adid_addrinf      = 0,
		.addr_adid         = 0,
		.patch_addrinf     = 0,
		.addr_patch        = 0,
		.reset_addr        = 0,
        .reset_val         = 0,
        .adid_flag_addr    = 0,
        .adid_flag         = 0,
	};
    if(head == NULL){
        return -1;
    }

    enum aic_fw fw_adid = FW_UNKNOWN;
    enum aic_fw fw_patch = FW_UNKNOWN;

	if(rwnx_hw->chipid == PRODUCT_ID_AIC8801){
		patch_info.addr_adid  = FW_RAM_ADID_BASE_ADDR;
		patch_info.addr_patch = FW_RAM_PATCH_BASE_ADDR;
	}
	else if(rwnx_hw->chipid == PRODUCT_ID_AIC8800DC){
	}

	if (rwnx_plat_bin_fw_upload_android(rwnx_hw, patch_info.addr_adid, FW_ADID_U03))
		return -1;
	if (rwnx_plat_bin_fw_upload_android(rwnx_hw, patch_info.addr_patch, FW_PATCH_U03))
		return -1;
	return 0;

}

static struct aicbt_info_t aicbt_info = {
	.btmode        = AICBT_BTMODE_DEFAULT,
	.btport        = AICBT_BTPORT_DEFAULT,
	.uart_baud     = AICBT_UART_BAUD_DEFAULT,
	.uart_flowctrl = AICBT_UART_FC_DEFAULT,
	.lpm_enable = AICBT_LPM_ENABLE_DEFAULT,
	.txpwr_lvl     = AICBT_TXPWR_LVL_DEFAULT,
};

struct aicbt_info_t aicbt_info_8800dc = {
	.btmode 	   = AICBT_BTMODE_BT_WIFI_COMBO,
	.btport 	   = AICBT_BTPORT_DEFAULT,
	.uart_baud	   = AICBT_UART_BAUD_DEFAULT,
	.uart_flowctrl = AICBT_UART_FC_DEFAULT,
	.lpm_enable    = AICBT_LPM_ENABLE_DEFAULT,
	.txpwr_lvl	   = AICBT_TXPWR_LVL_8800dc,
};

int aicbt_patch_table_load(struct rwnx_hw *rwnx_hw, struct aicbt_patch_table *head)
{
	RWNX_DBG(RWNX_FN_ENTRY_STR);

	struct aicbt_patch_table *p;
	int ret = 0, i;
	uint32_t *data = NULL;
    if(head == NULL){
        return -1;
    }
	if(rwnx_hw->chipid == PRODUCT_ID_AIC8801){
		for (p = head; p != NULL; p = p->next) {
			data = p->data;
			if (AICBT_PT_BTMODE == p->type) {
				*(data + 1)  = aicbsp_info.hwinfo < 0;
				*(data + 3)  = aicbsp_info.hwinfo;
				*(data + 5)  = aicbsp_info.cpmode;

				*(data + 7)  = aicbt_info.btmode;
				*(data + 9)  = aicbt_info.btport;
				*(data + 11) = aicbt_info.uart_baud;
				*(data + 13) = aicbt_info.uart_flowctrl;
				*(data + 15) = aicbt_info.lpm_enable;
				*(data + 17) = aicbt_info.txpwr_lvl;

				printk("%s bt uart_baud:%d \r\n", __func__, aicbt_info.uart_baud);
				printk("%s bt uart_flowctrl:%d \r\n", __func__, aicbt_info.uart_flowctrl);
				printk("%s bt lpm_enable:%d \r\n", __func__, aicbt_info.lpm_enable);
				printk("%s bt tx_pwr:%d \r\n", __func__, aicbt_info.txpwr_lvl);
			}

			if (AICBT_PT_VER == p->type) {
				printk("aicbsp: bt patch version: %s\n", (char *)p->data);
				continue;
			}

			for (i = 0; i < p->len; i++) {
				ret = rwnx_send_dbg_mem_write_req(rwnx_hw, *data, *(data + 1));
				if (ret != 0)
					return ret;
				data += 2;
			}
			if (p->type == AICBT_PT_PWRON)
				rtos_msleep(1);
		}
	}
	else if(rwnx_hw->chipid == PRODUCT_ID_AIC8800DC){
	}
	///aicbt_patch_table_free(&head);
	return 0;
}

int aicbt_init(struct rwnx_hw *rwnx_hw)
{
    RWNX_DBG(RWNX_FN_ENTRY_STR);

    int ret = 0;
    struct aicbt_patch_table *head = aicbt_patch_table_alloc(FW_PATCH_TABLE_U03);
	if (head == NULL){
        printk("aicbt_patch_table_alloc fail\n");
        return -1;
    }

    if (aicbt_patch_trap_data_load(rwnx_hw, head)) {
		printk("aicbt_patch_trap_data_load fail\n");
        ret = -1;
		goto err;
	}

	if (aicbt_patch_table_load(rwnx_hw, head)) {
		 printk("aicbt_patch_table_load fail\n");
        ret = -1;
		goto err;
	}

err:
	aicbt_patch_table_free(&head);
	return ret;
}


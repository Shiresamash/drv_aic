/*
 * Copyright (C) 2018-2020 AICSemi Ltd.
 *
 * All Rights Reserved
 */

//#include <config.h>
#include <stdio.h>
//#include <errno.h>
#include <string.h>
#include "sdio.h"

#include "hal_sdhost.h"
#include "sdmmc.h"
#include "sdio.h"

#include "_sd_define.h"
#include "_sdio.h"

#include "porting.h"
#include "aic_log.h"

//#include "sci_types.h"
//#include "sci_api.h"
#include "sdio_def.h"
#include "sdio_port.h"
//#include "gpio_drvapi.h"
//#include "gpio_prod_api.h"
//#include "sfs.h"
//#include "sdio_io.h"
#include "lmac_msg.h"
#include "rwnx_main.h"
#include "rtos_al.h"
#include "fhost_rx.h"
#include "rtos_errno.h"
#include "wifi.h"

#define SDIOM_MAX_FUNCS 3

extern bool_l func_flag_tx;
extern bool_l func_flag_rx;

extern struct rwnx_hw *g_rwnx_hw;

struct card_port_tag;
typedef struct card_port_tag* card_handle;

#define CONFIG_TXMSG_TEST_EN    0

#define IRQF_TRIGGER_HIGH  1
#define IRQF_TRIGGER_LOW  2
#define FUNC_0  0
#define FUNC_1  1
#define FUNC_2  2

#define udelay(n)	rtos_udelay(n)

//#define SDIO_PORT_DEBUG
#define SDIO_DT_MODE_ADDR	0x0f
#define SDIO_FBR_SYSADDR_0	0x15c
//cache
#define SYS_CACHE_LINE_SIZE  32U
#define WCN_CACHE_ALIGNED(addr) (((uint32_t)(addr) + (SYS_CACHE_LINE_SIZE - 1)) & (~(SYS_CACHE_LINE_SIZE - 1)))
#define IS_WCN_CACHE_ALIGNED(addr) !((uint32_t)(addr) & (SYS_CACHE_LINE_SIZE - 1))
#if 0
#define WCN_CACHE_ALIGN_VARIABLE    __align(SYS_CACHE_LINE_SIZE)
WCN_CACHE_ALIGN_VARIABLE static uint32_t sdiom_cache_align_addr[SYS_CACHE_LINE_SIZE/sizeof(uint32_t)];
WCN_CACHE_ALIGN_VARIABLE static uint32_t sdiom_cache_align_data[SYS_CACHE_LINE_SIZE/sizeof(uint32_t)];
#else
#define WCN_CACHE_ALIGN_VARIABLE    __attribute__((aligned(SYS_CACHE_LINE_SIZE)))
WCN_CACHE_ALIGN_VARIABLE static uint32_t sdiom_cache_align_addr[SYS_CACHE_LINE_SIZE/sizeof(uint32_t)];
//WCN_CACHE_ALIGN_VARIABLE static uint32_t sdiom_cache_align_data[SYS_CACHE_LINE_SIZE/sizeof(uint32_t)];
#endif

static struct sdio_func *sdio_function[SDIOM_MAX_FUNCS];
static struct mmc_card* sdio_card;
//static struct sdio_func sdio_function_inf[SDIOM_MAX_FUNCS];
#ifdef CONFIG_AIC_SDIO_INT_PINNUM
static unsigned int sdio_gpio_num = CONFIG_AIC_SDIO_INT_PINNUM;
#else
static unsigned int sdio_gpio_num = 0xFFFFFFFF;
#endif
static uint32_t sdio_block_size;
typedef void (*SDIO_ISR_FUNC)(void);

SDIO_ISR_FUNC g_sdio_isr_func = NULL;

static int msgcfm_poll_en = 1;
static rtos_semaphore sdio_rx_sema = NULL;
struct aic_sdio_dev sdio_dev = {NULL,};
static rtos_task_handle sdio_task_hdl = NULL;

#if (FHOST_RX_SW_VER == 3)
static struct sdio_buf_node_s sdio_rx_buf_node[SDIO_RX_BUF_COUNT];
WCN_CACHE_ALIGN_VARIABLE static uint8_t sdio_rx_buf_pool[SDIO_RX_BUF_COUNT][SDIO_RX_BUF_SIZE];
static struct sdio_buf_list_s sdio_rx_buf_list;
#endif

#ifdef PLATFORM_ALLWIN_RT_THREAD

 int32_t
mmc_io_rw_extended(struct mmc_card *card, uint8_t write, uint8_t fn, uint32_t addr, uint32_t incr_addr,
               const void *buf, uint32_t blocks, uint32_t blksz);

/**
 *  read/write IO memory in Block/Stream mode with fixed/increaming address
 *    This will split an arbitrarily sized data transfer into several IO_RW_EXTENDED commands.
 *  @func_num: function number
 *  @write: IOMEM_WR:write, IOMEM_RD:read
 *  @addr: address of register read from or write to
 *  @incr_addr: 1: in, 0: not, used for fifio
 *  @buf: pointer to data buffer
 *  @size: block counter(block mode)/byte counter(byte mode)
 *  @ret: RET_OK, RET_FAIL
 */
static int32_t
sdio_io_rw_ext_helper(struct mmc_card *card, uint8_t func_num, int32_t write, uint32_t addr,
                      uint32_t incr_addr, uint8_t *buf, uint32_t size)
{
	uint32_t remainder = size;
	int32_t ret = -1;
	uint32_t blocks;
	int32_t fn_bsize;
	uint8_t *buf_tmp = buf;

	/* Do the bulk of the transfer using block mode (if supported). */
	//if (func->card->cccr.multi_block && (size > sdio_max_byte_size(func))) {
	fn_bsize = card->fn_bsize[func_num];
	/* Do the bulk of the transfer using block mode (if supported). */
	while (remainder >= fn_bsize) {
		blocks = remainder / fn_bsize;
		size = blocks * fn_bsize;

		ret = mmc_io_rw_extended(card, write, func_num, addr, incr_addr, buf, blocks, fn_bsize);
		if (ret) {
			SD_LOGE("%s,%d %s IO%x [%lx] SZ:%ld Err:%ld !!", __func__, __LINE__,
			          write?"W":"R", func_num, HAL_PR_SZ_L(addr), HAL_PR_SZ_L(size), HAL_PR_SZ_L(ret));
			return ret;
		}
		remainder -= size;
		buf += size;
		if (incr_addr)
			addr += size;
	}

	/* Write the remainder using byte mode. */
	while (remainder > 0) {
		size = MIN(remainder, 512);

		ret = mmc_io_rw_extended(card, write, func_num, addr, incr_addr, buf, 0, size);
		if (ret) {
			SD_LOGE("%s,%d %s IO%x [%lx] SZ:%ld Err:%ld !!", __func__, __LINE__,
			          write?"W":"R", func_num, HAL_PR_SZ_L(addr), HAL_PR_SZ_L(size), HAL_PR_SZ_L(ret));
			return ret;
		}
		remainder -= size;
		buf += size;
		if (incr_addr)
			addr += size;
	}

//	printf("%s,%d,%x %x,%x", __FUNCTION__,__LINE__, buf_tmp,(uint32_t)buf_tmp, (uint32_t)buf);
	return ret;
}

/**
 *	sdio_readsb - read from a FIFO on a SDIO function
 *	@func: SDIO function to access
 *	@dst: buffer to store the data
 *	@addr: address of (single byte) FIFO
 *	@count: number of bytes to read
 *
 *	Reads from the specified FIFO of a given SDIO function. Return
 *	value indicates if the transfer succeeded or not.
 */
static int sdio_readsb(struct mmc_card *card, uint32_t func_num, void *dst, unsigned int addr,
	int count)
{
	return sdio_io_rw_ext_helper(card, func_num, 0, addr, 0, dst, count);
}

/**
 *	sdio_writesb - write to a FIFO of a SDIO function
 *	@func: SDIO function to access
 *	@addr: address of (single byte) FIFO
 *	@src: buffer that contains the data to write
 *	@count: number of bytes to write
 *
 *	Writes to the specified FIFO of a given SDIO function. Return
 *	value indicates if the transfer succeeded or not.
 */
static int sdio_writesb(struct mmc_card *card, uint32_t func_num, unsigned int addr, void *src,
	int count)
{
	return sdio_io_rw_ext_helper(card, func_num, 1, addr, 0, src, count);
}

#ifndef CONFIG_USE_MMC_QUIRK

#define SDIO_ANY_ID (~0)

static inline int mmc_card_lenient_fn0(const struct mmc_card *c)
{
	return c->quirks & MMC_QUIRK_LENIENT_FN0;
}
#endif

/**
 *	sdio_f0_writeb - write a single byte to SDIO function 0
 *	@func: an SDIO function of the card
 *	@b: byte to write
 *	@addr: address to write to
 *	@err_ret: optional status value from transfer
 *
 *	Writes a single byte to the address space of SDIO function 0.
 *	@err_ret will contain the status of the actual transfer.
 *
 *	Only writes to the vendor specific CCCR registers (0xF0 -
 *	0xFF) are permiited; @err_ret will be set to -EINVAL for *
 *	writes outside this range.
 */
void sdio_f0_writeb(struct sdio_func *func, unsigned char b, unsigned int addr,
	int *err_ret)
{
	int ret;

	if (!func) {
		*err_ret = -EINVAL;
		return;
	}

	if ((addr < 0xF0 || addr > 0xFF) && (!mmc_card_lenient_fn0(func->card))) {
		if (err_ret)
			*err_ret = -EINVAL;
		return;
	}

	ret = mmc_io_rw_direct(func->card, 1, 0, addr, b, NULL);
	if (err_ret)
		*err_ret = ret;
}

/**
 * Find a sdio function by given function interface code, vendor id and product id.
 *
 * @class: SDIO standard interface code
 *           0h: No SDIO standard interface supported by this function
 *           1h: This function supports the SDIO Standard UART
 *           2h: This function supports the SDIO Bluetooth Type-A standard interface
 *           3h: This function supports the SDIO Bluetooth Type-B standard interface
 *           4h: This function supports the SDIO GPS standard interface
 *           5h: This function supports the SDIO Camera standard interface
 *           6h: This function supports the SDIO PHS standard interface
 *           7h: This function supports the SDIO WLAN interface
 *           8h: This function supports the Embedded SDIO-ATA standard interface
 *           9h: This function supports the SDIO Bluetooth Type-A AMP standard interface
 *               (AMP: Alternate MAC PHY)
 *           10h-Eh: Not assigned, reserved for future use
 *           Fh: This function supports an SDIO standard interface number greater than Eh.
 *
 * @vendor: vendor id (Reference to SDIO SPEC: TPLMID_MANF)
 * @device: product id (Reference to SDIO SPEC: TPLMID_CARD)
 *
 * Pass SDIO_ANY_ID in instead of specific id for which do not care the id.
 *
 */
struct sdio_func *sdio_find_func(u8 class, u16 vendor, u16 device)
{
	struct sdio_func **sdio_func;
	struct sdio_func *func;
	uint8_t i, j;

	for (i = 0; i < SDC_NUM; i++) {
		sdio_func = get_mmc_card_func(i);
		if (sdio_func == NULL) continue;
		for (j = 0; j < SDIO_MAX_FUNCS; j++) {
			func = sdio_func[j];
			if (func == NULL) continue;
			if (class != (u8)SDIO_ANY_ID && class != func->class)
				continue;
			if (vendor != (u16)SDIO_ANY_ID && vendor != func->vendor)
				continue;
			if (device != (u16)SDIO_ANY_ID && device != func->device)
				continue;
			return func;
		}
	}
	return NULL;
}
#endif

bool sdio_readb_cmd52(uint32_t addr, uint8_t *data)
{
    int err;
    uint8_t  val;

    //AIC_LOG_PRINTF("sdio_readb_cmd52, addr: 0x%x", addr);
    sdio_claim_host(sdio_card);
    val = sdio_readb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, addr, &err);
    sdio_release_host(sdio_card);
    if(err) {
        //AIC_LOG_PRINTF("sdio_readb_cmd52 fail %d!", err);
        printf("sdio_readb_cmd52 fail %d!", err);
        return FALSE;
    }

    //AIC_LOG_PRINTF("sdio_readb_cmd52 done, val=0x%x", val);
    *data = val;
    return TRUE;
}

bool sdio_readb_cmd52_func2(uint32_t addr, uint8_t *data)
{
    int err;
    uint8_t  val;

    //AIC_LOG_PRINTF("sdio_readb_cmd52, addr: 0x%x", addr);
    sdio_claim_host(sdio_function[FUNC_2]->card);
    val = sdio_readb(sdio_function[FUNC_2]->card, sdio_function[FUNC_2]->num, addr, &err);
    sdio_release_host(sdio_function[FUNC_2]->card);
    if(err) {
        printf("sdio_readb_cmd52_func2 fail %d!", err);
        return FALSE;
    }

    //AIC_LOG_PRINTF("sdio_readb_cmd52_func2, val=0x%x\r", val);
    *data = val;
    return TRUE;
}

bool sdio_writeb_cmd52(uint32_t addr, uint8_t data)
{
    int err;
    sdio_claim_host(sdio_card);
    sdio_writeb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, data, addr, &err);
    sdio_release_host(sdio_card);
    if(err) {
        AIC_LOG_PRINTF("sdio_writeb_cmd52 fail %d!", err);
        return FALSE;
    }


    //AIC_LOG_PRINTF("sdio_writeb_cmd52 done, addr 0x%x, data=0x%x", addr, data);

    return TRUE;
}

bool sdio_writeb_cmd52_func2(uint32_t addr, uint8_t data)
{
    int err;

    sdio_claim_host(sdio_function[FUNC_2]->card);
    sdio_writeb(sdio_function[FUNC_2]->card, sdio_function[FUNC_2]->num, data, addr, &err);
    sdio_release_host(sdio_function[FUNC_2]->card);
    if(err) {
        AIC_LOG_PRINTF("sdio_writeb_cmd52_func2 fail %d!", err);
        return FALSE;
    }


    //AIC_LOG_PRINTF("sdio_writeb_cmd52, addr 0x%x, data=0x%x", addr, data);

    return TRUE;
}

bool sdio_read_cmd53(uint32_t dataPort, uint8_t *dat, size_t size)
{
    int ret = 0;
    uint32_t rx_blocks = 0, blksize = 0;
    //char* temp_addr, *temp_addr2;
    //static int init_malloc = 0;
    //sdiom_cache_align_addr[0] = dataPort;
    if (size > sdio_block_size)
    {
        rx_blocks = (size + sdio_block_size - 1) / sdio_block_size;
        blksize = sdio_block_size;
    }
    else
    {
        blksize = size;
        rx_blocks = 1;
    }

    #if 0
    if (init_malloc == 0)
    {
        temp_addr = (char*)OS_MemAlloc(8192+0x3f);
        init_malloc = 1;
    }

    if (temp_addr)
    {
        temp_addr2 = temp_addr + (0x3f - (int)temp_addr&0x3f)+1;
        //AIC_LOG_PRINTF("sdio_read_cmd53 11, add1=0x%x, addr2=0x%x, dataPort=0x%x, siez=%d", temp_addr, temp_addr2, 
dataPort, size);
        //sdio_claim_host(sdio_card);
        ret = sdio_memcpy_fromio(sdio_function[FUNC_1], temp_addr2, sdiom_cache_align_addr[0], rx_blocks*blksize);
        memset(dat, 0, size);
        memcpy(dat, temp_addr2, size);
    }
    #else
    sdio_claim_host(sdio_card);
    ret = sdio_memcpy_fromio(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, dat, dataPort, rx_blocks*blksize
);
    sdio_release_host(sdio_card);
    #endif
    if(ret != TRUE){
        AIC_LOG_PRINTF("sdio_read_cmd53 size = %ld, fail!", size);
        return FALSE;
    }
    //AIC_LOG_PRINTF("sdio_read_cmd53 12, dat0=0x%x, dat2=0x%x, dat3=0x%x, dat4=0x%x", dat[0], dat[1], dat[2], dat[3]);
    return TRUE;
}

bool sdio_write_cmd53(uint32_t dataPort, uint8_t *dat, size_t size)
{
    int ret = 0;
    //char* temp_addr, *temp_addr2;
    uint32_t tx_blocks = 0, blksize = 0;

    sdiom_cache_align_addr[0] = dataPort;

    if (size > sdio_block_size)
    {
        tx_blocks = (size + sdio_block_size - 1) / sdio_block_size;
        blksize = sdio_block_size;
    }
    else
    {
        blksize = size;
        tx_blocks = 1;
    }

    size = blksize * tx_blocks;

#if 0
    temp_addr = (char*)OS_MemAlloc(size+0x3f);

    temp_addr2 = temp_addr + (0x3f - (int)temp_addr&0x3f)+1;
    memcpy(temp_addr2, dat, size);

    //AIC_LOG_PRINTF("sdio_write_cmd53 11,add1=0x%x, addr2=0x%x, dataPort=0x%x, siez=%d", temp_addr, temp_addr2, 
dataPort, size);
#endif

    sdio_claim_host(sdio_card);
    ret = sdio_memcpy_toio(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, sdiom_cache_align_addr[0], dat, 
size);
    //ret = sdio_memcpy_toio(sdio_function[FUNC_1], sdiom_cache_align_addr[0], temp_addr2, blksize*tx_blocks);
    sdio_release_host(sdio_card);
    //free(temp_addr);
    if(ret != TRUE){
        AIC_LOG_PRINTF("sdio_write_cmd53 size = %ld, fail!!", size);
        return FALSE;
    }

    return TRUE;
}

void sdio_release_func2(void)
{
    int ret = 0;
    AIC_LOG_PRINTF("%s", __func__);
    ret = sdio_writeb_cmd52_func2(SDIOWIFI_INTR_CONFIG_REG, 0x0);
    if (ret < 0) {
        AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_INTR_CONFIG_REG);
    }
    sdio_claim_host(sdio_function[FUNC_2]->card);
    sdio_release_irq(sdio_function[FUNC_2]);
    sdio_release_host(sdio_function[FUNC_2]->card);
}

int tx_aggr_counter = MAX_AGGR_TXPKT_CNT + DATA_FLOW_CTRL_THRESH;
int aicwf_sdio_flow_ctrl_msg(void)
{
    int ret = -1;
    u8 fc_reg = 0;
    u32 count = 0;
    struct rwnx_hw *rwnx_hw = g_rwnx_hw;

    while (true) {
        struct aic_sdio_dev *sdiodev = &sdio_dev;
        rtos_mutex_lock(sdiodev->bus_txrx, -1);
        if (rwnx_hw->chipid == PRODUCT_ID_AIC8800D80)
            ret = sdio_readb_cmd52(SDIOWIFI_FLOW_CTRL_Q1_REG_V3, &fc_reg);
        else
            ret = sdio_readb_cmd52(SDIOWIFI_FLOW_CTRL_REG, &fc_reg);
        rtos_mutex_unlock(sdiodev->bus_txrx);
        if (ret == FALSE) {
            AIC_LOG_PRINTF("%s, reg read failed", __func__);
            return -1;
        }
        if (rwnx_hw->chipid != PRODUCT_ID_AIC8800D80)
            fc_reg = fc_reg & SDIOWIFI_FLOWCTRL_MASK_REG;

        if (fc_reg != 0) {
            ret = fc_reg;
            if (ret > tx_aggr_counter) {
                ret = tx_aggr_counter;
            }
            return ret;
        } else {
            if (count >= FLOW_CTRL_RETRY_COUNT) {
                ret = -fc_reg;
                AIC_LOG_PRINTF("msg fc:%d", ret);
                break;
            }
            count++;
            if (count < 30)
                udelay(200);
            else if(count < 40)
                rtos_msleep(2);
            else
                rtos_msleep(10);
        }
    }

    return ret;
}

int aicwf_sdio_flow_ctrl(void)
{
    int ret = -1;
    u8 fc_reg = 0;
    u32 count = 0;
    struct rwnx_hw *rwnx_hw = g_rwnx_hw;

    while (true) {
        struct aic_sdio_dev *sdiodev = &sdio_dev;
        rtos_mutex_lock(sdiodev->bus_txrx, -1);
        if (rwnx_hw->chipid == PRODUCT_ID_AIC8800D80)
		    ret = sdio_readb_cmd52(SDIOWIFI_FLOW_CTRL_Q1_REG_V3, &fc_reg);
		else
            ret = sdio_readb_cmd52(SDIOWIFI_FLOW_CTRL_REG, &fc_reg);
        rtos_mutex_unlock(sdiodev->bus_txrx);
        if (ret == FALSE) {
            AIC_LOG_PRINTF("%s, reg read failed", __func__);
            return -1;
        }
        if (rwnx_hw->chipid != PRODUCT_ID_AIC8800D80)
            fc_reg = fc_reg & SDIOWIFI_FLOWCTRL_MASK_REG;

        if (fc_reg > DATA_FLOW_CTRL_THRESH) {
            ret = fc_reg;
            if (ret > tx_aggr_counter) {
                ret = tx_aggr_counter;
            }
            return ret;
        } else {
            if (count >= FLOW_CTRL_RETRY_COUNT) {
                ret = -fc_reg;
                AIC_LOG_PRINTF("data fc:%d", ret);
                break;
            }
            count++;
            if (count < 30)
                udelay(200);
            else if(count < 40)
                rtos_msleep(2);
            else
                rtos_msleep(10);
        }
    }

    return ret;
}

int aicwf_sdio_send_msg(u8 *buf, uint count)
{
    int ret = 0;
    struct aic_sdio_dev *sdiodev = &sdio_dev;
    rtos_mutex_lock(sdiodev->bus_txrx, -1);
    if (!func_flag_tx){
        sdio_claim_host(sdio_card);
        ret = sdio_writesb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, SDIOWIFI_WR_FIFO_ADDR, buf, count);
        sdio_release_host(sdio_card);
    } else {
        sdio_claim_host(sdio_function[FUNC_2]->card);
        ret = sdio_writesb(sdio_function[FUNC_2]->card, sdio_function[FUNC_2]->num, SDIOWIFI_WR_FIFO_ADDR, buf, count);
        sdio_release_host(sdio_function[FUNC_2]->card);
    }
    rtos_mutex_unlock(sdiodev->bus_txrx);
    return ret;
}

int aicwf_sdio_send_pkt(u8 *buf, uint count)
{
    int ret = 0;
    struct aic_sdio_dev *sdiodev = &sdio_dev;
    rtos_mutex_lock(sdiodev->bus_txrx, -1);
    sdio_claim_host(sdio_card);
    if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8800D80)
        ret = sdio_writesb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, SDIOWIFI_WR_FIFO_ADDR_V3, buf, count);
    else
        ret = sdio_writesb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, SDIOWIFI_WR_FIFO_ADDR, buf, count);

    sdio_release_host(sdio_card);
    rtos_mutex_unlock(sdiodev->bus_txrx);
    return ret;
}

int aicwf_sdio_recv_pkt(u8 *buf, u32 size, u8 msg)
{
    int ret = -1;

    if ((!buf) || (!size)) {
        return -EINVAL;;
    }

    struct aic_sdio_dev *sdiodev = &sdio_dev;
    rtos_mutex_lock(sdiodev->bus_txrx, -1);
    if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8801) {
        sdio_claim_host(sdio_card);
        ret = sdio_readsb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, buf, SDIOWIFI_RD_FIFO_ADDR, size);
        sdio_release_host(sdio_card);
    } else if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
        if (!func_flag_rx) {
            sdio_claim_host(sdio_card);
            ret = sdio_readsb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, buf, SDIOWIFI_RD_FIFO_ADDR, 
size);
            sdio_release_host(sdio_card);
        } else {
            if(!msg) {
                sdio_claim_host(sdio_card);
                ret = sdio_readsb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, buf, SDIOWIFI_RD_FIFO_ADDR
, size);
                sdio_release_host(sdio_card);
            } else {
                sdio_claim_host(sdio_function[FUNC_2]->card);
                ret = sdio_readsb(sdio_function[FUNC_2]->card, sdio_function[FUNC_2]->num, buf, SDIOWIFI_RD_FIFO_ADDR
, size);
                sdio_release_host(sdio_function[FUNC_2]->card);
            }
        }
    } else if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8800D80) {
        sdio_claim_host(sdio_card);
        ret = sdio_readsb(sdio_function[FUNC_1]->card, sdio_function[FUNC_1]->num, buf, SDIOWIFI_RD_FIFO_ADDR_V3, size
);
        sdio_release_host(sdio_card);
    }
    rtos_mutex_unlock(sdiodev->bus_txrx);

    return ret;
}

int aicwf_sdio_tx_msg(u8 *buf, uint count, u8 *out)
{
    int err = 0;
    u16 len;
    u8 *payload = buf;
    u16 payload_len = (u16)count;
    u8 adjust_str[4] = {0, 0, 0, 0};
    int adjust_len = 0;
    int buffer_cnt = 0;
    u8 retry = 0;
    struct aic_sdio_dev *sdiodev = &sdio_dev;
    len = payload_len;
    if ((len % TX_ALIGNMENT) != 0) {
        adjust_len = (len + TX_ALIGNMENT - 1) & ~(TX_ALIGNMENT - 1); //roundup(len, TX_ALIGNMENT);
        memcpy(payload+payload_len, adjust_str, (adjust_len - len));
        payload_len += (adjust_len - len);
    }
    len = payload_len;

    //link tail is necessary
    if (len % SDIOWIFI_FUNC_BLOCKSIZE != 0) {
        memset(payload+payload_len, 0, TAIL_LEN);
        payload_len += TAIL_LEN;
        len = (payload_len/SDIOWIFI_FUNC_BLOCKSIZE + 1) * SDIOWIFI_FUNC_BLOCKSIZE;
    } else
        len = payload_len;

    if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8801 || g_rwnx_hw->chipid == PRODUCT_ID_AIC8800D80) {
        buffer_cnt = aicwf_sdio_flow_ctrl_msg();
        while ((buffer_cnt <= 0 || (buffer_cnt > 0 && len > (buffer_cnt * BUFFER_SIZE))) && retry < 10) {
            retry++;
            buffer_cnt = aicwf_sdio_flow_ctrl_msg();
        }
    } else if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
        if (!func_flag_tx) {
            buffer_cnt = aicwf_sdio_flow_ctrl_msg();
            while ((buffer_cnt <= 0 || (buffer_cnt > 0 && len > (buffer_cnt * BUFFER_SIZE))) && retry < 10) {
                retry++;
                buffer_cnt = aicwf_sdio_flow_ctrl_msg();
            }
        }
    }

    if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8801) {
        if (buffer_cnt > 0 && len <= (buffer_cnt * BUFFER_SIZE)) {
            //AIC_LOG_PRINTF("aicwf_sdio_send_pkt, len=%d", len);
            err = aicwf_sdio_send_pkt(payload, len);
            if (err) {
                AIC_LOG_PRINTF("aicwf_sdio_send_pkt fail%d", err);
                goto txmsg_exit;
            }
            if (msgcfm_poll_en && out) {
                u8 intstatus = 0;
                u32 data_len;
                int ret, idx;
                udelay(100);
                for (idx = 0; idx < 8; idx++) {
                    rtos_mutex_lock(sdiodev->bus_txrx, -1);
                    ret = sdio_readb_cmd52(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
                    rtos_mutex_unlock(sdiodev->bus_txrx);
                    while ((ret == FALSE) || (intstatus & SDIO_OTHER_INTERRUPT)) {
                        AIC_LOG_PRINTF("ret=%d, intstatus=%x",ret, intstatus);
                        rtos_mutex_lock(sdiodev->bus_txrx, -1);
                        ret = sdio_readb_cmd52(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
                        rtos_mutex_unlock(sdiodev->bus_txrx);
                    }
                    AIC_LOG_PRINTF("[%d] intstatus=%d", idx, intstatus);
                    if (intstatus > 0) {
                        if (intstatus < 64) {
                            data_len = intstatus * SDIOWIFI_FUNC_BLOCKSIZE;
                        } else {
                            u8 byte_len = 0;
                            rtos_mutex_lock(sdiodev->bus_txrx, -1);
                            ret = sdio_readb_cmd52(SDIOWIFI_BYTEMODE_LEN_REG, &byte_len);
                            rtos_mutex_unlock(sdiodev->bus_txrx);
                            if (ret == FALSE) {
                                AIC_LOG_PRINTF("byte mode len read err %d\r", ret);
                                err = ret;
                                goto txmsg_exit;
                            }
                            AIC_LOG_PRINTF("byte mode len=%d\r", byte_len);
                            data_len = byte_len * 4; //byte_len must<= 128
                        }
                        if (data_len) {
                            ret = aicwf_sdio_recv_pkt(out, data_len, 0);
                            if (ret) {
                                AIC_LOG_PRINTF("recv pkt err %d\r", ret);
                                err = ret;
                                goto txmsg_exit;
                            }
                            AIC_LOG_PRINTF("recv pkt done len=%d\r", data_len);
                        }
                        break;
                    }
                }
            }
        } else {
            AIC_LOG_PRINTF("tx msg fc retry fail");
            //up(&sdiodev->tx_priv->cmd_txsema);
            return -1;
        }
    } else if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
        if (((!func_flag_tx) && (buffer_cnt > 0 && len <= (buffer_cnt * BUFFER_SIZE))) || func_flag_tx) {
            //AIC_LOG_PRINTF("aicwf_sdio_send_pkt, len=%d", len);
            err = aicwf_sdio_send_msg(payload, len);
            if (err) {
                AIC_LOG_PRINTF("aicwf_sdio_send_pkt fail%d", err);
                goto txmsg_exit;
            }
            if (msgcfm_poll_en && out) {
                u8 intstatus = 0;
                u32 data_len;
                int ret, idx;
                udelay(100);
                for (idx = 0; idx < 8; idx++) {
                    rtos_mutex_lock(sdiodev->bus_txrx, -1);
                    ret = sdio_readb_cmd52_func2(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
                    rtos_mutex_unlock(sdiodev->bus_txrx);
                    while ((ret == FALSE) || (intstatus & SDIO_OTHER_INTERRUPT)) {
                        AIC_LOG_PRINTF("ret=%d, intstatus=%x",ret, intstatus);
                        rtos_mutex_lock(sdiodev->bus_txrx, -1);
                        ret = sdio_readb_cmd52_func2(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
                        rtos_mutex_unlock(sdiodev->bus_txrx);
                    }
                    AIC_LOG_PRINTF("[%d] intstatus=%d", idx, intstatus);
                    if (intstatus > 0) {
                        if (intstatus < 64) {
                            data_len = intstatus * SDIOWIFI_FUNC_BLOCKSIZE;
                        } else {
                            u8 byte_len = 0;
                            rtos_mutex_lock(sdiodev->bus_txrx, -1);
                            ret = sdio_readb_cmd52_func2(SDIOWIFI_BYTEMODE_LEN_REG, &byte_len);
                            rtos_mutex_unlock(sdiodev->bus_txrx);
                            if (ret == FALSE) {
                                AIC_LOG_PRINTF("byte mode len read err %d\r", ret);
                                err = ret;
                                goto txmsg_exit;
                            }
                            AIC_LOG_PRINTF("byte mode len=%d\r", byte_len);
                            data_len = byte_len * 4; //byte_len must<= 128
                        }
                        if (data_len) {
                            ret = aicwf_sdio_recv_pkt(out, data_len, 1);
                            if (ret) {
                                AIC_LOG_PRINTF("recv pkt err %d\r", ret);
                                err = ret;
                                goto txmsg_exit;
                            }
                            AIC_LOG_PRINTF("recv pkt done len=%d\r", data_len);
                        }
                        break;
                    }
                }
            }
        } else {
            AIC_LOG_PRINTF("tx msg fc retry fail");
            //up(&sdiodev->tx_priv->cmd_txsema);
            return -1;
        }
    }else if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8800D80) {
        if (buffer_cnt > 0 && len <= (buffer_cnt * BUFFER_SIZE)) {
            //AIC_LOG_PRINTF("aicwf_sdio_send_pkt, len=%d", len);
            err = aicwf_sdio_send_pkt(payload, len);
            if (err) {
                AIC_LOG_PRINTF("aicwf_sdio_send_pkt fail%d", err);
                goto txmsg_exit;
            }
            if (msgcfm_poll_en && out) {
                u8 intstatus = 0;
                u32 data_len;
                int ret, idx;
                udelay(100);
                for (idx = 0; idx < 8; idx++) {
                    do {
                        rtos_mutex_lock(sdiodev->bus_txrx, -1);
            			ret = sdio_readb_cmd52(SDIOWIFI_MISC_INT_STATUS_REG_V3, &intstatus);
                        rtos_mutex_unlock(sdiodev->bus_txrx);
            			if (ret) {
                			break;
            			}
            			AIC_LOG_PRINTF("ret=%d, intstatus=%x\r",ret, intstatus);
        			} while (1);
					if (intstatus & SDIO_OTHER_INTERRUPT) {
            			u8 int_pending;
                        rtos_mutex_lock(sdiodev->bus_txrx, -1);
            			ret = sdio_readb_cmd52(SDIOWIFI_INTR_PENDING_REG_V3, &int_pending);
                        rtos_mutex_unlock(sdiodev->bus_txrx);
            			if (ret == FALSE) {
                			AIC_LOG_PRINTF("reg:%d read failed!", SDIOWIFI_INTR_PENDING_REG_V3);
            			}
            			int_pending &= ~0x01; // dev to host soft irq
                        rtos_mutex_lock(sdiodev->bus_txrx, -1);
            			ret = sdio_writeb_cmd52(SDIOWIFI_INTR_PENDING_REG_V3, int_pending);
                        rtos_mutex_unlock(sdiodev->bus_txrx);
            			if (ret == FALSE) {
                			AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_INTR_PENDING_REG_V3);
            			}
        			}
                    AIC_LOG_PRINTF("[%d] intstatus=%d", idx, intstatus);
					if (intstatus > 0) {
                        uint8_t intmaskf2 = intstatus | (0x1UL << 3);
                        if (intstatus == 120U) {    // byte mode
                            u8 byte_len = 0;
                            rtos_mutex_lock(sdiodev->bus_txrx, -1);
                            ret = sdio_readb_cmd52(SDIOWIFI_BYTEMODE_LEN_REG_V3, &byte_len);
                            rtos_mutex_unlock(sdiodev->bus_txrx);
                            if (ret) {
                                AIC_LOG_PRINTF("byte mode len read err %d\r", ret);
                            }
                            AIC_LOG_PRINTF("byte mode len=%d\r", byte_len);
                            data_len = byte_len * 4; //byte_len must<= 128
                        } else {
                            data_len = (intstatus & 0x7FU) * SDIOWIFI_FUNC_BLOCKSIZE;
                        }
                        if (data_len) {
                            ret = aicwf_sdio_recv_pkt(out, data_len, 0);
                            if (ret) {
                                AIC_LOG_PRINTF("recv pkt err %d\r", ret);
                                err = ret;
                                goto txmsg_exit;
                            }
                            AIC_LOG_PRINTF("recv pkt done len=%d\r", data_len);
                        }
                    }
                }
           }
        } else {
            AIC_LOG_PRINTF("tx msg fc retry fail");
            //up(&sdiodev->tx_priv->cmd_txsema);
            return -1;
        }
    }

txmsg_exit:
    return err;
}

int aicwf_sdio_aggr(struct aic_sdio_dev *sdiodev, u8 *pkt_data, u32 pkt_len);
void aicwf_sdio_aggr_send(struct aic_sdio_dev *sdiodev);
void aicwf_sdio_aggrbuf_reset(struct aic_sdio_dev *sdiodev);

int aicwf_sdio_send_check(void)
{
    struct aic_sdio_dev *sdiodev = &sdio_dev;
    u32 aggr_len = 0;

    aggr_len = (sdiodev->tail - sdiodev->head);
    if(((sdiodev->aggr_count == 0) && (aggr_len != 0))
        || ((sdiodev->aggr_count != 0) && (aggr_len == 0))) {
        if (aggr_len > 0)
            aicwf_sdio_aggrbuf_reset(sdiodev);
        AIC_LOG_PRINTF("aggr_count=%d, aggr_len=%d, check fail", sdiodev->aggr_count, aggr_len);
        return -1;
    }

    if (sdiodev->aggr_count == (sdiodev->fw_avail_bufcnt - DATA_FLOW_CTRL_THRESH)) {
        if (sdiodev->aggr_count > 0) {
            sdiodev->fw_avail_bufcnt -= sdiodev->aggr_count;
            aic_dbg("cnt equals");
            aicwf_sdio_aggr_send(sdiodev); //send and check the next pkt;
            return 1;
        }
    }

    return 0;
}

int aicwf_sdio_send(u8 *pkt_data, u32 pkt_len, bool last)
{
    struct sk_buff *pkt;
    struct aic_sdio_dev *sdiodev = &sdio_dev;
    int retry_times = 0;
    int max_retry_times = 5;

#if 0
    if (sdiodev->fw_avail_bufcnt <= 2) { // init val
        sdiodev->fw_avail_bufcnt = aicwf_sdio_flow_ctrl();
        while(sdiodev->fw_avail_bufcnt <=2 && retry_times < max_retry_times) {
            retry_times++;
            sdiodev->fw_avail_bufcnt = aicwf_sdio_flow_ctrl();
        }
        if(sdiodev->fw_avail_bufcnt <= 2) {
            AIC_LOG_PRINTF("fc retry %d fail", sdiodev->fw_avail_bufcnt);
            goto done;
        }
    }
    aic_dbg("ava_cnt=%d,last=%d",sdiodev->fw_avail_bufcnt,last);
#endif
retry:
    #if 1
    if(sdiodev==NULL || sdiodev->tail==NULL)
        AIC_LOG_PRINTF("null error");
    if (aicwf_sdio_aggr(sdiodev, pkt_data, pkt_len)) {
        if (sdiodev->aggr_end) {
            sdiodev->fw_avail_bufcnt -= sdiodev->aggr_count;
            aicwf_sdio_aggr_send(sdiodev);
            goto retry;
        } else {
            aicwf_sdio_aggrbuf_reset(sdiodev);
            AIC_LOG_PRINTF("add aggr pkts failed!");
            goto done;
        }
    }

    //when aggr finish or there is cmd to send, just send this aggr pkt to fw
    //if ((int)atomic_read(&sdiodev->tx_priv->tx_pktcnt) == 0 || sdiodev->tx_priv->cmd_txstate) { //no more pkt send 11it!
    if (last || sdiodev->aggr_end) {
        sdiodev->fw_avail_bufcnt -= sdiodev->aggr_count;
        aicwf_sdio_aggr_send(sdiodev);
    } else {
        goto done;
    }
    #else
    aicwf_sdio_aggr(sdiodev, pkt_data, pkt_len);
    aicwf_sdio_aggr_send(sdiodev);
    #endif

done:
    return 0;
}

uint8_t crc8_ponl_107(uint8_t *p_buffer, uint16_t cal_size)
{
    uint8_t i;
    uint8_t crc = 0;
    if (cal_size==0) {
        return crc;
    }
    while (cal_size--) {
        for (i = 0x80; i > 0; i /= 2) {
            if (crc & 0x80)  {
                crc *= 2;
                crc ^= 0x07; //polynomial X8 + X2 + X + 1,(0x107)
            } else {
                crc *= 2;
            }
            if ((*p_buffer) & i) {
                crc ^= 0x07;
            }
        }
        p_buffer++;
    }
    return crc;
}

int aicwf_sdio_aggr(struct aic_sdio_dev *sdiodev, u8 *pkt_data, u32 pkt_len)
{
    struct rwnx_txhdr *txhdr = (struct rwnx_txhdr *)pkt_data;
    u8 *start_ptr = sdiodev->tail;
    u8 sdio_header[4];
    u8 adjust_str[4] = {0, 0, 0, 0};
    u32 curr_len = 0;
    int allign_len = 0;
    u32 aggr_len = sdiodev->len + ((pkt_len + sizeof(sdio_header) + (TX_ALIGNMENT - 1)) & (~(TX_ALIGNMENT - 1)));
    if ((aggr_len % TXPKT_BLOCKSIZE) != 0) {
        aggr_len += TAIL_LEN;
    }

    if (aggr_len > MAX_AGGR_TXPKT_LEN) {
        AIC_LOG_PRINTF("sdio aggr overflow:%d/%d/%d/%d", sdiodev->len, pkt_len, aggr_len, (u32)(sdiodev->aggr_buf_align - sdiodev->aggr_buf));
        sdiodev->aggr_end = 1;
        return -1;
    }
    #if 0
    sdio_header[0] =((pkt_len - sizeof(struct rwnx_txhdr) + sizeof(struct txdesc_api)) & 0xff);
    sdio_header[1] =(((pkt_len - sizeof(struct rwnx_txhdr) + sizeof(struct txdesc_api)) >> 8)&0x0f);
    sdio_header[2] = 0x01; //data
    sdio_header[3] = 0; //reserved

    memcpy(sdiodev->tail, (u8 *)&sdio_header, sizeof(sdio_header));
    sdiodev->tail += sizeof(sdio_header);
    //payload
    memcpy(sdiodev->tail, (u8 *)(long)&txhdr->sw_hdr->desc, sizeof(struct txdesc_api));
    sdiodev->tail += sizeof(struct txdesc_api); //hostdesc
    memcpy(sdiodev->tail, (u8 *)((u8 *)txhdr + txhdr->sw_hdr->headroom), pkt_len-txhdr->sw_hdr->headroom);
    sdiodev->tail += (pkt_len - txhdr->sw_hdr->headroom);
    #else
    sdio_header[0] =((pkt_len) & 0xff);
    sdio_header[1] =(((pkt_len) >> 8)&0x0f);
    sdio_header[2] = 0x01; //data
    if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8800D80)
		sdio_header[3] = crc8_ponl_107(&sdio_header[0], 3); // crc8
    else
		sdio_header[3] = 0; //reserved

    memcpy(sdiodev->tail, (u8 *)&sdio_header, sizeof(sdio_header));
    sdiodev->tail += sizeof(sdio_header);
    // hostdesc + payload
    memcpy(sdiodev->tail, (u8 *)pkt_data, pkt_len);
    sdiodev->tail += pkt_len;
    #endif

    //word alignment
    curr_len = sdiodev->tail - sdiodev->head;
    if (curr_len & (TX_ALIGNMENT - 1)) {
        allign_len = TX_ALIGNMENT - (curr_len & (TX_ALIGNMENT - 1));
        memcpy(sdiodev->tail, adjust_str, allign_len);
        sdiodev->tail += allign_len;
    }

    if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8801 || g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DC ||
        g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
        start_ptr[0] = ((sdiodev->tail - start_ptr - 4) & 0xff);
        start_ptr[1] = (((sdiodev->tail - start_ptr - 4)>>8) & 0x0f);
    }

    #if 0
    if(!txhdr->sw_hdr->need_cfm) {
        kmem_cache_free(txhdr->sw_hdr->rwnx_vif->rwnx_hw->sw_txhdr_cache, txhdr->sw_hdr);
        skb_pull(pkt, txhdr->sw_hdr->headroom);
        consume_skb(pkt);
    }
    #endif

    sdiodev->len = sdiodev->tail - sdiodev->head;
    if (((sdiodev->len + (TXPKT_BLOCKSIZE - 1)) & ~(TXPKT_BLOCKSIZE - 1)) > MAX_AGGR_TXPKT_LEN) {
		printf("over MAX_AGGR_TXPKT_LEN");
        sdiodev->aggr_end = 1;
    }
    sdiodev->aggr_count++;
    if (sdiodev->aggr_count == sdiodev->fw_avail_bufcnt - DATA_FLOW_CTRL_THRESH) {
        sdiodev->aggr_end = 1;
    }

    return 0;
}

void aicwf_sdio_aggr_send(struct aic_sdio_dev *sdiodev)
{
    u8 *tx_buf = sdiodev->aggr_buf_align;
    int ret = 0;
    int curr_len = 0;

    if (sdiodev->aggr_count > 1) {
        //aic_dbg("sdio ac=%d",sdiodev->aggr_count);
    }

    //link tail is necessary
    curr_len = sdiodev->tail - sdiodev->head;
    if ((curr_len % TXPKT_BLOCKSIZE) != 0) {
        memset(sdiodev->tail, 0, TAIL_LEN);
        sdiodev->tail += TAIL_LEN;
    }

    sdiodev->len = sdiodev->tail - sdiodev->head;
//print_hex_dump_bytes(tx_buf, sdiodev->len);
    curr_len = (sdiodev->len + SDIOWIFI_FUNC_BLOCKSIZE - 1) / SDIOWIFI_FUNC_BLOCKSIZE * SDIOWIFI_FUNC_BLOCKSIZE;
    ret = aicwf_sdio_send_pkt(tx_buf, curr_len);
    if (ret < 0) {
        AIC_LOG_PRINTF("fail to send aggr pkt!");
    }

    aicwf_sdio_aggrbuf_reset(sdiodev);
}

void aicwf_sdio_aggrbuf_reset(struct aic_sdio_dev *sdiodev)
{
    sdiodev->tail = sdiodev->head;
    sdiodev->len = 0;
    sdiodev->aggr_count = 0;
    sdiodev->aggr_end = 0;
}

void aicwf_sdio_tx_init(void)
{
    int ret;
    struct aic_sdio_dev *sdiodev = &sdio_dev;
    sdiodev->aggr_buf = rtos_malloc(MAX_AGGR_TXPKT_LEN + AGGR_TXPKT_ALIGN_SIZE);
    if(!sdiodev->aggr_buf) {
        AIC_LOG_PRINTF("Alloc sdio tx aggr_buf failed!");
        return;
    }
    sdiodev->aggr_buf_align = (u8 *)(((uint32_t)sdiodev->aggr_buf + AGGR_TXPKT_ALIGN_SIZE - 1) & ~(AGGR_TXPKT_ALIGN_SIZE - 1));
    sdiodev->fw_avail_bufcnt = 0;
    //sdiodev->tx_pktcnt = 0;
    sdiodev->head = sdiodev->aggr_buf_align;
    aicwf_sdio_aggrbuf_reset(sdiodev);
    ret = rtos_mutex_create(&sdiodev->bus_txrx, "sdiodev->bus_txrx");
    if (ret) {
        AIC_LOG_PRINTF("Alloc sdio txrx mutex failed, ret=%d", ret);
    }
    AIC_LOG_PRINTF("sdio aggr_buf:%p, aggr_buf_align:%p", sdiodev->aggr_buf, sdiodev->aggr_buf_align);
}

void aicwf_sdio_tx_deinit(void)
{
    struct aic_sdio_dev *sdiodev = &sdio_dev;
    if (sdiodev->aggr_buf) {
        rtos_free(sdiodev->aggr_buf);
        sdiodev->aggr_buf = NULL;
        sdiodev->aggr_buf_align = NULL;
    }
    aicwf_sdio_aggrbuf_reset(sdiodev);
    rtos_mutex_delete(sdiodev->bus_txrx);
}


#define DRV_Reg32(addr)               (*(volatile INT32U *)(addr))

static __inline int gpio_request_irq(uint32_t gpio_id, uint32_t trig_type, int (* isr)(uint32_t, uint32_t))
{
//    GPIO_SetInterruptSense(gpio_id, trig_type);
    #if 0
    sprd_gpio_int_reg(gpio_id, (GPIO_CALLBACK)isr);
    #endif
    return TRUE;
}

static __inline void gpio_enable_irq(uint32_t gpio_id)
{
//    GPIO_EnableIntCtl(gpio_id);
}

static __inline void gpio_disable_irq(uint32_t gpio_id)
{
//    GPIO_DisableIntCtl(gpio_id);
}

bool sdio_host_enable_isr(bool enable)
{
#ifdef CONFIG_AIC_SDIO_INT_PINNUM
     if(enable)
        gpio_enable_irq(sdio_gpio_num);
     else
        gpio_disable_irq(sdio_gpio_num);
#endif
    return TRUE;
}

bool aic_sdio_set_block_size(unsigned int blksize)
{
    unsigned char blk[2];
    uint8_t in, out;
    int err_ret = 0;

    if ((blksize == 0) || (blksize > 512))
    {
        blksize = SDIOWIFI_FUNC_BLOCKSIZE;
    }
    #if 0
    blk[0] = blksize & 0x0ff;
    blk[1] = (blksize >> 8)&0x0ff;

    ////sdio_claim_host(sdio_function[FUNC_0]);
    //sdio_writeb(sdio_function[FUNC_0], blk[0], SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG, &err_ret);
    sdio_f0_writeb(func, blk[0], SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG, &err_ret);
    if(err_ret != TRUE){
        AIC_LOG_PRINTF("aic_sdio_set_block_size fail 0!");
        ////sdio_release_host(sdio_function[FUNC_0]);
        return FALSE;
    }

    //sdio_writeb(sdio_function[FUNC_0], blk[1], SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG + 1, &err_ret);
    sdio_f0_writeb(func, blk[1], SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG + 1, &err_ret);
    if(err_ret != TRUE){
        AIC_LOG_PRINTF("aic_sdio_set_block_size fail 1!");
        ////sdio_release_host(sdio_function[FUNC_0]);
        return FALSE;
    }

    blk[0] = 0;
    blk[1] = 0;
    //blk[0] = sdio_readb(sdio_function[FUNC_0], SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG, &err_ret);
    blk[0] = sdio_f0_readb(func, SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG, &err_ret);
    if(err_ret != TRUE){
        AIC_LOG_PRINTF("sdio_readb 0x%d fail 0!", SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG);
        ////sdio_release_host(sdio_function[FUNC_0]);
        return FALSE;
    }

    //blk[1] = sdio_readb(sdio_function[FUNC_0], SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG + 1, &err_ret);
    blk[1] = sdio_f0_readb(func, SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG + 1, &err_ret);
    if(err_ret != TRUE){
        AIC_LOG_PRINTF("sdio_readb 0x%x fail 1!", SDIOWIFI_FBR_FUNC1_BLK_SIZE_REG + 1);
        ////sdio_release_host(sdio_function[FUNC_0]);
        return FALSE;
    }

    ////sdio_release_host(sdio_function[FUNC_0]);

    if (((unsigned int)(blk[1] << 8) | blk[0]) != blksize) {
        AIC_LOG_PRINTF("aic_sdio_set_block_size fail, target=%d, readback=%d!", blksize, ((unsigned int)(blk[1] << 8
) | blk[0]));
        return FALSE;
    }
    #endif
    sdio_block_size = blksize;
    return TRUE;
}

bool aic_sdio_set_block_size_func2(unsigned int blksize)
{
    unsigned char blk[2];
    uint8_t in, out;
    int err_ret = 0;

    if ((blksize == 0) || (blksize > 512))
    {
        blksize = SDIOWIFI_FUNC_BLOCKSIZE;
    }
    #if 0
    blk[0] = blksize & 0x0ff;
    blk[1] = (blksize >> 8)&0x0ff;

    //sdio_claim_host(sdio_function[FUNC_0]);
    sdio_writeb(sdio_function[FUNC_0], blk[0], SDIOWIFI_FBR_FUNC2_BLK_SIZE_REG, &err_ret);
    if(err_ret != TRUE){
        AIC_LOG_PRINTF("aic_sdio_set_block_size fail0!");
        //sdio_release_host(sdio_function[FUNC_0]);
        return FALSE;
    }

    sdio_writeb(sdio_function[FUNC_0], blk[1], SDIOWIFI_FBR_FUNC2_BLK_SIZE_REG + 1, &err_ret);
    if(err_ret != TRUE){
        AIC_LOG_PRINTF("aic_sdio_set_block_size fail0!");
        //sdio_release_host(sdio_function[FUNC_0]);
        return FALSE;
    }

    blk[0] = 0;
    blk[1] = 0;
    blk[0] = sdio_readb(sdio_function[FUNC_0], SDIOWIFI_FBR_FUNC2_BLK_SIZE_REG, &err_ret);
    if(err_ret != TRUE){
        AIC_LOG_PRINTF("sdio_readb 0x%d fail0!", SDIOWIFI_FBR_FUNC2_BLK_SIZE_REG);
        //sdio_release_host(sdio_function[FUNC_0]);
        return FALSE;
    }

    blk[1] = sdio_readb(sdio_function[FUNC_0], SDIOWIFI_FBR_FUNC2_BLK_SIZE_REG + 1, &err_ret);
    if(err_ret != TRUE){
        AIC_LOG_PRINTF("sdio_readb 0x%x fail0!", SDIOWIFI_FBR_FUNC2_BLK_SIZE_REG + 1);
        //sdio_release_host(sdio_function[FUNC_0]);
        return FALSE;
    }

    //sdio_release_host(sdio_function[FUNC_0]);

    if (((unsigned int)(blk[1] << 8) | blk[0]) != blksize) {
        AIC_LOG_PRINTF("aic_sdio_set_block_size fail, target=%d, readback=%d!", blksize, ((unsigned int)(blk[1] << 8
) | blk[0]));
        return FALSE;
    }
    #endif
    sdio_block_size = blksize;
    return TRUE;
}

uint32_t sdio_get_block_size(void)
{
    return sdio_block_size;
}

bool sdio_set_clk(uint32_t clk)
{
    return TRUE;
}

bool sdio_set_bwidth(uint8_t bwidth)
{
    //if(SDIO_BUS_1_BIT == bwidth)
    //    return sdio_set_bus_width(USE_ONE_BUS);

    //if(SDIO_BUS_4_BIT == bwidth)
    //    return sdio_set_bus_width(USE_FOUR_BUS);
    return TRUE;
}

void sdio_host_isr (uint32_t gpio_id, uint32_t gpio_state)
{
    //AIC_LOG_PRINTF("sdio_host_isr gpio_id=%d", gpio_id);
    //if (SDHCI_INTR_STS_CARD_INTR & arg)
    {
        #if 0
        sdio_host_enable_isr(FALSE);
        #endif
        #if 0
        if (g_sdio_isr_func)
        {
            g_sdio_isr_func();
        }
        #endif
    }
    rtos_semaphore_signal(sdio_rx_sema, true);
}

#if (FHOST_RX_SW_VER == 3)
void sdio_buf_init(void)
{
    int idx, ret;
    ret = rtos_mutex_create(&sdio_rx_buf_list.mutex, "sdio_rx_buf_list.mutex");
    if (ret) {
        aic_dbg("sdio rx buf mutex create fail: %d", ret);
        return;
    }
    co_list_init(&sdio_rx_buf_list.list);
    //if (rtos_semaphore_create(&sdio_rx_buf_list.sdio_rx_node_sema, "sdio_rx_buf_list.sdio_rx_node_sema", SDIO_RX_BUF_COUNT, 0)) {
    //    ASSERT_ERR(0);
    //}
    for (idx = 0; idx < SDIO_RX_BUF_COUNT; idx++) {
        struct sdio_buf_node_s *node = &sdio_rx_buf_node[idx];
        node->buf_raw = &sdio_rx_buf_pool[idx][0];
        node->buf = NULL;
        node->buf_len = 0;
        node->pad_len = 0;
        co_list_push_back(&sdio_rx_buf_list.list, &node->hdr);
        //rtos_semaphore_signal(sdio_rx_buf_list.sdio_rx_node_sema, 0);
    }
    //AIC_LOG_PRINTF("sdio_rx_node_sema initial count:%d", rtos_semaphore_get_count(sdio_rx_buf_list.1155sdio_rx_node_sema));
}

struct sdio_buf_node_s *sdio_buf_alloc(uint16_t buf_len)
{
    struct sdio_buf_node_s *node = NULL;
    int ret = 0; //rtos_semaphore_wait(sdio_rx_buf_list.sdio_rx_node_sema, 100);

    if (ret == 0) {
        rtos_mutex_lock(sdio_rx_buf_list.mutex, -1);
        if(co_list_is_empty(&sdio_rx_buf_list.list)) {
            printf("Wait sdio rx buf");
            rtos_mutex_unlock(sdio_rx_buf_list.mutex);
            return node;
        } else
            //AIC_LOG_PRINTF("sdio_rx_buf cnt %d", co_list_cnt(&sdio_rx_buf_list.list));
        node = (struct sdio_buf_node_s *)co_list_pop_front(&sdio_rx_buf_list.list);
        if (buf_len > SDIO_RX_BUF_SIZE) {
            uint8_t *buf_raw = rtos_malloc(buf_len + SYS_CACHE_LINE_SIZE);
            if (buf_raw == NULL) {
                AIC_LOG_PRINTF("sdio buf alloc fail(len=%d)!!!", buf_len);
                node->buf = NULL;
                node->buf_len = 0;
                node->pad_len = 0;
            } else {
                node->buf = (uint8_t *)WCN_CACHE_ALIGNED(buf_raw);
                node->buf_len = buf_len;
                node->pad_len = node->buf - buf_raw;
            }
        } else {
            node->buf = node->buf_raw;
            node->buf_len = buf_len;
            node->pad_len = 0;
        }
        rtos_mutex_unlock(sdio_rx_buf_list.mutex);
    } else {
        AIC_LOG_PRINTF("sdio_rx_node_sema wait failed");
    }
    return node;
}

void sdio_buf_free(struct sdio_buf_node_s *node)
{
    rtos_mutex_lock(sdio_rx_buf_list.mutex, -1);
    if (node->buf_len == 0) {
        AIC_LOG_PRINTF("null sdio buf free, buf=%p", node->buf);
    } else if (node->buf_len > SDIO_RX_BUF_SIZE) {
        uint8_t *buf_raw = node->buf - node->pad_len;
        rtos_free(buf_raw);
    }
    node->buf = NULL;
    node->buf_len = 0;
    node->pad_len = 0;
    co_list_push_back(&sdio_rx_buf_list.list, &node->hdr);
    rtos_mutex_unlock(sdio_rx_buf_list.mutex);
    //rtos_semaphore_signal(sdio_rx_buf_list.sdio_rx_node_sema, 0);
}
#endif

void sdio_rx_task(void *argv)
{
    struct rwnx_hw *rwnx_hw = (struct rwnx_hw *)argv; //g_rwnx_hw;
    //printf("sdio_rx_task");
    while (1) {
        int polling = 1;
        rtos_semaphore_wait(sdio_rx_sema, -1);
        //AIC_LOG_PRINTF("aft sdio sema\n");

        if (msgcfm_poll_en == 0) { // process sdio rx in task
    	    u8 intstatus = 0;
            u32 data_len;
            int ret = 0, idx, retry_cnt = 0;
            static uint32_t max_data_len = 0;
		    struct aic_sdio_dev *sdiodev = &sdio_dev;
            rtos_mutex_lock(sdiodev->bus_txrx, -1);
		    if (rwnx_hw->chipid == PRODUCT_ID_AIC8801) {
        	    ret = sdio_readb_cmd52(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
        	    while ((ret == FALSE) || (intstatus & SDIO_OTHER_INTERRUPT)) {
				    AIC_LOG_PRINTF("ret=%d, intstatus=%x",ret, intstatus);
 				    ret = sdio_readb_cmd52(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
				    retry_cnt++;
				    if (retry_cnt >= 8) {
                	    break;
				    }
        	    }
    		} else if (rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
    			if (func_flag_rx)
    				ret = sdio_readb_cmd52_func2(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
    			else
    				ret = sdio_readb_cmd52(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
    			while ((ret == FALSE) || (intstatus & SDIO_OTHER_INTERRUPT)) {
    				AIC_LOG_PRINTF("ret=%d, intstatus=%x",ret, intstatus);
    				if (func_flag_rx)
    					ret = sdio_readb_cmd52_func2(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
    				else
    					ret = sdio_readb_cmd52(SDIOWIFI_BLOCK_CNT_REG, &intstatus);
    				retry_cnt++;
    				if (retry_cnt >= 8) {
    					break;
    				}
    			}
    		} else if (rwnx_hw->chipid == PRODUCT_ID_AIC8800D80) {
    			do {
    				ret = sdio_readb_cmd52(SDIOWIFI_MISC_INT_STATUS_REG_V3, &intstatus);
    				if (ret)
                    	break;
    				AIC_LOG_PRINTF("%s, ret=%d, intstatus=%x\r", __func__, ret, intstatus);
    			} while (1);
    			if (intstatus & SDIO_OTHER_INTERRUPT) {
                	u8 int_pending;
                	ret = sdio_readb_cmd52(SDIOWIFI_INTR_PENDING_REG_V3, &int_pending);
                	if (ret == FALSE) {
                    	AIC_LOG_PRINTF("reg:%d read failed!", SDIOWIFI_INTR_PENDING_REG_V3);
                	}
                	int_pending &= ~0x01; // dev to host soft irq
                	ret = sdio_writeb_cmd52(SDIOWIFI_INTR_PENDING_REG_V3, int_pending);
                	if (ret == FALSE) {
                    	AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_INTR_PENDING_REG_V3);
                	}
    			}
    		}
            rtos_mutex_unlock(sdiodev->bus_txrx);

            //AIC_LOG_PRINTF("[task] intstatus=%d, retry_cnt=%d", intstatus, retry_cnt);
            if ((intstatus > 0) && (retry_cnt < 8)) {
				if (rwnx_hw->chipid == PRODUCT_ID_AIC8800D80) {
					uint8_t intmaskf2 = intstatus | (0x1UL << 3);
					u8 byte_len = 0;
                	if (intstatus == 120U) { // byte mode
                    	rtos_mutex_lock(sdiodev->bus_txrx, -1);
                    	ret = sdio_readb_cmd52(SDIOWIFI_BYTEMODE_LEN_REG_V3, &byte_len);
                    	rtos_mutex_unlock(sdiodev->bus_txrx);
						if (ret == FALSE) {
                            AIC_LOG_PRINTF("byte mode len read err %d\r", ret);
                    	}
                    	AIC_LOG_PRINTF("byte mode len=%d\r", byte_len);
                    	data_len = byte_len * 4; //byte_len must<= 128
                	} else { // block mode
                    	data_len = (intstatus & 0x7FU) * SDIOWIFI_FUNC_BLOCKSIZE;
                	}
				} else {
					if (intstatus < 64) {
                    	data_len = intstatus * SDIOWIFI_FUNC_BLOCKSIZE;
                	} else {
                    	u8 byte_len = 0;

                    	rtos_mutex_lock(sdiodev->bus_txrx, -1);
                    	if (rwnx_hw->chipid == PRODUCT_ID_AIC8801) {
                        	ret = sdio_readb_cmd52(SDIOWIFI_BYTEMODE_LEN_REG, &byte_len);
                    	} else if (rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
                        	if (func_flag_rx)
                            	ret = sdio_readb_cmd52_func2(SDIOWIFI_BYTEMODE_LEN_REG, &byte_len);
                        	else
                            	ret = sdio_readb_cmd52(SDIOWIFI_BYTEMODE_LEN_REG, &byte_len);
                    	}
                    	rtos_mutex_unlock(sdiodev->bus_txrx);
                    	if (ret == FALSE) {
                        	AIC_LOG_PRINTF("byte mode len read err %d\r", ret);
                    	}
                    	AIC_LOG_PRINTF("byte mode len=%d\r", byte_len);
                    	data_len = byte_len * 4; //byte_len must<= 128
                	}
                }
                if (data_len) {
                    if (max_data_len < data_len) {
                        max_data_len = data_len;
                        aic_dbg("max_data_len=%d", max_data_len);
                    }
                    #if (FHOST_RX_SW_VER == 3)
                    do {
                        uint8_t *buf_rx;
                        int ret;
                        struct sdio_buf_node_s *node = sdio_buf_alloc(data_len);
                        if ((node == NULL) || (node != NULL && node->buf == NULL)) {
                            //AIC_LOG_PRINTF("node/buf alloc fail(len=%d),node=%p,buf=%p!!!", data_len, node, node-buf);
                            if (node) {
                                sdio_buf_free(node);
                                node = NULL;
                            }
                            break;
                        }
                        buf_rx = node->buf;
                        ret = aicwf_sdio_recv_pkt(buf_rx, data_len, 1);
                        if (ret) {
                            AIC_LOG_PRINTF("recv pkt err %d", ret);
                            sdio_buf_free(node);
                            break;
                        }
                        //aic_dbg("enq,%p,%d, node:%p",buf_rx, data_len, node);
                        fhost_rxframe_enqueue(node);
                        //printf("enq cnt %d", co_list_cnt(&fhost_rx_env.rxq.list));
                        rtos_semaphore_signal(fhost_rx_env.rxq_trigg, 0);
                    } while (0);
                    #endif
                }
            } else if (!polling) {
                AIC_LOG_PRINTF("Interrupt but no data, intstatus=%d, retry_cnt=%d", intstatus, retry_cnt);
            }
        } else {
            AIC_LOG_PRINTF("msgcfm_poll_en is 1");
        }
        //aic_dbg("#*So");
   }
}

bool is_truly_isr(void)
{
    return TRUE;
}

static void aicwf_sdio_irq_hdl(struct sdio_func *func)
{
    rtos_semaphore_signal(sdio_rx_sema, true);
    //sdio_rx_task(func);
}

static int sdio_interrupt_init(void)
{
    int ret = 0;
    #if !defined PLATFORM_ALLWIN_RT_THREAD
    AIC_LOG_PRINTF("sdio_host_init:sdiom_gpio_num: %u", sdio_gpio_num);

    ret = gpio_direction_input(sdio_gpio_num);
    if (ret != TRUE) {
        AIC_LOG_PRINTF("sdio_host_init:gpio:%d input set fail!!!", sdio_gpio_num);
        return -1;
    }
    ret = gpio_request_irq(sdio_gpio_num, IRQF_TRIGGER_HIGH, sdio_host_isr);
    if (ret != TRUE) {
        AIC_LOG_PRINTF("sdio_host_init:request irq err!!!gpio is %d!!!", sdio_gpio_num);
        return -1;
    }
    #endif
    #if 1
    sdio_claim_host(sdio_card);
    sdio_claim_irq(sdio_function[FUNC_1], NULL);
    sdio_function[FUNC_1]->irq_handler = aicwf_sdio_irq_hdl;
    sdio_release_host(sdio_card);

    if (g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || g_rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
        sdio_claim_host(sdio_function[FUNC_2]->card);
        sdio_claim_irq(sdio_function[FUNC_2], NULL);
        sdio_function[FUNC_2]->irq_handler = aicwf_sdio_irq_hdl;
        sdio_release_host(sdio_function[FUNC_2]->card);
    }
    #endif
    return ret;
}

#if (CONFIG_TXMSG_TEST_EN)
void aic_txmsg_test(void)
{
    __align(64) static u8 buffer[64] = {0,};
    __align(64) static u8 buffer_rx[512] = {0,};
    int err;
    int len = sizeof(struct lmac_msg) + sizeof(struct dbg_mem_read_req);
    struct dbg_mem_read_cfm rd_mem_addr_cfm;
    struct dbg_mem_read_cfm *cfm = &rd_mem_addr_cfm;
    struct lmac_msg *msg;
    struct dbg_mem_read_req *req;
    int index = 0;
    buffer[0] = (len+4) & 0x00ff;
    buffer[1] = ((len+4) >> 8) &0x0f;
    buffer[2] = 0x11;
    buffer[3] = 0x0;
    index += 4;
    //there is a dummy word
    index += 4;
    msg = (struct lmac_msg *)&buffer[index];
    msg->id = DBG_MEM_READ_REQ;
    msg->dest_id = TASK_DBG;
    msg->src_id = 100;
    msg->param_len = sizeof(struct dbg_mem_read_req);
    req = (struct dbg_mem_read_req *)&msg->param[0];
    req->memaddr = 0x40500000;
    err = aicwf_sdio_tx_msg(buffer, len + 8, buffer_rx);
    if (!err) {
        AIC_LOG_PRINTF("tx msg done");
    }
}
#endif

int aic_gpio_ind_init(void)
{
    int err = 0;
    #if 0
    __align(64) static u8 buffer[64] = {0,};
    __align(64) static u8 buffer_rx[512] = {0,};
    int len = sizeof(struct lmac_msg) + sizeof(struct dbg_mem_write_req);
    struct dbg_mem_write_cfm wr_mem_cfm;
    struct dbg_mem_write_cfm *cfm = &wr_mem_cfm;
    struct lmac_msg *msg;
    struct dbg_mem_write_req *req;
    int index = 0;
    buffer[0] = (len+4) & 0x00ff;
    buffer[1] = ((len+4) >> 8) &0x0f;
    buffer[2] = 0x11;
    buffer[3] = 0x0;
    index += 4;
    //there is a dummy word
    index += 4;
    msg = (struct lmac_msg *)&buffer[index];
    msg->id = DBG_MEM_WRITE_REQ;
    msg->dest_id = TASK_DBG;
    msg->src_id = 100;
    msg->param_len = sizeof(struct dbg_mem_write_req);
    req = (struct dbg_mem_write_req *)&msg->param[0];
    #if 1
    do {
        req->memaddr = 0x40500028;
        req->memdata = 0x00000000;
        err = aicwf_sdio_tx_msg(buffer, len + 8, buffer_rx);
        if (err) {
            AIC_LOG_PRINTF("tx msg [0] fail");
            break;
        }
        req->memaddr = 0x4050301C;
        req->memdata = 0x00000007;
        err = aicwf_sdio_tx_msg(buffer, len + 8, buffer_rx);
        if (err) {
            AIC_LOG_PRINTF("tx msg [1] fail");
            break;
        }
        req->memaddr = 0x40100054;
        req->memdata = 0x00000001;
        err = aicwf_sdio_tx_msg(buffer, len + 8, buffer_rx);
        if (err) {
            AIC_LOG_PRINTF("tx msg [2] fail");
            break;
        }
        req->memaddr = 0x4024107C;
        req->memdata = 0x00000001;
        err = aicwf_sdio_tx_msg(buffer, len + 8, buffer_rx);
        if (err) {
            AIC_LOG_PRINTF("tx msg [3] fail");
            break;
        }
        req->memaddr = 0x402400F0;
        req->memdata = 0x00340022;
        err = aicwf_sdio_tx_msg(buffer, len + 8, buffer_rx);
        if (err) {
            AIC_LOG_PRINTF("tx msg [4] fail");
            break;
        }
    } while (0);
    #else
    int idx, cnt = 0;
    uint32_t (*p_tbl)[2] = NULL;
    // for 8800d
    const uint32_t gpio_cfg_tbl_8800d[][2] = {
        {0x40500028, 0x00000000},
        {0x4050301C, 0x00000007},
        {0x40100054, 0x00000001},
        {0x4024107C, 0x00000001},
        {0x402400F0, 0x00340022},
    };
    // for 8800dc/dw
    const uint32_t gpio_cfg_tbl_8800dcdw[][2] = {
        {0x40500040, 0x00000000},
        {0x4050401C, 0x00000007},
        {0x40100030, 0x00000001},
        {0x40241020, 0x00000001},
        {0x402400F0, 0x00340022},
    };
    if (rwnx_hw->chipid == PRODUCT_ID_AIC8801) {
        p_tbl = gpio_cfg_tbl_8800d;
        cnt = sizeof(gpio_cfg_tbl_8800d) / sizeof(uint32_t) / 2;
    } else if ((rwnx_hw->chipid == PRODUCT_ID_AIC8800DC) || (rwnx_hw->chipid == PRODUCT_ID_AIC8800DW)) {
        p_tbl = gpio_cfg_tbl_8800dcdw;
        cnt = sizeof(gpio_cfg_tbl_8800dcdw) / sizeof(uint32_t) / 2;
    } else {
        AIC_LOG_PRINTF("unsupported chipid");
        return -1;
    }
    for (idx = 0; idx < cnt; idx++) {
        req->memaddr = p_tbl[idx][0];
        req->memdata = p_tbl[idx][1];
        err = aicwf_sdio_tx_msg(buffer, len + 8, buffer_rx);
        if (err) {
            AIC_LOG_PRINTF("tx msg [%d] fail", idx);
            break;
        }
    }
    #endif
    #endif
    msgcfm_poll_en = 0;
    return err;
}

uint32_t sdio_drv_probe(void) {
    TRACE_IN();
    if (sdio_find_func(SDIO_ANY_ID, SDIO_ANY_ID, SDIO_ANY_ID) == NULL) {
        AIC_LOG_PRINTF("sdio_drv_probe: get func err!");
        return -ENODEV;
    }
    TRACE_OUT();
    return 0;
}

bool sdio_host_init(struct rwnx_hw *rwnx_hw, void (*sdio_isr)(void))
{
	//struct mmc_card *card;
    int32_t ret = 0;
    uint8_t in;
    int err_ret = 0;
    int i =0;
    uint8_t block_bit0 = 0x1;
    uint8_t byte_mode_disable = 0x1;//1: no byte mode
    
    aicwf_sdio_tx_init();

    /* Enable Function 1 */
    if (rwnx_hw->chipid == PRODUCT_ID_AIC8801) {
		sdio_function[FUNC_1] = sdio_find_func(0x7, 0x5449, 0x145);
		if(!sdio_function[FUNC_1]){
			ret = -ENODEV;
			AIC_LOG_PRINTF("%s: sdio_find_func func1 failed!!(%d)", __func__, ret);
			return ret;
		}
	} else if (rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
		sdio_function[FUNC_0] = sdio_find_func(0x7, ~0, ~0);
		if(!sdio_function[FUNC_0]){
			ret = -ENODEV;
			AIC_LOG_PRINTF("%s: sdio_find_func func0 failed!!(%d)", __func__, ret);
			//return ret;
		}
        ret = sdio_enable_func(sdio_function[FUNC_0]->card, sdio_function[FUNC_0]->num);
        if (ret < 0) {
            //AIC_LOG_PRINTF("sdio_host_init:enable func0 err! ret is %d, num %d\r", ret, sdio_function[FUNC_0]->num);
            //return ret;
        }
        sdio_function[FUNC_1] = sdio_find_func(0x7, 0xc8a1, 0xc08d);
		if(!sdio_function[FUNC_1]){
			ret = -ENODEV;
			AIC_LOG_PRINTF("%s: sdio_find_func func1 failed!!(%d)", __func__, ret);
			return ret;
		}
	} else if (rwnx_hw->chipid == PRODUCT_ID_AIC8800D80) {
		sdio_function[FUNC_1] = sdio_find_func(0x7, 0xc8a1, 0x82);
		if(!sdio_function[FUNC_1]){
			ret = -ENODEV;
			AIC_LOG_PRINTF("%s: sdio_find_func func1 failed!!(%d)", __func__, ret);
			return ret;
		}
	}

	sdio_card = sdio_function[FUNC_1]->card;
    sdio_claim_host(sdio_card);
    ret = sdio_enable_func(sdio_card, sdio_function[FUNC_1]->num);
    sdio_release_host(sdio_card);
    if (ret < 0) {
        AIC_LOG_PRINTF("sdio_host_init:enable func1 err! ret is %d", ret);
        return ret;
    }
    AIC_LOG_PRINTF("sdio_host_init:enable func1 ok!");

	if (rwnx_hw->chipid == PRODUCT_ID_AIC8800D80) {
		u8 val = 0;
		struct mmc_host *host = sdio_function[FUNC_1]->card->host;
        sdio_function[FUNC_1]->card->quirks |= MMC_QUIRK_LENIENT_FN0;
		sdio_f0_writeb(sdio_function[FUNC_1], 0x7F, 0xF2, &ret);
    	if (ret) {
        	AIC_LOG_PRINTF("set fn0 0xF2 fail %d", ret);
        	return ret;
    	}
    	if (sdio_card->sd_bus_speed == UHS_DDR50_BUS_SPEED) {
        	val = 0x21;//0x1D;//0x5;
    	} else {
        	val = 0x01;//0x19;//0x1;
    	}
    	val |= SDIOCLK_FREE_RUNNING_BIT;
    	sdio_f0_writeb(sdio_function[FUNC_1], val, 0xF0, &ret);
    	if (ret) {
        	AIC_LOG_PRINTF("set iopad ctrl fail %d", ret);
        	return ret;
    	}
    	sdio_f0_writeb(sdio_function[FUNC_1], 0x0, 0xF8, &ret);
    	if (ret) {
        	AIC_LOG_PRINTF("set iopad delay2 fail %d", ret);
        	return ret;
    	}
    	sdio_f0_writeb(sdio_function[FUNC_1], 0x80, 0xF1, &ret);
    	if (ret) {
        	AIC_LOG_PRINTF("set iopad delay1 fail %d", ret);
        	return ret;
    	}
    	udelay(2000);
#if 0 //SDIO CLOCK SETTING
		if ((host->ios.clock > 0) && (host->ios.timing != SDIO_SPEED_DDR50)) {
			host->ios.clock = FEATURE_SDIO_CLOCK_V3;
			host->ops->set_ios(host, &host->ios);
			AIC_LOG_PRINTF("Set SDIO Clock %d MHz", host->ios.clock/1000000);
		}
#else
//		ret = HAL_SDC_Update_Clk(card->host, FEATURE_SDIO_CLOCK_V3);
//		AIC_LOG_PRINTF("Set SDIO Clock %d MHz", FEATURE_SDIO_CLOCK_V3/1000000);
#endif
		AIC_LOG_PRINTF("sdio_host_init:aic_sdio_set_block_size %d", SDIOWIFI_FUNC_BLOCKSIZE);
    	aic_sdio_set_block_size(SDIOWIFI_FUNC_BLOCKSIZE);
    
    	AIC_LOG_PRINTF("sdio_host_init:sdio_set_block_size %d", SDIOWIFI_FUNC_BLOCKSIZE);
    	sdio_set_block_size(sdio_card, sdio_function[FUNC_1]->num, SDIOWIFI_FUNC_BLOCKSIZE);
    	if (sdio_block_size != SDIOWIFI_FUNC_BLOCKSIZE) {
        	AIC_LOG_PRINTF("sdio_host_init: blksize set failed");
        	return FALSE;
    	}

    	//1: no byte mode
    	ret = sdio_writeb_cmd52(SDIOWIFI_BYTEMODE_ENABLE_REG_V3, byte_mode_disable);
    	if (ret == FALSE) {
        	AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_BYTEMODE_ENABLE_REG_V3);
        	return ret;
    	}

		//enable sdio interrupt
		sdio_f0_writeb(sdio_function[FUNC_1], 0x07, 0x04, &ret);
		if (ret) {
    		AIC_LOG_PRINTF("set func0 int en fail %d", ret);
        }
		ret = sdio_writeb_cmd52(SDIOWIFI_INTR_ENABLE_REG_V3, 0x7);
    	if (ret == FALSE) {
        	AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_INTR_ENABLE_REG_V3);
        	return ret;
    	}
	}else {
        //struct mmc_host *host;

        AIC_LOG_PRINTF("sdio_host_init:sdio_set_quirks");
        sdio_card->quirks |= MMC_QUIRK_LENIENT_FN0;
		sdio_f0_writeb(sdio_function[FUNC_1], 2, 0x13, &ret);

        AIC_LOG_PRINTF("sdio_host_init:aic_sdio_set_block_size %d", SDIOWIFI_FUNC_BLOCKSIZE);
        aic_sdio_set_block_size(SDIOWIFI_FUNC_BLOCKSIZE);
    
    	sdio_set_block_size(sdio_card, sdio_function[FUNC_1]->num, SDIOWIFI_FUNC_BLOCKSIZE);
    	if (sdio_block_size != SDIOWIFI_FUNC_BLOCKSIZE) {
        	AIC_LOG_PRINTF("sdio_host_init: blksize set failed");
        	return FALSE;
    	}
    
    	ret = sdio_writeb_cmd52(SDIOWIFI_REGISTER_BLOCK, block_bit0);
    	if (ret == FALSE) {
        	AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_REGISTER_BLOCK);
        	return ret;
    	}

        //1: no byte mode
        ret = sdio_writeb_cmd52(SDIOWIFI_BYTEMODE_ENABLE_REG, byte_mode_disable);
        if (ret == FALSE) {
            AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_BYTEMODE_ENABLE_REG);
            return ret;
        }

        //enable sdio interrupt
        ret = sdio_writeb_cmd52(SDIOWIFI_INTR_CONFIG_REG, 0x7);
        if (ret == FALSE) {
            AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_INTR_CONFIG_REG);
            return ret;
        }
    }

    if (rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
#if 1
        /* Enable Function 2 */
        sdio_function[FUNC_2] = sdio_find_func(0x7, 0xc8a1, 0xc18d);
        if(!sdio_function[FUNC_2]){
            ret = -ENODEV;
            AIC_LOG_PRINTF("%s: sdio_find_func func2 failed!!(%d)", __func__, ret);
            return ret;
        }

        sdio_claim_host(sdio_function[FUNC_2]->card);
        ret = sdio_enable_func(sdio_function[FUNC_2]->card, sdio_function[FUNC_2]->num);
        sdio_release_host(sdio_function[FUNC_2]->card);
        if (ret < 0) {
            AIC_LOG_PRINTF("sdio_host_init:enable func2 err! ret is %d", ret);
            return ret;
        }
        AIC_LOG_PRINTF("sdio_host_init:enable fun2 ok!");

        AIC_LOG_PRINTF("sdio_host_init:func2:aic_sdio_set_block_size %d", SDIOWIFI_FUNC_BLOCKSIZE);
        aic_sdio_set_block_size_func2(SDIOWIFI_FUNC_BLOCKSIZE);
        AIC_LOG_PRINTF("sdio_host_init:func2:sdio_set_block_size %d", SDIOWIFI_FUNC_BLOCKSIZE);
        sdio_set_block_size(sdio_function[FUNC_2]->card, sdio_function[2]->num, SDIOWIFI_FUNC_BLOCKSIZE);
        if (sdio_block_size != SDIOWIFI_FUNC_BLOCKSIZE) {
            AIC_LOG_PRINTF("sdio_host_init:func2: blksize set failed");
        }

        ret = sdio_writeb_cmd52_func2(SDIOWIFI_REGISTER_BLOCK, block_bit0);
        if (ret < 0) {
            AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_REGISTER_BLOCK);
            return ret;
        }

        //1: no byte mode
        ret = sdio_writeb_cmd52_func2(SDIOWIFI_BYTEMODE_ENABLE_REG_V3, byte_mode_disable);
        if (ret < 0) {
            AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_BYTEMODE_ENABLE_REG);
            return ret;
        }

        //enable sdio interrupt
        ret = sdio_writeb_cmd52_func2(SDIOWIFI_INTR_CONFIG_REG, 0x7);
        if (ret < 0) {
            AIC_LOG_PRINTF("reg:%d write failed!", SDIOWIFI_INTR_CONFIG_REG);
            return ret;
        }
#endif
    }

    if (sdio_interrupt_init()) {
        AIC_LOG_PRINTF("sdio_host_init: sdio_interrupt_init failed");
        return FALSE;
    }
    //sdio_enable_rx_irq();

    #if 0
    /* disable sdio control interupt at first */
    sdio_host_enable_isr(FALSE);
    #endif

    /* install isr here */
    //g_sdio_isr_func = sdio_isr;

    /* prepare for sdio isr */
    if (aic_gpio_ind_init()) {
        AIC_LOG_PRINTF("gpio ind init fail");
        return FALSE;
    }

    #if (FHOST_RX_SW_VER == 3)
    sdio_buf_init();
    #endif

    rtos_semaphore_create(&sdio_rx_sema, "sdio_rx_sema", 8, 0);
    if (sdio_rx_sema == NULL) {
        AIC_LOG_PRINTF("sdio rx sema create fail");
        return FALSE;
    }
    
    ret = rtos_task_create(sdio_rx_task, "sdio_rx_task", SDIO_DATRX_TASK,
                           sdio_datrx_stack_size, (void*)rwnx_hw, sdio_datrx_priority,
                           &sdio_task_hdl);
    if (ret || (sdio_task_hdl == NULL)) {
        AIC_LOG_PRINTF("sdio task create fail");
        return FALSE;
    }

    #if 0
    /* enable sdio control interupt */
    sdio_host_enable_isr(TRUE);
    #endif

    AIC_LOG_PRINTF("sdio_host_init:host_int ok");

    #if (CONFIG_TXMSG_TEST_EN)
    aic_txmsg_test();
    #endif

    return TRUE;
}

bool sdio_host_deinit(struct rwnx_hw *rwnx_hw)
{
    int ret = 0;

    AIC_LOG_PRINTF("sdio_host_deinit");

    rtos_semaphore_delete(sdio_rx_sema);
    sdio_rx_sema = NULL;

    aicwf_sdio_tx_deinit();
    #if 0
    sdio_host_enable_isr(0);
    #endif
    if (rwnx_hw->chipid == PRODUCT_ID_AIC8800DC || rwnx_hw->chipid == PRODUCT_ID_AIC8800DW) {
        func_flag_tx = true;
        func_flag_rx = true;
    }

    return TRUE;
}

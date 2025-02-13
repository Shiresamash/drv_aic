/*
 * Copyright (C) 2018-2020 AICSemi Ltd.
 *
 * All Rights Reserved
 */

#ifndef _SDIO_PORT_H_
#define _SDIO_PORT_H_

#include "rwnx_defs.h"
#include "co_list.h"

#define SDIO_RX_BUF_COUNT   20//32
#define SDIO_RX_BUF_SIZE    2048

typedef unsigned int    uint;

struct aic_sdio_dev {
    u8 *aggr_buf;
    u8 *aggr_buf_align;
    u8 *head;
    u8 *tail;
    u32 aggr_count;
    u32 len;
    int32 fw_avail_bufcnt;
    u32 aggr_end;
    rtos_mutex bus_txrx;
//    u32 tx_pktcnt;
};

struct sdio_buf_node_s {
    struct co_list_hdr hdr;
    uint8_t *buf_raw; // static alloced
    uint8_t *buf; // 64B aligned, rx in-use
    uint16_t buf_len;
    uint16_t pad_len;
};

struct sdio_buf_list_s {
    struct co_list list;
    rtos_mutex mutex;
    rtos_semaphore sdio_rx_node_sema;
};

extern bool sdio_readb_cmd52(uint32_t addr, uint8_t *data);
bool sdio_readb_cmd52_func2(uint32_t addr, uint8_t *data);
extern bool sdio_writeb_cmd52(uint32_t addr, uint8_t data);
bool sdio_writeb_cmd52_func2(uint32_t addr, uint8_t data);
extern bool sdio_write_cmd53(uint32_t dataPort,uint8_t *dat, size_t size);
extern bool sdio_read_cmd53(uint32_t dataPort,uint8_t *dat, size_t size);
extern bool _sdio_read_reg(uint32_t addr, uint32_t *data);
extern bool aic_sdio_set_block_size(unsigned int blksize);
extern uint32_t sdio_get_block_size(void);
extern bool sdio_host_init(struct rwnx_hw *rwnx_hw, void (*sdio_isr)(void));
extern bool sdio_host_deinit(struct rwnx_hw *rwnx_hw);
extern bool sdio_host_enable_isr(bool enable);
extern bool is_truly_isr(void);
extern uint32_t sdio_drv_probe(void);
bool sdio_set_bwidth(uint8_t bwidth);
bool sdio_set_clk(uint32_t clk);
int aicwf_sdio_flow_ctrl(void);
int aicwf_sdio_tx_msg(u8 *buf, uint count, u8 *out);
int aicwf_sdio_send_check(void);
int aicwf_sdio_send(u8 *pkt_data, u32 pkt_len, bool last);
struct sdio_buf_node_s *sdio_buf_alloc(uint16_t buf_len);
void sdio_buf_free(struct sdio_buf_node_s *node);
void sdio_release_func2(void);
uint8_t crc8_ponl_107(uint8_t *p_buffer, uint16_t cal_size);
#endif /* _SDIO_H_ */


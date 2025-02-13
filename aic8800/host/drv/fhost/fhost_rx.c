/**
 ****************************************************************************************
 *
 * @file fhost_rx.c
 *
 * @brief Implementation of the fully hosted RX task.
 *
 * Copyright (C) RivieraWaves 2017-2019
 *
 ****************************************************************************************
 */

/**
 ****************************************************************************************
 * @addtogroup FHOST_RX
 * @{
 ****************************************************************************************
 */
/*
 * INCLUDE FILES
 ****************************************************************************************
 */
#include "fhost_rx.h"
#include "fhost_rx_def.h"
#include "fhost.h"
#include "co_endian.h"
#include "co_utils.h"
#include "cfgrwnx.h"
#include "rwnx_config.h"
#include "rwnx_rx.h"
#include "rwnx_msg_rx.h"
#include "mac_frame.h"
#include "fhost_cntrl.h"
#include "rwnx_utils.h"
#include "rwnx_main.h"
#include "fhost_tx.h"
#ifdef CONFIG_SDIO_SUPPORT
#include "sdio_def.h"
#endif
#ifdef CONFIG_USB_SUPPORT
#endif
#include "net_al.h"
#include "wifi.h"

/*
 * GLOBAL VARIABLES
 ****************************************************************************************
 */
struct fhost_rx_env_tag fhost_rx_env;
static rtos_semaphore fhost_rx_task_exit_sem = NULL;
static bool fhost_rx_task_exit_flag = false;

/// RFC1042 LLC/SNAP Header
const struct llc_snap_short llc_rfc1042_hdr = {
                                                  0xAAAA, // DSAP LSAP
                                                  0x0003, // Control/Prot0
                                                  0x0000, // Prot1 and 2
                                              };

/// Bridge-Tunnel LLC/SNAP Header
const struct llc_snap_short llc_bridge_tunnel_hdr = {
                                                        0xAAAA, // DSAP LSAP
                                                        0x0003, // Control/Prot0
                                                        0xF800, // Prot1 and 2
                                                    };
#if 0
/// Pool of RX buffers
static struct fhost_rx_buf_tag fhost_rx_buf_mem[FHOST_RX_BUF_CNT] __SHAREDRAM;
#if NX_UF_EN
/// Pool of UF buffers
static struct fhost_rx_uf_buf_tag fhost_rx_uf_buf_mem[FHOST_RX_BUF_CNT] __SHAREDRAM;
#endif // NX_UF_EN
#endif

static rtos_task_handle fhost_rx_task_hdl = NULL;
#ifdef CONFIG_FHOST_RX_ASYNC
#define RX_ASYNC_DESC_CNT    80
static struct fhost_rx_async_desc_tag rx_async_desc_pool[RX_ASYNC_DESC_CNT];
#ifdef CONFIG_SDIO_SUPPORT
static struct sdio_buf_node_s *rx_frame_in_process = NULL;
static uint8 * rx_in_process_buf = NULL;
#endif
#ifdef CONFIG_USB_SUPPORT
static struct aicwf_usb_buf *rx_frame_in_process = NULL;
#endif
static bool rx_frame_to_async = false;
#endif

/*
 * FUNCTIONS
 ****************************************************************************************
 */
/**
 ****************************************************************************************
 * @brief Push a RX buffer to the WiFi task.
 * This buffer can then be used by the WiFi task to copy a received MPDU.
 *
 * @param[in] net_buf   Pointer to the RX buffer to push
 ****************************************************************************************
 */
void fhost_rx_buf_push(void *net_buf)
{
    struct fhost_rx_buf_tag *buf = net_buf;

    //aic_dbg("<%s>, buf %x\r\n", __func__, buf);
    buf->info.pattern = RX_BUFFER_PUSHED;
    //ipc_host_rxbuf_push(&ipc_env, (uint32_t)buf, (uint32_t)&(buf->net_hdr.hdr));
}

void fhost_rx_buf_free(void *net_buf)
{
    fhost_rx_buf_push(net_buf);
}


/**
 ****************************************************************************************
 * @brief Forward a RX buffer containing a A-MSDU to the networking stack.
 *
 * @param[in] buf Pointer to the RX buffer to forward
 ****************************************************************************************
 */
static void fhost_rx_amsdu_forward(struct fhost_rx_buf_tag *buf)
{
#ifdef NX_AMSDU
    struct rx_info *info =&buf->info;
    uint8_t vif_idx = (info->flags & RX_FLAGS_VIF_INDEX_MSK) >> RX_FLAGS_VIF_INDEX_OFT;
    struct fhost_vif_tag *fhost_vif = fhost_env.mac2fhost_vif[vif_idx];
    net_if_t *net_if = &fhost_vif->net_if;
    uint8_t *payload;
    uint16_t len;
    int subframe_idx = 0;
    struct llc_snap *llc_snap;
    uint8_t offset;

    do
    {
        offset = 0;

        // Get payload pointer
        payload = (uint8_t *)buf->payload;

        // Get the subframe length
        len = co_ntohs(co_read16(&payload[LLC_ETHERTYPE_LEN_OFT])) + LLC_ETHER_HDR_LEN;

        // Map LLC/SNAP structure on buffer
        llc_snap = (struct llc_snap *)&payload[LLC_ETHER_HDR_LEN];
        if ((!memcmp(llc_snap, &llc_rfc1042_hdr, sizeof(llc_rfc1042_hdr))
             //&& (llc_snap->proto_id != LLC_ETHERTYPE_AARP) - Appletalk depracated ?
             && (llc_snap->proto_id != LLC_ETHERTYPE_IPX))
            || (!memcmp(llc_snap, &llc_bridge_tunnel_hdr, sizeof(llc_bridge_tunnel_hdr))))
        {
            // Packet becomes
            /********************************************
             *  DA  |  SA  |  SNAP->ETHERTYPE  |  DATA  |
             ********************************************/
            // We remove the LLC/SNAP, so adjust the length and the offset
            len -= LLC_802_2_HDR_LEN;
            offset = LLC_802_2_HDR_LEN;

            // Move the source/dest addresses at the right place
            MAC_ADDR_CPY(&payload[offset + MAC_ADDR_LEN], &payload[MAC_ADDR_LEN]);
            MAC_ADDR_CPY(&payload[offset], &payload[0]);

            // No need to copy the Ethertype which is already in place
        }

        // Forward to the networking stack
        net_if_input((net_buf_rx_t *)buf, net_if, &payload[offset], len, fhost_rx_buf_free);

        // Check if we may still have some subframes
        if (subframe_idx == (NX_MAX_MSDU_PER_RX_AMSDU - 1))
            break;

        // Get next subframe
        #if NX_AMSDU_DEAGG
        buf = (struct fhost_rx_buf_tag *)info->amsdu_hostids[subframe_idx++];
        #endif
    } while (buf != NULL);
#endif
}

/**
****************************************************************************************
* @brief Forward a MGMT frame to the registered callback.
*
* @param[in] buf Pointer to the RX buffer to forward
****************************************************************************************
*/
static void fhost_rx_mgmt_buf_forward(struct fhost_rx_buf_tag *buf)
{
   struct fhost_frame_info info;
   //int8_t rx_rssi[2];

   if (fhost_rx_env.mgmt_cb == NULL)
       return;

   info.payload = (uint8_t *)buf->payload;
   info.length = buf->info.vect.frmlen;
   info.freq = PHY_INFO_CHAN(buf->info.phy_info);
   //info.rssi = hal_desc_get_rssi(&buf->info.vect.rx_vec_1, rx_rssi);

   fhost_rx_env.mgmt_cb(&info, fhost_rx_env.mgmt_cb_arg);
}

uint8_t machdr_len_get(uint16_t frame_cntl)
{
    // MAC Header length
    uint8_t mac_hdr_len = MAC_SHORT_MAC_HDR_LEN;

    // Check if Address 4 field is present (FDS and TDS set to 1)
    if ((frame_cntl & (MAC_FCTRL_TODS | MAC_FCTRL_FROMDS))
                                    == (MAC_FCTRL_TODS | MAC_FCTRL_FROMDS))
    {
        mac_hdr_len += (MAC_LONG_MAC_HDR_LEN - MAC_SHORT_MAC_HDR_LEN);
    }

    // Check if QoS Control Field is present
    if (IS_QOS_DATA(frame_cntl))
    {
        mac_hdr_len += (MAC_LONG_QOS_MAC_HDR_LEN - MAC_LONG_MAC_HDR_LEN);
    }

    // Check if HT Control Field is present (Order bit set to 1)
    if (frame_cntl & MAC_FCTRL_ORDER)
    {
        mac_hdr_len += (MAC_LONG_QOS_HTC_MAC_HDR_LEN - MAC_LONG_QOS_MAC_HDR_LEN);
    }

    return (mac_hdr_len);
}

static uint8_t fhost_mac2ethernet(void *buf)
{
    struct fhost_rx_buf_tag *rx_buf = (struct fhost_rx_buf_tag *)buf;
    uint8_t *frame = (uint8_t *)rx_buf->payload;
    uint32_t statinfo = rx_buf->info.vect.statinfo;
    struct mac_hdr *machdr_ptr = (struct mac_hdr *)frame;
    struct mac_addr da;
    struct mac_addr sa;
    // LLC/SNAP part of the PDU
    struct llc_snap *llc_snap;
    struct mac_eth_hdr *eth_hdr;
    // Compute MAC Header Length (will IV length + EIV length if present)
    uint8_t machdr_len = 0;
    uint8_t payl_offset = 0;

    //aic_dbg("fhost_mac2ethernet, len %d\r\n", rx_buf->info.vect.frmlen); //1542
    //dump_b(frame, 128);

    //aic_dbg("fhost_mac2ethernet, fctl %x, %x, %x\r\n", machdr_ptr->fctl, machdr_ptr->fctl & MAC_FCTRL_TYPE_MASK, MAC_FCTRL_DATA_T);
    //if(MAC_FCTRL_DATA_T == (machdr_ptr->fctl & MAC_FCTRL_TYPE_MASK))
    //    aic_dbg("S %d\r\n", machdr_ptr->seq >> 4);

    if ((machdr_ptr->fctl & MAC_FCTRL_TYPE_MASK) != MAC_FCTRL_DATA_T)
        return payl_offset;

    // Get DA
    if (machdr_ptr->fctl & MAC_FCTRL_TODS)
    {
        MAC_ADDR_CPY(&da, &machdr_ptr->addr3);
    }
    else
    {
        MAC_ADDR_CPY(&da, &machdr_ptr->addr1);
    }

    // Get SA
    if (machdr_ptr->fctl & MAC_FCTRL_FROMDS)
    {

        MAC_ADDR_CPY(&sa, &machdr_ptr->addr3);
    }
    else
    {
        MAC_ADDR_CPY(&sa, &machdr_ptr->addr2);
    }

    //dump_buf(&sa, 6);
    //dump_buf(&da, 6);

    machdr_len = machdr_len_get(machdr_ptr->fctl);
    //aic_dbg("fhost_mac2ethernet, machdr_len %d\r\n", machdr_len);
    //aic_dbg("fhost_mac2ethernet, statinfo %08x\r\n", statinfo);

    switch (statinfo & RX_HD_DECRSTATUS)
    {
        case RX_HD_DECR_CCMP128:
        case RX_HD_DECR_TKIP:
            machdr_len += MAC_IV_LEN + MAC_EIV_LEN;
            break;
        case RX_HD_DECR_WEP:
            machdr_len += MAC_IV_LEN;
            break;
        default:
            break;
    }

    payl_offset = machdr_len + sizeof(struct llc_snap) - sizeof(struct mac_eth_hdr);
    //aic_dbg("fhost_mac2ethernet, payl_offset %d\r\n", payl_offset);

    // Pointer to the payload - Skip MAC Header
    llc_snap = (struct llc_snap *)((uint16_t *)machdr_ptr + (machdr_len >> 1));
    //dump_buf(llc_snap, 8);
    /********************************
     *  DA  |  SA  |  LEN  |  DATA  |
     ********************************/
    /*
     * Ethernet Header will start 7 half-words (MAC Address length is 6 bytes and Length
     * field is 2 bytes) before LLC Snap
     */
    eth_hdr = (struct mac_eth_hdr *)((uint16_t *)llc_snap - 3);

    // Set length (Initial length - MAC Header Length)
    //eth_hdr->len = co_htons(rx_buf->info.vect.frmlen - machdr_len);
    // Set DA and SA in the Ethernet Header
    MAC_ADDR_CPY(&eth_hdr->da, &da);
    MAC_ADDR_CPY(&eth_hdr->sa, &sa);

    //aic_dbg("fhost_ethernet, len %d\r\n", eth_hdr->len);
    //dump_buf(eth_hdr, 128);

    return payl_offset;
}
#if NX_BEACONING
static uint8_t fhost_frame2others(void *buf, struct mac_addr *mac)
{
    struct fhost_rx_buf_tag *rx_buf = (struct fhost_rx_buf_tag *)buf;
    uint8_t *frame = (uint8_t *)rx_buf->payload;
    struct mac_hdr *machdr_ptr = (struct mac_hdr *)frame;
    struct mac_addr da;
    struct mac_addr sa;

    //AIC_LOG_PRINTF("fhost_frame2others %x\r\n", machdr_ptr->fctl);

    if ((machdr_ptr->fctl & MAC_FCTRL_TYPE_MASK) != MAC_FCTRL_DATA_T)
        return false;

    // Get DA
    if (machdr_ptr->fctl & MAC_FCTRL_TODS)
    {
        MAC_ADDR_CPY(&da, &machdr_ptr->addr3);
    }
    else
    {
        MAC_ADDR_CPY(&da, &machdr_ptr->addr1);
    }

    // Get SA
    if (machdr_ptr->fctl & MAC_FCTRL_FROMDS)
    {

        MAC_ADDR_CPY(&sa, &machdr_ptr->addr3);
    }
    else
    {
        MAC_ADDR_CPY(&sa, &machdr_ptr->addr2);
    }

    if(!(MAC_ADDR_CMP(&da, mac))) {
        return true;
    }

    return false;
}
#endif



/**
 ****************************************************************************************
 * @brief Forward a RX buffer to the networking stack.
 *
 * @param[in] buf Pointer to the RX buffer to forward
 ****************************************************************************************
 */
extern uint8_t mac_vif_index;
void fhost_rx_buf_forward(struct fhost_rx_buf_tag *buf)
{
    struct rx_info *info =&buf->info;
    uint8_t payl_offset = 0;

    //rwnx_data_dump("info", info, sizeof(struct rx_info));
    //rwnx_data_dump("payload", buf->payload, 8);

    // Check if the buffer can be forwarded as is
    if (info->flags & RX_FLAGS_IS_AMSDU_BIT)
    {
        // Packet is a A-MSDU, forward each MSDU to the networking stack
        fhost_rx_amsdu_forward((struct fhost_rx_buf_tag *)buf);
    }
    else if (info->flags & RX_FLAGS_NON_MSDU_MSK)
    {
        fhost_rx_mgmt_buf_forward(buf);
        fhost_rx_buf_free(buf);
    }
    else
    {
        uint8_t vif_idx = (info->flags & RX_FLAGS_VIF_INDEX_MSK) >> RX_FLAGS_VIF_INDEX_OFT;
        struct fhost_vif_tag *fhost_vif = fhost_env.mac2fhost_vif[vif_idx];
        if (!fhost_vif) {
            aic_dbg("%s %d(%d)\r\n", __func__, vif_idx,  mac_vif_index);
            fhost_rx_buf_free(buf);
            return;
        }
        net_if_t *net_if = &fhost_vif->net_if;

        // Data frame
        // MAC802.11 -> 802.3
        payl_offset = fhost_mac2ethernet(buf);

        struct mac_eth_hdr* ethhdr = (struct mac_eth_hdr*)((uint8_t *)buf->payload + payl_offset);
        uint8_t *ethdata = (uint8_t *)buf->payload + payl_offset + sizeof(struct mac_eth_hdr);
        #ifdef CONFIG_PING_DUMP
        if (co_ntohs(ethhdr->type) == LLC_ETHERTYPE_IP) {
            if (ethdata[9] == 0x01) {
                char ipaddr_str[44];
                uint8_t type = ethdata[20];
                uint8_t code = ethdata[21];
                sprintf(ipaddr_str, "src:%d.%d.%d.%d dst:%d.%d.%d.%d",
                    ethdata[12], ethdata[13], ethdata[14], ethdata[15],
                    ethdata[16], ethdata[17], ethdata[18], ethdata[19]);
                if ((type == 0x08) || (type == 0x00)) {
                    uint16_t sn = ethdata[27] | (ethdata[26] << 8);
                    char echo_str[16];
                    if (type == 0x08) {
                       sprintf(echo_str, "%s", "echo request");
                    } else {
                        sprintf(echo_str, "%s", "echo reply");
                    }
                    AIC_LOG_PRINTF("ICMP rx %s sn:%d, %s\n", echo_str, sn, ipaddr_str);
                } else {
                    AIC_LOG_PRINTF("ICMP rx type:%d, code:%d, %s\n", type, code, ipaddr_str);
                }
            }
        } else if (co_ntohs(ethhdr->type) == LLC_ETHERTYPE_IPV6) {
            //todo
        }
        #endif
        if (co_ntohs(ethhdr->type) == LLC_ETHERTYPE_EAP_T) {
            aic_dbg("R eapol, len %d(%ld)\r\n",  (info->vect.frmlen - payl_offset), rtos_now(0));
            net_eth_receive((uint8_t *)buf->payload + payl_offset, (info->vect.frmlen - payl_offset), net_if);
        } else {
            // Forward to the networking stack
            rx_eth_data_process((uint8_t *)buf->payload + payl_offset, info->vect.frmlen - 
                                                                payl_offset,  net_if);
        }
    }
}

/**
 ****************************************************************************************
 * @brief Call registered monitor callback for the received buffer.
 *
 * Extract useful information from RX buffer and call the monitor callback with this as
 * parameter. Returns immediately if no monitor callback is registered.
 *
 * @param[in] buf  Pointer to the RX buffer
 * @param[in] uf   Whether frame has been decoded or not by the modem.
 *                 (false: decoded frame, true: unsupported frame)
 ****************************************************************************************
 */
void fhost_rx_monitor_cb(void *buf, bool uf)
{
    struct fhost_frame_info info;
    //int8_t rx_rssi[2];

    if (fhost_rx_env.monitor_cb == NULL)
        return;

    #if NX_UF_EN
    if (uf) {
        uint8_t rx_format;
        struct rx_vector_desc *rx_vector = (struct rx_vector_desc *)buf;
        struct uf_rx_vector_1 *uf_rx_v1= (struct uf_rx_vector_1 *)(&rx_vector->rx_vec_1);
        info.payload = NULL;
        rx_format = uf_rx_v1->format_mod;
        if(2 == rx_format) { // HT
            info.length = uf_rx_v1->ht.length - 8 * uf_rx_v1->ht.aggregation;
        } else if(4 == rx_format) { // VHT
            info.length = hal_desc_get_vht_length(&rx_vector->rx_vec_1); //psdu length
        }
        info.rssi = uf_rx_v1->rssi1;
        info.freq = PHY_INFO_CHAN(rx_vector->phy_info);
    } else
    #endif /* NX_UF_EN */
    {
        struct fhost_rx_buf_tag *rx_buf = (struct fhost_rx_buf_tag *)buf;
        info.payload = (uint8_t *)rx_buf->payload;
        info.length = rx_buf->info.vect.frmlen;
        info.freq = PHY_INFO_CHAN(rx_buf->info.phy_info);
        //info.rssi = hal_desc_get_rssi(&buf->info.vect.rx_vec_1, rx_rssi);
    }

    fhost_rx_env.monitor_cb(&info, fhost_rx_env.monitor_cb_arg);
}

void fhost_rx_set_mgmt_cb(cb_fhost_rx cb, void *arg)
{
    fhost_rx_env.mgmt_cb = cb;
    fhost_rx_env.mgmt_cb_arg = arg;
}

void fhost_rx_set_monitor_cb(cb_fhost_rx cb, void *arg)
{
    fhost_rx_env.monitor_cb = cb;
    fhost_rx_env.monitor_cb_arg = arg;
}

int fhost_rx_data_resend(net_if_t *net_if, struct fhost_rx_buf_tag *buf,
                         struct mac_addr *da, struct mac_addr *sa, uint8_t machdr_len)
{
    uint8_t *frame = (uint8_t *)buf->payload;
    uint32_t statinfo = buf->info.vect.statinfo;
    struct mac_hdr *machdr_ptr = (struct mac_hdr *)frame;
    struct mac_eth_hdr *eth_hdr;
    uint8_t payl_offset = 0;
    net_buf_tx_t *net_buf;
    payl_offset = machdr_len + sizeof(struct llc_snap) - sizeof(struct mac_eth_hdr);
    net_buf = net_buf_tx_alloc(frame + payl_offset, buf->info.vect.frmlen - payl_offset);
    if (net_buf == NULL) {
        aic_dbg("net buf alloc fail\r\n");
        return -1;
    }
    // fill ether header after alloc
    eth_hdr = (struct mac_eth_hdr *)(net_buf->data_ptr);
    MAC_ADDR_CPY(&eth_hdr->da, da);
    MAC_ADDR_CPY(&eth_hdr->sa, sa);
    //eth_hdr->type = eth_type; // already exist
    //AIC_LOG_PRINTF("%s pkt %x %x, t:%x\n", __func__, net_buf, net_buf->data_ptr, net_buf->pkt_type);
    fhost_tx_start(net_if, net_buf, NULL, NULL);
    return 0;
}

#if (FHOST_RX_SW_VER == 2)
void fhost_rx_task(void *arg)
{
    AIC_LOG_PRINTF("fhost_rx_task\n");
    while (1) {
        struct fhost_rx_buf_tag *buf = NULL;
        int ret = rtos_semaphore_wait(fhost_rx_env.rxq_trigg, SCI_WAIT_FOREVER);
        AIC_LOG_PRINTF("aft rxq sema\n");
        if (ret < 0) {
            AIC_LOG_PRINTF("wait fhost rxq trigg fail: ret=%d\n", ret);
        }
        buf = (struct fhost_rx_buf_tag *)fhost_rxq_pop(&fhost_rx_env.rxq_post);
        if (buf) {
            fhost_rx_buf_forward(buf);
            fhost_rxq_push(&fhost_rx_env.rxq_free, &buf->hdr);
        } else {
            AIC_LOG_PRINTF("rxq triggered but post list empty\n");
        }
    }
}

void fhost_rx_init(void)
{
    int idx, ret;
    rtos_task_handle wlanrx_task_hdl = NULL;
    //int buf_size = (sizeof(struct fhost_rx_buf_tag)  + (FHOST_RX_BUF_ALIGN_NUM - 1)) & ~(FHOST_RX_BUF_ALIGN_NUM - 1);
    int buf_size = sizeof(struct fhost_rx_buf_tag)  + FHOST_RX_BUF_ALIGN_NUM;
    //int buf_size = 2048;
    aic_dbg("buf_size = %d\n",buf_size);
    ret = rtos_mutex_create(&fhost_rx_env.rxq_free.mutex, "fhost_rx_env.rxq_free.mutex");
    if (ret) {
        aic_dbg("fhost rxq_free mutex create fail: %d\n", ret);
        return;
    }
    aic_dbg("rxq_free init\n");
    rtos_mutex_lock(fhost_rx_env.rxq_free.mutex, -1);
    co_list_init(&fhost_rx_env.rxq_free.list);
    for (idx = 0; idx < FHOST_RX_BUF_COUNT; idx++) {
        uint8_t *buf_raw = rtos_malloc(buf_size);
        struct fhost_rx_buf_tag *buf_rx;
        if ((uint32_t)(buf_raw + offsetof(struct fhost_rx_buf_tag, info)) & (FHOST_RX_BUF_ALIGN_NUM - 1)) // not align
        {
            buf_rx = (struct fhost_rx_buf_tag *)((((uint32_t)(buf_raw + offsetof(struct fhost_rx_buf_tag, info)) +
                (FHOST_RX_BUF_ALIGN_NUM - 1)) & ~(FHOST_RX_BUF_ALIGN_NUM - 1)) - offsetof(struct fhost_rx_buf_tag, info));
            buf_rx->headroom = (uint32_t)buf_rx - (uint32_t)buf_raw;
        } else {
            buf_rx = (struct fhost_rx_buf_tag *)buf_raw;
            buf_rx->headroom = 0;
        }
        aic_dbg("addr: %p\n", &buf_rx->info);
        if ((uint32_t)buf_rx < (uint32_t)buf_raw) {
            aic_dbg("rx buf calc fail:%p,%p\n",buf_raw, buf_rx);
        }
        co_list_push_back(&fhost_rx_env.rxq_free.list, &buf_rx->hdr);
    }
    rtos_mutex_unlock(fhost_rx_env.rxq_free.mutex);
    aic_dbg("rxq_post init\n");
    ret = rtos_mutex_create(&fhost_rx_env.rxq_post.mutex, "fhost_rx_env.rxq_post.mutex");
    if (ret) {
        aic_dbg("fhost rxq_post mutex create fail: %d\n", ret);
        return;
    }
    rtos_mutex_lock(fhost_rx_env.rxq_post.mutex, -1);
    co_list_init(&fhost_rx_env.rxq_post.list);
    rtos_mutex_unlock(fhost_rx_env.rxq_post.mutex);
    fhost_rx_env.rxq_trigg = NULL;
    #ifdef CONFIG_SDIO_SUPPORT
    ret = rtos_semaphore_create(&fhost_rx_env.rxq_trigg, "fhost_rx_env.rxq_trigg", SDIO_RX_BUF_COUNT, 0);
    #endif
    if (ret) {
        aic_dbg("fhost rxq_trigg create fail: %d\n", ret);
        return;
    }
    ret = rtos_task_create(fhost_rx_task, "fhost_rx_task", FHOST_RX_TASK,
                           fhost_rx_stack_size, NULL, fhost_rx_priority,
                           &wlanrx_task_hdl);
    if (ret || (wlanrx_task_hdl == NULL)) {
        AIC_LOG_PRINTF("fhost wlanrx task create fail,%d\n",ret);
        return;
    }
}

void fhost_rx_deinit(void)
{
    struct fhost_rx_buf_tag *buf_rx = NULL;
    uint8_t *buf_raw = NULL;
    rtos_mutex_lock(fhost_rx_env.rxq_free.mutex, -1);
    do {
        buf_rx = co_list_pop_front(&fhost_rx_env.rxq_free);
        if (buf_rx == NULL) {
            break;
        }
        buf_raw = (uint32_t)buf_rx - buf_rx->headroom;
        rtos_free(buf_raw);
    } while (1);
    rtos_mutex_unlock(fhost_rx_env.rxq_free.mutex);
    rtos_mutex_delete(fhost_rx_env.rxq_free.mutex);
    rtos_mutex_lock(fhost_rx_env.rxq_post.mutex, -1);
    do {
        buf_rx = co_list_pop_front(&fhost_rx_env.rxq_post);
        if (buf_rx == NULL) {
            break;
        }
        buf_raw = (uint8_t *)buf_rx - buf_rx->headroom;
        rtos_free(buf_raw);
    } while (1);
    rtos_mutex_unlock(fhost_rx_env.rxq_post.mutex);
    rtos_mutex_delete(fhost_rx_env.rxq_post.mutex);
	if(fhost_rx_env.rxq_trigg)
	{
    	rtos_semaphore_delete(fhost_rx_env.rxq_trigg);
		fhost_rx_env.rxq_trigg = NULL;
	}
}

struct co_list_hdr *fhost_rxq_pop(fhost_rxq_t *rxq)
{
    struct co_list_hdr *hdr = NULL;
    rtos_mutex_lock(rxq->mutex, -1);
    hdr = co_list_pop_front(&rxq->list);
    rtos_mutex_unlock(rxq->mutex);
    return hdr;
}

void fhost_rxq_push(fhost_rxq_t *rxq, struct co_list_hdr *hdr)
{
    rtos_mutex_lock(rxq->mutex, -1);
    co_list_push_back(&rxq->list, hdr);
    rtos_mutex_unlock(rxq->mutex);
}
#endif /* FHOST_RX_SW_VER == 2 */

#if (FHOST_RX_SW_VER == 3)
static bool aicwf_another_ptk(uint8_t *data, uint32_t len)
{
    uint16_t aggr_len = 0;
    if (data == NULL || len == 0) {
        return false;
    }
    aggr_len = (*data | (*(data + 1) << 8));
    if (aggr_len == 0) {
        return false;
    }
    if (aggr_len > len) {
        AIC_LOG_PRINTF("%s error:%d/%d\n", __func__, aggr_len, len);
        return false;
    }
    return true;
}

#ifdef CONFIG_SDIO_SUPPORT
void fhost_rx_task(void *arg)
{
    AIC_LOG_PRINTF("fhost_rx_task\n");
    while (1) {
        struct sdio_buf_node_s *node = NULL;
        int ret = rtos_semaphore_wait(fhost_rx_env.rxq_trigg, -1);
        //AIC_LOG_PRINTF("aft rxq sema\n");

        if (ret < 0) {
            AIC_LOG_PRINTF("wait fhost rxq trigg fail: ret=%d\n", ret);
        }
        node = fhost_rxframe_dequeue();
        if (node) {
            uint8_t *buf_raw;
            uint8_t *data = node->buf;
            uint32_t len = node->buf_len;
            if (data == NULL) {
                AIC_LOG_PRINTF("err: rx data null: node=%p\n", node);
            }
            while (aicwf_another_ptk(data, len)) {
                uint16_t pkt_len = (*data | (*(data + 1) << 8));
                uint16_t aggr_len;
                if((data[2] & SDIO_TYPE_CFG) != SDIO_TYPE_CFG) { // type : data
                    struct fhost_rx_buf_tag *buf = (struct fhost_rx_buf_tag *)data;
                    //AIC_LOG_PRINTF("[task] rx data: %p, %p, %p, %d\n", rx_frame_in_process, rx_in_process_buf, buf, pkt_len);
                    //rwnx_data_dump("buffer_rx", buffer_rx, (pkt_len < 32) ? 32 : pkt_len);
                    #if (AICWF_RX_REORDER)
                    rwnx_rxdataind_aicwf(buf);
                    #else
                    fhost_rx_buf_forward(buf);
                    #endif
                    aggr_len = sizeof(struct rx_info) + pkt_len;
                    aggr_len = (aggr_len + (RX_ALIGNMENT - 1)) & ~(RX_ALIGNMENT - 1);
                } else {
                    uint8_t *msg = data;
                    uint8_t type = *(msg + 2) & 0x7f;
                    if (type == SDIO_TYPE_CFG_CMD_RSP) {
                        //AIC_LOG_PRINTF("[task] rx cmd rsp\n");
                        struct rwnx_hw *rwnx_hw = (struct rwnx_hw *)arg;
                        rwnx_rx_handle_msg(rwnx_hw, (struct e2a_msg *)(msg + 4));
                    } else if (type == SDIO_TYPE_CFG_DATA_CFM) {
                        fhost_tx_cfm_push((u32 *)(msg + 4));
                        //AIC_LOG_PRINTF("[task] rx data cfm\n");
                    } else {
                        AIC_LOG_PRINTF("unsupported type:%x\n", type);
                    }
                    aggr_len = (pkt_len + 4 + (RX_ALIGNMENT - 1)) & ~(RX_ALIGNMENT - 1);
                }
                data += aggr_len;
                len -= aggr_len;
                if ((uint32_t)(data - node->buf) > node->buf_len) {
                    AIC_LOG_PRINTF("%s len error:%d/%d\n", __func__, (uint32_t)(data - node->buf), node->buf_len);
                    break;
                }
            }
            //aic_dbg("deq:%p,%d, node:%p\n",node->buf,node->buf_len, node);
            sdio_buf_free(node);
        } else {
            AIC_LOG_PRINTF("rxq triggered but queue is empty\n");
        }

    }
}
#endif

#ifdef CONFIG_USB_SUPPORT
void fhost_rx_task(void *arg)
{
    AIC_LOG_PRINTF("fhost_rx_task\n");
    #ifdef CONFIG_FHOST_RX_TASK_TS
    uint32_t start_time = 0;
    uint32_t end_time = 0;
    static volatile uint8_t rx_count = 0;
    #endif
#ifdef CONFIG_USB_MSG_IN_EP
    static volatile uint8_t ep_type = 0; // 0: data ep, 1: msg ep
#endif
    while (1) {
        struct aicwf_usb_buf *node = NULL;
        int ret = rtos_semaphore_wait(fhost_rx_env.rxq_trigg, -1);
        #ifdef PLATFORM_SUNPLUS_ECOS
        if (fhost_rx_task_exit_flag) {
            break;
        }
        #endif
            #ifdef CONFIG_FHOST_RX_TASK_TS
            rx_count++;
            start_time = (uint32_t)rtos_now(0);
            aic_dbg("rxin:%u/%u\n", start_time, rx_count);
            #endif
            if (ret < 0) {
                AIC_LOG_PRINTF("wait fhost rxq trigg fail: ret=%d\n", ret);
            }
            node = fhost_rxframe_dequeue();
            if (node) {
                #ifdef CONFIG_FHOST_RX_ASYNC
                rx_frame_in_process = node;
                rx_frame_to_async = false;
                #endif
                struct aic_sk_buff *skb = node->skb;
                if (skb == NULL) {
                    AIC_LOG_PRINTF("err: rx skb null: node=%p\n", node);
                }
                uint8_t *data = skb->data;
                uint32_t len = skb->len;
                if (data == NULL) {
                    AIC_LOG_PRINTF("err: rx data null: node=%p\n", node);
                }
                if ((data[2] & USB_TYPE_CFG) != USB_TYPE_CFG) { // type : data
                    #ifdef CONFIG_USB_MSG_IN_EP
                    ep_type = 0;
                    #endif
                    struct fhost_rx_buf_tag *buf = (struct fhost_rx_buf_tag *)data;
                    //AIC_LOG_PRINTF("[task] rx data: %d, %d\n", data_len, pkt_len);
                    //rwnx_data_dump("buffer_rx", buffer_rx, (pkt_len < 32) ? 32 : pkt_len);
                    #if (AICWF_RX_REORDER)
                    rwnx_rxdataind_aicwf(buf);
                    #else
                    fhost_rx_buf_forward(buf);
                    #endif
                } else {
                    uint8_t *msg = data;
                    uint8_t type = *(msg + 2) & 0x7f;
                    if (type == USB_TYPE_CFG_CMD_RSP) {
                        #ifdef CONFIG_USB_MSG_IN_EP
                        ep_type = 1;
                        #endif
                        //AIC_LOG_PRINTF("[task] rx cmd rsp\n");
                        struct rwnx_hw *rwnx_hw = (struct rwnx_hw *)arg;
                        rwnx_rx_handle_msg(rwnx_hw, (struct e2a_msg *)(msg + 4));
                    } else if (type == USB_TYPE_CFG_DATA_CFM) {
                        #ifdef CONFIG_USB_MSG_IN_EP
                        ep_type = 0;
                        #endif
                        fhost_tx_cfm_push((u32 *)(msg + 4));
                        AIC_LOG_PRINTF("[task] rx data cfm\n");
                    } else {
                        AIC_LOG_PRINTF("unsupported type:%x\n", type);
                    }
                }
#ifdef CONFIG_USB_MSG_IN_EP
                if (g_aic_usb_dev->chipid != PRODUCT_ID_AIC8801 &&
                    g_aic_usb_dev->chipid != PRODUCT_ID_AIC8800D81) {
#ifdef CONFIG_FHOST_RX_ASYNC
                    if (!rx_frame_to_async) {
                        ep_type? aicwf_usb_msg_rx_buf_put(g_aic_usb_dev, node) : aicwf_usb_rx_buf_put(g_aic_usb_dev, node);
                    }
                    rx_frame_in_process = NULL;
                    rx_frame_to_async = false;
#else
                    ep_type? aicwf_usb_msg_rx_buf_put(g_aic_usb_dev, node) : aicwf_usb_rx_buf_put(g_aic_usb_dev, node);
#endif
                    ep_type? aicwf_usb_msg_rx_submit_all_urb(g_aic_usb_dev) : aicwf_usb_rx_submit_all_urb(g_aic_usb_dev);
                }
#else
#ifdef CONFIG_FHOST_RX_ASYNC
                if (!rx_frame_to_async) {
                    aicwf_usb_rx_buf_put(g_aic_usb_dev, node);
                }
                rx_frame_in_process = NULL;
                rx_frame_to_async = false;
#else
                aicwf_usb_rx_buf_put(g_aic_usb_dev, node);
#endif
                aicwf_usb_rx_submit_all_urb(g_aic_usb_dev);
#endif
            } else {
                AIC_LOG_PRINTF("rxq triggered but queue is empty\n");
            }
#ifdef CONFIG_FHOST_RX_TASK_TS
            AIC_LOG_PRINTF("rxout:%u/%u\n", end_time, rx_count);
#endif
    }
exit:
    AIC_LOG_PRINTF("Exit fhost_rx_task\r\n");
    #ifdef PLATFORM_GX_ECOS
    rtos_semaphore_signal(fhost_rx_task_exit_sem, false);
    #endif
}
#endif

void fhost_rx_init(struct rwnx_hw *rwnx_hw)
{
    int idx, ret;

    AIC_LOG_PRINTF("fhost_rx_init\n");
    ret = rtos_mutex_create(&fhost_rx_env.rxq.mutex, "fhost_rx_env.rxq.mutex");
    if (ret) {
        aic_dbg("fhost rxq mutex create fail: %d\n", ret);
        return;
    }
    co_list_init(&fhost_rx_env.rxq.list);
    #ifdef CONFIG_SDIO_SUPPORT
    ret = rtos_semaphore_create(&fhost_rx_env.rxq_trigg, "fhost_rx_env.rxq_trigg", SDIO_RX_BUF_COUNT, 0);
    #endif
    #ifdef CONFIG_USB_SUPPORT
    ret = rtos_semaphore_create(&fhost_rx_env.rxq_trigg, "fhost_rx_env.rxq_trigg", AICWF_USB_RX_URBS, 0);
    #endif
    if (ret) {
        aic_dbg("fhost rxq_trigg create fail: %d\n", ret);
        return;
    }
    if (rtos_semaphore_create(&fhost_rx_task_exit_sem, "fhost_rx_task_exit_sem", 0x7FFFFFFF, 0)) {
        AIC_LOG_PRINTF("fhost_rx_task_exit_sem create fail\n");
        return;
    }
    #ifdef CONFIG_FHOST_RX_ASYNC
    int i = 0;
    ret = rtos_mutex_create(&fhost_rx_env.rxq_async_free.mutex, "fhost_rx_env.rxq_async_free.mutex");
    if (ret) {
        aic_dbg("fhost rxq_async_free mutex create fail: %d\n", ret);
        return;
    }
    co_list_init(&fhost_rx_env.rxq_async_free.list);
    memset(&rx_async_desc_pool, 0, sizeof(rx_async_desc_pool));
    for (i = 0; i < RX_ASYNC_DESC_CNT ; i++) {
        co_list_push_back(&fhost_rx_env.rxq_async_free.list, &rx_async_desc_pool[i].hdr);
    }

    ret = rtos_mutex_create(&fhost_rx_env.rxq_async_post.mutex, "fhost_rx_env.rxq_async_post.mutex");
    if (ret) {
        aic_dbg("fhost rxq_async_post mutex create fail: %d\n", ret);
        return;
    }
    co_list_init(&fhost_rx_env.rxq_async_post.list);
    #endif

    ret = rtos_task_create(fhost_rx_task, "fhost_rx_task", FHOST_RX_TASK,
                           fhost_rx_stack_size, (void *)rwnx_hw, fhost_rx_priority,
                           &fhost_rx_task_hdl);
    if (ret || (fhost_rx_task_hdl == NULL)) {
        AIC_LOG_PRINTF("fhost wlanrx task create fail,%d\n",ret);
        return;
    }
    #if (AICWF_RX_REORDER)
    rwnx_reord_init();
    #endif
}

void fhost_rx_deinit(struct rwnx_hw *rwnx_hw)
{
    if (fhost_rx_task_hdl) {
        fhost_rx_task_exit_flag = true;
        rtos_semaphore_signal(fhost_rx_env.rxq_trigg, false);
        rtos_semaphore_wait(fhost_rx_task_exit_sem, -1);
        fhost_rx_task_exit_flag = false;
        rtos_task_delete(fhost_rx_task_hdl);
        fhost_rx_task_hdl = NULL;
    }

    #ifdef CONFIG_FHOST_RX_ASYNC
    struct fhost_rx_async_desc_tag *async_desc = NULL;

    do {
        async_desc = fhost_rx_async_post_dequeue();
        if (async_desc == NULL) {
            break;
        }
        if (async_desc->from_heap) {
            rtos_free(async_desc);
        }
    } while (1);
    rtos_mutex_delete(fhost_rx_env.rxq_async_post.mutex);

    rtos_mutex_lock(fhost_rx_env.rxq_async_free.mutex, -1);
    struct fhost_rx_async_desc_tag *desc = NULL;
    do {
        desc = (struct fhost_rx_async_desc_tag *)co_list_pop_front(&fhost_rx_env.rxq_async_free.list);
        if (desc == NULL) {
            break;
        }
        if (desc->from_heap) {
            rtos_free(desc);
        }
    } while (1);
    rtos_mutex_unlock(fhost_rx_env.rxq_async_free.mutex);
    rtos_mutex_delete(fhost_rx_env.rxq_async_free.mutex);
    #endif
#ifdef CONFIG_USB_SUPPORT
    struct aicwf_usb_buf *usb_buf = NULL;
#else
	struct sdio_buf_node_s *node;
#endif
    do {
#ifdef CONFIG_USB_SUPPORT
        usb_buf = fhost_rxframe_dequeue();
        if (usb_buf == NULL) {
            break;
        }
        if (usb_buf->urb) {
            usb_free_urb(usb_buf->urb);
            usb_buf->urb = NULL;
        } else {
            AIC_LOG_PRINTF("%s urb null\n", __func__);
        }
        if (usb_buf->skb) {
            aic_dev_kfree_skb_any(usb_buf->skb);
            usb_buf->skb = NULL;
        } else {
            AIC_LOG_PRINTF("%s skb null\n", __func__);
        }
#else
        node = fhost_rxframe_dequeue();
        if (node) {
            sdio_buf_free(node);
            node = NULL;
        } else
            break;
#endif
    } while (1);
    if (fhost_rx_task_exit_sem) {
        rtos_semaphore_delete(fhost_rx_task_exit_sem);
		fhost_rx_task_exit_sem = NULL;
    }
    if (fhost_rx_env.rxq_trigg) {
        rtos_semaphore_delete(fhost_rx_env.rxq_trigg);
		fhost_rx_env.rxq_trigg = NULL;
    }
    rtos_mutex_delete(fhost_rx_env.rxq.mutex);
    #if (AICWF_RX_REORDER)
    rwnx_reord_deinit();
    #endif
}

#ifdef CONFIG_SDIO_SUPPORT
struct sdio_buf_node_s * fhost_rxframe_dequeue(void)
{
    struct sdio_buf_node_s *node;
    //rtos_mutex_lock(fhost_rx_env.rxq.mutex, -1);
    rtos_entercritical();
    node = (struct sdio_buf_node_s *)co_list_pop_front(&fhost_rx_env.rxq.list);
    //printf("de: %d, time: %d\n", co_list_cnt(&fhost_rx_env.rxq.list), rtos_now(false));
    ///rtos_mutex_unlock(fhost_rx_env.rxq.mutex);
    rtos_exitcritical();
    return node;
}

void fhost_rxframe_enqueue(struct sdio_buf_node_s *node)
{
    //rtos_mutex_lock(fhost_rx_env.rxq.mutex, -1);
    rtos_entercritical();
    co_list_push_back(&fhost_rx_env.rxq.list, &node->hdr);
    //printf("en: %d, time: %d\n", co_list_cnt(&fhost_rx_env.rxq.list), rtos_now(false));
    //rtos_mutex_unlock(fhost_rx_env.rxq.mutex);
    rtos_exitcritical();
}
#endif

#ifdef CONFIG_USB_SUPPORT
struct aicwf_usb_buf * fhost_rxframe_dequeue(void)
{
    struct aicwf_usb_buf *node;
    //rtos_mutex_lock(fhost_rx_env.rxq.mutex, -1);
    rtos_entercritical();
    node = (struct aicwf_usb_buf *)co_list_pop_front(&fhost_rx_env.rxq.list);
    //printf("de: %d, time: %d\n", co_list_cnt(&fhost_rx_env.rxq.list), rtos_now(false));
    //rtos_mutex_unlock(fhost_rx_env.rxq.mutex);
    rtos_exitcritical();
    return node;
}

void fhost_rxframe_enqueue(struct aicwf_usb_buf *node)
{
    //rtos_mutex_lock(fhost_rx_env.rxq.mutex, -1);
    rtos_entercritical();
    co_list_push_back(&fhost_rx_env.rxq.list, &node->hdr);
    //printf("en: %d, time: %d\n", co_list_cnt(&fhost_rx_env.rxq.list), rtos_now(false));
    //rtos_mutex_unlock(fhost_rx_env.rxq.mutex);
    rtos_exitcritical();
}
#endif

#ifdef CONFIG_FHOST_RX_ASYNC
struct fhost_rx_async_desc_tag * fhost_rx_async_desc_alloc(void)
{
    bool from_heap = false;
    struct fhost_rx_async_desc_tag *desc;
    rtos_mutex_lock(fhost_rx_env.rxq_async_free.mutex, -1);
    //rtos_entercritical();
    desc = (struct fhost_rx_async_desc_tag *)co_list_pop_front(&fhost_rx_env.rxq_async_free.list);
    rtos_mutex_unlock(fhost_rx_env.rxq_async_free.mutex);
    //rtos_exitcritical();

    if (desc == NULL) {
        desc = rtos_malloc(sizeof(struct fhost_rx_async_desc_tag));
        if (desc) {
            from_heap = true;
        }
    }

    if (desc) {
        memset(desc, 0, sizeof(struct fhost_rx_async_desc_tag));
        desc->from_heap = from_heap;
    }

    return desc;
}

void fhost_rx_async_desc_free(struct fhost_rx_async_desc_tag *desc)
{
    if (!desc->from_heap) {
        rtos_mutex_lock(fhost_rx_env.rxq_async_free.mutex, -1);
        //rtos_entercritical();
        co_list_push_back(&fhost_rx_env.rxq_async_free.list, &desc->hdr);
        rtos_mutex_unlock(fhost_rx_env.rxq_async_free.mutex);
        //rtos_exitcritical();
    } else {
        rtos_free(desc);
    }
}

struct fhost_rx_async_desc_tag * fhost_rx_async_post_dequeue(void)
{
    struct fhost_rx_async_desc_tag *desc;
    rtos_mutex_lock(fhost_rx_env.rxq_async_post.mutex, -1);
    //rtos_entercritical();
    desc = (struct fhost_rx_async_desc_tag *)co_list_pop_front(&fhost_rx_env.rxq_async_post.list);
    rtos_mutex_unlock(fhost_rx_env.rxq_async_post.mutex);
    //rtos_exitcritical();

    return desc;
}

void fhost_rx_async_post_enqueue(struct fhost_rx_async_desc_tag *desc)
{
    rtos_mutex_lock(fhost_rx_env.rxq_async_post.mutex, -1);
    //rtos_entercritical();
    co_list_push_back(&fhost_rx_env.rxq_async_post.list, &desc->hdr);
    rtos_mutex_unlock(fhost_rx_env.rxq_async_post.mutex);
    //rtos_exitcritical();
}

uint32_t fhost_rx_async_post_cnt(bool lock)
{
    uint32_t cnt;

    if (lock) {
        rtos_mutex_lock(fhost_rx_env.rxq_async_post.mutex, -1);
        //rtos_entercritical();
    }

    cnt = co_list_cnt(&fhost_rx_env.rxq_async_post.list);

    if (lock) {
        rtos_mutex_unlock(fhost_rx_env.rxq_async_post.mutex);
        //rtos_exitcritical();
    }

    return cnt;
}

void *fhost_rx_frame_in_process_get(void)
{
    return (void *)rx_frame_in_process;
}

#ifdef CONFIG_REORD_FORWARD_LIST
void *fhost_rx_frame_match(struct fhost_rx_buf_tag *buf)
{
    void *frame = NULL;
#ifdef CONFIG_USB_SUPPORT
    if (rx_frame_in_process) {
        struct fhost_rx_buf_tag *buf_in_process = (struct fhost_rx_buf_tag *)rx_frame_in_process->skb->data;
        if (buf_in_process == buf) {
            frame = rx_frame_in_process;
        }
    }
#elif CONFIG_SDIO_SUPPORT
    if (rx_in_process_buf) {
        if (buf == rx_in_process_buf) {
            frame = rx_in_process_buf;
        }
    }
#endif
    return frame;
}
#else
bool fhost_rx_frame_match(struct fhost_rx_buf_tag *buf, struct fhost_rx_async_desc_tag *desc)
{
    bool match = false;

    if (rx_frame_in_process) {
        #ifdef CONFIG_USB_SUPPORT
        struct fhost_rx_buf_tag *buf_in_process = (struct fhost_rx_buf_tag *)rx_frame_in_process->skb->data;
        if (buf_in_process == buf) {
            match = true;
            rx_frame_to_async = true;
            desc->frame_ptr = (void *)rx_frame_in_process;
            desc->frame_type = RX_ASYNC_RX_FRAME;
        }
        #elif CONFIG_SDIO_SUPPORT
        struct fhost_rx_buf_tag *buf_in_process = (struct fhost_rx_buf_tag *)rx_frame_in_process->buf;
        if (buf_in_process == buf) {
            match = true;
            rx_frame_to_async = true;
            desc->frame_ptr = (void *)rx_frame_in_process;
            desc->frame_type = RX_ASYNC_RX_FRAME;
        }
        #endif
    }

    return match;
}
#endif
#endif

#endif

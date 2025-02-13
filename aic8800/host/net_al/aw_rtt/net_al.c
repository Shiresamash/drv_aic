/*
 * Copyright (C) 2018-2020 AICSemi Ltd.
 *
 * All Rights Reserved
 */

/*
 * INCLUDE FILES
 ****************************************************************************************
 */
#ifdef PLATFORM_ALLWIN_RT_THREAD
#include <rtthread.h>
#include "lwip/netifapi.h"
#include "lwip/etharp.h"
#include "lwip/dns.h"
#endif
#include "fhost_tx.h"
#include "fhost_rx.h"
#include "fhost_cntrl.h"
#include "fhost_config.h"
#include "tx_swdesc.h"
#include "rtos_al.h"
#include "net_al.h"
#include "aic_log.h"
#include "wifi.h"
#include "rwnx_utils.h"
#ifdef CONFIG_USB_SUPPORT
#include "usb_port.h"
#endif

#define NX_NB_L2_FILTER 2

struct l2_filter_tag
{
    net_if_t *net_if;
    int sock;
    struct fhost_cntrl_link *link;
    uint16_t ethertype;
};

static struct l2_filter_tag l2_filter[NX_NB_L2_FILTER] = {0};
static rtos_semaphore l2_semaphore;
static rtos_mutex     l2_mutex;

#define ERR_BUF (-1)
#define ERR_OK (0)

struct net_tx_buf_tag
{
    /// Chained list element
    struct co_list_hdr hdr;
    TCPIP_PACKET_INFO_T pkt_hdr;
    uint8_t buf[1600];
};

#define NET_TXBUF_CNT 40//28
/// List element for the free TX buf
struct co_list net_tx_buf_free_list;
static rtos_mutex net_tx_buf_mutex;
static rtos_semaphore net_tx_buf_sema;
static bool net_inited = false;

#if defined PLATFORM_ALLWIN_RT_THREAD
static uint8_t *deliver_buf = NULL;
static uint32_t deliver_len = 0;
#endif

/*
 * FUNCTIONS
 ****************************************************************************************
 */

#if 1
#ifdef DUMP_HEX_DATA
#define DHCP_MESSAGE_TYPE_OFFSET 0x11A

static void dump_hex_data(void* ptr, int len, char* name)
{
    unsigned char *data = ((unsigned char*)ptr);
    u8_t* options = (u8_t*)ptr;
    const struct ip_hdr *iphdr;
    iphdr = (struct ip_hdr *)data;
    int i;

    //printf("\n[%s] TYPE[%02x], OP[%02x]\n", name, options[DHCP_MESSAGE_TYPE_OFFSET], options[
DHCP_MESSAGE_TYPE_OFFSET + 2]);
    printf("[Eth %s] \r\n[%04d]\n", name, len);

    for(i=0; i < len; i++)
    {
        if(!(i % 0x10))
            printf("\n");

        printf("%02x ", data[i]);
    }
    printf("\n\n");
}
#endif

void ethernetif_recv(struct netif *netif, int total_len)
{
    int errcode;
    struct eth_drv_sg sg_list[MAX_ETH_DRV_SG];
    struct pbuf *p, *q;
    int sg_len = 0;

    if ((total_len > MAX_ETH_MSG) || (total_len < 0))
        total_len = MAX_ETH_MSG;
    // Allocate buffer to store received packet
    p = pbuf_alloc(PBUF_RAW, total_len, PBUF_RAM);
    if (p == NULL)
    {
        printf("\n\rCannot allocate pbuf to receive packet,l%d.\n", __LINE__);
        return;
    }
    // Create scatter list
    for (q = p; q != NULL && sg_len < MAX_ETH_DRV_SG; q = q->next)
    {
        sg_list[sg_len].buf = (unsigned int)(unsigned long)q->payload;
        sg_list[sg_len++].len = q->len;
	}

    // Copy received packet to scatter list from wrapper rx skb
	AIC8800_rtos_deliver(sg_list, sg_len);

#if DUMP_RCV_DATA
    dump_hex_data((void *)p->payload, p->tot_len, "Recv pbuf");
#endif

    // Pass received packet to the interface
    errcode = netif->input(p, netif);
    if (ERR_OK != errcode)
    {
        printf("netif->input error.code=%d.\n", errcode);
        pbuf_free(p);
    }
}

/**
 ****************************************************************************************
 * @brief Callback used by the networking stack to push a buffer for transmission by the
 * WiFi interface.
 *
 * @param[in] net_if Pointer to the network interface on which the TX is done
 * @param[in] p_buf  Pointer to the buffer to transmit
 *
 * @return ERR_OK upon successful pushing of the buffer, ERR_BUF otherwise
 ****************************************************************************************
 */
static err_t net_if_output(net_if_t *net_if, struct pbuf *p_buf)
{
    struct pbuf *q;
    unsigned char *ptr;
    struct eth_hdr *ethhdr;
    struct eth_drv_sg sg_list[MAX_ETH_DRV_SG];
    int sg_len = 0;

    if (!netif_is_up(net_if)) {
        printf("net_if_output error ERR_IF \n");
        return ERR_IF;
    }

    for (q = p_buf; q != NULL && sg_len < MAX_ETH_DRV_SG; q = q->next)
    {
        sg_list[sg_len].buf = (unsigned int)(unsigned long)q->payload;
        sg_list[sg_len++].len = q->len;
    }

#if DUMP_XMT_DATA
          dump_hex_data((void *)p_buf->payload, p_buf->tot_len, "Xmit pbuf");
#endif
    if (sg_len)
        AIC8800_rtos_send(sg_list, sg_len, p_buf->tot_len);

    return ERR_OK;
    #if 0
	net_buf_tx_t *net_buf;
    err_t status = ERR_BUF;

    net_buf = net_buf_tx_alloc(p_buf->payload, p_buf->len);
    if (net_buf == NULL)
        goto out;
//print_hex_dump_bytes(net_buf->data_ptr, net_buf->data_len);
    // Push the buffer and verify the status
    if (netif_is_up(net_if) && fhost_tx_start(net_if, net_buf, NULL, NULL) == 0)
    {
        status = ERR_OK;
    }

out:
	pbuf_free(p_buf);

    return (status);
    #endif
}
#endif
static char netif_num = 0;
/**
 ****************************************************************************************
 * @brief Callback used by the networking stack to setup the network interface.
 * This function should be passed as a parameter to netifapi_netif_add().
 *
 * @param[in] net_if Pointer to the network interface to setup
 * @param[in] p_buf  Pointer to the buffer to transmit
 *
 * @return ERR_OK upon successful setup of the interface, other status otherwise
 ****************************************************************************************
 */
err_t net_if_init(net_if_t *net_if)
{
    err_t status = ERR_OK;
    struct fhost_vif_tag *vif;

    //net_if->vif = &fhost_env.vif[0];
#if LWIP_NETIF_HOSTNAME
    /* Initialize interface hostname */
    net_if->hostname = "AicWlan";
#endif
    net_if->name[ 0 ] = 'w';
    net_if->name[ 1 ] = 'l';

    vif = &fhost_env.vif[0];

    #if 1
    net_if->output = etharp_output;
    net_if->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_IGMP;
    net_if->hwaddr_len = ETHARP_HWADDR_LEN;
    net_if->mtu = LLC_ETHER_MTU;
    net_if->linkoutput = net_if_output;
    #endif
    memcpy(&vif->mac_addr, get_mac_address(), 6);
    memcpy(net_if->hwaddr, &vif->mac_addr, 6);

    return status;
}

int net_if_add(net_if_t *net_if,
               const uint32_t *ipaddr,
               const uint32_t *netmask,
               const uint32_t *gw,
               struct fhost_vif_tag *vif)
{
    err_t status;

    #if 1
    status = netifapi_netif_add(net_if,
                               (const ip4_addr_t *)ipaddr,
                               (const ip4_addr_t *)netmask,
                               (const ip4_addr_t *)gw,
                               vif,
                               net_if_init,
                               tcpip_input);
    #endif
    net_if->num  = netif_num++;

	AIC_LOG_PRINTF("net_if_add %s return %d\n", net_if->name, status);
    return (status == ERR_OK ? 0 : -1);
}
//uint16_t net_ip_chksum(const void *dataptr, int len)
//{
//    // Simply call the LwIP function
//    //return lwip_standard_chksum(dataptr, len);
//}

const uint8_t *net_if_get_mac_addr(net_if_t *net_if)
{
    return (uint8_t *)net_if->hwaddr;
}

net_if_t *net_if_find_from_name(const char *name)
{
    return netif_find(name);
}

net_if_t *net_if_find_from_wifi_idx(unsigned int idx)
{
    if ((idx >= NX_VIRT_DEV_MAX) || (fhost_env.vif[idx].mac_vif == NULL))
        return NULL;


    if (fhost_env.vif[idx].mac_vif->type != VIF_UNKNOWN)
    {
        return &fhost_env.vif[idx].net_if;
    }

    return NULL;
}

int net_if_get_name(net_if_t *net_if, char *buf, int len)
{
    if (len > 0)
        buf[0] = net_if->name[0];
    if (len > 1)
        buf[1] = net_if->name[1];
    if (len > 2)
        buf[2] = net_if->num + '0';
    if ( len > 3)
        buf[3] = '\0';

    return 3;
}

int net_if_get_wifi_idx(net_if_t *net_if)
{
    struct fhost_vif_tag *vif;
    int idx;

    if (!net_if)
        return -1;

    vif = (struct fhost_vif_tag *)net_if;
    idx = CO_GET_INDEX(vif, fhost_env.vif);

    /* sanity check */
    if (&fhost_env.vif[idx].net_if == net_if)
        return idx;

    return -1;
}

void net_if_up(net_if_t *net_if)
{
    netifapi_netif_set_up(net_if);
}

void net_if_down(net_if_t *net_if)
{
    netifapi_netif_set_down(net_if);
}

void net_if_set_default(net_if_t *net_if)
{
    netifapi_netif_set_default(net_if);
}

void net_if_set_ip(net_if_t *net_if, uint32_t ip, uint32_t mask, uint32_t gw)
{
    if (!net_if)
        return;
    netif_set_addr(net_if, (const ip4_addr_t *)&ip, (const ip4_addr_t *)&mask,
                   (const ip4_addr_t *)&gw);
}

int net_if_get_ip(net_if_t *net_if, uint32_t *ip, uint32_t *mask, uint32_t *gw)
{
    if (!net_if)
        return -1;
#if 1
    if (ip)
        *ip = netif_ip4_addr(net_if)->addr;
    if (mask)
        *mask = netif_ip4_netmask(net_if)->addr;
    if (gw)
        *gw = netif_ip4_gw(net_if)->addr;
#endif
    return 0;
}

int net_if_input(net_buf_rx_t *buf, net_if_t *net_if, void *addr, uint16_t len, net_buf_free_fn free_fn)
{
    struct pbuf* p;
    AIC_LOG_ERROR("%s\n", __func__);
#if 0
    buf->custom_free_function = (pbuf_free_custom_fn)free_fn;
    p = pbuf_alloced_custom(PBUF_RAW, len, PBUF_REF, buf, addr, len);
    ASSERT_ERR(p != NULL);

    if (net_if->input(p, net_if))
    {
        free_fn(buf);
        return -1;
    }
#endif
    return 0;
}

struct fhost_vif_tag *net_if_vif_info(net_if_t *net_if)
{
    return (&fhost_env.vif[0]);
}

net_buf_tx_t *net_buf_tx_alloc(const uint8_t *payload, uint32_t length)
{
    unsigned int reserved_len = SDIO_HOSTDESC_SIZE;
    net_buf_tx_t *buf = rtos_malloc(CO_ALIGN4_HI(sizeof(net_buf_tx_t)) + CO_ALIGN4_HI(length + reserved_len));
    if(!buf) {
        AIC_LOG_ERROR("%s tx buffer null\n", __func__);
        return NULL;
    }
    memset(buf, 0, (sizeof(net_buf_tx_t)));
    uint8_t *payload_buf = (uint8_t *)buf + CO_ALIGN4_HI(sizeof(net_buf_tx_t));
    memcpy((payload_buf + reserved_len), payload, length);
    buf->data_ptr = (payload_buf + reserved_len);
    buf->data_len = length;
    buf->pkt_type = 0xFF;

    //AIC_LOG_PRINTF("%s tcpip %p _buf %p %p\n", __func__, buf, payload_buf, buf->data_ptr);
    //AIC_LOG_PRINTF("nbta:%p/%p\n", buf, buf->data_ptr);

    return buf;
}

void net_buf_tx_info(net_buf_tx_t *buf, uint16_t *tot_len, uint8_t *seg_cnt)
{
    #if 0
    uint8_t  idx;
    uint16_t length = buf->tot_len;

    *tot_len = length;

    idx = 0;
    while (length && buf)
    {
        // Sanity check - the payload shall be in shared RAM
        //ASSERT_ERR(!TST_SHRAM_PTR(buf->payload));

        length -= buf->len;
        idx++;
        // Get info of extra segments if any
        buf = buf->next;
    }

    *seg_cnt = idx;
    if (length != 0)
    {
        // The complete buffer must be included in all the segments
        ASSERT_ERR(0);
    }
    #endif
    *tot_len = buf->data_len;
    *seg_cnt = 1;
}

void net_buf_tx_free(net_buf_tx_t *buf)
{
    if (!buf) {
        return ;
    }
    //AIC_LOG_PRINTF("%s tcpip %x %x %x\n", __func__, buf, buf->data_ptr, buf->pkt_type);
    if (0xFF == buf->pkt_type) {
        //AIC_LOG_PRINTF("nbtf:%p/%p\n", buf, buf->data_ptr);
        rtos_free(buf);
        buf = NULL;
    } else {
        //buf->data_ptr -= (offsetof(struct hostdesc, cfm_cb));
        //buf->data_ptr -= sizeof(struct co_list_hdr);
        uint8_t *list_hdr = (uint8_t *)buf;
        list_hdr -= sizeof(struct co_list_hdr);
        //AIC_LOG_PRINTF("%s buf %x, net_buf %x\n", __func__, list_hdr, buf->data_ptr);

        rtos_mutex_lock(net_tx_buf_mutex, -1);
        co_list_push_back(&net_tx_buf_free_list, (struct co_list_hdr *)(list_hdr));
        rtos_mutex_unlock(net_tx_buf_mutex);
        rtos_semaphore_signal(net_tx_buf_sema, 0);
    }
}

uint32_t net_buf_tx_cnt(void) {
    rtos_mutex_lock(net_tx_buf_mutex, -1);
    uint32_t cnt = co_list_cnt(&net_tx_buf_free_list);
    rtos_mutex_unlock(net_tx_buf_mutex);
    return cnt;
}

int net_init(void)
{
    if (rtos_semaphore_create(&l2_semaphore, "l2_semaphore", 1, 0))
    {
        ASSERT_ERR(0);
    }

    if (rtos_mutex_create(&l2_mutex, "l2_mutex"))
    {
        ASSERT_ERR(0);
    }
    // Initial free tx buf
    co_list_init(&net_tx_buf_free_list);
    if (rtos_semaphore_create(&net_tx_buf_sema, "net_tx_buf_sema", NET_TXBUF_CNT, 0)) {
        ASSERT_ERR(0);
    }
    uint8_t i;
    for(i = 0; i < NET_TXBUF_CNT; i++)
    {
        struct net_tx_buf_tag *net_tx_buffer = rtos_malloc(sizeof(struct net_tx_buf_tag));
        if(net_tx_buffer) {
            //AIC_LOG_PRINTF("%s net_buf %d %x\n", __func__, i, (net_tx_buffer));
            co_list_push_back(&net_tx_buf_free_list, (struct co_list_hdr *)(net_tx_buffer));
            rtos_semaphore_signal(net_tx_buf_sema, 0);
        }
    }
    AIC_LOG_PRINTF("net_tx_buf_sema initial count:%d\n", rtos_semaphore_get_count(net_tx_buf_sema));
    if (rtos_mutex_create(&net_tx_buf_mutex, "net_tx_buf_mutex"))
    {
        ASSERT_ERR(0);
    }

    return 0;
}

int net_deinit(void)
{
    if (l2_semaphore) {
        rtos_semaphore_delete(l2_semaphore);
        l2_semaphore = NULL;
    }
    if(l2_mutex) {
        rtos_mutex_delete(l2_mutex);
        l2_mutex = NULL;
    }

    if (net_tx_buf_sema) {
        rtos_semaphore_delete(net_tx_buf_sema);
        net_tx_buf_sema = NULL;
    }
    if (net_tx_buf_mutex) {
        rtos_mutex_lock(net_tx_buf_mutex, -1);
        struct net_tx_buf_tag *net_tx_buffer = co_list_pop_front(&net_tx_buf_free_list);
        while (net_tx_buffer) {
            rtos_free(net_tx_buffer);
            net_tx_buffer = co_list_pop_front(&net_tx_buf_free_list);
        }
       rtos_mutex_unlock(net_tx_buf_mutex);
       //printf("fl.f: %p\n", net_tx_buf_free_list.first);
       //printf("fl.fn: %p\n", net_tx_buf_free_list.first->next);
       rtos_mutex_delete(net_tx_buf_mutex);
       net_tx_buf_mutex = NULL;
    }

    return 0;
}
extern
    void print_hex_dump_bytes(const void *addr, unsigned int len);

extern struct rwnx_hw *cntrl_rwnx_hw;
int rx_eth_data_process(unsigned char *pdata,
                     unsigned short len, net_if_t *netif)
{
    #if 1
    struct pbuf* p;

    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p != NULL) {
        memcpy(p->payload, pdata, len);
        //print_hex_dump_bytes(pdata, len);
        if (netif->input(p, netif) != ERR_OK) {
          pbuf_free(p);
        }
    }
    #else
    //if (fhost_rx_async_post_cnt(true) > 0) {
        int fhost_vif_idx = 0;
       	ethernetif_recv(&fhost_env.vif[fhost_vif_idx].net_if, len); 
   // }
    #endif
    return 0;
}

static void net_l2_send_cfm(uint32_t frame_id, bool acknowledged, void *arg)
{
    if (arg)
        *((bool *)arg) = acknowledged;
    rtos_semaphore_signal(l2_semaphore, false);
}

int net_l2_send(net_if_t *net_if, const uint8_t *data, int data_len, uint16_t ethertype,
                const uint8_t *dst_addr, bool *ack)
{
    int res;

    net_buf_tx_t *net_buf;

    if (net_if == NULL || data == NULL /* || data_len >= net_if->mtu || !netif_is_up(net_if) */)
        return -1;

    net_buf = net_buf_tx_alloc((data - sizeof(struct mac_eth_hdr)), (data_len + sizeof(struct mac_eth_hdr)));
    if (net_buf == NULL)
        return 0;

    if (dst_addr)
    {
        // Need to add ethernet header as fhost_tx_start is called directly
        struct mac_eth_hdr* ethhdr;
        ethhdr = (struct mac_eth_hdr*)net_buf->data_ptr;
        ethhdr->type = htons(ethertype);
        memcpy(&ethhdr->da, dst_addr, 6);
        memcpy(&ethhdr->sa, net_if->hwaddr, 6);
    }
//print_hex_dump_bytes(net_buf->data_ptr, net_buf->data_len);

    // Ensure no other thread will program a L2 transmission while this one is waiting
    // for its confirmation
    rtos_mutex_lock(l2_mutex, -1);

    //AIC_LOG_PRINTF("%s pkt %x %x, t:%x\n", __func__, net_buf, net_buf->data_ptr, net_buf->pkt_type);
    // In order to implement this function as blocking until the completion of the frame
    // transmission, directly call fhost_tx_start with a confirmation callback.
    res = fhost_tx_start(net_if, net_buf, net_l2_send_cfm, ack);

    // Wait for the transmission completion
    rtos_semaphore_wait(l2_semaphore, -1);

    // Now new L2 transmissions are possible
    rtos_mutex_unlock(l2_mutex);

    return res;
}

int net_l2_socket_create(net_if_t *net_if, uint16_t ethertype)
{
    struct l2_filter_tag *filter = NULL;
    int i;
    struct fhost_cntrl_link *link;

    /* First find free filter and check that socket for this ethertype/net_if couple
       doesn't already exists */
    for (i = 0; i < NX_NB_L2_FILTER; i++)
    {
        if ((l2_filter[i].net_if == net_if) &&
            (l2_filter[i].ethertype == ethertype))
        {
            return -1;
        }
        else if ((filter == NULL) && (l2_filter[i].net_if == NULL))
        {
            filter = &l2_filter[i];
        }
    }

    if (!filter)
        return -1;
    // Open link with cntrl task to send cfgrwnx commands and retrieve events
    link = fhost_cntrl_cfgrwnx_link_open();
    if (link == NULL)
        return -1;

    filter->link = link;
    filter->sock = link->sock_recv;
    if (filter->sock == -1)
        return -1;

    filter->net_if = net_if;
    filter->ethertype = ethertype;

    return filter->sock;
}

int net_l2_socket_delete(int sock)
{
    int i;
    for (i = 0; i < NX_NB_L2_FILTER; i++)
    {
        if ((l2_filter[i].net_if != NULL) &&
            (l2_filter[i].sock == sock))
        {
            l2_filter[i].net_if = NULL;
            fhost_cntrl_cfgrwnx_link_close(l2_filter[i].link);
            l2_filter[i].sock = -1;
            return 0;
        }
    }

    return -1;
}

err_t net_eth_receive(unsigned char *pdata, unsigned short len, net_if_t *netif)
{
    struct l2_filter_tag *filter = NULL;
    struct mac_eth_hdr* ethhdr = (struct mac_eth_hdr*)pdata;
    uint16_t ethertype = ntohs(ethhdr->type);
    int i;

    for (i = 0; i < NX_NB_L2_FILTER; i++)
    {
        if ((l2_filter[i].net_if == netif) &&
            (l2_filter[i].ethertype == ethertype))
        {
            filter = &l2_filter[i];
            break;
        }
    }

    if (!filter)
        return -1;

    if (send(filter->link->sock_send, pdata, len, 0) < 0)
    {
        AIC_LOG_PRINTF("Err: %s len %d\n", __func__, len);
        return -1;
    }

    return ERR_OK;
}

static int net_dhcp_started = 0;
int net_dhcp_start(int net_id)
{
    int ret = 0;
    return ret;
}

void net_dhcp_stop(net_if_t *net_if)
{
    #if LWIP_IPV4 && LWIP_DHCP
    netifapi_dhcp_stop(net_if);
    net_dhcp_started = 0;
    #endif //LWIP_IPV4 && LWIP_DHCP
}

int net_dhcp_start_status(void)
{
    return net_dhcp_started;
}

int net_dhcp_release(net_if_t *net_if)
{
    #if LWIP_IPV4 && LWIP_DHCP
    if (netifapi_dhcp_release(net_if) ==  ERR_OK)
        return 0;
    #endif //LWIP_IPV4 && LWIP_DHCP
    return -1;
}

int net_dhcp_address_obtained(net_if_t *net_if)
{
    #if LWIP_IPV4 && LWIP_DHCP
    if (dhcp_supplied_address(net_if))
        return 0;
    #endif //LWIP_IPV4 && LWIP_DHCP
    return -1;
}

int net_set_dns(uint32_t dns_server)
{
    #if LWIP_DNS
    ip_addr_t ip;
    ip_addr_set_ip4_u32(&ip, dns_server);
    dns_setserver(0, &ip);
    return 0;
    #else
    return -1;
    #endif
}

int net_get_dns(uint32_t *dns_server)
{
    #if LWIP_DNS
    const ip_addr_t *ip;

    if (dns_server == NULL)
        return -1;

    ip = dns_getserver(0);
    *dns_server = ip_addr_get_ip4_u32(ip);
    return 0;
    #else
    return -1;
    #endif
}

char* aic_inet_ntoa(struct in_addr addr)
{
  	return inet_ntoa(addr);
}

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

struct	ether_header {
	u_char	ether_dhost[ETHER_ADDR_LEN];
	u_char	ether_shost[ETHER_ADDR_LEN];
	u_short	ether_type;
} __attribute__ ((aligned(1), packed));

void AIC8800_rtos_send(struct eth_drv_sg *sg_list, int sg_len, int total_len)
{
    //aic_dbg("%s %p %d %d\n", __func__, sg_list, sg_len, total_len);
    #ifdef CONFIG_ECOS_SEND_TS
    uint32_t start_time = 0;
    uint32_t end_time = 0;
    static volatile uint8_t send_count = 0;
    #endif

    #ifdef CONFIG_ECOS_SEND_TS
    send_count++;
    start_time = rtos_now(false);
    #endif

    uint32_t offset = 0;

    //aic_dbg("es:%d\n", len);
    //aic_dbg("es:%d %d %d\n", len, id, priority);
    //aic_dbg("es:%d %s %d\n", len, info.name, info.cur_pri);
    #ifdef CONFIG_ECOS_SEND_TS
    aic_dbg("esin:%u/%u/%u\n", start_time, send_count, priority);
    #endif

    TCPIP_PACKET_INFO_T *sent_pkt;
    struct fhost_vif_tag *fhost_vif;
    fhost_vif = &fhost_env.vif[0];

    if (!net_tx_buf_sema)
        return ;
 
    uint32_t reserved_len = SDIO_HOSTDESC_SIZE;
    int ret = rtos_semaphore_wait(net_tx_buf_sema, 100);
    struct net_tx_buf_tag *tx_buf = NULL;
    if (ret == 0) {
        rtos_mutex_lock(net_tx_buf_mutex, -1);
        //printf("fl.f: %p\n", net_tx_buf_free_list.first);
        //printf("fl.fn: %p\n", net_tx_buf_free_list.first->next);
        tx_buf = (struct net_tx_buf_tag *)co_list_pop_front(&net_tx_buf_free_list);
        rtos_mutex_unlock(net_tx_buf_mutex);
    }
    if (!tx_buf) {
        aic_dbg("%s get buf fail, ret = %d\n", __func__, ret);
        return;
    }

    uint8_t *buf = tx_buf->buf + reserved_len;

    if (sg_list && (sg_len > 0)) {
        while (sg_len > 0) {
            //aic_dbg("sg:%d\n", sg_list->len);
            memcpy((void *)(unsigned long)(buf + offset), (void *)(unsigned long)sg_list->buf, sg_list->len);
            offset += sg_list->len;
            sg_list++;
            sg_len--;
        }
    }

    #ifdef CONFIG_ECOS_SEND_TCP_PARSE
    struct ether_header *ehdr = (struct ether_header *)buf;
    if (ntohs(ehdr->ether_type) == ETHERTYPE_IP) {
        struct ip *ihdr = (struct ip *)(buf + sizeof(struct ether_header));
        if (ihdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *thdr = (struct tcphdr *)(buf + sizeof(struct ether_header) + ihdr->ip_hl * 4);
            //aic_dbg("tx:%u %u %u\n", ntohl(thdr->th_seq), ntohl(thdr->th_ack), ntohs(thdr->th_win));
            aic_dbg("tx:%u %u\n", ntohl(thdr->th_seq), ntohl(thdr->th_ack));
        }
    }
    #endif

    sent_pkt = (TCPIP_PACKET_INFO_T *)&(tx_buf->pkt_hdr);
    sent_pkt->data_ptr = tx_buf->buf + reserved_len;
    sent_pkt->data_len = offset;
    sent_pkt->net_id   = 0;
    sent_pkt->pkt_type = 0;
    //printf("es:%u, tid:%u\n", send_count, cyg_thread_get_id(cyg_thread_self()));
    fhost_tx_start(&fhost_vif->net_if, sent_pkt, NULL, NULL);
    #ifdef CONFIG_ECOS_SEND_TS
    end_time = rtos_now(false);
    aic_dbg("esout:%u/%u\n", end_time, send_count);
    #endif
}

static void AIC8800_rtos_recv(struct eth_drv_sg *sg_list, int sg_len)
{    
    //TRACE_IN();

    //uint32_t cur_time = rtos_now(false);
    //if (sg_list[0].len != sizeof(struct ether_header)) {
    //    aic_dbg("Packet miss match, sg_list[0].len(%d) != sizeof(struct ether_header)(%d)\n", sg_list[0].len, sizeof(struct ether_header));
    //}
    ///aic_dbg("sg_len %d, deliver_len %d\n", sg_len, deliver_len);
    //memcpy((unsigned char*)sg_list[0].buf, deliver_buf, sizeof(struct ether_header));
    //sg_list++;
    //sg_len--;

    unsigned char *source = deliver_buf;// + sizeof(struct ether_header);
    int srcLen = deliver_len;// - sizeof(struct ether_header);
    while (sg_len > 0 && srcLen > 0) {
        if (sg_list->buf) {
            //aic_dbg("receive sglist len=%d, srcLen=%d\n", sg_list->len, srcLen);
            memcpy((unsigned char*)(unsigned long)sg_list->buf,source,sg_list->len);
        }

        source += sg_list->len;
        srcLen -= sg_list->len;
        ++sg_list;
        --sg_len;
    }
    if (srcLen != 0) {
        aic_dbg("Packet miss match, left data len(%d)\n", srcLen);
    }
    //printf("d: %d\n", rtos_now(false) - cur_time);
    //TRACE_OUT();
}

void AIC8800_rtos_deliver(struct eth_drv_sg *sg_list, int sg_len)
{
    //TRACE_IN();

    #ifdef DCONFIG_ECOS_DELIVER_TS
    uint32_t start_time = 0;
    uint32_t end_time = 0;
    static volatile uint8_t deliver_count = 0;
    #endif

    #ifdef DCONFIG_ECOS_DELIVER_TS
    deliver_count++;
    start_time = rtos_now(false);
    #endif

    #ifdef CONFIG_FHOST_RX_ASYNC
    struct fhost_rx_async_desc_tag *async_desc = fhost_rx_async_post_dequeue();
    if (async_desc == NULL) {
        return;
    }
    deliver_buf = async_desc->data;
    deliver_len = async_desc->len;
    #endif

    #ifdef DCONFIG_ECOS_DELIVER_TS
    uint8_t deliver_buf_valid = (deliver_buf && deliver_len) ? 1 : 0;
    aic_dbg("edin:%u/%u/%u\n", start_time, deliver_count, deliver_buf_valid);
    #endif

    if (deliver_buf && deliver_len) {
        #ifdef CONFIG_ECOS_DELIVER_TCP_PARSE
        struct ether_header *ehdr = (struct ether_header *)deliver_buf;
        if (ntohs(ehdr->ether_type) == ETHERTYPE_IP) {
            struct ip *ihdr = (struct ip *)(deliver_buf + sizeof(struct ether_header));
            if (ihdr->ip_p == IPPROTO_TCP) {
                struct tcphdr *thdr = (struct tcphdr *)(deliver_buf + sizeof(struct ether_header) + ihdr->ip_hl * 4);
                //aic_dbg("rx:%u %u %u\n", ntohl(thdr->th_seq), ntohl(thdr->th_ack), ntohs(thdr->th_win));
                aic_dbg("rx:%u %u\n", ntohl(thdr->th_seq), ntohl(thdr->th_ack));
            }
        }
        #endif

        //uint32_t cur_time = rtos_now(false);
        AIC8800_rtos_recv(sg_list, sg_len);
        //printf("delta: %d\n", rtos_now(false) - cur_time);
        deliver_buf = NULL;
        deliver_len = 0;
    }

    #ifdef CONFIG_FHOST_RX_ASYNC
    if (async_desc->frame_type == RX_ASYNC_RX_FRAME) {
        #ifdef CONFIG_USB_SUPPORT
        struct aicwf_usb_buf *frame = (struct aicwf_usb_buf *)async_desc->frame_ptr;
        aicwf_usb_rx_buf_put(g_aic_usb_dev, frame);
        aicwf_usb_rx_submit_all_urb(g_aic_usb_dev);
        #elif CONFIG_SDIO_SUPPORT
        /*
        struct sdio_buf_node_s *frame = (struct sdio_buf_node_s *)async_desc->frame_ptr;
        sdio_buf_free(frame);
        */
        #endif
    } else if (async_desc->frame_type == RX_ASYNC_REORDER_FRAME) {
        struct recv_msdu *frame = (struct recv_msdu *)async_desc->frame_ptr;
        reord_rxframe_free(frame);
    } else {
        aic_dbg("Err: unknown frame type to deliver\n");
    }
    fhost_rx_async_desc_free(async_desc);
    #endif

    #ifdef DCONFIG_ECOS_DELIVER_TS
    end_time = rtos_now(false);
    aic_dbg("edout:%u/%u\n", end_time, deliver_count);
    #endif
}

void AIC8800_rtos_deliver_init(void)
{
    //rtos_semaphore_create(&deliver_sema, "deliver_sema", 0x7FFFFFFF, 0);
    deliver_buf = NULL;
    deliver_len = 0;
}


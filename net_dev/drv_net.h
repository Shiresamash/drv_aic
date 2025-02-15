/*
* Copyright (c) 2019-2025 Allwinner Technology Co., Ltd. ALL rights reserved.
*
* Allwinner is a trademark of Allwinner Technology Co.,Ltd., registered in
* the the People's Republic of China and other countries.
* All Allwinner Technology Co.,Ltd. trademarks are used with permission.
*
* DISCLAIMER
* THIRD PARTY LICENCES MAY BE REQUIRED TO IMPLEMENT THE SOLUTION/PRODUCT.
* IF YOU NEED TO INTEGRATE THIRD PARTY’S TECHNOLOGY (SONY, DTS, DOLBY, AVS OR MPEGLA, ETC.)
* IN ALLWINNERS’SDK OR PRODUCTS, YOU SHALL BE SOLELY RESPONSIBLE TO OBTAIN
* ALL APPROPRIATELY REQUIRED THIRD PARTY LICENCES.
* ALLWINNER SHALL HAVE NO WARRANTY, INDEMNITY OR OTHER OBLIGATIONS WITH RESPECT TO MATTERS
* COVERED UNDER ANY REQUIRED THIRD PARTY LICENSE.
* YOU ARE SOLELY RESPONSIBLE FOR YOUR USAGE OF THIRD PARTY’S TECHNOLOGY.
*
*
* THIS SOFTWARE IS PROVIDED BY ALLWINNER"AS IS" AND TO THE MAXIMUM EXTENT
* PERMITTED BY LAW, ALLWINNER EXPRESSLY DISCLAIMS ALL WARRANTIES OF ANY KIND,
* WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING WITHOUT LIMITATION REGARDING
* THE TITLE, NON-INFRINGEMENT, ACCURACY, CONDITION, COMPLETENESS, PERFORMANCE
* OR MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
* IN NO EVENT SHALL ALLWINNER BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS, OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
* OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef SUNXI_DRV_NET_H
#define SUNXI_DRV_NET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rtthread.h>


typedef struct sunxi_driver_net {
    struct rt_device   base;
    int32_t            dev_id;
    const void        *hal_drv;
} sunxi_driver_net_t;

typedef struct sunxi_hal_driver_net {
    int (*initialize)(int netif_id);
    int (*uninitialize)(int netif_id);
    int (*send)(int netif_id, unsigned long pos, const void *buf, uint32_t size);
    int (*receive)(int netif_id, unsigned long pos, void *buf, uint32_t size);
    int (*control)(int netif_id, int cmd, void *args);
} const sunxi_hal_driver_net_t;


typedef enum {
    NET_EVENT_WIFI_STA_MAC_CONNECT = 0,
    NET_EVENT_WIFI_STA_MAC_DISCONNECT,

    NET_EVENT_WIFI_AP_MAC_CONNECT  = 100,
    NET_EVENT_WIFI_AP_MAC_DISCONNECT,

    NET_EVENT_WIFI_P2P_MAC_CONNECT = 200,
    NET_EVENT_WIFI_P2P_IP_CONNECT,
    NET_EVENT_WIFI_P2P_MAC_DISCONNECT,

    NET_EVENT_DHCPC_SUCCESS = 300,
}sunxi_driver_net_event_e;

typedef enum {
    NET_MODE_STA,
    NET_MODE_AP,
    NET_MODE_P2P,
}sunxi_driver_net_mode_e;

typedef enum {
    /*STA*/
    NET_CMD_WIFI_STA_START,
    NET_CMD_WIFI_STA_SCAN,
    NET_CMD_WIFI_STA_CONNECT,
    NET_CMD_WIFI_STA_DISCONNECT,
    NET_CMD_WIFI_STA_GET_CONNECTING_INFO,
    /*AP*/
    NET_CMD_WIFI_AP_START,    
    NET_CMD_WIFI_AP_STOP,
    /*P2P*/
    NET_CMD_WIFI_P2P_GO_START,   
    NET_CMD_WIFI_P2P_GO_STOP,
    NET_CMD_WIFI_P2P_GET_ROLE,
    NET_CMD_WIFI_P2P_CONNECT,
    NET_CMD_WIFI_P2P_DISCONNECT,
    /*COMMON*/
    NET_CMD_WIFI_SET_EVENT_CB, 
    NET_CMD_WIFI_DISABLE_ALL,  
    NET_CMD_WIFI_GET_INFO,
	
	NET_CMD_WIFI_STA_GET_SCAN,
    NET_CMD_WIFI_STA_SCAN_CLOSE,
    NET_CMD_WIFI_STA_GET_CONNECT_STATE,

    NET_CMD_MAX,
}sunxi_driver_net_cmd_e;

#ifdef __cplusplus
}
#endif

#endif

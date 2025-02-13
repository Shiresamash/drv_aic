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
#ifndef __DEV_NET_H__
#define __DEV_NET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef enum {
    HAL_WIFI_MODE_NONE = 0,
	HAL_WIFI_MODE_STA,
	HAL_WIFI_MODE_AP,
	HAL_WIFI_MODE_STA_AP,
	HAL_WIFI_MODE_PROMISC,
	HAL_WIFI_MODE_P2P
}hal_wifi_mode_e;

typedef enum {
    HAL_WIFI_STATUS_OFF,
	HAL_WIFI_STATUS_ON,
	HAL_WIFI_STATUS_CONNECT,
	HAL_WIFI_STATUS_DISCONNECT,
}hal_wifi_status_e;

typedef struct {
	int (*p2p_enable)(int enable);
	int (*p2p_go_enable)(int enable);
	int (*p2p_get_device_ip)(int *cnt, unsigned int **buf);
	int (*p2p_get_rtsp_port)(void);
	int (*p2p_get_role)(void);
	int (*p2p_get_status)(void);
}net_dev_ops_t;

int dev_net_init(int netif_id);
int dev_net_uninit(int netif_id);
int dev_net_write(int netif_id, unsigned long pos, const void *buf, uint32_t size);
int dev_net_read(int netif_id, unsigned long pos, void *buf, uint32_t size);
int dev_net_control(int netif_id, int cmd, void *args);
extern net_dev_ops_t *dev_net_get_ops(void);

#ifdef __cplusplus
}
#endif

#endif
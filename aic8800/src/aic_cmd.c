#include <rtthread.h>

#ifdef RT_USING_FINSH
#include <finsh.h>
#include <stdlib.h>
#include <string.h>

#include "os_semaphore.h"

#include "hal_sdhost.h"
#include "sdmmc.h"
#include "sdio.h"

#include "_sd_define.h"
#include "_sdhost.h"

#include "lwip/tcpip.h"
#include "lwip/dhcp.h"

#include "dhcp_server.h"

#include "cmd/cmd_util.h"

#include "fhost_tx.h"
#include "fhost.h"
#include "cli_cmd.h"
#include "wlan_if.h"

#include "plat_config.h"
#include "porting.h"

#define CONFIG_AIC_SDC_ID 	1

extern struct rwnx_hw *g_rwnx_hw;

struct sdio_info {
	uint16_t card_id;
	SDC_InitTypeDef sdc_param;
	SDCard_InitTypeDef card_param;
	struct mmc_card *card;
};

static int sdio_card_detect(struct sdio_info *sdio)
{
    int ret = mmc_card_create(sdio->card_id, &sdio->card_param);
	if (ret != 0) {
		printf( "SDIO failed to init. ret=%d\n", ret );
		return ret;
	}

	sdio->card = mmc_card_open(sdio->card_id);
	if (sdio->card == NULL) {
		printf("card open fail\n");
		return ret;
	}
	/* scan card for detect card is exist? */
	if (!mmc_card_present(sdio->card)) {
		if (mmc_rescan(sdio->card, sdio->card->id)) {
			printf("Initial card failed!!\n");
			mmc_card_close(sdio->card_id);
			return ret;
		} else {
			printf("Initial card success\n");
			mmc_card_close(sdio->card_id);
		}
	} else {
		printf("%s not eixst\n", __func__);
		mmc_card_close(sdio->card_id);
		return ret;
	}

	return ret;
}


static struct sdio_info sdio_wifi;
void sdio_controller_init( uint32_t index )
{
	SDC_InitTypeDef sdc_param;
	struct mmc_host *host;

	memset(&sdio_wifi, 0, sizeof(struct sdio_info));
	sdio_wifi.sdc_param.cd_mode = CARD_ALWAYS_PRESENT;
	//sdio_wifi.sdc_param.cd_cb = &sdio_card_detect;
	sdio_wifi.sdc_param.debug_mask = (ROM_INF_MASK | ROM_WRN_MASK | ROM_ERR_MASK | ROM_ANY_MASK);
	sdio_wifi.sdc_param.dma_use = 1;

	sdio_wifi.card_id = index;
	sdio_wifi.card_param.debug_mask = sdio_wifi.sdc_param.debug_mask;
	sdio_wifi.card_param.type = MMC_TYPE_SDIO;

	host = hal_sdc_create(index, &sdio_wifi.sdc_param);
	host->param.pwr_mode = POWER_MODE_330;
	hal_sdc_init(host);

	if (sdio_wifi.sdc_param.cd_mode == CARD_ALWAYS_PRESENT) {
		sdio_card_detect(&sdio_wifi);
	}
}

int aic_wifi_drv_event_cbk(const wifi_drv_event* drv_event)
{
	CMD_DBG("wifi event: %d\n", drv_event->type);
	return 0;
}

#define MSH_CMD_BUF_SIZE	256

static char msh_cmd_buf[MSH_CMD_BUF_SIZE];
extern void AIC8800_rtos_deliver_init(void);

int aic_cmd_commands(int argc, char *argv[])
{
	int i, len;
	int left = MSH_CMD_BUF_SIZE;
	char *ptr = msh_cmd_buf;
	if (argc > 1) {
		if (strcmp((const char*)argv[1], "init") == 0) {
			platform_config_init();
			platform_pwr_en_pin_set(0);
			rtos_task_suspend(10);
			platform_pwr_en_pin_set(1);
			sdio_controller_init(platform_get_sdc_index());
			tcpip_init(NULL, NULL);
			AIC8800_rtos_deliver_init();
			wifi_drv_event_set_cbk(aic_wifi_drv_event_cbk);
			aic_wifi_init(WIFI_MODE_UNKNOWN, 0, NULL);
			return 0;
		} else if (strcmp((const char*)argv[1], "deinit") == 0) {
			//sdio_controller_init(CONFIG_AIC_SDC_ID);
			//tcpip_init(NULL, NULL);
			//AIC8800_rtos_deliver_init();
			//wifi_drv_event_set_cbk(aic_wifi_drv_event_cbk);
			//aic_wifi_deinit(WIFI_MODE_UNKNOWN);
			return 0;
		} else if (strcmp((const char*)argv[1], "rfinit") == 0) {
			sdio_controller_init(platform_get_sdc_index());
			tcpip_init(NULL, NULL);
			AIC8800_rtos_deliver_init();
			wifi_drv_event_set_cbk(aic_wifi_drv_event_cbk);
			aic_wifi_init(WIFI_MODE_RFTEST, 0, NULL);
			return 0;
		}

		for (i = 1; i < argc && left >= 2; ++i) {
			len = cmd_strlcpy(ptr, argv[i], left);
			ptr += len;
			left -= len;
			if (i < argc - 1 && left >= 2) {
				*ptr++ = ' ';
				*ptr = '\0';
				left -= 1;
			}
		}
		CMD_DBG("net cmd: %s\n", msh_cmd_buf);

		aic_cli_run_cmd(msh_cmd_buf);
	}

	return 0;
}

MSH_CMD_EXPORT_ALIAS(aic_cmd_commands, aic, AIC wifi control commands);

#include "lwip/netif.h"
#include "lwip/dns.h"

void aic_ifconfig(void)
{
    rt_ubase_t index;
    struct netif * netif;

    rt_enter_critical();

    netif = netif_list;

    while( netif != RT_NULL )
    {
        rt_kprintf("network interface: %c%c%s\n",
                   netif->name[0],
                   netif->name[1],
                   (netif == netif_default)?" (Default)":"");
        rt_kprintf("MTU: %d\n", netif->mtu);
        rt_kprintf("MAC: ");
        for (index = 0; index < netif->hwaddr_len; index ++)
            rt_kprintf("%02x ", netif->hwaddr[index]);
        rt_kprintf("\nFLAGS:");
        if (netif->flags & NETIF_FLAG_UP) rt_kprintf(" UP");
        else rt_kprintf(" DOWN");
        if (netif->flags & NETIF_FLAG_LINK_UP) rt_kprintf(" LINK_UP");
        else rt_kprintf(" LINK_DOWN");
        if (netif->flags & NETIF_FLAG_ETHARP) rt_kprintf(" ETHARP");
        if (netif->flags & NETIF_FLAG_BROADCAST) rt_kprintf(" BROADCAST");
        if (netif->flags & NETIF_FLAG_IGMP) rt_kprintf(" IGMP");
        rt_kprintf("\n");
        rt_kprintf("ip address: %s\n", ipaddr_ntoa(&(netif->ip_addr)));
        rt_kprintf("gw address: %s\n", ipaddr_ntoa(&(netif->gw)));
        rt_kprintf("net mask  : %s\n", ipaddr_ntoa(&(netif->netmask)));
#if 0	//LWIP_IPV6
		{
			ip6_addr_t *addr;
			int addr_state;
			int i;
			
			addr = (ip6_addr_t *)&netif->ip6_addr[0];
			addr_state = netif->ip6_addr_state[0];
			
			rt_kprintf("\nipv6 link-local: %s state:%02X %s\n", ip6addr_ntoa(addr), 
			addr_state, ip6_addr_isvalid(addr_state)?"VALID":"INVALID");
			
			for(i=1; i<LWIP_IPV6_NUM_ADDRESSES; i++)
			{
				addr = (ip6_addr_t *)&netif->ip6_addr[i];
				addr_state = netif->ip6_addr_state[i];
			
				rt_kprintf("ipv6[%d] address: %s state:%02X %s\n", i, ip6addr_ntoa(addr), 
				addr_state, ip6_addr_isvalid(addr_state)?"VALID":"INVALID");
			}
			
		}
        rt_kprintf("\r\n");
#endif /* LWIP_IPV6 */
        netif = netif->next;
    }

#if 1	//LWIP_DNS
    {
        const ip_addr_t *ip_addr;

        for(index=0; index<DNS_MAX_SERVERS; index++)
        {
            ip_addr = dns_getserver(index);
            rt_kprintf("dns server #%d: %s\n", index, ipaddr_ntoa(ip_addr));
        }
    }
#endif /**< #if LWIP_DNS */

    rt_exit_critical();
}

int aic_cmd_ifconfig(int argc, char *argv[])
{
    struct netif * netif;
	ip4_addr_t addr;
	
	if (argc == 1) {
	    aic_ifconfig();
	} else {
		//	ifconfig wl0 ip 192.168.1.252 netmask 255.255.255.0 gw 192.168.1.1 dns 8.8.8.8 up
		netif = netif_find(argv[1]);
		if (netif == NULL)
		{
			__err("netif no found");
			return 0;
		}

		argv += 2;
        argc -= 2;
		while (argc >= 2) {
			if (strcmp(argv[0], "ip") == 0) {
				inet_pton(AF_INET, argv[1], &addr);
		    	netif_set_ipaddr(netif, &addr);
		  	} else if (strcmp(argv[0], "netmask") == 0) {
				inet_pton(AF_INET, argv[1], &addr);
		    	netif_set_netmask(netif, &addr);
		  	} else if (strcmp(argv[0], "gw") == 0) {
				inet_pton(AF_INET, argv[1], &addr);
		    	netif_set_gw(netif, &addr);
		  	} else if (strcmp(argv[0], "dns") == 0) {
				inet_pton(AF_INET, argv[1], &addr);
		    	dns_setserver(0, &addr);
		  	}
			argv += 2;
	        argc -= 2;
		}

		if (argc > 0) {
			if (strcmp(argv[0], "up") == 0) {
		    	netif_set_up(netif);
		  	} else if (strcmp(argv[0], "down") == 0) {
		    	netif_set_down(netif);
		  	} else {
				printf("Usage:\n");
				printf("  ifconfig\n");
				printf("  ifconfig wl0 ip 192.168.21.1 netmask 255.255.255.0 gw 192.168.21.1 dns 8.8.8.8 up\n");
	  		}
		}
	}

	return 0;
}
MSH_CMD_EXPORT_ALIAS(aic_cmd_ifconfig, ifconfig, ifconfig);

#include "dhcp_server.h"

void dhcpd_start(const char *netif_name, int mode);
int aic_cmd_dhcpd(int argc, char *argv[])
{
	if (argc == 2) {
		dhcpd_start(argv[1], 0);
	} else {
		printf("Usage: dhcpd if_name\n");
	}
	
	return 0;
}
MSH_CMD_EXPORT_ALIAS(aic_cmd_dhcpd, dhcpd, dhcp server);

int aic_cmd_dhcpc(int argc, char *argv[])
{
	if (argc == 2) {
		struct netif *netif;
		netif = netif_find(argv[1]);
		if (netif == NULL) {
            printf("dhcpc netif not found\n");
            return 0;
        }
		err_t ret = dhcp_start(netif);
        if (ret)
            printf("dhcp_start failed %d\n", ret);
	} else {
		printf("Usage: dhcpc if_name\n");
	}
	
	return 0;
}
MSH_CMD_EXPORT_ALIAS(aic_cmd_dhcpc, dhcpc, dhcp client);

#endif /* RT_USING_FINSH */

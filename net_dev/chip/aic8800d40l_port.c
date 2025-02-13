#include "wifi.h"
#include "log.h"
#include "kapi.h"
#include "lwip/tcpip.h"
#include "lwip/dhcp.h"
#include "fhost.h"
#include "wlan_if.h"
#include "drv_net.h"
#include "dev_net.h"
#include "dns.h"
#include <pthread.h>


extern void sdio_controller_init( uint32_t index);
extern void AIC8800_rtos_deliver_init(void);
extern void dhcpd_start_ex(const char *netif_name, int mode);
extern void dhcpds_stop(void);
extern int dev_net_event_report(int event, void* para);
extern int wlan_sta_get_connect_info(char *ssid, char *psk);

static int sdc_channel = 1;
static int init_flag = 0;
static void *wifi_regon = NULL;
extern uint8_t p2p_started;

static int aic_wifi_drv_event_cb(const wifi_drv_event* drv_event)
{
	// __log("wifi event: %d\n", drv_event->type);

    switch(drv_event->type)
    {
        case WIFI_DRV_EVENT_DEFAULT:
        {
            break;
        }
        case WIFI_DRV_EVENT_NET_DEVICE:  
        {
            break;
        }
        case WIFI_DRV_EVENT_AP:
        {
            __u64 para[7] = {0};
            memcpy(&para[0], &drv_event->node.ap_event.peer_dev_mac_addr[0], 6);//mac
            if(drv_event->node.ap_event.event_type == WIFI_AP_EVENT_ON_ASSOC)
            {
                dev_net_event_report(NET_EVENT_WIFI_AP_MAC_CONNECT, &para);
                __log("ap: sta connect mac = %x:%x:%x:%x:%x:%x",drv_event->node.ap_event.peer_dev_mac_addr[0],
                                                                drv_event->node.ap_event.peer_dev_mac_addr[1],
                                                                drv_event->node.ap_event.peer_dev_mac_addr[2],
                                                                drv_event->node.ap_event.peer_dev_mac_addr[3],
                                                                drv_event->node.ap_event.peer_dev_mac_addr[4],
                                                                drv_event->node.ap_event.peer_dev_mac_addr[5]);
            }
            else if(drv_event->node.ap_event.event_type == WIFI_AP_EVENT_ON_DISASSOC)
            {
                dev_net_event_report(NET_EVENT_WIFI_AP_MAC_DISCONNECT, &para);
                __log("ap: sta disconnect mac = %x:%x:%x:%x:%x:%x", drv_event->node.ap_event.peer_dev_mac_addr[0],
                                                                    drv_event->node.ap_event.peer_dev_mac_addr[1],
                                                                    drv_event->node.ap_event.peer_dev_mac_addr[2],
                                                                    drv_event->node.ap_event.peer_dev_mac_addr[3],
                                                                    drv_event->node.ap_event.peer_dev_mac_addr[4],
                                                                    drv_event->node.ap_event.peer_dev_mac_addr[5]);
            }
            break;
        }
        case WIFI_DRV_EVENT_P2P:
        {
            __u64 para[7] = {0};
            memcpy(&para[0], &drv_event->node.p2p_event.peer_dev_mac_addr[0], 6);//mac
            if(drv_event->node.p2p_event.event_type == WIFI_AP_EVENT_ON_ASSOC)
            {
                dev_net_event_report(NET_EVENT_WIFI_P2P_MAC_CONNECT, &para);
                __log("p2p: peer connect mac = %x:%x:%x:%x:%x:%x",drv_event->node.p2p_event.peer_dev_mac_addr[0],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[1],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[2],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[3],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[4],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[5]);
            }
            else if(drv_event->node.p2p_event.event_type == WIFI_AP_EVENT_ON_DISASSOC)
            {
                dev_net_event_report(NET_EVENT_WIFI_P2P_MAC_DISCONNECT, &para);
                __log("p2p: peer disconnect mac = %x:%x:%x:%x:%x:%x",drv_event->node.p2p_event.peer_dev_mac_addr[0],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[1],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[2],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[3],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[4],
                                                                drv_event->node.p2p_event.peer_dev_mac_addr[5]);
            }
            break;
        } 
        case WIFI_DRV_EVENT_STA:
        {
            __u64 para[7] = {0};
            if(drv_event->node.sta_event.event_type == WIFI_STA_EVENT_ON_ASSOC)
            {
                dev_net_event_report(NET_EVENT_WIFI_STA_MAC_CONNECT, &para);
                __log("sta: connect ok");
            }
            else if(drv_event->node.sta_event.event_type == WIFI_STA_EVENT_ON_DISASSOC)
            {
                dev_net_event_report(NET_EVENT_WIFI_STA_MAC_DISCONNECT, &para);
                __log("sta:disconnect ok");
            }
            break;
        }
    }
	return 0;
}

int net_port_wifi_init(void)
{
    int channel = 1;
    user_gpio_set_t  gpio_set[1] = {0};
    int ret = 0;
    
    ret = esCFG_GetKeyValue("wifi_para", "wifi_sdc_id", (__s32 *)&channel, 1);
    if(ret >= 0)
	{
    	if(channel < 0 || channel > 2)
        {
            __err("wifi_sdc_id[%d] set err\n", channel);
            channel = 1;
        }
        sdc_channel = channel;
	}
	else
	{
		__err("read cfg file fail wifi_sdc_id...\n");
	}

    ret = esCFG_GetKeyValue("wifi_para", "wifi_reg_on", (int *)gpio_set, sizeof(user_gpio_set_t)/4);
	if(ret >= 0)
	{
    	wifi_regon = esPINS_PinGrpReq(gpio_set, 1);
	}
	else
	{
		__err("read cfg file fail wifi_reg_on...\n");
	}

    if(init_flag == 0)
    {
        esPINS_SetPinIO(wifi_regon, 1, NULL);
    	esPINS_WritePinData(wifi_regon, 0, NULL);
        esKRNL_TimeDly(2);
        esPINS_WritePinData(wifi_regon, 1, NULL);

        sdio_controller_init(channel);
        tcpip_init(NULL, NULL);
        AIC8800_rtos_deliver_init();
        wifi_drv_event_set_cbk(aic_wifi_drv_event_cb);
		
        aic_wifi_init(WIFI_MODE_UNKNOWN, 0, NULL);
        init_flag = 1;
    }
	
    return 0;
}

int net_port_wifi_deinit(void)
{
    if(init_flag == 0)
    {
        return 0;
    }
    if(wifi_regon)
    {
        esPINS_PinGrpRel(wifi_regon, 0);
    }
    init_flag = 0;
    return 0;
}

int net_port_wifi_ap(char *ssid, char *password)
{
    struct aic_ap_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.band = PHY_BAND_2G4;
    cfg.channel = 4;
    cfg.type = PHY_CHNL_BW_40;
    cfg.max_inactivity = 60;
    cfg.enable_he = 0;
    cfg.bcn_interval = 100;
    cfg.sercurity_type = KEY_WPA2;
    cfg.sta_num = 5;
    memcpy(cfg.aic_ap_ssid.array, ssid, strlen(ssid));//最多32字节
    memcpy(cfg.aic_ap_passwd.array, password, strlen(password));//最多32字节
    cfg.aic_ap_ssid.length = strlen(cfg.aic_ap_ssid.array);
    cfg.aic_ap_passwd.length = strlen(cfg.aic_ap_passwd.array);
    aic_wifi_init(WIFI_MODE_AP, 0, &cfg);

    struct netif * netif;
    ip4_addr_t addr;
    netif = netif_find("wl0");
    inet_pton(AF_INET, "192.168.169.1", &addr);
    netif_set_ipaddr(netif, &addr);
    inet_pton(AF_INET, "255.255.255.0", &addr);
    netif_set_netmask(netif, &addr);
    inet_pton(AF_INET, "192.168.169.1", &addr);
    netif_set_gw(netif, &addr);
    netif_set_up(netif);
    netif_set_default(netif);
    dhcpd_start_ex("wl", 0);
    // printf("def netif ap = 0x%x\n",netif);
    return 0;
}

/***********************************     wifi   scan   task    ******************************************/

static rtos_queue wifi_scan_task_queue = NULL;
static rtos_task_handle wifi_scan_task = NULL;
#define WIFI_SCAN_MSG_USE_QUEUE 0

static void wifi_scan_task_func(void)
{
	for(;;){
		__log("-------------------->   wifi  scan  task  is  running \n");
		
		if(wlan_get_connect_status()){
			__log("-------------------->   no  wifi  scan  \n");
		}else{
			__log("-------------------->   have  wifi  scan  \n");
			wlan_if_scan();  //wifi 扫描
		}
		
		esKRNL_TimeDly(100);
	}
	
}

static int net_port_wifi_scan_task_init(void)
{
	if(wifi_scan_task_queue){
		__log("------------------------------> Error: %s \n", __func__);
		return -1;
	}

    #if WIFI_SCAN_MSG_USE_QUEUE
    if (rtos_queue_create(sizeof(uint32_t), 60, &wifi_scan_task_queue, "wifi_scan_task_queue")) {
        __log("------------------------------> wifi_scan_task_queue fail\r\n");
        return 1;
    }
    #endif

	if (rtos_task_create(wifi_scan_task_func, "Wifi Scan task", 11,
                         4096, NULL, 20, &wifi_scan_task)) {
        __log("------------------------------> Wifi Scan task fail\r\n");
        return 2;
    }
	return 0;
}

/***********************************     wifi   scan   task    ******************************************/

int net_port_wifi_scan(void)
{
	#if 1
	//int wifi_scan_ret = net_port_wifi_scan_task_init();
	//__log("-----------------------------> wifi_scan_ret  = %d  \n",wifi_scan_ret);

	wlan_if_scan();
	#else
	wlan_if_scan_init();
	#endif
	return 0;
}

int net_port_wifi_get_scan(void * ap_list)
{
	//wlan_if_scan();
	wlan_if_getscan((wifi_ap_list_t *)ap_list, 0);
	return 0;
}

void net_port_wifi_scan_close(void)
{
	wlan_if_scan_close();
}

pthread_t hThread;
static void wait_dhcp_success(void *para)
{

	char *ip = "0.0.0.0";
	while(1)
	{
    	struct netif * netif = netif_find("wl");
		if(netif != NULL)
			ip = ipaddr_ntoa(&(netif->ip_addr));

		if(strcmp(ip, "0.0.0.0") != 0)
		{
			dev_net_event_report(NET_EVENT_DHCPC_SUCCESS, (void *)ip);
			break;
		}
		else
		{
			//__err("sssssss sleep  ip:%s", ip);
			usleep(500*1000);
		}
	}
	hThread = NULL;
}

int net_port_wifi_sta(char *ssid, char *password)
{
    struct netif * netif;
    ip4_addr_t addr;

	wlan_start_sta(NULL, NULL, -1);

	int wifi_connect_ret = 0;		//add new
    wifi_connect_ret = wlan_sta_connect(ssid, password, 15*1000);
	__log("--- wifi_connect_ret  = %d",wifi_connect_ret);
	if(wifi_connect_ret < 0)
	{
		return -1;
	}

    netif = netif_find("wl0");
    netif_set_up(netif);
    netif_set_default(netif);
	
    int dhcp_start_ret = dhcp_start(netif);
	__log("--- dhcp_start_ret  =  %d",dhcp_start_ret);
	if(dhcp_start_ret == 0 && hThread == NULL)
	{
		pthread_create(&hThread, NULL, wait_dhcp_success, NULL);
		pthread_detach(hThread);
	}
    
    return 0;
}

int wifi_sta_get_connect_status(void)
{
	return wlan_get_connect_status();
}

int net_port_wifi_p2p(char *ssid, char *password)
{
    struct aic_p2p_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.band = PHY_BAND_2G4;
    cfg.channel = 4;
    cfg.type = PHY_CHNL_BW_40;
    cfg.enable_he = 1;
    memcpy(cfg.aic_p2p_ssid.array, ssid, strlen(ssid));
    memcpy(cfg.aic_ap_passwd.array, password, strlen(password));
    cfg.aic_p2p_ssid.length = strlen(cfg.aic_p2p_ssid.array);
    cfg.aic_ap_passwd.length = strlen(cfg.aic_ap_passwd.array);
    user_p2p_start(&cfg);

    struct netif * netif;
    ip4_addr_t addr;
    netif = netif_find("wl0");
    inet_pton(AF_INET, "192.168.169.1", &addr);
    netif_set_ipaddr(netif, &addr);
    inet_pton(AF_INET, "255.255.255.0", &addr);
    netif_set_netmask(netif, &addr);
    inet_pton(AF_INET, "192.168.169.1", &addr);
    netif_set_gw(netif, &addr);
    netif_set_up(netif);
    netif_set_default(netif);
    dhcpd_start_ex("wl", 1);
	__log("----------------------- net_port_wifi_p2p   end :  --------------\n");
    // printf("def netif p2p = 0x%x\n",netif);
    return 0;
}

int net_port_wifi_off(int mode)
{
    if(mode == NET_MODE_STA)
    {
        wlan_disconnect_sta(0);
    }
    else if(mode == NET_MODE_AP)
    {
        aic_wifi_deinit(WIFI_MODE_AP);
    }
    else if(mode == NET_MODE_P2P)
    {

    }

    struct netif * netif;
    ip4_addr_t addr;
    netif = netif_find("wl0");
    netif_set_down(netif);
    //netif_set_link_down(netif);
	__log("----------------------- net_port_wifi_off   1 :  --------------\n");
    dhcp_stop(netif);
	__log("----------------------- net_port_wifi_off   2 :  --------------\n");
    dhcp_cleanup(netif);
	__log("----------------------- net_port_wifi_off   3 :  --------------\n");
    //dhcp_stop(netif);
	__log("----------------------- net_port_wifi_off   4 :  --------------\n");
    dhcpds_stop();
	__log("----------------------- net_port_wifi_off   5 :  --------------\n");
    //netif_remove(netif);
	__log("----------------------- net_port_wifi_off   6 :  --------------\n");
    // free(netif);//此驱动不需要释放
    
	if(mode == NET_MODE_P2P)
	{
	
    	if (p2p_started) {
        	wlan_stop_p2p();
        	aic_wifi_event_register(NULL);
			p2p_started = 0;
    	}
	}
	
    return 0;
}

int net_port_wifi_sta_disconnect(int argc, char **argv)
{
	wlan_disconnect_sta(NET_MODE_STA);
    struct netif * netif;
    ip4_addr_t addr;
    netif = netif_find("wl0");
	inet_pton(AF_INET, "0.0.0.0", &addr);
	netif_set_ipaddr(netif, &addr);
	netif_set_netmask(netif, &addr);
	netif_set_gw(netif, &addr);
	/*dns_setserver(netif, &addr);*/
	dhcp_release_and_stop(netif);
	netif_set_down(netif);
	return 0;
}

int net_port_wifi_get_mode(void)
{
    int mode = -1;
    mode = aic_wifi_get_mode();

    if(mode == WIFI_MODE_STA)
    {
        mode = NET_MODE_STA;
    }
    else if(mode == WIFI_MODE_AP)
    {
        mode = NET_MODE_AP;
    }
    else if(mode == WIFI_MODE_P2P)
    {
        mode = WIFI_MODE_P2P;
    }
    
    return mode;
}





static int wifi_disabled(void)
{
	int mode = net_port_wifi_get_mode();
	net_port_wifi_off(mode);
	return 0;
}

static int cmd_wifi_connect(int argc, char **argv)
{
	char *ssid=NULL, *psk=NULL;
	int time_out = -1;
	if(argc < 2)
	{
		__err("use:wifi_connect ssid psk <time_out(s)>\n");
		return -1;
	}
	if(argv[1] != NULL)
	{
		ssid = argv[1];
	}
	if(argv[2] != NULL)
	{
		psk = argv[2];
	}
	if(argv[3] != NULL)
	{
		time_out = atol(argv[3]);
	}

	wlan_start_sta(NULL, NULL, -1);
    wlan_sta_connect(ssid, psk, time_out*1000);
	return 0;
}

static int cmd_wifi_scan(int argc, char **argv)
{
	wifi_ap_list_t ap_list;
	__log("scan start");
	wlan_if_scan();
	__log("scan finish");
	wlan_if_getscan(&ap_list, 1);
	__log("get scan finish");
	return 0;
}

static int cmd_wifi_sta_connecting_info(int argc, char **argv)
{
	char ssid[32] = {0};
	char psk[32] = {0};
	wlan_sta_get_connect_info(ssid, psk);
	__log("connecting: ssid:%s  psk:%s", ssid, psk);
	return 0;
}





MSH_CMD_EXPORT_ALIAS(net_port_wifi_off, wifi_off, wifioff);
MSH_CMD_EXPORT_ALIAS(cmd_wifi_sta_connecting_info, wifi_sta_connecting_info, wifi);
MSH_CMD_EXPORT_ALIAS(cmd_wifi_connect, wifi_connect, wifi);
MSH_CMD_EXPORT_ALIAS(cmd_wifi_scan, wifi_scan, wifi);
MSH_CMD_EXPORT_ALIAS(net_port_wifi_init, wifi_init, wifi);
MSH_CMD_EXPORT_ALIAS(net_port_wifi_sta_disconnect, wifi_disconnect_sta, wifi);


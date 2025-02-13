#include "dev_net.h"
#include "drv_net.h"
#include <stdlib.h>
#include <stddef.h>
#include "kapi.h"
#include "log.h"
#include "net_port_wifi.h"

#include <log.h>
#include <kapi.h>
#include <elibs_string.h>
#include <dfs_posix.h>

typedef struct {
	int (*event_cb)(int event, void *para);
	int mode;
}net_dev_t;

extern int wlan_sta_get_connect_info(char *ssid, char *psk);
static net_dev_t net_dev;

int dev_net_init(int netif_id)
{
	net_port_wifi_init();
    return 0;
}

int dev_net_uninit(int netif_id)
{
	net_port_wifi_deinit();
    return 0;
}

int dev_net_write(int netif_id, unsigned long pos, const void *buf, uint32_t size)
{
    return 0;
}

int dev_net_read(int netif_id, unsigned long pos, void *buf, uint32_t size)
{
    return 0;
}


int dev_net_control(int netif_id, int cmd, void *args)
{
    unsigned long *pbuffer = args;
    unsigned long ret = -1;
    switch(cmd)
    {          
        case NET_CMD_WIFI_SET_EVENT_CB:
		{
			net_dev.event_cb = (void *)pbuffer[0];
            break;
		}

		case NET_CMD_WIFI_STA_SCAN: 
		{	
			net_port_wifi_scan();
			break;
		}
		case NET_CMD_WIFI_STA_GET_SCAN:
		{	
			net_port_wifi_get_scan(args);
			break;
		}

		case NET_CMD_WIFI_STA_SCAN_CLOSE:
		{	
			net_port_wifi_scan_close();
			break;
		}
		
		case NET_CMD_WIFI_STA_START:
		{
			char *ssid = (char *)pbuffer[0];
			char *password = (char *)pbuffer[1];
			
			ret = net_port_wifi_sta(ssid, password);
            break;	
		}
		
		case NET_CMD_WIFI_STA_DISCONNECT:
		{
			ret = net_port_wifi_sta_disconnect();
            break;	
		}

		case NET_CMD_WIFI_STA_GET_CONNECTING_INFO:
		{
			char *ssid = (char *)pbuffer[0];
			char *psk = (char *)pbuffer[1];
			ret = wlan_sta_get_connect_info(ssid, psk);
            break;	
		}

		case NET_CMD_WIFI_STA_GET_CONNECT_STATE:
		{
			//*(int *)args = wifi_sta_get_connect_status();
			ret = wifi_sta_get_connect_status();
            break;	
		}
		
        case NET_CMD_WIFI_AP_START:
		{
			char *ssid = (void *)pbuffer[0];
			char *password = (void *)pbuffer[1];
			net_port_wifi_ap(ssid, password);
            break;	
		}
        case NET_CMD_WIFI_P2P_GO_START:
		{
			char *ssid = (void *)pbuffer[0];
			char *password = (void *)pbuffer[1];
			net_port_wifi_p2p(ssid, password);
            break;	
		}
		case NET_CMD_WIFI_DISABLE_ALL:
		{
			int mode = net_port_wifi_get_mode();
			net_port_wifi_off(mode);
		}     
		default:
        	break;
    }
    return ret;
}

int dev_net_event_report(int event, void* para)
{
	if(net_dev.event_cb == NULL)
	{
		__log("net_dev.event_cb == NULL!");
		return -1;
	}
	
	__log("net_dev.event_cb = 0x%x",net_dev.event_cb);
	return net_dev.event_cb(event, para);
}

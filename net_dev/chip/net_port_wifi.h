#ifndef __NET_PORT_WIFI_H__
#define __NET_PORT_WIFI_H__

int net_port_wifi_init(void);
int net_port_wifi_deinit(void);
int net_port_wifi_off(int mode);
int net_port_wifi_ap(char *ssid, char *password);
#if 0
int net_port_wifi_sta(char *ssid, char *password);
#else
int net_port_wifi_sta(char *ssid, char *password);

#endif
int wifi_sta_get_connect_status(void);
int net_port_wifi_sta_disconnect(void);
int net_port_wifi_p2p(char *ssid, char *password);
int net_port_wifi_get_mode(void);

int net_port_wifi_scan(void);
int net_port_wifi_get_scan(void * ap_list);
void net_port_wifi_scan_close(void);


#endif

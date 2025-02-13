#include "lmac_types.h"
#include "fhost_wpa.h"
#include "fhost_config.h"
#include "fhost_cntrl.h"
#include "rtos_al.h"
#include "net_al.h"
#include "fhost.h"
#include "mac.h"
//#include "dhcp.h"
#include "rwnx_msg_tx.h"
#include "rwnx_utils.h"
#ifdef CFG_SOFTAP
//#include "dhcps.h"
#endif /* CFG_SOFTAP */
#include "fhost_tx.h"
#include "wlan_if.h"
#include "compiler.h"

#ifdef PLATFORM_ALLWIN_RT_THREAD
#include "wifi_driver_event.h"
#endif

#include "porting.h"
#include "aic_log.h"
#include "rtos_errno.h"

//#define ASSERT_ERR(cond)

/// Console task message queue size
#define WLAN_QUEUE_SIZE    5

/*
 * GLOBAL VARIABLES
 ****************************************************************************************
 */
char network_id[4];
char connecting_ssid[32];
char connecting_psk[32];

// sta connecting AP config
static uint8_t sta_link_cfg[256] = {0};
#ifdef CFG_SOFTAP
uint32_t ap_ip_addr     = (192 | (168 << 8) | (88 << 16) | (1 << 24));
uint32_t ap_subnet_mask = 0x00FFFFFF; //255.255.255.0
uint32_t cfg_ap_bcn_interval = 0;
uint8_t cfg_ap_channel_num = 0;
uint8_t cfg_ap_enable_he_rate = 1;
uint8_t cfg_ap_hidden_ssid = 0;
uint8_t cfg_allow_sta_inactivity_s = 0;
#endif /* CFG_SOFTAP */

uint32_t cfg_sta_connect_chan_num = 0;
static uint8_t netif_initialed = 0;

uint8_t disconnected_by_user = 0;
uint8_t is_fixed_ip = 0;
uint32_t fixed_ip, fixed_gw, fixed_mask;

static int mac_acl_mode;
static int last_mac_acl_mode;

#define WIFI_MAX_STA_NUM	10
#define WIFI_MAC_ADDR_LEN   6

static struct co_list mac_acl_list;

static struct fhost_cntrl_link *sta_cntrl_link;
void set_sta_connect_chan_num(uint32_t chan_num)
{
    cfg_sta_connect_chan_num = chan_num;
}

uint32_t get_sta_connect_chan_freq(void)
{
    bool em_status = false;

    if (cfg_sta_connect_chan_num) {
        if (false == em_status) {
            return phy_channel_to_freq(((cfg_sta_connect_chan_num > 14)?1:0), cfg_sta_connect_chan_num);
        }
    }
    return 0;
}

static int wlan_sta_cfg(uint8_t *ssid, uint8_t *pw, uint8_t is_wep)
{
    int index = 0;
	uint32_t freq = 0;
    if (ssid == NULL) {
        AIC_LOG_PRINTF("NULL SSID\r\n");
        return -1;
    }

    memset(sta_link_cfg, 0, 128);
    memcpy(&(sta_link_cfg[index]), "ssid \"", 6);
    index += 6;
    memcpy(&(sta_link_cfg[index]), ssid, strlen((char *)ssid));
    index += strlen((char *)ssid);
    if((pw == NULL) || (strlen((const char *)pw) == 0) || (is_wep != 0)) {
        AIC_LOG_PRINTF("Open System");
        memcpy(&(sta_link_cfg[index]), "\";key_mgmt NONE", 15);
        index += 15;
    }
    else {
        memcpy(&(sta_link_cfg[index]), "\";key_mgmt WPA-PSK;psk \"", 24);
        index += 24;
        memcpy(&(sta_link_cfg[index]), pw, strlen((char *)pw));
        index += strlen((char *)pw);
        memcpy(&(sta_link_cfg[index]), "\"", 1);
        index +=1;
       // memcpy(&(sta_link_cfg[index]), ";proto RSN", 10);
    }

    if(is_wep) {
        memcpy(&(sta_link_cfg[index]), ";wep_key0 \"", 11);
        index += 11;
        memcpy(&(sta_link_cfg[index]), pw, strlen((char *)pw));
        index += strlen((char *)pw);
        memcpy(&(sta_link_cfg[index]), "\"", 1);
        index +=1;
        memcpy(&(sta_link_cfg[index]), ";wep_tx_keyidx 0;priority 5;auth_alg SHARED", 43);
        index += 43;
    }
    memcpy(&(sta_link_cfg[index]), ";scan_ssid 1", 12);
    index += 12;

    // Frequencies (optional)
    freq = get_sta_connect_chan_freq();
    if (!freq) {
        uint32_t res = snprintf((char *)&(sta_link_cfg[index]), (sizeof(sta_link_cfg) - index), ";scan_freq %d", freq);
        index += res;
    }

    if(index >= sizeof(sta_link_cfg)) {
        AIC_LOG_PRINTF("wlan_sta_init Fail\r\n");
        return -1;
    }
    return 0;
}

/**
 ******************************************************************************
 * @brief Retrieve IP address using DHCP
 *
 * Start DHCP procedure for the specified interface and wait (no timeout) until
 * it is completed.
 *
 * @param[in] net_if Interface on which DHCP must be started
 *
 * @return 0 when ip address has been received amd !=0 an error occured.
 ******************************************************************************
 */
int wlan_dhcp(net_if_t *net_if)
{
    int ret = 0;
    uint32_t ip_addr = 0;
    uint32_t gateway_addr = 0;

#if 0
    #if 0//ndef CFG_HOST_COMBO
    #if !PLF_BAND5G
    struct sta_info_tag *sta;
    // Fix rate
    struct vif_info_tag *fhost_vif = fhost_env.vif[0].mac_vif;
    uint8_t staid = INVALID_STA_IDX;
    for (uint8_t i = 0; i < STA_MAX; i ++) {
        sta = &sta_info_tab[i];
        if (sta->valid && MAC_ADDR_CMP(sta->mac_addr.array, vif_info_tab[fhost_vif->index].bss_info.bssid.array)) {
            staid = sta->staid;
            break;
        }
    }

    if (INVALID_STA_IDX != staid)
        fhost_cntrl_cfgrwnx_set_fixed_rate(staid, 0, 0, 2); // 1M
    #endif /* !PLF_BAND5G */
    #endif /* !CFG_HOST_COMBO */

    #if LWIP_IPV4
    if (is_fixed_ip) {
        net_if_set_ip(net_if, fixed_ip, fixed_mask, fixed_gw);
    } else {
        sleep_prevent_set(SLEEP_PREVENT_LWIP_DHCP);
        // Run DHCP client
        if (net_dhcp_start(net_if)) {
            AIC_LOG_PRINTF("Failed to start DHCP\r\n");
            ret = -1;
            goto exit;
        }
        uint32_t dhcp_start_time = sys_now();
        while (net_dhcp_start_status() && net_dhcp_address_obtained(net_if)) {
            if(sys_now() - dhcp_start_time > 30000) {
                net_dhcp_stop(net_if);
                AIC_LOG_PRINTF("DHCP Timeout \r\n");
                ret = -1;
                goto exit;
            }

            rtos_task_suspend(200);
        }

        if (!(net_dhcp_start_status())) {
            ret = -1;
            goto exit;
        }
    }

    update_etharp_table(net_if, netif_ip4_addr(net_if));

    sleep_prevent_clr(SLEEP_PREVENT_LWIP_DHCP);
    net_if_get_ip(net_if, &ip_addr, NULL, &gateway_addr);
    #endif

    AIC_LOG_PRINTF("DHCP completed: ip=%d.%d.%d.%d gw=%d.%d.%d.%d\r\n",
          ip_addr & 0xff, (ip_addr >> 8) & 0xff,
          (ip_addr >> 16) & 0xff, (ip_addr >> 24) & 0xff,
          gateway_addr & 0xff, (gateway_addr >> 8) & 0xff,
          (gateway_addr >> 16) & 0xff, (gateway_addr >> 24) & 0xff);

exit:
    #if 0//ndef CFG_HOST_COMBO
    #if !PLF_BAND5G
    if (INVALID_STA_IDX != staid)
        fhost_cntrl_cfgrwnx_set_fixed_rate(staid, 0x1F, 0x1FF, 0x3);
    #endif /* !PLF_BAND5G */
    #endif /* !CFG_HOST_COMBO */
#endif
    return ret;
}
static uint32_t net_id = 0;
static void wlan_re_dhcp(wifi_mac_status_e st)
{
    AIC_LOG_PRINTF("wlan_re_dhcp %d\r\n", st);
    if (WIFI_MAC_STATUS_DISCONNECTED == st) {
        // TODO:
    } else {
        if (net_dhcp_start(net_id)) {
            wlan_connected = 0;
            AIC_LOG_PRINTF("dhcp fail, wait connect ...\r\n");
        } else {
            wlan_connected = 1;
        }
    }
}

bool time_out_flag = false;

int wlan_sta_connect(uint8_t *ssid, uint8_t *pw, int timeout_ms)
{
	int fhost_vif_idx = 0;
	int to_ms = 10000;
	int ret = -1;

	AIC_LOG_PRINTF("Connect Wi-Fi: %s, %s", ssid, pw);
	memset(connecting_ssid, 0x0, sizeof(connecting_ssid));
	memset(connecting_psk, 0x0, sizeof(connecting_psk));

    if (pw && (strlen((const char *)pw)) && (strlen((const char *)pw) < 8)) {
        AIC_LOG_PRINTF("Err: password < 8");
		ret = -1;
		goto fail;
    }

	if((timeout_ms > 0)&&(timeout_ms & CO_BIT(0))) { // is wep
		wlan_sta_cfg(ssid, pw, 1);
	} else {
		wlan_sta_cfg(ssid, pw, 0);
	}

	if((timeout_ms != 0) && (timeout_ms != 1))
		to_ms = timeout_ms;

	// Connect to access point
	if (fhost_wpa_create_network(fhost_vif_idx, (char *)sta_link_cfg, true, to_ms))
	{
		extern wifi_drv_event_cbk aw_aic_wifi_event_cb;
		AIC_LOG_PRINTF("fhost_wpa_create_network fail");
		 if (time_out_flag) {
			if (aw_aic_wifi_event_cb) {
				wifi_drv_event drv_event;
				struct wifi_sta_event dev_event;
				dev_event.event_type = WIFI_STA_EVENT_ON_ASSOC_FAIL;
				drv_event.type = WIFI_DRV_EVENT_STA;
				drv_event.node.sta_event = dev_event;
				aw_aic_wifi_event_cb(&drv_event);
			}
			time_out_flag = false;
		}
		 ret = -3;
		goto fail;
	}

	wlan_connected = 1;
	strcat(connecting_ssid, ssid);
	strcat(connecting_psk, pw);
	int fhost_wpa_sta_not_autoconnect(int fhost_vif_idx);
	fhost_wpa_sta_not_autoconnect(0);

	return 0;
fail:
	wlan_connected = 0;
	return ret;

}

int wlan_start_sta(uint8_t *ssid, uint8_t *pw, int timeout_ms)
{
    net_if_t *net_if = NULL;
    int fhost_vif_idx = 0;
    int to_ms = 10000;

	if(aic_wifi_get_mode() == WIFI_MODE_STA)
	{
		return 0;
	}
    AIC_LOG_PRINTF("Connect Wi-Fi: %s, %s\r\n", ssid, pw);

    if(pw && (strlen((const char *)pw)) && (strlen((const char *)pw) < 8)) {
        AIC_LOG_PRINTF("Err: password < 8\r\n");
        return -1;
    }

    //ipc_host_cntrl_start();
    struct fhost_vif_tag *fhost_vif;
    fhost_vif = &fhost_env.vif[fhost_vif_idx];
    if (0 == netif_initialed) {
        net_if_init(&fhost_vif->net_if);
        net_if_add(&fhost_vif->net_if, NULL, NULL, NULL, fhost_vif);
        netif_initialed = 1;
    }
    net_id = net_init();

    sta_cntrl_link = fhost_cntrl_cfgrwnx_link_open();
    if (sta_cntrl_link == NULL) {
        AIC_LOG_PRINTF("Failed to open link\n");
        //ASSERT_ERR(0);
    }

    // Reset STA interface (this will end previous wpa_supplicant task)
    if (fhost_set_vif_type(sta_cntrl_link, fhost_vif_idx, VIF_UNKNOWN, false) ||
        fhost_set_vif_type(sta_cntrl_link, fhost_vif_idx, VIF_STA, false)) {
        fhost_cntrl_cfgrwnx_link_close(sta_cntrl_link);
        return -2;
    }

    fhost_cntrl_cfgrwnx_link_close(sta_cntrl_link);

	fhost_tx_task_init();
    /*
    if((timeout_ms > 0)&&(timeout_ms & CO_BIT(0))) { // is wep
        wlan_sta_cfg(ssid, pw, 1);
    } else {
        wlan_sta_cfg(ssid, pw, 0);
    }

   if((timeout_ms != 0) && (timeout_ms != 1))
        to_ms = timeout_ms;

    // Connect to access point
    if (fhost_wpa_create_network(fhost_vif_idx, (char *)sta_link_cfg, true, to_ms)) {
        AIC_LOG_PRINTF("fhost_wpa_create_network fail\r\n");
        return -3;
    }
    */
    //fhost_cntrl_mm_set_filter(0X3503848C); // Bit8 (acceptProbeReq) 1 -> 0

    // Get the first network interface (created by CNTRL task).
    net_if = net_if_find_from_wifi_idx(fhost_vif_idx);
    if (net_if == NULL) {
        AIC_LOG_PRINTF("[AIC] net_if_find_from_wifi_idx fail\r\n");
        return -4;
    }

//    if(!netif_is_up(net_if)) {
//        AIC_LOG_PRINTF("[AIC] netif_is_down\r\n");
//        return -5;
//    }

    // use this interface as default
    net_if_set_default(net_if);

    #if 0
    // Start DHCP client to retrieve ip address
    if (net_dhcp_start(net_id)) {
        AIC_LOG_PRINTF("[AIC] dhcp fail\r\n");
        fhost_reconnect_dhcp_register(wlan_re_dhcp);
        if (-1 != timeout_ms) {
            wlan_disconnect_sta((uint8_t)fhost_vif_idx);
        }
        return -6;
    } else {
        fhost_reconnect_dhcp_register(wlan_re_dhcp);
    }
    #endif

    //wlan_connected = 1;
    aic_wifi_set_mode(WIFI_MODE_STA);
    return net_id;
}
#if 0
int wlan_start_wps(void)
{
    net_if_t *net_if = NULL;
    int fhost_vif_idx = 0;

    set_mac_address(NULL);

    ipc_host_cntrl_start();

    sta_cntrl_link = fhost_cntrl_cfgrwnx_link_open();
    if (sta_cntrl_link == NULL) {
        AIC_LOG_PRINTF(D_ERR "Failed to open link\n");
        ASSERT_ERR(0);
    }

    // Reset STA interface (this will end previous wpa_supplicant task)
    if (fhost_set_vif_type(sta_cntrl_link, fhost_vif_idx, VIF_UNKNOWN, false) ||
        fhost_set_vif_type(sta_cntrl_link, fhost_vif_idx, VIF_STA, false))
        return -1;

    fhost_cntrl_cfgrwnx_link_close(sta_cntrl_link);

    // Get the first network interface (created by CNTRL task).
    net_if = net_if_find_from_wifi_idx(fhost_vif_idx);
    if (net_if == NULL) {
        AIC_LOG_PRINTF("[AIC] net_if_find_from_wifi_idx fail\r\n");
        return 1;
    }

#if (PLF_BT_STACK || PLF_BLE_STACK) && (PLF_WIFI_STACK)
    if(wb_coex_bt_connected_get()) {
        if(wb_coex_bt_a2dp_on_get() || wb_coex_bt_sco_on_get()) {
            rwnx_set_disable_agg_req(1, 0xFF);
            rwnx_set_coex_config_req(1, 1, 1, 1, 0x01800100, 0x0);
        }
    }
#endif
    // Connect to access point
    if (fhost_wpa_wps(fhost_vif_idx, true, -1))
        return 2;

    // Start DHCP client to retrieve ip address
    if (wlan_dhcp(net_if)) {
        wlan_disconnect_sta((uint8_t)fhost_vif_idx);
        AIC_LOG_PRINTF("[AIC] dhcp fail\r\n");
        return 3;
    }

    // Now that we got an IP address use this interface as default
    net_if_set_default(net_if);

    return 0;
}
#endif

int wlan_disconnect_sta(uint8_t idx)
{
    net_if_t *net_if = NULL;
    struct vif_info_tag *mac_vif = fhost_to_mac_vif(idx);

    //fhost_cntrl_mm_set_filter(0X35038188); // Not rx beacons

    // Get the first network interface (created by CNTRL task).
    net_if = net_if_find_from_wifi_idx(idx);
    if (net_if == NULL) {
        AIC_LOG_PRINTF("[AIC] net_if_find_from_wifi_idx fail\r\n");
        return 0;
    }
    disconnected_by_user = 1;

    if (mac_vif->u.sta.ap_id != INVALID_STA_IDX) {
        fhost_tx_do_sta_del(mac_vif->u.sta.ap_id );
    }
    #if (AICWF_RX_REORDER)
    reord_deinit_sta_by_mac((uint8_t *)get_mac_address());
    #endif
    fhost_wpa_disconnect_network(idx);
    fhost_wpa_end(idx);
    fhost_reconnect_dhcp_register(NULL);
    fhost_tx_task_deinit();
    //fhost_wpa_kill();
    mac_vif->active = false;
    mac_vif->type   = VIF_UNKNOWN;
    net_deinit();
	aic_wifi_set_mode(WIFI_MODE_UNKNOWN);
	memset(connecting_ssid, 0x0, sizeof(connecting_ssid));
	memset(connecting_psk, 0x0, sizeof(connecting_psk));

    return 0;
}

int wlan_get_connect_status(void)
{
    return wlan_connected;
}

int wlan_sta_get_connect_info(char *ssid, char *psk)
{
	int ret = -1;
	if(ssid == NULL || psk == NULL)
		return ret;
    strcat(ssid, connecting_ssid);
    strcat(psk, connecting_psk);
	return 0;
}

#ifdef CFG_P2P
static struct fhost_cntrl_link *p2p_cntrl_link;
extern uint8_t p2p_started;
extern char* custom_vendor_ie;

int wlan_start_p2p(struct aic_p2p_cfg *user_cfg)
{
    struct fhost_vif_p2p_cfg cfg;
    int offset = 0;

    //struct fhost_vif_ip_addr_cfg ip_cfg;
    int fhost_vif_idx = 0;
    struct fhost_vif_tag *fhost_vif;
    static uint32_t net_id;

    if (p2p_started) {
        AIC_LOG_PRINTF("P2P already started\r\n");
        fhost_vif = &fhost_env.vif[fhost_vif_idx];
        net_id = 0;//fhost_vif->net_if.net_id;
        return net_id;
    }

    memset(&cfg, 0, sizeof(cfg));

    //ssid
    size_t ssid_len = user_cfg->aic_p2p_ssid.length;
    if (ssid_len > sizeof(cfg.ssid.array))
    {
        AIC_LOG_PRINTF("Invalid SSID\r\n");
        return 1;
    }

    memcpy(cfg.ssid.array, user_cfg->aic_p2p_ssid.array, ssid_len);
    cfg.ssid.length = ssid_len;

    if (user_cfg->aic_ap_passwd.length) {
        memcpy(cfg.key, user_cfg->aic_ap_passwd.array, user_cfg->aic_ap_passwd.length);
    }


    struct mac_chan_def *chan = NULL;
    if ((user_cfg->band == 0) && (user_cfg->channel == 0)) {
        cfg.chan.band = PHY_BAND_2G4;
        cfg.chan.prim20_freq = phy_channel_to_freq(PHY_BAND_2G4, 11);
    } else {
        cfg.chan.band = user_cfg->band;
        cfg.chan.prim20_freq = phy_channel_to_freq(user_cfg->band, user_cfg->channel);
    }
    if (user_cfg->type == PHY_CHNL_BW_40) {
        uint8_t k = 0, found = 0;
        cfg.chan.type = PHY_CHNL_BW_40;
        if (user_cfg->band == PHY_BAND_5G) {
            int band5g_above_allowed[12] = {36,44,52,60,100,108,116,124,132,140,149,157};
            int band5g_below_allowed[11] = {40,48,56,64,104,112,120,128,136,153,161};
            for (k = 0; k < (sizeof(band5g_above_allowed) / sizeof(int)); k++) {
                //HT40+
                if (user_cfg->channel == band5g_above_allowed[k]) {
                    offset = 10;
                    found = 1;
                    break;
                }
            }
            if (found == 0) {
                //HT40-
                for (k = 0; k < (sizeof(band5g_below_allowed) / sizeof(int)); k++) {
                    if (user_cfg->channel == band5g_below_allowed[k]) {
                        offset = -10;
                        found = 1;
                        break;
                    }
                }
            }
            if (found == 0) {
                cfg.chan.type = PHY_CHNL_BW_20; //20M only
            }
        }else {
            if (user_cfg->channel < 5) {
                offset = 10;
             } else if (user_cfg->channel > 9) {
                offset = -10;
            } else {
                offset = 10;
            }
        }
        if(user_cfg->enable_acs) {
            offset = 10;
        }
    }else {
        cfg.chan.type = PHY_CHNL_BW_20;
    }

     if (!user_cfg->enable_acs) {
        chan = fhost_chan_get(cfg.chan.prim20_freq);
        if (!chan)
        {
            AIC_LOG_PRINTF("Invalid channel %d\n", cfg.chan.prim20_freq);
            return 1;
        }
    }

    cfg.chan.center1_freq = cfg.chan.prim20_freq + offset;
    cfg.enable_he = user_cfg->enable_he;
    cfg.enable_acs = user_cfg->enable_acs;
    #ifdef CONFIG_VENDOR_IE
    cfg.vendor_ie = custom_vendor_ie;
    #endif
    if (fhost_vif_idx < 0)
        return 2;

    if ((cfg.ssid.length == 0))
        return 3;

    fhost_vif = &fhost_env.vif[fhost_vif_idx];
    if (0 == netif_initialed) {
       net_if_init(&fhost_vif->net_if);
        net_if_add(&fhost_vif->net_if, NULL, NULL, NULL, fhost_vif);
          netif_initialed = 1;
    }
    net_id = net_init();
    AIC_LOG_PRINTF("net_id %x registered\n", net_id);
    //fhost_vif->net_if.net_id = (int)net_id;

    #ifdef PLATFORM_SUNPLUS_ECOS
    init_loopback_interface(0);
    #endif
    p2p_cntrl_link = fhost_cntrl_cfgrwnx_link_open();
    if (p2p_cntrl_link == NULL) {
        AIC_LOG_PRINTF("Failed to open link with control task\n");
        //ASSERT_ERR(0);
    }

    // (Re)Set interface type to AP for P2P_GO
    if (fhost_set_vif_type(p2p_cntrl_link, fhost_vif_idx, VIF_UNKNOWN, true) ||
        fhost_set_vif_type(p2p_cntrl_link, fhost_vif_idx, VIF_AP, true)) {
        fhost_cntrl_cfgrwnx_link_close(p2p_cntrl_link);
        return 1;
    }
    fhost_cntrl_cfgrwnx_link_close(p2p_cntrl_link);

    MAC_ADDR_CPY(&(vif_info_tab[fhost_vif_idx].mac_addr), &(fhost_vif->mac_addr));

    if (fhost_p2p_cfg(fhost_vif_idx, &cfg))
    {
        printf("Failed to start P2P!\n");
        AIC_LOG_PRINTF("Failed to start P2P, check your configuration");
        return 1;
    }

    p2p_started = 1;
	__log("p2p start xxxxxxxxxxxxxx p2p_started=1");

    //fhost_cntrl_mm_set_filter(0X3507838C);

    fhost_tx_task_init();

    return net_id;

}

int wlan_stop_p2p(void)
{
    int fhost_vif_idx = 0;

    if(!p2p_started) {
        return -1;
    }

    struct fhost_vif_tag *fhost_vif = &fhost_env.vif[fhost_vif_idx];

    net_if_set_ip((fhost_to_net_if(fhost_vif_idx)), 0, 0, 0);
    fhost_wpa_stop_p2p(fhost_vif_idx);
    fhost_wpa_end(fhost_vif_idx);

    fhost_vif->mac_vif->active = false;
    fhost_vif->mac_vif->type   = VIF_UNKNOWN;

    fhost_tx_task_deinit();
    //fhost_wpa_kill();
    p2p_started = 0;
    net_deinit();
	aic_wifi_set_mode(WIFI_MODE_UNKNOWN);

    return 0;
}

#endif

#ifdef CFG_SOFTAP
static struct fhost_cntrl_link *ap_cntrl_link = NULL;
static uint8_t softap_started = 0;
/**
 ****************************************************************************************
 * @brief Find the first valid network interface.
 *
 * @return Index of the FHOST wifi interface.
 ****************************************************************************************
 */
static int fhost_search_first_valid_itf(void)
{
    unsigned int idx;
    net_if_t *net_if = NULL;

    for (idx = 0; idx < NX_VIRT_DEV_MAX; idx++)
    {
      net_if = net_if_find_from_wifi_idx(idx);
      if (net_if)
          break;
    }

    if (idx == NX_VIRT_DEV_MAX)
        return -1;

    return idx;
}
void set_ap_channel_num(uint8_t num)
{
    cfg_ap_channel_num = num;
}
uint8_t get_ap_channel_num(void)
{
    return cfg_ap_channel_num;
}
void set_ap_enable_he_rate(uint8_t en)
{
    cfg_ap_enable_he_rate = en;
}
uint8_t get_ap_enable_he_rate(void)
{
    return cfg_ap_enable_he_rate;
}
void set_ap_hidden_ssid(uint8_t val)
{
    cfg_ap_hidden_ssid = val;
}
uint8_t get_ap_hidden_ssid(void)
{
    return cfg_ap_hidden_ssid;
}
void set_ap_allow_sta_inactivity_s(uint8_t s)
{
    cfg_allow_sta_inactivity_s = s;
}
uint8_t get_ap_allow_sta_inactivity_s(void)
{
    return cfg_allow_sta_inactivity_s;
}

void set_ap_ip_addr(uint32_t new_ip_addr)
{
    ap_ip_addr = new_ip_addr;
}
uint32_t get_ap_ip_addr(void)
{
    return ap_ip_addr;
}

void set_ap_subnet_mask(uint32_t new_mask)
{
    ap_subnet_mask = new_mask;
}
uint32_t get_ap_subnet_mask(void)
{
    return ap_subnet_mask;
}

void set_ap_bcn_interval(uint32_t bcn_interval_ms)
{
    cfg_ap_bcn_interval = bcn_interval_ms;
}
uint32_t get_ap_bcn_interval(void)
{
    return cfg_ap_bcn_interval;
}
uint8_t get_ap_enable_vht_80(void)
{
    return fhost_config_value_get(FHOST_CFG_80MHZ);
}
int wlan_start_ap(struct aic_ap_cfg *user_cfg)
{
    #if NX_BEACONING
    struct fhost_vif_ap_cfg cfg;
    int offset = 0;
    int res = 0;
    int net_id = 0;

    //struct fhost_vif_ip_addr_cfg ip_cfg;
    int fhost_vif_idx = 0;//fhost_search_first_valid_itf();
    struct fhost_vif_tag *fhost_vif;

retry:
    AIC_LOG_PRINTF("%s ssid:%s pw:%s band:%d type:%d ch:%d hid:%d max_inactive:%d he:%d acs:%d bcn:%d security:%d sta:%d\n",
        __func__, user_cfg->aic_ap_ssid.array, user_cfg->aic_ap_passwd.array, user_cfg->band, user_cfg->type,
        user_cfg->channel, user_cfg->hidden_ssid, user_cfg->max_inactivity, user_cfg->enable_he, user_cfg->enable_acs,
        user_cfg->bcn_interval, user_cfg->sercurity_type, user_cfg->sta_num);

    if (softap_started) {
        AIC_LOG_PRINTF("AP already started\r\n");
        fhost_vif = &fhost_env.vif[fhost_vif_idx];
        net_id = 0;//fhost_vif->net_if.net_id;
        goto exit;
    }

    if ((user_cfg->band == PHY_BAND_5G) && (aicwf_is_5g_enable() == 0)) {
        AIC_LOG_PRINTF("Err: try to use 5G while 5G is disabled\n");
        res = -1;
        goto exit;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.akm =  CO_BIT(MAC_AKM_NONE);

    if ((user_cfg->sta_num > 0) && (user_cfg->sta_num <= NX_REMOTE_STA_MAX)) {
        cfg.sta_num = user_cfg->sta_num;
    } else {
        AIC_LOG_PRINTF("Error: invalid sta_num:%d\n", user_cfg->sta_num);
        res = -2;
        goto exit;
    }

    //ssid
    size_t ssid_len = user_cfg->aic_ap_ssid.length;
    if (ssid_len > sizeof(cfg.ssid.array))
    {
        AIC_LOG_PRINTF("Invalid SSID\r\n");
        res = -3;
        goto exit;
    }

    if (user_cfg->sercurity_type == KEY_NONE) {
        cfg.akm = CO_BIT(MAC_AKM_NONE);
    } else if (user_cfg->sercurity_type == KEY_WEP) {
        cfg.akm = CO_BIT(MAC_AKM_PRE_RSN);
    } else if (user_cfg->sercurity_type == KEY_WPA) {
        cfg.akm = CO_BIT(MAC_AKM_PRE_RSN);
        cfg.unicast_cipher = MAC_CIPHER_TKIP;
    } else if (user_cfg->sercurity_type == KEY_WPA2) {
        cfg.akm = CO_BIT(MAC_AKM_PSK);
    } else if (user_cfg->sercurity_type == KEY_WPA3) {
        cfg.akm = CO_BIT(MAC_AKM_SAE);
        cfg.mfp = 2;
    }

    memcpy(cfg.ssid.array, user_cfg->aic_ap_ssid.array, ssid_len);
    cfg.ssid.length = ssid_len;

    //pw
    if (user_cfg->aic_ap_passwd.length) {
        if (user_cfg->sercurity_type == KEY_NONE) {
            cfg.akm = CO_BIT(MAC_AKM_PSK);
        }
        memcpy(cfg.key, user_cfg->aic_ap_passwd.array, user_cfg->aic_ap_passwd.length);
    }

    struct mac_chan_def *chan = NULL;
    if ((user_cfg->enable_acs == 0) && (user_cfg->channel == 0)) {
        if (user_cfg->band == 0) {
            cfg.chan.band = PHY_BAND_2G4;
            cfg.chan.prim20_freq = phy_channel_to_freq(PHY_BAND_2G4, 11);
            set_ap_channel_num(11);
        } else {
            cfg.chan.band = PHY_BAND_5G;
            cfg.chan.prim20_freq = phy_channel_to_freq(PHY_BAND_5G, 36);
            set_ap_channel_num(36);
        }
    } else {
        cfg.chan.band = user_cfg->band;
        cfg.chan.prim20_freq = phy_channel_to_freq(user_cfg->band, user_cfg->channel);
    }

    #if defined(CONFIG_AIC8800D80)
    if ((user_cfg->band == PHY_BAND_5G) && (get_ap_enable_vht_80())) {
        cfg.chan.type = PHY_CHNL_BW_80;
        int band5g_bw80_center_chan_ava[] = {42, 58, 106, 122, 155};
        int cnt = sizeof(band5g_bw80_center_chan_ava) / sizeof(int);
        int prim_chan = get_ap_channel_num();
        int cent_chan, chan_valid = 0;
        int idx;
        for (idx = 0; idx < cnt; idx++) {
            cent_chan = band5g_bw80_center_chan_ava[idx];
            if (prim_chan < cent_chan) {
                if ((prim_chan == (cent_chan - 2)) || (prim_chan == (cent_chan - 6))) {
                    chan_valid = 1;
                }
                break;
            }
            else if (prim_chan < (cent_chan + 8)) {
                if ((prim_chan == (cent_chan + 2)) || (prim_chan == (cent_chan + 6))) {
                    chan_valid = 1;
                }
                break;
            }
        }
        if (chan_valid) {
            offset = (cent_chan - prim_chan) * 5;
        } else {
            cfg.chan.type = PHY_CHNL_BW_20; //20M only
        }
    }
    else
    #endif /* CONFIG_AIC8800D80 */
    if (user_cfg->type == PHY_CHNL_BW_40) {
        uint8_t k = 0, found = 0;
        cfg.chan.type = PHY_CHNL_BW_40;
        if (user_cfg->band == PHY_BAND_5G) {
            int band5g_above_allowed[12] = {36,44,52,60,100,108,116,124,132,140,149,157};
            int band5g_below_allowed[11] = {40,48,56,64,104,112,120,128,136,153,161};
            for (k = 0; k < (sizeof(band5g_above_allowed) / sizeof(int)); k++) {
                //HT40+
                if (user_cfg->channel == band5g_above_allowed[k]) {
                    offset = 10;
                    found = 1;
                    break;
                }
            }
            if (found == 0) {
                //HT40-
                for (k = 0; k < (sizeof(band5g_below_allowed) / sizeof(int)); k++) {
                    if (user_cfg->channel == band5g_below_allowed[k]) {
                        offset = -10;
                        found = 1;
                        break;
                    }
                }
            }
            if (found == 0) {
                cfg.chan.type = PHY_CHNL_BW_20; //20M only
            }
        }else {
            if (user_cfg->channel < 5) {
                offset = 10;
             } else if (user_cfg->channel > 9) {
                offset = -10;
            } else {
                offset = 10;
            }
        }
        if(user_cfg->enable_acs) {
            offset = 10;
        }
    }else {
        cfg.chan.type = PHY_CHNL_BW_20;
    }

    cfg.bcn_interval = user_cfg->bcn_interval;

    if (!user_cfg->enable_acs) {
        chan = fhost_chan_get(cfg.chan.prim20_freq);
        if (!chan)
        {
            AIC_LOG_PRINTF("Err: Invalid channel %d\n", cfg.chan.prim20_freq);
            res = -4;
            goto exit;
        }
    }

    cfg.chan.center1_freq = cfg.chan.prim20_freq + offset;

    cfg.hidden_ssid = user_cfg->hidden_ssid;
    cfg.enable_he = user_cfg->enable_he;
    cfg.max_inactivity = user_cfg->max_inactivity;
    cfg.enable_acs = user_cfg->enable_acs;
    #ifdef CONFIG_VENDOR_IE
    cfg.vendor_ie = custom_vendor_ie;
    #endif

    if (fhost_vif_idx < 0) {
        AIC_LOG_PRINTF("Err: Invalid fhost_vif_idx %d\n", fhost_vif_idx);
        res = -5;
        goto exit;
    }

    if ((cfg.ssid.length == 0) || ((cfg.enable_acs == 0) && (cfg.chan.prim20_freq == 0))) {
        AIC_LOG_PRINTF("Err: ssid.length:%d prim20_freq:%d\n", cfg.ssid.length, cfg.chan.prim20_freq);
        res = -6;
        goto exit;
    }

    fhost_vif = &fhost_env.vif[fhost_vif_idx];
    if (0 == netif_initialed) {
        net_if_init(&fhost_vif->net_if);
        net_if_add(&fhost_vif->net_if, NULL, NULL, NULL, fhost_vif);
        netif_initialed = 1;
    }
    net_id = net_init();
    AIC_LOG_PRINTF("net_id %x registered\n", net_id);
    //fhost_vif->net_if.net_id = (int)net_id;

    #ifdef PLATFORM_SUNPLUS_ECOS
    init_loopback_interface(0);
    #endif
    if (ap_cntrl_link == NULL) {
        ap_cntrl_link = fhost_cntrl_cfgrwnx_link_open();
    }
    if (ap_cntrl_link == NULL) {
        AIC_LOG_PRINTF("Failed to open link with control task\n");
        res = -7;
        goto exit;
    }

    // Save IP configuration (if any)
    //fhost_get_vif_ip(fhost_vif_idx, &ip_cfg);

    // (Re)Set interface type to AP
    if (fhost_set_vif_type(ap_cntrl_link, fhost_vif_idx, VIF_UNKNOWN, false) ||
        fhost_set_vif_type(ap_cntrl_link, fhost_vif_idx, VIF_AP, false)) {
        fhost_cntrl_cfgrwnx_link_close(ap_cntrl_link);
        ap_cntrl_link = NULL;
        res = -8;
        goto exit;
    }
    fhost_cntrl_cfgrwnx_link_close(ap_cntrl_link);
    ap_cntrl_link = NULL;

    MAC_ADDR_CPY(&(vif_info_tab[fhost_vif_idx].mac_addr), &(fhost_vif->mac_addr));
    fhost_tx_task_init();

    if (fhost_ap_cfg(fhost_vif_idx, &cfg))
    {
        if (user_cfg->enable_acs) {
            chan = fhost_chan_get(phy_channel_to_freq(user_cfg->band, user_cfg->channel));
            if (chan)
            {
                user_cfg->enable_acs = 0;
                goto retry;
            }
        }
        fhost_tx_task_deinit();
        AIC_LOG_PRINTF("Failed to start AP, check your configuration");
        res = -9;
        goto exit;
    }

    //fhost_cntrl_mm_set_filter(0X3507838C);

    //AIC_LOG_PRINTF("DHCPS init: ip=%d.%d.%d.%d\r\n",
    //      (ip_addr)&0xFF, (ip_addr>>8)&0xFF, (ip_addr>>16)&0xFF, (ip_addr>>24)&0xFF);

    wlan_ap_mac_acl_init();

    softap_started = 1;

exit:
    AIC_LOG_PRINTF("%s res:%d\n", __func__, res);

    return net_id;

    #endif // NX_BEACONING
}

int wlan_stop_ap(void)
{
    int fhost_vif_idx = 0;

    if(!softap_started) {
        return -1;
    }

    uint32_t ip_mask = 0x0;
    uint32_t ip_addr = 0;
    struct fhost_vif_tag *fhost_vif = &fhost_env.vif[fhost_vif_idx];

    net_if_set_ip((fhost_to_net_if(fhost_vif_idx)), ip_addr, ip_mask, 0);
    fhost_wpa_stop_ap(fhost_vif_idx);
    fhost_wpa_end(fhost_vif_idx);

    fhost_vif->mac_vif->active = false;
    fhost_vif->mac_vif->type   = VIF_UNKNOWN;

    fhost_tx_task_deinit();
    //fhost_wpa_kill();
    wlan_ap_mac_acl_deinit();
    softap_started = 0;
    net_deinit();

    return 0;
}

int wlan_ap_disassociate_sta(struct mac_addr *macaddr)
{
    int fhost_vif_idx = 0;
    struct vif_info_tag *mac_vif = fhost_to_mac_vif(fhost_vif_idx);
    uint8_t sta_idx = vif_mgmt_get_staid(mac_vif, macaddr);

    aic_dbg("wlan_ap_disassociate_sta %d\r\n", sta_idx);
    if (sta_idx == INVALID_STA_IDX) {
        return -1;
    }

    fhost_tx_flush_txq(sta_idx);
    #ifdef CONFIG_FHOST_TX_SCHEDULE_SEPERATE
    #ifdef CONFIG_FHOST_TX_AC_SCHEDULE
    fhost_tx_ac_flush_sta(macaddr);
    #else
    fhost_tx_list_flush_sta(macaddr);
    #endif
    #endif

    return fhost_wpa_disassociate_sta(fhost_vif_idx, macaddr);
}

int wlan_ap_switch_channel(uint8_t chan_num)
{
    int fhost_vif_idx = 0;

    //if(!softap_started) {
    //    return -1;
    //}
    uint32_t freq = 2412;

    if(chan_num <= 14) {
        freq = phy_channel_to_freq(PHY_BAND_2G4, chan_num);
    } else {
        freq = phy_channel_to_freq(PHY_BAND_5G, chan_num);
    }

    return fhost_wpa_switch_channel(fhost_vif_idx, freq);
}
int phy_freq_to_channel(uint8_t band, uint16_t freq)
{
    int channel = 0;

    do
    {
        //2.4.GHz
        if (band == PHY_BAND_2G4)
        {
            // Check if frequency is in the expected range
            if ((freq < 2412) || (freq > 2484))
                break;

            // Compute the channel number
            if (freq == 2484)
                channel = 14;
            else
                channel = (freq - 2407)/5;
        }
        //5 GHz
        else if (band == PHY_BAND_5G)
        {
            // Check if frequency is in the expected range
            if ((freq < 5005) || (freq > 5825))
                break;

            // Compute the channel number
            channel = (freq - PHY_FREQ_5G)/5;
        }
    } while(0);

    return (channel);
}

uint16_t phy_channel_to_freq(uint8_t band, int channel)
{
    if ((band == PHY_BAND_2G4) && (channel >= 1) && (channel <= 14))
    {
        if (channel == 14)
            return 2484;
        else
            return 2407 + channel * 5;
    }
    else if ((band == PHY_BAND_5G) && (channel >= 1) && (channel <= 165))
    {
        return PHY_FREQ_5G + channel * 5;
    }
    return 0;
}
void wlan_if_scan_open(void)
{
    struct aic_sta_cfg cfg = {0};
    memcpy(cfg.aic_ap_ssid.array, "scan", 4);
    cfg.aic_ap_ssid.array[4] = '\0';
    cfg.aic_ap_ssid.length = 4;
    cfg.aic_ap_passwd.length = 0;
    aic_wifi_init(WIFI_MODE_UNKNOWN, 0, &cfg);

}
void wlan_if_scan(void)
{
    int nb_res, fvif_idx = 1;//shire  该参数为零时，扫描会断开已连接WiFi
    struct fhost_cntrl_link *link = NULL;
    link = fhost_cntrl_cfgrwnx_link_open();
    if (link == NULL) {
        aic_dbg("Failed to open link with control task\n");
        return;
    }
    // Reset STA interface (this will end previous wpa_supplicant task)
    if (fhost_set_vif_type(link, fvif_idx, VIF_UNKNOWN, false) ||
        fhost_set_vif_type(link, fvif_idx, VIF_STA, false)) {
        fhost_cntrl_cfgrwnx_link_close(link);
        aic_dbg("Failed to set vif type\n");
        return;
    }

    nb_res = fhost_scan(link, fvif_idx, NULL);
    fhost_cntrl_cfgrwnx_link_close(link);
}

void wlan_if_getscan(wifi_ap_list_t *ap_list, bool show)
{
	int tu_res = 0;
    int nb_res = 0;
    struct mac_scan_result result;
    struct fhost_cntrl_link *link1 = NULL;
    link1 = fhost_cntrl_cfgrwnx_link_open();
    if (link1 == NULL) {
        aic_dbg("Failed to open link with control task\n");
        return;
    }

    while(fhost_get_scan_results(link1, nb_res++, 1, &result)) {
        result.ssid.array[result.ssid.length] = '\0'; // set ssid string ending
		//滤除空ssid的wifi
		if(strlen(result.ssid.array) == 0 || (result.ssid.length == 0))
		{
			continue;
		}
        #if 0
        aic_dbg("(%3d dBm) CH=%3d BSSID=%02x:%02x:%02x:%02x:%02x:%02x SSID=%s\n",
            (int8_t)result.rssi, phy_freq_to_channel(result.chan->band, result.chan->freq),
            ((uint8_t *)result.bssid.array)[0], ((uint8_t *)result.bssid.array)[1],
            ((uint8_t *)result.bssid.array)[2], ((uint8_t *)result.bssid.array)[3],
            ((uint8_t *)result.bssid.array)[4], ((uint8_t *)result.bssid.array)[5],
            (char *)result.ssid.array);
        #endif
            if (nb_res < MAX_AP_COUNT) {
                memcpy(ap_list->ap_info[tu_res].bssid, ((uint8_t *)result.bssid.array), 6);
                memcpy(ap_list->ap_info[tu_res].ssid, ((uint8_t *)result.ssid.array), (result.ssid.length + 1));
                ap_list->ap_info[tu_res].channel = phy_freq_to_channel(result.chan->band, result.chan->freq);
                ap_list->ap_info[tu_res].rssi = result.rssi;
#if 0//在后面排序后打印
                aic_dbg("[%d](%3d dBm) CH=%3d BSSID=%02x:%02x:%02x:%02x:%02x:%02x SSID=%s\n", 
                        (tu_res), (int8_t)ap_list->ap_info[tu_res].rssi, phy_freq_to_channel(result.chan->band, result.chan->freq),
                        ap_list->ap_info[tu_res].bssid[0], ap_list->ap_info[tu_res].bssid[1],
                        ap_list->ap_info[tu_res].bssid[2], ap_list->ap_info[tu_res].bssid[3],
                        ap_list->ap_info[tu_res].bssid[4], ap_list->ap_info[tu_res].bssid[5],
                        (char *)ap_list->ap_info[tu_res].ssid);
#endif
				tu_res++;
            }
    }

	//按信号强弱排序
	{
		int i,j,max;
		wifi_ap_info_t tmp;

		for(i=0; i < tu_res -1; i++)
		{
			max = i;
			for(j = i + 1; j < tu_res; j++)
			{
            	if((int8_t)ap_list->ap_info[max].rssi < (int8_t)ap_list->ap_info[j].rssi)
            	{
            	    max = j;
            	}
			}

			if(max != i)
        	{
				memset(&tmp, 0x0, sizeof(wifi_ap_info_t));
				memcpy(&tmp, &ap_list->ap_info[i], sizeof(wifi_ap_info_t));

				memset(&ap_list->ap_info[i], 0x0, sizeof(wifi_ap_info_t));
				memcpy(&ap_list->ap_info[i], &ap_list->ap_info[max], sizeof(wifi_ap_info_t));

				memset(&ap_list->ap_info[max], 0x0, sizeof(wifi_ap_info_t));
				memcpy(&ap_list->ap_info[max], &tmp, sizeof(wifi_ap_info_t));
        	}
		}

		if(show)
		{
			for(i=0; i<tu_res; i++)
			{
				aic_dbg("[%d](%3d dBm) CH=%3d BSSID=%02x:%02x:%02x:%02x:%02x:%02x SSID=%s\n", 
						(i), (int8_t)ap_list->ap_info[i].rssi, phy_freq_to_channel(result.chan->band, result.chan->freq),
						ap_list->ap_info[i].bssid[0], ap_list->ap_info[i].bssid[1],
						ap_list->ap_info[i].bssid[2], ap_list->ap_info[i].bssid[3],
						ap_list->ap_info[i].bssid[4], ap_list->ap_info[i].bssid[5],
						(char *)ap_list->ap_info[i].ssid);
			}
		}
	}


    /*ap_list->ap_count = nb_res;*/
    ap_list->ap_count = tu_res;
    fhost_cntrl_cfgrwnx_link_close(link1);
}

static int _is_multicast_ether_addr(const u8 *a)
{
	return a[0] & 0x01;
}

static int _is_zero_ether_addr(const u8 *a)
{
	return !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5]);
}

void wlan_if_scan_close(void)
{
    aic_wifi_deinit(WIFI_MODE_UNKNOWN);
}

static struct wifi_mac_node *fetch_mac(struct co_list *list, char *mac)
{
	struct wifi_mac_node *mac_node, *temp;

	/* Loop through list to find the corresponding event */
	mac_node = (struct wifi_mac_node *)co_list_pick(list);

	while (mac_node) {
		if (!memcmp(mac_node->mac, mac, WIFI_MAC_ADDR_LEN))
			return mac_node;
		mac_node = (struct wifi_mac_node *)co_list_next(&mac_node->node);
	}
	return NULL;
}

int wlan_ap_get_mac_acl_mode(void)
{
	return mac_acl_mode;
}

//called in wlan_start_ap
int wlan_ap_mac_acl_init(void)
{
    mac_acl_mode = WIFI_MAC_ACL_DISABLED;
    last_mac_acl_mode = WIFI_MAC_ACL_DISABLED;
    co_list_init(&mac_acl_list);

    return 0;
}

//called in wlan_stop_ap
int wlan_ap_mac_acl_deinit(void)
{
    struct wifi_mac_node *marked_sta = NULL;

    while (1) {
        marked_sta = co_list_pop_front(&mac_acl_list);
        if (marked_sta == NULL) {
            break;
        }
        rtos_free(marked_sta);
    }
    return 0;
}

int wlan_ap_set_mac_acl_mode(char mode)
{
	int size;
	int ret = 0;
	void *dev;
	unsigned char mac[WIFI_MAC_ADDR_LEN];
	struct wifi_mac_node *marked_sta = NULL;
	struct sta_info_tag *tmp, *assoc_sta;

	#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

	if (mode == mac_acl_mode) {
		aic_dbg("MAC ACL mode unchanged!\n");
		return ret;
	}

	switch (mode) {
	case WIFI_MAC_ACL_BLACKLIST:
	case WIFI_MAC_ACL_WHITELIST:
		if (mac_acl_mode != WIFI_MAC_ACL_DISABLED) {
			aic_dbg("already enabled!\n");
			return -1;
		}
	case WIFI_MAC_ACL_DISABLED:
		last_mac_acl_mode = mac_acl_mode;
		mac_acl_mode = mode;
		break;
	default:
		return -EINVAL;
	}

	memset(mac, 0xff, WIFI_MAC_ADDR_LEN);

	if (mac_acl_mode == WIFI_MAC_ACL_WHITELIST) {
		#if 0
		aic_dbg("%s to enable to whitelist \n", __func__);
		ret = wifi_drv_set_mac_acl(dev,
						   WIFI_MAC_ACL_ENABLE,
						   WIFI_MAC_ACL_WHITELIST, 1,
						   mac);
		dl_list_for_each(marked_sta, &mac_acl_list,
				 struct wifi_mac_node, node) {
				 aic_dbg(" add (" MACSTR ") to whitelist\n",
				 	MAC2STR((unsigned char *)marked_sta->mac));
				ret = wifi_drv_set_mac_acl(dev, WIFI_MAC_ACL_ADD,
				   WIFI_MAC_ACL_WHITELIST,
				   1, marked_sta->mac);
		}
		if (ret)
			aic_dbg(MSG_WARNING,"failed to set MAC ACL! %d\n");
		#endif
	} else	if (mac_acl_mode == WIFI_MAC_ACL_BLACKLIST){
		marked_sta = (struct wifi_mac_node *)co_list_pick(&mac_acl_list);
		while (marked_sta) {
			aic_dbg(" add (" MACSTR ") to blacklist\n", MAC2STR((unsigned char *)marked_sta->mac));
			ret = fhost_ap_add_blacklist(0, (char *)marked_sta->mac);
			marked_sta = (struct wifi_mac_node *)co_list_next(&marked_sta->node);
		}
	} else if (mac_acl_mode == WIFI_MAC_ACL_DISABLED) {
		if (last_mac_acl_mode == WIFI_MAC_ACL_WHITELIST) {
			#if 0
			dl_list_for_each(marked_sta, &mac_acl_list,
				 struct wifi_mac_node, node) {
				  aic_dbg(MSG_INFO, " del (" MACSTR ") from whitelist\n",
				 	MAC2STR((unsigned char *)marked_sta->mac));
				ret = wifi_drv_set_mac_acl(dev, WIFI_MAC_ACL_DEL,
				   last_mac_acl_mode,
				   1, marked_sta->mac);
			}
			aic_dbg(MSG_WARNING,"%s to disenable to whitelist \n", __func__);
			ret = wifi_drv_set_mac_acl(dev,
						   WIFI_MAC_ACL_DISABLE,
						   WIFI_MAC_ACL_WHITELIST, 1,
						   mac);
			if (ret)
				aic_dbg(MSG_WARNING,"failed to clear MAC ACL! %d\n");
			#endif
		
		} else if (last_mac_acl_mode == WIFI_MAC_ACL_BLACKLIST){
			marked_sta = (struct wifi_mac_node *)co_list_pick(&mac_acl_list);
			while (marked_sta) {
				aic_dbg(" del (" MACSTR ") from Blaklist\n",
				 	MAC2STR((unsigned char *)marked_sta->mac));

				ret = fhost_ap_delete_blacklist(0, marked_sta->mac);
				marked_sta = (struct wifi_mac_node *)co_list_next(&marked_sta->node);
			}
		}
	}

	if (mac_acl_mode == WIFI_MAC_ACL_WHITELIST) {
		#if 0
		dl_list_for_each_safe(assoc_sta, tmp, &assoc_list,
			      struct wifi_mac_node, node) {
			marked_sta = fetch_mac(&mac_acl_list, assoc_sta->mac);
			if (!marked_sta) {
				aic_dbg(MSG_INFO, "the assoc sta ("MACSTR") not in whitelist , del it",
					MAC2STR((unsigned char *)assoc_sta->mac));
				wifi_ap_del_station(assoc_sta->mac);
			}
		}
		#endif
	} else if (mac_acl_mode == WIFI_MAC_ACL_BLACKLIST) {
		struct vif_info_tag *vif = fhost_to_mac_vif(0);

		assoc_sta = (struct sta_info_tag *)co_list_pick(&vif->sta_list);
		while (assoc_sta) {
			marked_sta = fetch_mac(&mac_acl_list, assoc_sta->mac_addr.array);
			if (marked_sta) {
				aic_dbg("the assoc sta ("MACSTR") in  blacklist , del it\r\n",
					MAC2STR((unsigned char *)assoc_sta->mac_addr.array));
				wlan_ap_disassociate_sta(assoc_sta->mac_addr.array);
			}
			assoc_sta = (struct sta_info_tag *)co_list_next(&assoc_sta->list_hdr);
		}
	}
	#undef MAC2STR(a)
	return ret;
}

int wlan_ap_add_blacklist(struct mac_addr *macaddr)
{
	int ret = 0;
	struct wifi_mac_node *marked_sta = NULL;
	unsigned char mac[WIFI_MAC_ADDR_LEN];

	if (macaddr && !_is_multicast_ether_addr((const u8 *)macaddr) && 
		!_is_zero_ether_addr((const u8 *)macaddr)) {
		memcpy(mac, macaddr, WIFI_MAC_ADDR_LEN);
	} else if (!macaddr) {
		memset(mac, 0xff, WIFI_MAC_ADDR_LEN);
	} else {
		aic_dbg("invalid MAC address!\n");
		return -1;
	}

	marked_sta = rtos_malloc(sizeof(struct wifi_mac_node));
	if (!marked_sta) {
		ret = -ENOMEM;
		return -1;
	}
	memset(marked_sta, 0, sizeof(struct wifi_mac_node));
	memcpy(marked_sta->mac, mac, WIFI_MAC_ADDR_LEN);
	co_list_push_back(&mac_acl_list, &marked_sta->node);
	aic_dbg("Added \r\n");

	return ret;
}
int wlan_ap_delete_blacklist(struct mac_addr *macaddr)
{
	int ret = 0;
	struct wifi_mac_node *marked_sta = NULL;
	unsigned char mac[WIFI_MAC_ADDR_LEN];

	if (macaddr && !_is_multicast_ether_addr((const u8 *)macaddr) && 
		!_is_zero_ether_addr((const u8 *)macaddr)) {
		memcpy(mac, macaddr, WIFI_MAC_ADDR_LEN);
	} else if (!macaddr) {
		memset(mac, 0xff, WIFI_MAC_ADDR_LEN);
	} else {
		aic_dbg("invalid MAC address!\n");
		return -1;
	}
	
	marked_sta = fetch_mac(&mac_acl_list, mac);
	if (marked_sta) {
		co_dl_list_remove_node(&marked_sta->node);
		rtos_free(marked_sta);
		aic_dbg("Delete \r\n");
	}
	return ret;

}

int wlan_ap_add_whitelist(struct mac_addr *macaddr)
{
	int ret = 0;
	struct wifi_mac_node *marked_sta = NULL;
	unsigned char mac[WIFI_MAC_ADDR_LEN];

	if (macaddr && !_is_multicast_ether_addr((const u8 *)macaddr) && 
		!_is_zero_ether_addr((const u8 *)macaddr)) {
		memcpy(mac, macaddr, WIFI_MAC_ADDR_LEN);
	} else if (!macaddr) {
		memset(mac, 0xff, WIFI_MAC_ADDR_LEN);
	} else {
		aic_dbg("invalid MAC address!\n");
		return -1;
	}

	marked_sta = rtos_malloc(sizeof(struct wifi_mac_node));
	if (!marked_sta) {
		ret = -ENOMEM;
		return -1;
	}
	memset(marked_sta, 0, sizeof(struct wifi_mac_node));
	memcpy(marked_sta->mac, mac, WIFI_MAC_ADDR_LEN);
	co_list_push_back(&mac_acl_list, &marked_sta->node);
	aic_dbg("Added White list\r\n");

	return ret;
}

int wlan_ap_delete_whitelist(struct mac_addr *macaddr)
{
	int ret = 0;
	struct wifi_mac_node *marked_sta = NULL;
	unsigned char mac[WIFI_MAC_ADDR_LEN];
	struct sta_info_tag *assoc_sta;

	if (macaddr && !_is_multicast_ether_addr((const u8 *)macaddr) && 
		!_is_zero_ether_addr((const u8 *)macaddr)) {
		memcpy(mac, macaddr, WIFI_MAC_ADDR_LEN);
	} else if (!macaddr) {
		memset(mac, 0xff, WIFI_MAC_ADDR_LEN);
	} else {
		aic_dbg("invalid MAC address!\n");
		return -1;
	}
	
	marked_sta = fetch_mac(&mac_acl_list, mac);
	if (marked_sta) {
        fhost_ap_delete_whitelist(0, marked_sta->mac);
        #if 0
        struct vif_info_tag *vif = fhost_to_mac_vif(0);

		assoc_sta = (struct sta_info_tag *)co_list_pick(&vif->sta_list);
		while (assoc_sta) {
			if (!memcmp(marked_sta->mac, assoc_sta->mac_addr.array, WIFI_MAC_ADDR_LEN)) {
                aic_dbg("the assoc sta ("MACSTR") in  whitelist , del it\r\n",
                    MAC2STR((unsigned char *)assoc_sta->mac_addr.array));
                wlan_ap_disassociate_sta(assoc_sta->mac_addr.array);

            }
			assoc_sta = (struct sta_info_tag *)co_list_next(&assoc_sta->list_hdr);
		}
        #endif
        co_list_extract(&mac_acl_list, marked_sta);
		rtos_free(marked_sta);
        marked_sta = NULL;

		aic_dbg("Delete white list\r\n");
	}
	return ret;
}

uint8_t wlan_ap_get_mac_acl_list_cnt(void)
{
    return co_list_cnt(&mac_acl_list);
}

void * wlan_ap_get_mac_acl_list(void)
{
    return &mac_acl_list;
}

uint8_t wlan_ap_get_associated_sta_cnt(void)
{
    return vif_mgmt_sta_cnt();
}

void *wlan_ap_get_associated_sta_list(void)
{
    return get_vif_mgmt_sta_list();
}

int8_t wlan_ap_get_associated_sta_rssi(uint8_t *addr)
{
    return data_pkt_rssi_get(addr);
}

int set_sta_not_autoconnect(int vif_idx)
{
    int ret = 0;
    if (vif_idx >= NX_VIRT_DEV_MAX) {
        aic_dbg("vif_idx is invaild.\n");
        return -2;
    }

    ret = fhost_wpa_sta_not_autoconnect(vif_idx);
    return ret;
}

#endif /* CFG_SOFTAP */

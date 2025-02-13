/*
 * Copyright (C) 2018-2020 AICSemi Ltd.
 *
 * All Rights Reserved
 */

#include "wifi.h"
#include "porting.h"
#include "aic_log.h"
#include "rwnx_defs.h"
#include "rtos_al.h"
#include "rwnx_main.h"
#include "fhost_config.h"
#include "fhost_api.h"
#include "fhost_wpa.h"
#include "sdio_port.h"
//#include "test_main.h"
#include "cli_cmd.h"
#include "lmac_mac.h"
#include "wlan_if.h"

#define CONFIG_TEST_MAIN_EN 0
#define CONFIG_RTOS_AL_TEST_EN    0

#define AIC_WIFI_EVENT_ENABLE

uint8_t p2p_started;

extern const char *aic_version;
extern const char *aic_date;
extern const char *rlsversion;
extern const char aic_wifi_version[];


#ifdef AIC_WIFI_EVENT_ENABLE
static int aic_wifi_scan_status = 0;
#endif

aic_wifi_event_cb g_aic_wifi_event_cb = NULL;
wifi_drv_event_cbk aw_aic_wifi_event_cb = NULL;
int dev_mode = WIFI_MODE_UNKNOWN;
int g_wifi_init = 0;

#if (CONFIG_RTOS_AL_TEST_EN)
rtos_semaphore sema = NULL;

rtos_task_handle test_task_handle = NULL;
#define TEST_TASK_ID 10
#define TEST_TASK_STACK_DEPTH 512
#define TEST_TASK_PRIO 1
rtos_semaphore task_sema = NULL;

#define TEST_QUEUE_ELT_CNT 5
struct test_queue_msg {
    uint32_t id;
    uint32_t param;
};
rtos_queue test_queue = NULL;

void my_timer_func(void *param)
{
    AIC_LOG_PRINTF("my_timer_func, now: %d, param: %x", rtos_now(false), (uint32_t)param);
    rtos_semaphore_signal(sema, 0);
}

void my_task_func(void *param)
{
    int ret = 0;
    AIC_LOG_PRINTF("%s enter, param: %x", __func__, (uint32_t)param);

    while (1) {
        ret = rtos_semaphore_wait(task_sema, 3000);
        if ((ret == 0))
            AIC_LOG_PRINTF("semaphore success");
        if ((ret == 1))
            AIC_LOG_PRINTF("semaphore timeout");
        else
            AIC_LOG_PRINTF("semaphore error");

        break;
    }
}

void rtos_al_test(void)
{
    AIC_LOG_PRINTF("rtos_al_test start");

    int ret = 0;
    unsigned int i = 0;

    // 1.rtos_now/rtos_msleep
    AIC_LOG_PRINTF("now: %d", rtos_now(false));
    rtos_msleep(20);
    AIC_LOG_PRINTF("now: %d", rtos_now(false));

    // 2.rtos_malloc/rtos_free/rtos_memcpy/rtos_memset
    char *ptr = NULL;
    ptr = (char *)rtos_malloc(16);
    if (ptr == NULL)
        AIC_LOG_PRINTF("rtos_malloc failed");
    else
        AIC_LOG_PRINTF("rtos_malloc successfully, addr: 0x%lx", (unsigned long)ptr);

    rtos_memset(ptr, 0, 16);
    //rwnx_data_dump("rtos_memset", ptr, 16);
    AIC_LOG_PRINTF("rtos_memset:");
    for (i = 0; i < 16; i++) {
        aic_dbg("%02x ", ptr[i]);
    }
    aic_dbg("\n");

    char a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    rtos_memcpy(ptr, a, 16);
    //rwnx_data_dump("rtos_memset", ptr, 16);
    AIC_LOG_PRINTF("rtos_memcpy:");
    for (i = 0; i < 16; i++) {
        aic_dbg("%02x ", ptr[i]);
    }
    aic_dbg("\n");

    rtos_free(ptr);

    // 3.rtos_entercritical/rtos_exitcritical

    // 4.task
    ret = rtos_semaphore_create(&task_sema, "task_sema", 1, 0);
    if (ret != 0)
        AIC_LOG_PRINTF("rtos_semaphore_create failed");
    else
        AIC_LOG_PRINTF("rtos_semaphore_create successfully");

    ret = rtos_mutex_create(&task_mutex);
    if (ret != 0)
        AIC_LOG_PRINTF("rtos_mutex_create failed");
    else
        AIC_LOG_PRINTF("rtos_mutex_create successfully");

    AIC_LOG_PRINTF("test_task_handle ptr: %x\n", (uint32_t)&test_task_handle);
    ret = rtos_task_create(my_task_func, "Test", TEST_TASK_ID, TEST_TASK_STACK_DEPTH, &test_task_handle, TEST_TASK_PRIO, &test_task_handle);
    if (ret != 0)
        AIC_LOG_PRINTF("rtos_task_create failed");
    else
        AIC_LOG_PRINTF("rtos_task_create successfully");
    AIC_LOG_PRINTF("test_task_priority:%x\n" ,rtos_task_get_priority(test_task_handle));


    AIC_LOG_PRINTF("%s task_mutex lock start@%u", __func__, rtos_now(false));
    ret = rtos_mutex_lock(task_mutex, -1);
    AIC_LOG_PRINTF("%s task_mutex lock end@%u, ret=%d", __func__, rtos_now(false), ret);

#if 1
    AIC_LOG_PRINTF("test_task2_handle ptr: %x", (uint32_t)&test_task2_handle);
    ret = rtos_task_create(my_task2_func, "Test2", TEST_TASK2_ID, TEST_TASK2_STACK_DEPTH, &test_task2_handle, TEST_TASK2_PRIO, &test_task2_handle);
    if (ret != 0)
        AIC_LOG_PRINTF("rtos_task_create failed");
    else
        AIC_LOG_PRINTF("rtos_task_create successfully");
    AIC_LOG_PRINTF("test_task2_priority:%x\n" ,rtos_task_get_priority(test_task2_handle));
#endif

    rtos_msleep(10);
    rtos_semaphore_signal(task_sema, 0);
    rtos_msleep(150);

    AIC_LOG_PRINTF("%s task_mutex unlock@%u", __func__, rtos_now(false));
    rtos_mutex_unlock(task_mutex);

    AIC_LOG_PRINTF("test_task delete start");
    rtos_task_delete(test_task_handle);
    AIC_LOG_PRINTF("test_task delete end");
#if 1
    AIC_LOG_PRINTF("test_task2 delete start");
    rtos_task_delete(test_task2_handle);
    AIC_LOG_PRINTF("test_task2 delete end");
#endif
    rtos_semaphore_delete(task_sema);
    rtos_mutex_delete(task_mutex);
	task_sema = NULL;

    // 5.queue
    struct test_queue_msg msg;
    ret = rtos_queue_create(sizeof(struct test_queue_msg), TEST_QUEUE_ELT_CNT, &test_queue, "test_queue");
    if (ret != 0)
        AIC_LOG_PRINTF("rtos_queue_create failed");
    else
        AIC_LOG_PRINTF("rtos_queue_create successfully");
    AIC_LOG_PRINTF("test_queue:%X\n", (uint32_t)test_queue);
    AIC_LOG_PRINTF("rtos_queue cnt:%d full:%d empty:%d", rtos_queue_cnt(test_queue), rtos_queue_is_full(test_queue), rtos_queue_is_empty(test_queue));
    AIC_LOG_PRINTF("rtos_queue_read empty queue start@:%d", rtos_now(false));
    ret = rtos_queue_read(test_queue, &msg, 10, 0);
    AIC_LOG_PRINTF("rtos_queue_read empty queue end @%d ret:%d", rtos_now(false), ret);

    msg.id = 1;
    msg.param = 1;
    ret = rtos_queue_write(test_queue, &msg, 0, 0);
    AIC_LOG_PRINTF("rtos_queue_write ret:%d id:%d param:%d", ret, msg.id, msg.param);
    AIC_LOG_PRINTF("rtos_queue cnt:%d full:%d empty:%d", rtos_queue_cnt(test_queue), rtos_queue_is_full(test_queue), rtos_queue_is_empty(test_queue));

    msg.id = 2;
    msg.param = 2;
    ret = rtos_queue_write(test_queue, &msg, 0, 0);
    AIC_LOG_PRINTF("rtos_queue_write ret:%d id:%d param:%d", ret, msg.id, msg.param);
    AIC_LOG_PRINTF("rtos_queue cnt:%d full:%d empty:%d", rtos_queue_cnt(test_queue), rtos_queue_is_full(test_queue), rtos_queue_is_empty(test_queue));

    memset(&msg, 0, sizeof(struct test_queue_msg));
    ret = rtos_queue_read(test_queue, &msg, 10, 0);
    AIC_LOG_PRINTF("rtos_queue_read ret:%d id:%d param:%d", ret, msg.id, msg.param);
    AIC_LOG_PRINTF("rtos_queue cnt:%d full:%d empty:%d", rtos_queue_cnt(test_queue), rtos_queue_is_full(test_queue), rtos_queue_is_empty(test_queue));

    memset(&msg, 0, sizeof(struct test_queue_msg));
    ret = rtos_queue_read(test_queue, &msg, 10, 0);
    AIC_LOG_PRINTF("rtos_queue_read ret:%d id:%d param:%d", ret, msg.id, msg.param);
    AIC_LOG_PRINTF("rtos_queue cnt:%d full:%d empty:%d", rtos_queue_cnt(test_queue), rtos_queue_is_full(test_queue), rtos_queue_is_empty(test_queue));

    rtos_queue_delete(test_queue);

    // 6.semaphore
    ret = rtos_semaphore_create(&sema, "sema", 1, 0);
    if (ret != 0)
        AIC_LOG_PRINTF("rtos_semaphore_create failed");
    else
        AIC_LOG_PRINTF("rtos_semaphore_create successfully");

    // 7.timer
    rtos_timer test_timer;
    AIC_LOG_PRINTF("test_timer ptr:%x\n", (uint32_t)&test_timer);
    ret = rtos_timer_create("test_timer", &test_timer, 10, 0, &test_timer, my_timer_func);
    if (ret != 0)
        AIC_LOG_PRINTF("rtos_timer_create failed");
    else
        AIC_LOG_PRINTF("rtos_timer_create successfully");

    AIC_LOG_PRINTF("test_timer start@%d\n", rtos_now(false));
    rtos_timer_start(test_timer, 0, 0);

    ret = rtos_semaphore_wait(sema, 30);
    if (ret == 0)
        AIC_LOG_PRINTF("get semaphore singal successfully");
    else if (ret == 1)
        AIC_LOG_PRINTF("get semaphore singal timeout");
    else
        AIC_LOG_PRINTF("get semaphore singal failed");

    ret = rtos_timer_delete(test_timer, 0);
    if ((ret != 0))
        AIC_LOG_PRINTF("rtos_timer_delete failed");
    else
        AIC_LOG_PRINTF("rtos_timer_delete successfully");

    ret = rtos_timer_create("test_timer", &test_timer, 10, 1, &test_timer, my_timer_func);
    if (ret != 0)
        AIC_LOG_PRINTF("rtos_timer_create failed");
    else
        AIC_LOG_PRINTF("rtos_timer_create successfully");

    AIC_LOG_PRINTF("test_timer start@%d", rtos_now(false));
    rtos_timer_start(test_timer, 20, 0);

    rtos_msleep(100);

    ret = rtos_timer_delete(test_timer, 0);
    if ((ret != 0))
        AIC_LOG_PRINTF("rtos_timer_delete failed");
    else
        AIC_LOG_PRINTF("rtos_timer_delete successfully");

    uint32_t idx = 0;
    for (idx = 0; idx < 20; idx++) {
        AIC_LOG_PRINTF("timer_sema count:%u", rtos_semaphore_get_count(timer_sema));
        ret = rtos_semaphore_wait(timer_sema, 10);
        AIC_LOG_PRINTF("timer_sema wait, idx:%d, ret:%d", idx, ret);
    }
    rtos_semaphore_delete(timer_sema);
	timer_sema = NULL;

    uint32_t sec = 0, usec = 0;
    aic_time_get(0, &sec, &usec);
    AIC_LOG_PRINTF("now:%u sec:%u usec:%u", rtos_now(false), sec, usec);

    AIC_LOG_PRINTF("sleep 10");
    rtos_msleep(10);

    aic_time_get(0, &sec, &usec);
    AIC_LOG_PRINTF("now:%u sec:%u usec:%u", rtos_now(false), sec, usec);

    AIC_LOG_PRINTF("rtos_al_test end");
}
#endif

void temp_isr(void)
{
    //AIC_LOG_PRINTF("temp_isr\r\n");
}


struct rwnx_hw *g_rwnx_hw = NULL;

void aicwf_get_chipid(void)
{
    struct rwnx_hw *rwnx_hw = g_rwnx_hw;
#if defined(CONFIG_AIC8801)
    rwnx_hw->chipid = PRODUCT_ID_AIC8801;
    AIC_LOG_PRINTF("aicwf chipid: USE AIC8801");
#elif defined(CONFIG_AIC8800DC)
    rwnx_hw->chipid = PRODUCT_ID_AIC8800DC;
    AIC_LOG_PRINTF("aicwf chipid: USE AIC8800DC");
#elif defined(CONFIG_AIC8800DW)
    rwnx_hw->chipid = PRODUCT_ID_AIC8800DW;
    AIC_LOG_PRINTF("aicwf chipid: USE AIC8800DW");
#elif defined(CONFIG_AIC8800D80)
    rwnx_hw->chipid = PRODUCT_ID_AIC8800D80;
    AIC_LOG_PRINTF("aicwf chipid: USE AIC8800D80");
#else
    AIC_LOG_PRINTF("aicwf chipid: no aic product");
#endif
}

unsigned int aicwf_is_5g_enable(void)
{
#ifdef USE_5G
    return 1;
#else
    return 0;
#endif
}

/**
 * @brief initializing wifi
 * @author
 * @date
 * @param [in] mode  wifi mode
 * @param [in] param a pointer to ap/sta cfg
 * @return int
 * @retval   0  initializing sucessful
 * @retval  -1 initializing fail
 */
static int aic_wifi_open(int mode, void *param, u16 chip_id)
{
    struct rwnx_hw *rwnx_hw = NULL;
    static uint8_t g_wifi_opened = 0;
	int ret = 0;
    static unsigned char mac_addr[6] = {0};
#if 0
	static bool mac_set = 0;
	if(!mac_set)
	{
		mac_addr[0] = rand()%0xff;
		mac_addr[1] = rand()%0xff;
		mac_addr[2] = rand()%0xff;
		mac_addr[3] = rand()%0xff;
		mac_addr[4] = rand()%0xff;
		mac_addr[5] = rand()%0xff;
		mac_set = 1;
	}
#endif
    /*__err("xxxxxxxxxxxxx fhost_mac_addr %02x %02x %02x %02x %02x %02x\r\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);*/
    //AIC_LOG_PRINTF("Wifilib version:%s\r\n", aic_wifi_get_version());
    AIC_LOG_PRINTF("aic_wifi_open: %d", mode);

    if (g_wifi_opened == 0)
    {
        // pwrkey en
        platform_pwr_en_pin_init();
        // platform_pwr_en_pin_set(0);
        // rtos_task_suspend(10);
        // platform_pwr_en_pin_set(1);
        // alloc structs
        rwnx_hw = rtos_malloc(sizeof(struct rwnx_hw));
        if (rwnx_hw == NULL) {
            AIC_LOG_PRINTF("rwnx_hw alloc failed");
            return -1;
        }
        g_rwnx_hw = rwnx_hw;
        rwnx_hw->mode = mode;

        #ifdef CONFIG_SDIO_SUPPORT
        aicwf_get_chipid();
        sdio_host_init(rwnx_hw, temp_isr);
        #endif
        #ifdef CONFIG_USB_SUPPORT
        rwnx_hw->chipid = chip_id;
        aic_usb_host_init(rwnx_hw);
        #endif
        fhost_init(rwnx_hw);
        rwnx_cmd_mgr_init(&rwnx_hw->cmd_mgr);
        ret = rwnx_fdrv_init(rwnx_hw);
        if(ret) return ret;
        aic_cli_cmd_init(rwnx_hw);

        g_wifi_opened = 1;
    } else {
        rwnx_hw = g_rwnx_hw;
    }
    for (uint8_t i = 0; i < 6 ; i++) {
        uint8_t times = co_rand_byte() % 5;
        for (uint8_t j = 0; j < times ; j++) {
            mac_addr[i] = co_rand_byte();
        }
    }
    set_mac_address(mac_addr); //NULL: mac addr in efuse
    uint8_t *m_addr = get_mac_address();
    AIC_LOG_PRINTF("fhost_mac_addr %02x %02x %02x %02x", m_addr[0], m_addr[1], m_addr[4], m_addr[5]);
    /*__err("fhost_mac_addr %02x %02x %02x %02x %02x %02x", m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4], m_addr[5]);*/

    if (mode == WIFI_MODE_AP) {
#if 0
        #define AP_SSID_STRING  "AIC-AP-SUNPLUS"
        #define AP_PASS_STRING  "kkkkkkkk"
        struct aic_ap_cfg user_ap_cfg = {
            .aic_ap_ssid = {
                strlen(AP_SSID_STRING),
                AP_SSID_STRING
            },
            .aic_ap_passwd = {
                strlen(AP_PASS_STRING),
                AP_PASS_STRING
            },
            .band = 1,
            .type = PHY_CHNL_BW_20,
            .channel = 149,
            .hidden_ssid = 0,
            .max_inactivity = 60,
            .enable_he = 1,
            .enable_acs = 0,
            .bcn_interval = 100,
            .sta_num = 10,
        };
        #undef AP_SSID_STRING
        #undef AP_PASS_STRING
#endif
        rwnx_hw->net_id = wlan_start_ap((struct aic_ap_cfg *)param);
    } else if (mode == WIFI_MODE_STA) {
        rwnx_hw->net_id = wlan_start_sta("Empty_SSID", "Empty_Password", -1);
    } else if (mode == WIFI_MODE_P2P) {
        //aic_wifi_set_mode(WIFI_MODE_P2P);
    }

    g_wifi_init = 1;
    AIC_LOG_PRINTF("wifi open ok");
    return 0;
}

static int aic_wifi_close(int mode)
{
    int ret = 0;
    struct rwnx_hw *rwnx_hw = g_rwnx_hw;

    AIC_LOG_PRINTF("aic_wifi_deinit_mode: %d", mode);

    if (g_wifi_init == 0)
    {
        AIC_LOG_PRINTF("aic_wifi_deinit already deinit");
        return 0;
    }

    if (mode == WIFI_MODE_AP) {
        ret = wlan_stop_ap();
        if (ret) {
            AIC_LOG_PRINTF("wlan_stop_ap failed: %d", ret);
            return -1;
        } else {
            AIC_LOG_PRINTF("wlan_stop_ap success: %d", ret);
        }
        rwnx_hw->net_id = 0;
    }


#if 0
    aic_cli_cmd_deinit(rwnx_hw);
    rwnx_fdrv_deinit(rwnx_hw);
    rwnx_cmd_mgr_deinit(&rwnx_hw->cmd_mgr);
    fhost_deinit(rwnx_hw);
    sdio_host_deinit();

    rtos_free(rwnx_hw);
#endif

    AIC_LOG_PRINTF("aic_wifi_close success");
    return ret;
}

AIC_WIFI_MODE aic_wifi_get_mode(void)
{
    return dev_mode;
}

void aic_wifi_set_mode(AIC_WIFI_MODE mode)
{
    dev_mode = mode;
}

void aic_wifi_event_register(aic_wifi_event_cb cb)
{
    g_aic_wifi_event_cb = (aic_wifi_event_cb)cb;
}

int wifi_drv_event_set_cbk(wifi_drv_event_cbk cbk)
{
    aw_aic_wifi_event_cb = cbk;
    AIC_LOG_PRINTF("%s is called, aw_aic_wifi_event_cb: %p", __func__, aw_aic_wifi_event_cb);

    return 1;
}

void wifi_drv_event_reset_cbk(void) {
    aw_aic_wifi_event_cb = NULL;

    aic_wifi_deinit(WIFI_MODE_AP);
}

static wifi_event_handle m_scan_result_handle = NULL;
static wifi_event_handle m_scan_done_handle = NULL;
static wifi_event_handle m_join_success_handle = NULL;
static wifi_event_handle m_join_fail_handle = NULL;
static wifi_event_handle m_leave_handle = NULL;

static unsigned int aic_p2p_dev_port = 7236; //default port number
static unsigned char aic_p2p_associating = 0;

void aic_wifi_event_callback(AIC_WIFI_EVENT enEvent, aic_wifi_event_data *enData)
{
    switch(enEvent)
    {
        case SCAN_RESULT_EVENT:
            {
                //MLOGE("func:%s, SCAN_RESULT_EVENT received\n",__FUNCTION__);
                if (m_scan_result_handle)
                {
                    m_scan_result_handle(enData);
                }
                break;
            }
        case SCAN_DONE_EVENT:
            {
                if (m_scan_done_handle)
                {
                    m_scan_done_handle(enData);
                }
                #if 0
                if (1)
                {
                    wlan_event_msg_t event;
                    //make a fake wlan event
                    event.event_type = WLAN_E_SCAN_COMPLETE;
                    WLAN_SYS_StatusCallback(&event);
                }
                #endif
                break;
            }
        case JOIN_SUCCESS_EVENT:
            {
                if (m_join_success_handle)
                {
                    m_join_success_handle(enData);
                }
                #if 0
                if (1)
                {
                    wlan_event_msg_t event;
                    //make a fake wlan event
                    event.event_type = WLAN_E_LINK;
                    event.flags = 1;
                    WLAN_SYS_StatusCallback(&event);
                }
                #endif
                break;
            }
        case JOIN_FAIL_EVENT:
            {
                if (m_join_fail_handle)
                {
                    m_join_fail_handle(enData);
                }
                #if 0
                if (1)
                {
                    struct resp_evt_result *join_res = (struct resp_evt_result *)enData;
                    wlan_event_msg_t event;
                    event.event_type = WLAN_E_LINK;
                    event.flags = 0;
                    event.reason = join_res->u.join.status_code;
                    WLAN_SYS_StatusCallback(&event);
                }
                #endif
                break;
            }
        case LEAVE_RESULT_EVENT:
            {
                if (m_leave_handle)
                {
                    m_leave_handle(enData);
                }
                #if 0
                if (1)
                {
                    struct resp_evt_result *leave_res = (struct resp_evt_result *)enData;
                    wlan_event_msg_t event;
                    event.event_type = WLAN_E_LINK;
                    event.flags = 0;
                    event.reason = leave_res->u.leave.reason_code;
                    WLAN_SYS_StatusCallback(&event);
                }

                #endif
                break;
            }
        case PRO_DISC_REQ_EVENT:
            {
            	if (aic_p2p_associating) {
					break;
				}
				aic_p2p_associating = 1;
                uint32_t *mac_addr = enData->data.auth_deauth_data.reserved;
                aic_dbg("PRO_DISC_REQ_EVENT mac_addr = %02x:%02x:%02x:%02x:%02x:%02x\r\n"
                       , mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
                if (aw_aic_wifi_event_cb) {
                    wifi_drv_event drv_event;
                    struct wifi_p2p_event p2p_event;
                    p2p_event.event_type = WIFI_P2P_EVENT_GOT_PRO_DISC_REQ_AFTER_GONEGO_OK;
                    p2p_event.peer_dev_mac_addr[0] = (unsigned char)enData->data.auth_deauth_data.reserved[0];
                    p2p_event.peer_dev_mac_addr[1] = (unsigned char)enData->data.auth_deauth_data.reserved[1];
                    p2p_event.peer_dev_mac_addr[2] = (unsigned char)enData->data.auth_deauth_data.reserved[2];
                    p2p_event.peer_dev_mac_addr[3] = (unsigned char)enData->data.auth_deauth_data.reserved[3];
                    p2p_event.peer_dev_mac_addr[4] = (unsigned char)enData->data.auth_deauth_data.reserved[4];
                    p2p_event.peer_dev_mac_addr[5] = (unsigned char)enData->data.auth_deauth_data.reserved[5];
                    drv_event.type = WIFI_DRV_EVENT_P2P;
                    drv_event.node.p2p_event = p2p_event;

                    aic_p2p_dev_port = enData->p2p_dev_port_num;
                    aw_aic_wifi_event_cb(&drv_event);
                }
                user_wps_button_pushed();
                break;
            }
        case EAPOL_STA_FIN_EVENT:
            {
                uint32_t *mac_addr = enData->data.auth_deauth_data.reserved;
                aic_dbg("EAPOL_STA_FIN_EVENT mac_addr = %02x:%02x:%02x:%02x:%02x:%02x\r\n"
                       , mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
                if (aw_aic_wifi_event_cb) {
                    wifi_drv_event drv_event;
                    struct wifi_ap_event ap_event;
                    ap_event.event_type = WIFI_AP_EVENT_ON_ASSOC;
                    drv_event.type = WIFI_DRV_EVENT_AP;
                    ap_event.peer_dev_mac_addr[0] = (unsigned char)enData->data.auth_deauth_data.reserved[0];
                    ap_event.peer_dev_mac_addr[1] = (unsigned char)enData->data.auth_deauth_data.reserved[1];
                    ap_event.peer_dev_mac_addr[2] = (unsigned char)enData->data.auth_deauth_data.reserved[2];
                    ap_event.peer_dev_mac_addr[3] = (unsigned char)enData->data.auth_deauth_data.reserved[3];
                    ap_event.peer_dev_mac_addr[4] = (unsigned char)enData->data.auth_deauth_data.reserved[4];
                    ap_event.peer_dev_mac_addr[5] = (unsigned char)enData->data.auth_deauth_data.reserved[5];
                    drv_event.node.ap_event = ap_event;

                    //diag_dump_buf(ap_event.peer_dev_mac_addr, 6);
                    aw_aic_wifi_event_cb(&drv_event);
                }
                break;
            }
        case EAPOL_P2P_FIN_EVENT:
            {
                uint32_t *mac_addr = enData->data.auth_deauth_data.reserved;
                aic_dbg("EAPOL_P2P_FIN_EVENT mac_addr = %02x:%02x:%02x:%02x:%02x:%02x\r\n"
                       , mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
                if (aw_aic_wifi_event_cb) {
                    wifi_drv_event drv_event;
                    struct wifi_p2p_event p2p_event;
                    p2p_event.event_type = WIFI_P2P_EVENT_ON_ASSOC_REQ;
                    p2p_event.peer_dev_port = aic_p2p_dev_port;
                    p2p_event.peer_dev_mac_addr[0] = (unsigned char)enData->data.auth_deauth_data.reserved[0];
                    p2p_event.peer_dev_mac_addr[1] = (unsigned char)enData->data.auth_deauth_data.reserved[1];
                    p2p_event.peer_dev_mac_addr[2] = (unsigned char)enData->data.auth_deauth_data.reserved[2];
                    p2p_event.peer_dev_mac_addr[3] = (unsigned char)enData->data.auth_deauth_data.reserved[3];
                    p2p_event.peer_dev_mac_addr[4] = (unsigned char)enData->data.auth_deauth_data.reserved[4];
                    p2p_event.peer_dev_mac_addr[5] = (unsigned char)enData->data.auth_deauth_data.reserved[5];
                    drv_event.type = WIFI_DRV_EVENT_P2P;
                    drv_event.node.p2p_event = p2p_event;

                    aw_aic_wifi_event_cb(&drv_event);
                }
                break;
            }
        case ASSOC_IND_EVENT:
            {
                uint32_t *mac_addr = enData->data.auth_deauth_data.reserved;
                aic_dbg("ASSOC_IND_EVENT mac_addr = %02x:%02x:%02x:%02x:%02x:%02x\r\n"
                       , mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
                #if 0
                if (1)
                {
                    wlan_event_msg_t event;
                    //make a fake wlan event
                    event.event_type = WLAN_E_ASSOC_IND;
                    event.addr.mac[0] = enData->data.auth_deauth_data.reserved[0];
                    event.addr.mac[1] = enData->data.auth_deauth_data.reserved[1];
                    event.addr.mac[2] = enData->data.auth_deauth_data.reserved[2];
                    event.addr.mac[3] = enData->data.auth_deauth_data.reserved[3];
                    event.addr.mac[4] = enData->data.auth_deauth_data.reserved[4];
                    event.addr.mac[5] = enData->data.auth_deauth_data.reserved[5];
                    WLAN_SYS_StatusCallback(&event);
                }
                #endif
				aic_p2p_associating = 0;
                break;
            }
        case STA_DISCONNECT_EVENT:
            {
                AIC_WIFI_MODE mode = aic_wifi_get_mode();
                aic_dbg("STA_DISCONNECT_EVENT, current mode:%d\r\n", mode);
                if (aw_aic_wifi_event_cb &&  mode == WIFI_MODE_STA) {
                    wifi_drv_event drv_event;
                    struct wifi_sta_event dev_event;
                    dev_event.event_type = WIFI_STA_EVENT_ON_DISASSOC;
                    drv_event.type = WIFI_DRV_EVENT_STA;
                    drv_event.node.sta_event = dev_event;
                    aw_aic_wifi_event_cb(&drv_event);
                }
                break;
            }
        case DISASSOC_STA_IND_EVENT:
            {
                uint32_t *mac_addr = enData->data.auth_deauth_data.reserved;
                aic_dbg("DISASSOC_STA_IND_EVENT mac_addr = %02x:%02x:%02x:%02x:%02x:%02x\r\n"
                       , mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
                #if 0
                if (1)
                {
                    wlan_event_msg_t event;
                    //make a fake wlan event
                    event.event_type = WLAN_E_DISASSOC_IND;
                    event.addr.mac[0] = enData->data.auth_deauth_data.reserved[0];
                    event.addr.mac[1] = enData->data.auth_deauth_data.reserved[1];
                    event.addr.mac[2] = enData->data.auth_deauth_data.reserved[2];
                    event.addr.mac[3] = enData->data.auth_deauth_data.reserved[3];
                    event.addr.mac[4] = enData->data.auth_deauth_data.reserved[4];
                    event.addr.mac[5] = enData->data.auth_deauth_data.reserved[5];
                    WLAN_SYS_StatusCallback(&event);
                }
                #endif
                if(aw_aic_wifi_event_cb) {
                    wifi_drv_event drv_event;
                    struct wifi_ap_event ap_event;
                    ap_event.event_type = WIFI_AP_EVENT_ON_DISASSOC;
                    ap_event.peer_dev_mac_addr[0] = (unsigned char)enData->data.auth_deauth_data.reserved[0];
                    ap_event.peer_dev_mac_addr[1] = (unsigned char)enData->data.auth_deauth_data.reserved[1];
                    ap_event.peer_dev_mac_addr[2] = (unsigned char)enData->data.auth_deauth_data.reserved[2];
                    ap_event.peer_dev_mac_addr[3] = (unsigned char)enData->data.auth_deauth_data.reserved[3];
                    ap_event.peer_dev_mac_addr[4] = (unsigned char)enData->data.auth_deauth_data.reserved[4];
                    ap_event.peer_dev_mac_addr[5] = (unsigned char)enData->data.auth_deauth_data.reserved[5];
                    drv_event.type = WIFI_DRV_EVENT_AP;
                    drv_event.node.ap_event = ap_event;

                    aw_aic_wifi_event_cb(&drv_event);
                }
                break;
            }
        case DISASSOC_P2P_IND_EVENT:
            {
                uint32_t *mac_addr = enData->data.auth_deauth_data.reserved;
                aic_dbg("DISASSOC_P2P_IND_EVENT mac_addr = %02x:%02x:%02x:%02x:%02x:%02x\r\n"
                       , mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
                #if 0
                if (1)
                {
                    wlan_event_msg_t event;
                    //make a fake wlan event
                    event.event_type = WLAN_E_DISASSOC_IND;
                    event.addr.mac[0] = enData->data.auth_deauth_data.reserved[0];
                    event.addr.mac[1] = enData->data.auth_deauth_data.reserved[1];
                    event.addr.mac[2] = enData->data.auth_deauth_data.reserved[2];
                    event.addr.mac[3] = enData->data.auth_deauth_data.reserved[3];
                    event.addr.mac[4] = enData->data.auth_deauth_data.reserved[4];
                    event.addr.mac[5] = enData->data.auth_deauth_data.reserved[5];
                    WLAN_SYS_StatusCallback(&event);
                }
                #endif
                if(aw_aic_wifi_event_cb) {
                    wifi_drv_event drv_event;
                    struct wifi_p2p_event p2p_event;
                    p2p_event.event_type = WIFI_P2P_EVENT_ON_DISASSOC;
                    p2p_event.peer_dev_mac_addr[0] = (unsigned char)enData->data.auth_deauth_data.reserved[0];
                    p2p_event.peer_dev_mac_addr[1] = (unsigned char)enData->data.auth_deauth_data.reserved[1];
                    p2p_event.peer_dev_mac_addr[2] = (unsigned char)enData->data.auth_deauth_data.reserved[2];
                    p2p_event.peer_dev_mac_addr[3] = (unsigned char)enData->data.auth_deauth_data.reserved[3];
                    p2p_event.peer_dev_mac_addr[4] = (unsigned char)enData->data.auth_deauth_data.reserved[4];
                    p2p_event.peer_dev_mac_addr[5] = (unsigned char)enData->data.auth_deauth_data.reserved[5];
                    drv_event.type = WIFI_DRV_EVENT_P2P;
                    drv_event.node.p2p_event = p2p_event;

                    aw_aic_wifi_event_cb(&drv_event);
                }
                break;
            }
        default:
            {
                break;
            }
    }
}

int aic_wifi_init_mac(void)
{
    int ret = 0;

    unsigned char mac_addr[6] = {0x88, 0x00, 0x33, 0x77, 0x69, 0x22};
    unsigned int mac_local[6] = {0};

    /* use chip info as MAC in now(By Sunplus),
     * TODO: the MAC value read from efuse will be modified later(By AIC company).
     */
    extern int dovBTMAC(int* mac);
    ret = dovBTMAC(mac_local);
    if(ret) {
        mac_local[0] = (mac_local[0] > 0xfd) ?
                        (mac_local[0] - 1) :
                        (mac_local[0] + 1);

        mac_addr[0] = mac_local[5] & 0xff;
        mac_addr[1] = mac_local[4] & 0xff;
        mac_addr[2] = mac_local[3] & 0xff;
        mac_addr[3] = mac_local[2] & 0xff;
        mac_addr[4] = mac_local[1] & 0xff;
        mac_addr[5] = mac_local[0] & 0xff;
    }

    set_mac_address(mac_addr);
       return 0;
}

int aic_wifi_init(int mode, int chip_id, void *param)
{
    int ret = 0;
    unsigned char mac_addr[6] = {0};
    //unsigned int mac_local[6] = {0};

    AIC_LOG_PRINTF("aic_wifi_init, mode=%d", mode);
    AIC_LOG_PRINTF("release version:%s", aic_wifi_version);

    #if (CONFIG_RTOS_AL_TEST_EN)
    rtos_al_test();
    #endif

    /*
    if (g_wifi_init == 1)
    {
        AIC_LOG_PRINTF("aic_wifi_init already init\r\n");
        return g_rwnx_hw->net_id;
    } */

   ret = aic_wifi_open(mode, param, chip_id);
    if (ret) {
        AIC_LOG_PRINTF("wifi_open fail, ret=%d", ret);
        return -1;
    }

    aic_wifi_event_register(aic_wifi_event_callback);

    #if (CONFIG_TEST_MAIN_EN)
    test_main_entry();
    #endif
    AIC_LOG_PRINTF("aic_wifi_init ok");
retry:
    if (aw_aic_wifi_event_cb) {
        wifi_drv_event drv_event;
        struct wifi_dev_event dev_event;
        dev_event.drv_status = WIFI_DEVICE_DRIVER_LOADED;
        memcpy(mac_addr, get_mac_address(), 6);
        dev_event.local_mac_addr[0] = mac_addr[0];
        dev_event.local_mac_addr[1] = mac_addr[1];
        dev_event.local_mac_addr[2] = mac_addr[2];
        dev_event.local_mac_addr[3] = mac_addr[3];
        dev_event.local_mac_addr[4] = mac_addr[4];
        dev_event.local_mac_addr[5] = mac_addr[5];
        drv_event.type = WIFI_DRV_EVENT_NET_DEVICE;
        drv_event.node.dev_event = dev_event;
        aw_aic_wifi_event_cb(&drv_event);
    } else {
        rtos_msleep(5);
        goto retry;
    }

    return g_rwnx_hw->net_id;
}

void aic_wifi_deinit(int mode)
{
    AIC_LOG_PRINTF("aic_wifi_deinit, mode=%d", mode);

    if (g_wifi_init == 1)
    {
       aic_wifi_close(mode);

       aic_wifi_event_register(NULL);
    }
    if(aw_aic_wifi_event_cb) {
        wifi_drv_event drv_event;
        struct wifi_dev_event dev_event;
        dev_event.drv_status = WIFI_DEVICE_DRIVER_UNLOAD;
        drv_event.type = WIFI_DRV_EVENT_NET_DEVICE;
        drv_event.node.dev_event = dev_event;
        aw_aic_wifi_event_cb(&drv_event);
    }
    g_wifi_init = 0;

	aic_wifi_set_mode(WIFI_MODE_UNKNOWN);
    AIC_LOG_PRINTF("aic_wifi_deinit ok");
}
extern void sys_aic_reboot(struct rwnx_hw *rwnx_hw);
extern void sys_aic_wdt(struct rwnx_hw *rwnx_hw, uint8_t cmd, uint32_t seconds);
void aic_wifi_reboot(void)
{
    AIC_LOG_PRINTF("aic_wifi_reboot");
    sys_aic_reboot(g_rwnx_hw);
}

void aic_wifi_wdt(uint8_t cmd, uint32_t seconds)
{
    AIC_LOG_PRINTF("aic_wifi_wdt,  %d %d", cmd,  seconds);
    sys_aic_wdt(g_rwnx_hw, cmd,  seconds);
}

extern uint8_t p2p_started;

#ifdef CONFIG_VENDOR_IE
char* custom_vendor_ie = DEFAULT_VENDOR_IE;

void aic_add_custom_ie (char* vendor_ie) {
    custom_vendor_ie = vendor_ie;
}

void aic_update_custom_ie (char* vendor_ie) {
    custom_vendor_ie = vendor_ie;
}

void aic_del_custom_ie (void) {
    custom_vendor_ie = NULL;
}
#endif

int user_p2p_setDN(const char* device_name)
{
    int fhost_vif_idx = 0;
    char set_p2p_dev_name_cmd[64];
    char set_ap_dev_name_cmd[64];
    strcpy(set_p2p_dev_name_cmd, "SET p2p_dev_name ");
    strcpy(set_ap_dev_name_cmd, "P2P_SET ssid_postfix ");
    strcat(set_p2p_dev_name_cmd, device_name);
    strcat(set_ap_dev_name_cmd, device_name);
    fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 300, set_p2p_dev_name_cmd);
    fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 300, set_ap_dev_name_cmd);
    return 0;
}

int user_set_wfd_type(int wfd_device_type)
{
    int fhost_vif_idx = 0;
    if (wfd_device_type)
        fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 300, "WFD_SUBELEM_SET 0 000600111C440032");
    else
        fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 300, "WFD_SUBELEM_SET 0 000600101C440032");
    return 0;
}

int user_set_wfd_enable(int wfd_device_enable)
{
    int fhost_vif_idx = 0;
    if (wfd_device_enable)
        fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 300, "SET wifi_display 1");
    else
        fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 300, "SET wifi_display 0");
    return 0;
}

int user_wps_button_pushed(void)
{
    int fhost_vif_idx = 0;
    printf("%s in\n", __func__);
    fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 500, "WPS_PBC");
    return 0;
}

int user_p2p_start(struct aic_p2p_cfg *user_p2p_cfg)
{
    printf("p2p state:%d\n", p2p_started);
    if (p2p_started) {
        wlan_stop_p2p();
        aic_p2p_associating = 0;
        aic_wifi_event_register(NULL);
        return 0;
     } else {
        aic_wifi_event_register(aic_wifi_event_callback);
        g_rwnx_hw->net_id = wlan_start_p2p(user_p2p_cfg);
        aic_wifi_set_mode(WIFI_MODE_P2P);
    }

    user_p2p_setDN(user_p2p_cfg->aic_p2p_ssid.array);

    char set_p2p_go_cmd[128];
    char freq[5];
    uint16 prim20_freq;
    int fhost_vif_idx = 0;

    memset(set_p2p_go_cmd, 0, sizeof(set_p2p_go_cmd));
    strcpy(set_p2p_go_cmd, "P2P_GROUP_ADD he ");
    strcat(set_p2p_go_cmd, "pass=");
    strcat(set_p2p_go_cmd, user_p2p_cfg->aic_ap_passwd.array);
    strcat(set_p2p_go_cmd, " freq=");

    if ((user_p2p_cfg->band == 0) && (user_p2p_cfg->channel == 0)) {
        prim20_freq = phy_channel_to_freq(PHY_BAND_2G4, 11);
    } else {
        prim20_freq = phy_channel_to_freq(user_p2p_cfg->band, user_p2p_cfg->channel);
    }

    memset(freq, 0, sizeof(freq));
    sprintf(freq, "%d", prim20_freq);
    strcat(set_p2p_go_cmd, freq);
    if (strlen(set_p2p_go_cmd) >= sizeof(set_p2p_go_cmd)) {
        AIC_LOG_PRINTF("Cmd truncated. need %ld bytes", strlen(set_p2p_go_cmd));
        return -1;
    }

    user_set_wfd_type(1);
    user_set_wfd_enable(1);

    int res = (fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, -1, set_p2p_go_cmd) |
                fhost_wpa_enable_network(fhost_vif_idx, 20000));
    return res;
}

#if 0
extern uint8_t p2p_started;
HOSTAP_HANDLE * aic_start_ap(WiFiConfig * config)
{
    if(p2p_started) {
        if(strncmp(config->ssid, "DIRECT-", 7) != 0) {
            printf("Stop p2p before enable ap\n");
            wlan_stop_p2p();
        } else {
            printf("No need to start ap when p2p is on\n");
            return 1;
        }
    }

    aic_wifi_set_mode(WIFI_MODE_AP);
    if(!config) {
        #define AP_SSID_STRING  "AIC-AP-SUNPLUS"
        #define AP_PASS_STRING  "kkkkkkkk"
        struct aic_ap_cfg user_ap_cfg = {
            .aic_ap_ssid = {
                strlen(AP_SSID_STRING),
                AP_SSID_STRING
            },
            .aic_ap_passwd = {
                strlen(AP_PASS_STRING),
                AP_PASS_STRING
            },
            .band = 1,
            .type = PHY_CHNL_BW_20,
            .channel = 149,
            .hidden_ssid = 0,
            .max_inactivity = 60,
            .enable_he = 1,
            .enable_acs = 0,
            .bcn_interval = 100,
            .sta_num = 10,
        };
        return (void*)wlan_start_ap(&user_ap_cfg);
        #undef AP_SSID_STRING
        #undef AP_PASS_STRING
    } else {
        struct aic_ap_cfg user_ap_cfg = {
            .band = 0,
            .type = PHY_CHNL_BW_20,
            .channel = config->channel,
            .hidden_ssid = 0,
            .max_inactivity = 60,
            .enable_he = 1,
            .enable_acs = 0,
            .bcn_interval = config->beacon_int,
            .sta_num = 10,
        };
        user_ap_cfg.aic_ap_ssid.length = strlen(config->ssid);
        strcpy(user_ap_cfg.aic_ap_ssid.array, config->ssid);
        user_ap_cfg.aic_ap_passwd.length = strlen(config->wpa_passphrase);
        strcpy(user_ap_cfg.aic_ap_passwd.array, config->wpa_passphrase);

        return (void*)wlan_start_ap(&user_ap_cfg);
    }
}

void aic_stop_ap(HOSTAP_HANDLE * handle)
{
    wlan_stop_ap();
}

HOSTAP_HANDLE * hostapd_enable_ap(WiFiConfig * config)
{
    char set_p2p_go_cmd[64];
    char freq[5];
    uint16_t prim20_freq;
    int fhost_vif_idx = 0;

    struct aic_p2p_cfg user_p2p_cfg = {
        .band = PHY_BAND_2G4,
        .type = PHY_CHNL_BW_20,
        .channel = config->channel,
        .enable_he = 1,
        .enable_acs = 0,
    };

    /* 2.4G: 1,2,3,4,5,6,7,8,9,10,11,12,13,14 */
    /* 5G:   7,8,9,11,12,16,34,36...*/
    if(config->channel > 14)  //AIC not support set channel 7~16 as 5G band
        user_p2p_cfg.band = PHY_BAND_5G;

    aic_wifi_set_mode(WIFI_MODE_AP);

    user_p2p_cfg.aic_p2p_ssid.length = strlen(config->ssid);
    strcpy(user_p2p_cfg.aic_p2p_ssid.array, config->ssid);
    user_p2p_cfg.aic_ap_passwd.length = strlen(config->wpa_passphrase);
    strcpy(user_p2p_cfg.aic_ap_passwd.array, config->wpa_passphrase);

    printf("p2p state:%d\n", p2p_started);
    if(p2p_started) {
        wlan_stop_p2p();
    }
    if(!p2p_started) {
        g_rwnx_hw->net_id = wlan_start_p2p(&user_p2p_cfg);
    }

    user_p2p_setDN(user_p2p_cfg.aic_p2p_ssid.array);

    strcpy(set_p2p_go_cmd, "P2P_GROUP_ADD he ");
    strcat(set_p2p_go_cmd, "pass=");
    strcat(set_p2p_go_cmd, user_p2p_cfg.aic_ap_passwd.array);
    strcat(set_p2p_go_cmd, " freq=");

    if ((user_p2p_cfg.band == 0) && (user_p2p_cfg.channel == 0)) {
        prim20_freq = phy_channel_to_freq(PHY_BAND_2G4, 11);
    } else {
        prim20_freq = phy_channel_to_freq(user_p2p_cfg.band, user_p2p_cfg.channel);
    }

    memset(freq, 0, sizeof(freq));
    sprintf(freq, "%d", prim20_freq);
    strcat(set_p2p_go_cmd, freq);
    printf("set_p2p_go_cmd as %s\n", set_p2p_go_cmd);

    fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 300, "WFD_SUBELEM_SET 0 000600111C440032");
    int res = (fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, -1, set_p2p_go_cmd) |
                fhost_wpa_enable_network(fhost_vif_idx, 20000));

    return (HOSTAP_HANDLE *)1;
}

void hostapd_disable_ap(HOSTAP_HANDLE * handle)
{
    wlan_stop_ap();
}

int wifi_drv_feature_config(wifi_drv_conf* conf)
{
    return 0;
}

int hostapd_user_wps_button_pushed(HOSTAP_HANDLE * handle,       const unsigned char *p2p_dev_addr)
{
    int fhost_vif_idx = 0;
    printf("%s in\n", __func__);
    fhost_wpa_execute_cmd(fhost_vif_idx, NULL, NULL, 300, "WPS_PBC");
    return 0;
}

int hostapd_set_hidden_ssid_mode(HOSTAP_HANDLE * handle, int is_hidden)
{
    return 0;
}

int hostapd_remove_sta(HOSTAP_HANDLE * handle, const unsigned char *sta_addr)
{
    return 0;
}

void hostapd_commmand(int argc, char ** argv) {}

int wpa_enable_sta(void)
{
    char * param[4];

    param[0] = "iwpriv";
    param[1] = "wlan0";
    param[2] = "p2p_set";
    param[3] = "sta_enable=1";
    return iw_cmd( 4, param);
}

int wpa_disable_sta(void)
{
    char * param[4];

    param[0] = "iwpriv";
    param[1] = "wlan0";
    param[2] = "p2p_set";
    param[3] = "sta_enable=0";
    return iw_cmd( 4, param);
}

int wpa_sta_disconnect(const unsigned char *mac)
{
    (void)mac;
    int ret = 0;
    char * param[4];

    ret = wlan_disconnect_sta(0);
    if(ret < 0)
        printf("disconnect sta fail\n");

    param[0] = "iwpriv";
    param[1] = "wlan0";
    param[2] = "p2p_set";
    param[3] = "sta_enable=1";
    ret = iw_cmd( 4, param);
    if(ret < 0) {
        diag_printf("wifi_sta_enable fail!\n");
    }
    return ret;
}

int wpa_sta_connect(const char *ssid, const char *passwd, int timeout_ms)
{
    return wlan_sta_connect(ssid, passwd, timeout_ms);
}

void wpa_sta_scan()
{
    wlan_if_scan();
}

void wpa_sta_getscan(hostapd_scan_list_t *result_list)
{
    wifi_ap_list_t *ap_list = rtos_malloc(sizeof(wifi_ap_list_t));
    int i = 0;
    int max_result_cnt = 0;

    wlan_if_getscan(ap_list, 0);

    max_result_cnt = sizeof(result_list->ap_info)/sizeof(result_list->ap_info[0]);
    result_list->ap_count = ap_list->ap_count;

    for(i = 0; i < max_result_cnt && i < ap_list->ap_count; i++) {
        rtos_memcpy(result_list->ap_info[i].ssid,
                     ap_list->ap_info[i].ssid,
                      sizeof(result_list->ap_info[i].ssid));
        rtos_memcpy(result_list->ap_info[i].bssid,
                     ap_list->ap_info[i].bssid,
                     sizeof(result_list->ap_info[i].bssid));

        result_list->ap_info[i].channel = ap_list->ap_info[i].channel;
        result_list->ap_info[i].rssi = ap_list->ap_info[i].rssi;
    }

    rtos_free(ap_list);
}
#endif


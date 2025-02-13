/*
 * Copyright (C) 2018-2020 AICSemi Ltd.
 *
 * All Rights Reserved
 */

#define _PORTING_C_
#include <porting.h>
//#include "log_sdi_api.h"
//#include "os_api.h"
#include "plat_config.h"

#define APP_INCLUDE_WIFI_FW

/*============Task Priority===================*/
uint32_t sdio_datrx_priority = SDIO_DATRX_PRIORITY;
uint32_t fhost_cntrl_priority = FHOST_CNTRL_PRIORITY;
uint32_t fhost_wpa_priority = FHOST_WPA_PRIORITY;
uint32_t fhost_tx_priority = FHOST_TX_PRIORITY;
uint32_t fhost_rx_priority = FHOST_RX_PRIORITY;
uint32_t cli_cmd_priority = CLI_CMD_PRIORITY;
uint32_t rwnx_timer_priority = RWNX_TIMER_PRIORITY;
uint32_t rwnx_apm_staloss_priority = RWNX_APM_STALOSS_PRIORITY;
uint32_t tcpip_priority = TCPIP_PRIORITY;
uint32_t task_end_prio = TASK_END_PRIO;
uint32_t aic_priority_mode = AIC_PRIORITY_MODE;

/*============Stack Size (unint: 16bytes)===================*/
uint32_t sdio_datrx_stack_size = SDIO_DATRX_STACK_SIZE;
uint32_t fhost_cntrl_stack_size = FHOST_CNTRL_STACK_SIZE;
uint32_t fhost_wpa_stack_size = FHOST_WPA_STACK_SIZE;
uint32_t fhost_tx_stack_size = FHOST_TX_STACK_SIZE;
uint32_t fhost_rx_stack_size = FHOST_RX_STACK_SIZE;
uint32_t cli_cmd_stack_size = CLI_CMD_STACK_SIZE;
uint32_t rwnx_timer_stack_size = RWNX_TIMER_STACK_SIZE;
uint32_t rwnx_apm_staloss_stack_size = RWNX_APM_STALOSS_STACK_SIZE;

//=====================Platform LDO EN ping setting=======================
#define AIC_PWR_EN_PINNUM   12

void platform_pwr_en_pin_init(void)
{
    //GPIO_PullenSetup( pin,0);
    //GPIO_Enable(AIC_PWR_EN_PINNUM);
    //GPIO_SetDirection(AIC_PWR_EN_PINNUM, 1);
}

void platform_pwr_en_pin_set(bool en)
{
    //GPIO_SetValue(AIC_PWR_EN_PINNUM, en);
    platform_set_regon_en(en);
}


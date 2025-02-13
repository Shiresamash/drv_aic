#include "kapi.h"
#include "log.h"

static int sdc_channel = 1;
static void *wifi_regon = NULL;
static void *wifi_wake_up = NULL;
static int is_init = 0;

void platform_config_init(void)
{
    int channel = 1;
    user_gpio_set_t  gpio_set[1] = {0};
    int ret = 0;
    
    if(is_init == 1)
    {
        return;
    }

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

    ret = esCFG_GetKeyValue("wifi_para", "wifi_wakeup_ap", (int *)gpio_set, sizeof(user_gpio_set_t)/4);
	if(ret >= 0)
	{
    	wifi_wake_up = esPINS_PinGrpReq(gpio_set, 1);
	}
	else
	{
		__err("read cfg file fail wifi_reg_on...\n");
	}

    is_init = 1;

    return;
}

void platform_config_destory(void)
{
    if(wifi_regon)
    {
        esPINS_PinGrpRel(wifi_regon, 0);
		wifi_regon = NULL;
    }

    if(wifi_wake_up)
    {
        esPINS_PinGrpRel(wifi_wake_up, 0);
		wifi_wake_up = NULL;
    }
}

int platform_get_sdc_index(void)
{
    return sdc_channel;
}

int platform_set_regon_en(int en)
{
    if(wifi_regon == NULL)
    {
        return -1;
    }

    esPINS_SetPinIO(wifi_regon, 1, NULL);
    esPINS_SetPinIO(wifi_wake_up, 1, NULL);
    if(en == 1)
    {
    	esPINS_WritePinData(wifi_regon, 1, NULL);
    	esPINS_WritePinData(wifi_wake_up, 1, NULL);
    }
    else
    {
        esPINS_WritePinData(wifi_regon, 0, NULL);
        esPINS_WritePinData(wifi_wake_up, 0, NULL);
    }
	esKRNL_TimeDly(10);
	return 0;
}




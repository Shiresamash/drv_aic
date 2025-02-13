#ifndef __PLAT_CONFIG_H__
#define __PLAT_CONFIG_H__

void platform_config_init(void);
void platform_config_destory(void);
int platform_get_sdc_index(void);
int platform_set_regon_en(int en);

#endif

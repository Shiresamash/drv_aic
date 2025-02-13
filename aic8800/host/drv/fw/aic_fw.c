#include <stdint.h>
#include <stddef.h>
#include "aic_fw.h"
#include "fmacfw.h"
#include "fmacfw_rf.h"
#include "fw_adid_u03.h"
#include "fw_patch_u03.h"
#include "fw_patch_table_u03.h"

#include "fmacfw_patch_8800dc_u02.h"
#include "fmacfw_patch_tbl_8800dc_u02.h"
#include "fmacfw_calib_8800dc_u02.h"
#include "fmacfw_patch_8800dc_h_u02.h"
#include "fmacfw_patch_tbl_8800dc_h_u02.h"
#include "fmacfw_calib_8800dc_h_u02.h"
#include "lmacfw_rf_8800dc.h"
#include "fmacfw_8800d80_u02.h"
#include "fw_adid_8800d80_u02.h"
#include "fw_patch_8800d80_u02.h"
#include "fw_patch_table_8800d80_u02.h"
#include "lmacfw_rf_8800d80_u02.h"
#include "fmacfw_8800d80_h_u02.h"
#include "rtos_al.h"

#if defined(CONFIG_AIC8801)
void *aic8800d_fw_ptr_get(void)
{
    return (void *)fmacfw;
}

uint32_t aic8800d_fw_size_get(void)
{
    return sizeof(fmacfw);
}

#if defined(CONFIG_WIFI_MODE_RFTEST)
void *aic8800d_rf_fw_ptr_get(void)
{
    return (void *)fmacfw_rf;
}

uint32_t aic8800d_rf_fw_size_get(void)
{
    return sizeof(fmacfw_rf);
}
#endif /* CONFIG_WIFI_MODE_RFTEST */
#endif

void *aic_fw_ptr_get(enum aic_fw name)
{
    void *ptr = NULL;

    switch (name) {
#ifdef CONFIG_BT_SUPPORT
    case FW_ADID_U03:
        ptr = fw_adid_u03;
        break;
    case FW_PATCH_U03:
        ptr = fw_patch_u03;
        break;
    case FW_PATCH_TABLE_U03:
        ptr = fw_patch_table_u03;
        break;
#if 0
    case FW_ADID_8800D80:
        ptr = fw_adid_8800d80;
        break;
#endif
    case FW_ADID_8800D80_U02:
        ptr = fw_adid_8800d80_u02;
        break;
#endif
    default:
        ptr = NULL;
        break;
    }

    return ptr;
}

uint32_t aic_fw_size_get(enum aic_fw name)
{
    uint32_t size = 0;

    switch (name) {
#ifdef CONFIG_BT_SUPPORT
    case FW_ADID_U03:
        size = sizeof(fw_adid_u03);
        break;
    case FW_PATCH_U03:
        size = sizeof(fw_patch_u03);
        break;
    case FW_PATCH_TABLE_U03:
        size = sizeof(fw_patch_table_u03);
        break;
#if 0
    case FW_ADID_8800D80:
        size = sizeof(fw_adid_8800d80);
        break;
#endif
    case FW_ADID_8800D80_U02:
        size = sizeof(fw_adid_8800d80_u02);
        break;
#endif
    default:
        size = 0;
        break;
    }

    return size;
}


/*---------------------D80-----------------------*/
#if 0
void *aic8800d80_fmacfw_ptr_get(void)
{
    return (void *)fmacfw_8800d80;
}

uint32_t aic8800d80_fmacfw_size_get(void)
{
    return sizeof(fmacfw_8800d80);
}

void *aic8800d80_rf_fmacfw_ptr_get(void)
{
    return (void *)fmacfw_rf_8800d80;
}

uint32_t aic8800d80_rf_fmacfw_size_get(void)
{
    return sizeof(fmacfw_rf_8800d80);
}

void *aic8800d80_patch_ptr_get(void)
{
    return (void *)fw_patch_8800d80;
}

uint32_t aic8800d80_patch_size_get(void)
{
    return sizeof(fw_patch_8800d80);
}

void *aic8800d80_patch_tbl_ptr_get(void)
{
    return (void *)fw_patch_table_8800d80;
}

uint32_t aic8800d80_patch_tbl_size_get(void)
{
    return sizeof(fw_patch_table_8800d80);
}
#endif
#if defined(CONFIG_AIC8800DC) || defined(CONFIG_AIC8800DW)
void *aic8800dc_u01_fw_ptr_get(void)
{
    return NULL;
}

uint32_t aic8800dc_u01_fw_size_get(void)
{
    return 0;
}

void *aic8800dc_u02_fw_ptr_get(void)
{
    return (void *)fmacfw_patch_8800dc_u02;
}

uint32_t aic8800dc_u02_fw_size_get(void)
{
    return sizeof(fmacfw_patch_8800dc_u02);
}

void *aic8800dc_u02_patch_tbl_ptr_get(void)
{
    return (void *)fmacfw_patch_tbl_8800dc_u02;
}

uint32_t aic8800dc_u02_patch_tbl_size_get(void)
{
    return sizeof(fmacfw_patch_tbl_8800dc_u02);
}

void *aic8800dc_u02_calib_fw_ptr_get(void)
{
    return (void *)fmacfw_calib_8800dc_u02;
}

uint32_t aic8800dc_u02_calib_fw_size_get(void)
{
    return sizeof(fmacfw_calib_8800dc_u02);
}

void *aic8800dc_h_u02_fw_ptr_get(void)
{
    return (void *)fmacfw_patch_8800dc_h_u02;
}

uint32_t aic8800dc_h_u02_fw_size_get(void)
{
    return sizeof(fmacfw_patch_8800dc_h_u02);
}

uint32_t aic8800dc_h_u02_patch_tbl_size_get(void)
{
    return sizeof(fmacfw_patch_tbl_8800dc_h_u02);
}

void *aic8800dc_h_u02_patch_tbl_ptr_get(void)
{
    return (void *)fmacfw_patch_tbl_8800dc_h_u02;
}

void *aic8800dc_h_u02_calib_fw_ptr_get(void)
{
    return (void *)fmacfw_calib_8800dc_h_u02;
}

uint32_t aic8800dc_h_u02_calib_fw_size_get(void)
{
    return sizeof(fmacfw_calib_8800dc_h_u02);
}
#if defined(CONFIG_WIFI_MODE_RFTEST)
void *aic8800dc_rf_lmacfw_ptr_get(void)
{
    return (void *)lmacfw_rf_8800dc;
}

uint32_t aic8800dc_rf_lmacfw_size_get(void)
{
    return sizeof(lmacfw_rf_8800dc);
}
void *aic8800dc_rf_fmacfw_ptr_get(void)
{
    return NULL;
}

uint32_t aic8800dc_rf_fmacfw_size_get(void)
{
    return 0;
}
#endif /* CONFIG_WIFI_MODE_RFTEST */
#endif
/*---------------------D80_U02-----------------------*/
#if defined(CONFIG_AIC8800D80)
void *aic8800d80_u02_fw_ptr_get(void)
{
    return (void *)fmacfw_8800d80_u02;
}

uint32_t aic8800d80_u02_fw_size_get(void)
{
    return sizeof(fmacfw_8800d80_u02);
}
#if defined(CONFIG_WIFI_MODE_RFTEST)
void *aic8800d80_u02_rf_fw_ptr_get(void)
{
    return (void *)lmacfw_rf_8800d80_u02;
}

uint32_t aic8800d80_u02_rf_fw_size_get(void)
{
    return sizeof(lmacfw_rf_8800d80_u02);
}
#endif /* CONFIG_WIFI_MODE_RFTEST */

void *aic8800d80_u02_patch_ptr_get(void)
{
    return (void *)fw_patch_8800d80_u02;
}

uint32_t aic8800d80_u02_patch_size_get(void)
{
    return sizeof(fw_patch_8800d80_u02);
}

void *aic8800d80_u02_patch_tbl_ptr_get(void)
{
    return (void *)fw_patch_table_8800d80_u02;
}

uint32_t aic8800d80_u02_patch_tbl_size_get(void)
{
    return sizeof(fw_patch_table_8800d80_u02);
}

/*---------------------D80_H_U02-----------------------*/
void *aic8800d80_h_u02_fw_ptr_get(void)
{
    return (void *)fmacfw_8800d80_h_u02;
}

uint32_t aic8800d80_h_u02_fw_size_get(void)
{
    return sizeof(fmacfw_8800d80_h_u02);
}
#endif


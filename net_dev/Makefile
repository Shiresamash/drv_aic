OS = aw_rtt

LWIP_PATH = $(srctree)/ekernel/components/thirdparty/net/rt-thread/lwip
SDMMC_INC_PATH = $(srctree)/ekernel/drivers/include/hal/sdmmc

# sdmmc
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/sys/
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/hal
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/osal
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/os
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/osal/RT-Thread
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/hal/source/sdmmc

# The minimum set of files needed for lwIP.
subdir-ccflags-y += 	-I$(LWIP_PATH)/src/include/
subdir-ccflags-y += 	-I$(LWIP_PATH)/src/include/lwip/
subdir-ccflags-y += 	-I$(LWIP_PATH)/src/
subdir-ccflags-y += 	-I$(LWIP_PATH)/src/core/ipv4/
subdir-ccflags-y += 	-I$(LWIP_PATH)/src/arch/include/
subdir-ccflags-y += 	-I$(LWIP_PATH)/src/include/compat/posix
subdir-ccflags-y += 	-I$(srctree)/ekernel/components/thirdparty/net/rt-thread/lwip_dhcpd

subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/inc/priv
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/common/api
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/drv/macif
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/drv/sdio
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/drv/fw
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/drv/wlan
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/drv/fhost
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/drv/aic_bsp

subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/inc

subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/wpa_supplicant/src
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/wpa_supplicant/src/utils
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/wpa_supplicant/src/rsn_supp
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/wpa_supplicant/wpa_supplicant


subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/net_al/$(OS)
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/platform/aw_sdio
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/rtos_al/$(OS)
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/net_dev
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/net_dev/chip

ifeq ($(CONFIG_AIC_INTF_SDIO), y)
HCI_NAME = sdio
EXTRA_CFLAGS += -DCONFIG_SDIO_SUPPORT
endif
ifeq ($(CONFIG_AIC_INTF_USB), y)
EXTRA_CFLAGS += -DCONFIG_USB_SUPPORT
endif

EXTRA_CFLAGS += -DCONFIG_VENDOR_IE
EXTRA_CFLAGS += -DPLATFORM_ALLWIN_RT_THREAD
EXTRA_CFLAGS += -DCONFIG_RWNX_FULLMAC
EXTRA_CFLAGS += -DUSE_5G
EXTRA_CFLAGS += -DCONFIG_PMIC_SETTING
EXTRA_CFLAGS += -DCONFIG_DOWNLOAD_FW
EXTRA_CFLAGS += -DCONFIG_LOAD_USERCONFIG
EXTRA_CFLAGS += -DCONFIG_FHOST_RX_ASYNC
EXTRA_CFLAGS += -DCONFIG_REORD_FORWARD_LIST
EXTRA_CFLAGS += -DCONFIG_OFFCHANNEL
EXTRA_CFLAGS += -DCONFIG_P2P
EXTRA_CFLAGS += -DCONFIG_RWNX_DBG
EXTRA_CFLAGS += -DAIC_LOG_DEBUG_ON
EXTRA_CFLAGS += -DCONFIG_INTERWORKING
EXTRA_CFLAGS += -DCONFIG_GAS
EXTRA_CFLAGS += -DCONFIG_HS20


### MHD test ###
#subdir-ccflags-y += -DMHD_API_RELEASE -DMHD_API_TEST -DMHD_PING_TEST -DMHD_IPERF_TEST

subdir-ccflags-y += $(EXTRA_CFLAGS)

obj-y += drv_net.o
obj-y += dev_net.o
obj-y += chip/aic8800d40l_port.o


# TARGET := $(srctree)/ekernel/drivers/drv/source/net/aic8800/host/lib/libnetdev.a

# include $(MELIS_BASE)/scripts/Makefile.rename
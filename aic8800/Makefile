# This file is indended to be included in end-user CMakeLists.txt
# include(/path/to/Filelists.o \make)
# It assumes the variable srctree is defined pointing to the
# root path of lwIP sources.
#
# This file is NOT designed (on purpose) to be used as cmake
# subdir via add_subdirectory()
# The intention is to provide greater flexibility to users to
# create their own targets using the *_srcS variables.

# LWIP_VERSION_RC is set to LWIP_RC_RELEASE for official releases
# LWIP_VERSION_RC is set to LWIP_RC_DEVELOPMENT for Git versions
# Numbers 1..31 are reserved for release candidates
#
OS = aw_rtt

LWIP_PATH = $(srctree)/ekernel/components/thirdparty/net/rt-thread/lwip
SDMMC_INC_PATH = $(srctree)/ekernel/drivers/rtos-hal/include/hal/sdmmc

# sdmmc
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/sys/
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/hal
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/osal
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/os
subdir-ccflags-y += 	-I$(SDMMC_INC_PATH)/osal/RT-Thread
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/rtos-hal/hal/source/sdmmc

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
#EXTRA_CFLAGS += -DUSE_5G
EXTRA_CFLAGS += -DCONFIG_PMIC_SETTING
EXTRA_CFLAGS += -DCONFIG_DOWNLOAD_FW
EXTRA_CFLAGS += -DCONFIG_LOAD_USERCONFIG
EXTRA_CFLAGS += -DCONFIG_OFFCHANNEL
EXTRA_CFLAGS += -DCONFIG_P2P
EXTRA_CFLAGS += -DCONFIG_RWNX_DBG
EXTRA_CFLAGS += -DAIC_LOG_DEBUG_ON
EXTRA_CFLAGS += -DCONFIG_INTERWORKING
EXTRA_CFLAGS += -DCONFIG_GAS
EXTRA_CFLAGS += -DCONFIG_HS20
EXTRA_CFLAGS += -DCONFIG_FHOST_TX_SCHEDULE_SEPERATE
EXTRA_CFLAGS += -DCONFIG_FHOST_TX_AC_SCHEDULE
EXTRA_CFLAGS += -DCONFIG_WIFI_MODE_RFTEST

#EXTRA_CFLAGS += -DCONFIG_RWNX_RADAR
EXTRA_CFLAGS += -DFHOST_RX_REORDER=0
EXTRA_CFLAGS += -DRECOVER_ENABLE=0
EXTRA_CFLAGS += -DPLF_HW_PXP=0
EXTRA_CFLAGS += -DDUMP_RCV_DATA=0
EXTRA_CFLAGS += -DDUMP_XMT_DATA=0



### MHD test ###
#subdir-ccflags-y += -DMHD_API_RELEASE -DMHD_API_TEST -DMHD_PING_TEST -DMHD_IPERF_TEST

subdir-ccflags-y += $(EXTRA_CFLAGS)

COMMON_OPEN_FILES := \
			host/common/src/co_list.o \
			host/common/src/co_math.o \
			host/common/src/co_pool.o \
			host/common/src/co_ring.o \
			host/common/src/co_version.o
COMMON_PRIV_FILES :=
#host/common/src/co_dlist.o

DRV_OPEN_FILES := host/drv/fhost/fhost_config.o \
			host/drv/fhost/fhost_rx.o \
			host/drv/fhost/fhost_tx.o \
			host/drv/fhost/fhost_wpa_config.o \
			host/drv/aic_bsp/aic_bsp_driver.o \
			host/drv/aic_bsp/aic_bsp_main.o \
			host/drv/fw/aic_fw.o \
			host/drv/macif/cli_cmd.o \
			host/drv/macif/rwnx_main.o \
			host/drv/macif/rwnx_msg.o \
			host/drv/macif/rwnx_platform.o \
			host/drv/wlan/wifi_api_dummy.o

DRV_PRIV_FILES := host/drv/fhost/fhost.o \
			host/drv/fhost/fhost_ip.o \
			host/drv/fhost/fhost_ipc_cntrl.o \
			host/drv/fhost/fhost_wpa.o \
			host/drv/wlan/wlan_if.o \
			host/drv/fhost/fhost_cntrl.o \
			host/drv/macif/rwnx_msg_rx.o \
			host/drv/macif/rwnx_msg_tx.o \
			host/drv/macif/rwnx_cmds.o \
			host/drv/macif/rwnx_utils.o \
			host/drv/macif/rwnx_radar.o

NET_AL_OPEN_FILES := host/net_al/$(OS)/net_al.o
NET_AL_PRIV_FILES :=
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/net_al/$(OS)

PLATFORM_OPEN_FILES := host/platform/aw_sdio/porting.o \
			host/platform/aw_sdio/$(HCI_NAME)_port.o\
			host/platform/aw_sdio/plat_config.o 
PLATFORM_PRIV_FILES :=
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/platform/aw_sdio

RTOS_AL_OPEN_FILES := host/rtos_al/$(OS)/rtos_al.o
RTOS_AL_PRIV_FILES :=
subdir-ccflags-y += 	-I$(srctree)/ekernel/drivers/drv/source/net/aic8800/host/rtos_al/$(OS)

P2P_PRIV_FILES := host/wpa_supplicant/src/ap/wps_hostapd.o \
			host/wpa_supplicant/src/eapol_supp/eapol_supp_sm.o \
			host/wpa_supplicant/src/eap_peer/eap_methods.o \
			host/wpa_supplicant/src/eap_peer/eap.o \
			host/wpa_supplicant/wpa_supplicant/wps_supplicant.o \
			host/wpa_supplicant/wpa_supplicant/offchannel.o \
			host/wpa_supplicant/wpa_supplicant/p2p_supplicant.o \
			host/wpa_supplicant/wpa_supplicant/p2p_supplicant_sd.o \
			host/wpa_supplicant/wpa_supplicant/wifi_display.o \

WPA_OPEN_FILES :=
WPA_PRIV_FILES := host/wpa_supplicant/src/ap/ap_config.o \
			host/wpa_supplicant/src/ap/acs.o \
			host/wpa_supplicant/src/ap/ap_drv_ops.o \
			host/wpa_supplicant/src/ap/ap_list.o \
			host/wpa_supplicant/src/ap/ap_mlme.o \
			host/wpa_supplicant/src/ap/authsrv.o \
			host/wpa_supplicant/src/ap/beacon.o \
			host/wpa_supplicant/src/ap/bss_load.o \
			host/wpa_supplicant/src/ap/ctrl_iface_ap.o \
			host/wpa_supplicant/src/ap/dfs.o \
			host/wpa_supplicant/src/ap/drv_callbacks.o \
			host/wpa_supplicant/src/ap/eap_user_db.o \
			host/wpa_supplicant/src/ap/hostapd.o \
			host/wpa_supplicant/src/ap/hw_features.o \
			host/wpa_supplicant/src/ap/ieee802_11.o \
			host/wpa_supplicant/src/ap/ieee802_11_auth.o \
			host/wpa_supplicant/src/ap/ieee802_11_he.o \
			host/wpa_supplicant/src/ap/ieee802_11_ht.o \
			host/wpa_supplicant/src/ap/ieee802_11_shared.o \
			host/wpa_supplicant/src/ap/ieee802_11_vht.o \
			host/wpa_supplicant/src/ap/ieee802_1x.o \
			host/wpa_supplicant/src/ap/neighbor_db.o \
			host/wpa_supplicant/src/ap/pmksa_cache_auth.o \
			host/wpa_supplicant/src/ap/p2p_hostapd.o \
			host/wpa_supplicant/src/ap/rrm.o \
			host/wpa_supplicant/src/ap/sta_info.o \
			host/wpa_supplicant/src/ap/tkip_countermeasures.o \
			host/wpa_supplicant/src/ap/utils.o \
			host/wpa_supplicant/src/ap/wmm.o \
			host/wpa_supplicant/src/ap/wnm_ap.o \
			host/wpa_supplicant/src/ap/wpa_auth.o \
			host/wpa_supplicant/src/ap/wpa_auth_glue.o \
			host/wpa_supplicant/src/ap/wpa_auth_ie.o \
			host/wpa_supplicant/src/common/hw_features_common.o \
			host/wpa_supplicant/src/common/ieee802_11_common.o \
			host/wpa_supplicant/src/common/wpa_common.o \
			host/wpa_supplicant/src/common/gas.o \
			host/wpa_supplicant/src/crypto/aes-internal-dec.o \
			host/wpa_supplicant/src/crypto/aes-internal-enc.o \
			host/wpa_supplicant/src/crypto/aes-internal.o \
			host/wpa_supplicant/src/crypto/aes-cbc.o \
			host/wpa_supplicant/src/crypto/aes-omac1.o \
			host/wpa_supplicant/src/crypto/aes-unwrap.o \
			host/wpa_supplicant/src/crypto/aes-wrap.o \
			host/wpa_supplicant/src/crypto/crypto_internal-modexp.o \
			host/wpa_supplicant/src/crypto/dh_groups.o \
			host/wpa_supplicant/src/crypto/dh_group5.o \
			host/wpa_supplicant/src/crypto/md5-internal.o \
			host/wpa_supplicant/src/crypto/md5.o \
			host/wpa_supplicant/src/crypto/random.o \
			host/wpa_supplicant/src/crypto/rc4.o \
			host/wpa_supplicant/src/crypto/sha1-internal.o \
			host/wpa_supplicant/src/crypto/sha1-pbkdf2.o \
			host/wpa_supplicant/src/crypto/sha1-prf.o \
			host/wpa_supplicant/src/crypto/sha1.o \
			host/wpa_supplicant/src/crypto/sha256-internal.o \
			host/wpa_supplicant/src/crypto/sha256-prf.o \
			host/wpa_supplicant/src/crypto/sha256.o \
			host/wpa_supplicant/src/crypto/tls_none.o \
			host/wpa_supplicant/src/drivers/drivers.o \
			host/wpa_supplicant/src/drivers/driver_common.o \
			host/wpa_supplicant/src/drivers/driver_rwnx.o \
			host/wpa_supplicant/src/eapol_auth/eapol_auth_sm.o \
			host/wpa_supplicant/src/eap_common/chap.o \
			host/wpa_supplicant/src/eap_common/eap_common.o \
			host/wpa_supplicant/src/eap_common/eap_wsc_common.o \
			host/wpa_supplicant/src/eap_server/eap_server.o \
			host/wpa_supplicant/src/eap_server/eap_server_identity.o \
			host/wpa_supplicant/src/eap_server/eap_server_methods.o \
			host/wpa_supplicant/src/eap_server/eap_server_wsc.o \
			host/wpa_supplicant/src/eap_peer/eap_wsc.o \
			host/wpa_supplicant/src/l2_packet/l2_packet_rwnx.o \
			host/wpa_supplicant/src/p2p/p2p_build.o \
			host/wpa_supplicant/src/p2p/p2p.o \
			host/wpa_supplicant/src/p2p/p2p_dev_disc.o \
			host/wpa_supplicant/src/p2p/p2p_go_neg.o \
			host/wpa_supplicant/src/p2p/p2p_group.o \
			host/wpa_supplicant/src/p2p/p2p_invitation.o \
			host/wpa_supplicant/src/p2p/p2p_parse.o \
			host/wpa_supplicant/src/p2p/p2p_pd.o \
			host/wpa_supplicant/src/p2p/p2p_sd.o \
			host/wpa_supplicant/src/p2p/p2p_utils.o \
			host/wpa_supplicant/src/rsn_supp/preauth.o \
			host/wpa_supplicant/src/rsn_supp/wpa.o \
			host/wpa_supplicant/src/rsn_supp/wpa_ie.o \
			host/wpa_supplicant/src/rsn_supp/pmksa_cache.o \
			host/wpa_supplicant/src/tls/bignum.o \
			host/wpa_supplicant/src/utils/base64.o \
			host/wpa_supplicant/src/utils/bitfield.o \
			host/wpa_supplicant/src/utils/common.o \
			host/wpa_supplicant/src/utils/eloop.o \
			host/wpa_supplicant/src/utils/ip_addr.o \
			host/wpa_supplicant/src/utils/os_rwnx.o \
			host/wpa_supplicant/src/utils/uuid.o \
			host/wpa_supplicant/src/utils/wpabuf.o \
			host/wpa_supplicant/src/utils/wpa_debug.o \
			host/wpa_supplicant/src/wps/wps.o \
			host/wpa_supplicant/src/wps/wps_attr_build.o \
			host/wpa_supplicant/src/wps/wps_attr_parse.o \
			host/wpa_supplicant/src/wps/wps_attr_process.o \
			host/wpa_supplicant/src/wps/wps_common.o \
			host/wpa_supplicant/src/wps/wps_dev_attr.o \
			host/wpa_supplicant/src/wps/wps_enrollee.o \
			host/wpa_supplicant/src/wps/wps_registrar.o \
			host/wpa_supplicant/wpa_supplicant/ap.o \
			host/wpa_supplicant/wpa_supplicant/blacklist.o \
			host/wpa_supplicant/wpa_supplicant/bss.o \
			host/wpa_supplicant/wpa_supplicant/config.o \
			host/wpa_supplicant/wpa_supplicant/config_none.o \
			host/wpa_supplicant/wpa_supplicant/ctrl_iface.o \
			host/wpa_supplicant/wpa_supplicant/ctrl_iface_udp.o \
			host/wpa_supplicant/wpa_supplicant/eap_register.o \
			host/wpa_supplicant/wpa_supplicant/events.o \
			host/wpa_supplicant/wpa_supplicant/main_rwnx.o \
			host/wpa_supplicant/wpa_supplicant/notify.o \
			host/wpa_supplicant/wpa_supplicant/op_classes.o \
			host/wpa_supplicant/wpa_supplicant/scan.o \
			host/wpa_supplicant/wpa_supplicant/sta_rrm.o \
			host/wpa_supplicant/wpa_supplicant/wmm_ac.o \
			host/wpa_supplicant/wpa_supplicant/wpas_glue.o \
			host/wpa_supplicant/wpa_supplicant/wpa_supplicant.o \
			host/wpa_supplicant/wpa_supplicant/interworking.o \
			host/wpa_supplicant/wpa_supplicant/gas_query.o \
			host/wpa_supplicant/wpa_supplicant/hs20_supplicant.o  \
			host/wpa_supplicant/src/ap/hs20.o \
			host/wpa_supplicant/src/ap/gas_serv.o
IW_OPEN_FILES := iw/iw.o \
			iw/iw_handlers.o
IW_PRIV_FILES :=

#PRIV_OBJS += $(APP_PRIV_FILES)
PRIV_OBJS += $(COMMON_PRIV_FILES)
PRIV_OBJS += $(DRV_PRIV_FILES)
PRIV_OBJS += $(NET_AL_PRIV_FILES)
PRIV_OBJS += $(PLATFORM_PRIV_FILES)
PRIV_OBJS += $(RTOS_AL_PRIV_FILES)
PRIV_OBJS += $(WPA_PRIV_FILES)
#PRIV_OBJS += $(OTHER_PRIV_FILES)
PRIV_OBJS += $(P2P_PRIV_FILES)

#OPEN_OBJS += $(APP_OPEN_FILES)
OPEN_OBJS += $(COMMON_OPEN_FILES)
OPEN_OBJS += $(DRV_OPEN_FILES)
OPEN_OBJS += $(NET_AL_OPEN_FILES)
OPEN_OBJS += $(PLATFORM_OPEN_FILES)
OPEN_OBJS += $(RTOS_AL_OPEN_FILES)
OPEN_OBJS += $(WPA_OPEN_FILES)
#OPEN_OBJS += $(OTHER_OPEN_FILES)
#OPEN_OBJS += $(IW_OPEN_FILES)

obj-$(CONFIG_AIC8800) += src/aic_cmd.o \
			userconfig.o \
			wifi.o

obj-$(CONFIG_AIC8800) += $(OPEN_OBJS)

CONFIG_AIC_BUILD_LIB=n
CONFIG_AIC_USE_LIB=n

ifeq ($(CONFIG_AIC_BUILD_LIB),y)

# make aic8800 lib
lib-y += $(PRIV_OBJS)

TARGET := $(srctree)/ekernel/drivers/drv/source/net/aic8800/host/lib/libsdiowifi-aic8800.a

include $(MELIS_BASE)/scripts/Makefile.rename

endif

ifeq ($(CONFIG_AIC_USE_LIB),y)

obj-$(CONFIG_AIC8800) += host/lib/libsdiowifi-aic8800.a

else

obj-$(CONFIG_AIC8800) += $(PRIV_OBJS)

endif

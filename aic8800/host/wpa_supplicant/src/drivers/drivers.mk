##### CLEAR VARS

DRV_CFLAGS =
DRV_WPA_CFLAGS =
DRV_AP_CFLAGS =
DRV_OBJS =
DRV_WPA_OBJS =
DRV_AP_OBJS =
DRV_LIBS =
DRV_WPA_LIBS =
DRV_AP_LIBS =

##### COMMON DRIVERS

ifdef CONFIG_DRIVER_WIRED
DRV_CFLAGS += -DCONFIG_DRIVER_WIRED
DRV_OBJS += src/drivers/driver_wired.c
NEED_DRV_WIRED_COMMON=1
endif

ifdef CONFIG_DRIVER_MACSEC_LINUX
DRV_CFLAGS += -DCONFIG_DRIVER_MACSEC_LINUX
DRV_OBJS += src/drivers/driver_macsec_linux.c
NEED_DRV_WIRED_COMMON=1
CONFIG_LIBNL3_ROUTE=y
NEED_LIBNL=y
endif

ifdef NEED_DRV_WIRED_COMMON
DRV_OBJS += src/drivers/driver_wired_common.c
endif

ifdef CONFIG_DRIVER_NL80211
DRV_CFLAGS += -DCONFIG_DRIVER_NL80211
DRV_OBJS += src/drivers/driver_nl80211.c
DRV_OBJS += src/drivers/driver_nl80211_android.c
DRV_OBJS += src/drivers/driver_nl80211_capa.c
DRV_OBJS += src/drivers/driver_nl80211_event.c
DRV_OBJS += src/drivers/driver_nl80211_monitor.c
DRV_OBJS += src/drivers/driver_nl80211_scan.c
ifdef CONFIG_DRIVER_NL80211_QCA
DRV_CFLAGS += -DCONFIG_DRIVER_NL80211_QCA
endif
NEED_SME=y
NEED_AP_MLME=y
NEED_NETLINK=y
NEED_LINUX_IOCTL=y
NEED_RFKILL=y
NEED_RADIOTAP=y
NEED_LIBNL=y
endif

ifdef CONFIG_DRIVER_BSD
ifndef CONFIG_L2_PACKET
CONFIG_L2_PACKET=freebsd
endif
DRV_CFLAGS += -DCONFIG_DRIVER_BSD
DRV_OBJS += src/drivers/driver_bsd.c
CONFIG_L2_FREEBSD=y
CONFIG_DNET_PCAP=y
endif

ifdef CONFIG_DRIVER_OPENBSD
ifndef CONFIG_L2_PACKET
CONFIG_L2_PACKET=freebsd
endif
DRV_CFLAGS += -DCONFIG_DRIVER_OPENBSD
DRV_OBJS += src/drivers/driver_openbsd.c
endif

ifdef CONFIG_DRIVER_NONE
DRV_CFLAGS += -DCONFIG_DRIVER_NONE
DRV_OBJS += src/drivers/driver_none.c
endif

##### PURE AP DRIVERS

ifdef CONFIG_DRIVER_HOSTAP
DRV_AP_CFLAGS += -DCONFIG_DRIVER_HOSTAP
DRV_AP_OBJS += src/drivers/driver_hostap.c
CONFIG_WIRELESS_EXTENSION=y
NEED_AP_MLME=y
NEED_NETLINK=y
NEED_LINUX_IOCTL=y
endif

ifdef CONFIG_DRIVER_ATHEROS
DRV_AP_CFLAGS += -DCONFIG_DRIVER_ATHEROS
DRV_AP_OBJS += src/drivers/driver_atheros.c
CONFIG_L2_PACKET=linux
NEED_NETLINK=y
NEED_LINUX_IOCTL=y
endif

##### PURE CLIENT DRIVERS

ifdef CONFIG_DRIVER_WEXT
DRV_WPA_CFLAGS += -DCONFIG_DRIVER_WEXT
CONFIG_WIRELESS_EXTENSION=y
NEED_NETLINK=y
NEED_LINUX_IOCTL=y
NEED_RFKILL=y
endif

ifdef CONFIG_DRIVER_NDIS
DRV_WPA_CFLAGS += -DCONFIG_DRIVER_NDIS
DRV_WPA_OBJS += src/drivers/driver_ndis.c
ifdef CONFIG_NDIS_EVENTS_INTEGRATED
DRV_WPA_OBJS += src/drivers/driver_ndis_.c
endif
ifndef CONFIG_L2_PACKET
CONFIG_L2_PACKET=pcap
endif
CONFIG_WINPCAP=y
ifdef CONFIG_USE_NDISUIO
DRV_WPA_CFLAGS += -DCONFIG_USE_NDISUIO
endif
endif

ifdef CONFIG_DRIVER_ROBOSWITCH
DRV_WPA_CFLAGS += -DCONFIG_DRIVER_ROBOSWITCH
DRV_WPA_OBJS += src/drivers/driver_roboswitch.c
endif

ifdef CONFIG_WIRELESS_EXTENSION
DRV_WPA_CFLAGS += -DCONFIG_WIRELESS_EXTENSION
DRV_WPA_OBJS += src/drivers/driver_wext.c
NEED_RFKILL=y
endif

ifdef NEED_NETLINK
DRV_OBJS += src/drivers/netlink.c
endif

ifdef NEED_LINUX_IOCTL
DRV_OBJS += src/drivers/linux_ioctl.c
endif

ifdef NEED_RFKILL
DRV_OBJS += src/drivers/rfkill.c
endif

ifdef NEED_RADIOTAP
DRV_OBJS += src/utils/radiotap.c
endif

ifdef CONFIG_DRIVER_CUSTOM
DRV_CFLAGS += -DCONFIG_DRIVER_CUSTOM
endif

ifdef CONFIG_VLAN_NETLINK
ifdef CONFIG_FULL_DYNAMIC_VLAN
NEED_LIBNL=y
CONFIG_LIBNL3_ROUTE=y
endif
endif

ifdef NEED_LIBNL
ifdef CONFIG_LIBNL32
  DRV_LIBS += -lnl-3
  DRV_LIBS += -lnl-genl-3
  DRV_CFLAGS += -DCONFIG_LIBNL20 -I/usr/include/libnl3
ifdef CONFIG_LIBNL3_ROUTE
  DRV_LIBS += -lnl-route-3
  DRV_CFLAGS += -DCONFIG_LIBNL3_ROUTE
endif
else
  ifdef CONFIG_LIBNL_TINY
    DRV_LIBS += -lnl-tiny
  else
    DRV_LIBS += -lnl
  endif

  ifdef CONFIG_LIBNL20
    ifndef CONFIG_LIBNL_TINY
      DRV_LIBS += -lnl-genl
    endif
    DRV_CFLAGS += -DCONFIG_LIBNL20
  endif
endif
endif

##### COMMON VARS
DRV_BOTH_CFLAGS := $(DRV_CFLAGS) $(DRV_WPA_CFLAGS) $(DRV_AP_CFLAGS)
DRV_WPA_CFLAGS += $(DRV_CFLAGS)
DRV_AP_CFLAGS += $(DRV_CFLAGS)

DRV_BOTH_LIBS := $(DRV_LIBS) $(DRV_WPA_LIBS) $(DRV_AP_LIBS)
DRV_WPA_LIBS += $(DRV_LIBS)
DRV_AP_LIBS += $(DRV_LIBS)

DRV_BOTH_OBJS := $(DRV_OBJS) $(DRV_WPA_OBJS) $(DRV_AP_OBJS)
DRV_WPA_OBJS += $(DRV_OBJS)
DRV_AP_OBJS += $(DRV_OBJS)

DRV_BOTH_LDFLAGS := $(DRV_LDFLAGS) $(DRV_WPA_LDFLAGS) $(DRV_AP_LDFLAGS)
DRV_WPA_LDFLAGS += $(DRV_LDFLAGS)
DRV_AP_LDFLAGS += $(DRV_LDFLAGS)

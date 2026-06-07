# Makefile - 私密图库应用（传统 Make 构建系统）
#
# 小米手环9 Pro (openvela)
# 注意：实际构建使用 CMakeList.txt，此文件为兼容性保留

include $(APPDIR)/Make.defs

ifeq ($(CONFIG_LVX_USE_DEMO_PRIVATE_GALLERY), y)
PROGNAME = ${CONFIG_PRIVATE_GALLERY_PROGNAME}
PRIORITY = ${CONFIG_PRIVATE_GALLERY_PRIORITY}
STACKSIZE = ${CONFIG_PRIVATE_GALLERY_STACKSIZE}
MODULE = $(CONFIG_LVX_USE_DEMO_PRIVATE_GALLERY)

CSRCS = private_gallery.c
MAINSRC = private_gallery_main.c
endif

include $(APPDIR)/Application.mk

# CMakeLists.txt - 私密图库应用构建脚本
#
# 小米手环9 Pro (openvela)

if(CONFIG_LVX_USE_DEMO_PRIVATE_GALLERY)
  nuttx_add_application(
    NAME
    ${CONFIG_PRIVATE_GALLERY_PROGNAME}

    SRCS
    private_gallery_main.c
    private_gallery.c

    STACKSIZE
    ${CONFIG_PRIVATE_GALLERY_STACKSIZE}

    PRIORITY
    ${CONFIG_PRIVATE_GALLERY_PRIORITY}

    INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}

    DEPENDS
    lvgl
  )
endif()

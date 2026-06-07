/**
 * private_gallery.h - 私密图库手表端头文件
 *
 * 小米手环9 Pro (openvela/LVGL)
 *
 * 设计原则:
 * - 手表端任何界面上绝不对用户显示存在"私密"和"普通"两种模式
 * - 统一标题"图库"，统一密码输入界面
 * - 密码决定显示哪组图片，但UI本身无差别
 * - 使用常量时间密码比较防止时序攻击
 * - 密码以SHA-256哈希存储
 * - 退出即锁定，不留任何模式痕迹
 */

#ifndef __PRIVATE_GALLERY_H__
#define __PRIVATE_GALLERY_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "lvgl/lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 配置常量
 * ================================================================ */

/** 密码长度（固定6位数字） */
#define PG_PIN_LENGTH           6

/** 密码尝试最大次数，超过后锁定一段时间 */
#define PG_MAX_ATTEMPTS         5

/** 锁定时间（毫秒） */
#define PG_LOCKOUT_DURATION_MS  30000

/** 缩略图尺寸 */
#define PG_THUMB_SIZE           60

/** 缩略图列数 */
#define PG_GRID_COLS            3

/** 缩略图间距 */
#define PG_GRID_SPACING         4

/** 屏幕宽度（小米手环9 Pro: 194*368，横屏使用为 368*194） */
#define PG_SCREEN_W             368
#define PG_SCREEN_H             194

/** 图片基础路径 */
#define PG_BASE_PATH            "/data/gallery"

/** 普通图片目录 */
#define PG_NORMAL_DIR           "/data/gallery/normal"

/** 私密图片目录 */
#define PG_PRIVATE_DIR          "/data/gallery/private"

/** 密码哈希存储文件 */
#define PG_PASSWORD_FILE        "/data/gallery/.pw"

/** 图片文件扩展名过滤 */
#define PG_IMAGE_EXTS           ".png,.bmp,.jpg,.jpeg,.bin"

/** 每页加载的最大图片数 */
#define PG_MAX_IMAGES           200

/* ================================================================
 * 图库模式（仅在内部使用，绝不在UI上暴露）
 * ================================================================ */

typedef enum {
    PG_MODE_NORMAL = 0,     /**< 普通模式 */
    PG_MODE_PRIVATE = 1,    /**< 私密模式 */
    PG_MODE_NONE = 2        /**< 未解锁 */
} pg_mode_t;

/* ================================================================
 * 数据结构
 * ================================================================ */

/** 图片条目 */
typedef struct {
    char    path[256];      /**< 图片文件完整路径 */
    char    name[128];      /**< 图片文件名 */
    lv_img_dsc_t *thumbnail; /**< 缩略图描述符（LVGL 9.x 使用 lv_image_dsc_t） */
    bool    thumbnail_loaded; /**< 缩略图是否已加载 */
} pg_image_t;

/** 应用运行时上下文 */
typedef struct {
    /* --- UI 对象 --- */
    lv_obj_t    *screen_main;       /**< 主屏幕（密码输入） */
    lv_obj_t    *screen_gallery;    /**< 图库浏览屏幕 */
    lv_obj_t    *screen_viewer;     /**< 图片查看屏幕 */

    /* --- 密码输入 --- */
    char        pin_buffer[PG_PIN_LENGTH + 1]; /**< 当前输入的PIN */
    uint8_t     pin_index;          /**< 已输入的位数 */
    lv_obj_t    *pin_dots[PG_PIN_LENGTH]; /**< 密码圆点控件 */
    lv_obj_t    *pin_label;         /**< 密码提示标签 */

    /* --- 模式与安全 --- */
    pg_mode_t   current_mode;       /**< 当前解锁模式 */
    uint8_t     attempt_count;      /**< 失败尝试次数 */
    uint64_t    lockout_until;      /**< 锁定截止时间（毫秒时间戳） */

    /* --- 图片列表 --- */
    pg_image_t  *images;            /**< 图片数组 */
    uint16_t    image_count;        /**< 图片总数 */
    uint16_t    current_index;      /**< 当前查看的图片索引 */

    /* --- 图库网格 --- */
    lv_obj_t    *grid_cont;         /**< 网格容器 */

    /* --- 图片查看器 --- */
    lv_obj_t    *viewer_img;        /**< 查看器中的图片对象 */
    lv_obj_t    *viewer_label;      /**< 查看器中的计数器标签 */
    lv_obj_t    *viewer_prev_area;  /**< 左滑区域 */
    lv_obj_t    *viewer_next_area;  /**< 右滑区域 */

    /* --- 密码哈希 --- */
    uint8_t     normal_pw_hash[32]; /**< 普通密码 SHA-256 */
    uint8_t     private_pw_hash[32]; /**< 私密密码 SHA-256 */

    /* --- 定时器 --- */
    lv_timer_t  *lockout_timer;     /**< 锁定倒计时定时器 */
} pg_context_t;

/* ================================================================
 * 全局上下文
 * ================================================================ */

extern pg_context_t g_pg;

/* ================================================================
 * 公共 API
 * ================================================================ */

/**
 * 应用入口：创建并初始化私密图库
 */
void pg_app_create(void);

/**
 * 锁定图库，返回密码输入界面
 */
void pg_lock(void);

/**
 * 退出图库应用
 */
void pg_app_destroy(void);

/* ================================================================
 * 密码模块
 * ================================================================ */

/**
 * 初始化密码系统，加载密码哈希
 */
void pg_password_init(void);

/**
 * 验证输入的密码
 * @param pin  6位数字密码字符串
 * @return     匹配的模式（PG_MODE_NORMAL/PG_MODE_PRIVATE/PG_MODE_NONE）
 *
 * 注意：使用常量时间比较，防止时序攻击推断密码正确性
 */
pg_mode_t pg_password_verify(const char *pin);

/**
 * 保存密码（从Android端调用）
 * @param mode  密码类型
 * @param pin   6位数字密码字符串
 * @return      0成功，-1失败
 */
int pg_password_save(pg_mode_t mode, const char *pin);

/* ================================================================
 * 密码输入界面
 * ================================================================ */

/**
 * 创建密码输入界面
 */
void pg_create_password_screen(void);

/**
 * 处理数字按键
 */
void pg_password_input_digit(char digit);

/**
 * 处理退格
 */
void pg_password_input_backspace(void);

/**
 * 确认密码输入
 */
void pg_password_confirm(void);

/* ================================================================
 * 图库浏览界面
 * ================================================================ */

/**
 * 创建图库浏览界面
 */
void pg_create_gallery_screen(void);

/**
 * 加载图片列表
 * @param dir_path  图片目录路径
 */
int pg_load_image_list(const char *dir_path);

/**
 * 刷新图库网格
 */
void pg_refresh_gallery_grid(void);

/**
 * 释放已加载的图片资源
 */
void pg_free_image_list(void);

/* ================================================================
 * 图片查看器界面
 * ================================================================ */

/**
 * 创建图片查看器
 */
void pg_create_viewer_screen(void);

/**
 * 显示指定索引的图片
 */
void pg_viewer_show_image(uint16_t index);

/**
 * 显示上一张图片
 */
void pg_viewer_prev(void);

/**
 * 显示下一张图片
 */
void pg_viewer_next(void);

/* ================================================================
 * 工具函数
 * ================================================================ */

/**
 * 常量时间内存比较（防止时序攻击）
 * @return  0相同，非0不同
 */
int pg_const_memcmp(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * 简易 SHA-256 实现
 */
void pg_sha256(const uint8_t *data, size_t len, uint8_t *hash);

/**
 * 检查是否为支持的图片文件
 */
bool pg_is_image_file(const char *filename);

/**
 * 检查文件是否存在
 */
bool pg_file_exists(const char *path);

/**
 * 确保目录存在
 */
int pg_mkdir_p(const char *path);

/**
 * 获取当前毫秒时间戳
 */
uint64_t pg_get_tick_ms(void);

#ifdef __cplusplus
}
#endif

#endif /* __PRIVATE_GALLERY_H__ */

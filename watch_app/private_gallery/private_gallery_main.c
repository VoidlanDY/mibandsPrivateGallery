/**
 * private_gallery_main.c - 私密图库应用主入口
 *
 * 小米手环9 Pro (openvela/NuttX)
 *
 * 作为系统应用运行，自启动或从启动器打开
 */

#include "private_gallery.h"

/**
 * main - NuttX 任务入口
 *
 * 用法（在 NSH 终端中）:
 *   pgallery &       # 后台运行
 */
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* 初始化LVGL（如果尚未初始化） */
    /* 注意：在实际部署中，LVGL 已由系统初始化 */

    /* 创建应用 */
    pg_app_create();

    /* 进入事件循环
     * 在 openvela 中，LVGL 定时器和事件在后台处理
     * main 返回后任务退出，但LVGL对象保留
     * 因此需要保持任务运行来处理生命周期事件 */
    while (g_pg.screen_main || g_pg.screen_gallery || g_pg.screen_viewer) {
        lv_timer_handler();
        usleep(5000); /* 5ms 延迟，减少CPU占用 */
    }

    return 0;
}
// trigger ci check

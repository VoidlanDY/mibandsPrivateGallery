/**
 * private_gallery.c - 私密图库核心实现
 *
 * 小米手环9 Pro (openvela/LVGL)
 *
 * 核心隐私设计：
 * 1. 手表端所有界面完全相同，不暴露"普通/私密"模式的存在
 * 2. 使用常量时间密码比较，防止时序分析
 * 3. 密码哈希存储，不可逆
 * 4. 错误提示统一为"密码错误"，不区分是哪种密码错了
 * 5. 退出即全部锁定，下次进入需要重新输入密码
 * 6. 连续失败5次锁定30秒
 * 7. 图片目录在文件系统层面完全分离
 * 8. 不提供任何设置菜单或模式切换入口
 */

#include "private_gallery.h"

/* ================================================================
 * 全局上下文
 * ================================================================ */

pg_context_t g_pg;

/* ================================================================
 * 常量时间内存比较
 * ================================================================ */

int pg_const_memcmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    /* 返回0表示相同，非0表示不同。
     * 这个比较不会提前退出，执行时间与数据无关 */
    return (int)diff;
}

/* ================================================================
 * 简易 SHA-256 实现（适用于嵌入式环境）
 * ================================================================ */

/* SHA-256 常量 */
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t sha256_rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

#define SHA256_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_BSIG0(x)   (sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22))
#define SHA256_BSIG1(x)   (sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25))
#define SHA256_SSIG0(x)   (sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3))
#define SHA256_SSIG1(x)   (sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10))

void pg_sha256(const uint8_t *data, size_t len, uint8_t *hash)
{
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint8_t block[64];
    uint32_t w[64];
    size_t block_idx = 0;
    uint64_t bit_len = (uint64_t)len * 8;

    /* 处理每个完整块 */
    for (size_t i = 0; i < len; i++) {
        block[block_idx++] = data[i];
        if (block_idx == 64) {
            /* 扩展消息调度 */
            for (int t = 0; t < 16; t++) {
                w[t] = ((uint32_t)block[t*4] << 24) |
                       ((uint32_t)block[t*4+1] << 16) |
                       ((uint32_t)block[t*4+2] << 8) |
                       ((uint32_t)block[t*4+3]);
            }
            for (int t = 16; t < 64; t++) {
                w[t] = SHA256_SSIG1(w[t-2]) + w[t-7] +
                       SHA256_SSIG0(w[t-15]) + w[t-16];
            }

            /* 压缩 */
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int t = 0; t < 64; t++) {
                uint32_t t1 = hh + SHA256_BSIG1(e) + SHA256_CH(e,f,g) + sha256_k[t] + w[t];
                uint32_t t2 = SHA256_BSIG0(a) + SHA256_MAJ(a,b,c);
                hh = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
            block_idx = 0;
        }
    }

    /* 填充 */
    block[block_idx++] = 0x80;
    if (block_idx > 56) {
        while (block_idx < 64) block[block_idx++] = 0;
        /* 处理填充块 */
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint32_t)block[t*4] << 24) |
                   ((uint32_t)block[t*4+1] << 16) |
                   ((uint32_t)block[t*4+2] << 8) |
                   ((uint32_t)block[t*4+3]);
        }
        for (int t = 16; t < 64; t++) {
            w[t] = SHA256_SSIG1(w[t-2]) + w[t-7] +
                   SHA256_SSIG0(w[t-15]) + w[t-16];
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int t = 0; t < 64; t++) {
            uint32_t t1 = hh + SHA256_BSIG1(e) + SHA256_CH(e,f,g) + sha256_k[t] + w[t];
            uint32_t t2 = SHA256_BSIG0(a) + SHA256_MAJ(a,b,c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        block_idx = 0;
    }
    while (block_idx < 56) block[block_idx++] = 0;

    /* 写入长度 */
    for (int i = 7; i >= 0; i--) {
        block[56 + i] = (uint8_t)(bit_len >> ((7-i) * 8));
    }

    /* 处理最后一个块 */
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[t*4] << 24) |
               ((uint32_t)block[t*4+1] << 16) |
               ((uint32_t)block[t*4+2] << 8) |
               ((uint32_t)block[t*4+3]);
    }
    for (int t = 16; t < 64; t++) {
        w[t] = SHA256_SSIG1(w[t-2]) + w[t-7] +
               SHA256_SSIG0(w[t-15]) + w[t-16];
    }
    {
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int t = 0; t < 64; t++) {
            uint32_t t1 = hh + SHA256_BSIG1(e) + SHA256_CH(e,f,g) + sha256_k[t] + w[t];
            uint32_t t2 = SHA256_BSIG0(a) + SHA256_MAJ(a,b,c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    /* 输出 */
    for (int i = 0; i < 8; i++) {
        hash[i*4]     = (uint8_t)(h[i] >> 24);
        hash[i*4 + 1] = (uint8_t)(h[i] >> 16);
        hash[i*4 + 2] = (uint8_t)(h[i] >> 8);
        hash[i*4 + 3] = (uint8_t)(h[i]);
    }
}

/* ================================================================
 * 时间戳工具
 * ================================================================ */

uint64_t pg_get_tick_ms(void)
{
    return lv_tick_get();
}

/* ================================================================
 * 文件系统工具
 * ================================================================ */

bool pg_file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

bool pg_is_image_file(const char *filename)
{
    const char *ext = strrchr(filename, '.');
    if (!ext) return false;

    /* 不区分大小写检查 */
    size_t ext_len = strlen(ext);
    if (ext_len < 3 || ext_len > 5) return false;

    char lower_ext[6];
    for (size_t i = 0; i < ext_len && i < 5; i++) {
        lower_ext[i] = (ext[i] >= 'A' && ext[i] <= 'Z')
                       ? ext[i] + 32 : ext[i];
    }
    lower_ext[ext_len] = '\0';

    return (strcmp(lower_ext, ".png") == 0 ||
            strcmp(lower_ext, ".bmp") == 0 ||
            strcmp(lower_ext, ".jpg") == 0 ||
            strcmp(lower_ext, ".jpeg") == 0 ||
            strcmp(lower_ext, ".bin") == 0);
}

int pg_mkdir_p(const char *path)
{
    char tmp[256];
    size_t len = strlen(path);

    if (len >= sizeof(tmp)) return -1;

    for (size_t i = 0; i < len; i++) {
        tmp[i] = path[i];
        if ((path[i] == '/' && i > 0) || i == len - 1) {
            if (i == len - 1 && path[i] != '/') {
                tmp[i+1] = '\0';
            } else if (i > 0) {
                tmp[i] = '\0';
            } else {
                continue;
            }
            struct stat st;
            if (stat(tmp, &st) != 0) {
                if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

/* ================================================================
 * 密码系统
 * ================================================================ */

void pg_password_init(void)
{
    /* 确保目录存在 */
    pg_mkdir_p(PG_BASE_PATH);
    pg_mkdir_p(PG_NORMAL_DIR);
    pg_mkdir_p(PG_PRIVATE_DIR);

    /* 尝试加载密码文件 */
    FILE *fp = fopen(PG_PASSWORD_FILE, "rb");
    if (fp) {
        size_t nread = fread(g_pg.normal_pw_hash, 1, 32, fp);
        if (nread < 32) {
            /* 文件不完整，使用默认密码 "000000" */
            pg_sha256((const uint8_t *)"000000", 6, g_pg.normal_pw_hash);
            memset(g_pg.private_pw_hash, 0, 32);
        }
        nread = fread(g_pg.private_pw_hash, 1, 32, fp);
        if (nread < 32) {
            /* 没有私密密码，初始为空（任何密码都无法匹配） */
            memset(g_pg.private_pw_hash, 0xFF, 32);
        }
        fclose(fp);
    } else {
        /* 密码文件不存在，使用默认密码 "000000" 作为初始普通密码 */
        pg_sha256((const uint8_t *)"000000", 6, g_pg.normal_pw_hash);
        /* 私密密码设置为不可能匹配的值（全部0xFF无法通过SHA-256产生） */
        memset(g_pg.private_pw_hash, 0xFF, 32);
        /* 保存初始密码 */
        pg_password_save(PG_MODE_NORMAL, "000000");
    }
}

pg_mode_t pg_password_verify(const char *pin)
{
    uint8_t input_hash[32];
    pg_sha256((const uint8_t *)pin, PG_PIN_LENGTH, input_hash);

    /* 常量时间比较：一次遍历比较两个密码哈希 */
    uint8_t normal_diff = 0;
    uint8_t private_diff = 0;

    for (int i = 0; i < 32; i++) {
        normal_diff |= (input_hash[i] ^ g_pg.normal_pw_hash[i]);
        private_diff |= (input_hash[i] ^ g_pg.private_pw_hash[i]);
    }

    /* normal_diff == 0 表示匹配普通密码 */
    /* private_diff == 0 表示匹配私密密码 */
    /* 注意：如果两密码相同，优先匹配私密密码（更高的隐私保护） */

    if (private_diff == 0) {
        return PG_MODE_PRIVATE;
    }
    if (normal_diff == 0) {
        return PG_MODE_NORMAL;
    }
    return PG_MODE_NONE;
}

int pg_password_save(pg_mode_t mode, const char *pin)
{
    uint8_t hash[32];
    pg_sha256((const uint8_t *)pin, PG_PIN_LENGTH, hash);

    if (mode == PG_MODE_NORMAL) {
        memcpy(g_pg.normal_pw_hash, hash, 32);
    } else if (mode == PG_MODE_PRIVATE) {
        memcpy(g_pg.private_pw_hash, hash, 32);
    } else {
        return -1;
    }

    /* 写入文件 */
    FILE *fp = fopen(PG_PASSWORD_FILE, "wb");
    if (!fp) return -1;

    size_t written = fwrite(g_pg.normal_pw_hash, 1, 32, fp);
    written += fwrite(g_pg.private_pw_hash, 1, 32, fp);
    fclose(fp);

    return (written == 64) ? 0 : -1;
}

/* ================================================================
 * 图片加载
 * ================================================================ */

int pg_load_image_list(const char *dir_path)
{
    pg_free_image_list();

    /* 为最大图片数分配内存 */
    g_pg.images = (pg_image_t *)calloc(PG_MAX_IMAGES, sizeof(pg_image_t));
    if (!g_pg.images) return -1;

    g_pg.image_count = 0;

    /* 打开目录 */
    DIR *dir = opendir(dir_path);
    if (!dir) {
        /* 目录为空或不存在，正常返回（空图库） */
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && g_pg.image_count < PG_MAX_IMAGES) {
        if (entry->d_type == DT_REG && pg_is_image_file(entry->d_name)) {
            pg_image_t *img = &g_pg.images[g_pg.image_count];

            /* 构建完整路径 */
            snprintf(img->path, sizeof(img->path), "%s/%s", dir_path, entry->d_name);

            /* 复制文件名 */
            strncpy(img->name, entry->d_name, sizeof(img->name) - 1);
            img->name[sizeof(img->name) - 1] = '\0';

            img->thumbnail = NULL;
            img->thumbnail_loaded = false;

            g_pg.image_count++;
        }
    }
    closedir(dir);

    return (int)g_pg.image_count;
}

void pg_free_image_list(void)
{
    if (g_pg.images) {
        for (uint16_t i = 0; i < g_pg.image_count; i++) {
            if (g_pg.images[i].thumbnail) {
                /* 释放缩略图内存 */
                if (g_pg.images[i].thumbnail->data) {
                    free((void *)g_pg.images[i].thumbnail->data);
                }
                free(g_pg.images[i].thumbnail);
            }
        }
        free(g_pg.images);
        g_pg.images = NULL;
    }
    g_pg.image_count = 0;
    g_pg.current_index = 0;
}

/* ================================================================
 * 密码输入界面
 * ================================================================ */

static void pg_create_pin_keypad(lv_obj_t *parent);

void pg_create_password_screen(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    /* 标题：统一使用"图库"，不暴露模式信息 */
    lv_obj_t *title = lv_label_create(scr);
    lv_label_set_text(title, "图库");
    lv_obj_set_style_text_color(title, lv_color_white(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    /* 密码提示 */
    g_pg.pin_label = lv_label_create(scr);
    lv_label_set_text(g_pg.pin_label, "请输入密码");
    lv_obj_set_style_text_color(g_pg.pin_label, lv_color_hex(0xAAAAAA), 0);
    lv_obj_set_style_text_font(g_pg.pin_label, &lv_font_montserrat_14, 0);
    lv_obj_align(g_pg.pin_label, LV_ALIGN_TOP_MID, 0, 38);

    /* 密码圆点容器 */
    lv_obj_t *dots_cont = lv_obj_create(scr);
    lv_obj_set_size(dots_cont, PG_SCREEN_W - 40, 24);
    lv_obj_set_style_bg_opa(dots_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(dots_cont, 0, 0);
    lv_obj_set_flex_flow(dots_cont, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(dots_cont, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_align(dots_cont, LV_ALIGN_TOP_MID, 0, 60);

    for (int i = 0; i < PG_PIN_LENGTH; i++) {
        g_pg.pin_dots[i] = lv_obj_create(dots_cont);
        lv_obj_set_size(g_pg.pin_dots[i], 16, 16);
        lv_obj_set_style_bg_color(g_pg.pin_dots[i], lv_color_hex(0x333333), 0);
        lv_obj_set_style_bg_opa(g_pg.pin_dots[i], LV_OPA_COVER, 0);
        lv_obj_set_style_radius(g_pg.pin_dots[i], 8, 0);
        lv_obj_set_style_border_width(g_pg.pin_dots[i], 1, 0);
        lv_obj_set_style_border_color(g_pg.pin_dots[i], lv_color_hex(0x666666), 0);
    }

    /* 数字键盘 */
    pg_create_pin_keypad(scr);

    g_pg.screen_main = scr;
    g_pg.pin_index = 0;
    memset(g_pg.pin_buffer, 0, sizeof(g_pg.pin_buffer));

    lv_scr_load(scr);
}

static void pg_keypad_btn_event_cb(lv_event_t *e)
{
    lv_event_code_t code = lv_event_get_code(e);
    if (code == LV_EVENT_CLICKED) {
        lv_obj_t *btn = lv_event_get_target(e);
        const char *text = lv_label_get_text(lv_obj_get_child(btn, 0));
        if (!text) return;

        if (text[0] >= '0' && text[0] <= '9' && text[1] == '\0') {
            pg_password_input_digit(text[0]);
        } else if (strcmp(text, "←") == 0) {
            pg_password_input_backspace();
        } else if (strcmp(text, "OK") == 0) {
            pg_password_confirm();
        }
    }
}

static lv_obj_t *pg_create_keypad_btn(lv_obj_t *parent, const char *text,
                                       int col, int row, lv_color_t color)
{
    lv_obj_t *btn = lv_btn_create(parent);
    lv_obj_set_size(btn, 56, 40);
    lv_obj_set_style_bg_color(btn, color, 0);
    lv_obj_set_style_bg_opa(btn, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(btn, 8, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_grid_cell(btn, LV_GRID_ALIGN_CENTER, col, 1,
                              LV_GRID_ALIGN_CENTER, row, 1);

    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, lv_color_white(), 0);
    if (strlen(text) > 1) {
        lv_obj_set_style_text_font(label, &lv_font_montserrat_12, 0);
    } else {
        lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);
    }
    lv_obj_center(label);

    lv_obj_add_event_cb(btn, pg_keypad_btn_event_cb, LV_EVENT_CLICKED, NULL);
    return btn;
}

static void pg_create_pin_keypad(lv_obj_t *parent)
{
    lv_obj_t *cont = lv_obj_create(parent);
    lv_obj_set_size(cont, 200, 140);
    lv_obj_set_style_bg_opa(cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(cont, 0, 0);
    lv_obj_set_style_pad_all(cont, 0, 0);
    lv_obj_align(cont, LV_ALIGN_CENTER, 0, 10);

    /* 3列 x 4行 布局 */
    static lv_coord_t col_dsc[] = {56, 56, 56, LV_GRID_TEMPLATE_LAST};
    static lv_coord_t row_dsc[] = {40, 40, 40, 40, LV_GRID_TEMPLATE_LAST};
    lv_obj_set_grid_dsc_array(cont, col_dsc, row_dsc);

    lv_color_t num_color = lv_color_hex(0x1A1A1A);
    lv_color_t func_color = lv_color_hex(0x2A2A2A);
    lv_color_t ok_color = lv_color_hex(0x0066CC);

    /* 第一行: 1 2 3 */
    pg_create_keypad_btn(cont, "1", 0, 0, num_color);
    pg_create_keypad_btn(cont, "2", 1, 0, num_color);
    pg_create_keypad_btn(cont, "3", 2, 0, num_color);

    /* 第二行: 4 5 6 */
    pg_create_keypad_btn(cont, "4", 0, 1, num_color);
    pg_create_keypad_btn(cont, "5", 1, 1, num_color);
    pg_create_keypad_btn(cont, "6", 2, 1, num_color);

    /* 第三行: 7 8 9 */
    pg_create_keypad_btn(cont, "7", 0, 2, num_color);
    pg_create_keypad_btn(cont, "8", 1, 2, num_color);
    pg_create_keypad_btn(cont, "9", 2, 2, num_color);

    /* 第四行: ← 0 OK */
    pg_create_keypad_btn(cont, "←", 0, 3, func_color);
    pg_create_keypad_btn(cont, "0", 1, 3, num_color);
    pg_create_keypad_btn(cont, "OK", 2, 3, ok_color);
}

void pg_password_input_digit(char digit)
{
    if (g_pg.pin_index >= PG_PIN_LENGTH) return;

    g_pg.pin_buffer[g_pg.pin_index] = digit;

    /* 更新圆点显示（填充状态） */
    lv_obj_set_style_bg_color(g_pg.pin_dots[g_pg.pin_index],
                              lv_color_hex(0xFFFFFF), 0);

    g_pg.pin_index++;

    /* 自动确认 */
    if (g_pg.pin_index >= PG_PIN_LENGTH) {
        /* 延迟一小段时间让用户看到最后一个点被填充 */
        lv_timer_t *timer = lv_timer_create(
            (lv_timer_cb_t)pg_password_confirm, 200, NULL);
        lv_timer_set_repeat_count(timer, 1);
    }
}

void pg_password_input_backspace(void)
{
    if (g_pg.pin_index == 0) return;

    g_pg.pin_index--;
    g_pg.pin_buffer[g_pg.pin_index] = '\0';

    /* 恢复圆点为未填充状态 */
    lv_obj_set_style_bg_color(g_pg.pin_dots[g_pg.pin_index],
                              lv_color_hex(0x333333), 0);
}

void pg_password_confirm(void)
{
    /* 检查是否处于锁定状态 */
    if (g_pg.lockout_until > 0) {
        uint64_t now = pg_get_tick_ms();
        if (now < g_pg.lockout_until) {
            /* 仍在锁定中，更新时间提示 */
            uint32_t remaining = (uint32_t)((g_pg.lockout_until - now) / 1000);
            char msg[64];
            snprintf(msg, sizeof(msg), "请等待 %lu 秒", (unsigned long)remaining);
            lv_label_set_text(g_pg.pin_label, msg);
            return;
        } else {
            /* 锁定时间已过 */
            g_pg.lockout_until = 0;
            g_pg.attempt_count = 0;
        }
    }

    /* 确保输入了完整的6位密码 */
    if (g_pg.pin_index < PG_PIN_LENGTH) {
        lv_label_set_text(g_pg.pin_label, "请输入6位密码");
        return;
    }

    g_pg.pin_buffer[PG_PIN_LENGTH] = '\0';

    /* 验证密码 */
    pg_mode_t mode = pg_password_verify(g_pg.pin_buffer);

    if (mode == PG_MODE_NONE) {
        /* 密码错误 - 统一提示，不区分模式 */
        g_pg.attempt_count++;

        /* 重置密码输入 */
        g_pg.pin_index = 0;
        memset(g_pg.pin_buffer, 0, sizeof(g_pg.pin_buffer));
        for (int i = 0; i < PG_PIN_LENGTH; i++) {
            lv_obj_set_style_bg_color(g_pg.pin_dots[i],
                                      lv_color_hex(0x333333), 0);
        }

        if (g_pg.attempt_count > PG_MAX_ATTEMPTS) {
            /* 锁定：超过最大尝试次数后锁定 */
            g_pg.lockout_until = pg_get_tick_ms() + PG_LOCKOUT_DURATION_MS;
            /* 重置尝试计数，锁定期间不显示剩余次数 */
            lv_label_set_text(g_pg.pin_label, "请等待 30 秒");
        } else {
            char msg[32];
            /* PG_MAX_ATTEMPTS - g_pg.attempt_count + 1 确保显示正确的剩余次数 */
            snprintf(msg, sizeof(msg), "密码错误（剩余%u次）",
                     PG_MAX_ATTEMPTS - g_pg.attempt_count + 1);
            lv_label_set_text(g_pg.pin_label, msg);
        }
        return;
    }

    /* 密码正确 - 进入图库
     * 关键：后续所有UI行为完全相同，不区分模式 */
    g_pg.current_mode = mode;
    g_pg.attempt_count = 0;
    g_pg.lockout_until = 0;

    pg_create_gallery_screen();
}

/* ================================================================
 * 图库浏览界面
 * ================================================================ */

static void pg_gallery_thumbnail_click_cb(lv_event_t *e)
{
    lv_event_code_t code = lv_event_get_code(e);
    if (code == LV_EVENT_CLICKED) {
        lv_obj_t *img_obj = lv_event_get_target(e);
        uint32_t index = (uint32_t)(uintptr_t)lv_obj_get_user_data(img_obj);
        if (index < g_pg.image_count) {
            g_pg.current_index = (uint16_t)index;
            pg_create_viewer_screen();
        }
    }
}

static void pg_load_thumbnail(pg_image_t *img, lv_obj_t *img_obj)
{
    /* 尝试打开图片文件 */
    FILE *fp = fopen(img->path, "rb");
    if (!fp) return;

    /* 获取文件大小 */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 256 * 1024) { /* 最大256KB */
        fclose(fp);
        return;
    }

    /* 分配内存并读取 */
    uint8_t *data = (uint8_t *)malloc((size_t)fsize);
    if (!data) {
        fclose(fp);
        return;
    }

    size_t nread = fread(data, 1, (size_t)fsize, fp);
    fclose(fp);

    if (nread != (size_t)fsize) {
        free(data);
        return;
    }

    /* 创建LVGL图片描述符 */
    lv_img_dsc_t *dsc = (lv_img_dsc_t *)calloc(1, sizeof(lv_img_dsc_t));
    if (!dsc) {
        free(data);
        return;
    }

    dsc->data = data;
    dsc->data_size = (uint32_t)nread;

    /* 设置图片源并缩放以适配缩略图 */
    lv_img_set_src(img_obj, dsc);
    lv_img_set_zoom(img_obj, 64); /* 根据实际大小调整缩放 */

    img->thumbnail = dsc;
    img->thumbnail_loaded = true;
}

void pg_create_gallery_screen(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    /* 顶部标题栏 - 统一"图库" */
    lv_obj_t *title_bar = lv_obj_create(scr);
    lv_obj_set_size(title_bar, PG_SCREEN_W, 32);
    lv_obj_set_style_bg_color(title_bar, lv_color_hex(0x0A0A0A), 0);
    lv_obj_set_style_bg_opa(title_bar, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(title_bar, 0, 0);
    lv_obj_set_style_radius(title_bar, 0, 0);
    lv_obj_align(title_bar, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *title = lv_label_create(title_bar);
    lv_label_set_text(title, "图库");
    lv_obj_set_style_text_color(title, lv_color_white(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_18, 0);
    lv_obj_center(title);

    /* 返回按钮（返回到密码界面即锁定） */
    lv_obj_t *back_btn = lv_btn_create(title_bar);
    lv_obj_set_size(back_btn, 50, 28);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x222222), 0);
    lv_obj_set_style_radius(back_btn, 6, 0);
    lv_obj_set_style_shadow_width(back_btn, 0, 0);
    lv_obj_align(back_btn, LV_ALIGN_LEFT_MID, 4, 0);

    lv_obj_t *back_label = lv_label_create(back_btn);
    lv_label_set_text(back_label, "←");
    lv_obj_set_style_text_color(back_label, lv_color_white(), 0);
    lv_obj_center(back_label);

    lv_obj_add_event_cb(back_btn, (lv_event_cb_t)pg_lock, LV_EVENT_CLICKED, NULL);

    /* 图片数量标签 */
    lv_obj_t *count_label = lv_label_create(title_bar);
    char count_text[32];
    snprintf(count_text, sizeof(count_text), "%u", g_pg.image_count);
    lv_label_set_text(count_label, count_text);
    lv_obj_set_style_text_color(count_label, lv_color_hex(0x888888), 0);
    lv_obj_set_style_text_font(count_label, &lv_font_montserrat_12, 0);
    lv_obj_align(count_label, LV_ALIGN_RIGHT_MID, -8, 0);

    /* 图片网格容器 */
    g_pg.grid_cont = lv_obj_create(scr);
    lv_obj_set_size(g_pg.grid_cont, PG_SCREEN_W - 4, PG_SCREEN_H - 36);
    lv_obj_set_style_bg_opa(g_pg.grid_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(g_pg.grid_cont, 0, 0);
    lv_obj_set_style_pad_all(g_pg.grid_cont, 2, 0);
    lv_obj_align(g_pg.grid_cont, LV_ALIGN_BOTTOM_MID, 0, 0);

    /* 设置网格布局 */
    lv_coord_t col_dsc[] = {
        PG_THUMB_SIZE, PG_THUMB_SIZE, PG_THUMB_SIZE,
        LV_GRID_TEMPLATE_LAST
    };
    /* 动态行描述符 */
    uint16_t rows = (g_pg.image_count + PG_GRID_COLS - 1) / PG_GRID_COLS;
    if (rows < 2) rows = 2;
    lv_coord_t *row_dsc = (lv_coord_t *)calloc(rows + 1, sizeof(lv_coord_t));
    if (row_dsc) {
        for (uint16_t i = 0; i < rows; i++) {
            row_dsc[i] = PG_THUMB_SIZE;
        }
        row_dsc[rows] = LV_GRID_TEMPLATE_LAST;
    }
    lv_obj_set_grid_dsc_array(g_pg.grid_cont, col_dsc,
                              row_dsc ? row_dsc : NULL);

    /* 刷新网格内容 */
    pg_refresh_gallery_grid();

    if (row_dsc) free(row_dsc);

    g_pg.screen_gallery = scr;
    lv_scr_load(scr);
}

void pg_refresh_gallery_grid(void)
{
    if (!g_pg.grid_cont) return;

    /* 清空现有子控件 */
    lv_obj_clean(g_pg.grid_cont);

    /* 没有图片时显示提示 */
    if (g_pg.image_count == 0) {
        lv_obj_t *empty_label = lv_label_create(g_pg.grid_cont);
        lv_label_set_text(empty_label, "暂无图片\n\n请使用手机导入");
        lv_obj_set_style_text_color(empty_label, lv_color_hex(0x666666), 0);
        lv_obj_set_style_text_align(empty_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(empty_label);
        return;
    }

    /* 创建缩略图 */
    for (uint16_t i = 0; i < g_pg.image_count; i++) {
        lv_obj_t *thumb_cont = lv_obj_create(g_pg.grid_cont);
        lv_obj_set_size(thumb_cont, PG_THUMB_SIZE, PG_THUMB_SIZE);
        lv_obj_set_style_bg_color(thumb_cont, lv_color_hex(0x1A1A1A), 0);
        lv_obj_set_style_bg_opa(thumb_cont, LV_OPA_COVER, 0);
        lv_obj_set_style_border_width(thumb_cont, 0, 0);
        lv_obj_set_style_radius(thumb_cont, 4, 0);
        lv_obj_set_style_pad_all(thumb_cont, 0, 0);

        /* 图片对象 */
        lv_obj_t *thumb_img = lv_img_create(thumb_cont);
        lv_obj_set_size(thumb_img, PG_THUMB_SIZE, PG_THUMB_SIZE);

        /* 设置用户数据为图片索引 */
        lv_obj_set_user_data(thumb_img, (void *)(uintptr_t)i);

        /* 点击事件 */
        lv_obj_add_flag(thumb_img, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(thumb_img, pg_gallery_thumbnail_click_cb,
                            LV_EVENT_CLICKED, NULL);

        /* 异步加载缩略图 */
        pg_load_thumbnail(&g_pg.images[i], thumb_img);

        /* 网格定位 */
        uint16_t col = i % PG_GRID_COLS;
        uint16_t row = i / PG_GRID_COLS;
        lv_obj_set_grid_cell(thumb_cont, LV_GRID_ALIGN_CENTER, col, 1,
                                          LV_GRID_ALIGN_CENTER, row, 1);
    }
}

/* ================================================================
 * 图片查看器
 * ================================================================ */

static void pg_viewer_prev_event_cb(lv_event_t *e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
        pg_viewer_prev();
    }
}

static void pg_viewer_next_event_cb(lv_event_t *e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
        pg_viewer_next();
    }
}

static void pg_viewer_back_event_cb(lv_event_t *e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
        /* 返回图库（已解锁状态不变） */
        if (g_pg.screen_gallery) {
            lv_obj_del(g_pg.screen_viewer);
            g_pg.screen_viewer = NULL;
            lv_scr_load(g_pg.screen_gallery);
        }
    }
}

/* 手势滑动处理 */
static void pg_viewer_gesture_cb(lv_event_t *e)
{
    lv_obj_t *obj = lv_event_get_target(e);
    lv_dir_t dir = lv_indev_get_gesture_dir(lv_indev_get_act());

    if (dir == LV_DIR_LEFT) {
        pg_viewer_next();
    } else if (dir == LV_DIR_RIGHT) {
        pg_viewer_prev();
    }
}

void pg_create_viewer_screen(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    /* 顶部透明状态栏 */
    lv_obj_t *top_bar = lv_obj_create(scr);
    lv_obj_set_size(top_bar, PG_SCREEN_W, 30);
    lv_obj_set_style_bg_opa(top_bar, LV_OPA_20, 0);
    lv_obj_set_style_bg_color(top_bar, lv_color_black(), 0);
    lv_obj_set_style_border_width(top_bar, 0, 0);
    lv_obj_set_style_radius(top_bar, 0, 0);
    lv_obj_align(top_bar, LV_ALIGN_TOP_MID, 0, 0);

    /* 返回按钮 */
    lv_obj_t *back_btn = lv_btn_create(top_bar);
    lv_obj_set_size(back_btn, 50, 26);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x333333), 0);
    lv_obj_set_style_radius(back_btn, 6, 0);
    lv_obj_align(back_btn, LV_ALIGN_LEFT_MID, 4, 0);

    lv_obj_t *back_lbl = lv_label_create(back_btn);
    lv_label_set_text(back_lbl, "←");
    lv_obj_set_style_text_color(back_lbl, lv_color_white(), 0);
    lv_obj_center(back_lbl);
    lv_obj_add_event_cb(back_btn, pg_viewer_back_event_cb, LV_EVENT_CLICKED, NULL);

    /* 图片计数器 */
    g_pg.viewer_label = lv_label_create(top_bar);
    lv_obj_set_style_text_color(g_pg.viewer_label, lv_color_white(), 0);
    lv_obj_set_style_text_font(g_pg.viewer_label, &lv_font_montserrat_12, 0);
    lv_obj_align(g_pg.viewer_label, LV_ALIGN_CENTER, 0, 0);

    /* 主图片显示区域 */
    g_pg.viewer_img = lv_img_create(scr);
    lv_obj_set_size(g_pg.viewer_img, PG_SCREEN_W - 20, PG_SCREEN_H - 60);
    lv_obj_align(g_pg.viewer_img, LV_ALIGN_CENTER, 0, -10);
    lv_obj_set_style_bg_color(g_pg.viewer_img, lv_color_hex(0x0A0A0A), 0);
    lv_obj_set_style_bg_opa(g_pg.viewer_img, LV_OPA_COVER, 0);

    /* 添加手势支持 */
    lv_obj_add_flag(g_pg.viewer_img, LV_OBJ_FLAG_GESTURE_BUBBLE);
    lv_obj_add_event_cb(g_pg.viewer_img, pg_viewer_gesture_cb, LV_EVENT_GESTURE, NULL);

    /* 左/右触摸区域 */
    g_pg.viewer_prev_area = lv_obj_create(scr);
    lv_obj_set_size(g_pg.viewer_prev_area, PG_SCREEN_W / 3, PG_SCREEN_H - 60);
    lv_obj_set_style_bg_opa(g_pg.viewer_prev_area, LV_OPA_0, 0);
    lv_obj_set_style_border_width(g_pg.viewer_prev_area, 0, 0);
    lv_obj_align(g_pg.viewer_prev_area, LV_ALIGN_LEFT_MID, 0, -10);
    lv_obj_add_flag(g_pg.viewer_prev_area, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(g_pg.viewer_prev_area, pg_viewer_prev_event_cb,
                        LV_EVENT_CLICKED, NULL);

    g_pg.viewer_next_area = lv_obj_create(scr);
    lv_obj_set_size(g_pg.viewer_next_area, PG_SCREEN_W / 3, PG_SCREEN_H - 60);
    lv_obj_set_style_bg_opa(g_pg.viewer_next_area, LV_OPA_0, 0);
    lv_obj_set_style_border_width(g_pg.viewer_next_area, 0, 0);
    lv_obj_align(g_pg.viewer_next_area, LV_ALIGN_RIGHT_MID, 0, -10);
    lv_obj_add_flag(g_pg.viewer_next_area, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(g_pg.viewer_next_area, pg_viewer_next_event_cb,
                        LV_EVENT_CLICKED, NULL);

    /* 底部操作栏 */
    lv_obj_t *bottom_bar = lv_obj_create(scr);
    lv_obj_set_size(bottom_bar, PG_SCREEN_W, 30);
    lv_obj_set_style_bg_opa(bottom_bar, LV_OPA_20, 0);
    lv_obj_set_style_bg_color(bottom_bar, lv_color_black(), 0);
    lv_obj_set_style_border_width(bottom_bar, 0, 0);
    lv_obj_align(bottom_bar, LV_ALIGN_BOTTOM_MID, 0, 0);

    /* 上一张按钮 */
    lv_obj_t *prev_btn = lv_btn_create(bottom_bar);
    lv_obj_set_size(prev_btn, 60, 24);
    lv_obj_set_style_bg_color(prev_btn, lv_color_hex(0x333333), 0);
    lv_obj_set_style_radius(prev_btn, 6, 0);
    lv_obj_set_style_shadow_width(prev_btn, 0, 0);
    lv_obj_align(prev_btn, LV_ALIGN_LEFT_MID, 10, 0);
    lv_obj_t *prev_lbl = lv_label_create(prev_btn);
    lv_label_set_text(prev_lbl, "上一张");
    lv_obj_set_style_text_color(prev_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(prev_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(prev_lbl);
    lv_obj_add_event_cb(prev_btn, pg_viewer_prev_event_cb, LV_EVENT_CLICKED, NULL);

    /* 下一张按钮 */
    lv_obj_t *next_btn = lv_btn_create(bottom_bar);
    lv_obj_set_size(next_btn, 60, 24);
    lv_obj_set_style_bg_color(next_btn, lv_color_hex(0x333333), 0);
    lv_obj_set_style_radius(next_btn, 6, 0);
    lv_obj_set_style_shadow_width(next_btn, 0, 0);
    lv_obj_align(next_btn, LV_ALIGN_RIGHT_MID, -10, 0);
    lv_obj_t *next_lbl = lv_label_create(next_btn);
    lv_label_set_text(next_lbl, "下一张");
    lv_obj_set_style_text_color(next_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(next_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(next_lbl);
    lv_obj_add_event_cb(next_btn, pg_viewer_next_event_cb, LV_EVENT_CLICKED, NULL);

    g_pg.screen_viewer = scr;
    lv_scr_load(scr);

    /* 加载当前图片 */
    pg_viewer_show_image(g_pg.current_index);
}

void pg_viewer_show_image(uint16_t index)
{
    if (!g_pg.viewer_img || index >= g_pg.image_count) return;

    g_pg.current_index = index;
    pg_image_t *img = &g_pg.images[index];

    /* 从文件加载完整图片 */
    FILE *fp = fopen(img->path, "rb");
    if (!fp) {
        lv_img_set_src(g_pg.viewer_img, NULL);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 512 * 1024) { /* 最大512KB */
        fclose(fp);
        return;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)fsize);
    if (!data) {
        fclose(fp);
        return;
    }

    size_t nread = fread(data, 1, (size_t)fsize, fp);
    fclose(fp);

    if (nread != (size_t)fsize) {
        free(data);
        return;
    }

    lv_img_dsc_t *dsc = (lv_img_dsc_t *)calloc(1, sizeof(lv_img_dsc_t));
    if (!dsc) {
        free(data);
        return;
    }

    dsc->data = data;
    dsc->data_size = (uint32_t)nread;
    lv_img_set_src(g_pg.viewer_img, dsc);

    /* 保存以便后续释放 */
    if (img->thumbnail && img->thumbnail->data &&
        img->thumbnail->data != (const uint8_t *)dsc) {
        /* 不同对象，保留缩略图 */
    }

    /* 更新计数器 */
    if (g_pg.viewer_label) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u/%u",
                 g_pg.current_index + 1, g_pg.image_count);
        lv_label_set_text(g_pg.viewer_label, buf);
    }
}

void pg_viewer_prev(void)
{
    if (g_pg.current_index > 0) {
        pg_viewer_show_image(g_pg.current_index - 1);
    }
}

void pg_viewer_next(void)
{
    if (g_pg.current_index + 1 < g_pg.image_count) {
        pg_viewer_show_image(g_pg.current_index + 1);
    }
}

/* ================================================================
 * 锁定与退出
 * ================================================================ */

void pg_lock(void)
{
    /* 释放图片资源 */
    pg_free_image_list();

    /* 释放图片查看器 */
    if (g_pg.screen_viewer) {
        lv_obj_del(g_pg.screen_viewer);
        g_pg.screen_viewer = NULL;
    }

    /* 释放图库界面 */
    if (g_pg.screen_gallery) {
        lv_obj_del(g_pg.screen_gallery);
        g_pg.screen_gallery = NULL;
    }

    /* 清除模式信息 */
    g_pg.current_mode = PG_MODE_NONE;

    /* 回到密码输入界面 */
    pg_create_password_screen();
}

/* ================================================================
 * 应用入口
 * ================================================================ */

void pg_app_create(void)
{
    /* 清零上下文 */
    memset(&g_pg, 0, sizeof(g_pg));

    g_pg.current_mode = PG_MODE_NONE;

    /* 初始化密码系统 */
    pg_password_init();

    /* 创建密码输入界面 */
    pg_create_password_screen();
}

void pg_app_destroy(void)
{
    /* 释放所有资源 */
    pg_free_image_list();

    if (g_pg.screen_viewer) {
        lv_obj_del(g_pg.screen_viewer);
        g_pg.screen_viewer = NULL;
    }
    if (g_pg.screen_gallery) {
        lv_obj_del(g_pg.screen_gallery);
        g_pg.screen_gallery = NULL;
    }
    if (g_pg.screen_main) {
        lv_obj_del(g_pg.screen_main);
        g_pg.screen_main = NULL;
    }
}

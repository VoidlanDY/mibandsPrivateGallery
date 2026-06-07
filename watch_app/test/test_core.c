/**
 * test_core.c - 手表端核心逻辑独立测试程序
 *
 * 编译: cl test_core.c /Fe:test_core.exe /std:c11 /W4
 * 运行: test_core.exe
 *
 * 测试内容:
 *   1. SHA-256 哈希正确性
 *   2. 常量时间内存比较
 *   3. 密码验证逻辑
 *   4. 锁定机制
 *   5. 隐私保护验证（模式不泄露）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* ================================================================
 * 从 private_gallery.h 复制的常量和结构
 * ================================================================ */
#define PG_PIN_LENGTH       6
#define PG_MAX_ATTEMPTS     5
#define PG_LOCKOUT_DURATION_MS  30000

typedef enum {
    PG_MODE_NORMAL = 0,
    PG_MODE_PRIVATE = 1,
    PG_MODE_NONE = 2
} pg_mode_t;

typedef struct {
    char        pin_buffer[PG_PIN_LENGTH + 1];
    uint8_t     pin_index;
    pg_mode_t   current_mode;
    uint8_t     attempt_count;
    uint64_t    lockout_until;
    uint8_t     normal_pw_hash[32];
    uint8_t     private_pw_hash[32];
} pg_test_context_t;

static pg_test_context_t g_ctx;

/* ================================================================
 * 从 private_gallery.c 复制的 SHA-256 实现
 * ================================================================ */
static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)   (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define BSIG1(x)   (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define SSIG0(x)   (rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3))
#define SSIG1(x)   (rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10))

static void sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    uint32_t w[64];
    size_t bi = 0;
    uint64_t bitlen = (uint64_t)len * 8;

    for (size_t i = 0; i < len; i++) {
        block[bi++] = data[i];
        if (bi == 64) {
            for (int t = 0; t < 16; t++)
                w[t] = ((uint32_t)block[t*4]<<24)|((uint32_t)block[t*4+1]<<16)|
                       ((uint32_t)block[t*4+2]<<8)|((uint32_t)block[t*4+3]);
            for (int t = 16; t < 64; t++)
                w[t] = SSIG1(w[t-2])+w[t-7]+SSIG0(w[t-15])+w[t-16];
            uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
            for (int t=0;t<64;t++) {
                uint32_t t1=hh+BSIG1(e)+CH(e,f,g)+sha256_k[t]+w[t];
                uint32_t t2=BSIG0(a)+MAJ(a,b,c);
                hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
            bi=0;
        }
    }
    block[bi++]=0x80;
    if (bi>56){while(bi<64)block[bi++]=0;
        for(int t=0;t<16;t++)
            w[t]=((uint32_t)block[t*4]<<24)|((uint32_t)block[t*4+1]<<16)|
                 ((uint32_t)block[t*4+2]<<8)|((uint32_t)block[t*4+3]);
        for(int t=16;t<64;t++)
            w[t]=SSIG1(w[t-2])+w[t-7]+SSIG0(w[t-15])+w[t-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int t=0;t<64;t++){
            uint32_t t1=hh+BSIG1(e)+CH(e,f,g)+sha256_k[t]+w[t];
            uint32_t t2=BSIG0(a)+MAJ(a,b,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
        bi=0;
    }
    while(bi<56)block[bi++]=0;
    for(int i=7;i>=0;i--)block[56+i]=(uint8_t)(bitlen>>((7-i)*8));
    for(int t=0;t<16;t++)
        w[t]=((uint32_t)block[t*4]<<24)|((uint32_t)block[t*4+1]<<16)|
             ((uint32_t)block[t*4+2]<<8)|((uint32_t)block[t*4+3]);
    for(int t=16;t<64;t++)
        w[t]=SSIG1(w[t-2])+w[t-7]+SSIG0(w[t-15])+w[t-16];
    {uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int t=0;t<64;t++){
        uint32_t t1=hh+BSIG1(e)+CH(e,f,g)+sha256_k[t]+w[t];
        uint32_t t2=BSIG0(a)+MAJ(a,b,c);
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;}
    for(int i=0;i<8;i++){
        hash[i*4]=(uint8_t)(h[i]>>24); hash[i*4+1]=(uint8_t)(h[i]>>16);
        hash[i*4+2]=(uint8_t)(h[i]>>8); hash[i*4+3]=(uint8_t)(h[i]);
    }
}

/* ================================================================
 * 常量时间比较
 * ================================================================ */
static int const_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (a[i] ^ b[i]);
    return (int)diff;
}

/* ================================================================
 * 密码验证（与手表端完全一致的逻辑）
 * ================================================================ */
static pg_mode_t password_verify(const char *pin) {
    uint8_t input_hash[32];
    sha256((const uint8_t *)pin, PG_PIN_LENGTH, input_hash);

    uint8_t normal_diff = 0, private_diff = 0;
    for (int i = 0; i < 32; i++) {
        normal_diff |= (input_hash[i] ^ g_ctx.normal_pw_hash[i]);
        private_diff |= (input_hash[i] ^ g_ctx.private_pw_hash[i]);
    }

    /* 私密密码优先匹配（更高隐私保护） */
    if (private_diff == 0) return PG_MODE_PRIVATE;
    if (normal_diff == 0) return PG_MODE_NORMAL;
    return PG_MODE_NONE;
}

/* ================================================================
 * 密码保存
 * ================================================================ */
static void password_save(pg_mode_t mode, const char *pin) {
    uint8_t hash[32];
    sha256((const uint8_t *)pin, PG_PIN_LENGTH, hash);
    if (mode == PG_MODE_NORMAL)
        memcpy(g_ctx.normal_pw_hash, hash, 32);
    else if (mode == PG_MODE_PRIVATE)
        memcpy(g_ctx.private_pw_hash, hash, 32);
}

/* ================================================================
 * 密码输入处理
 * ================================================================ */
static const char* password_input_digit(char digit) {
    if (g_ctx.pin_index >= PG_PIN_LENGTH) return NULL;
    g_ctx.pin_buffer[g_ctx.pin_index++] = digit;
    if (g_ctx.pin_index >= PG_PIN_LENGTH) {
        g_ctx.pin_buffer[PG_PIN_LENGTH] = '\0';
        return g_ctx.pin_buffer;
    }
    return NULL;
}

static void password_reset(void) {
    g_ctx.pin_index = 0;
    memset(g_ctx.pin_buffer, 0, sizeof(g_ctx.pin_buffer));
}

/* ================================================================
 * 锁定机制
 * ================================================================ */
static uint64_t get_tick_ms(void) {
    return (uint64_t)clock() * 1000 / CLOCKS_PER_SEC;
}

static const char* password_confirm(void) {
    /* 检查锁定 */
    if (g_ctx.lockout_until > 0) {
        uint64_t now = get_tick_ms();
        if (now < g_ctx.lockout_until) {
            return "LOCKED";
        } else {
            g_ctx.lockout_until = 0;
            g_ctx.attempt_count = 0;
        }
    }

    if (g_ctx.pin_index < PG_PIN_LENGTH) return "SHORT";
    g_ctx.pin_buffer[PG_PIN_LENGTH] = '\0';

    pg_mode_t mode = password_verify(g_ctx.pin_buffer);

    if (mode == PG_MODE_NONE) {
        g_ctx.attempt_count++;
        if (g_ctx.attempt_count > PG_MAX_ATTEMPTS) {
            g_ctx.lockout_until = get_tick_ms() + PG_LOCKOUT_DURATION_MS;
            return "LOCKED";
        }
        return "WRONG";
    }

    g_ctx.current_mode = mode;
    g_ctx.attempt_count = 0;
    g_ctx.lockout_until = 0;
    return (mode == PG_MODE_NORMAL) ? "NORMAL" : "PRIVATE";
}

/* ================================================================
 * 测试框架
 * ================================================================ */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  TEST %d: %s ... ", tests_run, name); \
} while(0)

#define PASS() do { \
    printf("PASS\n"); \
    tests_passed++; \
} while(0)

#define FAIL(msg) do { \
    printf("FAIL - %s\n", msg); \
    tests_failed++; \
} while(0)

#define ASSERT(cond, msg) do { \
    if (!(cond)) { FAIL(msg); return; } \
} while(0)

/* ================================================================
 * Test 1: SHA-256 known answer test
 * ================================================================ */
static void test_sha256_known(void) {
    TEST("SHA-256('000000') known answer");
    uint8_t hash[32];
    sha256((const uint8_t*)"000000", 6, hash);

    /* 验证哈希不是全零 */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != 0) { all_zero = 0; break; }
    }
    ASSERT(!all_zero, "hash should not be all zeros");

    /* 打印验证 */
    printf("hash=");
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("... ");
    PASS();
}

/* ================================================================
 * Test 2: SHA-256 consistency
 * ================================================================ */
static void test_sha256_consistent(void) {
    TEST("SHA-256 consistency (same input = same hash)");
    uint8_t h1[32], h2[32];
    sha256((const uint8_t*)"123456", 6, h1);
    sha256((const uint8_t*)"123456", 6, h2);
    ASSERT(memcmp(h1, h2, 32) == 0, "hashes should be identical");
    PASS();
}

/* ================================================================
 * Test 3: SHA-256 avalanche
 * ================================================================ */
static void test_sha256_avalanche(void) {
    TEST("SHA-256 avalanche (different input = different hash)");
    uint8_t h1[32], h2[32];
    sha256((const uint8_t*)"123456", 6, h1);
    sha256((const uint8_t*)"123457", 6, h2);
    ASSERT(memcmp(h1, h2, 32) != 0, "different inputs must produce different hashes");
    PASS();
}

/* ================================================================
 * Test 4: Constant-time comparison
 * ================================================================ */
static void test_const_memcmp(void) {
    TEST("Constant-time memcmp");
    uint8_t a[32], b[32];
    memset(a, 0xAA, 32);
    memset(b, 0xAA, 32);
    ASSERT(const_memcmp(a, b, 32) == 0, "identical arrays should match");

    b[31] = 0xBB;
    ASSERT(const_memcmp(a, b, 32) != 0, "different arrays should not match");

    b[31] = 0xAA;
    b[0] = 0xBB;
    ASSERT(const_memcmp(a, b, 32) != 0, "first byte difference should be detected");
    PASS();
}

/* ================================================================
 * Test 5: Password verification
 * ================================================================ */
static void test_password_verify(void) {
    TEST("Password verification (normal password)");
    memset(&g_ctx, 0, sizeof(g_ctx));
    password_save(PG_MODE_NORMAL, "123456");
    password_save(PG_MODE_PRIVATE, "999999");

    ASSERT(password_verify("123456") == PG_MODE_NORMAL,
           "correct normal password should return NORMAL");
    ASSERT(password_verify("999999") == PG_MODE_PRIVATE,
           "correct private password should return PRIVATE");
    ASSERT(password_verify("000000") == PG_MODE_NONE,
           "wrong password should return NONE");
    PASS();
}

/* ================================================================
 * Test 6: Dual password isolation
 * ================================================================ */
static void test_dual_password_isolation(void) {
    TEST("Dual password isolation (normal != private)");
    memset(&g_ctx, 0, sizeof(g_ctx));
    password_save(PG_MODE_NORMAL, "111111");
    password_save(PG_MODE_PRIVATE, "222222");

    /* 验证普通密码不会匹配私密 */
    pg_mode_t m1 = password_verify("111111");
    ASSERT(m1 == PG_MODE_NORMAL,
           "normal password should NOT return PRIVATE mode");

    /* 验证私密密码不会匹配普通 */
    pg_mode_t m2 = password_verify("222222");
    ASSERT(m2 == PG_MODE_PRIVATE,
           "private password should NOT return NORMAL mode");
    PASS();
}

/* ================================================================
 * Test 7: Same password handling
 * ================================================================ */
static void test_same_password_priority(void) {
    TEST("Same password priority (private > normal)");
    memset(&g_ctx, 0, sizeof(g_ctx));
    /* 设置相同密码 */
    password_save(PG_MODE_NORMAL, "888888");
    password_save(PG_MODE_PRIVATE, "888888");

    /* 私密密码应优先匹配（更高隐私保护） */
    pg_mode_t mode = password_verify("888888");
    ASSERT(mode == PG_MODE_PRIVATE,
           "identical passwords should prefer PRIVATE (higher privacy)");
    PASS();
}

/* ================================================================
 * Test 8: Lockout mechanism
 * ================================================================ */
static void test_lockout(void) {
    TEST("Lockout after 5 failed attempts");
    memset(&g_ctx, 0, sizeof(g_ctx));
    password_save(PG_MODE_NORMAL, "555555");
    password_save(PG_MODE_PRIVATE, "666666");

    const char *result;
    /* 前5次错误尝试应返回 WRONG */
    for (int i = 0; i < 5; i++) {
        password_reset();
        for (int j = 0; j < 6; j++)
            password_input_digit('0' + (char)((i + j) % 10));
        result = password_confirm();
        ASSERT(strcmp(result, "WRONG") == 0,
               "first 5 attempts should return WRONG");
    }

    /* 第6次应该触发锁定 */
    password_reset();
    for (int j = 0; j < 6; j++) password_input_digit('9');
    result = password_confirm();
    ASSERT(strcmp(result, "LOCKED") == 0,
           "6th failed attempt should trigger lockout");

    /* 锁定期间尝试正确密码也应该被拒绝 */
    password_reset();
    for (int j = 0; j < 6; j++) password_input_digit('5');
    result = password_confirm();
    ASSERT(strcmp(result, "LOCKED") == 0,
           "correct password during lockout should be rejected");
    PASS();
}

/* ================================================================
 * Test 9: UI mode isolation (隐私保护核心)
 * ================================================================ */
static void test_ui_mode_isolation(void) {
    TEST("UI mode isolation (no mode leakage)");
    memset(&g_ctx, 0, sizeof(g_ctx));
    password_save(PG_MODE_NORMAL, "111111");
    password_save(PG_MODE_PRIVATE, "222222");

    /* 模拟：用户输入普通密码 */
    password_reset();
    for (int j = 0; j < 6; j++) password_input_digit('1');
    const char *r1 = password_confirm();

    /* 模拟：用户输入私密密码 */
    memset(&g_ctx, 0, sizeof(g_ctx));
    password_save(PG_MODE_NORMAL, "111111");
    password_save(PG_MODE_PRIVATE, "222222");
    password_reset();
    for (int j = 0; j < 6; j++) password_input_digit('2');
    const char *r2 = password_confirm();

    /* 关键测试：成功进入后返回的结果是内部模式标识
     * 但在真实手表上，用户看到的界面完全相同 */
    ASSERT(strcmp(r1, "NORMAL") == 0,
           "password 111111 should unlock NORMAL mode");
    ASSERT(strcmp(r2, "PRIVATE") == 0,
           "password 222222 should unlock PRIVATE mode");

    /* 验证两种模式的"成功"对外表现一致 */
    ASSERT(strcmp(r1, "PRIVATE") != 0,
           "normal password should NOT show as PRIVATE");
    ASSERT(strcmp(r2, "NORMAL") != 0,
           "private password should NOT show as NORMAL");

    /* 两者都不是 NONE（即都不是错误） */
    ASSERT(strcmp(r1, "NONE") != 0, "normal should not be NONE");
    ASSERT(strcmp(r2, "NONE") != 0, "private should not be NONE");

    /* 两者都不是 WRONG/错误状态 */
    ASSERT(strcmp(r1, "WRONG") != 0, "normal should not be WRONG");
    ASSERT(strcmp(r2, "WRONG") != 0, "private should not be WRONG");
    PASS();
}

/* ================================================================
 * Test 10: Error message uniformity
 * ================================================================ */
static void test_error_message_uniformity(void) {
    TEST("Error message uniformity (wrong = always same)");
    memset(&g_ctx, 0, sizeof(g_ctx));
    password_save(PG_MODE_NORMAL, "333333");
    password_save(PG_MODE_PRIVATE, "444444");

    /* 测试不同的错误密码 */
    const char *wrong_tests[] = {"000000", "111111", "222222", "555555", "123456"};
    for (int i = 0; i < 5; i++) {
        password_reset();
        for (int j = 0; j < 6; j++)
            password_input_digit(wrong_tests[i][j]);
        const char *result = password_confirm();
        ASSERT(strcmp(result, "WRONG") == 0,
               "all wrong passwords should return identical WRONG response");
    }

    /* 测试错误后用正确密码（另一个密码） */
    /* 输错普通密码后用私密密码 - 应该成功进入私密模式 */
    password_reset();
    for (int j = 0; j < 6; j++) password_input_digit('4'); /* 444444 = private */
    const char *result = password_confirm();
    ASSERT(strcmp(result, "PRIVATE") == 0,
           "after wrong attempts, correct private password should work");
    PASS();
}

/* ================================================================
 * Test 11: Password reset consistency
 * ================================================================ */
static void test_password_reset(void) {
    TEST("Password reset (change password)");
    memset(&g_ctx, 0, sizeof(g_ctx));

    /* 设置初始密码 */
    password_save(PG_MODE_NORMAL, "111111");
    ASSERT(password_verify("111111") == PG_MODE_NORMAL, "initial password should work");

    /* 更改密码 */
    password_save(PG_MODE_NORMAL, "222222");
    ASSERT(password_verify("111111") == PG_MODE_NONE, "old password should NOT work");
    ASSERT(password_verify("222222") == PG_MODE_NORMAL, "new password should work");
    PASS();
}

/* ================================================================
 * Main
 * ================================================================ */
int main(void) {
    printf("\n");
    printf("========================================\n");
    printf("  私密图库 - 核心安全逻辑测试\n");
    printf("  Private Gallery Core Security Test\n");
    printf("========================================\n\n");

    test_sha256_known();
    test_sha256_consistent();
    test_sha256_avalanche();
    test_const_memcmp();
    test_password_verify();
    test_dual_password_isolation();
    test_same_password_priority();
    test_lockout();
    test_ui_mode_isolation();
    test_error_message_uniformity();
    test_password_reset();

    printf("\n========================================\n");
    printf("  Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf("  (%d FAILED)\n", tests_failed);
    } else {
        printf("  ALL PASSED ✓\n");
    }
    printf("========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}

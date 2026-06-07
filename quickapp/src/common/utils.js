/**
 * common/utils.js - 私密图库核心逻辑
 *
 * 包含 SHA-256 哈希、常量时间比较、密码验证、锁定机制
 * 所有隐私保护逻辑都在这里实现
 */

/* ================================================================
 * SHA-256 实现 (纯 JavaScript)
 * ================================================================ */

const SHA256 = (function () {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  function ch(x, y, z) { return (x & y) ^ (~x & z); }
  function maj(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
  function bsig0(x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
  function bsig1(x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
  function ssig0(x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3); }
  function ssig1(x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10); }

  function hash(data) {
    const bytes = typeof data === 'string'
      ? (function () {
          const arr = [];
          for (let i = 0; i < data.length; i++)
            arr.push(data.charCodeAt(i) & 0xFF);
          return arr;
        })()
      : data;
    const len = bytes.length;
    const bitLen = len * 8;

    let h = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    const blocks = [];
    for (let i = 0; i < len + 9; i++) {
      if (i < len) blocks[i] = bytes[i];
      else if (i === len) blocks[i] = 0x80;
      else blocks[i] = 0;
    }

    // Append bit length as 64-bit big-endian
    for (let i = 0; i < 8; i++)
      blocks[len + 1 + i] = 0;
    for (let i = 0; i < 8; i++)
      blocks[len + 1 + (7 - i)] = (bitLen >>> (i * 8)) & 0xFF;

    const totalLen = len + 9;
    const paddedLen = Math.ceil(totalLen / 64) * 64;

    for (let bi = 0; bi < paddedLen; bi += 64) {
      const w = new Array(64);
      for (let t = 0; t < 16; t++) {
        w[t] = ((blocks[bi + t * 4] || 0) << 24) |
               ((blocks[bi + t * 4 + 1] || 0) << 16) |
               ((blocks[bi + t * 4 + 2] || 0) << 8) |
               ((blocks[bi + t * 4 + 3] || 0));
      }
      for (let t = 16; t < 64; t++)
        w[t] = (ssig1(w[t - 2]) + w[t - 7] + ssig0(w[t - 15]) + w[t - 16]) | 0;

      let a = h[0], b = h[1], c = h[2], d = h[3],
          e = h[4], f = h[5], g = h[6], hh = h[7];

      for (let t = 0; t < 64; t++) {
        const t1 = (hh + bsig1(e) + ch(e, f, g) + K[t] + w[t]) | 0;
        const t2 = (bsig0(a) + maj(a, b, c)) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0;
      h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0;
      h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }

    const result = [];
    for (let i = 0; i < 8; i++) {
      result.push((h[i] >>> 24) & 0xFF, (h[i] >>> 16) & 0xFF,
                  (h[i] >>> 8) & 0xFF, h[i] & 0xFF);
    }
    return result;
  }

  return { hash: hash };
})();

/* ================================================================
 * 常量
 * ================================================================ */

const PIN_LENGTH = 6;
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 30000;

// 存储键名（存储名称应保持中性，不暗示模式）
const STORAGE_KEY_NORMAL_PW = 'pg_nk';   // 普通密码哈希
const STORAGE_KEY_PRIVATE_PW = 'pg_pk';  // 私密密码哈希

/* ================================================================
 * 常量时间字节比较（防止时序攻击）
 * ================================================================ */

function constTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ^ b[i]);
  }
  return diff === 0;
}

/* ================================================================
 * 密码验证
 * ================================================================ */

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += ('0' + bytes[i].toString(16)).slice(-2);
  }
  return hex;
}

function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

/**
 * 验证密码
 * @param {string} pin - 6位数字密码
 * @param {string} normalHashHex - 普通密码SHA-256哈希(hex)
 * @param {string} privateHashHex - 私密密码SHA-256哈希(hex)
 * @returns {string} 'NORMAL' | 'PRIVATE' | 'NONE'
 */
function verifyPassword(pin, normalHashHex, privateHashHex) {
  const inputHash = SHA256.hash(pin);
  const inputHex = bytesToHex(inputHash);

  const normalMatch = constTimeEqual(
    inputHash,
    hexToBytes(normalHashHex || '')
  );
  const privateMatch = constTimeEqual(
    inputHash,
    hexToBytes(privateHashHex || '')
  );

  // 私密密码优先（如果两密码相同，默认进入私密模式以保隐私）
  if (privateMatch) return 'PRIVATE';
  if (normalMatch) return 'NORMAL';
  return 'NONE';
}

/**
 * 计算密码哈希
 * @param {string} pin - 6位数字密码
 * @returns {string} hex格式哈希
 */
function hashPassword(pin) {
  return bytesToHex(SHA256.hash(pin));
}

/* ================================================================
 * 锁定管理
 * ================================================================ */

let lockState = {
  attemptCount: 0,
  lockoutUntil: 0
};

function resetLockState() {
  lockState.attemptCount = 0;
  lockState.lockoutUntil = 0;
}

/**
 * 检查是否处于锁定状态
 * @returns {{locked: boolean, remaining: number}}
 */
function checkLockout() {
  if (lockState.lockoutUntil > 0) {
    const now = Date.now();
    if (now < lockState.lockoutUntil) {
      return {
        locked: true,
        remaining: Math.ceil((lockState.lockoutUntil - now) / 1000)
      };
    } else {
      // 锁定时间已过
      lockState.lockoutUntil = 0;
      lockState.attemptCount = 0;
    }
  }
  return { locked: false, remaining: 0 };
}

/**
 * 记录一次失败尝试
 * @returns {{locked: boolean, remaining: number, message: string}}
 */
function recordFailedAttempt() {
  lockState.attemptCount++;
  if (lockState.attemptCount > MAX_ATTEMPTS) {
    lockState.lockoutUntil = Date.now() + LOCKOUT_DURATION_MS;
    return { locked: true, remaining: 30, message: '请等待 30 秒' };
  }
  return {
    locked: false,
    remaining: MAX_ATTEMPTS - lockState.attemptCount + 1,
    message: '密码错误（剩余' + (MAX_ATTEMPTS - lockState.attemptCount + 1) + '次）'
  };
}

export {
  SHA256,
  PIN_LENGTH,
  MAX_ATTEMPTS,
  STORAGE_KEY_NORMAL_PW,
  STORAGE_KEY_PRIVATE_PW,
  constTimeEqual,
  verifyPassword,
  hashPassword,
  resetLockState,
  checkLockout,
  recordFailedAttempt
};

// 1. 生成14位设备唯一机器码（基于CPU+MAC+系统）
export function getMachineCode() {
  const os = require('os');
  const crypto = require('crypto');

  // 硬件+系统信息（确保唯一性）
  const cpu = os.cpus()[0].model + os.cpus()[0].speed;
  let mac = 'unknown';
  const interfaces = os.networkInterfaces();
  for (const key in interfaces) {
    const iface = interfaces[key];
    for (let i = 0; i < iface.length; i++) {
      const alias = iface[i];
      if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal && alias.mac) {
        mac = alias.mac;
        break;
      }
    }
    if (mac !== 'unknown') break;
  }
  const system = os.platform() + os.release();

  // SHA256哈希后取前14位（大写），确保唯一性和简洁性
  const hash = crypto.createHash('sha256');
  hash.update(cpu + mac + system);
  return hash.digest('hex').toUpperCase().substring(0, 14);
}

// 2. 检测系统时间是否被篡改（核心防绕过逻辑）
export function checkTimeTampering(expireDateStr) {
  const electron = require('electron');
  const fs = require('fs');
  const path = require('path');

  // 1. 解析注册码有效期（YYYYMMDD转时间戳）
  const expireYear = parseInt(expireDateStr.slice(0, 4));
  const expireMonth = parseInt(expireDateStr.slice(4, 6)) - 1; // 月份从0开始
  const expireDay = parseInt(expireDateStr.slice(6, 8));
  const expireTimestamp = new Date(expireYear, expireMonth, expireDay).getTime();

  // 2. 获取当前系统时间戳
  const currentTimestamp = new Date().getTime();

  // 3. 读取本地缓存的时间差值（首次验证时缓存）
  const cachePath = path.join(electron.app.getPath('userData'), 'timeCache.json');
  let timeCache = null;
  try {
    if (fs.existsSync(cachePath)) {
      const cacheStr = fs.readFileSync(cachePath, 'utf8');
      timeCache = JSON.parse(cacheStr);
    }
  } catch (error) {
    console.error('读取时间缓存失败：', error);
  }

  // 4. 计算当前差值（有效期时间戳 - 当前系统时间戳）
  const currentDiff = expireTimestamp - currentTimestamp;

  // 5. 首次验证：缓存差值（仅当差值为正，即未过期时缓存）
  if (!timeCache && currentDiff > 0) {
    const cacheData = {
      diff: currentDiff,
      timestamp: currentTimestamp // 缓存时的系统时间
    };
    fs.writeFileSync(cachePath, JSON.stringify(cacheData), 'utf8');
    return { isTampered: false }; // 首次无篡改
  }

  // 6. 非首次验证：检查差值是否异常（变化超过1小时=3600000ms则判定为篡改）
  if (timeCache) {
    const diffChange = Math.abs(currentDiff - timeCache.diff);
    if (diffChange > 3600000) { // 1小时阈值，可调整
      // 篡改时间，删除缓存，强制重新验证
      fs.unlinkSync(cachePath);
      return { isTampered: true, message: '检测到系统时间被篡改，请重新输入注册码' };
    }
  }

  // 7. 未篡改，更新缓存（防止正常时间同步导致的微小差异）
  if (currentDiff > 0) {
    const cacheData = {
      diff: currentDiff,
      timestamp: currentTimestamp
    };
    fs.writeFileSync(cachePath, JSON.stringify(cacheData), 'utf8');
  }

  return { isTampered: false };
}

// 3. 验证注册码（机器码+有效期+时间篡改检测+签名）
export function verifyRegCode(machineCode, regCode) {
  const crypto = require('crypto');
  const fs = require('fs');
  const path = require('path');
  const electron = require('electron');

  // 【关键】你的自定义密钥（必须保密！与生成器一致）
  const SECRET_KEY = 'asdfghjklqwertyuiopzxcvbnm147258'; // 32位字符串

  try {
    // 步骤1：解码注册码
    const decoded = Buffer.from(regCode, 'base64').toString('utf8');
    const [regMachineCode, expireDate, signature] = decoded.split(':');
    if (!regMachineCode || !expireDate || !signature) {
      return { success: false, message: '注册码格式错误' };
    }

    // 步骤2：校验机器码是否匹配
    if (regMachineCode !== machineCode) {
      return { success: false, message: '注册码与设备不匹配' };
    }

    // 步骤3：检测系统时间是否被篡改
    const timeCheckRes = checkTimeTampering(expireDate);
    if (timeCheckRes.isTampered) {
      return { success: false, message: timeCheckRes.message };
    }

    // 步骤4：校验有效期（基于本地时间，已通过篡改检测确保真实性）
    const currentDate = new Date().toISOString().split('T')[0].replace(/-/g, '');
    if (currentDate > expireDate) {
      // 过期，删除时间缓存
      const cachePath = path.join(electron.app.getPath('userData'), 'timeCache.json');
      if (fs.existsSync(cachePath)) {
        fs.unlinkSync(cachePath);
      }
      return { success: false, message: `注册码已过期（有效期至${expireDate}）` };
    }

    // 步骤5：校验签名（防止伪造注册码）
    const signStr = `${regMachineCode}:${expireDate}:${SECRET_KEY}`;
    const signHash = crypto.createHash('sha256').update(signStr).digest('hex');
    if (signHash !== signature) {
      return { success: false, message: '注册码无效（伪造）' };
    }

    // 所有校验通过
    return { success: true };
  } catch (error) {
    console.error('注册码验证失败：', error);
    return { success: false, message: '注册码验证异常，请重试' };
  }
}

// 4. （管理员用）生成注册码（本地执行，给用户发放）
export function generateRegCode(machineCode, expireDays) {
  const crypto = require('crypto');
  const SECRET_KEY = 'asdfghjklqwertyuiopzxcvbnm147258'; // 与上面密钥一致

  // 计算有效期（YYYYMMDD格式）
  const expireDate = new Date();
  expireDate.setDate(expireDate.getDate() + expireDays);
  const expireStr = expireDate.toISOString().split('T')[0].replace(/-/g, '');

  // 生成签名（防伪造）
  const signStr = `${machineCode}:${expireStr}:${SECRET_KEY}`;
  const signature = crypto.createHash('sha256').update(signStr).digest('hex');

  // 拼接并Base64编码，生成最终注册码
  return Buffer.from(`${machineCode}:${expireStr}:${signature}`).toString('base64');
}

// 5. 清除注册码缓存（可选，用于注销功能）
export function clearRegCodeCache() {
  const electron = require('electron');
  const fs = require('fs');
  const path = require('path');
  const cachePath = path.join(electron.app.getPath('userData'), 'timeCache.json');
  if (fs.existsSync(cachePath)) {
    fs.unlinkSync(cachePath);
  }
}

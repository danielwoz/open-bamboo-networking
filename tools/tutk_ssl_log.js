'use strict';

// Log stock libBambuSource traffic for Device -> Files RE.
//
// Primary hooks: Bambu_SendMessage / Bambu_ReadSample (JSON plaintext at ABI).
// Secondary: tutk_third_SSL_* and TUTKSSL_* (wire encryption layer).
//
// Output: JSON/text as a single line; hexdump only for binary-only payloads
// or trailing binary after JSON (e.g. thumbnail JPEG after SUB_FILE reply).
//
// Attach: ./tools/frida_tutk_attach.sh

const MOD_NAME = 'libBambuSource.so';
const LOG_PATH = '/tmp/tutk_ssl.log';
const MAX_HEX_CONSOLE = 2048;

let logFile = null;
const hooked = new Set();

function openLog() {
  if (logFile) return;
  try {
    logFile = new File(LOG_PATH, 'a');
    logFile.write('\n--- session ' + new Date().toISOString() + ' ---\n');
    logFile.flush();
  } catch (e) {
    console.error('cannot open ' + LOG_PATH + ': ' + e);
  }
}

function emit(line) {
  console.log(line);
  openLog();
  if (logFile) {
    logFile.write(line + '\n');
    logFile.flush();
  }
}

function readBytes(ptr, len) {
  if (len <= 0 || ptr.isNull()) return null;
  return new Uint8Array(ptr.readByteArray(len));
}

function readU32LE(data, off) {
  return (
    data[off] |
    (data[off + 1] << 8) |
    (data[off + 2] << 16) |
    (data[off + 3] << 24)
  ) >>> 0;
}

function parseFrames(data) {
  const frames = [];
  let i = 0;
  while (i + 16 <= data.length) {
    const pl = readU32LE(data, i);
    const magic = readU32LE(data, i + 4);
    const seq = readU32LE(data, i + 8);
    const end = i + 16 + pl;
    if (end > data.length) break;
    frames.push({
      pl: pl,
      magic: magic,
      seq: seq,
      body: data.subarray(i + 16, end),
    });
    i = end;
  }
  return { frames: frames, tail: data.subarray(i) };
}

function jsonPrefixEnd(data) {
  if (!data.length || data[0] !== 0x7b) return -1;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    if (inStr) {
      if (esc) esc = false;
      else if (b === 0x5c) esc = true;
      else if (b === 0x22) inStr = false;
      continue;
    }
    if (b === 0x22) inStr = true;
    else if (b === 0x7b) depth++;
    else if (b === 0x7d) {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function lstripWs(data) {
  let i = 0;
  while (i < data.length && (data[i] === 0x0a || data[i] === 0x0d ||
         data[i] === 0x09 || data[i] === 0x20)) {
    i++;
  }
  return data.subarray(i);
}

function decodeUtf8(data) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(data);
  } catch (_) {
    return null;
  }
}

function isPrintableText(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x0a || c === 0x0d || c === 0x09) continue;
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

function splitTextAndBinary(data) {
  if (!data.length) return { text: null, binary: new Uint8Array(0) };

  const jend = jsonPrefixEnd(data);
  if (jend > 0) {
    const text = decodeUtf8(data.subarray(0, jend));
    if (text !== null) {
      return { text: text, binary: lstripWs(data.subarray(jend)) };
    }
  }

  const text = decodeUtf8(data);
  if (text !== null && isPrintableText(text)) {
    return { text: text, binary: new Uint8Array(0) };
  }
  return { text: null, binary: data };
}

function formatHex(data, hexLimit) {
  if (!data.length) return [];
  const lines = ['--- binary ' + data.length + ' bytes ---'];
  const show = Math.min(data.length, hexLimit);
  const buf = Memory.alloc(show);
  buf.writeByteArray(data.subarray(0, show));
  const dump = hexdump(buf, { length: show, ansi: false });
  dump.split('\n').forEach(function (line) {
    if (line.length) lines.push(line);
  });
  if (data.length > show) {
    lines.push('... (' + (data.length - show) + ' more bytes)');
  }
  return lines;
}

function formatPayload(data, hexLimit) {
  const parts = splitTextAndBinary(data);
  const lines = [];
  if (parts.text !== null) lines.push(parts.text);
  if (parts.binary.length) {
    formatHex(parts.binary, hexLimit).forEach(function (line) {
      lines.push(line);
    });
  }
  return lines;
}

function formatBytes(data, hexLimit) {
  const parsed = parseFrames(data);
  const lines = [];
  if (parsed.frames.length) {
    parsed.frames.forEach(function (f) {
      formatPayload(f.body, hexLimit).forEach(function (line) {
        lines.push(line);
      });
    });
    if (parsed.tail.length) {
      formatPayload(parsed.tail, hexLimit).forEach(function (line) {
        lines.push(line);
      });
    }
  } else {
    formatPayload(data, hexLimit).forEach(function (line) {
      lines.push(line);
    });
  }
  return lines;
}

function logBytes(tag, ptr, len) {
  const data = readBytes(ptr, len);
  if (!data) return;
  emit('[' + new Date().toISOString() + '] ' + tag + ' ' + len + ' bytes');
  formatBytes(data, MAX_HEX_CONSOLE).forEach(function (line) {
    emit(line);
  });
}

function hookExport(mod, name, callbacks) {
  const key = mod.name + '!' + name;
  if (hooked.has(key)) return true;
  const addr = mod.findExportByName(name);
  if (!addr) return false;
  Interceptor.attach(addr, callbacks);
  hooked.add(key);
  emit('[+] hook ' + name);
  return true;
}

function hookSslIo(mod) {
  const names = [
    'TUTKSSL_write', 'TUTKSSL_read',
    'tutk_third_SSL_write', 'tutk_third_SSL_read',
    'tutk_third_SSL_write_ex', 'tutk_third_SSL_read_ex',
  ];
  for (const name of names) {
    if (name.indexOf('write') >= 0) {
      hookExport(mod, name, {
        onEnter(args) {
          const len = args[2].toInt32();
          if (len > 0) logBytes('SSL ' + name + ' C->P', args[1], len);
        },
      });
    } else {
      hookExport(mod, name, {
        onEnter(args) {
          this.buf = args[1];
        },
        onLeave(retval) {
          const n = retval.toInt32();
          if (n > 0) logBytes('SSL ' + name + ' P->C', this.buf, n);
        },
      });
    }
  }
}

function hookBambuAbi(mod) {
  hookExport(mod, 'Bambu_SendMessage', {
    onEnter(args) {
      const ctrl = args[1].toInt32();
      const data = args[2];
      const len = args[3].toInt32();
      emit('[ABI] Bambu_SendMessage ctrl=0x' + ctrl.toString(16) + ' len=' + len);
      if (len > 0) logBytes('ABI SendMessage', data, len);
    },
  });

  hookExport(mod, 'Bambu_ReadSample', {
    onEnter(args) {
      this.sample = args[1];
    },
    onLeave(retval) {
      const rc = retval.toInt32();
      if (rc !== 0 || this.sample.isNull()) return;
      // struct Bambu_Sample { int itrack; int size; int flags; const uchar* buffer; ull decode_time; }
      const size = this.sample.add(4).readS32();
      const bufPtr = this.sample.add(16).readPointer();
      emit('[ABI] Bambu_ReadSample rc=' + rc + ' size=' + size);
      if (size > 0 && !bufPtr.isNull()) {
        logBytes('ABI ReadSample', bufPtr, size);
      }
    },
  });

  hookExport(mod, 'Bambu_Open', {
    onEnter() {
      emit('[ABI] Bambu_Open');
    },
  });

  hookExport(mod, 'Bambu_StartStreamEx', {
    onEnter(args) {
      emit('[ABI] Bambu_StartStreamEx type=0x' + args[1].toInt32().toString(16));
    },
  });
}

function installHooks() {
  const mod = Process.findModuleByName(MOD_NAME);
  if (!mod) return false;
  if (hooked.has(MOD_NAME + '!installed')) return true;

  emit('[+] module ' + MOD_NAME + ' base=' + mod.base);
  hookBambuAbi(mod);
  hookSslIo(mod);
  hooked.add(MOD_NAME + '!installed');
  emit('[*] ready — switch External / Internal in Device -> Files now');
  return true;
}

function waitForModule() {
  if (installHooks()) return;
  emit('[*] waiting for ' + MOD_NAME + ' (open Device tab)...');

  const dlopen = Module.findExportByName(null, 'dlopen');
  if (dlopen) {
    Interceptor.attach(dlopen, {
      onLeave() {
        installHooks();
      },
    });
  }

  const timer = setInterval(function () {
    if (installHooks()) clearInterval(timer);
  }, 500);
}

waitForModule();

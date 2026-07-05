// ArgonGuard dev harness（Node.js；協議凍結於 spec/harness-contract.json schemaVersion 1）。
// stdin: {"schemaVersion":1,"commands":[...]} → stdout 單行: {"schemaVersion":1,"results":[...]}
// op: hash{profile,passwordHex} / verify{passwordHex,encoded} / needsRehash{activeProfile,encoded,legacyRegistered?}
// 需先 `npm run build`（本檔 import ../dist/index.js）。
import { readFileSync } from "node:fs";
import { ArgonGuardError, ArgonGuardPasswordHasher } from "../dist/index.js";

const PROFILES = new Set(["default", "high", "highest"]);

function parseProfile(name) {
  if (!PROFILES.has(name)) throw new RangeError(`unknown profile: ${name}`);
  return name;
}

function utf8FromHex(hex) {
  return Buffer.from(hex, "hex").toString("utf8");
}

/** harness 協議中 legacyRegistered=true 的標準認領器（與向量語意一致）。 */
const bcryptPrefixClaimer = {
  canHandle: (encodedHash) => encodedHash.startsWith("$2b$"),
  verify: () => false,
};

const input = JSON.parse(readFileSync(0, "utf8"));
if (input.schemaVersion !== 1) {
  process.stderr.write("unsupported schemaVersion\n");
  process.exit(2);
}

const results = [];
for (const cmd of input.commands) {
  try {
    switch (cmd.op) {
      case "hash": {
        const hasher = new ArgonGuardPasswordHasher({ profile: parseProfile(cmd.profile) });
        results.push({ ok: true, encoded: await hasher.hashPassword(utf8FromHex(cmd.passwordHex)) });
        break;
      }
      case "verify": {
        const hasher = new ArgonGuardPasswordHasher();
        results.push({ ok: true, value: await hasher.verifyPassword(utf8FromHex(cmd.passwordHex), cmd.encoded) });
        break;
      }
      case "needsRehash": {
        const options = { profile: parseProfile(cmd.activeProfile) };
        if (cmd.legacyRegistered === true) options.legacyVerifiers = [bcryptPrefixClaimer];
        const hasher = new ArgonGuardPasswordHasher(options);
        results.push({ ok: true, value: hasher.needsRehash(cmd.encoded) });
        break;
      }
      default:
        results.push({ ok: false, error: "HarnessError", reason: "unknown_op" });
        break;
    }
  } catch (error) {
    if (error instanceof ArgonGuardError) {
      // error 名＝五類別名（無 "Error" 後綴），與 .NET harness（無 "Exception" 後綴）一致
      results.push({ ok: false, error: error.name.replace(/Error$/, ""), reason: error.reason });
    } else {
      throw error;
    }
  }
}

process.stdout.write(JSON.stringify({ schemaVersion: 1, results }) + "\n");

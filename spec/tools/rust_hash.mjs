// RustCrypto (via @node-rs/argon2) 獨立實作向量來源。
// stdin: JSON [{passwordHex, saltHex, m, t, p, tagLen}] → stdout: JSON [tagHex]
import { hashRawSync, Algorithm, Version } from "@node-rs/argon2";
import { readFileSync } from "node:fs";

const jobs = JSON.parse(readFileSync(0, "utf8"));
const out = jobs.map((j) =>
  Buffer.from(
    hashRawSync(Buffer.from(j.passwordHex, "hex"), {
      salt: Buffer.from(j.saltHex, "hex"),
      memoryCost: j.m,
      timeCost: j.t,
      parallelism: j.p,
      outputLen: j.tagLen,
      algorithm: Algorithm.Argon2id,
      version: Version.V0x13,
    })
  ).toString("hex")
);
process.stdout.write(JSON.stringify(out));

import { ArgonGuardPasswordHasher, SPEC_VERSION, type ArgonGuardProfile } from "../src/index.js";

/**
 * 測試用 worker：暴露 hash / verify / needsRehash / version，供 workerd.test.ts 在真
 * workerd（Miniflare）環境驗證 edge 套件的 wasm 靜態 import 與跨引擎 bit-identical。
 * 非發佈產物。
 */
interface HashReq { op: "hash"; password: string; profile?: ArgonGuardProfile }
interface VerifyReq { op: "verify"; password: string; encoded: string }
interface RehashReq { op: "needsRehash"; encoded: string; profile?: ArgonGuardProfile }
interface VersionReq { op: "version" }
type Req = HashReq | VerifyReq | RehashReq | VersionReq;

export default {
  async fetch(request: Request): Promise<Response> {
    let body: Req;
    try {
      body = (await request.json()) as Req;
    } catch {
      return new Response("bad json", { status: 400 });
    }
    try {
      if (body.op === "version") return Response.json({ version: SPEC_VERSION });
      if (body.op === "hash") {
        const hasher = new ArgonGuardPasswordHasher(body.profile ? { profile: body.profile } : undefined);
        return Response.json({ encoded: await hasher.hashPassword(body.password) });
      }
      if (body.op === "verify") {
        const hasher = new ArgonGuardPasswordHasher();
        return Response.json({ ok: await hasher.verifyPassword(body.password, body.encoded) });
      }
      if (body.op === "needsRehash") {
        const hasher = new ArgonGuardPasswordHasher(body.profile ? { profile: body.profile } : undefined);
        return Response.json({ value: hasher.needsRehash(body.encoded) });
      }
      return new Response("bad op", { status: 400 });
    } catch (e) {
      return Response.json({ error: e instanceof Error ? e.message : String(e), reason: (e as { reason?: string }).reason }, { status: 422 });
    }
  },
};

/**
 * Cloudflare Workers / bundler 把 `import x from '*.wasm'` 處理成預編譯的
 * WebAssembly.Module（wrangler `[[rules]] type="CompiledWasm"`）。此宣告讓 TS 知道其型別。
 */
declare module "*.wasm" {
  const wasmModule: WebAssembly.Module;
  export default wasmModule;
}

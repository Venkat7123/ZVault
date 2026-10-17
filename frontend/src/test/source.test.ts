import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return name === "test" ? [] : sourceFiles(p);
    return /\.(tsx?|css|html)$/.test(name) ? [p] : [];
  });
}

const files = sourceFiles(join(__dirname, ".."));

describe("source rules", () => {
  it("scans real files", () => {
    expect(files.length).toBeGreaterThan(15);
  });

  it("never uses dangerouslySetInnerHTML or innerHTML", () => {
    for (const f of files) {
      expect(readFileSync(f, "utf8"), f).not.toMatch(/dangerouslySetInnerHTML|\.innerHTML|insertAdjacentHTML/);
    }
  });

  it("has no inline style props (the gateway CSP forbids them)", () => {
    for (const f of files.filter((x) => x.endsWith(".tsx"))) {
      expect(readFileSync(f, "utf8"), f).not.toMatch(/\bstyle=\{/);
    }
  });

  it("never touches browser storage", () => {
    for (const f of files) {
      expect(readFileSync(f, "utf8"), f).not.toMatch(/localStorage|sessionStorage|indexedDB|document\.cookie/);
    }
  });

  it("has no hardcoded localhost URLs", () => {
    for (const f of files) {
      expect(readFileSync(f, "utf8"), f).not.toMatch(/https?:\/\/(localhost|127\.0\.0\.1)/);
    }
  });
});

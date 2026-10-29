// Avrana fork: Next.js runs src/middleware.ts in the Edge runtime, where Prisma cannot load. A middleware import that
// reaches the database client builds fine and passes mocked unit tests, then makes every page a 500 at runtime (seen
// 2026-10-29 with on-behalf.ts). This walks the middleware's own import graph and fails if it reaches the database.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

const SRC = path.resolve(__dirname, '../../src');
const FORBIDDEN_FILES = [path.join(SRC, 'lib/db.ts')];
const FORBIDDEN_PACKAGES = ['@prisma/client', '@prisma/adapter-better-sqlite3', 'better-sqlite3', 'pg'];
const IMPORT = /(?:^|\n)\s*(?:import|export)\s[^'"]*?from\s+['"]([^'"]+)['"]|(?:^|\n)\s*import\s+['"]([^'"]+)['"]/g;

function resolveLocal(spec: string, from: string): string | null {
    const base = spec.startsWith('@/') ? path.join(SRC, spec.slice(2))
        : spec.startsWith('.') ? path.resolve(path.dirname(from), spec) : null;
    if (!base) return null;
    for (const file of [base, `${base}.ts`, `${base}.tsx`, path.join(base, 'index.ts')]) {
        if (fs.existsSync(file) && fs.statSync(file).isFile()) return file;
    }
    return null;
}

function walk(entry: string): { files: Set<string>; packages: Set<string> } {
    const files = new Set<string>(), packages = new Set<string>(), queue = [entry];
    while (queue.length) {
        const file = queue.pop()!;
        if (files.has(file)) continue;
        files.add(file);
        const text = fs.readFileSync(file, 'utf8');
        for (const m of text.matchAll(IMPORT)) {
            const spec = m[1] ?? m[2];
            if (/^\s*import\s+type\s/.test(m[0].trimStart())) continue;     // type-only imports vanish at build
            const local = resolveLocal(spec, file);
            if (local) queue.push(local);
            else packages.add(spec);
        }
    }
    return { files, packages };
}

describe('Avrana fork: the middleware stays Edge-safe', () => {
    const { files, packages } = walk(path.join(SRC, 'middleware.ts'));

    it('never reaches the database client', () => {
        for (const bad of FORBIDDEN_FILES) expect([...files]).not.toContain(bad);
        for (const bad of FORBIDDEN_PACKAGES) expect([...packages]).not.toContain(bad);
    });

    it('takes the on-behalf gate from the import-free module', () => {
        expect(files).toContain(path.join(SRC, 'lib/on-behalf-gate.ts'));
        expect(files).not.toContain(path.join(SRC, 'lib/on-behalf.ts'));
        expect(fs.readFileSync(path.join(SRC, 'lib/on-behalf-gate.ts'), 'utf8')).not.toMatch(/^\s*import\s/m);
    });
});

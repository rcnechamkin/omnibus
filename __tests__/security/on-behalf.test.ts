import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import crypto from 'crypto';

const mocks = vi.hoisted(() => ({
    getToken: vi.fn(),
    apiKeyFindUnique: vi.fn(),
    apiKeyUpdate: vi.fn(),
    userFindUnique: vi.fn(),
    auditCreate: vi.fn(),
}));

vi.mock('next-auth/jwt', () => ({ getToken: mocks.getToken }));
vi.mock('@/lib/db', () => ({
    prisma: {
        apiKey: { findUnique: mocks.apiKeyFindUnique, update: mocks.apiKeyUpdate },
        user: { findUnique: mocks.userFindUnique },
        auditLog: { create: mocks.auditCreate },
    },
}));

import { middleware } from '@/middleware';
import { resolveOnBehalf, wantsOnBehalf } from '@/lib/on-behalf';

const RAW = 'omn_test_key';
const KEY = { id: 'k1', prefix: 'omn_test...', allowOnBehalf: true, expiresAt: null, createdById: 'admin1',
              createdBy: { role: 'ADMIN' } };
const MEMBER = { id: 'u2', username: 'member', role: 'USER' };

function req(path: string, method = 'GET', headers: Record<string, string> = {}) {
    return new NextRequest(`http://localhost${path}`, { method, headers });
}

beforeEach(() => {
    vi.clearAllMocks();
    mocks.getToken.mockResolvedValue(null);
    mocks.apiKeyUpdate.mockResolvedValue({});
    mocks.auditCreate.mockResolvedValue({});
});

describe('On-behalf API keys', () => {
    it('lets the middleware pass only exact search/request routes with both headers, GET and POST only', async () => {
        const both = { 'x-api-key': RAW, 'x-omnibus-user': 'member' };
        expect(wantsOnBehalf('/api/search', 'GET', new Headers(both))).toBe(true);
        expect(wantsOnBehalf('/api/request', 'POST', new Headers(both))).toBe(true);
        expect(wantsOnBehalf('/api/request', 'PATCH', new Headers(both))).toBe(false);
        expect(wantsOnBehalf('/api/request', 'DELETE', new Headers(both))).toBe(false);
        expect(wantsOnBehalf('/api/search/interactive', 'GET', new Headers(both))).toBe(false);
        expect(wantsOnBehalf('/api/admin/api-keys', 'GET', new Headers(both))).toBe(false);
        expect(wantsOnBehalf('/api/search', 'GET', new Headers({ 'x-api-key': RAW }))).toBe(false);

        const passed = await middleware(req('/api/search?q=x', 'GET', both)) as Response;
        expect(passed.status).not.toBe(401);
        const blocked = await middleware(req('/api/request', 'PATCH', both)) as Response;
        expect(blocked.status).toBe(401);
        const admin = await middleware(req('/api/admin/users', 'GET', both)) as Response;
        expect(admin.status).toBe(401);
    });

    it('resolves the named member for an enabled admin-created key, and audits it', async () => {
        mocks.apiKeyFindUnique.mockResolvedValue(KEY);
        mocks.userFindUnique.mockResolvedValue(MEMBER);
        const who = await resolveOnBehalf(req('/api/request', 'POST', { 'x-api-key': RAW, 'x-omnibus-user': 'member' }), 'request');
        expect(who).toMatchObject({ id: 'u2', sub: 'u2', name: 'member', role: 'USER' });
        expect(mocks.apiKeyFindUnique).toHaveBeenCalledWith(expect.objectContaining({
            where: { keyHash: crypto.createHash('sha256').update(RAW).digest('hex') } }));
        expect(mocks.auditCreate).toHaveBeenCalledWith(expect.objectContaining({
            data: expect.objectContaining({ action: 'API_ON_BEHALF', userId: 'admin1' }) }));
    });

    it('refuses keys without the flag, from non-admins, expired keys, admins as targets and odd usernames', async () => {
        const cases: Array<[any, any, string]> = [
            [{ ...KEY, allowOnBehalf: false }, MEMBER, 'member'],
            [{ ...KEY, createdBy: { role: 'USER' } }, MEMBER, 'member'],
            [{ ...KEY, expiresAt: new Date(Date.now() - 1000) }, MEMBER, 'member'],
            [KEY, { ...MEMBER, role: 'ADMIN' }, 'member'],
            [KEY, null, 'member'],
            [null, MEMBER, 'member'],
            [KEY, MEMBER, 'bad name with spaces'],
        ];
        for (const [key, member, username] of cases) {
            mocks.apiKeyFindUnique.mockResolvedValue(key);
            mocks.userFindUnique.mockResolvedValue(member);
            const who = await resolveOnBehalf(req('/api/search', 'GET', { 'x-api-key': RAW, 'x-omnibus-user': username }), 'search');
            expect(who).toBeNull();
        }
    });

    it('never reads the key from the query string', async () => {
        mocks.apiKeyFindUnique.mockResolvedValue(KEY);
        mocks.userFindUnique.mockResolvedValue(MEMBER);
        const who = await resolveOnBehalf(req(`/api/search?apiKey=${RAW}`, 'GET', { 'x-omnibus-user': 'member' }), 'search');
        expect(who).toBeNull();
        expect(mocks.apiKeyFindUnique).not.toHaveBeenCalled();
    });
});

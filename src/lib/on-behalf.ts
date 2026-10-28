// src/lib/on-behalf.ts
// Server-to-server requests on a member's behalf (e.g. a home page that lets members ask for comics).
//
// A caller sends BOTH headers:
//   X-Api-Key:      an admin API key whose `allowOnBehalf` flag an admin switched on
//   X-Omnibus-User: the username of the member to act as
// and may then use exactly two routes: GET /api/search and GET/POST /api/request. Everything else still needs a
// session. The named member must exist and must not be an admin; their own Request permission, auto-approve and
// approval rules apply unchanged. Each use is written to the audit log.
import crypto from 'crypto';
import { prisma } from './db';
import { Logger } from './logger';

export const ON_BEHALF_ROUTES = ['/api/search', '/api/request'] as const;
export const ON_BEHALF_METHODS = ['GET', 'POST'] as const;
const USERNAME = /^[A-Za-z0-9._@+-]{1,150}$/;

export interface OnBehalfToken {
    id: string;
    sub: string;
    name: string;
    role: 'USER';
    onBehalfKeyId: string;
}

/** True when the request carries on-behalf headers for a route and method that accept them (middleware gate). */
export function wantsOnBehalf(pathname: string, method: string, headers: Headers): boolean {
    return (ON_BEHALF_ROUTES as readonly string[]).includes(pathname)
        && (ON_BEHALF_METHODS as readonly string[]).includes(method.toUpperCase())
        && !!headers.get('x-api-key')
        && !!headers.get('x-omnibus-user');
}

/**
 * The member to act as, or null. Only the `X-Api-Key` header is read for the key (never a query string or Basic
 * auth, so the key cannot end up in an access log). Never throws.
 */
export async function resolveOnBehalf(req: Request, action: string): Promise<OnBehalfToken | null> {
    const raw = req.headers.get('x-api-key')?.trim();
    const username = req.headers.get('x-omnibus-user')?.trim();
    if (!raw || !username || !USERNAME.test(username)) return null;
    try {
        const keyHash = crypto.createHash('sha256').update(raw).digest('hex');
        const key = await prisma.apiKey.findUnique({ where: { keyHash }, include: { createdBy: true } });
        if (!key || !key.allowOnBehalf || key.createdBy?.role !== 'ADMIN') return null;
        if (key.expiresAt && new Date() > key.expiresAt) return null;
        const member = await prisma.user.findUnique({
            where: { username },
            select: { id: true, username: true, role: true },
        });
        if (!member || member.role === 'ADMIN') return null;   // never act as an administrator
        prisma.apiKey.update({ where: { id: key.id }, data: { lastUsedAt: new Date() } }).catch(() => {});
        prisma.auditLog.create({
            data: { userId: key.createdById, action: 'API_ON_BEHALF', details: `${action} as ${member.username} (key ${key.prefix})` },
        }).catch(() => {});
        return { id: member.id, sub: member.id, name: member.username, role: 'USER', onBehalfKeyId: key.id };
    } catch (e) {
        Logger.log('[On Behalf] lookup failed', 'warn');
        return null;
    }
}

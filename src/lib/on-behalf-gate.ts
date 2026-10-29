// src/lib/on-behalf-gate.ts
// Avrana fork: the part of on-behalf.ts the middleware needs, with NO imports. Next.js runs middleware in the Edge
// runtime, where Prisma cannot load: importing on-behalf.ts (which reads the database) there made every page a 500.
// Keep this file free of imports; __tests__/security/middleware-edge-imports.test.ts checks it.
export const ON_BEHALF_ROUTES = ['/api/search', '/api/request'] as const;
export const ON_BEHALF_METHODS = ['GET', 'POST'] as const;

/** True when the request carries on-behalf headers for a route and method that accept them (middleware gate). */
export function wantsOnBehalf(pathname: string, method: string, headers: Headers): boolean {
    return (ON_BEHALF_ROUTES as readonly string[]).includes(pathname)
        && (ON_BEHALF_METHODS as readonly string[]).includes(method.toUpperCase())
        && !!headers.get('x-api-key')
        && !!headers.get('x-omnibus-user');
}

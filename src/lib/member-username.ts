// src/lib/member-username.ts
// Avrana fork: the usernames a front end may name in X-Omnibus-User (on-behalf.ts), and so the only ones a new SSO
// account is given (sso-username.ts). No imports, so tests need no database mock.
export const MEMBER_USERNAME = /^[A-Za-z0-9._@+-]{1,150}$/;

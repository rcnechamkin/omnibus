import { describe, it, expect } from 'vitest';
import { ssoUsername } from '@/lib/sso-username';

const none = async () => false;

describe('Avrana fork: SSO account usernames', () => {
    it('uses the identity provider username, not the display name', async () => {
        expect(await ssoUsername({ preferredUsername: 'jane_doe', email: 'jane@example.test', name: 'Jane Doe' }, none))
            .toBe('jane_doe');
    });

    it('falls back to the e-mail local part, then the display name, skipping what the header cannot carry', async () => {
        expect(await ssoUsername({ preferredUsername: 'jane doe', email: 'jane@example.test', name: 'Jane' }, none))
            .toBe('jane');
        expect(await ssoUsername({ preferredUsername: null, email: null, name: 'Jane' }, none)).toBe('Jane');
    });

    it('never takes a name another account holds', async () => {
        const held = new Set(['jane_doe']);
        const taken = async (name: string) => held.has(name.toLowerCase());
        expect(await ssoUsername({ preferredUsername: 'jane_doe', email: 'jdoe@example.test' }, taken)).toBe('jdoe');
    });

    it('numbers the first candidate when every candidate is taken', async () => {
        const held = new Set(['jane_doe', 'jdoe']);
        const taken = async (name: string) => held.has(name);
        expect(await ssoUsername({ preferredUsername: 'jane_doe', email: 'jdoe@example.test' }, taken)).toBe('jane_doe2');
    });

    it('has a fixed name when the profile offers nothing usable', async () => {
        expect(await ssoUsername({ preferredUsername: '  ', email: '@x', name: 'Ünïcode Name' }, none)).toBe('sso-user');
    });
});

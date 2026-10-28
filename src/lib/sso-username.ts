// src/lib/sso-username.ts
// Avrana fork: the username a brand-new SSO account gets.
//
// Upstream named it after the display name ("Jane Doe"), so a front end that acts for members by username
// (X-Omnibus-User, see on-behalf.ts) could never find them. The account is named after the identity provider's
// username instead (`preferred_username`), then the e-mail's local part, then the display name; only a candidate the
// on-behalf header could carry is used, and never one another account already holds. If every candidate is taken,
// the first candidate gets a number. Existing accounts are never renamed.
import { MEMBER_USERNAME } from './member-username';

export interface SsoProfile {
    preferredUsername?: string | null;
    email?: string | null;
    name?: string | null;
}

const MAX_SUFFIX = 99;
const FALLBACK = 'sso-user';

function candidates(profile: SsoProfile): string[] {
    const local = profile.email?.split('@')[0];
    return [profile.preferredUsername, local, profile.name]
        .map((value) => (typeof value === 'string' ? value.trim() : ''))
        .filter((value) => MEMBER_USERNAME.test(value))
        .filter((value, i, all) => all.indexOf(value) === i);
}

/** The new account's username; `taken` says whether some account already uses a name (case-insensitively). */
export async function ssoUsername(profile: SsoProfile, taken: (name: string) => Promise<boolean>): Promise<string> {
    const names = candidates(profile);
    if (names.length === 0) names.push(FALLBACK);
    for (const name of names) {
        if (!(await taken(name))) return name;
    }
    const base = names[0];
    for (let n = 2; n <= MAX_SUFFIX; n++) {
        const name = `${base.slice(0, 140)}${n}`;
        if (!(await taken(name))) return name;
    }
    throw new Error('No free username for this SSO account');
}

// Event broadcast when the server reports that the current session is no
// longer valid (expired JWT, idle-revoked session, or signed-out elsewhere).
export const UNAUTHORIZED_EVENT = 'auth:unauthorized';

export class ApiError extends Error {
    constructor(
        public readonly status: number,
        public readonly code: string,
        message: string,
        public readonly retryAfterMs: number | null = null,
    ) {
        super(message);
        this.name = 'ApiError';
    }
}

export async function apiErrorFrom(res: Response): Promise<ApiError> {
    const text = await res.text().catch(() => '');
    let code = `HTTP_${res.status}`;
    let message = text || res.statusText || `Request failed (${res.status})`;
    try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === 'object') {
            if (typeof parsed.code === 'string') code = parsed.code;
            if (typeof parsed.message === 'string') message = parsed.message;
        }
    } catch { /* plain-text body */ }
    const retryAfter = Number(res.headers.get('Retry-After'));
    return new ApiError(res.status, code, message, Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : null);
}

export function apiErrorCode(err: unknown): string {
    return err instanceof ApiError ? err.code : 'NETWORK';
}

const configuredApiOrigin = (() => {
    const value = import.meta.env.VITE_API_ORIGIN?.trim();
    if (!value) return '';
    try {
        const parsed = new URL(value);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return '';
        }
        return value.replace(/\/+$/, '');
    } catch {
        return '';
    }
})();

export function apiEndpoint(path: string): string {
    if (!path.startsWith('/')) throw new Error('API paths must start with "/"');
    return configuredApiOrigin ? `${configuredApiOrigin}${path}` : path;
}

export async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const res = await fetch(input, init);
    if (res.status === 401 && res.headers.get('X-Session-Invalid') === '1') {
        if (typeof window !== 'undefined') {
            window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
        }
    }
    return res;
}

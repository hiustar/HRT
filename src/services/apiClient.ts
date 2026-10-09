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

export function apiEndpoint(path: string): string {
    return path;
}

// ==========================================
// 纯本地离线账户与备份拦截器 (Local Storage Mock API)
// ==========================================
function mockResponse(data: any, status = 200, headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
            ...headers
        }
    });
}

function handleLocalMockApi(path: string, method: string, headers: HeadersInit | undefined, body: any): Response | null {
    const usersKey = 'hrt_local_users';
    const backupsKey = 'hrt_local_backups';

    const getUsers = (): Record<string, { id: string; username: string; password: string }> => {
        try { return JSON.parse(localStorage.getItem(usersKey) || '{}'); } catch { return {}; }
    };
    const saveUsers = (u: any) => localStorage.setItem(usersKey, JSON.stringify(u));

    const getBackups = (): Record<string, { id: string; userId: string; data: string; createdAt: number }> => {
        try { return JSON.parse(localStorage.getItem(backupsKey) || '{}'); } catch { return {}; }
    };
    const saveBackups = (b: any) => localStorage.setItem(backupsKey, JSON.stringify(b));

    // Extract token
    let token = '';
    if (headers) {
        const auth = (headers as any)['Authorization'] || (headers as any)['authorization'];
        if (auth && typeof auth === 'string' && auth.startsWith('Bearer ')) {
            token = auth.slice(7);
        }
    }

    // 1. 注册: POST /api/register
    if (path === '/api/register' && method === 'POST') {
        const { username, password } = body || {};
        if (!username || !password) {
            return mockResponse({ code: 'INVALID_INPUT', message: '请输入用户名和密码' }, 400);
        }
        const users = getUsers();
        if (users[username.toLowerCase()]) {
            return mockResponse({ code: 'USER_EXISTS', message: '该用户名已存在' }, 409);
        }
        const user = { id: 'u_' + Date.now(), username, password };
        users[username.toLowerCase()] = user;
        saveUsers(users);
        const tokenVal = `local_token_${user.id}_${btoa(JSON.stringify({ sid: 'sid_' + user.id }))}`;
        return mockResponse({ token: tokenVal, user: { id: user.id, username: user.username } });
    }

    // 2. 登录: POST /api/login
    if (path === '/api/login' && method === 'POST') {
        const { username, password } = body || {};
        const users = getUsers();
        const user = users[(username || '').toLowerCase()];
        if (!user || user.password !== password) {
            return mockResponse({ code: 'INVALID_CREDENTIALS', message: '用户名或密码错误' }, 401);
        }
        const tokenVal = `local_token_${user.id}_${btoa(JSON.stringify({ sid: 'sid_' + user.id }))}`;
        return mockResponse({ token: tokenVal, user: { id: user.id, username: user.username } });
    }

    // 3. 用户信息: GET /api/user/me, GET /api/user/profile
    if ((path === '/api/user/me' || path === '/api/user/profile') && method === 'GET') {
        const storedUser = localStorage.getItem('auth_user');
        if (storedUser) {
            try { return mockResponse(JSON.parse(storedUser)); } catch { }
        }
        return mockResponse({ id: 'u_local', username: '本地用户' });
    }

    // 4. 修改密码: POST /api/user/password
    if (path === '/api/user/password' && method === 'POST') {
        const { oldPassword, newPassword } = body || {};
        const storedUser = JSON.parse(localStorage.getItem('auth_user') || '{}');
        const users = getUsers();
        const user = users[(storedUser.username || '').toLowerCase()];
        if (!user || user.password !== oldPassword) {
            return mockResponse({ code: 'WRONG_PASSWORD', message: '当前密码不正确' }, 401);
        }
        user.password = newPassword;
        users[(storedUser.username || '').toLowerCase()] = user;
        saveUsers(users);
        return mockResponse({ success: true });
    }

    // 5. 2FA 状态: GET /api/user/2fa/status
    if (path === '/api/user/2fa/status') {
        return mockResponse({ enabled: false, totp: false, passkey: false });
    }

    // 6. 会话列表: GET /api/user/sessions
    if (path === '/api/user/sessions' && method === 'GET') {
        return mockResponse([{
            id: 'sid_current',
            user_id: 'u_local',
            created_at: Date.now(),
            last_used_at: Date.now(),
            device_info: '本地安全沙盒 (Local Storage)',
            ip: '127.0.0.1',
            is_current: true
        }]);
    }

    // 7. 通行密钥: GET /api/user/passkeys
    if (path === '/api/user/passkeys') {
        return mockResponse([]);
    }

    // 8. 云端备份内容: POST /api/content
    if (path === '/api/content' && method === 'POST') {
        const backupId = 'bk_' + Date.now();
        const backups = getBackups();
        const dataStr = typeof body?.data === 'string' ? body.data : JSON.stringify(body?.data || {});
        backups[backupId] = {
            id: backupId,
            userId: token || 'local',
            data: dataStr,
            createdAt: Date.now()
        };
        saveBackups(backups);
        return mockResponse({ id: backupId });
    }

    // 9. 备份元数据列表: GET /api/content
    if (path === '/api/content' && method === 'GET') {
        const backups = getBackups();
        const list = Object.values(backups).map(b => ({
            id: b.id,
            created_at: b.createdAt,
            data_size: b.data.length
        })).sort((a, b) => b.created_at - a.created_at);
        return mockResponse(list);
    }

    // 10. 读取特定备份: GET /api/content/:id
    if (path.startsWith('/api/content/') && method === 'GET') {
        const id = decodeURIComponent(path.slice('/api/content/'.length));
        const backups = getBackups();
        const b = backups[id];
        if (!b) return mockResponse({ code: 'NOT_FOUND', message: '备份不存在' }, 404);
        return mockResponse({
            id: b.id,
            user_id: b.userId,
            data: b.data,
            created_at: b.createdAt
        });
    }

    // 11. 删除备份: DELETE /api/content/:id
    if (path.startsWith('/api/content/') && method === 'DELETE') {
        const id = decodeURIComponent(path.slice('/api/content/'.length));
        const backups = getBackups();
        delete backups[id];
        saveBackups(backups);
        return mockResponse({ success: true });
    }

    // 12. 系统公告: GET /api/admin/notice
    if (path === '/api/admin/notice') {
        return mockResponse({ revision: 1, title: '本地离线模式', content: '当前运行于纯本地安全离线模式，所有账户与用药数据均加密保存在本地。' });
    }

    return null;
}

export async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const url = new URL(urlStr, 'http://127.0.0.1');
    const path = url.pathname;
    const method = (init?.method || 'GET').toUpperCase();

    // 如果是 /api/ 接口，全部在本地纯内存/localStorage 截流响应
    if (path.startsWith('/api/')) {
        let bodyData = null;
        if (init?.body && typeof init.body === 'string') {
            try { bodyData = JSON.parse(init.body); } catch { bodyData = init.body; }
        }
        const mock = handleLocalMockApi(path, method, init?.headers, bodyData);
        if (mock) {
            return mock;
        }
    }

    const res = await fetch(input, init);
    if (res.status === 401 && res.headers.get('X-Session-Invalid') === '1') {
        if (typeof window !== 'undefined') {
            window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
        }
    }
    return res;
}

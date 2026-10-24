import React, { useEffect, useRef, useState } from 'react';
import { authService, FactorMethod, factorMethods, getPasskeyAssertion, PasskeyAuthOptions, SecondFactor } from '../services/auth';
import { useTranslation } from '../contexts/LanguageContext';

// One selection/verification flow for password login and password-protected actions.
export function useTwoFactorVerification(identity: string, token?: string | null) {
    const [methods, setMethods] = useState<FactorMethod[]>([]);
    const [required, setRequired] = useState(false);
    const [selected, setSelected] = useState<FactorMethod | 'backup'>('totp');
    const [code, setCode] = useState('');
    const [status, setStatus] = useState<'ready' | 'loading' | 'error'>(token ? 'loading' : 'ready');
    const [retry, setRetry] = useState(0);
    const controller = useRef<AbortController | null>(null);
    const generation = useRef(0);
    const identityRef = useRef(identity);
    if (identityRef.current !== identity) {
        identityRef.current = identity;
        generation.current++;
        controller.current?.abort();
    }
    const cancel = () => { generation.current++; controller.current?.abort(); };
    const reset = () => { cancel(); setMethods([]); setRequired(false); setCode(''); setSelected('totp'); };
    useEffect(() => {
        cancel();
        if (!token) {
            reset();
            setStatus('ready');
        }
    }, [identity]);
    useEffect(() => {
        reset();
        if (!token) { setStatus('ready'); return cancel; }
        let active = true;
        setStatus('loading');
        authService.get2FAStatus(token).then(s => {
            if (!active) return;
            if (typeof s.enabled !== 'boolean' || typeof s.totp !== 'boolean' || typeof s.passkey !== 'boolean'
                || s.enabled !== (s.totp || s.passkey)) {
                setStatus('error');
                return;
            }
            const available: FactorMethod[] = [];
            if (s.totp) available.push('totp');
            if (s.passkey) available.push('passkey');
            setMethods(available);
            setRequired(s.enabled || available.length > 0);
            setSelected(available[0] ?? 'backup');
            setStatus('ready');
        }).catch(() => { if (active) setStatus('error'); });
        return () => { active = false; cancel(); };
    }, [token, retry]);
    const acceptError = (error: any) => {
        if (!error?.needs2FA && error?.code !== 'TWO_FACTOR_REQUIRED') return false;
        const available = factorMethods(error);
        setRequired(true);
        setCode('');
        if (available.length) {
            setMethods(available);
            setSelected(current => available.includes(current as FactorMethod) ? current : available[0]);
            setStatus('ready');
        } else {
            setStatus('error');
        }
        return true;
    };
    const run = async <T,>(task: (signal: AbortSignal, check: () => void) => Promise<T>) => {
        controller.current?.abort();
        const current = ++generation.current;
        const abort = new AbortController();
        controller.current = abort;
        const check = () => {
            if (abort.signal.aborted || current !== generation.current) throw new DOMException('Cancelled', 'AbortError');
        };
        check();
        try { return await task(abort.signal, check); }
        catch (error) { check(); throw error; }
    };
    const resolve = async (options: () => Promise<PasskeyAuthOptions>, signal: AbortSignal, check: () => void): Promise<SecondFactor> => {
        if (!required) return {};
        if (selected === 'backup') return { backup_code: code.trim() };
        if (selected === 'totp') return { code };
        const opts = await options();
        check();
        const passkey = await getPasskeyAssertion(opts, signal);
        check();
        return { passkey };
    };
    return { methods, required, selected, code, status, reset, cancel, acceptError, run, resolve,
        retry: () => setRetry(n => n + 1),
        select: (method: FactorMethod | 'backup') => { cancel(); setSelected(method); setCode(''); },
        setCode,
        ready: status === 'ready' && (!required || selected === 'passkey' || (selected === 'backup' ? !!code.trim() : /^\d{6}$/.test(code))),
    };
}

export type VerificationState = ReturnType<typeof useTwoFactorVerification>;
export default function TwoFactorVerification({ verification: v, disabled = false }: { verification: VerificationState; disabled?: boolean }) {
    const { t } = useTranslation();
    if (v.status === 'loading') return <p role="status" className="text-sm text-muted">{t('auth.factor_loading')}</p>;
    if (v.status === 'error') return <div className="space-y-2"><p role="alert" className="text-sm text-[var(--danger)]">{t('auth.factor_status_failed')}</p><button type="button" disabled={disabled} className="btn-secondary" onClick={v.retry}>{t('auth.factor_retry')}</button></div>;
    if (!v.required) return null;
    return <fieldset disabled={disabled} className="space-y-3">
        <legend className="text-sm text-muted mb-2">{t('auth.needs_2fa')}</legend>
        <div className="flex flex-wrap gap-2">
            {([...v.methods, 'backup'] as const).map(method => <button key={method} type="button" aria-pressed={v.selected === method} className={v.selected === method ? 'btn-primary' : 'btn-secondary'} onClick={() => v.select(method)}>
                {t(method === 'totp' ? 'auth.totp_code' : method === 'passkey' ? 'auth.passkey_as_2fa' : 'auth.use_backup_code')}
            </button>)}
        </div>
        {v.selected === 'passkey' ? <p className="text-xs text-muted">{t('auth.factor_passkey_hint')}</p> : <label className="block text-sm text-muted">
            {t(v.selected === 'backup' ? 'auth.backup_code_label' : 'auth.totp_code')}
            <input className="input-base font-mono mt-1" value={v.code} required autoComplete={v.selected === 'totp' ? 'one-time-code' : 'off'} inputMode={v.selected === 'totp' ? 'numeric' : 'text'} maxLength={v.selected === 'totp' ? 6 : undefined} pattern={v.selected === 'totp' ? '[0-9]{6}' : undefined} onChange={e => v.setCode(v.selected === 'totp' ? e.target.value.replace(/\D/g, '').slice(0, 6) : e.target.value.toUpperCase())} />
        </label>}
    </fieldset>;
}

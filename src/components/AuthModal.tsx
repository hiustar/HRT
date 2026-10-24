import React, { useState } from 'react';
import { X, Loader2, Fingerprint } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useTranslation } from '../contexts/LanguageContext';
import { authService, getPasskeyAssertion } from '../services/auth';
import TwoFactorVerification, { useTwoFactorVerification } from './TwoFactorVerification';

interface AuthModalProps { isOpen: boolean; onClose: () => void }
const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose }) => {
    const [isLogin, setIsLogin] = useState(true);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const verification = useTwoFactorVerification(JSON.stringify([isOpen, isLogin, username, password]));
    const { login, register, loginWithToken } = useAuth();
    const { t } = useTranslation();
    const close = () => { verification.reset(); setPassword(''); setError(null); onClose(); };
    const submit = async (direct = false) => {
        if (loading) return;
        setLoading(true);
        setError(null);
        try {
            await verification.run(async (signal, check) => {
                if (direct) {
                    const options = await authService.passkeyAuthOptions(username || undefined);
                    check();
                    const assertion = await getPasskeyAssertion(options, signal, true);
                    check();
                    const data = await authService.passkeyAuthVerify(assertion.challengeToken, assertion.credential);
                    check();
                    await loginWithToken(data);
                } else if (isLogin) {
                    const factor = await verification.resolve(() => authService.passkeyAuthOptions(username, password, 'login'), signal, check);
                    check();
                    await login(username, password, factor.code, factor.backup_code, factor.passkey);
                } else {
                    check();
                    await register(username, password);
                }
                check();
                close();
            });
        } catch (e: any) {
            if (e.name === 'AbortError') return;
            if (!verification.acceptError(e)) setError(e.name === 'NotAllowedError' ? t('auth.factor_cancelled') : e.message || t('error.generic'));
        } finally { setLoading(false); }
    };
    if (!isOpen) return null;
    return <div className="modal-overlay"><div className="modal-shell"><div className="modal-card overflow-hidden p-0">
        <div className="flex items-center justify-between px-5 pt-5 pb-2">
            <h2 className="modal-title mb-0">{t(isLogin ? 'auth.sign_in' : 'auth.sign_up')}</h2>
            <button onClick={close} aria-label={t('notice.dismiss')} className="p-1 text-muted"><X size={18} /></button>
        </div>
        <form onSubmit={e => { e.preventDefault(); void submit(); }} className="px-5 pb-5 pt-1 space-y-3">
            {error && <p role="alert" className="text-sm text-[var(--danger)]">{error}</p>}
            <label className="block text-sm text-muted">{t('auth.username')}<input required disabled={loading} autoComplete="username" className="input-base mt-1" value={username} onChange={e => { verification.reset(); setUsername(e.target.value); setError(null); }} /></label>
            <label className="block text-sm text-muted">{t('auth.password')}<input required disabled={loading} type="password" autoComplete={isLogin ? 'current-password' : 'new-password'} className="input-base mt-1" value={password} onChange={e => { verification.reset(); setPassword(e.target.value); setError(null); }} /></label>
            {isLogin && <TwoFactorVerification verification={verification} disabled={loading} />}
            <button type="submit" disabled={loading || !verification.ready} className="btn-primary w-full">{loading && <Loader2 size={16} className="animate-spin" />}{t(isLogin ? 'auth.sign_in' : 'auth.sign_up')}</button>
            {isLogin && <button type="button" disabled={loading} onClick={() => void submit(true)} className="btn-secondary w-full"><Fingerprint size={16} />{t('auth.passkey_login')}</button>}
            <div className="pt-2 text-center text-sm text-muted">{t(isLogin ? 'auth.no_account' : 'auth.has_account')}{' '}<button type="button" disabled={loading} onClick={() => { verification.reset(); setIsLogin(!isLogin); setError(null); }} className="text-[var(--accent-ink)]">{t(isLogin ? 'auth.go_register' : 'auth.go_login')}</button></div>
        </form>
    </div></div></div>;
};
export default AuthModal;

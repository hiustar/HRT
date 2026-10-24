import React, { useState } from 'react';
import PageHeader, { PAGE_COLUMN } from '../components/PageHeader';
import { AlertTriangle, Loader2 } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useTranslation } from '../contexts/LanguageContext';
import { authService } from '../services/auth';
import TwoFactorVerification, { useTwoFactorVerification } from '../components/TwoFactorVerification';

const DeleteAccount: React.FC<{ onBack: () => void }> = ({ onBack }) => {
    const { t } = useTranslation();
    const { deleteAccount, token } = useAuth();
    const [password, setPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const verification = useTwoFactorVerification(JSON.stringify([token, password]), token);
    const handleSubmit = async () => {
        if (!token || !password || isLoading || verification.status !== 'ready' || !verification.ready) return;
        setIsLoading(true);
        setError('');
        try {
            await verification.run(async (signal, check) => {
                const factor = await verification.resolve(() => authService.sensitivePasskeyOptions(token, 'delete', password), signal, check);
                check();
                await deleteAccount(password, factor);
                onBack();
            });
        } catch (e: any) {
            if (e.name === 'AbortError') return;
            if (!verification.acceptError(e)) setError(e.name === 'NotAllowedError' ? t('auth.factor_cancelled') : e.message || t('error.generic'));
        } finally { setIsLoading(false); }
    };
    return <div className="relative pb-32">
        <PageHeader onBack={onBack} title={t('account.delete_account')} />
        <div className={`${PAGE_COLUMN} mt-4 space-y-5 [&>*]:max-w-md`}>
            <div className="flex items-start gap-3">
                <span className="icon-line text-sm leading-relaxed"><AlertTriangle size={18} className="text-[var(--danger)]" /></span>
                <div className="space-y-1"><p className="text-sm text-muted leading-relaxed">{t('account.delete_account_desc')}</p><p className="text-sm font-medium text-[var(--danger)] leading-relaxed">{t('account.delete_warning')}</p></div>
            </div>
            {error && <p role="alert" className="text-sm text-[var(--danger)]">{error}</p>}
            <label className="block text-xs font-medium text-muted">{t('account.enter_password_confirm')}
                <input required disabled={isLoading} type="password" autoComplete="current-password" value={password} onChange={e => { setPassword(e.target.value); setError(''); }} className="input-base mt-1.5" autoFocus style={{ fontSize: '16px' }} />
            </label>
            <TwoFactorVerification verification={verification} disabled={isLoading} />
            <button onClick={handleSubmit} disabled={!token || !password || isLoading || verification.status !== 'ready' || !verification.ready} className="btn-danger w-full">
                {isLoading && <Loader2 size={15} className="animate-spin" />}{t('account.delete_account')}
            </button>
        </div>
    </div>;
};
export default DeleteAccount;

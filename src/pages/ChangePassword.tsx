import React, { useState } from 'react';
import PageHeader, { PAGE_COLUMN } from '../components/PageHeader';
import { Lock } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useTranslation } from '../contexts/LanguageContext';
import { settingsMuted, settingsOn } from '../components/SettingsListItem';
import { authService } from '../services/auth';
import TwoFactorVerification, { useTwoFactorVerification } from '../components/TwoFactorVerification';

const ChangePassword: React.FC<{ onBack: () => void }> = ({ onBack }) => {
    const { t } = useTranslation();
    const { changePassword, token } = useAuth();
    const [current, setCurrent] = useState('');
    const [newPass, setNewPass] = useState('');
    const [confirm, setConfirm] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const verification = useTwoFactorVerification(JSON.stringify([token, current]), token);

    const on = settingsOn;
    const muted = settingsMuted;
    const inputCls = `w-full px-4 py-3 text-sm bg-[var(--field)] border border-[var(--border)] rounded-md focus:border-[var(--text)] outline-none ${on} placeholder:text-[var(--text-muted)]`;

    const handleSubmit = async () => {
        if (!token || !current || !newPass || !confirm || isLoading || verification.status !== 'ready' || !verification.ready) return;
        if (newPass !== confirm) { setError(t('pw.mismatch')); return; }
        if (newPass.length < 8) { setError(t('pw.too_short')); return; }

        setIsLoading(true);
        setError('');
        try {
            await verification.run(async (signal, check) => {
                const factor = await verification.resolve(() => authService.sensitivePasskeyOptions(token, 'password', current), signal, check);
                check();
                await changePassword(current, newPass, factor);
                check();
                onBack();
            });
        } catch (e: any) {
            if (e.name === 'AbortError') return;
            if (!verification.acceptError(e)) setError(e.name === 'NotAllowedError' ? t('auth.factor_cancelled') : e.message || t('error.generic'));
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="relative pb-32">
            <PageHeader onBack={onBack} title={t('account.change_password')} />

            <div className={`${PAGE_COLUMN} mt-4 space-y-5 [&>*]:max-w-md`}>
                <div className="flex items-start gap-3">
                    <span className="icon-line text-sm leading-relaxed"><Lock size={18} className={muted} /></span>
                    <p className={`text-sm leading-relaxed ${muted}`}>{t('account.change_password_desc')}</p>
                </div>

                {error && (
                    <p className="text-sm text-[var(--danger)]">{error}</p>
                )}

                <div className="space-y-4">
                    <div>
                        <label htmlFor="change-current-password" className={`block text-xs font-medium mb-1.5 ${muted}`}>{t('account.current_password')}</label>
                        <input id="change-current-password" disabled={isLoading} required type="password" value={current} onChange={e => setCurrent(e.target.value)} className={inputCls} autoFocus />
                    </div>
                    <div>
                        <label htmlFor="change-new-password" className={`block text-xs font-medium mb-1.5 ${muted}`}>{t('account.new_password')}</label>
                        <input id="change-new-password" disabled={isLoading} required type="password" value={newPass} onChange={e => setNewPass(e.target.value)} className={inputCls} />
                    </div>
                    <div>
                        <label htmlFor="change-confirm-password" className={`block text-xs font-medium mb-1.5 ${muted}`}>{t('account.confirm_password')}</label>
                        <input id="change-confirm-password" disabled={isLoading} required type="password" value={confirm} onChange={e => setConfirm(e.target.value)} className={inputCls} />
                    </div>
                </div>

                <TwoFactorVerification verification={verification} disabled={isLoading} />
                <button
                    onClick={handleSubmit}
                    disabled={!token || !current || !newPass || !confirm || isLoading || verification.status !== 'ready' || !verification.ready}
                    className="btn-primary w-full"
                >
                    {isLoading ? '...' : t('btn.save')}
                </button>
            </div>
        </div>
    );
};

export default ChangePassword;

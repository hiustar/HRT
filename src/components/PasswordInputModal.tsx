import { useState, useEffect } from 'react';
import { useTranslation } from '../contexts/LanguageContext';
import { useEscape } from '../hooks/useEscape';

interface PasswordInputModalProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: (pw: string, code?: string) => void;
    title?: string;
    description?: string;
    error?: string | null;
    loading?: boolean;
    /** Mask the input as a password field (defaults to the legacy visible text). */
    masked?: boolean;
    requireCode?: boolean;
}

const PasswordInputModal = ({ isOpen, onClose, onConfirm, title, description, error, loading, masked, requireCode = false }: PasswordInputModalProps) => {
    const { t } = useTranslation();
    const [password, setPassword] = useState("");
    const [code, setCode] = useState("");

    useEscape(onClose, isOpen);

    useEffect(() => {
        if (isOpen) {
            setPassword("");
            setCode("");
        }
    }, [isOpen]);

    if (!isOpen) return null;

    const canSubmit = !!password && !loading && (!requireCode || code.length === 6);
    const submit = () => { if (canSubmit) onConfirm(password, requireCode ? code : undefined); };

    return (
        <div className="modal-overlay z-[60] p-4">
            <div className="modal-shell">
                <div className="modal-card">
                    <h3 className="modal-title text-center">{title ?? t('import.password_title')}</h3>
                    <p className="text-xs text-muted mb-4 text-center leading-relaxed">{description ?? t('import.password_desc')}</p>

                    <input
                        type={masked ? 'password' : 'text'}
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') submit(); }}
                        className="input-base font-mono text-center mb-2"
                        style={{ fontSize: '16px' }}
                        placeholder={t('auth.password')}
                        autoComplete="current-password"
                        autoFocus
                    />

                    {requireCode && (
                        <label className="block text-xs text-muted mb-2">
                            {t('account.2fa_code')}
                            <input
                                type="text"
                                inputMode="numeric"
                                pattern="[0-9]{6}"
                                maxLength={6}
                                value={code}
                                onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                onKeyDown={e => { if (e.key === 'Enter') submit(); }}
                                className="input-base font-mono text-center mt-1"
                                style={{ fontSize: '16px' }}
                                autoComplete="one-time-code"
                            />
                        </label>
                    )}

                    {error && (
                        <p className="text-xs text-[var(--danger)] mb-2 text-center">{error}</p>
                    )}

                    <div className="flex gap-2 mt-2">
                        <button onClick={onClose} className="btn-secondary flex-1">{t('btn.cancel')}</button>
                        <button
                            onClick={submit}
                            disabled={!canSubmit}
                            className="btn-primary flex-1"
                        >
                            {t('btn.ok')}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PasswordInputModal;

import { formatRelative } from '../utils/helpers';
import React, { useEffect, useRef, useState, useCallback } from 'react';
import { RefreshCw } from 'lucide-react';
import PageHeader, { PAGE_COLUMN } from '../components/PageHeader';

import { useTranslation } from '../contexts/LanguageContext';

interface TransparencyStats {
    total_users: number;
    total_backups: number;
    new_users_24h: number;
    new_users_7d: number;
    admin_deleted_count: number;
    self_deleted_count: number;
    admin_deleted_7d: number;
    self_deleted_7d: number;
    recent_registrations: { anon_id: string; created_at: number }[];
    server_time: number;
}

const REFRESH_INTERVAL_MS = 30_000;

const COUNT_KEYS = ['total_users', 'total_backups', 'new_users_24h', 'new_users_7d',
    'admin_deleted_count', 'self_deleted_count', 'admin_deleted_7d', 'self_deleted_7d'] as const;

function isTransparencyStats(value: unknown): value is TransparencyStats {
    if (value === null || typeof value !== 'object') return false;
    const data = value as Record<string, unknown>;
    return COUNT_KEYS.every(key => typeof data[key] === 'number' && Number.isSafeInteger(data[key]) && (data[key] as number) >= 0)
        && typeof data.server_time === 'number' && Number.isFinite(data.server_time)
        && Array.isArray(data.recent_registrations)
        && data.recent_registrations.every(r => r && typeof r.anon_id === 'string'
            && /^[a-f0-9]{4}$/.test(r.anon_id)
            && typeof r.created_at === 'number' && Number.isFinite(r.created_at));
}

const displayCount = (value: number | undefined) => value === undefined ? '—' : value.toLocaleString();

const rowBase = "flex items-baseline justify-between py-[18px] border-b border-[var(--border)]";

interface TransparencySettingsProps {
    onBack: () => void;
}

const TransparencySettings: React.FC<TransparencySettingsProps> = ({ onBack }) => {
    const { t } = useTranslation();
    const [stats, setStats] = useState<TransparencyStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [lastUpdated, setLastUpdated] = useState<number | null>(null);
    const timerRef = useRef<number | null>(null);

    const load = useCallback(async (signal?: AbortSignal) => {
        setLoading(true);
        setError(null);
        try {
            const res = await fetch('/api/transparency', { signal, cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data: unknown = await res.json();
            if (!isTransparencyStats(data)) throw new Error('Invalid transparency response');
            setStats(data);
            setLastUpdated(Date.now());
        } catch (e: any) {
            if (e.name === 'AbortError') return;
            setError(t('transparency.load_error'));
        } finally {
            setLoading(false);
        }
    }, [t]);

    useEffect(() => {
        const ctrl = new AbortController();
        load(ctrl.signal);
        timerRef.current = window.setInterval(() => load(ctrl.signal), REFRESH_INTERVAL_MS);
        return () => {
            ctrl.abort();
            if (timerRef.current) window.clearInterval(timerRef.current);
        };
    }, [load]);

    const now = stats?.server_time ?? Math.floor(Date.now() / 1000);

    return (
        <div className="pb-32">
            {/* Header */}
            <PageHeader onBack={onBack} title={t('transparency.title')} />

            <div className={PAGE_COLUMN}>
                <p className="mt-3 text-sm leading-relaxed text-[var(--text-muted)]">{t('transparency.intro')}</p>
                <div className="my-4 flex items-center justify-between gap-3">
                    <p role="status" className="text-xs text-[var(--text-muted)]">
                        {lastUpdated
                            ? t('transparency.last_updated').replace('{t}', new Date(lastUpdated).toLocaleTimeString())
                            : loading ? t('transparency.loading') : '—'}
                    </p>
                    <button type="button" onClick={() => load()} disabled={loading}
                        className="flex min-h-11 items-center gap-2 rounded-[var(--radius-md)] px-3 text-sm text-[var(--text-muted)] hover:bg-[var(--surface-hover)] hover:text-[var(--text)] disabled:opacity-50">
                        <RefreshCw size={15} className={loading ? 'animate-spin motion-reduce:animate-none' : ''} />
                        {t('transparency.refresh')}
                    </button>
                </div>
                {error && (
                    <p role="alert" className="mb-4 text-sm text-[var(--danger)]">
                        {error}
                    </p>
                )}

                {/* Stats */}
                <div aria-busy={loading}>
                    <div className={rowBase}>
                        <span className="text-[0.9375rem] text-[var(--text)]">
                            {t('transparency.stat.total_users')}
                        </span>
                        <span className="text-2xl font-semibold text-[var(--text)] tabular-nums">
                            {displayCount(stats?.total_users)}
                        </span>
                    </div>

                    <div className={rowBase}>
                        <span className="text-[0.9375rem] text-[var(--text)]">
                            {t('transparency.stat.total_backups')}
                        </span>
                        <span className="text-2xl font-semibold text-[var(--text)] tabular-nums">
                            {displayCount(stats?.total_backups)}
                        </span>
                    </div>

                    <div className={rowBase}>
                        <div>
                            <p className="text-[0.9375rem] text-[var(--text)]">
                                {t('transparency.stat.new_users_24h')}
                            </p>
                            <p className="text-xs text-[var(--text-muted)] mt-0.5">
                                {t('transparency.stat.new_users_7d').replace('{n}', displayCount(stats?.new_users_7d))}
                            </p>
                        </div>
                        <span className="text-2xl font-semibold text-[var(--text)] tabular-nums">
                            {displayCount(stats?.new_users_24h)}
                        </span>
                    </div>

                    <div className={rowBase}>
                        <div>
                            <p className="text-[0.9375rem] text-[var(--text)]">
                                {t('transparency.stat.self_deleted')}
                            </p>
                            <p className="text-xs text-[var(--text-muted)] mt-0.5">
                                {t('transparency.stat.delta_7d').replace('{n}', displayCount(stats?.self_deleted_7d))}
                            </p>
                        </div>
                        <span className="text-2xl font-semibold text-[var(--text)] tabular-nums">
                            {displayCount(stats?.self_deleted_count)}
                        </span>
                    </div>

                    <div className={`${rowBase} border-b-0`}>
                        <div>
                            <p className="text-[0.9375rem] text-[var(--text)]">
                                {t('transparency.stat.admin_deleted')}
                            </p>
                            <p className="text-xs text-[var(--text-muted)] mt-0.5">
                                {t('transparency.stat.delta_7d').replace('{n}', displayCount(stats?.admin_deleted_7d))}
                            </p>
                        </div>
                        <span className="text-2xl font-semibold text-[var(--text)] tabular-nums">
                            {displayCount(stats?.admin_deleted_count)}
                        </span>
                    </div>
                </div>

                {/* Recent registrations */}
                <h2 className="text-xl font-semibold text-[var(--text)] mt-10 mb-6">
                    {t('transparency.recent.title')}
                </h2>

                <div className="divide-y divide-[var(--border)]">
                    {!stats ? (
                        <p className="py-6 text-sm text-center text-[var(--text-muted)]">
                            {loading ? t('transparency.loading') : '—'}
                        </p>
                    ) : stats.recent_registrations.length === 0 ? (
                        <p className="py-6 text-sm text-center text-[var(--text-muted)]">
                            {t('transparency.recent.empty')}
                        </p>
                    ) : (
                        (stats?.recent_registrations ?? []).map((r, idx) => (
                            <div key={`${r.anon_id}-${r.created_at}-${idx}`} className="flex items-center justify-between py-3">
                                <span className="font-mono text-sm text-[var(--text)]">
                                    user_{r.anon_id}***
                                </span>
                                <span className="text-xs text-[var(--text-muted)] tabular-nums">
                                    {formatRelative(r.created_at, now, t)}
                                </span>
                            </div>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
};

export default TransparencySettings;

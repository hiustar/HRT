import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { JSDOM } from 'jsdom';
import React from 'react';

const root = fileURLToPath(new URL('../', import.meta.url));
const tmp = await mkdtemp(join(root, '.venv', 'sl-settings-'));
const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost/' });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: dom.window.navigator });
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
globalThis.__slMode = 'transfem';
const { render, fireEvent, cleanup, waitFor } = await import('@testing-library/react');
await build({
    stdin: { contents: `export { default as Settings } from './src/pages/Settings';
        export { default as PKParamsPage } from './src/pages/PKParams';
        export { default as Forecast } from './src/pages/Forecast';
        export * from './logic'; export { TRANSLATIONS } from './src/i18n/translations';`,
        resolveDir: root, loader: 'tsx' },
    outfile: join(tmp, 'settings.mjs'), bundle: true, packages: 'external',
    platform: 'node', format: 'esm', jsx: 'automatic',
    plugins: [{ name: 'test-settings-contexts', setup(b) {
        b.onResolve({ filter: /(HRTModeContext|PixelCatContext|LanguageContext|DialogContext)$/ }, args => ({ path: args.path, namespace: 'context' }));
        b.onLoad({ filter: /.*/, namespace: 'context' }, args => ({ contents: args.path.endsWith('HRTModeContext')
            ? `export const useHRTMode = () => ({mode: globalThis.__slMode, isTransmasc: globalThis.__slMode === 'transmasc'});`
            : args.path.endsWith('LanguageContext') ? `export const useTranslation = () => ({t: globalThis.__slT, lang: 'zh'});`
            : args.path.endsWith('DialogContext') ? `export const useDialog = () => ({showDialog: (type, message, confirm) => confirm?.()});`
            : `export const usePixelCats = () => ({showCats: false, setShowCats() {}, catStyle: 'flag', setCatStyle() {}});` }));
        b.onResolve({ filter: /utils\/regimen$/ }, args => args.importer.endsWith('Forecast.tsx')
            ? { path: 'forecast-calculations', namespace: 'forecast-test' } : undefined);
        b.onResolve({ filter: /components\/ForecastChart$/ }, () => ({ path: 'forecast-chart', namespace: 'forecast-test' }));
        b.onLoad({ filter: /.*/, namespace: 'forecast-test' }, args => ({ contents: args.path === 'forecast-chart'
            ? `export default () => null;`
            : `export const forecastCurrent = () => { globalThis.__forecastCalls.current++; return null; };
               export const forecastPlan = () => { globalThis.__forecastCalls.plan++; return null; };
               export const adherenceOf = () => ({missRate: 0, jitterSdH: 0});` }));
    } }],
});
const { Settings, PKParamsPage, Forecast, DEFAULT_PK_PARAMS, TRANSLATIONS } = await import(pathToFileURL(join(tmp, 'settings.mjs')));
const t = key => TRANSLATIONS.zh[key] ?? key;
globalThis.__slT = t;
after(async () => { cleanup(); dom.window.close(); await rm(tmp, { recursive: true, force: true }); });

function props(extra = {}) {
    return { t, lang: 'zh', theme: 'light', languageOptions: [], events: [], weight: 70,
        pkParams: null, supplyCount: 0, ...extra };
}

test('settings offers exactly three models between weight and parameter editing', () => {
    const initial = { ...DEFAULT_PK_PARAMS, e2_kClear: 0.6 };
    let selected = initial;
    const view = render(React.createElement(Settings, props({ pkParams: initial,
        onSublingualModelChange: value => { selected = { ...DEFAULT_PK_PARAMS, ...selected, sublingualModel: value }; },
    })));
    const group = view.getByRole('radiogroup', { name: t('settings.sublingual_model') });
    assert.deepEqual(view.getAllByRole('radio').map(o => o.value), ['legacy', 'new', 'metabolite']);
    assert.equal(view.getByRole('radio', { checked: true }).value, 'metabolite');
    const weight = view.getByRole('button', { name: /体重.*70 kg/ });
    const params = view.getByRole('button', { name: /编辑参数/ });
    assert.ok(weight.compareDocumentPosition(group) & dom.window.Node.DOCUMENT_POSITION_FOLLOWING);
    assert.ok(group.compareDocumentPosition(params) & dom.window.Node.DOCUMENT_POSITION_FOLLOWING);
    for (const value of ['legacy', 'new', 'metabolite']) {
        fireEvent.click(view.getByRole('radio', { name: t(`settings.sublingual_model.${value}`) }));
        assert.equal(selected.sublingualModel, value);
        assert.equal(selected.e2_kClear, 0.6);
        view.rerender(React.createElement(Settings, props({ pkParams: selected,
            onSublingualModelChange: v => { selected = { ...selected, sublingualModel: v }; },
        })));
        assert.equal(view.getByRole('radio', { checked: true }).value, value);
    }
    cleanup();
});

test('transmasc settings omit the estradiol sublingual model control', () => {
    globalThis.__slMode = 'transmasc';
    const view = render(React.createElement(Settings, props()));
    assert.equal(view.queryByRole('radiogroup', { name: t('settings.sublingual_model') }), null);
    cleanup(); globalThis.__slMode = 'transfem';
});

test('every language supplies the complete model selector without legacy route names', () => {
    assert.equal(TRANSLATIONS.tr['settings.sublingual_model'], 'Dil altı modeli');
    for (const [lang, pack] of Object.entries(TRANSLATIONS)) {
        for (const key of ['settings.sublingual_model', 'settings.sublingual_model_desc',
            ...['legacy', 'new', 'metabolite'].map(m => `settings.sublingual_model.${m}`)]) {
            assert.ok(pack[key]?.length > 1, `${lang}: missing ${key}`);
        }
        if (pack['route.sublingualNew']) assert.equal(pack['route.sublingualNew'], pack['route.sublingual']);
    }
});

test('saving numeric edits preserves a model changed by sync while the editor is open', () => {
    let saved;
    const base = { onBack() {}, onReset() {}, onSave: params => { saved = params; } };
    const view = render(React.createElement(PKParamsPage, { ...base,
        pkParams: { ...DEFAULT_PK_PARAMS, sublingualModel: 'legacy', e2_kClear: 0.6 } }));
    view.rerender(React.createElement(PKParamsPage, { ...base,
        pkParams: { ...DEFAULT_PK_PARAMS, sublingualModel: 'new' } }));
    fireEvent.click(view.getByRole('button', { name: t('btn.save') }));
    assert.equal(saved.sublingualModel, 'new');
    assert.equal(saved.e2_kClear, 0.6, 'numeric draft must survive the incoming model change');
    cleanup();
});

test('a cloud-synced model change invalidates the current and scenario forecast caches', async () => {
    globalThis.__forecastCalls = { current: 0, plan: 0 };
    const base = { onBack() {}, events: [], weight: 70, labResults: [], regimens: [],
        calibration: { scale: 1, halfLifeDeltaPct: 0, fitErrPct: null }, calibrationMethod: 'hybrid',
        calibrationHistoryMode: 'retrospective', nowH: 498000, isDarkMode: false, onSaveTemplate() {} };
    const view = render(React.createElement(Forecast, { ...base,
        pkParams: { ...DEFAULT_PK_PARAMS, sublingualModel: 'legacy' } }));
    await waitFor(() => assert.equal(globalThis.__forecastCalls.plan, 1));
    assert.equal(globalThis.__forecastCalls.current, 1);
    view.rerender(React.createElement(Forecast, { ...base,
        pkParams: { ...DEFAULT_PK_PARAMS, sublingualModel: 'metabolite' } }));
    await waitFor(() => assert.equal(globalThis.__forecastCalls.plan, 2));
    assert.equal(globalThis.__forecastCalls.current, 2);
    cleanup();
});

test('worker accepts historical sublingual shares and persists only the canonical route', async () => {
    const source = await readFile(join(root, 'worker.ts'), 'utf8');
    // Bundle the actual validator with dead-code elimination; no server/database
    // mocks can mask a rejection of an existing client's historical route name.
    await build({ stdin: { contents: `${source}\nexport { sanitizeShareSnapshot };`, resolveDir: root, loader: 'ts' },
        outfile: join(tmp, 'worker.mjs'), bundle: true, packages: 'external', platform: 'node', format: 'esm' });
    const { sanitizeShareSnapshot } = await import(pathToFileURL(join(tmp, 'worker.mjs')));
    const event = { id: 'old-share', route: 'sublingualNew', ester: 'E2', doseMG: 1,
        timeH: 498000, extras: { sublingualTheta: 0.11 } };
    const raw = { version: 1, mode: 'transfem', timezone: 'Asia/Hong_Kong', createdAt: 123456,
        events: [event], simulation: null };
    const result = sanitizeShareSnapshot(raw);
    assert.equal(result.error, undefined);
    assert.deepEqual(result.snapshot.events, [{ ...event, route: 'sublingual' }]);
    assert.equal(raw.events[0].route, 'sublingualNew');
    assert.deepEqual(sanitizeShareSnapshot(result.snapshot).snapshot, result.snapshot);
    assert.match(sanitizeShareSnapshot({ ...raw, events: [{ ...event, route: 'unknown-route' }] }).error, /route/);
});

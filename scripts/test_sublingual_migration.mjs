import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import { build } from 'esbuild';
import { JSDOM } from 'jsdom';
import Module from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost/' });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.localStorage = dom.window.localStorage;
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: dom.window.navigator });
globalThis.HTMLElement = dom.window.HTMLElement;
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const aliases = {
    AuthContext: `export const useAuth = () => ({ user: null });`,
    HRTModeContext: `export const useHRTMode = () => ({ mode: globalThis.__testMode || 'transfem', isTransmasc: globalThis.__testMode === 'transmasc' });`,
    LanguageContext: `export const useTranslation = () => ({ t: key => key, lang: 'en' });`,
};
const compiled = await build({
    stdin: { contents: `export * from './src/hooks/useAppData'; export * from './src/utils/syncMerge'; export * from './src/utils/plan'; export * from './src/utils/regimen'; export * from './src/services/shareSnapshot'; export * from './logic';`, resolveDir: root, loader: 'ts' },
    bundle: true, write: false, format: 'cjs', platform: 'node', packages: 'external',
    plugins: [{ name: 'test-contexts', setup(b) {
        b.onResolve({ filter: /contexts\/(AuthContext|HRTModeContext|LanguageContext)$/ }, args => ({ path: args.path.split('/').at(-1), namespace: 'test-context' }));
        b.onLoad({ filter: /.*/, namespace: 'test-context' }, args => ({ contents: aliases[args.path], loader: 'js' }));
    } }],
});
const mod = new Module(path.join(root, 'test-migration.cjs'));
mod.filename = path.join(root, 'test-migration.cjs');
mod.paths = Module._nodeModulePaths(root);
mod._compile(compiled.outputFiles[0].text, mod.filename);
const { useAppData, normalizeSyncState, readModePayloadBlock, mergeSyncStates, fingerprintState, normalizePlanItem, normalizeSupply, normalizeSublingualRecord, buildSharedDosageSnapshot, DEFAULT_PK_PARAMS } = mod.exports;
const { renderHook, act, cleanup } = await import('@testing-library/react');
after(() => { cleanup(); dom.window.close(); });
const route = 'sublingualNew';
const nowH = Date.now() / 3600000;
const event = { id: 'event-1', route, ester: 'E2', timeH: nowH, doseMG: 2, extras: { sublingualTheta: 0.4, future: 7 }, updatedAt: 12345, futureField: { keep: true } };
const template = { id: 'template-1', name: 'test', route, ester: 'E2', doseMG: 2, extras: { sublingualTier: 2, future: 8 }, createdAt: 42, updatedAt: 23456 };
const quick = { id: 'quick-1', route, ester: 'E2', value: 2, createdAt: 55 };
const plan = { id: 'plan-1', route, ester: 'E2', doseMG: 2, extras: { future: 9 }, everyDays: 1, timesPerDay: 1, updatedAt: 333 };
const supply = { id: 'supply-1', route, ester: 'E2', pack: { kind: 'pill', mg: 2 }, count: 10, startedAt: 100, updatedAt: 444, future: true };
const block = { events: [event], doseTemplates: [template], labResults: [], plan: [plan], supplies: [supply] };
const payload = { mode: 'transfem', modes: { transfem: block, transmasc: block } };
const canonical = value => ({ ...value, route: 'sublingual' });
const put = (key, value) => localStorage.setItem(key, JSON.stringify(value));

test('local loads, canonical persistence, exports, imports and repeated sync preserve records', () => {
    localStorage.clear();
    put('hrt-events', [event]); put('hrt-dose-templates', [template]); put('hrt-quick-doses', [quick]);
    put('hrt-plan', [plan]); put('hrt-supplies', [supply]);
    put('hrt-masc-events', [event]); put('hrt-masc-dose-templates', [template]); put('hrt-masc-plan', [plan]); put('hrt-masc-supplies', [supply]);
    put('hrt-pk-params', { ...DEFAULT_PK_PARAMS, sublingualModel: 'legacy', e2_kClear: 0.03 });
    const { result, unmount } = renderHook(() => useAppData(() => {}));
    assert.deepEqual(result.current.events[0], canonical(event));
    assert.deepEqual(result.current.doseTemplates[0], canonical(template));
    assert.deepEqual(result.current.quickDoses[0], canonical(quick));
    assert.deepEqual(result.current.plan[0], canonical(plan));
    assert.deepEqual(result.current.supplies[0], canonical(supply));
    assert.deepEqual(JSON.parse(localStorage.getItem('hrt-events'))[0], canonical(event));
    let out = result.current.buildExportPayload();
    assert.deepEqual(out.modes.transmasc.events[0], canonical(event));
    assert.deepEqual(out.modes.transmasc.doseTemplates[0], canonical(template));
    assert.deepEqual(out.modes.transmasc.plan[0], canonical(plan));
    assert.deepEqual(out.modes.transmasc.supplies[0], canonical(supply));
    act(() => { assert.equal(result.current.mergeImportedData(payload), true); });
    act(() => { assert.equal(result.current.mergeImportedData(payload), true); });
    assert.equal(result.current.events.length, 1);
    assert.equal(result.current.doseTemplates.length, 1);
    assert.equal(result.current.plan.length, 1);
    assert.equal(result.current.supplies.length, 1);
    assert.deepEqual(result.current.events[0], canonical(event));
    const duplicated = { ...payload, modes: { ...payload.modes, transfem: { ...block, events: [event, event], doseTemplates: [template, template] } } };
    act(() => { assert.equal(result.current.processImportedData(duplicated), true); });
    assert.equal(result.current.events.length, 1);
    assert.equal(result.current.doseTemplates.length, 1);
    assert.deepEqual(result.current.events[0], canonical(event));
    assert.deepEqual(result.current.doseTemplates[0], canonical(template));
    assert.deepEqual(JSON.parse(localStorage.getItem('hrt-masc-plan'))[0], canonical(plan));
    const local = normalizeSyncState(result.current.buildExportPayload());
    const remote = normalizeSyncState(payload);
    const merged = mergeSyncStates(local, remote);
    act(() => result.current.applySyncedState(merged.merged));
    act(() => result.current.applySyncedState(mergeSyncStates(normalizeSyncState(result.current.buildExportPayload()), remote).merged));
    assert.equal(result.current.events.length, 1);
    assert.deepEqual(result.current.events[0], canonical(event));
    assert.deepEqual(result.current.doseTemplates[0], canonical(template));
    act(() => result.current.clearPkParams());
    assert.equal(result.current.pkParams.sublingualModel, 'legacy');
    assert.equal(result.current.pkParams.e2_kClear, DEFAULT_PK_PARAMS.e2_kClear);
    unmount();
});

test('alias normalization is nonmutating, preserves metadata and converges fingerprints', () => {
    assert.equal(normalizeSublingualRecord(canonical(event)).route, 'sublingual');
    const unchanged = { route: 'unknown', extras: { arbitrary: 1 } };
    assert.equal(normalizeSublingualRecord(unchanged), unchanged);
    assert.deepEqual(normalizePlanItem(plan), canonical(plan));
    assert.deepEqual(normalizeSupply(supply), canonical(supply));
    const old = normalizeSyncState(payload);
    const modern = normalizeSyncState(JSON.parse(JSON.stringify(old)));
    assert.equal(fingerprintState(old), fingerprintState(modern));
    const merged = mergeSyncStates(old, modern);
    assert.equal(merged.stats.added, 0);
    assert.equal(merged.stats.updated, 0);
    assert.equal(merged.merged.modes.transfem.events.length, 1);
    assert.deepEqual(merged.merged.modes.transfem.events[0], canonical(event));
    assert.equal(event.route, route);
    const rewrite = mergeSyncStates(modern, old);
    assert.equal(rewrite.remoteStale, true, 'latest cloud snapshot gets one canonical rewrite');
    assert.equal(rewrite.localChanged, false);
    assert.equal(mergeSyncStates(rewrite.merged, normalizeSyncState(rewrite.merged)).remoteStale, false,
        'canonical cloud rewrite must converge without repeated uploads');
    const shared = buildSharedDosageSnapshot({ mode: 'transfem', events: [event], simulation: null, calibrationFn: () => 1 });
    assert.equal(shared.events[0].route, 'sublingual');
    assert.notEqual(shared.events[0].id, event.id); // sharing deliberately uses ephemeral IDs
    assert.deepEqual(shared.events[0].extras, event.extras);
});

test('plan and supplies only imports restore either mode', () => {
    localStorage.clear();
    const { result, unmount } = renderHook(() => useAppData(() => {}));
    act(() => assert.equal(result.current.processImportedData({ modes: { transfem: { plan: [plan], supplies: [supply] }, transmasc: { plan: [plan], supplies: [supply] } } }), true));
    assert.deepEqual(result.current.plan[0], canonical(plan));
    assert.deepEqual(JSON.parse(localStorage.getItem('hrt-masc-supplies'))[0], canonical(supply));
    unmount();
});

test('flat historical imports preserve distinct IDs and model backup restores defaults explicitly', () => {
    localStorage.clear();
    const { result, unmount } = renderHook(() => useAppData(() => {}));
    const sameDose = { ...event, id: 'a-different-real-record', route: 'sublingual' };
    const flat = [event, canonical(event), sameDose];
    act(() => assert.equal(result.current.processImportedData(flat), true));
    assert.deepEqual(result.current.events.map(e => e.id), [event.id, sameDose.id]);
    assert.ok(result.current.events.every(e => e.route === 'sublingual'));
    act(() => result.current.mergeImportedData(flat));
    assert.equal(result.current.events.length, 2);
    for (const sublingualModel of ['legacy', 'new', 'metabolite']) {
        act(() => result.current.setPkParams({ ...DEFAULT_PK_PARAMS, sublingualModel, e2_kClear: 0.6 }));
        const backup = JSON.parse(JSON.stringify(result.current.buildExportPayload()));
        act(() => result.current.setPkParams({ ...DEFAULT_PK_PARAMS, sublingualModel: 'legacy' }));
        act(() => assert.equal(result.current.processImportedData(backup), true));
        assert.equal(result.current.pkParams.sublingualModel, sublingualModel);
        assert.equal(result.current.pkParams.e2_kClear, 0.6);
    }
    act(() => assert.equal(result.current.processImportedData({ pkParams: null }), true));
    assert.equal(result.current.pkParams, null);
    assert.equal(result.current.events.length, 2, 'a params-only restore cannot remove doses');
    unmount();
});

test('same-ID alias conflicts preserve the newest content and unknown metadata in either order', () => {
    const newer = { ...canonical(event), updatedAt: event.updatedAt + 100, futureField: { keep: true, new: 42 } };
    const oldState = normalizeSyncState({ events: [event] });
    const newState = normalizeSyncState({ events: [newer] });
    for (const [a, b] of [[oldState, newState], [newState, oldState]]) {
        assert.deepEqual(mergeSyncStates(a, b).merged.modes.transfem.events, [newer]);
    }
    assert.notEqual(fingerprintState(oldState), fingerprintState(newState));
    localStorage.clear();
    const { result, unmount } = renderHook(() => useAppData(() => {}));
    for (const records of [[event, newer], [newer, event]]) {
        act(() => assert.equal(result.current.processImportedData(records), true));
        assert.deepEqual(result.current.events, [newer]);
    }
    unmount();
});


test('v2 fields are authoritative, with missing-field mirrors only for declared mode', () => {
    const mirrorEvent = { ...event, id: 'mirror-event' };
    const mirrorPlan = { ...plan, id: 'mirror-plan' };
    const input = { mode: 'transmasc', events: [mirrorEvent], doseTemplates: [template], plan: [mirrorPlan], supplies: [supply],
        modes: { transfem: { plan: [plan], supplies: [] }, transmasc: { events: [], plan: [plan] } } };
    const masc = readModePayloadBlock(input, 'transmasc');
    assert.deepEqual(masc.events, []); // explicit empty beats nonempty top mirror
    assert.deepEqual(masc.doseTemplates, [template]); // missing field falls back
    assert.deepEqual(masc.plan, [plan]); // block beats conflicting mirror
    assert.deepEqual(readModePayloadBlock(input, 'transfem').supplies, []);
    assert.equal(readModePayloadBlock(input, 'transfem').events, undefined);
    const state = normalizeSyncState(input);
    assert.deepEqual(state.modes.transmasc.events, []);
    assert.deepEqual(state.modes.transmasc.doseTemplates, [canonical(template)]);
    assert.deepEqual(state.modes.transmasc.plan, [canonical(plan)]);
    assert.deepEqual(state.modes.transfem.plan, [canonical(plan)]);
    assert.equal(state.modes.transfem.events.length, 0);
    const missing = normalizeSyncState({ mode: 'transmasc', modes: {}, events: [mirrorEvent], plan: [mirrorPlan] });
    assert.deepEqual(missing.modes.transmasc.events, [canonical(mirrorEvent)]);
    assert.deepEqual(missing.modes.transmasc.plan, [canonical(mirrorPlan)]);
    assert.deepEqual(missing.modes.transfem.events, []);
    const undeclared = normalizeSyncState({ modes: {}, events: [mirrorEvent] });
    assert.deepEqual(undeclared.modes.transfem.events, []);
    assert.deepEqual(undeclared.modes.transmasc.events, []);
});

test('replace and merge imports do not use another mode top-level mirrors', () => {
    for (const method of ['processImportedData', 'mergeImportedData']) {
        for (const active of ['transfem', 'transmasc']) {
            localStorage.clear();
            globalThis.__testMode = active;
            const other = active === 'transfem' ? 'transmasc' : 'transfem';
            const activePlan = { ...plan, id: 'active-plan' };
            const otherPlan = { ...plan, id: 'other-plan' };
            const activeSupply = { ...supply, id: 'active-supply' };
            const otherSupply = { ...supply, id: 'other-supply' };
            const input = { mode: other, plan: [otherPlan], supplies: [otherSupply], events: [event],
                modes: { [active]: { plan: [activePlan], supplies: [activeSupply] }, [other]: { plan: [otherPlan], supplies: [otherSupply] } } };
            const { result, unmount } = renderHook(() => useAppData(() => {}));
            act(() => assert.equal(result.current[method](input), true));
            assert.deepEqual(result.current.plan, [canonical(activePlan)]);
            assert.deepEqual(result.current.supplies, [canonical(activeSupply)]);
            assert.deepEqual(result.current.events, []);
            const otherKey = other === 'transmasc' ? 'hrt-masc-events' : 'hrt-events';
            assert.deepEqual(JSON.parse(localStorage.getItem(otherKey)), [canonical(event)]);
            unmount();
        }
    }
    globalThis.__testMode = 'transfem';
});

test('import missing active block falls back to declared mirrors and honors explicit empty fields', () => {
    for (const method of ['processImportedData', 'mergeImportedData']) {
        localStorage.clear();
        globalThis.__testMode = 'transfem';
        const { result, unmount } = renderHook(() => useAppData(() => {}));
        const input = { mode: 'transfem', modes: {}, events: [event], doseTemplates: [template], plan: [plan], supplies: [supply] };
        act(() => assert.equal(result.current[method](input), true));
        assert.deepEqual(result.current.events, [canonical(event)]);
        assert.deepEqual(result.current.doseTemplates, [canonical(template)]);
        assert.deepEqual(result.current.plan, [canonical(plan)]);
        assert.deepEqual(result.current.supplies, [canonical(supply)]);
        unmount();
    }
    localStorage.clear();
    const { result, unmount } = renderHook(() => useAppData(() => {}));
    const input = { mode: 'transfem', events: [event], plan: [plan], modes: { transfem: { events: [], plan: [] } } };
    act(() => assert.equal(result.current.processImportedData(input), true));
    assert.deepEqual(result.current.events, []);
    assert.deepEqual(result.current.plan, []);
    unmount();
});


test('replace import honors an explicit empty events block without falling back to mirrors', () => {
    localStorage.clear();
    globalThis.__testMode = 'transfem';
    put('hrt-events', [event]);
    const { result, unmount } = renderHook(() => useAppData(() => {}));
    act(() => assert.equal(result.current.processImportedData({ mode: 'transfem', events: [event], modes: { transfem: { events: [] } } }), true));
    assert.deepEqual(result.current.events, []);
    unmount();
});

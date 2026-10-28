import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build, transform } from 'esbuild';

const root = fileURLToPath(new URL('../', import.meta.url));
async function load(source, extra = '') {
    const result = await build({ stdin: { contents: source + extra, resolveDir: root, loader: 'ts' },
        bundle: true, write: false, format: 'esm', platform: 'node', target: 'es2022' });
    return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString('base64')}`);
}
const source = await readFile(new URL('../logic.ts', import.meta.url), 'utf8');
const pk = await load(source, `\nexport { PrecomputedEventModel, resolveParams, computeMaxLifetimeH };
export * from './src/pk/estradiolMetabolites';`);
const { Route, Ester, ExtraKey, DEFAULT_PK_PARAMS, SL_TIER_ORDER, SublingualTierParams,
    applyPKOverrides, getBioavailabilityMultiplier, getToE2Factor, getActivePKParams, sanitizePKParams,
    PrecomputedEventModel, resolveParams, computeMaxLifetimeH, runSimulation, runSimulationWithParams,
    getEstrogenMetaboliteProfile: profile, swallowedEstrogenInput, estrogenAbsorptionKernel } = pk;
const start = Date.UTC(2026, 9, 27, 4) / 3_600_000;
const realNow = Date.now;
Date.now = () => start * 3_600_000;
after(() => { Date.now = realNow; applyPKOverrides(null); });
const at = [0, 1 / 60, 0.25, 0.5, 0.75, 1, 1.5, 2, 4, 6, 8, 12, 24, 48, 96];
function event(ester = Ester.E2, theta = 0.11, doseMG = 1, route = Route.sublingualNew, timeH = start) {
    return { id: `${route}-${ester}-${timeH}`, route, ester, doseMG, timeH,
        extras: { [ExtraKey.sublingualTheta]: theta } };
}
function close(actual, expected, label = '', rel = 1e-9, abs = 1e-12) {
    assert.ok(Number.isFinite(actual), `${label}: non-finite ${actual}`);
    assert.ok(Math.abs(actual - expected) <= abs + rel * Math.max(Math.abs(actual), Math.abs(expected)),
        `${label}: got ${actual}, expected ${expected}`);
}
function model(e) { return new PrecomputedEventModel(e, [e]); }
function pgMl(amount, kg = 70) { return amount * 1e9 / (2 * kg * 1000); }
function metrics(fn) {
    let cmax = 0, tmax = 0;
    for (let i = 0; i <= 4800; i++) {
        const t = i / 100, c = pgMl(fn(t));
        if (c > cmax) { cmax = c; tmax = t; }
    }
    return { cmax, tmax, c4: pgMl(fn(4)), c8: pgMl(fn(8)), c24: pgMl(fn(24)), c48: pgMl(fn(48)), c72: pgMl(fn(72)) };
}
function simpson(fn, upper = 1440, steps = 72000) {
    const h = upper / steps;
    let sum = fn(0) + fn(upper);
    for (let i = 1; i < steps; i++) sum += (i % 2 ? 4 : 2) * fn(i * h);
    return sum * h / 3;
}
// Independent 5-state continuous-time compartment generator. Does not use the
// production eigensolver, kernel, input builder, matrix or prior constants.
function generator(ester, p = DEFAULT_PK_PARAMS) {
    const ke = p.e2_kClear, s = p.e2_recycle_strength, ks = Math.LN2 / p.e2_sulfate_halfLifeH;
    const ka = ester === Ester.EV ? 0.05 : 0.32, f = p.e2_oral_bio;
    return [
        [-2.4, 0, 0, 0, 0],
        [0, -ka, 0, 0, 0],
        [0.28 * 2.4, f * ka, -ke, 0.06 * Math.LN2 * s, 0],
        [0, 0.1 * (1 - f) * ka, 0.5 * ke, -Math.LN2, 0.21 * ks * s],
        [0, 0.5 * (1 - f) * ka, 0, 0.54 * Math.LN2, -ks],
    ];
}
function multiply(m, x) { return m.map(row => row.reduce((sum, a, j) => sum + a * x[j], 0)); }
// Uniformization exp(Gt)x = exp(-qt) sum ((qt)^n/n!) (I+G/q)^n x.
// All summands are nonnegative; independent of production spectral solution.
function propagate(g, initial, t) {
    if (!(t > 0)) return initial.slice();
    const q = Math.max(...g.map((row, i) => -row[i])), qt = q * t;
    assert.ok(qt < 700, 'reference needs interval splitting beyond this range');
    const transition = g.map((row, i) => row.map((a, j) => (i === j ? 1 : 0) + a / q));
    let term = initial.slice(), weight = Math.exp(-qt), result = term.map(v => weight * v);
    const limit = Math.ceil(qt + 16 * Math.sqrt(qt + 1) + 80);
    for (let n = 1; n <= limit; n++) {
        term = multiply(transition, term);
        weight *= qt / n;
        for (let i = 0; i < result.length; i++) result[i] += weight * term[i];
    }
    return result;
}
function reference(t, e, p = DEFAULT_PK_PARAMS) {
    if (!(t > 0)) return 0;
    const theta = e.route === Route.oral ? 0 : e.extras[ExtraKey.sublingualTheta];
    const dose = e.doseMG * getToE2Factor(e.ester);
    return propagate(generator(e.ester, p), [theta * dose, (1 - theta) * dose, 0, 0, 0], t)[2];
}
function solve(a, b) {
    const m = a.map((row, i) => [...row, b[i]]), n = b.length;
    for (let i = 0; i < n; i++) {
        let pivot = i;
        for (let k = i + 1; k < n; k++) if (Math.abs(m[k][i]) > Math.abs(m[pivot][i])) pivot = k;
        [m[i], m[pivot]] = [m[pivot], m[i]];
        const divisor = m[i][i];
        for (let j = i; j <= n; j++) m[i][j] /= divisor;
        for (let k = 0; k < n; k++) if (k !== i) {
            const factor = m[k][i];
            for (let j = i; j <= n; j++) m[k][j] -= factor * m[i][j];
        }
    }
    return m.map(row => row[n]);
}

for (const ester of [Ester.E2, Ester.EV]) {
    test(`${ester}: theta=0 exactly shares oral E2/E1/E1S model, also under custom parameters`, () => {
        for (const s of [0, 1, 3]) for (const ke of [0.05, 0.32, 0.41, 2.4]) for (const f of [0, 0.03, 1]) {
            applyPKOverrides({ ...DEFAULT_PK_PARAMS, e2_kClear: ke, e2_oral_bio: f, e2_recycle_strength: s });
            const e = event(ester, 0, 2), sl = model(e), oral = model({ ...e, route: Route.oral });
            for (const t of at) close(sl.amount(start + t), oral.amount(start + t), `t=${t}`);
            close(getBioavailabilityMultiplier(e.route, ester, e.extras), getBioavailabilityMultiplier(Route.oral, ester));
        }
        applyPKOverrides(null);
    });
    test(`${ester}: spectral absorption agrees with independent positive-matrix exponential`, () => {
        for (const ke of [0.001, 0.05, 0.32, 0.41, 2.4, 5]) for (const s of [0, 1, 3]) for (const half of [4, 12, 36]) {
            const p = { ...DEFAULT_PK_PARAMS, e2_kClear: ke, e2_recycle_strength: s, e2_sulfate_halfLifeH: half };
            applyPKOverrides(p);
            for (const theta of [0, 0.11, 1]) {
                const e = event(ester, theta), m = model(e);
                for (const t of [1 / 60, 1, 8, 24, 96])
                    close(m.amount(start + t), reference(t, e, p), `${ester}/${ke}/${s}/${half}/${theta}/${t}`, 2e-8, 1e-11);
            }
        }
        applyPKOverrides(null);
    });
    test(`${ester}: disabling return exactly recovers no-return SL and historical oral`, () => {
        applyPKOverrides({ ...DEFAULT_PK_PARAMS, e2_recycle_strength: 0 });
        for (const theta of [0, 0.11, 1]) {
            const e = event(ester, theta, 2), m = model(e);
            for (const t of at) {
                const expected = 2 * getToE2Factor(ester) * (theta * 0.28 * estrogenAbsorptionKernel(t, 2.4, 0.41)
                    + (1 - theta) * 0.03 * estrogenAbsorptionKernel(t, ester === Ester.EV ? 0.05 : 0.32, 0.41));
                close(m.amount(start + t), expected, 'no-return limit', 2e-8, 1e-11);
            }
        }
        applyPKOverrides(null);
    });
    test(`${ester}: integrated E2 exposure includes only regenerated E2, not reservoir mass`, () => {
        applyPKOverrides(null);
        for (const theta of [0, 0.11, 1]) {
            const e = event(ester, theta, 2), m = model(e), g = generator(ester);
            const initial = [theta * 2 * getToE2Factor(ester), (1 - theta) * 2 * getToE2Factor(ester), 0, 0, 0];
            const expected = solve(g.map(row => row.map(v => -v)), initial)[2];
            close(simpson(t => m.amount(start + t)), expected, 'AUC independent solve', 3e-7);
            const directOnly = e.doseMG * getBioavailabilityMultiplier(e.route, ester, e.extras) / 0.41;
            assert.ok(expected > directOnly, 'displayed direct input coefficient is NOT total exposure');
        }
    });
    test(`${ester}: reservoir adds a small sustained tail without holding E2 near early peak`, () => {
        applyPKOverrides({ ...DEFAULT_PK_PARAMS, e2_recycle_strength: 0 });
        const noReturn = model(event(ester));
        applyPKOverrides(null);
        const m = model(event(ester)), curve = metrics(t => m.amount(start + t));
        assert.ok(curve.tmax > 0.5 && curve.tmax < 1.6, JSON.stringify(curve));
        assert.ok(curve.c8 < curve.cmax * 0.3, JSON.stringify(curve));
        for (const t of [8, 24, 48, 72]) assert.ok(m.amount(start + t) > noReturn.amount(start + t), `return at ${t}`);
        assert.ok(curve.c72 > 0 && curve.c72 < curve.c24);
        console.log(`${ester}, 1 mg / 70 kg / theta .11: ${JSON.stringify(curve)}`);
    });
    test(`${ester}: lifecycle follows slow network mode; old doses are not prematurely pruned`, () => {
        applyPKOverrides({ ...DEFAULT_PK_PARAMS, e2_sulfate_halfLifeH: 36, e2_recycle_strength: 3 });
        const e = event(ester), p = resolveParams(e), lifetime = computeMaxLifetimeH(p, e.route, [e], start), m = model(e);
        const minRate = Math.min(p.k1_fast, p.k1_slow, p.k3, ...p.metabolites.decayRates);
        assert.equal(lifetime, Math.ceil(Math.log(1e10) / minRate));
        assert.ok(lifetime > 720);
        assert.ok(pgMl(m.amount(start + lifetime)) < 1e-6);
        // A zero-dose marker extends horizon across the pruning boundary.
        const marker = event(ester, 0.11, 0, e.route, start + lifetime + 24);
        const sim = runSimulation([e, marker], 70);
        let maxError = 0;
        for (let i = 0; i < sim.timeH.length; i++)
            maxError = Math.max(maxError, Math.abs(sim.concPGmL_E2[i] - pgMl(m.amount(sim.timeH[i]))));
        assert.ok(maxError < 1e-6, `pruning error ${maxError}`);
        applyPKOverrides(null);
    });
    test(`${ester}: zero dose, dose/weight scaling, timing and repeated-dose superposition`, () => {
        applyPKOverrides(null);
        const events = [event(ester), event(ester, 0.11, 2, Route.sublingualNew, start + 8)];
        const sim = runSimulation(events, 70), sim140 = runSimulation(events, 140);
        for (const offset of [0.25, 1, 2, 4, 8, 9, 10, 12, 16, 20, 24, 32]) {
            const index = sim.timeH.indexOf(start + offset);
            assert.ok(index >= 0, `missing sample ${offset}`);
            const expected = events.reduce((sum, e) => sum + pgMl(reference(start + offset - e.timeH, e)), 0);
            close(sim.concPGmL_E2[index], expected, `superposition ${offset}`, 2e-8, 1e-8);
            close(sim140.concPGmL_E2[index] * 2, sim.concPGmL_E2[index]);
            close(sim.concPGmL_CPA[index], 0); close(sim.concNGdL_T[index], 0);
        }
        const zero = model(event(ester, 0.11, 0)), one = model(event(ester)), four = model(event(ester, 0.11, 4));
        for (const t of at) { close(zero.amount(start + t), 0); close(four.amount(start + t), 4 * one.amount(start + t)); }
        close(one.amount(start - 1), 0);
    });
}

test('network generator stays positive and dissipative across allowed sensitivity ranges', () => {
    for (const ke of [0.001, 0.41, 5]) for (const s of [0, 1e-12, 1, 3]) for (const half of [4, 12, 36]) {
        const p = profile(ke, s, half), m = p.matrix;
        for (let j = 0; j < 3; j++) {
            assert.ok(m[j][j] < 0);
            for (let i = 0; i < 3; i++) if (i !== j) assert.ok(m[i][j] >= 0);
            assert.ok(m.reduce((sum, row) => sum + row[j], 0) < 0, 'strictly positive unrepresented outflow');
        }
        assert.ok(p.decayRates.every(rate => rate > 0 && Number.isFinite(rate)));
        for (const input of [[1, 0, 0], [0, 1, 0], [0, 0, 1]]) {
            const fn = p.compileE2(0.32, input);
            for (const t of [0, 1e-10, 1e-5, 1, 8, 1000, 1e6]) assert.ok(Number.isFinite(fn(t)) && fn(t) >= 0);
            const expected = solve(m.map(row => row.map(v => -v)), input)[0];
            close(p.integratedE2(input), expected, 'integrated network state', 1e-8);
        }
    }
    for (const args of [[0, 1, 12], [NaN, 1, 12], [0.41, -1, 12], [0.41, 4, 12], [0.41, 1, 3], [0.41, 1, 37]])
        assert.throws(() => profile(...args), RangeError);
});

test('E1/E1S are not instantly counted as E2; eigenmode/absorption coincident-rate limits', () => {
    const p = profile(0.41, 1, 12);
    for (const input of [[1, 0, 0], [0, 1, 0], [0, 0, 1]]) for (const rate of p.decayRates) {
        for (const ka of [rate, rate * (1 + 1e-12), 2.4]) {
            const fn = p.compileE2(ka, input);
            const g = [[-ka, 0, 0, 0], ...p.matrix.map((row, i) => [ka * input[i], ...row])];
            for (const t of [1e-6, 0.1, 1, 8, 96]) close(fn(t), propagate(g, [1, 0, 0, 0], t)[1], 'coincident rate', 1e-8);
        }
    }
    assert.ok(p.compileE2(0.32, [0, 0, 1])(1e-4) < 1e-12);
    close(profile(0.41, 0, 12).compileE2(0.32, [0, 0, 1])(24), 0);
});

test('independent RK4 conserves dose including effective loss; absorbed input never exceeds dose', () => {
    const base = generator(Ester.E2), g = [...base.map(row => [...row, 0]), Array(6).fill(0)];
    for (let j = 0; j < 5; j++) g[5][j] = -base.reduce((sum, row) => sum + row[j], 0);
    let x = [0.11, 0.89, 0, 0, 0, 0];
    const h = 0.005;
    for (let step = 1; step <= 19200; step++) {
        const k1 = multiply(g, x), k2 = multiply(g, x.map((v, i) => v + h * k1[i] / 2));
        const k3 = multiply(g, x.map((v, i) => v + h * k2[i] / 2)), k4 = multiply(g, x.map((v, i) => v + h * k3[i]));
        x = x.map((v, i) => v + h / 6 * (k1[i] + 2 * k2[i] + 2 * k3[i] + k4[i]));
        if (step % 1600 === 0) {
            close(x.reduce((sum, v) => sum + v, 0), 1, 'molar balance', 1e-10);
            assert.ok(x.every(v => v >= 0));
            close(x[2], reference(step * h, event()), 'RK4 vs uniformization', 1e-8, 1e-11);
        }
    }
    for (const f of [0, 0.03, 0.5, 1]) {
        const input = swallowedEstrogenInput(f, 2);
        assert.ok(input.every(v => v >= 0));
        assert.ok(input.reduce((sum, v) => sum + v, 0) <= 2);
    }
});

test('daily dosing builds residual pool and converges; not confused with single-dose trough', () => {
    applyPKOverrides(null);
    const single = model(event()), fn = t => single.amount(start + t);
    const trough = n => Array.from({ length: n }, (_, i) => fn(24 * (i + 1))).reduce((sum, v) => sum + v, 0);
    assert.ok(trough(30) > trough(1)); close(trough(30), trough(60), 'steady trough convergence', 1e-8);
    const events = Array.from({ length: 30 }, (_, i) => event(Ester.E2, 0.11, 1, Route.sublingualNew, start + 24 * i));
    const sim = runSimulation(events, 70), index = sim.timeH.indexOf(start + 720);
    assert.ok(index >= 0); close(sim.concPGmL_E2[index], pgMl(trough(30)), 'multi-dose trough');
    const oral = model(event(Ester.E2, 0, 1, Route.oral));
    const oralTrough = Array.from({ length: 60 }, (_, i) => oral.amount(start + 24 * (i + 1))).reduce((a, b) => a + b, 0);
    const oralAverage = profile(0.41, 1, 12).integratedE2(swallowedEstrogenInput(0.03, 1)) / 24;
    console.log(`Default oral E2 1mg q24h, model-only: trough=${pgMl(oralTrough)}, mean=${pgMl(oralAverage)}`);
});

test('parameter migration/sanitization, compiled-profile isolation and temporary settings restoration', () => {
    const legacy = { ...DEFAULT_PK_PARAMS }; delete legacy.e2_recycle_strength; delete legacy.e2_sulfate_halfLifeH;
    assert.equal(sanitizePKParams(legacy).e2_recycle_strength, 1);
    assert.equal(sanitizePKParams(legacy).e2_sulfate_halfLifeH, 12);
    const bad = sanitizePKParams({ e2_recycle_strength: -1, e2_sulfate_halfLifeH: Infinity });
    assert.equal(bad.e2_recycle_strength, 0); assert.equal(bad.e2_sulfate_halfLifeH, 12);
    assert.equal(sanitizePKParams({ e2_recycle_strength: 5, e2_sulfate_halfLifeH: 0 }).e2_sulfate_halfLifeH, 4);
    const personal = { ...DEFAULT_PK_PARAMS, e2_kClear: 0.6, e2_oral_bio: 0.04, e2_recycle_strength: 2 };
    applyPKOverrides(personal); const m = model(event()), original = m.amount(start + 24);
    for (let i = 0; i < 30; i++) profile(0.1 + i / 100, 1, 12);
    assert.ok(runSimulationWithParams([event()], 70, DEFAULT_PK_PARAMS));
    assert.deepEqual(getActivePKParams(), personal); close(m.amount(start + 24), original);
    applyPKOverrides(null); close(m.amount(start + 24), original, 'compiled snapshot must not change');
});

test('tiers and direct-input display use the same split, not metabolite-inclusive AUC', () => {
    applyPKOverrides(null);
    for (const [i, key] of SL_TIER_ORDER.entries()) {
        const e = { ...event(), extras: { [ExtraKey.sublingualTier]: i } }, p = resolveParams(e);
        close(p.Frac_fast, SublingualTierParams[key].theta);
        close(p.F, getBioavailabilityMultiplier(e.route, e.ester, e.extras));
    }
    for (const extras of [{}, { sublingualTheta: -1 }, { sublingualTheta: 2 }, { sublingualTheta: NaN },
        { sublingualTier: Infinity }, { sublingualTheta: 0, sublingualTier: 3 }]) {
        const e = { ...event(), extras }, p = resolveParams(e);
        assert.ok(p.Frac_fast >= 0 && p.Frac_fast <= 1);
        close(p.F, getBioavailabilityMultiplier(e.route, e.ester, extras));
    }
});

test('legacy SL and other routes match fixed original fixtures; oral matches with return disabled', async () => {
    const fixtures = JSON.parse(await readFile(new URL('./fixtures/pk_legacy.json', import.meta.url), 'utf8'));
    for (const { event: e, amountsMG } of fixtures.cases) {
        const oralE2 = e.route === Route.oral && [Ester.E2, Ester.EV].includes(e.ester);
        applyPKOverrides(oralE2 ? { ...DEFAULT_PK_PARAMS, e2_recycle_strength: 0 } : null);
        const current = model(e);
        fixtures.offsetsH.forEach((t, i) => close(current.amount(e.timeH + t), amountsMG[i], `${e.ester}/${e.route}/${t}`, 2e-8, 1e-11));
    }
    applyPKOverrides(null);
});

test('historical and recent SL doses retain dense peri-peak samples with long forecast horizon', () => {
    applyPKOverrides(null);
    const events = [event(Ester.E2, 0.11, 1, Route.sublingualNew, start - 24 * 365), event()];
    const sim = runSimulation(events, 70);
    for (const e of events) for (const offset of [0.125, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 3]) {
        const index = sim.timeH.indexOf(e.timeH + offset);
        assert.ok(index >= 0, `missing dense sample ${offset}`);
        const expected = events.reduce((sum, dose) => sum + pgMl(model(dose).amount(e.timeH + offset)), 0);
        close(sim.concPGmL_E2[index], expected, 'historical sample', 1e-8, 1e-8);
    }
});

test('all seven language packs disclose uncertain return priors; controls have labels/fallback', async () => {
    const translations = await readFile(new URL('../src/i18n/translations.ts', import.meta.url), 'utf8');
    const { code } = await transform(translations, { loader: 'ts', format: 'esm', target: 'es2022' });
    const { TRANSLATIONS: tr } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
    for (const lang of ['zh', 'en', 'zh-TW', 'yue', 'ja', 'ko', 'tr']) {
        for (const key of ['sl.new_model_note', 'sl.new_ev_note', 'sl.metabolite_note']) assert.ok(tr[lang][key]?.length > 20, `${lang}/${key}`);
        for (const key of ['pk.e2_recycle_strength', 'pk.e2_sulfate_halfLifeH'])
            assert.ok((tr[lang][key] || (lang === 'yue' && tr['zh-TW'][key]))?.length > 3, `${lang}/${key}`);
    }
});

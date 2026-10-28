/**
 * Linear E2 <-> E1 <-> E1S network, in E2-equivalent (molar) amounts.
 * Only the E2 state is a contribution to the serum E2 curve. E1/E1S are NOT
 * added to it by mass or by estrogenic potency. No endogenous baseline is added.
 *
 * Mechanistic motivation: Ruder et al. 1972 (PMID 5014608), Longcope et al.
 * 1985 (PMID 4094413), Cirrincione et al. 2021 (PMID 33439749), and estradiol
 * product labels. These sources do NOT identify all rates in this model.
 * The rounded branch fractions and pool turnover below are explicit PRIORS,
 * not a fit to those studies, nor a universal human metabolic parameter set.
 * See docs/sublingual-model-review.md, revision 2.
 */
export type EstrogenAmounts = readonly [number, number, number]; // E2, E1, E1S
export type EstrogenMatrix = readonly [EstrogenAmounts, EstrogenAmounts, EstrogenAmounts];

export const ESTROGEN_METABOLITE_PRIORS = Object.freeze({
    e2ToE1Share: 0.5,         // share of the effective E2 disappearance flux
    e1TurnoverH: Math.LN2,   // effective E1 pool turnover, prior t1/2 = 1 h
    e1ReturnShare: 0.06,     // E1 -> E2 share before sensitivity scaling
    e1ToSulfateShare: 0.54,  // E1 -> E1S share; NOT a tracer transfer factor
    sulfateReturnShare: 0.21,// E1S -> E1 share before sensitivity scaling
    // Fractions of the swallowed dose NOT entering as direct E2. This keeps
    // direct + first-pass metabolite input <= dose even with custom oral F.
    firstPassE1Share: 0.1,
    firstPassSulfateShare: 0.5,
});

// Stable Bateman kernel, including exactly/near-coincident rates and tiny t.
export function estrogenAbsorptionKernel(t: number, ka: number, decay: number): number {
    if (!(t > 0) || !(ka > 0)) return 0;
    const delta = Math.abs(ka - decay);
    if (delta < 1e-10 * Math.max(ka, decay)) return ka * t * Math.exp(-decay * t);
    return ka * Math.exp(-Math.min(ka, decay) * t) * -Math.expm1(-delta * t) / delta;
}

// Jacobi diagonalization of the real symmetric 3x3 similarity transform.
// Computed once per PK profile, not once per dose/time evaluation.
function symmetricEigen3(input: number[][]): { rates: number[]; vectors: number[][] } {
    const a = input.map(row => [...row]);
    const u = [[1, 0, 0], [0, 1, 0], [0, 0, 1]];
    for (let sweep = 0; sweep < 32; sweep++) {
        let p = 0, q = 1;
        for (const [i, j] of [[0, 2], [1, 2]]) {
            if (Math.abs(a[i][j]) > Math.abs(a[p][q])) { p = i; q = j; }
        }
        if (Math.abs(a[p][q]) <= 1e-14 * Math.max(...a.map((r, i) => Math.abs(r[i])))) break;
        const angle = 0.5 * Math.atan2(2 * a[p][q], a[q][q] - a[p][p]);
        const c = Math.cos(angle), s = Math.sin(angle);
        const app = a[p][p], aqq = a[q][q], apq = a[p][q];
        a[p][p] = c * c * app - 2 * s * c * apq + s * s * aqq;
        a[q][q] = s * s * app + 2 * s * c * apq + c * c * aqq;
        a[p][q] = a[q][p] = 0;
        for (let k = 0; k < 3; k++) {
            if (k !== p && k !== q) {
                const akp = a[k][p], akq = a[k][q];
                a[k][p] = a[p][k] = c * akp - s * akq;
                a[k][q] = a[q][k] = s * akp + c * akq;
            }
            const ukp = u[k][p], ukq = u[k][q];
            u[k][p] = c * ukp - s * ukq;
            u[k][q] = s * ukp + c * ukq;
        }
    }
    return { rates: a.map((row, i) => -row[i]), vectors: u };
}

export interface EstrogenMetaboliteProfile {
    /** Columns are source pools; negative column sum is effective unrepresented outflow.
     * Omitted conjugates are not asserted to be physiologically irreversible. */
    readonly matrix: EstrogenMatrix;
    readonly decayRates: readonly number[];
    /** Compile one absorption input into a lightweight time -> E2 amount kernel. */
    compileE2(ka: number, input: EstrogenAmounts): (elapsedH: number) => number;
    /** Integral of E2 amount over [0, infinity), including recycling, mg*h. */
    integratedE2(input: EstrogenAmounts): number;
}

const profiles = new Map<string, EstrogenMetaboliteProfile>();

export function getEstrogenMetaboliteProfile(
    e2DisappearanceH: number,
    returnStrength: number,
    sulfateHalfLifeH: number,
): EstrogenMetaboliteProfile {
    if (!(e2DisappearanceH > 0) || !Number.isFinite(e2DisappearanceH) ||
        !Number.isFinite(returnStrength) || returnStrength < 0 || returnStrength > 3 ||
        !Number.isFinite(sulfateHalfLifeH) || sulfateHalfLifeH < 4 || sulfateHalfLifeH > 36) {
        throw new RangeError('Invalid estrogen metabolite profile');
    }
    const key = `${e2DisappearanceH}/${returnStrength}/${sulfateHalfLifeH}`;
    const existing = profiles.get(key);
    if (existing) return existing;
    const prior = ESTROGEN_METABOLITE_PRIORS;
    const k21 = prior.e2ToE1Share * e2DisappearanceH;
    const k12 = prior.e1ReturnShare * prior.e1TurnoverH * returnStrength;
    const k1s = prior.e1ToSulfateShare * prior.e1TurnoverH;
    const sulfateOut = Math.LN2 / sulfateHalfLifeH;
    const ks1 = prior.sulfateReturnShare * sulfateOut * returnStrength;
    const matrix: EstrogenMatrix = [
        [-e2DisappearanceH, k12, 0],
        [k21, -prior.e1TurnoverH, ks1],
        [0, k1s, -sulfateOut],
    ];

    let profile: EstrogenMetaboliteProfile;
    if (returnStrength === 0) {
        // One-way metabolism still exists, but E1/E1S cannot contribute to E2.
        // This exact limit reproduces the previous no-return Bateman model.
        profile = {
            matrix, decayRates: [e2DisappearanceH],
            compileE2: (ka, input) => t => input[0] * estrogenAbsorptionKernel(t, ka, e2DisappearanceH),
            integratedE2: input => input[0] / e2DisappearanceH,
        };
    } else {
        // M = D S D^-1, S symmetric because both links are reversible.
        const d = [1, Math.sqrt(k21 / k12), Math.sqrt(k21 / k12) * Math.sqrt(k1s / ks1)];
        const { rates, vectors: u } = symmetricEigen3([
            [matrix[0][0], Math.sqrt(k12 * k21), 0],
            [Math.sqrt(k12 * k21), matrix[1][1], Math.sqrt(k1s * ks1)],
            [0, Math.sqrt(k1s * ks1), matrix[2][2]],
        ]);
        if (rates.some(rate => !(rate > 0) || !Number.isFinite(rate))) {
            throw new RangeError('Estrogen metabolite network must be dissipative');
        }
        const coefficients = (input: EstrogenAmounts) => rates.map((_, j) =>
            u[0][j] * (u[0][j] * input[0] + u[1][j] * input[1] / d[1] + u[2][j] * input[2] / d[2]));
        profile = {
            matrix, decayRates: rates,
            compileE2: (ka, input) => {
                const c = coefficients(input);
                return t => {
                    if (!(t > 0)) return 0;
                    let amount = 0;
                    for (let j = 0; j < 3; j++) amount += c[j] * estrogenAbsorptionKernel(t, ka, rates[j]);
                    // The positive compartment system has no negative amounts;
                    // roundoff can leave a tiny negative residual at t ~ 0.
                    return Math.max(0, amount);
                };
            },
            integratedE2: input => coefficients(input).reduce((area, c, j) => area + c / rates[j], 0),
        };
    }
    // Candidate personal-PK fits create many profiles. Bound memory without
    // sharing mutable active settings or caching each recorded dose separately.
    if (profiles.size >= 24) profiles.delete(profiles.keys().next().value!);
    profiles.set(key, profile);
    return profile;
}

export function swallowedEstrogenInput(directE2Fraction: number, e2EquivalentDose: number): EstrogenAmounts {
    const remaining = 1 - directE2Fraction;
    return [
        directE2Fraction * e2EquivalentDose,
        ESTROGEN_METABOLITE_PRIORS.firstPassE1Share * remaining * e2EquivalentDose,
        ESTROGEN_METABOLITE_PRIORS.firstPassSulfateShare * remaining * e2EquivalentDose,
    ];
}

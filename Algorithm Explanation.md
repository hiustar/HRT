# HRT‑Recorder Pharmacokinetic Models

This README explains the algorithms used for each drug/route, key parameters and units, what was tuned, why we tuned it, and how the implementation evolved.

> **2026-10-27 / canary 更新**：§6 已按当前 TypeScript 舌下实现重写；新版模型的研究依据、参数先验、前后对照及限制见 [舌下模型审查](docs/sublingual-model-review.md)。其他章节含历史实现记录，不代表所有参数已获临床验证。

---

## 0) 总览（模型架构）

**目标**：用一套轻量的、可解释的 PK 近似模型，覆盖常见雌激素制剂与给药途径，在手机端实时算出血药浓度–时间曲线与 AUC。

**核心构件（与代码一一对应）**
- **DoseEvent**：一次给药事件，带路由、时间、剂量、酯别与一些附加字段（如凝胶面积、贴片标称释放速率 µg/day）。
- **ParameterResolver**：把事件映射为具体参数 `PKParams`（k₁/k₂/k₃、F、双库或双通路比例、零阶速率等）。
- **ThreeCompartmentModel**：解析解工具箱：
  - 三室模型（首过吸收 k₁ → 酯水解 k₂ → 游离 E2 清除 k₃）的解析式。
  - 单室 Bateman 形式（凝胶及部分旧实现）；口服 E2/EV 及新版舌下采用 E2/E1/E1S 网络卷积（§6）。
  - 双通路舌下模型（快：口腔黏膜；慢：吞咽口服；旧版与新版的 E2/EV 实现分别见 §6）。
  - 贴片：零阶输入在佩戴窗口内，移除后按 k₃ 衰减；或旧版一阶“假库”。
- **SimulationEngine**：把一堆 `DoseEvent` 预编译为时间→量的函数，遍历时间点，线性叠加各事件的中心室药量，再以体分布换算为浓度，AUC 用梯形法则积分。

**单位与换算**
- 剂量 `doseMG` 以 mg 计；中心室药量计算单位也是 mg。
- 浓度输出为 pg/mL：`conc = amountMG × 1e9 / Vd_ml`。
- 体分布体积：`Vd = vdPerKG × BW`，其中 `vdPerKG` 默认 **2.0 L·kg⁻¹**（可在设置中调整）。
- **当前 TypeScript 的 `doseMG` 是原药/酯剂量（mg），不是预先换算的 E2 等效剂量**；雌二醇路由在 `F` 中乘以分子量换算因子一次，避免重复折算。

---

## 1) 公共参数（`PKparameter.swift :: CorePK`）

| 名称 | 含义 | 默认值 | 备注 |
| --- | --- | --- | --- |
| `vdPerKG` | 表观分布容积（每 kg） | 2.0 L·kg⁻¹ | 移动端可配置；用于 mg → pg/mL 换算 |
| `kClear` | 游离 E2 清除速率常数 k₃ | 0.41 h⁻¹ | 对应 t½ ≈ 1.69 h；为经验标定值，用于与项目中目标曲线贴合 |
| `kClearInjection` | 注射专用游离 E2 清除速率常数 k₃（仅 injection 路由使用） | 0.041 h⁻¹ | 对应 t½ ≈ 16.9 h；保持 flip‑flop 形状以匹配 EEN/EV/EC 的 Tmax/Cmax，不等同于生理清除 |
| `depotK1Corr` | 注射两库 k₁ 的全局校正系数 | 1.0 | 改峰/拖尾时可整体缩放注射的 k₁ |

> 注：`kClear` 是游离 E2 中心室的表观清除常数，其锚点来自贴片移除后的终末半衰期（≈ 1–2 h），在此基础上取中间值 **0.41 h⁻¹** 以兼顾舌下与贴片的日内回落。它服务于本项目的简化模型与多路叠加稳定性，并不等价于群体生理清除率，不应外推到人群参数。

**关于 kClear 的来龙去脉**
- **锚点来源**：最初把 `kClear` 定在 1–2 小时的半衰期区间，是依据某些雌二醇贴片的说明书与审评资料对“移除贴片后”的血药下降描述。贴片移除时外源输入为零，后续的下降主要由系统清除主导，因此该时段的终末斜率可以近似视为清除常数 k₃ 的体现。
- **数值选择**：按 `t½ = 1–2 h` 反推 `k = ln2 / t½ ≈ 0.35–0.69 h⁻¹`，本项目选择中间值 `kClear = 0.41 h⁻¹`（`t½ ≈ 1.69 h`），既能匹配贴片移除后的回落节奏，也与舌下日内回落经验相符。
- **为什么不用口服去估**：口服 Bateman 场景下常见 flip‑flop 现象，当吸收速率 `ka` 与或小于清除速率 `ke` 时，终末相斜率反而更像 `ka` 而非 `ke`，因此不适合作为清除常数的锚点。相对地，贴片在移除后 `ka = 0`，终末相更干净。

**注射专用 `kClearInjection`（有效参数说明）**  
注射油剂的末端斜率主要受“从油性贮库进入血液”的缓慢输入所支配（flip‑flop）。为在简化一室清除的前提下复现文献级别的 EEN/EV/EC 峰时与长尾，注射路径使用了 **`kClearInjection = 0.041 h⁻¹`**（当前默认值，可在 PK 参数设置中调整）。它是为**形状校准**而设的有效参数，并不等同于生理清除。  
- 仅在 `event.route == .injection` 时使用；其他路由继续使用 `kClear = 0.41 h⁻¹`。  
- 这样可在不增加额外分布/代谢池的情况下，保持注射曲线的吸收限速形状（天级 Tmax、较平稳的稳态）。  
- 若需生理可解释性更强的估计，应考虑在模型中显式加入贮库/结合/可逆代谢池而非调整清除常数。

---

## 2) 注射油剂（EV/EB/EC/EN）

### 2.1 模型与参数路径
- **模型**：两并联“库”吸收 → 酯水解 → 清除。
- “快库”控制峰时与峰高（Tmax/Cmax），“慢库”控制尾相（半衰期）。
- 解析解使用三室模型：吸收 k₁、酯水解 k₂、清除 k₃。
- **参数来源**：`TwoPartDepotPK`、`EsterPK.k2`、`InjectionPK.formationFraction`、`EsterInfo.toE2Factor`、`CorePK.kClear`、`CorePK.depotK1Corr`。
- **代码入口**：`ParameterResolver.resolve(... case .injection ...)` → `ThreeCompartmentModel.injAmount(...)`。

### 2.2 关键数值（默认）

| 酯 | Frac_fast | k1_fast (h⁻¹) | t½_fast (h) | k1_slow (h⁻¹) | t½_slow (h) | k2 (h⁻¹) | t½_hydrolysis (h) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| EB | 0.90 | 0.144 | 4.81 | 0.114 | 6.08 | 0.090 | 7.70 |
| EV | 0.40 | 0.0216 | 32.08 | 0.0138 | 50.23 | 0.070 | 9.90 |
| EC | 0.229164549 | 0.005035046 | 137.66 | 0.004510574 | 153.67 | 0.045 | 15.40 |
| EN | 0.05 | 0.0010 | 693.15 | 0.0050 | 138.63 | 0.015 | 46.21 |

*注：注射路径的清除常数采用 `k3 = kClearInjection = 0.041 h⁻¹`。*

### 2.3 生物利用度（形成分数 F）
- 形成游离 E2 的经验分数 `InjectionPK.formationFraction[ester]`。本项目剂量已按 E2‑eq 输入，**因此 `F = formationFraction`**。

**当前 `formationFraction`（预乘 `toE2Factor` 之前）**  
| 酯 | formationFraction |
| --- | ---: |
| EB | 0.1092237647 |
| EV | 0.0622582882 |
| EC | 0.117255838 |
| EN | 0.12 |
这些数值为经验标定项，用于在不同酯别间保持相对关系的同时，将单次给药的 $C_{\max}/T_{\max}$ 和稳态峰谷对齐到文献级别的量级。

- **调参缘由**：临床/社区曲线显示注射后总体暴露较口服/经皮显著更高，且不同酯别水解率不同，故在保持相对关系的同时加入了经验倍数以贴实峰值与 AUC。

### 2.4 数学形式（概念）
- 两个并联吸收库按 `Frac_fast` 和 `1 − Frac_fast` 分药量，分别以 `k1_fast` 与 `k1_slow` 进入“酯”室，水解为 E2 后以 `k₃` 清除。
- 解析解采用三指数线性组合；当速率接近时采用极限形式（避免除零）。

### 2.5 模型尝试与取舍
- 先前的“单库吸收”很难同时兼顾峰与长尾，因此改为两库模型。
- 尝试过浓度依赖的清除（早期“hill/浓度反馈”想法），在实际叠加多事件时容易引入非物理解耦与数值不稳，最终回退为常数 `k₃`。
- 保留 `depotK1Corr` 作为一键全局微调旋钮，用于不同品牌或溶剂粘度的整体系数修正。

---

## 3) 贴片（E2）

### 3.1 路由与参数
- **两种实现**：  
  1) **零阶输入**：当事件带 `extras[.releaseRateUGPerDay]` 时，按标称 µg/day 转 mg/h 注入中心室，移除后按 `k₃` 衰减。  
  2) **一阶近似（遗留）**：若未提供标称释放率，则用 `PatchPK.generic = .firstOrder(k1: 0.0075 h⁻¹)` 作为高载量贴片的近似。
- **佩戴窗口**：`patchApply` 到随后的 `patchRemove` 之间的时间跨度 `wearH`。

- **零阶**：  
  佩戴期（`0 ≤ t ≤ wearH`）：
  
  $$
  A(t) = \frac{\text{rateMGh}}{k_3} \,(1 - e^{-k_3 t})
  $$
  
  移除后（`t > wearH`）：
  
  $$
  A(t) = A(\text{wearH})\, e^{-k_3 (t - \text{wearH})}
  $$
  
- **一阶**：以 `k₁` 做“假库”吸收 + 口径 `F = 1`；移除时截断后续输入（实现上等价于减去佩戴结束后的继续吸收项）。

### 3.3 调参与选择
- 文献与说明书以 µg/day 标称，实际贴补图形更接近零阶，因此默认优先零阶，仅在缺乏数据时降级为一阶近似。
- **`F = 1.0`（相对标称释放率）的依据**：现代基质型贴片（Vivelle-Dot、Climara、Alora 等）按设计使其"体内标称释放率"即为实际递送速率——FDA 说明书将其称为 nominal in vivo delivery rate，故零阶模型直接取 `F = 1.0 × toE2Factor`，不再额外打折。已于 2026-07 移除 UI 中的 Beta 标记。

---

## 4) 经皮凝胶（E2 / T）

### 4.1 路由与参数
- **模型**：单室一阶吸收 + 清除，`F` 为经皮可达的系统暴露分数。
- **吸收速率 `k₁`**：在 flip-flop 动力学下（`k₁ ≪ k₃`），末端衰减速率由吸收主导，故 `k₁` 取自说明书报告的凝胶表观消除半衰期（~36 h）：`k₁ = ln(2)/36 ≈ 0.0193 h⁻¹`。注意 36 h 出自 **EstroGel** 说明书（"about 36 hours following administration of 1.25 g EstroGel"，NDA 021166），此前本文档与代码注释均误标为 Divigel；Divigel 说明书写的是 "about 10 hours"（NDA 022038）。两份说明书确有分歧（产品、剂型、涂抹部位皆不同），36 h 属于二选一而非共识值。`k₁` 不影响暴露量（AUC = F·D/k₃ 与 `k₁` 无关），只决定 Tmax 与峰谷形状。
- **`F`（生物利用率）按涂抹部位**：手臂/大腿 ≈ 5%，阴囊/生殖器部位 ≈ 25%（约 5×，外推自阴囊贴片给药数据 Premoli et al. 2005，因缺乏阴囊凝胶给药的直接人体研究）。
  - 手臂/大腿的 5% 由**说明书自身的稳态血药浓度反推**得出，而非引用任何现成百分比——美国的雌二醇凝胶说明书根本未给出百分比（Divigel NDA 022038、EstroGel NDA 021166 对吸收只有定性描述）。Divigel 0.25/0.5/1.0 mg/day 的 Cavg 为 9.8/21/30.5 pg/mL，EstroGel 0.75 mg/day 为 28.3 pg/mL；本模型在 65–70 kg 下需 F = 0.039–0.058（均值 0.050）才能复现。说明书数值未做基线校正，故属上限，真值可能更接近 0.04。
  - **不应引用 Järvinen et al. 1999 来支撑这个数**：其"61% 片剂 / 109% 贴片"是**相对**生物利用率，无法确定绝对分数。不过贴片一侧可佐证量级：1.09 × 50 µg/day ÷ 1.5 mg 应用量 ≈ 3.6%。
  - **常见的"10%"是另一个量，不可直接代入 `F`**：那是在厂商大面积涂抹法（Oestrogel SmPC，750 cm² 整条手臂）下**穿过皮肤**的比例；Wikipedia "Pharmacokinetics of estradiol" 也给出 10%（引 Sitruk-Ware 1989），但针对的是醇溶液这一类别。同一款 0.06% 凝胶的德国 Gynokadin Fachinformation 则写 5–6% "Bioverfügbarkeit"，而两者报告的血药浓度相同（2.5 g 给药 60–80 pg/mL）。`F` 在模型中线性且只出现一次，改成 0.10 会让所有预测值翻倍；由于用户按预测值调整剂量，偏高的 `F` 会把实际用量推向偏低。
- **睾酮凝胶（T）**：手臂/大腿 ≈ 10%（AndroGel/Testim FDA 说明书），阴囊 ≈ 50%（保守取 Iyer et al. 2017, *Andrology*；Kuhnert et al. 2005 报道的 5–8× 范围下限）。2026-07 之前，T 凝胶未按部位区分（`t_gel_F` 恒为 0.10，UI 的部位选择器对 T 无效），现已修复为与 E2 对称的按部位实现。
- **代码入口**：`getBioavailabilityMultiplier(... case .gel ...)` → `resolveParams` → `oneCompAmount(...)`。

### 4.2 局限与后续方向
- 仍忽略涂抹面积/剂量密度的非线性饱和效应（原型 `sigmaSat ≈ 0.008 mg·cm⁻²` 已从代码移除；调试阶段曾出现"低剂量偏低、高剂量偏高"的系统性误差）；当前按部位的常量 `F` 是文献支持的简化，而非该非线性效应的完整还原。
- 阴囊/生殖器 E2 凝胶的 `F` 值为跨物质（T→E2）外推，非直接人体数据，标注于代码注释与 PK 自定义参数面板。
- 待办：恢复面积/剂量依赖，并引入皮肤贮库的短暂零阶泄放以更好描述涂抹后前数小时的平台。

---

## 5) 口服（E2/EV）

### 5.1 当前模型与参数

口服 E2/EV 使用 §6 的 E2/E1/E1S 三池网络，以 theta=0 计算。EV 的有效吸收仍为
`kAbsEV=0.05 h⁻¹`，E2 为 `kAbsE2=0.32 h⁻¹`；未另建酯水解室。
这些是继承的简化参数，不能把它们当成经临床拟合的真实吸收/裂解速率。

### 5.2 直接输入与总代谢物回补

`e2_oral_bio=0.03` 表示直接 E2 输入系数，另外有 E1/E1S 首过输入及后续回转。
因此它不再表示全部系统暴露。历史的单室 F/清除率校准不能直接继承其原有含义，
也不能用当前模型重现某项口服研究的峰时或谷值，除非取得相应时序数据重新拟合。

---

## 6) 舌下及口服 E2/EV：当前 TypeScript 实现（第二次修订）

舌下记录统一使用 `Route.sublingual`，设置中可选择 `legacy`（旧版）、`new`（原新版）或 `metabolite`（代谢回流版，默认）。历史 `sublingualNew` 自动兼容转换，不改变记录 ID、剂量、时间或吸收参数。代谢回流版与口服 E2/EV 共享
**E2 ↔ E1 ↔ E1S** 的有效三池网络。完整资料、方程、先验、数值及限制见
[2026-10-27 舌下模型审查](docs/sublingual-model-review.md)。这是机制启发近似，未完成临床拟合。

### 6.1 吸收输入与回转

```text
x = [A2, A1, AS]ᵀ（均为 mg E2 摩尔等效量）
x' = Mx + b_fast ka_fast exp(-ka_fast t) + b_slow ka_slow exp(-ka_slow t)
M = [-ke,       0.06 ln2 * strength,       0]
    [0.5 ke,   -ln2,                     0.21 ks * strength]
    [0,         0.54 ln2,                -ks]
ks = ln2 / sulfateHalfLifeH

b_fast = D r theta [0.28, 0, 0]
b_slow = D r (1-theta) [F, 0.1(1-F), 0.5(1-F)]
Delta C_E2 = A2 * 1e9 / (2.0 * weightKg * 1000) pg/mL
```

- `r=1`（E2）或 `272.38/356.50`（EV），只换算一次；口服为 theta=0。
- 快吸收 `ka=2.4 h⁻¹`，吞咽吸收 E2 `0.32`、EV `0.05 h⁻¹`，沿用经验参数。
- `ke=e2_kClear` 默认 0.41 h⁻¹ 是 E2 池总消失率，其中部分进入 E1，不再把全部消失视为永不返回。
- `strength=e2_recycle_strength` 默认 1、敏感性区间 0–3；0 关闭对 E2 的回补。
- `sulfateHalfLifeH=e2_sulfate_halfLifeH` 默认 12 h、敏感性区间 4–36 h，**不是已验证的人体范围或 E2 终末半衰期**。
- 所有分支比例和周转均为待拟合先验，不能将文献 tracer transfer factors 当作 h⁻¹ 或单次分支比例。默认 E1 周转先验为 1 h。
- E1/E1S 不直接加到 E2 浓度，只通过回转增加 A2。其他结合物和流出折叠处理，未显式拟合肠肝延迟或组织多室。
- `F=e2_oral_bio` 默认 0.03 现在指直接 E2 输入，不是回转后的总暴露；旧的个体校准需重新核对。
- AUC 药量积分为 `first_component(-M^-1(b_fast+b_slow))`，不能使用旧的 `D*F/ke`。
- EV 快支折叠快速酯裂解，不使用注射慢水解参数；EV 舌下仍缺少直接数据。

### 6.2 档位与叠加

`theta` 读取自定义分流或档位，默认档位 0.01/0.04/0.11/0.18，仅为兼容的经验权重，不是含服分钟数实测的吸收比例。
新版 theta=0 与本轮口服整轨迹严格重合。重复给药叠加各次完整网络响应，储库残余自然累积；不重复添加任意基础值。

### 6.3 旧版兼容

旧版 E2 继续用 `dualAbsAmount`，旧版 EV 继续用含酯水解的 `dualAbs3CAmount`；不把本轮网络或新参数悄悄应用到旧路由。其他激素、注射、凝胶及贴片内核未改。

### 6.4 求解、采样和数值截尾

三池网络用对称变换、Jacobi 特征分解及解析吸收卷积，按参数缓存；相等速率用连续极限。
生命周期纳入最慢网络模态，并用 `ln(1e10)/min(rate)` 留数值余量，无 8/24 h 强制归零。
所有历史剂量保留峰值附近采样，新版增加 0.125/0.75/1.25/1.5/3 h 等点，不受末端 14 天预测窗干扰。
自动验证入口：`node --test scripts/test_pk_sublingual.mjs`。独立数值算法和回归测试仅验证实现，不等于临床有效性。

## 7) AUC 计算与稳态
- **AUC**：在 `SimulationEngine` 中对已合成的浓度轨迹采用梯形法积分得到（单位 `pg·h/mL`）。
- **稳态**：模型为线性系统（在当前常数 `k₃` 设定下），重复给药时叠加自然收敛至稳态。注射两库与贴片零阶输入也保持线性可叠加性。
- **注意**：由于本项目对若干参数做了经验缩放使 `Cmax/Tmax` 更贴近观测，AUC 的绝对值在不同路由间比较时需谨慎，适合作为同一路由下的相对比较与个体内优化。

---

## 8) 探索历程（摘记）
以下按时间线回顾，方便未来溯源与复现。时间基于内部项目记录与代码注释。

- **2025‑06**：完成三室解析解（注射/口服/凝胶的公共内核），最初版本采用单库吸收。实现 AUC 计算与 pg/mL 输出。
- **2025‑07‑中**：  
  - 贴片新增零阶输入路径，UI 支持 `releaseRateUGPerDay`。未提供标称时继续启用一阶近似。  
  - 舌下路由从“含服时长”降维到固定双通路分流 θ，以减少用户面板的负担并稳定曲线。（此做法已在 2025‑09‑22 废弃，见下文）
- **2025‑07‑末**：注射改为两库模型（`TwoPartDepotPK`），分别用 `k1_fast` 与 `k1_slow` 控制峰与尾；为贴合真实暴露，`formationFraction` 引入经验放大因子并与 `toE2Factor` 相乘作为 `F`。
- **2025‑08‑初**：  
  - 尝试“浓度反馈清除”（早期 hill/抑制式 k），在多事件叠加时出现不稳定与过拟合风险，回退为常数 `k₃` 并在注释中保留方案。  
  - 凝胶在进行“剂量/面积”非线性修正时出现系统性偏差（低剂量低估、高剂量高估），临时回退为 `(k₁ = 0.045, F = 0.05)` 常量实现，并在代码旁保留 `sigmaSat` 等参数以待重启。
- **2025‑08‑中**：统一由 `ParameterResolver` 把各路由映射到 `PKParams`，`SimulationEngine` 以事件窗口裁剪贴片贡献（`patchApply → patchRemove`），AUC 梯形法稳定。
- **2025‑09‑03**：  
  - 为注射路径加入 `CorePK.kClearInjection = 0.05 h⁻¹`，并在 `ParameterResolver` 中按路由切换 `k3`。  
  - 重新标定注射两库参数：`Frac_fast`、`k1_fast`、`k1_slow`（详见 2.2 表），以复现 EV ≈ 2.1 d、EC ≈ 4 d、EN ≈ 6.5 d 的单剂达峰与稳态形状。  
  - 更新 `InjectionPK.formationFraction` 为分酯别经验值（见 2.3），并在 README 中明确其“有效参数”属性与适用范围。
- **2025‑09‑22**：
  - 舌下：**废弃 RF→θ 的反推与固定 θ**；引入**行为驱动**的 θ 计算（显式建模溶解 $k_{\text{diss}}$ 与吞咽清除 $k_{\text{sw}}$），按 $T_{\text{hold}}$ 数值积分得到 \(\theta\)。
  - UI：移除 `theta_default`，改为**四档可选**（Quick/Casual/Standard/Strict），默认显示建议含服时长与推荐 θ。
  - 舌下 EV：两支路均加入水解 \(k_2\)，实现切换为 `dualAbs3CAmount`；舌下 E2 继续用 `dualAbsAmount`。
  - 一致性单元测试：验证 $\theta=0$ 时舌下与口服整轨迹重合（慢支参数与 Oral 路由完全一致）。
- **2026‑07‑06**：
  - 三室解析核 `_analytic3C` 的**可去奇点**处理修复：当任意两个速率常数（k₁/k₂/k₃）几乎相等时，旧实现直接返回 0（造成曲线掉零或数值抵消不稳）。新实现先用 `_separateRates` 将重合速率分开 ~1e‑6·max(k) 的极小量，使解析式收敛到正确的 l'Hôpital 极限。已用 RK4 数值积分交叉验证（最坏相对误差 < 5e‑6），且对默认参数曲线**零改动**（仅在校准清除网格 kMul∈[0.5,2] 扫过酯水解率 k₂ 等重合区才触发）。
  - 文档与代码对齐：`kClearInjection` 现记为默认 **0.041 h⁻¹**（t½ ≈ 16.9 h），口服 `kAbsE2` 记为 **0.32 h⁻¹**（与其 `Tmax ≈ 2–3 h` 一致），修正早前文档中的过时数值。
- **2026‑07‑21**：
  - 凝胶（E2）：吸收速率由经验常量 `k₁ = 0.022 h⁻¹` 改为按文献表观半衰期反推 `k₁ = ln(2)/36 ≈ 0.0193 h⁻¹`（见 §4.1）。
  - 凝胶（T）：修复部位选择器对睾酮凝胶无效的问题——此前无论选择手臂/大腿/阴囊，`t_gel_F` 恒为 0.10；现按部位区分为 `t_gel_arm`/`t_gel_thigh`/`t_gel_scrotal`（默认 0.10 / 0.10 / 0.50），阴囊值外推自 Iyer et al. 2017、Kuhnert et al. 2005 的睾酮凝胶部位对比数据。PK 自定义参数面板同步更新。
  - 凝胶（E2）阴囊/生殖器部位的 `e2_gel_scrotal` 由 0.40 调整为 0.25（约 5× 手臂/大腿），改为直接对齐 Premoli et al. 2005 阴囊贴片给药的实测倍数，而非睾酮凝胶类比的上限。
  - 移除了未使用的死代码常量 `GelSiteParams`（与 `_getGelBio`/`_activePKParams` 的实际实现重复且未被引用）。
  - UI：移除 Gel、Patch Apply、Patch Remove 路由标签与提示文案中的 "(Beta)" 标记及相应免责声明——上述路由的核心假设（零阶贴片以标称释放率为 `F=1.0`；凝胶按部位生物利用率）均可追溯到具体文献/官方说明书，不再视为实验性功能。`ester.EU`（十一酸雌二醇）保留 Beta 标记，因其人体药代数据仍非常有限（个体间差异可达 10 倍，终末半衰期未知）。

---

## 9) 参考与依据（部分）
下列仅列出常用且与实现高度相关的部分参考，非详尽清单。

**社区与技术文档**
- mtf.wiki：雌二醇凝胶（含经皮半衰期、实用注意事项）<https://mtf.wiki/zh-cn/docs/medicine/estrogen/gel>
- Transfem Science（含注射曲线汇总、舌下综述、不同途径比较等）
- Injectable E2 meta-analysis（注射曲线的非正式荟萃）<https://transfemscience.org/articles/injectable-e2-meta-analysis/>
- Sublingual estradiol overview（舌下作为替代途径的综述）<https://transfemscience.org/articles/sublingual-e2-transfem/>
- Approximate comparable doses（不同途径的近似等效剂量）<https://transfemscience.org/articles/e2-equivalent-doses/>
- Oral vs transdermal estradiol（口服与透皮比较）<https://transfemscience.org/articles/oral-vs-transdermal-e2/>
- estrannai.se：对于Injection的三室模型和Patch的相关算法参考<https://estrannai.se/docs/ingredients/>

**官方说明书/监管资料**
- Climara®（Bayer）说明书：移除贴片后约 12 h 回落至基线，表观半衰期约 4 h（FDA 标签）<https://www.accessdata.fda.gov/drugsatfda_docs/label/2001/20375s16lbl.pdf>
- FDA NDA 临床药理综述与产品手册：透皮相对口服的生物利用度、部位差异、周内曲线稳定性等（多份，示例）  
  <https://www.accessdata.fda.gov/drugsatfda_docs/nda/99/020994_clinphrmr.pdf>  
  <https://www.accessdata.fda.gov/drugsatfda_docs/label/2008/020375s026lbl.pdf>

**期刊/综述（示例）**
- Ginsburg ES et al. Half-life of estradiol in postmenopausal women. Fertil Steril. 1998：贴片移除后终末半衰期约 161 min（107–221 min）。<https://pubmed.ncbi.nlm.nih.gov/9473164/>
- Kuhl H. Pharmacology of estrogens and progestogens: influence of different routes of administration. *Climacteric*. 2005. <https://pubmed.ncbi.nlm.nih.gov/16112947/>
- Oinonen et al. / Järvinen et al. Absorption and bioavailability of oestradiol from a gel, a patch and a tablet. *Maturitas*. 1999：凝胶生物利用率为片剂的 61%、贴片的 109%。**这是相对值**，仅用于佐证量级（贴片一侧折算约 3.6%），不作为 `e2_gel_arm` 的依据。<https://pubmed.ncbi.nlm.nih.gov/10465378/>
- Premoli MC et al. Scrotal transdermal estradiol delivery, 2005：阴囊贴片给药雌二醇水平约为前臂给药的 5 倍。
- Iyer R et al. Pharmacokinetics of testosterone cream applied to scrotal skin. *Andrology*. 2017：阴囊皮肤睾酮吸收显著高于腹部。<https://onlinelibrary.wiley.com/doi/full/10.1111/andr.12357>
- Kuhnert B et al. Testosterone substitution with a new transdermal, hydroalcoholic gel applied to scrotal or non-scrotal skin. 2005：阴囊 vs 非阴囊皮肤睾酮凝胶吸收比较。
- transfemscience.org: Genital Application via the Scrotum and Neolabia for Greatly Enhanced Absorption of Transdermal Estradiol in Transfeminine People（汇总阴囊/外阴部位给药的证据与外推依据）<https://transfemscience.org/articles/genital-e2-application/>
- 比较矩阵与储库型贴片的生物利用度与速率差异的研究（如 Menorest® vs Estraderm®）。

**官方说明书（补充）**
- EstroGel® 0.06% (estradiol gel) FDA 说明书：表观终末消除半衰期 **36 h**（`k₁` 即取自此处）；1.25 g/day 稳态 Cavg 28.3 pg/mL。<https://www.accessdata.fda.gov/drugsatfda_docs/label/2024/021166s019lbl.pdf>
- Divigel® 0.1% (estradiol gel) FDA 说明书：表观终末半衰期 **10 h**（与 EstroGel 不一致）；每日涂抹于大腿于第 12 天达稳态；0.25/0.5/1.0 mg/day 稳态 Cavg 9.8/21/30.5 pg/mL（未做基线校正）。<https://www.accessdata.fda.gov/drugsatfda_docs/label/2007/022038lbl.pdf>
- 两份美国雌二醇凝胶说明书均**未**给出任何吸收百分比或生物利用率数字。
- Vivelle-Dot® / AndroGel® FDA 说明书：贴片按"体内标称递送速率"设计（0.025–0.1 mg/day），凝胶睾酮系统生物利用率约 10%。

**百科与药学数据库**
- Wikipedia: Pharmacokinetics of estradiol（路由差异、凝胶 36 h 表观半衰期等聚合条目）<https://en.wikipedia.org/wiki/Pharmacokinetics_of_estradiol>
- Wikipedia: Estradiol undecylate（人体药代数据有限、终末半衰期未知、个体差异可达 10 倍——`ester.EU` 保留 Beta 标记的依据）<https://en.wikipedia.org/wiki/Estradiol_undecylate>
- DrugBank: Estradiol（透皮生物利用度对比口服、部位差异）<https://go.drugbank.com/drugs/DB00783>

> 说明：实现中还参考了多份品牌说明书与审评文档、二级综述与数据手册，此处不一一列举。

---

## 10) 局限
- 个体差异未建模：肝功能、SHBG、年龄、体脂、并用药等可能改变 `F` 与各速率常数。
- 凝胶的面积/负荷非线性：当前未在模型中体现；存在低剂量低估与高剂量高估的潜在风险。
- 注射溶剂/体积影响：对扩散 `k₁` 的影响尚未显式参数化，现仅可用全局系数 `depotK1Corr` 近似。
- 口服 E2/EV 及新版舌下已含 E1/E1S 有效三池，但回转和首过分配仍是未临床拟合的先验；旧版舌下未纳入，其他结合物、肠肝延迟和组织分布未显式表示。
- AUC 的跨路由可比性有限：参数含经验缩放，AUC 适合于相同路由内的相对比较与个体内优化。

---

## 11) 快速对照：各路由实现要点

| 路由 | 解析/数值 | 输入 | 模型 | 关键参数 | F 的来源 |
| --- | --- | --- | --- | --- | --- |
| 注射（油剂 EB/EV/EC/EN） | 解析 | mg | 两库吸收 + k₂ 水解 + k₃ 清除 | `Frac_fast, k1_fast, k1_slow, k2, k3 (= kClearInjection)` | `formationFraction` |
| 贴片（零阶） | 解析 | µg/day → mg/h | 零阶恒速输入 + k₃ 清除；移除后指数衰减 | `rateMGh, k3` | 固定 1.0 |
| 贴片（一阶遗留） | 解析 | mg | 一阶“假库” + k₃ 清除；移除时截断 | `k1, k3` | 固定 1.0 |
| 凝胶 | 解析 | mg（+面积 cm²） | 单室 Bateman（临时常量版） | `k1 = 0.022, F = 0.05, k3` | 常量 0.05 |
| 口服 E2 | 解析网络卷积 | mg | E2/E1/E1S 三池 | `ka=0.32`，回转参数见 §6 | 0.03 为直接 E2 输入系数，不是总暴露 |
| 口服 EV | 解析网络卷积 | mg（分子量换算一次） | E2/E1/E1S 三池 | `ka=0.05`，仍需复核 | 0.03 为直接 E2 输入系数，不是总暴露 |
| 舌下 E2/EV | 解析 | mg（原药/酯，F 内换算） | 旧版见 §6.3；新版双吸收输入共享 E2/E1/E1S 三池 | 新版快 `ka=2.4`；慢与口服相同；`theta` 为经验档位 | 新版快 `0.28 × MW因子`；慢含 E2/E1/E1S 输入，详见 §6；非临床验证 |

---

## 12) 实现细节摘抄
- **PrecomputedEventModel**：
  - 注射：`injAmount(tau, dose, p)`
  - 凝胶和其他口服：`oneCompAmount(tau, dose, p)`；口服 E2/EV 使用三池 `compileE2` 卷积。
  - 旧版舌下：`dualAbsAmount` / `dualAbs3CAmount`；新版：快/慢输入分别编译到同一个三池响应。
- **贴片**：
  - 找到紧随的 `patchRemove` 决定 `wearH`。
  - 零阶：佩戴内 `rateMGh/k3 × (1 − e^{−k3 t})`；移除后按 `e^{−k3 Δt}` 衰减。
  - 一阶：用 `oneCompAmount` 计算佩戴内吸收；移除后把“如果继续吸收”的部分减掉，使吸收在 `wearH` 处截断。
- **SimulationEngine**：
  - 时间网格均匀划分，逐点累加各事件药量 → 换算 pg/mL。
  - **AUC**：梯形法累计。

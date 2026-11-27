# WebAI2PC / Cosmos Studio 设计系统规范 v2.0 (`system.md`)

## 1. 适用范围与四轴外观契约

本规范定义 WebAI2PC 本地控制中心（`/studio`）、OAuth 2.1 授权确认页（`/consent`）以及下游宣传视频共用的多风格可替换设计变量体系。`src/cosmos_mcp/studio/static/themes.css` 作为 `studio.css` 之上的无侵入变量覆盖层运行，通过 `<html>` 根节点上的 4 个正交属性控制整站外观与图形姿态：

1. `data-style-pack`：控制底材层级、边框锐度、同心圆角阶梯、阴影策略、主辅品牌色、顶栏滤镜材质、字体栈与缓动曲线。内置 `warm-paper`（默认）、`obsidian-emerald`、`cupertino-frost`、`graphite-mono` 四套正式风格包及 `custom` 扩展插槽。
2. `data-theme`：控制明暗模式（`light` 与 `dark`）。每套风格包均独立配齐明暗两套语义色值，若页面未显式挂载 `data-theme`，自动按系统 `prefers-color-scheme` 匹配对应风格包的明暗分支。
3. `data-ip-pack`：控制品牌区图形方案，支持 `orbit-bot`（默认星环双体）、`peel-terminal`（黑曜石翻页终端）、`minimal-glyph`（几何桥接符号）、`pixel-companion`（点阵终端伙伴）。
4. `data-ip-pose`：控制品牌图标中代理角色头部（`.ip-head-group`）与视线（`.ip-gaze-group`）的朝向姿态，支持 `front`（正视待命）、`bridge-right`（右视本地终端）、`cloud-left`（左视网页云端）、`nod-ready`（俯视确认就绪）。

## 2. 五项跨页面固定设计特征

在切换任意风格包时，以下结构与排版规则保持不变：

1. **双体桥接标志结构**：左侧网页 AI 宿主标识经中间数字 `2` 桥接至右侧本地 `>_` 终端，颜色读取 `--ip-body`、`--ip-bridge`、`--ip-term-bg` 等语义变量。
2. **跨标签常驻状态条**：HTTPS 通道状态、已授权会话数、当前安全档位与运行中任务计数在 5 个模块标签页顶部保持固定位置。
3. **连接通道渐进披露行**：通道当前启用状态与详情展开状态解耦，后台轮询刷新不收起用户正在编辑的配置区。
4. **同心圆角与内凹输入槽**：外层弹窗、内容卡片、内部提示框与输入按钮严格遵循 `外圆角 = 内圆角 + 内边距` 递减关系，输入框统一使用比卡片更深的 `--surface-inset` 填充。
5. **等宽数字防抖动**：端口号、6 位配对码、4 位核对码、秒数与统计徽标统一启用 `font-variant-numeric: tabular-nums`。

## 3. 内置 4 套正式风格包参数表

全部 4 套风格包在 `light` 与 `dark` 双模式下均满足正文/背景 WCAG 对比度 `>= 7.0:1`、辅助说明字/卡片对比度 `>= 4.5:1`、主按钮前景字/按钮底色对比度 `>= 4.5:1`。

### 3.1 `warm-paper`（暖纸松林 · 默认主风格）

- **设计取向**：温润纸质哑光卡片、同色系吸顶栏、内凹输入槽，低对比暖灰分隔细线。
- **亮色模式（`light`）**：`--bg: #F7F6F2`、`--surface: #FFFFFF`、`--surface-alt: #FAF9F5`、`--surface-inset: #EFECE4`、`--border: #E2DFD5`、`--text: #14181F`、`--text-secondary: #3A414E`、`--muted: #58606E`、`--primary: #1F6E58`、`--on-primary: #FFFFFF`、`--bridge-amber: #E9A820`。
- **暗色模式（`dark`）**：`--bg: #0E1116`、`--surface: #161B22`、`--surface-alt: #1C2129`、`--surface-inset: #0B0E13`、`--border: #262C36`、`--text: #F0F6FC`、`--text-secondary: #C9D1D9`、`--muted: #8E97A2`、`--primary: #34A080`、`--on-primary: #041510`、`--bridge-amber: #F4BE4F`。
- **几何与材质**：同心圆角 `14px / 12px / 9px / 7px`，顶栏滤镜 `saturate(155%) blur(14px)`，亮色双层微阴影，暗色无投影细线层级。

### 3.2 `obsidian-emerald`（黑曜石翠绿 · 极客终端风）

- **设计取向**：冷调石板浅底与黑曜石深空底色，翡翠绿主行动色搭配天际蓝桥接色，激活卡片带终端微光描边。
- **亮色模式（`light`）**：`--bg: #F4F7FB`、`--surface: #FFFFFF`、`--surface-alt: #EEF3F9`、`--surface-inset: #E6EDF6`、`--border: #D5E0EE`、`--text: #0B1320`、`--text-secondary: #334155`、`--muted: #526075`、`--primary: #009E68`、`--on-primary: #02130C`、`--link-accent: #00754C`、`--bridge-amber: #0284C7`。
- **暗色模式（`dark`）**：`--bg: #060B13`、`--surface: #0D1522`、`--surface-alt: #121C2D`、`--surface-inset: #04080E`、`--border: #1B2940`、`--text: #F1F5F9`、`--text-secondary: #CBD5E1`、`--muted: #94A3B8`、`--primary: #00E5A3`、`--on-primary: #031610`、`--link-accent: #00E5A3`、`--bridge-amber: #38BDF8`。
- **几何与材质**：同心圆角 `12px / 10px / 8px / 6px`，顶栏滤镜 `saturate(150%) blur(14px)`，代码栈优先启用 `JetBrains Mono` 与 `Cascadia Mono`。

### 3.3 `cupertino-frost`（清冽原生 · 桌面系统设置风）

- **设计取向**：桌面操作系统偏好设置面板风格，高饱和半透明毛玻璃吸顶栏与柔和层叠卡片。
- **亮色模式（`light`）**：`--bg: #F5F5F7`、`--surface: #FFFFFF`、`--surface-alt: #F0F0F4`、`--surface-inset: #E8E8ED`、`--border: rgba(29, 29, 31, 0.10)`、`--text: #1D1D1F`、`--text-secondary: #3A3A3E`、`--muted: #5C5C62`、`--primary: #0071E3`、`--on-primary: #FFFFFF`、`--link-accent: #0066CC`、`--bridge-amber: #5856D6`。
- **暗色模式（`dark`）**：`--bg: #1C1C1E`、`--surface: #262629`、`--surface-alt: #2E2E32`、`--surface-inset: #141416`、`--border: rgba(245, 245, 247, 0.11)`、`--text: #F5F5F7`、`--text-secondary: #D1D1D6`、`--muted: #9E9EA6`、`--primary: #0A84FF`、`--on-primary: #031122`、`--link-accent: #52A8FF`、`--bridge-amber: #5E5CE6`。
- **几何与材质**：同心圆角 `16px / 12px / 9px / 8px`，顶栏滤镜 `saturate(180%) blur(16px)`，亮色柔和双层漫射阴影。

### 3.4 `graphite-mono`（极简石墨 · 高密度工程台）

- **设计取向**：纯线框零浮夸阴影，紧凑硬朗圆角，墨黑与交互蓝高对比主按钮配青紫信号色。
- **亮色模式（`light`）**：`--bg: #FAFAFA`、`--surface: #FFFFFF`、`--surface-alt: #F4F4F5`、`--surface-inset: #ECECEE`、`--border: #E4E4E7`、`--text: #09090B`、`--text-secondary: #27272A`、`--muted: #52525B`、`--primary: #18181B`、`--on-primary: #FFFFFF`、`--link-accent: #18181B`、`--bridge-amber: #6366F1`。
- **暗色模式（`dark`）**：`--bg: #09090B`、`--surface: #121215`、`--surface-alt: #18181C`、`--surface-inset: #050507`、`--border: #27272A`、`--text: #FAFAFA`、`--text-secondary: #D4D4D8`、`--muted: #9696A0`、`--primary: #2563EB`、`--on-primary: #FFFFFF`、`--link-accent: #60A5FA`、`--bridge-amber: #6366F1`。
- **几何与材质**：同心圆角 `8px / 6px / 5px / 4px`，`--shadow-sm: none`，`--card-shadow: none`，激活态采用 `1px` 内嵌实线框。

## 4. 现役 `studio.css` 与 `consent.html` 变量全量映射表

`themes.css` 完整覆盖 `studio.css` 的全部 61 个原生变量，并新增 15 个正交控制变量与 `consent.html` 兼容别名：

| 变量分组 | `studio.css` 现役变量名 | `themes.css` 扩展与跨页兼容变量 | 消费组件位置 |
| :--- | :--- | :--- | :--- |
| 底材与表面层级 | `--bg`, `--surface`, `--surface-glass`, `--surface-alt`, `--surface-inset`, `--modal-surface`, `--modal-scrim`, `--term-bg`, `--term-fg` | `--surface-elevated`, `--surface-solid`, `--surface-subtle`, `--control-bg` | 页面画布、`.card`、`.top-header`、`input/select`、`.appearance-popover`、`.log-viewer` |
| 次级控件底色 | `--secondary-btn`, `--secondary-btn-soft`, `--secondary-btn-hover`, `--segmented-track`, `--switch-off` | 无新增（随风格包底材同步偏移） | `.btn`、`.tabs-nav`、`.host-seg-bar`、`.apple-switch`、`.ip-pose-seg` |
| 边框体系 | `--border`, `--border-strong` | `--header-border`, `--border-hairline`, `--border-input` | 卡片外框、表格线、输入框边框、顶栏底部分隔线 |
| 四级文字层级 | `--text`, `--text-secondary`, `--muted` | `--text-tertiary`, `--on-primary` | 标题正文、表单标签、次要说明、`.btn-primary` 与 `.wake-banner-btn` 前景字 |
| 品牌与桥接强调 | `--primary`, `--primary-hover`, `--link-accent`, `--primary-soft`, `--primary-ring`, `--bridge-amber`, `--bridge-amber-soft` | `--brand`, `--brand-hover`, `--brand-soft`, `--brand-border`, `--amber`, `--accent` | 主按钮、聚焦光环、选中胶囊、`WebAI2PC` 数字 `2`、未保存提示框 |
| 语义状态与风险标签 | `--ok*` (5), `--edit*` (4), `--warn*` (4), `--danger*` (4), `--cat-ro-*` (3), `--cat-wr-*` (3), `--cat-ex-*` (3) | `--green`, `--red` | `.status-badge`、`.callout`、`.tag-cat-readonly/write/exec`、Diff 着色 |
| 圆角、阴影、材质与动效 | `--radius-xl`, `--radius-lg`, `--radius-md`, `--radius-sm`, `--shadow-sm`, `--shadow-seg`, `--ease-out`, `--font-sans`, `--font-mono` | `--radius-xs`, `--header-backdrop`, `--card-shadow`, `--card-active-shadow`, `--popover-shadow`, `--ease-in-out`, `--press-scale` | 全站卡片、按钮、顶栏 `backdrop-filter`、切换器浮层与按压回弹 |
| 品牌图形语义槽 | 无（旧版 SVG 内联硬编码色值） | `--ip-body`, `--ip-eye`, `--ip-orbit`, `--ip-bridge`, `--ip-bridge-fg`, `--ip-term-bg`, `--ip-term-fg`, `--ip-slot`, `--ip-gemini`, `--ip-chatgpt` | `.brand-mark-svg` 及多套 `data-ip-pack` 图标变体 |

## 5. 外观切换器组件与 IP 微转向交互规范

### 5.1 跨页面外观切换器类名契约

- 容器与触发器：`.appearance-switcher-wrap` 包裹 `.appearance-trigger-btn`（设置 `aria-expanded="true|false"`）与浮层 `.appearance-popover`。
- 浮层显隐：`.appearance-popover` 在附加 `.open`（或 `.is-open`、`[data-open="true"]`、触发按钮 `aria-expanded="true"` 且无 `[hidden]`）时展开；桌面端（`1440px`）右对齐定宽 `304px`，手机窄屏（`<= 640px`，含 `390px` 视口）切换为 `position: fixed; left: 12px; right: 12px; max-width: calc(100vw - 24px)` 贴边自适应面板，消除横向滚动条溢出。
- 内部选择器：分区标题使用 `.appearance-section-label`；风格包双列网格使用 `.style-pack-grid > .style-pack-option` 搭配三色圆点 `.style-swatch-dots`；IP 图标双列网格使用 `.ip-pack-grid > .ip-pack-option`；转向姿态分段器使用 `.ip-pose-seg > .ip-pose-btn`；底部宣传片参数导出按钮使用 `.appearance-export-btn`。

### 5.2 IP 转向微交互与无障碍降级

- `.brand-mark-svg .ip-head-group` 与 `.brand-mark-svg .ip-gaze-group` 锁定 `transform-box: fill-box; transform-origin: center;`，仅对 `transform` 与 `opacity` 执行 `180ms cubic-bezier(0.23, 1, 0.32, 1)` 过渡，不触发布局重排。
- 在 `@media (prefers-reduced-motion: reduce)` 下，`.ip-gaze-group`、`.ip-head-group`、光标闪烁与浮层入场动画全部关闭（`animation: none !important; transition: none !important;`）。

## 6. 新增第 N 套风格包步骤与 18 核心 Token 模板

第三方主题或下游宣传片只需准备以下 18 个核心语义 Token 的 JSON 配置，既可通过运行时注入 `--custom-*` 变量激活 `data-style-pack="custom"`，也可按同名变量段追加为 `themes.css` 中的具名风格包：

```json
{
  "id": "custom",
  "name": "自定义风格示例",
  "mode": "light",
  "tokens": {
    "bg": "#F7F6F2",
    "surface": "#FFFFFF",
    "surfaceAlt": "#FAF9F5",
    "surfaceInset": "#EFECE4",
    "surfaceGlass": "rgba(247, 246, 242, 0.90)",
    "headerBackdrop": "saturate(155%) blur(14px)",
    "border": "#E2DFD5",
    "borderStrong": "#CFCBC0",
    "text": "#14181F",
    "textSecondary": "#3A414E",
    "muted": "#58606E",
    "primary": "#1F6E58",
    "primaryHover": "#175644",
    "onPrimary": "#FFFFFF",
    "linkAccent": "#1B634F",
    "accent": "#E9A820",
    "radiusLg": "12px",
    "shadowSm": "0 1px 2px rgba(20, 24, 31, 0.04)"
  }
}
```

### 接入与校验三步流程

1. **挂载变量**：将 JSON 中 `tokens` 的 18 个驼峰键名转为短横线前缀 `--custom-<kebab-key>`（例如 `surfaceInset` 对应 `--custom-surface-inset`，`onPrimary` 对应 `--custom-on-primary`），写入 `document.documentElement.style`，并设置 `document.documentElement.dataset.stylePack = "custom"`；其余 40 余个次级背景、浅色光环与同心圆角由 `themes.css` 通过回退链与 `color-mix()` 自动推导。
2. **校验对比度门禁**：核验 `text` 对 `bg`/`surface` 对比度 `>= 7.0:1`，`textSecondary` 与 `muted` 对 `surface`/`surfaceInset` 对比度 `>= 4.5:1`，`onPrimary` 对 `primary` 对比度 `>= 4.5:1`。
3. **固化具名风格包（可选）**：若需沉淀为内置第 5 套预设，将对应键值复制为 `:root[data-style-pack="<pack-id>"][data-theme="light|dark"]` 规则段并加入外观切换器选项列表。

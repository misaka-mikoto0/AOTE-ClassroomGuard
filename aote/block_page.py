"""
AOTE 管控系统 - 浏览器拦截页（表现层）

单独成模块的原因：页面样式属于"表现层"，与沙盒的拦截逻辑解耦后，
调样式不必改动 browser_sandbox.py 的业务代码；两处使用点（路由层 403
响应、页面内 JS 注入）也共用同一份模板，避免两份样式各自漂移。

设计要点：
- 视觉：柔和浅色渐变底 + 低透明度光斑，杜绝高对比刺眼；跟随系统深色模式
- 层级：图标徽标 -> 主提示（唯一视觉焦点）-> 说明 -> 状态胶囊 -> 补充提示 -> 操作
- 质感：顶部渐变装饰条、柔和投影、渐变圆形徽标、内联 SVG 图标
        （不用 emoji——不同系统的 emoji 字形与字号差异大，容易破坏排版）
- 响应式：尺寸全部走 clamp() + flex，手机与桌面共用一套，无需媒体断点
- 依赖：零外部资源（不加载字体 / CDN / 图片），离线可用且不受页面 CSP 影响
"""

# 样式表：完整一套（浅色 + 深色 + 交互态 + 无障碍动效降级）
BLOCK_PAGE_STYLE = """<style>
  *,*::before,*::after{box-sizing:border-box}
  :root{
    --bg-1:#f7f9fd; --bg-2:#eef3fb; --bg-3:#f6f1fa;
    --card:#ffffff;
    --ink:#1e2a44; --ink-2:#566682; --ink-3:#8894a8;
    --line:rgba(30,42,68,.08);
    --accent:#5b8def; --accent-2:#8f7cf0;
    --chip-bg:rgba(91,141,239,.10); --chip-ink:#3f6fd8;
    --ring:rgba(91,141,239,.20);
    --halo:rgba(143,124,240,.14);
    --shadow:0 20px 55px rgba(30,42,68,.10), 0 2px 8px rgba(30,42,68,.04);
    --btn-shadow:0 1px 2px rgba(30,42,68,.06);
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg-1:#0f1621; --bg-2:#131c2a; --bg-3:#171427;
      --card:#161f2d;
      --ink:#e9eef7; --ink-2:#a8b5c9; --ink-3:#7d8ba1;
      --line:rgba(255,255,255,.08);
      --accent:#7aa2f7; --accent-2:#a78bfa;
      --chip-bg:rgba(122,162,247,.14); --chip-ink:#a9c4fb;
      --ring:rgba(122,162,247,.26);
      --halo:rgba(167,139,250,.16);
      --shadow:0 20px 55px rgba(0,0,0,.46), 0 2px 8px rgba(0,0,0,.30);
      --btn-shadow:0 1px 2px rgba(0,0,0,.35);
    }
  }
  html,body{height:100%}
  body{
    margin:0;
    min-height:100vh; min-height:100dvh;
    display:flex; align-items:center; justify-content:center;
    padding:clamp(16px,4vw,40px);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",
                "Hiragino Sans GB","Microsoft YaHei","Source Han Sans SC",sans-serif;
    font-size:16px; line-height:1.7; color:var(--ink);
    background:
      radial-gradient(900px 480px at 12% -10%, var(--ring), transparent 60%),
      radial-gradient(760px 420px at 92% 112%, var(--halo), transparent 62%),
      linear-gradient(158deg, var(--bg-1), var(--bg-2) 48%, var(--bg-3));
    background-attachment:fixed;
    -webkit-font-smoothing:antialiased;
    -moz-osx-font-smoothing:grayscale;
    text-rendering:optimizeLegibility;
  }
  .aote-card{
    position:relative;
    width:100%; max-width:min(92vw,560px);
    padding:clamp(28px,6vw,52px) clamp(22px,5.4vw,48px);
    background:var(--card);
    border:1px solid var(--line);
    border-radius:clamp(18px,3.2vw,26px);
    box-shadow:var(--shadow);
    text-align:center;
    overflow:hidden;
  }
  /* 顶部渐变装饰条：点出"管控中"的产品调性，不喧宾夺主 */
  .aote-card::before{
    content:""; position:absolute; top:0; left:0; right:0; height:4px;
    background:linear-gradient(90deg,var(--accent),var(--accent-2));
  }
  .aote-badge{
    width:clamp(62px,15vw,78px); height:clamp(62px,15vw,78px);
    margin:0 auto clamp(16px,3.4vw,22px);
    display:flex; align-items:center; justify-content:center;
    border-radius:50%; color:#fff;
    background:linear-gradient(140deg,var(--accent),var(--accent-2));
    box-shadow:0 12px 26px rgba(91,141,239,.26),
               inset 0 1px 0 rgba(255,255,255,.34);
  }
  .aote-badge svg{width:54%; height:54%; display:block}
  .aote-title{
    margin:0 0 clamp(10px,2.2vw,14px);
    font-size:clamp(21px,4.6vw,29px);
    font-weight:600; letter-spacing:.02em; color:var(--ink);
    line-height:1.35;
  }
  .aote-lead{
    margin:0 auto; max-width:31em;
    font-size:clamp(13.5px,2.6vw,15.5px);
    color:var(--ink-2);
  }
  .aote-chip{
    display:inline-flex; align-items:center; gap:8px;
    margin-top:clamp(18px,3.6vw,24px);
    padding:7px 16px; border-radius:999px;
    background:var(--chip-bg); color:var(--chip-ink);
    font-size:clamp(12px,2.3vw,13px); font-weight:500;
    letter-spacing:.01em;
  }
  .aote-chip .dot{
    width:6px; height:6px; border-radius:50%;
    background:currentColor; opacity:.8;
  }
  .aote-hint{
    margin:clamp(18px,3.6vw,24px) 0 0;
    padding-top:clamp(16px,3.2vw,20px);
    border-top:1px solid var(--line);
    font-size:clamp(12.5px,2.3vw,13.5px);
    color:var(--ink-3);
  }
  .aote-actions{
    display:flex; gap:12px; justify-content:center; flex-wrap:wrap;
    margin-top:clamp(18px,3.6vw,24px);
  }
  .aote-btn{
    appearance:none; -webkit-appearance:none;
    font:inherit; font-size:clamp(13px,2.5vw,14.5px); font-weight:500;
    padding:clamp(10px,2.2vw,12px) clamp(18px,4vw,26px);
    color:var(--ink-2); background:var(--card);
    border:1px solid var(--line); border-radius:12px;
    box-shadow:var(--btn-shadow); cursor:pointer;
    transition:background-color .2s ease, color .2s ease,
               border-color .2s ease, box-shadow .2s ease, transform .12s ease;
  }
  .aote-btn:hover{
    color:var(--ink);
    background:var(--chip-bg);
    border-color:var(--ring);
  }
  .aote-btn:active{transform:translateY(1px) scale(.99)}
  .aote-btn:focus-visible{outline:none; box-shadow:0 0 0 3px var(--ring)}
  @media (prefers-reduced-motion: reduce){
    .aote-btn{transition:none}
    .aote-btn:active{transform:none}
  }
  @media (max-width:360px){
    .aote-actions{flex-direction:column}
    .aote-btn{width:100%}
  }
</style>"""

# 内容主体：徽标（盾牌 + 停止横杠，克制不吓人）+ 分层文案 + 操作按钮
BLOCK_PAGE_BODY = """<div class="aote-card">
  <div class="aote-badge" aria-hidden="true">
    <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M24 5.5 40 11.6v12.9c0 9.2-6.3 15.4-16 18.9-9.7-3.5-16-9.7-16-18.9V11.6z"
            stroke="currentColor" stroke-width="2.8" stroke-linejoin="round"/>
      <path d="M17.2 24.4h13.6" stroke="currentColor" stroke-width="2.8"
            stroke-linecap="round"/>
    </svg>
  </div>
  <h1 class="aote-title">该网站已被管控</h1>
  <p class="aote-lead">当前处于受管控时段，娱乐类内容已暂停访问。请专注于学习内容。</p>
  <div class="aote-chip"><span class="dot"></span>AOTE 浏览器内容管控</div>
  <p class="aote-hint">如确为学习需要访问该站点，请联系管理员临时放行。</p>
  <div class="aote-actions">
    <button class="aote-btn" type="button"
            onclick="try{if(history.length&gt;1){history.back()}}catch(e){}">返回上一页</button>
  </div>
</div>"""

# 路由层 403 响应：完整文档（带 viewport，移动端按设备宽度渲染）
DEFAULT_BLOCKED_PAGE = (
    '<!DOCTYPE html>\n<html lang="zh-CN"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
    '<title>网站已被管控</title>'
    + BLOCK_PAGE_STYLE
    + '</head><body>\n'
    + BLOCK_PAGE_BODY
    + '\n</body></html>'
)

# 页面内 JS 注入：head + body 片段（用于替换 document.documentElement.innerHTML）
BLOCK_PAGE_FRAGMENT = (
    '<head><meta charset="utf-8"><title>网站已被管控</title>'
    + BLOCK_PAGE_STYLE
    + '</head><body>' + BLOCK_PAGE_BODY + '</body>'
)

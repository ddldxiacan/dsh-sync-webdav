/**
 * DSH Sync · Client 半区（Web 设置页配置卡片）
 *
 * 注册进宿主已声明的 slot `settings.section`（kind: list, scope: root），
 * 在设置面板里占一个独立页「配置同步（WebDAV）」。
 *
 * loader id 必须等于 package.json 的 name（dsh-sync-webdav）；HTTP 路径前缀、
 * 配置文件名、快照目录名仍沿用 `dsh-sync`，改名不影响接口与磁盘布局。
 *
 * 与 Host 半区（index.js）通过 HTTP 端点通信，契约冻结：
 *   GET  /dsh-sync/status                          -> { configured, config:{url,username,password,remoteDir,hasPassword,hasPassphrase}|null,
 *                                                        remote:{reachable,backups[{name,size,modified,remoteDir,encrypted}],latest?}, lastLocalSnapshot?, error? }
 *   POST /dsh-sync/config   {url,username,password,remoteDir} -> { ok:true } | { ok:false, error }
 *   POST /dsh-sync/passphrase {passphrase}|{clear:true} -> { ok:true, hasPassphrase } | { ok:false, error }
 *   POST /dsh-sync/backup   {passphrase?, remember?} -> { ok:true, name, size, fileCount, scope, pruned } | { ok:false, error }
 *   POST /dsh-sync/restore  {name?, remoteDir?, passphrase?, remember?} -> { ok:true, restored, snapshot, portability? } | { ok:false, error }
 *   POST /dsh-sync/rollback {snapshot}              -> { ok:true, restored }              | { ok:false, error }
 *   POST /dsh-sync/delete   {name, remoteDir?}|{names} -> { ok:true, deleted[] }          | { ok:false, error, deleted?, failed? }
 *   GET  /dsh-sync/plugins                          -> { ok:true, profile, deps[], missing[], needsInstall, pnpm }
 *   POST /dsh-sync/plugins/install {}               -> { ok:true, installed[], rewritten{}, removed[], durationMs, log } | { ok:false, error, log }
 *   GET  /dsh-sync/version[?force=1]                -> { ok:true, current, mode:'dev'|'managed', kind, spec, repo, hasUpdate,
 *                                                        latest, changelog[], checkedAt, checked, currentSha, latestSha, error }
 *   POST /dsh-sync/upgrade  {}                      -> { ok:true, from, to, upgraded, alreadyLatest?, spec, exitCode, durationMs, needRestart,
 *                                                        before, backup, log, error } | { ok:false, error, log?, restored? }
 * 所有响应 HTTP 200，按 `ok` 字段判断成败；错误统一在 `error` 字段。
 *
 * version 端点两条语义约定（宿主以 git commit sha 比较为主，不靠 semver）：
 *   - `hasUpdate` 是唯一权威判据，客户端不自行比较版本大小；
 *   - `latest` 不保证是 semver：有 tag 时如 "v0.2.0"，无 tag 时是远端短 sha，一律原样渲染。
 * /plugins 失败时是 { ok:false, error }（HTTP 仍 200），必须看返回体的 ok，不能依赖 res.ok。
 *
 * 约束：无 npm 依赖、无构建步骤、ESM 形态的 IIFE 包；不 require 任何
 * `@deepseek-ai/dsh-client-*` 包（宿主明确警告其不稳定，抛错会白屏整个 slot），
 * 控件自写、样式只用 `--dsw-alias-*` 主题令牌。fail-soft：端点不可用时
 * 显示「插件服务未就绪」，不抛错、不白屏。
 */

window.__ModuleLoader__.load({
  id: 'dsh-sync-webdav',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useState, useEffect, useRef, useCallback } = React;

    // ============================================================
    // 常量
    // ============================================================

    const BASE = '/dsh-sync';
    const PREFIX = 'dsh-sync';

    /** 端点不可达 / 未注册（插件 Host 半区未加载或未注册路由）时的统一文案。 */
    const NOT_READY = '插件服务未就绪：请确认本机已安装 dsh-sync-webdav 插件（与备份同版本）并重启 DeepSeek Harness';

    const CONFIG_FIELDS = [
      { key: 'url', label: 'WebDAV URL', placeholder: '例如 https://dav.example.com/dav/', type: 'text' },
      { key: 'username', label: '用户名', placeholder: '例如 user', type: 'text' },
      { key: 'password', label: '密码', placeholder: '保存后会回显为圆点', type: 'password' },
      { key: 'remoteDir', label: '远程目录', placeholder: '建议 dsh-sync；留空是网盘根目录，改完要点保存', type: 'text' },
    ];

    // ============================================================
    // 纯工具（不依赖 React，便于静态自检）
    // ============================================================

    /** 字节数的可读展示。 */
    function formatSize(bytes) {
      if (bytes === null || bytes === undefined || bytes === '') return '—';
      const n = Number(bytes);
      if (!isFinite(n) || n < 0) return '—';
      if (n < 1024) return n + ' B';
      if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
      return (n / 1024 / 1024).toFixed(2) + ' MB';
    }

    /** 远端 modified 可能是 ISO 串或 RFC1123（PROPFIND getlastmodified），统一本地化展示。 */
    function formatTime(value) {
      if (!value) return '—';
      const d = new Date(value);
      if (isNaN(d.getTime())) return String(value);
      const p = (x) => String(x).padStart(2, '0');
      return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
        ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
    }

    /** 相对时间：刚刚 / N 分钟前 / N 小时前 / N 天前；过久或不可解析时退回绝对时间。 */
    function formatRelTime(value, now) {
      if (!value) return '';
      const t = new Date(value).getTime();
      if (isNaN(t)) return '';
      const gap = (typeof now === 'number' ? now : Date.now()) - t;
      if (gap < 60 * 1000) return '刚刚';
      const min = Math.floor(gap / 60000);
      if (min < 60) return min + ' 分钟前';
      const hours = Math.floor(min / 60);
      if (hours < 24) return hours + ' 小时前';
      const days = Math.floor(hours / 24);
      if (days < 30) return days + ' 天前';
      return formatTime(value);
    }

    /** 与 Host 一致：空字符串表示网盘根目录。 */
    function normalizeDir(dir) {
      return String(dir || '').trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    }

    function locationLabel(remoteDir) {
      const d = normalizeDir(remoteDir);
      return d || '根目录';
    }

    /** 列表标题：同账号合并后的份数，以及是否加了口令。 */
    function backupSummary(backups) {
      const list = Array.isArray(backups) ? backups : [];
      const encrypted = list.filter((b) => !b || b.encrypted !== false).length;
      const plain = list.length - encrypted;
      if (!list.length) return '远端暂无备份条目';
      if (plain === 0) return '远端备份（' + list.length + '，全部已用口令加密）';
      return '远端备份（' + list.length + '，' + encrypted + ' 份已加密，' + plain + ' 份未加密）';
    }

    /** 短 sha 展示：40 位 hex 截 7 位，已是短 sha 的原样。 */
    function shortSha(value) {
      const s = String(value == null ? '' : value).trim();
      return s.length > 7 ? s.slice(0, 7) : s;
    }

    /**
     * 版本端点响应的归一化。只接受契约内的形状（ok:true + 字符串 current + 枚举 mode），
     * 其余一律当作「读不到版本状态」——与插件依赖卡片同样静默降级，不影响其它卡片。
     * currentSha / latestSha 可能为 null，必须容错。
     */
    function normalizeVersion(payload) {
      const d = (payload && typeof payload === 'object') ? payload : null;
      if (!d || d.ok !== true) return null;
      if (typeof d.current !== 'string' || !d.current) return null;
      if (d.mode !== 'dev' && d.mode !== 'managed') return null;
      return {
        current: d.current,
        mode: d.mode,
        kind: typeof d.kind === 'string' ? d.kind : 'unknown',
        spec: typeof d.spec === 'string' ? d.spec : '',
        repo: (typeof d.repo === 'string' && d.repo) ? d.repo : null,
        hasUpdate: d.hasUpdate === true,
        latest: (typeof d.latest === 'string' && d.latest) ? d.latest : null,
        changelog: Array.isArray(d.changelog) ? d.changelog.filter((x) => typeof x === 'string') : [],
        checkedAt: (typeof d.checkedAt === 'string' && d.checkedAt) ? d.checkedAt : null,
        currentSha: (typeof d.currentSha === 'string' && d.currentSha) ? d.currentSha : null,
        latestSha: (typeof d.latestSha === 'string' && d.latestSha) ? d.latestSha : null,
        error: (typeof d.error === 'string' && d.error) ? d.error : null,
      };
    }

    /**
     * 从响应体里取错误文案。Host 端契约把错误放在 `error` 字段（HTTP 恒 200）；
     * status 端点在 body 里给 `error` 但不带 `ok`。两者都要覆盖。
     */
    function pickError(payload, fallback) {
      if (payload && typeof payload.error === 'string' && payload.error) return payload.error;
      return fallback || '未知错误';
    }

    /**
     * 安装结果摘要：装了什么、改写了哪些来源、跳过了哪些、耗时，并提醒重启。
     * rewritten 是 { 包名: 改写后的依赖声明 } 映射。
     */
    function formatInstallResult(d) {
      const data = d || {};
      const installed = Array.isArray(data.installed) ? data.installed : [];
      const removed = Array.isArray(data.removed) ? data.removed : [];
      const rewritten = (data.rewritten && typeof data.rewritten === 'object') ? data.rewritten : {};
      const names = Object.keys(rewritten);
      const parts = [installed.length
        ? '已安装 ' + installed.length + ' 个（' + installed.join('、') + '）'
        : '没有新增安装'];
      if (names.length) parts.push('已改写 ' + names.map((n) => n + ' → ' + rewritten[n]).join('、'));
      if (removed.length) parts.push('已跳过 ' + removed.join('、'));
      const ms = Number(data.durationMs);
      if (isFinite(ms) && ms >= 0) parts.push('耗时 ' + (ms / 1000).toFixed(1) + ' 秒');
      return '插件重装完成：' + parts.join('；') + '。请重启 DeepSeek Harness 使插件生效。';
    }

    /**
     * 唯一网络出口。任何失败都收敛成 { ok:false, offline:boolean, error }，
     * 绝不把异常抛给渲染层。
     *
     * offline=true 表示「插件服务未就绪」：网络层直接失败（插件未加载、
     * 宿主不可达），或端点返回 404（路由未注册）。
     */
    async function request(path, options) {
      const opts = options || {};
      let res;
      try {
        res = await fetch(BASE + path, {
          method: opts.method || 'GET',
          headers: opts.body ? { 'Content-Type': 'application/json' } : undefined,
          body: opts.body ? JSON.stringify(opts.body) : undefined,
        });
      } catch (e) {
        return { ok: false, offline: true, error: NOT_READY };
      }
      if (res.status === 404) return { ok: false, offline: true, error: NOT_READY };
      let payload = null;
      try {
        payload = await res.json();
      } catch (e) {
        return { ok: false, offline: false, error: '响应不是合法 JSON（HTTP ' + res.status + '）' };
      }
      if (!res.ok) {
        return { ok: false, offline: false, error: pickError(payload, 'HTTP ' + res.status) };
      }
      return { ok: true, data: payload };
    }

    /** GET /dsh-sync/status —— 成功时返回 status 对象本身（它不以 ok 字段为载体）。 */
    const fetchStatus = () => request('/status');

    /** 9 个端点的语义化包装：统一返回 { ok, ... }，ok 时附带 data。 */
    const api = {
      status: fetchStatus,
      config: (body) => request('/config', { method: 'POST', body }),
      backup: (body) => request('/backup', { method: 'POST', body }),
      passphrase: (body) => request('/passphrase', { method: 'POST', body }),
      restore: (body) => request('/restore', { method: 'POST', body }),
      rollback: (body) => request('/rollback', { method: 'POST', body }),
      remove: (body) => request('/delete', { method: 'POST', body }),
      // 这两个端点的业务失败也是 HTTP 200，成败要看返回体里的 ok 字段
      plugins: () => request('/plugins'),
      pluginsInstall: (body) => request('/plugins/install', { method: 'POST', body }),
      // force=1 跳过宿主 10 分钟检查缓存
      version: (force) => request('/version' + (force ? '?force=1' : '')),
      upgrade: (body) => request('/upgrade', { method: 'POST', body }),
    };

    // ============================================================
    // 样式：随组件挂载/卸载（React 元素），只用 --dsw-alias-* 令牌
    // ============================================================

    // 只用宿主真实存在的 --dsw-alias-* 令牌（已对 @deepseek-ai 全部包核对过）：
    // 文本 label-*、边框 border-l*、底 bg-l*、状态 state-*、强调 brand-primary。
    // 令牌名写错只会降级外观、不会崩渲染，但仍按真实名录书写。
    const CSS = `
.${PREFIX}-root { display: flex; flex-direction: column; gap: 16px; padding: 4px 2px 24px; font-size: 13px; color: var(--dsw-alias-label-primary); }
.${PREFIX}-card { border: 1px solid var(--dsw-alias-settings-card-stroke, var(--dsw-alias-border-l2)); border-radius: 8px; padding: 14px 16px; display: flex; flex-direction: column; gap: 10px;
  background: var(--dsw-alias-settings-card-fill, var(--dsw-alias-bg-l1)); }
.${PREFIX}-card-title { font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.${PREFIX}-hint { color: var(--dsw-alias-label-tertiary); font-size: 12px; line-height: 1.6; }
.${PREFIX}-check { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--dsw-alias-label-secondary); }
.${PREFIX}-check input { margin: 0; }
.${PREFIX}-grid { display: flex; flex-direction: column; gap: 8px; }
.${PREFIX}-field { display: grid; grid-template-columns: 96px 1fr; align-items: center; gap: 8px; }
.${PREFIX}-field label { color: var(--dsw-alias-label-secondary); }
.${PREFIX}-input { width: 100%; box-sizing: border-box; padding: 6px 8px; border-radius: 6px; font: inherit; color: var(--dsw-alias-label-primary);
  border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-l2); }
.${PREFIX}-input:focus { outline: none; border-color: var(--dsw-alias-brand-primary); }
.${PREFIX}-input:disabled { opacity: .6; }
.${PREFIX}-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.${PREFIX}-btn { padding: 5px 12px; border-radius: 6px; font: inherit; cursor: pointer; color: var(--dsw-alias-label-primary);
  border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-l2); }
.${PREFIX}-btn:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover); }
.${PREFIX}-btn:disabled { opacity: .55; cursor: not-allowed; }
.${PREFIX}-btn-primary { background: var(--dsw-alias-button-primary-fill); border-color: var(--dsw-alias-button-primary-fill); color: var(--dsw-alias-label-primary-inverted); }
.${PREFIX}-btn-primary:hover:not(:disabled) { background: var(--dsw-alias-button-primary-hover); }
.${PREFIX}-btn-danger { border-color: var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary); }
.${PREFIX}-btn-sm { padding: 2px 8px; font-size: 12px; }
.${PREFIX}-list { display: flex; flex-direction: column; gap: 6px; }
.${PREFIX}-item { display: flex; align-items: center; gap: 10px; padding: 6px 8px; border-radius: 6px; background: var(--dsw-alias-fill-l2); }
.${PREFIX}-item-main { flex: 1; min-width: 0; }
.${PREFIX}-item-name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.${PREFIX}-item-meta { font-size: 12px; color: var(--dsw-alias-label-tertiary); }
.${PREFIX}-badge { font-size: 12px; padding: 1px 8px; border-radius: 999px; border: 1px solid currentColor; }
.${PREFIX}-ok { color: var(--dsw-alias-state-success-primary); }
.${PREFIX}-bad { color: var(--dsw-alias-state-error-primary); }
.${PREFIX}-msg { padding: 8px 10px; border-radius: 6px; font-size: 12px; word-break: break-word;
  background: var(--dsw-alias-fill-l1); border-left: 3px solid currentColor; }
.${PREFIX}-spin { display: inline-block; width: 12px; height: 12px; border-radius: 50%;
  border: 2px solid var(--dsw-alias-border-l2); border-top-color: var(--dsw-alias-brand-primary);
  animation: ${PREFIX}-spin .8s linear infinite; }
@keyframes ${PREFIX}-spin { to { transform: rotate(360deg); } }
.${PREFIX}-modal-mask { position: fixed; inset: 0; z-index: 60; display: flex; align-items: center; justify-content: center;
  background: var(--dsw-alias-bg-mask-3, rgba(0,0,0,.35)); }
.${PREFIX}-modal { width: min(420px, 90vw); border-radius: 10px; padding: 16px 18px; display: flex; flex-direction: column; gap: 12px;
  background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary);
  border: 1px solid var(--dsw-alias-border-l2); box-shadow: 0 12px 40px var(--dsw-alias-bg-mask-drop, rgba(0,0,0,.28)); }
.${PREFIX}-modal-title { font-weight: 600; }
.${PREFIX}-modal-body { font-size: 13px; line-height: 1.7; color: var(--dsw-alias-label-secondary); }
.${PREFIX}-modal-actions { display: flex; justify-content: flex-end; gap: 8px; }
.${PREFIX}-warn { padding: 8px 10px; border-radius: 6px; font-size: 12px; line-height: 1.7; color: var(--dsw-alias-label-secondary);
  background: var(--dsw-alias-fill-l1); border-left: 3px solid var(--dsw-alias-state-error-primary); }
.${PREFIX}-warn-title { color: var(--dsw-alias-state-error-primary); font-weight: 600; margin-bottom: 2px; }
.${PREFIX}-log { font-size: 12px; color: var(--dsw-alias-label-tertiary); }
.${PREFIX}-log summary { cursor: pointer; }
.${PREFIX}-log-pre { max-height: 200px; overflow: auto; margin: 6px 0 0; padding: 8px; border-radius: 6px; font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; word-break: break-all;
  color: var(--dsw-alias-label-secondary); background: var(--dsw-alias-bg-l2); border: 1px solid var(--dsw-alias-border-l2); }
`;

    // ============================================================
    // 基础控件
    // ============================================================

    function Button(props) {
      const { variant, small, children, ...rest } = props;
      const cls = [PREFIX + '-btn'];
      if (variant === 'primary') cls.push(PREFIX + '-btn-primary');
      if (variant === 'danger') cls.push(PREFIX + '-btn-danger');
      if (small) cls.push(PREFIX + '-btn-sm');
      return h('button', { type: 'button', className: cls.join(' '), ...rest }, children);
    }

    function Field(props) {
      const { label, id, ...rest } = props;
      return h('div', { className: PREFIX + '-field' },
        h('label', { htmlFor: id }, label),
        h('input', { id, className: PREFIX + '-input', ...rest }),
      );
    }

    /** 单条提示。kind: 'ok' | 'error' | 'info' */
    function Message(props) {
      const { kind, children } = props;
      if (!children) return null;
      const cls = [PREFIX + '-msg'];
      cls.push(kind === 'ok' ? PREFIX + '-ok' : kind === 'error' ? PREFIX + '-bad' : '');
      return h('div', { className: cls.join(' '), role: kind === 'error' ? 'alert' : 'status' }, children);
    }

    function Spinner() {
      return h('span', { className: PREFIX + '-spin', 'aria-hidden': true });
    }

    /** 自写确认弹窗：沿用 Modal 的关键行为（焦点、Escape、遮罩点击不误关）。 */
    function ConfirmModal(props) {
      const { open, title, body, confirmLabel, onConfirm, onCancel, busy } = props;
      const ref = useRef(null);

      useEffect(() => {
        if (!open) return undefined;
        const onKey = (e) => { if (e.key === 'Escape' && !busy) onCancel(); };
        document.addEventListener('keydown', onKey);
        if (ref.current && typeof ref.current.focus === 'function') ref.current.focus();
        return () => document.removeEventListener('keydown', onKey);
      }, [open, busy, onCancel]);

      if (!open) return null;
      return h('div', { className: PREFIX + '-modal-mask', onMouseDown: (e) => { if (e.target === e.currentTarget && !busy) onCancel(); } },
        h('div', { className: PREFIX + '-modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
          h('div', { className: PREFIX + '-modal-title' }, title),
          h('div', { className: PREFIX + '-modal-body' }, body),
          h('div', { className: PREFIX + '-modal-actions' },
            h(Button, { onClick: onCancel, disabled: busy }, '取消'),
            h(Button, { variant: props.confirmVariant || 'primary', onClick: onConfirm, disabled: busy, ref }, busy ? '处理中…' : confirmLabel),
          ),
        ),
      );
    }

    // ============================================================
    // 主组件
    // ============================================================

    function DshSyncSection() {
      // 表单：打开页面时从 Host 已保存的配置回填。用户开始改之后不再被刷新覆盖。
      const [form, setForm] = useState({ url: '', username: '', password: '', remoteDir: '' });
      const formDirtyRef = useRef(false);
      const installLock = useRef(false);
      const autoInstallTried = useRef(false);
      // 口令：勾选记住后由 Host 写入本机 dsh-sync.json，页面上只显示「已记住」，不回显原文
      const [passphrase, setPassphrase] = useState('');
      const [remember, setRemember] = useState(true);
      const [status, setStatus] = useState(null);
      // 插件依赖状态：null = 尚未取到或端点不可用（静默降级，不弹错）
      const [plugins, setPlugins] = useState(null);
      // 版本状态：null = 尚未取到或端点不可用（同样静默降级）
      const [version, setVersion] = useState(null);
      // 升级结果：null = 尚未升级过；{ to, log }
      const [upgraded, setUpgraded] = useState(null);
      const [loading, setLoading] = useState(true);
      const [busy, setBusy] = useState('');           // '' | 'config' | 'backup' | 'restore' | 'rollback' | 'delete' | 'install' | 'refresh' | 'version' | 'upgrade'
      const [msg, setMsg] = useState(null);           // { kind, text }
      const [offline, setOffline] = useState(false);
      const [confirm, setConfirm] = useState(null);   // { title, body, confirmLabel, run }

      const mountedRef = useRef(true);
      useEffect(() => () => { mountedRef.current = false; }, []);

      const setField = (key) => (e) => {
        formDirtyRef.current = true;
        setForm((f) => ({ ...f, [key]: e.target.value }));
      };

      /** 用状态接口带回的已保存配置填表。用户正在编辑时不覆盖。 */
      const applySavedConfig = (data) => {
        const c = data && data.config;
        if (!c || typeof c !== 'object' || formDirtyRef.current) return;
        setForm({
          url: typeof c.url === 'string' ? c.url : '',
          username: typeof c.username === 'string' ? c.username : '',
          password: typeof c.password === 'string' ? c.password : '',
          remoteDir: typeof c.remoteDir === 'string' ? c.remoteDir : '',
        });
      };

      /** 统一吞掉所有失败：置 offline / 错误提示，绝不抛出。 */
      const consume = useCallback((res, okText) => {
        if (!mountedRef.current) return false;
        if (res.ok) {
          setOffline(false);
          if (okText) setMsg({ kind: 'ok', text: okText });
          return true;
        }
        if (res.offline) {
          setOffline(true);
          setMsg({ kind: 'error', text: NOT_READY });
          return false;
        }
        setOffline(false);
        setMsg({ kind: 'error', text: pickError(res, '请求失败') });
        return false;
      }, []);

      /** GET /dsh-sync/status */
      const refresh = useCallback(async (opts) => {
        const silent = opts && opts.silent;
        if (!silent) setBusy((b) => b || 'refresh');
        setLoading(true);
        const res = await api.status();
        if (!mountedRef.current) return;
        setLoading(false);
        setBusy((b) => (b === 'refresh' ? '' : b));
        if (res.ok) {
          setOffline(false);
          setStatus(res.data || null);
          applySavedConfig(res.data);
          if (!silent && !res.data ) setMsg({ kind: 'error', text: '状态响应为空' });
        } else if (res.offline) {
          setOffline(true);
          setStatus(null);
          setMsg({ kind: 'error', text: NOT_READY });
        } else {
          setOffline(false);
          setStatus(null);
          setMsg({ kind: 'error', text: pickError(res, '读取状态失败') });
        }
      }, []);

      /**
       * GET /dsh-sync/plugins —— 插件依赖状态。失败静默降级：只把状态置空，
       * 不写 msg、不置 offline，卡片其余部分照常可用。
       */
      const refreshPlugins = useCallback(async () => {
        const res = await api.plugins();
        if (!mountedRef.current) return null;
        const data = (res.ok && res.data && res.data.ok) ? res.data : null;
        setPlugins(data);
        return data;
      }, []);

      /**
       * GET /dsh-sync/version —— 版本状态。与 refreshPlugins 同样静默降级：
       * 失败只置空状态，不写 msg、不置 offline，其它卡片照常可用。
       * silent=true 用于挂载时的自动检查：不占用 busy，避免限制用户操作。
       */
      const refreshVersion = useCallback(async (force, silent) => {
        if (!silent) setBusy((b) => b || 'version');
        const res = await api.version(!!force);
        if (!mountedRef.current) return;
        if (!silent) setBusy((b) => (b === 'version' ? '' : b));
        setVersion((res.ok ? normalizeVersion(res.data) : null));
      }, []);

      // 加载时拉一次状态与插件依赖。有「恢复后未安装」就自动装一次。
      useEffect(() => { refresh(); }, [refresh]);
      useEffect(() => {
        let cancel = false;
        (async () => {
          const plug = await refreshPlugins();
          if (cancel || !mountedRef.current) return;
          await maybeAutoInstall(plug);
        })();
        return () => { cancel = true; };
      }, [refreshPlugins]);
      // 打开设置页自动检查更新（不带 force，命中宿主缓存即可）
      useEffect(() => { refreshVersion(false, true); }, [refreshVersion]);

      /** POST /dsh-sync/config —— 保存并测试连接 */
      const onSaveConfig = async () => {
        if (busy) return;
        setBusy('config');
        setMsg(null);
        const res = await api.config({
          url: form.url, username: form.username, password: form.password, remoteDir: form.remoteDir,
        });
        if (!mountedRef.current) return;
        setBusy('');
        if (consume(res, '已保存，连接测试通过')) formDirtyRef.current = false;
        await refresh({ silent: true });
      };

      /** POST /dsh-sync/backup —— 立即备份。留空且已记住时，Host 用本机口令。 */
      const onBackup = async () => {
        if (busy) return;
        const savedDir = normalizeDir(status && status.config && status.config.remoteDir);
        const typedDir = normalizeDir(form.remoteDir);
        if (status && status.configured && typedDir !== savedDir) {
          setMsg({
            kind: 'error',
            text: '远程目录已改成「' + (typedDir || '根目录') + '」但还没保存，现在生效的仍是「' + (savedDir || '根目录') + '」。请先点「保存并测试连接」，避免新备份写到另一台电脑看不到的位置。',
          });
          return;
        }
        const known = !!(status && status.config && status.config.hasPassphrase);
        if (!passphrase && !(remember && known)) {
          setMsg({ kind: 'error', text: '请先输入口令。勾选「在本机记住」后，这台电脑以后可以留空。' });
          return;
        }
        setBusy('backup');
        setMsg(null);
        const res = await api.backup({ passphrase, remember });
        if (!mountedRef.current) return;
        setBusy('');
        if (consume(res, null)) {
          const d = res.data || {};
          const tops = (d.scope && Array.isArray(d.scope.topLevel) && d.scope.topLevel.length)
            ? '；范围 ' + d.scope.topLevel.map((t) => t.name + '×' + t.files).join('、')
            : '';
          const prunedNote = (Array.isArray(d.pruned) && d.pruned.length) ? '；已清理 ' + d.pruned.length + ' 份旧备份' : '';
          setMsg({ kind: 'ok', text: '备份成功：' + (d.name || '') + '（' + formatSize(d.size) + '，' + (d.fileCount || 0) + ' 个文件' + tops + prunedNote + '）' });
        }
        await refresh({ silent: true });
      };

      /** POST /dsh-sync/passphrase —— 只记住口令，不立刻打一份备份。 */
      const onSavePassphrase = async () => {
        if (busy) return;
        if (!passphrase) { setMsg({ kind: 'error', text: '请先输入要记住的口令' }); return; }
        setBusy('passphrase');
        setMsg(null);
        const res = await api.passphrase({ passphrase });
        if (!mountedRef.current) return;
        setBusy('');
        if (consume(res, '口令已记在本机，之后备份和恢复可以留空')) setPassphrase('');
        await refresh({ silent: true });
      };

      const onClearPassphrase = async () => {
        if (busy) return;
        setBusy('passphrase');
        setMsg(null);
        const res = await api.passphrase({ clear: true });
        if (!mountedRef.current) return;
        setBusy('');
        if (consume(res, '已清除本机记住的口令')) setPassphrase('');
        await refresh({ silent: true });
      };

      /** 恢复入口：先弹确认（提示会先自动快照现有配置，恢复后需重启才生效） */
      const askRestore = (backup) => {
        const name = backup && backup.name;
        const encrypted = !backup || backup.encrypted !== false;
        setConfirm({
          title: '确认恢复',
          body: h(React.Fragment, null,
            h('div', null, name ? '将从远端备份恢复：' : '将从同账号下最新的一份备份恢复（根目录和 dsh-sync 一起比较）。'),
            name ? h('div', { className: PREFIX + '-item-name' }, name) : null,
            name ? h('div', { className: PREFIX + '-hint' }, '位置：' + locationLabel(backup.remoteDir)) : null,
            h('div', null, encrypted ? '这份备份已用口令加密。留空并勾选记住时，使用本机已保存的口令。' : '这份备份没有口令。'),
            h('div', null, '恢复前会自动为当前配置创建一份本地快照，可用它回滚。'),
            h('div', { className: PREFIX + '-warn' },
              h('div', { className: PREFIX + '-warn-title' }, '恢复完成后必须重启 DeepSeek Harness 才会生效'),
              h('div', null, '备份不含插件代码。恢复后会把源机器的本机路径改成这台电脑可用的路径，并自动安装缺失的插件。安装结束前请不要重启。'),
            ),
          ),
          confirmLabel: '恢复',
          run: () => doRestore(backup),
        });
      };

      /** POST /dsh-sync/restore */
      const doRestore = async (backup) => {
        if (busy) return;
        const known = !!(status && status.config && status.config.hasPassphrase);
        if (!passphrase && !(remember && known)) {
          setConfirm(null);
          setMsg({ kind: 'error', text: '请先输入口令。勾选「在本机记住」后，这台电脑以后可以留空。' });
          return;
        }
        setBusy('restore');
        setMsg(null);
        const body = { passphrase, remember };
        if (backup && backup.name) {
          body.name = backup.name;
          body.remoteDir = normalizeDir(backup.remoteDir);
        }
        const res = await api.restore(body);
        if (!mountedRef.current) return;
        setBusy('');
        setConfirm(null);
        if (consume(res, null)) {
          const d = res.data || {};
          // 备份里没有 node_modules：恢复后插件只剩配置，这里立刻刷新插件状态
          const plug = await refreshPlugins();
          if (!mountedRef.current) return;
          const skipped = Array.isArray(d.skipped) ? d.skipped : [];
          const mismatch = Array.isArray(d.mismatches) ? d.mismatches : [];
          const parts = [];
          if (d.restored > 0 && d.verified === d.restored && !skipped.length && !mismatch.length) {
            parts.push('已恢复 ' + d.restored + ' 个文件（逐文件校验通过），快照：' + (d.snapshot || '—'));
          } else {
            if (d.restored > 0) parts.push('已写入 ' + d.restored + ' 个文件，校验通过 ' + (d.verified || 0) + ' 个');
            else parts.push('恢复没有写入任何文件');
            parts.push('快照：' + (d.snapshot || '—'));
          }
          if (skipped.length) {
            parts.push('有 ' + skipped.length + ' 个条目被跳过：' +
              skipped.slice(0, 5).map((s) => (s && s.path ? s.path : '?') + '（' + (s && s.reason ? s.reason : '?') + '）').join('、') +
              (skipped.length > 5 ? ' 等' : ''));
          }
          if (mismatch.length) {
            parts.push('有 ' + mismatch.length + ' 个文件写入校验失败：' +
              mismatch.slice(0, 5).map((m) => (m && m.path ? m.path : '?')).join('、') +
              (mismatch.length > 5 ? ' 等' : ''));
          }
          const ports = (d.portability && Array.isArray(d.portability.profiles)) ? d.portability.profiles : [];
          const rewrittenN = ports.reduce((n, p) => n + ((p.rewritten && p.rewritten.length) || 0), 0);
          const storeN = ports.filter((p) => p && p.storeDir).length;
          if (rewrittenN) parts.push('已改写 ' + rewrittenN + ' 条只在源电脑上有效的路径');
          if (storeN) parts.push('已把 pnpm 存储目录改到这台电脑');
          let installFailed = false;
          if (plug && plug.needsInstall && plug.pnpm && plug.pnpm.available) {
            autoInstallTried.current = true;
            parts.push('正在安装缺失的插件，请勿关闭或重启');
            setMsg({ kind: 'ok', text: '恢复完成：' + parts.join('。') });
            const installed = await doInstall({ quiet: true });
            if (installed && installed.ok) parts.push(formatInstallResult(installed));
            else {
              installFailed = true;
              parts.push('插件自动安装失败：' + pickError(installed, '请点下方「重装插件」'));
            }
          } else if (plug && plug.needsInstall) {
            parts.push('插件代码尚未安装，且找不到 pnpm。请手动执行 dsh plugin --profile desktop install');
          } else {
            parts.push('请重启 DeepSeek Harness 使恢复生效');
          }
          setMsg({ kind: skipped.length || mismatch.length || installFailed || !(d.verified === d.restored) ? 'error' : 'ok', text: '恢复完成：' + parts.join('。') });
        }
        await refresh({ silent: true });
      };

      /** 回滚入口：先弹确认 */
      const askRollback = (snapshot) => {
        setConfirm({
          title: '确认回滚',
          body: h(React.Fragment, null,
            h('div', null, '将用本地快照覆盖当前配置：'),
            h('div', { className: PREFIX + '-item-name' }, snapshot),
            h('div', null, '回滚前会再创建一份当前状态的快照，因此可以再滚回来。'),
          ),
          confirmLabel: '回滚',
          run: () => doRollback(snapshot),
        });
      };

      /** POST /dsh-sync/rollback */
      const doRollback = async (snapshot) => {
        if (busy) return;
        setBusy('rollback');
        setMsg(null);
        const res = await api.rollback({ snapshot });
        if (!mountedRef.current) return;
        setBusy('');
        setConfirm(null);
        if (consume(res, null)) {
          const d = res.data || {};
          setMsg({ kind: 'ok', text: '已回滚，恢复 ' + (d.restored || 0) + ' 个文件' });
        }
        await refresh({ silent: true });
      };

      /** 删除某一份云端备份。带上它所在的目录，避免根目录和 dsh-sync 里同名时删错。 */
      const askDelete = (backup) => {
        const name = backup && backup.name;
        if (!name) return;
        setConfirm({
          title: '删除云端备份',
          confirmVariant: 'danger',
          body: h(React.Fragment, null,
            h('div', null, '将从 WebDAV 上永久删除这份备份，删掉后无法恢复：'),
            h('div', { className: PREFIX + '-item-name' }, name),
            h('div', { className: PREFIX + '-hint' }, '位置：' + locationLabel(backup.remoteDir)),
          ),
          confirmLabel: '删除',
          run: () => doDelete(backup),
        });
      };

      const doDelete = async (backup) => {
        const name = backup && backup.name;
        if (busy || !name) return;
        setBusy('delete');
        setMsg(null);
        const res = await api.remove({ name, remoteDir: normalizeDir(backup.remoteDir) });
        if (!mountedRef.current) return;
        setBusy('');
        setConfirm(null);
        const data = (res.ok && res.data && typeof res.data === 'object') ? res.data : res;
        if (data && data.ok) {
          setMsg({ kind: 'ok', text: '已从云端删除：' + ((data.deleted && data.deleted[0]) || name) });
        } else if (res.offline) {
          setOffline(true);
          setMsg({ kind: 'error', text: NOT_READY });
        } else {
          setMsg({ kind: 'error', text: pickError(data, '删除失败') });
        }
        await refresh({ silent: true });
      };

      /** 重装入口：先弹确认（会联网装包，且重启后才生效） */
      const askInstall = (names) => {
        const list = Array.isArray(names) ? names : [];
        setConfirm({
          title: '确认重装插件',
          body: h(React.Fragment, null,
            h('div', null, '将为当前 profile 重新安装缺失的插件依赖：'),
            list.length
              ? h('div', { className: PREFIX + '-item-name' }, list.join('、'))
              : h('div', { className: PREFIX + '-hint' }, '（未列出具体包名）'),
            h('div', null, '安装会通过 pnpm 联网下载，可能需要几十秒，期间请勿关闭页面。'),
            h('div', null, '安装完成后需要重启 DeepSeek Harness 才会生效。'),
          ),
          confirmLabel: '重装',
          run: () => doInstall(),
        });
      };

      /** POST /dsh-sync/plugins/install —— 重装插件依赖（失败也可能带 log）。quiet 时由调用方自己组提示。 */
      const doInstall = async (opts) => {
        const quiet = opts && opts.quiet;
        if (installLock.current) return null;
        installLock.current = true;
        setBusy('install');
        if (!quiet) setMsg(null);
        const res = await api.pluginsInstall({});
        if (!mountedRef.current) { installLock.current = false; return null; }
        setBusy('');
        setConfirm(null);
        installLock.current = false;
        const data = (res.ok && res.data && typeof res.data === 'object') ? res.data : res;
        if (data && data.ok) {
          setOffline(false);
          await refreshPlugins();
          if (!mountedRef.current) return data;
          if (!quiet) setMsg({ kind: 'ok', text: formatInstallResult(data), log: data.log || '' });
          return data;
        }
        if (res.offline) {
          setOffline(true);
          if (!quiet) setMsg({ kind: 'error', text: NOT_READY });
          return { ok: false, error: NOT_READY };
        }
        setOffline(false);
        if (!quiet) setMsg({ kind: 'error', text: pickError(data, '安装失败'), log: (data && data.log) || '' });
        return data && typeof data === 'object' ? data : { ok: false, error: pickError(data, '安装失败') };
      };

      /** 上次恢复留下了未安装的插件时，打开设置页就装一次，避免用户重启后只看到「包不可用」。 */
      const maybeAutoInstall = async (plug) => {
        if (autoInstallTried.current) return;
        if (!plug || !plug.needsInstall || !plug.lastRestore || !plug.pnpm || !plug.pnpm.available) return;
        autoInstallTried.current = true;
        setMsg({ kind: 'ok', text: '检测到上次恢复后有插件依赖未安装，正在自动安装…请勿关闭或重启。' });
        await doInstall();
      };

      /** 升级入口：先弹确认（会重装插件，且重启后才生效） */
      const askUpgrade = (info) => {
        if (!info) return;
        setConfirm({
          title: '确认升级插件',
          body: h(React.Fragment, null,
            h('div', null, '当前版本 → 目标版本：'),
            h('div', { className: PREFIX + '-item-name' }, info.current + ' → ' + (info.latest || shortSha(info.latestSha))),
            h('div', null, '升级会重装插件，完成后需要重启 DeepSeek Harness。'),
            info.repo ? h('div', { className: PREFIX + '-hint' }, '来源：' + info.repo) : null,
          ),
          confirmLabel: '升级',
          run: () => doUpgrade(),
        });
      };

      /** POST /dsh-sync/upgrade —— 失败也可能带 log（延续 /plugins/install 的处理方式） */
      const doUpgrade = async () => {
        if (busy) return;
        setBusy('upgrade');
        setMsg(null);
        setUpgraded(null);
        const res = await api.upgrade({});
        if (!mountedRef.current) return;
        setBusy('');
        setConfirm(null);
        const data = (res.ok && res.data && typeof res.data === 'object') ? res.data : res;
        if (data && data.ok) {
          setOffline(false);
          if (data.upgraded === false) {
            if (data.alreadyLatest) {
              setMsg({ kind: 'ok', text: '已是最新版本 ' + (data.to || data.from || '') });
            } else {
              setMsg({ kind: 'error', text: pickError(data, '未执行升级'), log: data.log || '' });
            }
          } else {
            setUpgraded({ to: data.to || '', log: data.log || '' });
            if (data.error) setMsg({ kind: 'error', text: data.error });
          }
          await refreshVersion(true, true);
          return;
        }
        if (res.offline) {
          setOffline(true);
          setMsg({ kind: 'error', text: NOT_READY });
          return;
        }
        setOffline(false);
        setMsg({ kind: 'error', text: pickError(data, '升级失败'), log: (data && data.log) || '' });
      };

      const backups = (status && status.remote && Array.isArray(status.remote.backups)) ? status.remote.backups : [];
      const configured = !!(status && status.configured);
      const hasPassphrase = !!(status && status.config && status.config.hasPassphrase);
      const savedDir = normalizeDir(status && status.config && status.config.remoteDir);
      const typedDir = normalizeDir(form.remoteDir);
      const dirUnsaved = configured && typedDir !== savedDir;
      const outsideDir = backups.filter((b) => normalizeDir(b && b.remoteDir) !== savedDir);
      const reachable = !!(status && status.remote && status.remote.reachable);
      const lastLocalSnapshot = status && status.lastLocalSnapshot;
      const anyBusy = !!busy;

      const pluginDeps = (plugins && Array.isArray(plugins.deps)) ? plugins.deps : [];
      const missingPlugins = (plugins && Array.isArray(plugins.missing)) ? plugins.missing : [];
      const missingNames = missingPlugins.length
        ? missingPlugins
        : pluginDeps.filter((d) => d && d.installed === false).map((d) => d.name);
      const needsInstall = !!(plugins && plugins.needsInstall);
      const pnpmAvailable = !!(plugins && plugins.pnpm && plugins.pnpm.available);
      const lastRestore = (plugins && plugins.lastRestore) ? plugins.lastRestore : null;

      // 版本卡片：hasUpdate 是宿主给的权威判据，这里一律不自行比较版本大小
      const registryBlocked = !!(version && version.kind === 'registry');
      // latest 不保证是 semver（无 tag 时是远端短 sha），一律原样渲染，仅作空值兜底
      const latestText = version && (version.latest || shortSha(version.latestSha));
      // 两边 sha 都有且相等 -> 同一提交，展示 commit 短号
      const sameCommit = !!(version && version.currentSha && version.latestSha &&
        shortSha(version.currentSha) === shortSha(version.latestSha));

      // ---- 版本升级卡片的分支体（放在「插件依赖」之后、消息区之前）----
      let versionBody;
      if (!version) {
        versionBody = h('div', { className: PREFIX + '-hint' }, '读不到版本状态，不影响其余功能。');
      } else if (version.error) {
        // 检查没成功就一律不给结论、不给升级入口，正文只留上方的失败提示 + 重试
        versionBody = null;
      } else if (version.mode === 'dev') {
        versionBody = h('div', { className: PREFIX + '-hint' },
          '开发态安装（link:），不受版本升级管理；更新请在该目录执行 git pull');
      } else if (registryBlocked) {
        versionBody = h('div', { className: PREFIX + '-warn' },
          h('div', { className: PREFIX + '-warn-title' }, '当前为 registry 安装，但该包名在 npm 上属于其他作者的项目'),
          h('div', null, '出于安全考虑不自动升级；请改用 github: 方式安装。'),
          version.spec ? h('div', { className: PREFIX + '-item-name' }, version.spec) : null,
        );
      } else if (version.hasUpdate) {
        versionBody = h(React.Fragment, null,
          h('div', { className: PREFIX + '-row' },
            h('span', { className: PREFIX + '-badge ' + PREFIX + '-bad' }, '发现新版本 ' + (latestText || '')),
          ),
          version.changelog.length
            ? h('div', { className: PREFIX + '-list' },
                version.changelog.map((line, i) => h('div', { className: PREFIX + '-hint', key: i }, line)),
              )
            : null,
          h('div', { className: PREFIX + '-row' },
            h(Button, { variant: 'primary', disabled: anyBusy, onClick: () => askUpgrade(version) },
              busy === 'upgrade' ? '升级中…' : '立即升级'),
          ),
        );
      } else {
        versionBody = h(React.Fragment, null,
          h('div', { className: PREFIX + '-hint' },
            sameCommit
              ? '已是最新（commit ' + shortSha(version.latestSha) + '）'
              : '已是最新版本' + (latestText ? '（' + latestText + '）' : '')),
          h('div', { className: PREFIX + '-row' },
            h(Button, { small: true, disabled: anyBusy, onClick: () => refreshVersion(true, false) },
              busy === 'version' ? '检查中…' : '检查更新'),
          ),
        );
      }

      return h('div', { className: PREFIX + '-root' },
        h('style', null, CSS),

        // ---- 状态区 ----
        h('div', { className: PREFIX + '-card' },
          h('div', { className: PREFIX + '-card-title' },
            h('span', null, '状态'),
            loading ? h(Spinner, null) : null,
            offline
              ? h('span', { className: PREFIX + '-bad' }, '· ' + NOT_READY)
              : h('span', { className: configured ? PREFIX + '-ok' : PREFIX + '-bad' },
                  '· ' + (configured ? '已配置' : '未配置')),
            !offline && configured
              ? h('span', { className: reachable ? PREFIX + '-ok' : PREFIX + '-bad' },
                  '· 远端' + (reachable ? '可达' : '不可达'))
              : null,
            h('span', { style: { flex: 1 } }),
            h(Button, { small: true, disabled: anyBusy, onClick: () => refresh() }, anyBusy && busy === 'refresh' ? '刷新中…' : '刷新'),
          ),
          status && status.error ? h(Message, { kind: 'error' }, status.error) : null,
          h('div', { className: PREFIX + '-hint' },
            '最近一次本地快照：' + (lastLocalSnapshot || '无')),
          h('div', { className: PREFIX + '-hint' }, backupSummary(backups)),
          outsideDir.length
            ? h('div', { className: PREFIX + '-hint' },
                '其中 ' + outsideDir.length + ' 份不在当前保存的目录「' + locationLabel(savedDir) + '」。同一账号在根目录和 dsh-sync 里的备份会合并显示，可以直接恢复或删除。')
            : null,
          backups.length
            ? h('div', { className: PREFIX + '-list' },
                backups.map((b, i) => h('div', { className: PREFIX + '-item', key: ((b && b.remoteDir) || '') + '/' + ((b && b.name) || i) },
                  h('div', { className: PREFIX + '-item-main' },
                    h('div', { className: PREFIX + '-item-name', title: b && b.name }, (b && b.name) || '(未命名)'),
                    h('div', { className: PREFIX + '-item-meta' },
                      h('span', {
                        className: PREFIX + '-badge ' + ((b && b.encrypted === false) ? PREFIX + '-bad' : PREFIX + '-ok'),
                      }, (b && b.encrypted === false) ? '未加密' : '已加密'),
                      '位置 ' + locationLabel(b && b.remoteDir) + ' · ' + formatSize(b && b.size) + ' · ' + formatTime(b && b.modified)),
                  ),
                  h(Button, { small: true, disabled: anyBusy, onClick: () => askRestore(b) }, '恢复'),
                  h(Button, { small: true, variant: 'danger', disabled: anyBusy, onClick: () => askDelete(b) },
                    busy === 'delete' ? '删除中…' : '删除'),
                )),
              )
            : null,
          backups.length
            ? h('div', { className: PREFIX + '-row' },
                h(Button, { small: true, disabled: anyBusy, onClick: () => askRestore(null) },
                  busy === 'restore' ? '恢复中…' : '恢复最新'),
              )
            : null,
        ),

        // ---- 服务器配置 ----
        h('div', { className: PREFIX + '-card' },
          h('div', { className: PREFIX + '-card-title' }, '服务器配置'),
          (status && status.config && status.config.url)
            ? h('div', { className: PREFIX + '-hint' },
                '已保存：' + status.config.url +
                ' · 用户 ' + (status.config.username || '（空）') +
                ' · 目录 ' + (status.config.remoteDir || '（根目录）') +
                ' · 密码' + (status.config.hasPassword ? '已填写' : '未填写'))
            : h('div', { className: PREFIX + '-hint' }, '还没有保存过服务器配置。填好后点「保存并测试连接」，下次打开会显示在这里。'),
          h('div', { className: PREFIX + '-grid' },
            CONFIG_FIELDS.map((f) => h(Field, {
              key: f.key,
              id: PREFIX + '-' + f.key,
              label: f.label,
              type: f.type,
              placeholder: f.placeholder,
              value: form[f.key],
              disabled: anyBusy,
              autoComplete: 'off',
              onChange: setField(f.key),
            })),
          ),
          dirUnsaved
            ? h('div', { className: PREFIX + '-warn' },
                h('div', { className: PREFIX + '-warn-title' }, '远程目录还没保存'),
                h('div', null,
                  '输入框是「' + locationLabel(typedDir) + '」，当前生效的是「' + locationLabel(savedDir) + '」。新备份仍会写到生效的目录。请先点保存并测试连接，两台电脑才会把新备份写到同一处。'),
              )
            : null,
          h('div', { className: PREFIX + '-row' },
            h(Button, { variant: 'primary', disabled: anyBusy, onClick: onSaveConfig },
              busy === 'config' ? '测试中…' : '保存并测试连接'),
          ),
          h('div', { className: PREFIX + '-hint' }, '密码会随配置保存在本机 ~/.dsh/dsh-sync.json，用于访问该 WebDAV。列表会同时看根目录和 dsh-sync，所以以前写到根目录的备份也不会丢。'),
        ),

        // ---- 备份 ----
        h('div', { className: PREFIX + '-card' },
          h('div', { className: PREFIX + '-card-title' },
            h('span', null, '备份'),
            hasPassphrase
              ? h('span', { className: PREFIX + '-badge ' + PREFIX + '-ok' }, '本机已记住口令')
              : h('span', { className: PREFIX + '-badge ' + PREFIX + '-bad' }, '尚未记住口令'),
          ),
          h('div', { className: PREFIX + '-grid' },
            h(Field, {
              id: PREFIX + '-passphrase',
              label: '口令',
              type: 'password',
              placeholder: hasPassphrase ? '已记住，留空则继续用本机口令' : '设置后用于加密备份',
              value: passphrase,
              disabled: anyBusy,
              autoComplete: 'new-password',
              onChange: (e) => setPassphrase(e.target.value),
            }),
          ),
          h('label', { className: PREFIX + '-check' },
            h('input', {
              type: 'checkbox',
              checked: remember,
              disabled: anyBusy,
              onChange: (e) => setRemember(!!e.target.checked),
            }),
            '在本机记住口令，下次备份和恢复不用重填',
          ),
          h('div', { className: PREFIX + '-hint' },
            hasPassphrase
              ? '本机已记住口令。留空会用它；输入新口令并勾选记住，只影响之后的新备份，旧备份仍用当时的口令。每份备份在列表里标明是否加密。口令写在本机配置里，不会放进备份内容。'
              : '填一次并勾选记住即可。列表里每份备份都会标明「已加密」或「未加密」。口令只保存在这台电脑，不会放进备份内容。'),
          h('div', { className: PREFIX + '-row' },
            h(Button, { variant: 'primary', disabled: anyBusy, onClick: onBackup },
              busy === 'backup' ? '备份中…' : '立即备份'),
            h(Button, { small: true, disabled: anyBusy || !passphrase, onClick: onSavePassphrase },
              busy === 'passphrase' ? '保存中…' : '只保存口令'),
            hasPassphrase
              ? h(Button, { small: true, disabled: anyBusy, onClick: onClearPassphrase }, '清除本机口令')
              : null,
          ),
        ),

        // ---- 回滚 ----
        h('div', { className: PREFIX + '-card' },
          h('div', { className: PREFIX + '-card-title' }, '回滚'),
          h('div', { className: PREFIX + '-hint' }, '本地快照保存在 ~/.dsh-sync-snapshots，最多保留 5 份。'),
          h('div', { className: PREFIX + '-row' },
            h(Button, { small: true, disabled: anyBusy, onClick: () => askRollback(lastLocalSnapshot) },
              '回滚到最近快照'),
            lastLocalSnapshot
              ? h('span', { className: PREFIX + '-item-name' }, lastLocalSnapshot)
              : h('span', { className: PREFIX + '-hint' }, '暂无快照'),
          ),
        ),

        // ---- 插件依赖（恢复后重装）----
        h('div', { className: PREFIX + '-card' },
          h('div', { className: PREFIX + '-card-title' },
            h('span', null, '插件依赖'),
            plugins && needsInstall
              ? h('span', { className: PREFIX + '-bad' }, '· ' + missingNames.length + ' 个未安装')
              : null,
          ),
          !plugins
            ? h('div', { className: PREFIX + '-hint' }, '读不到插件依赖状态，不影响其余功能。')
            : needsInstall
              ? h(React.Fragment, null,
                  h('div', { className: PREFIX + '-warn' },
                    h('div', { className: PREFIX + '-warn-title' },
                      '检测到 ' + missingNames.length + ' 个插件依赖未安装' + (plugins.profile ? '（profile：' + plugins.profile + '）' : '')),
                    h('div', null, '备份里没有 node_modules。另一台电脑会把这些插件标成「包不可用」，直到依赖安装完成并重启。'),
                    missingNames.length
                      ? h('div', { className: PREFIX + '-row' },
                          missingNames.map((n) => h('span', { key: n, className: PREFIX + '-badge ' + PREFIX + '-bad' }, n)))
                      : null,
                    lastRestore
                      ? h('div', { className: PREFIX + '-hint' },
                          '上次恢复：' + formatTime(lastRestore.at) +
                          (lastRestore.bundle ? '（' + lastRestore.bundle + '）' : ''))
                      : null,
                  ),
                  pnpmAvailable
                    ? h('div', { className: PREFIX + '-row' },
                        h(Button, { variant: 'primary', disabled: anyBusy, onClick: () => askInstall(missingNames) },
                          busy === 'install' ? '安装中…' : '重装插件'),
                      )
                    : null,
                  pnpmAvailable
                    ? h('div', { className: PREFIX + '-hint' }, '安装由 pnpm 完成，装好后需要重启 DeepSeek Harness 才会生效。')
                    : h('div', { className: PREFIX + '-hint' }, '找不到 pnpm，无法自动安装，请手动执行 ',
                        h('span', { className: PREFIX + '-item-name' }, 'dsh plugin install')),
                )
              : h('div', { className: PREFIX + '-hint' }, '插件依赖完整（' + pluginDeps.length + ' 个）'),
        ),

        // ---- 版本升级 ----
        h('div', { className: PREFIX + '-card' },
          h('div', { className: PREFIX + '-card-title' },
            h('span', null, '版本升级'),
            h('span', { style: { flex: 1 } }),
            h('span', { className: PREFIX + '-badge ' + PREFIX + '-ok' }, 'v' + (version ? version.current : '—')),
          ),
          version && version.error
            ? h('div', { className: PREFIX + '-warn' },
                h('div', { className: PREFIX + '-warn-title' }, '检查更新失败'),
                h('div', null, version.error),
                h('div', { className: PREFIX + '-row' },
                  h(Button, { small: true, disabled: anyBusy, onClick: () => refreshVersion(true, false) },
                    busy === 'version' ? '检查中…' : '重试'),
                ),
              )
            : null,
          versionBody,
          upgraded
            ? h(React.Fragment, null,
                h('div', { className: PREFIX + '-hint' },
                  '已升级到 v' + upgraded.to + '，重启 DeepSeek Harness 后生效'),
                upgraded.log
                  ? h('details', { className: PREFIX + '-log' },
                      h('summary', null, '升级日志（点击展开）'),
                      h('pre', { className: PREFIX + '-log-pre' }, upgraded.log),
                    )
                  : null,
              )
            : null,
          version && version.checkedAt
            ? h('div', { className: PREFIX + '-hint' }, '上次检查：' + formatRelTime(version.checkedAt))
            : null,
        ),

        msg ? h(Message, { kind: msg.kind }, msg.text) : null,
        // 安装日志可能几千字符：折叠 + 限高滚动，不铺在卡片上
        msg && msg.log
          ? h('details', { className: PREFIX + '-log' },
              h('summary', null, '安装日志（点击展开）'),
              h('pre', { className: PREFIX + '-log-pre' }, msg.log),
            )
          : null,

        h(ConfirmModal, {
          open: !!confirm,
          title: confirm ? confirm.title : '',
          body: confirm ? confirm.body : null,
          confirmLabel: confirm ? confirm.confirmLabel : '确定',
          confirmVariant: confirm ? confirm.confirmVariant : 'primary',
          busy: anyBusy,
          onCancel: () => { if (!anyBusy) setConfirm(null); },
          onConfirm: () => { if (confirm && !anyBusy) confirm.run(); },
        }),
      );
    }

    // ============================================================
    // 注册
    // ============================================================

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('settings.section', () => ctx.slots.register(
          { name: 'settings.section', id: 'sync', order: 100, label: () => '配置同步（WebDAV）' },
          DshSyncSection,
        ));
      },
    };
  },
});

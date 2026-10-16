/**
 * DSH Sync · Client 半区（Web 设置页配置卡片）
 *
 * 注册进宿主已声明的 slot `settings.section`（kind: list, scope: root），
 * 在设置面板里占一个独立页「配置同步（WebDAV）」。
 *
 * 与 Host 半区（index.js）通过 HTTP 端点通信，契约冻结：
 *   GET  /dsh-sync/status                          -> { configured, remote:{reachable,backups[],latest?}, lastLocalSnapshot?, error? }
 *   POST /dsh-sync/config   {url,username,password,remoteDir} -> { ok:true } | { ok:false, error }
 *   POST /dsh-sync/backup   {passphrase}            -> { ok:true, name, size, fileCount } | { ok:false, error }
 *   POST /dsh-sync/restore  {name?, passphrase}     -> { ok:true, restored, snapshot }    | { ok:false, error }
 *   POST /dsh-sync/rollback {snapshot}              -> { ok:true, restored }              | { ok:false, error }
 * 所有响应 HTTP 200，按 `ok` 字段判断成败；错误统一在 `error` 字段。
 *
 * 约束：无 npm 依赖、无构建步骤、ESM 形态的 IIFE 包；不 require 任何
 * `@deepseek-ai/dsh-client-*` 包（宿主明确警告其不稳定，抛错会白屏整个 slot），
 * 控件自写、样式只用 `--dsw-alias-*` 主题令牌。fail-soft：端点不可用时
 * 显示「插件服务未就绪」，不抛错、不白屏。
 */

window.__ModuleLoader__.load({
  id: 'dsh-sync-plugin',
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
    const NOT_READY = '插件服务未就绪';

    const CONFIG_FIELDS = [
      { key: 'url', label: 'WebDAV URL', placeholder: 'https://dav.example.com/dav/', type: 'text' },
      { key: 'username', label: '用户名', placeholder: 'user', type: 'text' },
      { key: 'password', label: '密码', placeholder: '••••••••', type: 'password' },
      { key: 'remoteDir', label: '远程目录', placeholder: 'dsh-sync', type: 'text' },
    ];

    // ============================================================
    // 纯工具（不依赖 React，便于静态自检）
    // ============================================================

    /** 字节数的可读展示。 */
    function formatSize(bytes) {
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

    /**
     * 从响应体里取错误文案。Host 端契约把错误放在 `error` 字段（HTTP 恒 200）；
     * status 端点在 body 里给 `error` 但不带 `ok`。两者都要覆盖。
     */
    function pickError(payload, fallback) {
      if (payload && typeof payload.error === 'string' && payload.error) return payload.error;
      return fallback || '未知错误';
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

    /** 5 个端点的语义化包装：统一返回 { ok, ... }，ok 时附带 data。 */
    const api = {
      status: fetchStatus,
      config: (body) => request('/config', { method: 'POST', body }),
      backup: (body) => request('/backup', { method: 'POST', body }),
      restore: (body) => request('/restore', { method: 'POST', body }),
      rollback: (body) => request('/rollback', { method: 'POST', body }),
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
            h(Button, { variant: 'primary', onClick: onConfirm, disabled: busy, ref }, busy ? '处理中…' : confirmLabel),
          ),
        ),
      );
    }

    // ============================================================
    // 主组件
    // ============================================================

    function DshSyncSection() {
      // 表单：唯一持久化位置是 Host 端配置文件，这里只在内存里持有
      const [form, setForm] = useState({ url: '', username: '', password: '', remoteDir: '' });
      // 口令：仅内存，绝不写入任何持久化位置
      const [passphrase, setPassphrase] = useState('');
      const [status, setStatus] = useState(null);
      const [loading, setLoading] = useState(true);
      const [busy, setBusy] = useState('');           // '' | 'config' | 'backup' | 'restore' | 'rollback' | 'refresh'
      const [msg, setMsg] = useState(null);           // { kind, text }
      const [offline, setOffline] = useState(false);
      const [confirm, setConfirm] = useState(null);   // { title, body, confirmLabel, run }

      const mountedRef = useRef(true);
      useEffect(() => () => { mountedRef.current = false; }, []);

      const setField = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

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

      // 加载时拉一次状态
      useEffect(() => { refresh(); }, [refresh]);

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
        consume(res, '已保存，连接测试通过');
        await refresh({ silent: true });
      };

      /** POST /dsh-sync/backup —— 立即备份 */
      const onBackup = async () => {
        if (busy) return;
        if (!passphrase) { setMsg({ kind: 'error', text: '请先输入口令' }); return; }
        setBusy('backup');
        setMsg(null);
        const res = await api.backup({ passphrase });
        if (!mountedRef.current) return;
        setBusy('');
        if (consume(res, null)) {
          const d = res.data || {};
          setMsg({ kind: 'ok', text: '备份成功：' + (d.name || '') + '（' + formatSize(d.size) + '，' + (d.fileCount || 0) + ' 个文件）' });
        }
        await refresh({ silent: true });
      };

      /** 恢复入口：先弹确认（提示会先自动快照现有配置） */
      const askRestore = (name) => {
        setConfirm({
          title: '确认恢复',
          body: h(React.Fragment, null,
            h('div', null, name ? '将从远端备份恢复：' : '将从远端最新备份恢复。'),
            name ? h('div', { className: PREFIX + '-item-name' }, name) : null,
            h('div', null, '恢复前会自动为当前配置创建一份本地快照，可用它回滚。'),
          ),
          confirmLabel: '恢复',
          run: () => doRestore(name),
        });
      };

      /** POST /dsh-sync/restore */
      const doRestore = async (name) => {
        if (busy) return;
        if (!passphrase) { setConfirm(null); setMsg({ kind: 'error', text: '请先输入口令' }); return; }
        setBusy('restore');
        setMsg(null);
        const res = await api.restore(name ? { name, passphrase } : { passphrase });
        if (!mountedRef.current) return;
        setBusy('');
        setConfirm(null);
        if (consume(res, null)) {
          const d = res.data || {};
          setMsg({ kind: 'ok', text: '已恢复 ' + (d.restored || 0) + ' 个文件，快照：' + (d.snapshot || '—') });
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

      const backups = (status && status.remote && Array.isArray(status.remote.backups)) ? status.remote.backups : [];
      const configured = !!(status && status.configured);
      const reachable = !!(status && status.remote && status.remote.reachable);
      const lastLocalSnapshot = status && status.lastLocalSnapshot;
      const anyBusy = !!busy;

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
          h('div', { className: PREFIX + '-hint' },
            backups.length ? '远端备份（' + backups.length + '）' : '远端暂无备份条目'),
          backups.length
            ? h('div', { className: PREFIX + '-list' },
                backups.map((b, i) => h('div', { className: PREFIX + '-item', key: (b && b.name) || i },
                  h('div', { className: PREFIX + '-item-main' },
                    h('div', { className: PREFIX + '-item-name', title: b && b.name }, (b && b.name) || '(未命名)'),
                    h('div', { className: PREFIX + '-item-meta' },
                      formatSize(b && b.size) + ' · ' + formatTime(b && b.modified)),
                  ),
                  h(Button, { small: true, disabled: anyBusy, onClick: () => askRestore(b && b.name) }, '恢复'),
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
          h('div', { className: PREFIX + '-row' },
            h(Button, { variant: 'primary', disabled: anyBusy, onClick: onSaveConfig },
              busy === 'config' ? '测试中…' : '保存并测试连接'),
          ),
          h('div', { className: PREFIX + '-hint' }, '密码会随配置保存在本机 ~/.dsh/dsh-sync.json，用于访问该 WebDAV。'),
        ),

        // ---- 备份 ----
        h('div', { className: PREFIX + '-card' },
          h('div', { className: PREFIX + '-card-title' }, '备份'),
          h('div', { className: PREFIX + '-grid' },
            h(Field, {
              id: PREFIX + '-passphrase',
              label: '口令',
              type: 'password',
              placeholder: '用于加密备份',
              value: passphrase,
              disabled: anyBusy,
              autoComplete: 'new-password',
              onChange: (e) => setPassphrase(e.target.value),
            }),
          ),
          h('div', { className: PREFIX + '-hint' }, '口令只保留在内存中，不会写入磁盘；恢复时需要同一口令。'),
          h('div', { className: PREFIX + '-row' },
            h(Button, { variant: 'primary', disabled: anyBusy, onClick: onBackup },
              busy === 'backup' ? '备份中…' : '立即备份'),
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

        msg ? h(Message, { kind: msg.kind }, msg.text) : null,

        h(ConfirmModal, {
          open: !!confirm,
          title: confirm ? confirm.title : '',
          body: confirm ? confirm.body : null,
          confirmLabel: confirm ? confirm.confirmLabel : '确定',
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

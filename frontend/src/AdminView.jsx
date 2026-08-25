import { useEffect, useMemo, useState } from 'react';
import CountUp from './components/react-bits/CountUp.jsx';
import SpotlightCard from './components/react-bits/SpotlightCard.jsx';
import ShinyText from './components/react-bits/ShinyText.jsx';

function csrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : '';
}

async function requestJson(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.method && options.method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    headers['X-CSRF-Token'] = csrfToken();
  }
  const response = await fetch(url, { credentials: 'same-origin', ...options, headers });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    throw new Error(payload?.error?.message || `请求失败（HTTP ${response.status}）`);
  }
  return payload;
}

const COMPONENT_LABELS = {
  model: '模型连接',
  docker: 'Docker',
  task_packs: 'TaskPack',
  verifiers: 'Verifier',
  tool_registry: 'Tool Registry'
};

const CONNECTION_MESSAGES = {
  MODEL_CHECK_PASSED: '连接成功，模型已返回符合约束的结构化结果。',
  MODEL_AUTH_FAILED: 'API Key 错误或没有访问该模型的权限。',
  MODEL_NETWORK_ERROR: '无法连接模型服务，请检查网络和 API 地址。',
  MODEL_TIMEOUT: '模型服务响应超时。',
  MODEL_QUOTA_EXCEEDED: '模型账号额度或余额不可用。',
  MODEL_RATE_LIMITED: '模型服务触发了请求频率限制。',
  MODEL_REQUEST_REJECTED: '模型服务拒绝了本次探测请求。',
  MODEL_STRUCTURED_OUTPUT_INCOMPATIBLE: 'API 可以访问，但模型未返回要求的结构化结果。',
  MODEL_CHECK_SETUP_FAILED: '模型地址未通过安全检查，或本地连接环境不可用。'
};

export default function AdminView() {
  const [providers, setProviders] = useState([]);
  const [presets, setPresets] = useState([]);
  const [config, setConfig] = useState(null);
  const [health, setHealth] = useState(null);
  const [toolHealth, setToolHealth] = useState([]);

  const [provider, setProvider] = useState('');
  const [modelName, setModelName] = useState('');
  const [apiBaseUrl, setApiBaseUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [message, setMessage] = useState('');
  const [messageState, setMessageState] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  const [logs, setLogs] = useState([]);
  const [autoScroll, setAutoScroll] = useState(true);

  const presetsForProvider = useMemo(
    () => presets.filter((item) => item.provider === provider),
    [presets, provider]
  );

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [providerCatalog, presetCatalog, configuration] = await Promise.all([
          requestJson('/api/v1/admin/providers'),
          requestJson('/api/v1/model-presets'),
          requestJson('/api/v1/admin/configuration')
        ]);
        if (cancelled) return;
        setProviders(providerCatalog.providers || []);
        setPresets(presetCatalog.presets || []);
        setConfig(configuration);
        setProvider(configuration.provider || '');
        setModelName(configuration.model_name || '');
        setApiBaseUrl(configuration.api_base_url || '');
        setApiKey('');
        loadHealth();
      } catch (error) {
        if (!cancelled) setMessage(error.message);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadHealth() {
    try {
      addLog('info', '正在检查系统健康状态...');
      const healthData = await requestJson('/api/v1/admin/health');
      setHealth(healthData);
      try {
        const report = await requestJson('/debug/tools/health_report');
        setToolHealth(report.tools || []);
      } catch {
        setToolHealth([]);
      }
      const readyCount = healthData.checks.filter(c => c.state === 'ready').length;
      addLog('success', `健康检查完成: ${readyCount}/${healthData.checks.length} 项就绪`);
    } catch (error) {
      setMessage(error.message);
      addLog('error', `健康检查失败: ${error.message}`);
    }
  }

  function applyPreset(preset) {
    if (!preset) return;
    setProvider(preset.provider);
    setModelName(preset.model_id);
    setApiBaseUrl(preset.base_url);
  }

  function onProviderChange(nextProvider) {
    setProvider(nextProvider);
    const matching = presets.filter((item) => item.provider === nextProvider);
    if (matching.length === 1) {
      setModelName(matching[0].model_id);
      setApiBaseUrl(matching[0].base_url);
    }
    setMessage('');
  }

  async function saveConfiguration(event) {
    event.preventDefault();
    setSaving(true);
    setMessageState('');
    setMessage('正在保存服务端配置…');
    addLog('info', '开始保存模型配置...');
    const payload = {
      provider,
      model_name: modelName.trim(),
      api_base_url: apiBaseUrl.trim()
    };
    if (apiKey) payload.api_key = apiKey;
    try {
      const saved = await requestJson('/api/v1/admin/configuration', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      setConfig(saved);
      setApiKey('');
      setMessage('配置已保存。API Key 已转交服务端安全存储。');
      setMessageState('success');
      addLog('success', `配置保存成功: ${provider} / ${modelName}`);
      await loadHealth();
    } catch (error) {
      setMessage(error.message);
      setMessageState('error');
      addLog('error', `配置保存失败: ${error.message}`);
    } finally {
      setSaving(false);
    }
  }

  async function testConnection() {
    setTesting(true);
    setMessageState('');
    setMessage('正在执行 API 可达性与结构化输出检测…');
    addLog('info', '开始测试模型连接...');
    try {
      const result = await requestJson('/api/v1/admin/connection-test', {
        method: 'POST',
        body: '{}'
      });
      const summary = CONNECTION_MESSAGES[result.code] || result.message;
      setMessage(`${summary}（${result.latency_ms} ms，模型 ${result.model}）`);
      setMessageState(result.status === 'ok' ? 'success' : 'error');
      addLog(result.status === 'ok' ? 'success' : 'error',
        `连接测试完成: ${summary} (${result.latency_ms}ms)`);
      setConfig(await requestJson('/api/v1/admin/configuration'));
      await loadHealth();
    } catch (error) {
      setMessage(error.message);
      setMessageState('error');
      addLog('error', `连接测试失败: ${error.message}`);
    } finally {
      setTesting(false);
    }
  }

  function addLog(level, message) {
    const timestamp = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    setLogs(prev => [...prev, { timestamp, level, message }]);
  }

  function clearLogs() {
    setLogs([]);
  }

  useEffect(() => {
    if (autoScroll && logs.length > 0) {
      const logContainer = document.querySelector('.log-entries');
      if (logContainer) {
        logContainer.scrollTop = logContainer.scrollHeight;
      }
    }
  }, [logs, autoScroll]);

  const writable = config ? config.writable : false;

  return (
    <div className="admin-view">
      <section className="hero hero--compact">
        <ShinyText
          className="eyebrow"
          text="DEPLOYMENT ADMIN CONSOLE"
          color="#7c8ba0"
          shineColor="#e8eef4"
          speed={3.2}
        />
        <h1>部署管理与模型接入</h1>
        <p className="hero-copy">
          配置比赛模型连接、切换国产大模型预设，并完成启动前健康检查。工具、验证器、安全策略与执行逻辑为只读部署资产。
        </p>
      </section>

      <div className="admin-status-strip">
        {[
          ['配置状态', config ? (config.credential_configured ? '已配置密钥' : '待配置密钥') : '读取中'],
          ['当前模型', config ? (config.model_name || '未配置') : '—'],
          ['连接状态', config ? (config.connection_succeeded ? '结构化检测通过' : '未通过检测') : '未检测'],
          ['运行模式', config ? (config.mode === 'competition' ? '比赛锁定' : '部署准备') : '—']
        ].map(([label, value]) => (
          <div key={label} className="admin-stat">
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>

      <div className="admin-grid">
        <SpotlightCard className="panel" spotlightColor="rgba(34, 211, 238, 0.10)">
          <div className="panel-heading">
            <div>
              <p className="step-label">MODEL CONNECTION</p>
              <h2>国产大模型配置</h2>
            </div>
            <span className="panel-tag">{writable ? '可配置' : '只读锁定'}</span>
          </div>

          {providers.length > 0 && presets.length > 0 ? (
            <div className="preset-row">
              <span className="field-label">一键预设</span>
              <div className="preset-chips">
                {presets.map((preset) => (
                  <button
                    key={preset.preset_id}
                    type="button"
                    className={`preset-chip ${preset.provider === provider ? 'is-active' : ''}`}
                    disabled={!writable}
                    onClick={() => applyPreset(preset)}
                    title={`${preset.base_url} · ${preset.model_id}`}
                  >
                    {preset.display_name}
                    {preset.security_default ? <em>默认</em> : null}
                  </button>
                ))}
              </div>
            </div>
          ) : null}

          <form onSubmit={saveConfiguration} noValidate>
            <label className="field-group">
              <span className="field-label">模型供应商</span>
              <select
                className="admin-select"
                value={provider}
                disabled={!writable}
                onChange={(event) => onProviderChange(event.target.value)}
                required
              >
                {providers.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
              {presetsForProvider.length === 1 ? (
                <span className="field-hint">
                  已自动填充预设：{presetsForProvider[0].model_id}（{presetsForProvider[0].base_url}）
                </span>
              ) : null}
            </label>

            <label className="field-group">
              <span className="field-label">模型名称</span>
              <input
                type="text"
                maxLength={255}
                required
                disabled={!writable}
                value={modelName}
                onChange={(event) => setModelName(event.target.value)}
                placeholder="例如 deepseek-chat"
              />
            </label>

            <label className="field-group">
              <span className="field-label">API Base URL</span>
              <input
                type="url"
                maxLength={2048}
                required
                disabled={!writable}
                value={apiBaseUrl}
                onChange={(event) => setApiBaseUrl(event.target.value)}
                placeholder="https://api.example.cn/v1"
                autoComplete="off"
                spellCheck={false}
              />
            </label>

            <label className="field-group">
              <span className="field-label">API Key</span>
              <input
                type="password"
                maxLength={16384}
                disabled={!writable}
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder="留空则保留服务端已有密钥"
                autoComplete="new-password"
              />
              <span className="field-hint">密钥只提交到服务端安全存储，不会回显或保存在浏览器中。</span>
            </label>

            <div className="admin-actions">
              <button className="run-button" type="submit" disabled={!writable || saving}>
                <span className="run-button-icon" aria-hidden="true">✓</span>
                {saving ? '保存中…' : '保存配置'}
              </button>
              <button
                className="secondary-button"
                type="button"
                disabled={!writable || !config?.credential_configured || testing}
                onClick={testConnection}
              >
                {testing ? '检测中…' : '测试连接'}
              </button>
            </div>
          </form>

          <p className={`admin-message ${messageState}`} role="status" aria-live="polite" hidden={!message}>
            {message}
          </p>
        </SpotlightCard>

        <SpotlightCard className="panel" spotlightColor="rgba(52, 211, 153, 0.08)">
          <div className="panel-heading">
            <div>
              <p className="step-label">STARTUP GATE</p>
              <h2>比赛启动前检查</h2>
            </div>
            <button className="secondary-button compact" type="button" onClick={loadHealth}>
              刷新
            </button>
          </div>

          {health ? (
            <>
              <div className={`overall-health ${health.overall_ready ? 'ready' : ''}`}>
                {health.overall_ready ? '启动检查全部通过，可以进入比赛展示。' : '存在未就绪项目，请在比赛启动前处理。'}
              </div>
              <ul className="health-list" aria-live="polite">
                {health.checks.map((check) => (
                  <li key={check.component} className={`health-item ${check.state}`}>
                    <span className="health-mark">
                      {check.state === 'ready' ? '✓' : check.state === 'degraded' ? '!' : '×'}
                    </span>
                    <div className="health-body">
                      <span className="health-name">
                        {COMPONENT_LABELS[check.component] || check.component}
                      </span>
                      <span className="health-detail">{check.message}</span>
                      {check.component === 'tool_registry' && toolHealth.length > 0 ? (
                        <ul className="tool-health-list">
                          {toolHealth.map((tool) => (
                            <li
                              key={tool.tool_id}
                              title={tool.last_health_exception || tool.message}
                            >
                              <span className={`tool-health-dot ${tool.healthy ? 'ok' : 'bad'}`} aria-hidden="true" />
                              {tool.tool_id}
                              {!tool.healthy ? `: ${tool.message}` : ''}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </div>
                    {check.registered_count != null ? (
                      <CountUp className="health-count" to={check.registered_count} duration={0.6} />
                    ) : null}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <div className="overall-health">正在检查系统状态…</div>
          )}
        </SpotlightCard>

        <SpotlightCard className="panel" spotlightColor="rgba(168, 85, 247, 0.08)">
          <div className="panel-heading">
            <div>
              <p className="step-label">EXECUTION LOGS</p>
              <h2>智能体执行日志</h2>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', color: '#94a3b8' }}>
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                />
                自动滚动
              </label>
              <button className="secondary-button compact" type="button" onClick={clearLogs}>
                清空日志
              </button>
            </div>
          </div>

          <div className="log-container">
            <div className="log-entries">
              {logs.length === 0 ? (
                <div className="log-empty">暂无执行日志</div>
              ) : (
                logs.map((log, index) => (
                  <div key={index} className={`log-entry log-${log.level}`}>
                    <span className="log-timestamp">{log.timestamp}</span>
                    <span className="log-level">{log.level.toUpperCase()}</span>
                    <span className="log-message">{log.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </SpotlightCard>
      </div>

      <SpotlightCard className="panel admin-boundary" spotlightColor="rgba(245, 178, 63, 0.06)">
        <p className="step-label">IMMUTABLE SECURITY BOUNDARY</p>
        <h2>管理员权限边界</h2>
        <p>
          本页面仅管理模型供应商、模型名称、连接地址和服务端凭据。工具、验证器、安全策略、Docker
          参数与任务执行逻辑均为只读部署资产，无法从浏览器修改。
        </p>
      </SpotlightCard>
    </div>
  );
}

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import DecryptedText from './components/react-bits/DecryptedText.jsx';
import ShinyText from './components/react-bits/ShinyText.jsx';
import CountUp from './components/react-bits/CountUp.jsx';
import SpotlightCard from './components/react-bits/SpotlightCard.jsx';
import Magnet from './components/react-bits/Magnet.jsx';
import Noise from './components/react-bits/Noise.jsx';
import AdminView from './AdminView.jsx';

const STATUS_LABELS = {
  idle: '待运行',
  queued: '已进入队列',
  planning: '正在规划',
  validating_plan: '正在校验计划',
  running: '正在执行',
  waiting_human: '等待人工确认',
  completed: '已完成',
  failed: '执行失败',
  blocked: '已阻断',
  cancelled: '已取消'
};

const PHASE_ORDER = ['Task', 'Plan', 'Tool', 'Policy', 'Evidence', 'Verification'];
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'blocked', 'cancelled']);

const SCENARIOS = [
  {
    id: 'source.audit.python',
    icon: 'PY',
    iconClass: 'icon-source',
    title: 'Python源码审计',
    desc: '静态数据流与受控假设验证',
    label: '上传材料并开始审计',
    mediaType: 'application/zip',
    accept: '.zip,application/zip',
    placeholder: '例如：审计上传的 Python 项目，分析 SQL 注入数据流并完成受控假设验证。',
    inputLabel: '上传Python源码压缩包',
    fileHint: '选择一个经过授权的 .zip 文件'
  },
  {
    id: 'pwn.ret2win',
    icon: 'PWN',
    iconClass: 'icon-pwn',
    title: 'Pwn Ret2win利用',
    desc: '二进制属性分析与结构化溢出',
    label: '上传二进制并开始利用',
    mediaType: 'application/x-executable',
    accept: 'application/x-executable,.elf,.bin,application/octet-stream',
    placeholder: '例如：分析上传的 ret2win 二进制属性，构造结构化溢出载荷触发 win。',
    inputLabel: '上传 x86-64 ELF 可执行文件',
    fileHint: '选择一个经过授权的 ret2win 二进制'
  },
  {
    id: 'reverse.keycheck',
    icon: 'RE',
    iconClass: 'icon-reverse',
    title: '逆向Keycheck分析',
    desc: '静态提取与密钥运行验证',
    label: '上传二进制并开始逆向',
    mediaType: 'application/octet-stream',
    accept: 'application/octet-stream,.bin',
    placeholder: '例如：静态提取 keycheck 的变换与目标字节，推导密钥并完成运行验证。',
    inputLabel: '上传 keycheck 二进制文件',
    fileHint: '选择一个经过授权的 keycheck 二进制'
  },
  {
    id: 'incident.login_chain',
    icon: 'IR',
    iconClass: 'icon-incident',
    title: '登录链应急响应',
    desc: '只读日志调查与攻击链重建',
    label: '上传日志并开始调查',
    mediaType: 'application/zip',
    accept: '.zip,application/zip',
    placeholder: '例如：调查上传的日志包，识别失败登录到敏感访问的攻击链。',
    inputLabel: '上传日志压缩包',
    fileHint: '选择一个经过授权的 .zip 日志包'
  },
  {
    id: 'web.idor',
    icon: 'WEB',
    iconClass: '',
    title: 'Web安全评估',
    desc: '本地受控靶场 · 越权（IDOR）评估',
    label: '开始安全评估',
    placeholder: '例如：评估授权订单接口是否存在跨租户访问风险，并给出证据链。'
  }
];

function csrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : '';
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const message = payload?.error?.message || `请求失败（HTTP ${response.status}）`;
    throw new Error(message);
  }
  return payload;
}

function phaseForEvent(eventType) {
  if (['plan_proposed', 'plan_accepted', 'plan_rejected', 'replan_triggered'].includes(eventType)) {
    return 'Plan';
  }
  if (['tool_candidates_compared', 'execution_started', 'step_state_changed'].includes(eventType)) {
    return 'Tool';
  }
  if (['policy_allowed', 'policy_denied', 'human_decision'].includes(eventType)) {
    return 'Policy';
  }
  if (eventType === 'execution_finished') {
    return 'Evidence';
  }
  if (['verification_completed', 'run_finished', 'run_interrupted'].includes(eventType)) {
    return 'Verification';
  }
  return 'Task';
}

function eventLabel(eventType) {
  return String(eventType || 'audit_event')
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function formatTime(timestamp) {
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return '--:--:--';
  return parsed.toLocaleTimeString('zh-CN', { hour12: false });
}

function WorkbenchView() {
  const [scenarioId, setScenarioId] = useState('source.audit.python');
  const [requestText, setRequestText] = useState('');
  const [remoteHost, setRemoteHost] = useState('');
  const [remotePort, setRemotePort] = useState('');
  const [fileName, setFileName] = useState('');
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [formMessage, setFormMessage] = useState('');
  const [runtimeOffline, setRuntimeOffline] = useState(false);

  const [status, setStatus] = useState('idle');
  const [activePhase, setActivePhase] = useState('Task');
  const [currentStep, setCurrentStep] = useState('等待任务输入');
  const [verdict, setVerdict] = useState(null);
  const [auditEvents, setAuditEvents] = useState([]);
  const [auditCount, setAuditCount] = useState(0);
  const [runReference, setRunReference] = useState('运行后将在此显示可验证事件。');
  const [executionLogs, setExecutionLogs] = useState([]);
  const [recentRuns, setRecentRuns] = useState([]);
  const [recentRunsMessage, setRecentRunsMessage] = useState('');

  const fileInputRef = useRef(null);
  const runIdRef = useRef(null);
  const pollGenerationRef = useRef(0);
  const latestSequenceRef = useRef(0);
  const logContainerRef = useRef(null);

  const scenario = useMemo(
    () => SCENARIOS.find((item) => item.id === scenarioId) || SCENARIOS[0],
    [scenarioId]
  );

  useEffect(() => {
    checkRuntimeDataSources();
    loadRecentRuns({ restoreActive: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function checkRuntimeDataSources() {
    try {
      const sources = await requestJson('/api/v1/runtime-data-sources');
      if (sources.runs !== 'live') {
        setRuntimeOffline(true);
        setBusy(true);
        setFormMessage('当前没有真实 Run 数据源，页面不会生成或展示模拟执行结果。');
      }
    } catch {
      setRuntimeOffline(true);
      setBusy(true);
      setFormMessage('无法确认运行数据源。');
    }
  }

  async function loadRecentRuns({ restoreActive = false } = {}) {
    try {
      const payload = await requestJson('/api/v1/runs?limit=20');
      const items = payload.items || [];
      setRecentRuns(items);
      setRecentRunsMessage('');
      if (restoreActive) {
        const active = items.find((item) => !TERMINAL_STATUSES.has(item.status));
        if (active) {
          await loadRun(active.run_id);
        }
      }
    } catch {
      setRecentRunsMessage('无法加载最近任务。');
    }
  }

  function addLog(message, level = 'info') {
    const timestamp = new Date().toLocaleTimeString('zh-CN', { hour12: false, fractionalSecondDigits: 3 });
    setExecutionLogs((prev) => [...prev, { timestamp, message, level }]);
    // 自动滚动到底部
    setTimeout(() => {
      if (logContainerRef.current) {
        logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
      }
    }, 50);
  }

  function resetTrace() {
    latestSequenceRef.current = 0;
    setAuditEvents([]);
    setAuditCount(0);
    setVerdict(null);
    setCurrentStep('任务已接收，等待规划');
    setActivePhase('Task');
    setExecutionLogs([]);
  }

  function selectScenario(id) {
    const target = SCENARIOS.find((item) => item.id === id);
    if (!target || target.disabled) return;
    setScenarioId(id);
    setFile(null);
    setFileName('');
    setFormMessage('');
  }

  function handleFileChange(event) {
    const selected = event.target.files && event.target.files[0];
    if (selected) {
      setFile(selected);
      setFileName(selected.name);
    } else {
      setFile(null);
      setFileName('');
    }
  }

  async function uploadArtifact() {
    const payload = await requestJson('/api/v1/artifacts', {
      method: 'POST',
      headers: {
        'Content-Type': scenario.mediaType,
        'X-CSRF-Token': csrfToken()
      },
      body: file
    });
    return payload.artifact_id;
  }

  function scenarioInput() {
    if (scenario.id === 'source.audit.python') {
      return { language: 'python', audit_scope: 'sql_injection' };
    }
    if (scenario.id === 'pwn.ret2win') {
      const input = { exploit_kind: 'ret2win' };
      const host = remoteHost.trim();
      const port = remotePort.trim();
      if (host && port) {
        input.target_host = host;
        input.target_port = Number(port);
      }
      return input;
    }
    if (scenario.id === 'reverse.keycheck') {
      return { transform_kind: 'xor' };
    }
    if (scenario.id === 'incident.login_chain') {
      return { log_format: 'jsonl_csv' };
    }
    return {};
  }

  async function createRun(artifactId) {
    return requestJson('/api/v1/runs', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken()
      },
      body: JSON.stringify({
        task_pack_id: scenario.id,
        request_text: requestText.trim(),
        artifact_id: artifactId,
        scenario_input: scenarioInput()
      })
    });
  }

  function applySummary(summary) {
    setStatus(summary.status || 'idle');
    if (summary.current_step) {
      const stepText = `${summary.current_step.ordinal}. ${summary.current_step.objective}`;
      setCurrentStep(stepText);
      addLog(`步骤更新: ${stepText}`, 'info');
    } else if (summary.status === 'queued') {
      setCurrentStep('等待执行资源');
      addLog('任务已进入队列，等待执行资源', 'info');
    } else if (TERMINAL_STATUSES.has(summary.status)) {
      setCurrentStep('执行流程已结束');
      addLog(`任务结束，状态: ${STATUS_LABELS[summary.status] || summary.status}`, summary.status === 'completed' ? 'success' : 'error');
    }
    if (summary.verdict) {
      setVerdict(summary.verdict);
      setActivePhase('Verification');
      addLog(`验证完成: ${summary.verdict.outcome} - ${summary.verdict.summary}`, summary.verdict.outcome === 'success' ? 'success' : 'warn');
    }
  }

  function appendAuditEvent(event) {
    setAuditEvents((prev) => {
      const exists = prev.some((item) => item.sequence === event.sequence);
      if (exists) return prev;
      return [...prev, event];
    });
    latestSequenceRef.current = Math.max(latestSequenceRef.current, Number(event.sequence) || 0);
    setAuditCount((prev) => Math.max(prev, latestSequenceRef.current));
    const phase = phaseForEvent(event.event_type);
    setActivePhase(phase);
    addLog(`[${phase}] ${eventLabel(event.event_type)}: ${event.outcome || '事件已记录'}`, 'debug');
  }

  async function pollAudit(runId) {
    const payload = await requestJson(
      `/api/v1/runs/${encodeURIComponent(runId)}/audit?after_sequence=${latestSequenceRef.current}`
    );
    for (const event of payload.events || []) {
      appendAuditEvent(event);
    }
  }

  async function pollRun(runId, generation) {
    while (runIdRef.current === runId && pollGenerationRef.current === generation) {
      try {
        const summary = await requestJson(`/api/v1/runs/${encodeURIComponent(runId)}`);
        applySummary(summary);
        await pollAudit(runId);
        if (TERMINAL_STATUSES.has(summary.status)) {
          setBusy(false);
          loadRecentRuns();
          return;
        }
      } catch (error) {
        setFormMessage(error instanceof Error ? error.message : '无法获取运行状态。');
        setBusy(false);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 1200));
    }
  }

  async function loadRun(runId) {
    pollGenerationRef.current += 1;
    const generation = pollGenerationRef.current;
    runIdRef.current = runId;
    resetTrace();
    setRunReference(`Run ${runId}`);
    setFormMessage('');
    try {
      const summary = await requestJson(`/api/v1/runs/${encodeURIComponent(runId)}`);
      applySummary(summary);
      await pollAudit(runId);
      const active = !TERMINAL_STATUSES.has(summary.status);
      setBusy(active);
      if (active) {
        await pollRun(runId, generation);
      }
    } catch (error) {
      setFormMessage(error instanceof Error ? error.message : '无法加载任务记录。');
      setBusy(false);
    }
  }

  function restartFromHistory(item) {
    const target = SCENARIOS.find((scenarioItem) => scenarioItem.id === item.task_pack);
    if (!target) {
      setFormMessage('该历史任务所属场景已不可用。');
      return;
    }
    pollGenerationRef.current += 1;
    runIdRef.current = null;
    setScenarioId(target.id);
    setRequestText(item.request_text || item.request_preview || '');
    setFile(null);
    setFileName('');
    setStatus('idle');
    setBusy(false);
    resetTrace();
    setCurrentStep('已恢复任务输入，等待重新创建');
    setRunReference('历史任务已载入；重新创建后将在此显示新的可验证事件。');
    setFormMessage(
      target.mediaType
        ? '已恢复任务描述。原始附件已删除，请重新上传材料后启动。'
        : '已恢复任务描述。确认范围后可重新启动。'
    );
  }

  async function startRun(event) {
    event.preventDefault();
    setFormMessage('');
    if (!csrfToken()) {
      setFormMessage('本地安全会话不可用，请重新打开工作台。');
      return;
    }
    if (scenario.mediaType && !file) {
      setFormMessage('请先选择要上传的材料文件。');
      return;
    }

    setBusy(true);
    resetTrace();
    setStatus('queued');
    addLog('开始创建安全任务...', 'info');
    let artifactId = null;
    try {
      if (scenario.mediaType) {
        addLog(`上传文件: ${fileName}`, 'info');
        artifactId = await uploadArtifact();
        addLog(`文件上传成功，Artifact ID: ${artifactId}`, 'success');
      }
      addLog('创建运行实例...', 'info');
      const accepted = await createRun(artifactId);
      runIdRef.current = accepted.run_id;
      pollGenerationRef.current += 1;
      setRunReference(`Run ${accepted.run_id}`);
      setStatus(accepted.status);
      addLog(`任务已创建，Run ID: ${accepted.run_id}`, 'success');
      addLog('开始轮询任务状态...', 'info');
      loadRecentRuns();
      await pollRun(accepted.run_id, pollGenerationRef.current);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : '无法创建安全任务。';
      setFormMessage(errorMsg);
      setStatus('failed');
      setCurrentStep('任务未启动');
      setBusy(false);
      addLog(`任务创建失败: ${errorMsg}`, 'error');
    }
  }

  const runButtonLabel = busy && status !== 'idle' && status !== 'failed'
    ? '智能体运行中…'
    : scenario.label;

  return (
    <>
      <section className="hero">
        <ShinyText
          className="eyebrow"
          text="AUTONOMOUS SECURITY OPERATIONS"
          color="#7c8ba0"
          shineColor="#e8eef4"
          speed={3.2}
        />
        <h1>
          <DecryptedText
            text="网络安全智能体工作台"
            speed={46}
            maxIterations={12}
            sequential
            useOriginalCharsOnly
            revealDirection="start"
            animateOn="view"
            className="hero-decrypted"
            encryptedClassName="hero-encrypted"
          />
        </h1>
        <p className="hero-copy">
          从任务理解、规划和受控工具执行，到证据验证与审计留痕，完成可复核的安全任务闭环。
        </p>
        <div className="trust-row" aria-label="系统安全能力">
          <span className="trust-chip">策略门禁</span>
          <span className="trust-chip">隔离执行</span>
          <span className="trust-chip">证据验证</span>
          <span className="trust-chip">全程审计</span>
        </div>
      </section>

      <div className="workspace-grid">
        {/* --- Task intake --- */}
        <SpotlightCard className="panel" spotlightColor="rgba(34, 211, 238, 0.10)">
          <div className="panel-heading">
            <div>
              <p className="step-label">01 / TASK INTAKE</p>
              <h2>创建安全任务</h2>
            </div>
            <span className="panel-tag">受控输入</span>
          </div>

          <form onSubmit={startRun} noValidate>
            <div className="scenario-grid" role="radiogroup" aria-label="选择安全场景">
              {SCENARIOS.map((item) => (
                <label
                  key={item.id}
                  className={[
                    'scenario-card',
                    item.id === scenarioId ? 'is-selected' : '',
                    item.disabled ? 'is-disabled' : ''
                  ]
                    .filter(Boolean)
                    .join(' ')}
                >
                  <input
                    type="radio"
                    name="task-pack"
                    value={item.id}
                    checked={item.id === scenarioId}
                    disabled={item.disabled}
                    onChange={() => selectScenario(item.id)}
                  />
                  <span className={`scenario-icon ${item.iconClass}`} aria-hidden="true">
                    {item.icon}
                  </span>
                  <span>
                    <strong>{item.title}</strong>
                    <small>{item.desc}</small>
                  </span>
                  <span className="scenario-check" aria-hidden="true">✓</span>
                </label>
              ))}
            </div>

            <label className="field-group">
              <span className="field-label">自然语言任务描述（可选）</span>
              <textarea
                value={requestText}
                onChange={(event) => setRequestText(event.target.value)}
                rows={4}
                maxLength={100000}
                placeholder={scenario.placeholder}
              />
              <span className="field-hint">可不填；直接上传材料即可启动，智能体将按场景自动生成执行计划。</span>
            </label>

            {scenario.id === 'pwn.ret2win' ? (
              <div className="field-group remote-fields">
                <span className="field-label">靶机地址与端口（可选）</span>
                <div className="remote-row">
                  <input
                    type="text"
                    value={remoteHost}
                    onChange={(event) => setRemoteHost(event.target.value)}
                    placeholder="127.0.0.1"
                    maxLength={255}
                    autoComplete="off"
                    spellCheck="false"
                  />
                  <span className="remote-sep" aria-hidden="true">:</span>
                  <input
                    type="number"
                    value={remotePort}
                    onChange={(event) => setRemotePort(event.target.value)}
                    placeholder="1337"
                    min={1}
                    max={65535}
                  />
                </div>
                <span className="field-hint">留空=内置受控模拟；填写本机 loopback 靶场（如 127.0.0.1:1337）则走真实 TCP 连接。</span>
              </div>
            ) : null}

            {scenario.mediaType ? (
              <div className="field-group">
                <div
                  className="upload-zone"
                  role="button"
                  tabIndex={0}
                  onClick={() => fileInputRef.current && fileInputRef.current.click()}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      fileInputRef.current && fileInputRef.current.click();
                    }
                  }}
                >
                  <span className="upload-symbol" aria-hidden="true">
                    {scenario.icon}
                  </span>
                  <span>
                    <strong>{scenario.inputLabel}</strong>
                    <small>{fileName || scenario.fileHint}</small>
                  </span>
                  <span className="upload-action">选择文件</span>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept={scenario.accept}
                    onChange={handleFileChange}
                  />
                </div>
                <p className="upload-note">材料仅进入受控Artifact流程，不在浏览器或宿主目录中执行。</p>
              </div>
            ) : null}

            <div className="form-message" role="alert" hidden={!formMessage}>
              {formMessage}
            </div>

            <Magnet wrapperClassName="magnet-run" magnetStrength={8} padding={40} disabled={busy}>
              <button className="run-button" type="submit" disabled={busy}>
                <span className="run-button-icon" aria-hidden="true">▶</span>
                {runButtonLabel}
              </button>
            </Magnet>
          </form>
        </SpotlightCard>

        {/* --- Execution trace --- */}
        <SpotlightCard className="panel" spotlightColor="rgba(34, 211, 238, 0.08)">
          <div className="panel-heading">
            <div>
              <p className="step-label">02 / EXECUTION TRACE</p>
              <h2>智能体执行过程</h2>
            </div>
            <span className="panel-tag" data-status={status}>{STATUS_LABELS[status] || status}</span>
          </div>

          <div className="run-overview" aria-live="polite">
            <div className="overview-item">
              <span>当前步骤</span>
              <strong>{currentStep}</strong>
            </div>
            <div className="overview-item verdict-overview">
              <span>验证结论</span>
              <strong data-outcome={verdict?.outcome}>
                {verdict ? verdict.outcome : '尚未生成'}
              </strong>
              <small>
                {verdict
                  ? verdict.summary
                  : '工具成功不等于任务成功，最终结果必须经过Verifier。'}
              </small>
            </div>
          </div>

          <ol className="phase-track" aria-label="智能体执行阶段">
            {PHASE_ORDER.map((phase, index) => {
              const activeIndex = PHASE_ORDER.indexOf(activePhase);
              return (
                <li
                  key={phase}
                  className={
                    index < activeIndex
                      ? 'is-complete'
                      : index === activeIndex
                        ? 'is-active'
                        : ''
                  }
                >
                  <span className="phase-dot">{index + 1}</span>
                  <strong>{phase}</strong>
                  <small>{phase}</small>
                </li>
              );
            })}
          </ol>

          <div className="timeline-heading">
            <div>
              <h3>Audit 时间线</h3>
              <p>{runReference}</p>
            </div>
            <span className="audit-count">
              <CountUp to={auditCount} duration={0.8} /> events
            </span>
          </div>

          <ol className="audit-timeline" aria-live="polite">
            {auditEvents.length === 0 ? (
              <li className="audit-empty">
                <span className="empty-radar" aria-hidden="true" />
                <strong>等待智能体启动</strong>
                <small>Task、Plan、Tool、Policy、Evidence和Verification将按序呈现。</small>
              </li>
            ) : (
              auditEvents.map((event) => (
                <li key={event.event_id || event.sequence} className="audit-event">
                  <span className="audit-sequence">
                    {String(event.sequence).padStart(2, '0')}
                  </span>
                  <div className="audit-body">
                    <strong>{`${phaseForEvent(event.event_type)} · ${eventLabel(event.event_type)}`}</strong>
                    <p>{event.outcome || '审计事件已记录。'}</p>
                    {Array.isArray(event.reason_codes) && event.reason_codes.length > 0 ? (
                      <small>{event.reason_codes.join(' · ')}</small>
                    ) : null}
                  </div>
                  <time className="audit-time">{formatTime(event.timestamp)}</time>
                </li>
              ))
            )}
          </ol>
        </SpotlightCard>

        <SpotlightCard className="panel panel-history" spotlightColor="rgba(34, 211, 238, 0.06)">
          <div className="panel-heading">
            <div>
              <p className="step-label">RECENT RUNS</p>
              <h2>最近任务</h2>
            </div>
            <button className="secondary-button compact" type="button" onClick={() => loadRecentRuns()}>
              刷新
            </button>
          </div>
          {recentRuns.length === 0 ? (
            <div className="history-empty">
              <strong>暂无最近任务</strong>
              <small>{recentRunsMessage || '创建任务后，可在这里恢复查看其状态与审计记录。'}</small>
            </div>
          ) : (
            <ol className="history-list" aria-label="最近任务">
              {recentRuns.map((item) => (
                <li key={item.run_id} className="history-item">
                  <button type="button" onClick={() => loadRun(item.run_id)}>
                    <span className="history-status">{STATUS_LABELS[item.status] || item.status}</span>
                    <strong>{item.task_pack}</strong>
                    <small>{item.request_preview || '未提供任务描述'}</small>
                    <time>{formatTime(item.updated_at)}</time>
                  </button>
                  {item.error_code === 'RUN_INTERRUPTED_BY_RESTART' ? (
                    <span className="history-interrupted">服务重启导致中断</span>
                  ) : null}
                  <button
                    className="history-restart"
                    type="button"
                    onClick={() => restartFromHistory(item)}
                  >
                    重新开始
                  </button>
                </li>
              ))}
            </ol>
          )}
        </SpotlightCard>

        {/* --- Execution Logs --- */}
        <SpotlightCard className="panel panel-logs" spotlightColor="rgba(34, 211, 238, 0.06)">
          <div className="panel-heading">
            <div>
              <p className="step-label">03 / EXECUTION LOGS</p>
              <h2>实时运行日志</h2>
            </div>
            <span className="panel-tag">实时更新</span>
          </div>

          <div className="log-container" ref={logContainerRef}>
            {executionLogs.length === 0 ? (
              <div className="log-empty">
                <span className="empty-terminal" aria-hidden="true">$_</span>
                <strong>等待日志输出</strong>
                <small>智能体运行时的详细日志将在此显示</small>
              </div>
            ) : (
              <div className="log-entries">
                {executionLogs.map((log, index) => (
                  <div key={index} className={`log-entry log-${log.level}`}>
                    <span className="log-time">{log.timestamp}</span>
                    <span className="log-level">[{log.level.toUpperCase()}]</span>
                    <span className="log-message">{log.message}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </SpotlightCard>
      </div>

      {runtimeOffline ? (
        <div className="runtime-source-banner">
          <strong>任务运行数据源尚未启用</strong>
          <span>当前启动模式仅提供真实管理控制台；Run、Evidence、Audit 与 Report 不会使用模拟数据。</span>
        </div>
      ) : null}
    </>
  );
}

export default function App() {
  const [view, setView] = useState(
    () => (window.location.pathname === '/admin' ? 'admin' : 'workbench')
  );

  function switchView(next) {
    setView(next);
    const path = next === 'admin' ? '/admin' : '/';
    if (window.location.pathname !== path) {
      window.history.pushState({}, '', path);
    }
  }

  useEffect(() => {
    const onPopState = () => {
      setView(window.location.pathname === '/admin' ? 'admin' : 'workbench');
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  return (
    <>
      <div className="app-backdrop" aria-hidden="true" />
      <Noise patternAlpha={12} patternRefreshInterval={3} />

      <div className="app-shell">
        <header className="topbar">
          <a className="brand" href="/" aria-label="网络安全智能体工作台首页">
            <span className="brand-mark" aria-hidden="true">CA</span>
            <span>
              <strong>Cyber Agent</strong>
              <small>通用网络安全智能体</small>
            </span>
          </a>
          <nav className="main-nav" aria-label="主导航">
            <button
              type="button"
              className={`nav-tab ${view === 'workbench' ? 'is-active' : ''}`}
              onClick={() => switchView('workbench')}
            >
              工作台
            </button>
            <button
              type="button"
              className={`nav-tab ${view === 'admin' ? 'is-active' : ''}`}
              onClick={() => switchView('admin')}
            >
              部署管理
            </button>
          </nav>
          <div className="system-state">
            <span className="pulse" aria-hidden="true" />
            本地安全工作台
          </div>
        </header>

        {view === 'admin' ? <AdminView /> : <WorkbenchView />}

        <footer className="footer">
          <span>General Cybersecurity Agent · Competition Workbench</span>
          <span>本地运行 · 无第三方前端依赖</span>
        </footer>
      </div>
    </>
  );
}

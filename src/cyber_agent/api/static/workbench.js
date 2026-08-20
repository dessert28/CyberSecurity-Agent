(function () {
  "use strict";

  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const form = document.querySelector("#run-form");
  const requestText = document.querySelector("#request-text");
  const webFields = document.querySelector("#web-fields");
  const sourceFields = document.querySelector("#source-fields");
  const sourceZip = document.querySelector("#source-zip");
  const fileName = document.querySelector("#file-name");
  const runButton = document.querySelector("#run-button");
  const runButtonLabel = document.querySelector("#run-button-label");
  const formMessage = document.querySelector("#form-message");
  const runStatus = document.querySelector("#run-status");
  const currentStep = document.querySelector("#current-step");
  const verdictTitle = document.querySelector("#verdict-title");
  const verdictSummary = document.querySelector("#verdict-summary");
  const runReference = document.querySelector("#run-reference");
  const auditCount = document.querySelector("#audit-count");
  const auditTimeline = document.querySelector("#audit-timeline");
  const phaseItems = Array.from(document.querySelectorAll("[data-phase]"));
  const scenarioRadios = Array.from(document.querySelectorAll('input[name="task-pack"]'));
  const scenarioCards = Array.from(document.querySelectorAll("[data-scenario-card]"));
  const runtimeSourceBanner = document.querySelector("#runtime-source-banner");
  const runtimeSourceTitle = document.querySelector("#runtime-source-title");
  const runtimeSourceDetail = document.querySelector("#runtime-source-detail");
  const readinessLabels = Array.from(document.querySelectorAll("[data-taskpack-readiness]"));
  const evidenceCount = document.querySelector("#evidence-count");
  const evidenceList = document.querySelector("#evidence-list");
  const modelTraceCount = document.querySelector("#model-trace-count");

  const statusLabels = {
    idle: "待运行",
    queued: "已进入队列",
    planning: "正在规划",
    validating_plan: "正在校验计划",
    running: "正在执行",
    waiting_human: "等待人工确认",
    completed: "已完成",
    failed: "执行失败",
    blocked: "已阻断",
    cancelled: "已取消"
  };
  const phaseOrder = ["Task", "Plan", "Tool", "Policy", "Evidence", "Verification"];
  const terminalStatuses = new Set(["completed", "failed", "blocked", "cancelled"]);
  const readinessReasonLabels = {
    READY: "正式执行链已就绪",
    MODEL_NOT_READY: "模型尚未就绪",
    CREDENTIAL_MISSING: "模型凭据缺失",
    CAPABILITY_STALE: "模型能力检测已过期",
    CAPABILITY_FAILED: "模型能力检测失败",
    ADAPTER_NOT_READY: "模型适配器未就绪",
    PLANNER_NOT_READY: "规划服务未就绪",
    REGISTRY_NOT_READY: "工具注册表未就绪",
    POLICY_NOT_READY: "策略服务未就绪",
    ARTIFACT_RUNTIME_NOT_READY: "材料服务未就绪",
    EXECUTOR_NOT_READY: "受控执行器未就绪",
    TASKPACK_DISABLED: "TaskPack 已禁用",
    RUNTIME_SNAPSHOT_CONFLICT: "Runtime 身份发生变化"
  };
  let activeRunId = null;
  let latestAuditSequence = 0;
  let receivedAuditCount = 0;
  let pollGeneration = 0;
  let runtimeReadiness = null;
  let runtimeSourcesReady = false;
  let runBusy = false;

  function selectedTaskPack() {
    const selected = scenarioRadios.find((radio) => radio.checked);
    return selected ? selected.value : "web.idor";
  }

  function updateScenario() {
    const taskPackId = selectedTaskPack();
    const sourceSelected = taskPackId === "source.audit.python";
    webFields.hidden = sourceSelected;
    sourceFields.hidden = !sourceSelected;
    runButtonLabel.textContent = sourceSelected ? "上传材料并开始审计" : "开始安全评估";
    requestText.placeholder = sourceSelected
      ? "例如：审计上传的 Python 项目，分析 SQL 注入数据流并完成受控假设验证。"
      : "例如：评估授权订单接口是否存在跨租户访问风险，并给出证据链。";
    scenarioCards.forEach((card) => {
      card.classList.toggle("is-selected", card.dataset.scenarioCard === taskPackId);
    });
    updateRunAvailability();
    hideMessage();
  }

  function showMessage(message) {
    formMessage.textContent = message;
    formMessage.hidden = false;
  }

  function hideMessage() {
    formMessage.textContent = "";
    formMessage.hidden = true;
  }

  function setBusy(busy) {
    runBusy = busy;
    scenarioRadios.forEach((radio) => {
      radio.disabled = busy;
    });
    updateRunAvailability();
  }

  function selectedTaskPackReadiness() {
    if (!runtimeReadiness || !Array.isArray(runtimeReadiness.taskpacks)) {
      return null;
    }
    return runtimeReadiness.taskpacks.find((item) => item.task_pack_id === selectedTaskPack()) || null;
  }

  function selectedTaskPackReady() {
    const selected = selectedTaskPackReadiness();
    return Boolean(
      runtimeSourcesReady &&
      runtimeReadiness &&
      runtimeReadiness.runtime_available === true &&
      runtimeReadiness.model_ready === true &&
      runtimeReadiness.core_ready === true &&
      selected && selected.state === "READY"
    );
  }

  function updateRunAvailability() {
    runButton.disabled = runBusy || !selectedTaskPackReady();
    if (runBusy) {
      return;
    }
    const selected = selectedTaskPackReadiness();
    if (!selected || selected.state !== "READY" || !selectedTaskPackReady()) {
      runButtonLabel.textContent = "当前场景不可运行";
      return;
    }
    runButtonLabel.textContent = selectedTaskPack() === "source.audit.python"
      ? "上传材料并开始审计"
      : "开始安全评估";
  }

  function setStatus(status) {
    runStatus.dataset.status = status;
    runStatus.textContent = statusLabels[status] || status;
  }

  function setPhase(phaseName) {
    const currentIndex = phaseOrder.indexOf(phaseName);
    phaseItems.forEach((item) => {
      const itemIndex = phaseOrder.indexOf(item.dataset.phase);
      item.classList.toggle("is-complete", currentIndex >= 0 && itemIndex < currentIndex);
      item.classList.toggle("is-active", itemIndex === currentIndex);
    });
  }

  function resetTrace() {
    latestAuditSequence = 0;
    receivedAuditCount = 0;
    auditCount.textContent = "0 events";
    auditTimeline.replaceChildren(createEmptyAudit());
    verdictTitle.textContent = "尚未生成";
    verdictSummary.textContent = "工具成功不等于任务成功，最终结果必须经过 Verifier。";
    currentStep.textContent = "任务已接收，等待规划";
    evidenceCount.textContent = "0";
    modelTraceCount.textContent = "0";
    evidenceList.replaceChildren(createEmptyEvidence());
    setPhase("Task");
  }

  function createEmptyEvidence() {
    const item = document.createElement("li");
    item.className = "evidence-empty";
    item.textContent = "运行完成后在此显示证据。";
    return item;
  }

  function createEmptyAudit() {
    const item = document.createElement("li");
    item.className = "audit-empty";

    const radar = document.createElement("span");
    radar.className = "empty-radar";
    radar.setAttribute("aria-hidden", "true");

    const title = document.createElement("strong");
    title.textContent = "等待智能体启动";

    const detail = document.createElement("small");
    detail.textContent = "Task、Plan、Tool、Policy、Evidence 和 Verification 将按序呈现。";
    item.append(radar, title, detail);
    return item;
  }

  function errorMessage(payload, fallback) {
    if (payload && payload.error && typeof payload.error.message === "string") {
      return payload.error.message;
    }
    return fallback;
  }

  async function requestJson(url, options) {
    const response = await fetch(url, options);
    let payload = null;
    try {
      payload = await response.json();
    } catch (_) {
      payload = null;
    }
    if (!response.ok) {
      throw new Error(errorMessage(payload, `请求失败（HTTP ${response.status}）`));
    }
    return payload;
  }

  async function checkRuntimeDataSources() {
    const sources = await requestJson("/api/v1/runtime-data-sources", {
      credentials: "same-origin"
    });
    runtimeSourcesReady = sources.runs === "live";
    if (!runtimeSourcesReady) {
      runtimeSourceBanner.hidden = false;
      runtimeSourceTitle.textContent = "正式 Runtime 尚未就绪";
      runtimeSourceDetail.textContent = "请根据 TaskPack readiness 处理阻断项；页面不会使用模拟执行结果。";
    } else {
      runtimeSourceBanner.hidden = true;
    }
    updateRunAvailability();
  }

  function renderRuntimeReadiness(readiness) {
    runtimeReadiness = readiness;
    readinessLabels.forEach((element) => {
      const item = readiness.taskpacks.find(
        (entry) => entry.task_pack_id === element.dataset.taskpackReadiness
      );
      const state = item && typeof item.state === "string" ? item.state : "EXECUTOR_NOT_READY";
      element.dataset.state = state;
      element.textContent = `${state} · ${readinessReasonLabels[state] || "Runtime 未就绪"}`;
    });
    updateRunAvailability();
  }

  async function loadRuntimeReadiness() {
    const readiness = await requestJson("/api/v1/runtime-readiness", {
      credentials: "same-origin"
    });
    if (!readiness || !Array.isArray(readiness.taskpacks)) {
      throw new Error("Runtime readiness contract is invalid.");
    }
    renderRuntimeReadiness(readiness);
    return readiness;
  }

  async function uploadArtifact(file) {
    const payload = await requestJson("/api/v1/artifacts", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/zip",
        "X-CSRF-Token": csrfMeta.content
      },
      body: file
    });
    return payload.artifact_id;
  }

  function webScenarioInput() {
    const targetUrl = document.querySelector("#target-url").value.trim();
    const actorId = document.querySelector("#actor-id").value.trim();
    const baselineId = document.querySelector("#baseline-id").value.trim();
    const probeId = document.querySelector("#probe-id").value.trim();
    if (!targetUrl || !actorId || !baselineId || !probeId) {
      throw new Error("请完整填写授权目标与业务绑定。");
    }
    return {
      target_url: targetUrl,
      bindings: [
        {
          ordinal: 1,
          observation_type: "authorized_baseline",
          actor_id: actorId,
          expected_object_id: baselineId
        },
        {
          ordinal: 2,
          observation_type: "cross_tenant_probe",
          actor_id: actorId,
          expected_object_id: probeId
        }
      ]
    };
  }

  function sourceScenarioInput() {
    return {
      language: "python",
      audit_scope: "sql_injection"
    };
  }

  async function createRun(taskPackId, artifactId) {
    const scenarioInput = taskPackId === "source.audit.python"
      ? sourceScenarioInput()
      : webScenarioInput();
    return requestJson("/api/v1/runs", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfMeta.content
      },
      body: JSON.stringify({
        task_pack_id: taskPackId,
        request_text: requestText.value.trim(),
        artifact_id: artifactId,
        scenario_input: scenarioInput
      })
    });
  }

  function phaseForEvent(eventType) {
    if (["plan_proposed", "plan_accepted", "plan_rejected", "replan_triggered"].includes(eventType)) {
      return "Plan";
    }
    if (["tool_candidates_compared", "execution_started", "step_state_changed"].includes(eventType)) {
      return "Tool";
    }
    if (["policy_allowed", "policy_denied", "human_decision"].includes(eventType)) {
      return "Policy";
    }
    if (eventType === "execution_finished") {
      return "Evidence";
    }
    if (["verification_completed", "run_finished", "run_interrupted"].includes(eventType)) {
      return "Verification";
    }
    return "Task";
  }

  function eventLabel(eventType) {
    return String(eventType || "audit_event")
      .split("_")
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ");
  }

  function appendAuditEvent(event) {
    const empty = auditTimeline.querySelector(".audit-empty");
    if (empty) {
      empty.remove();
    }

    const item = document.createElement("li");
    item.className = "audit-event";

    const sequence = document.createElement("span");
    sequence.className = "audit-sequence";
    sequence.textContent = String(event.sequence).padStart(2, "0");

    const body = document.createElement("div");
    body.className = "audit-body";
    const title = document.createElement("strong");
    title.textContent = `${phaseForEvent(event.event_type)} · ${eventLabel(event.event_type)}`;
    const outcome = document.createElement("p");
    outcome.textContent = event.outcome || "审计事件已记录。";
    body.append(title, outcome);
    if (Array.isArray(event.reason_codes) && event.reason_codes.length > 0) {
      const reasons = document.createElement("small");
      reasons.textContent = event.reason_codes.join(" · ");
      body.append(reasons);
    }

    const time = document.createElement("time");
    time.className = "audit-time";
    time.textContent = formatTime(event.timestamp);
    item.append(sequence, body, time);
    auditTimeline.append(item);
  }

  function formatTime(timestamp) {
    const parsed = new Date(timestamp);
    if (Number.isNaN(parsed.getTime())) {
      return "--:--:--";
    }
    return parsed.toLocaleTimeString("zh-CN", { hour12: false });
  }

  function updateSummary(summary) {
    setStatus(summary.status);
    if (summary.current_step) {
      currentStep.textContent = `${summary.current_step.ordinal}. ${summary.current_step.objective}`;
    } else if (summary.status === "queued") {
      currentStep.textContent = "等待执行资源";
    } else if (terminalStatuses.has(summary.status)) {
      currentStep.textContent = "执行流程已结束";
    }

    if (summary.verdict) {
      verdictTitle.textContent = summary.verdict.outcome;
      verdictSummary.textContent = summary.verdict.summary;
      setPhase("Verification");
    }
    receivedAuditCount = Math.max(receivedAuditCount, Number(summary.audit_count) || 0);
    auditCount.textContent = `${receivedAuditCount} events`;
    evidenceCount.textContent = String(Number(summary.evidence_count) || 0);
    modelTraceCount.textContent = String(
      Array.isArray(summary.model_call_refs) ? summary.model_call_refs.length : 0
    );
  }

  async function loadEvidence(runId) {
    const payload = await requestJson(
      `/api/v1/runs/${encodeURIComponent(runId)}/evidence`,
      { credentials: "same-origin" }
    );
    const items = Array.isArray(payload.items) ? payload.items : [];
    evidenceCount.textContent = String(items.length);
    evidenceList.replaceChildren();
    if (items.length === 0) {
      evidenceList.append(createEmptyEvidence());
      return;
    }
    items.forEach((evidence) => {
      const item = document.createElement("li");
      item.className = "evidence-item";
      const title = document.createElement("strong");
      title.textContent = String(evidence.kind || "evidence");
      const summary = document.createElement("p");
      summary.textContent = String(evidence.summary || "证据摘要不可用。");
      const detail = document.createElement("small");
      detail.textContent = `${evidence.verification_method || "verification"} · confidence ${evidence.confidence ?? 0}`;
      item.append(title, summary, detail);
      evidenceList.append(item);
    });
  }

  async function pollAudit(runId) {
    const payload = await requestJson(
      `/api/v1/runs/${encodeURIComponent(runId)}/audit?after_sequence=${latestAuditSequence}`,
      { credentials: "same-origin" }
    );
    for (const event of payload.events || []) {
      appendAuditEvent(event);
      latestAuditSequence = Math.max(latestAuditSequence, Number(event.sequence) || 0);
      setPhase(phaseForEvent(event.event_type));
    }
    receivedAuditCount = Math.max(receivedAuditCount, latestAuditSequence);
    auditCount.textContent = `${receivedAuditCount} events`;
  }

  function wait(milliseconds) {
    return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
  }

  async function pollRun(runId, generation) {
    while (activeRunId === runId && generation === pollGeneration) {
      try {
        const summary = await requestJson(`/api/v1/runs/${encodeURIComponent(runId)}`, {
          credentials: "same-origin"
        });
        updateSummary(summary);
        await pollAudit(runId);
        if (terminalStatuses.has(summary.status)) {
          await loadEvidence(runId);
          setBusy(false);
          return;
        }
      } catch (error) {
        showMessage(error instanceof Error ? error.message : "无法获取运行状态。");
        setBusy(false);
        return;
      }
      await wait(1200);
    }
  }

  async function startRun(event) {
    event.preventDefault();
    hideMessage();
    const description = requestText.value.trim();
    if (!description) {
      showMessage("请先输入自然语言任务描述。");
      requestText.focus();
      return;
    }
    if (!csrfMeta || !csrfMeta.content) {
      showMessage("本地安全会话不可用，请重新打开工作台。");
      return;
    }

    const taskPackId = selectedTaskPack();
    let artifactId = null;
    setBusy(true);
    resetTrace();
    setStatus("queued");
    try {
      await loadRuntimeReadiness();
      if (!selectedTaskPackReady()) {
        const selected = selectedTaskPackReadiness();
        const state = selected ? selected.state : "TASKPACK_DISABLED";
        throw new Error(`${state} · ${readinessReasonLabels[state] || "Runtime 未就绪"}`);
      }
      if (taskPackId === "source.audit.python") {
        const file = sourceZip.files && sourceZip.files[0];
        if (!file) {
          throw new Error("Python 源码审计需要先选择 ZIP 材料。");
        }
        runButtonLabel.textContent = "正在安全上传材料…";
        artifactId = await uploadArtifact(file);
      }
      runButtonLabel.textContent = "正在创建运行…";
      const accepted = await createRun(taskPackId, artifactId);
      activeRunId = accepted.run_id;
      pollGeneration += 1;
      runReference.textContent = `Run ${activeRunId}`;
      setStatus(accepted.status);
      runButtonLabel.textContent = "智能体运行中…";
      await pollRun(activeRunId, pollGeneration);
    } catch (error) {
      showMessage(error instanceof Error ? error.message : "无法创建安全任务。");
      setStatus("failed");
      currentStep.textContent = "任务未启动";
      setBusy(false);
    } finally {
      if (!runButton.disabled) {
        runButtonLabel.textContent = selectedTaskPack() === "source.audit.python"
          ? "上传材料并开始审计"
          : "开始安全评估";
      }
    }
  }

  scenarioRadios.forEach((radio) => radio.addEventListener("change", updateScenario));
  sourceZip.addEventListener("change", () => {
    const file = sourceZip.files && sourceZip.files[0];
    fileName.textContent = file ? file.name : "选择一个经过授权的 .zip 文件";
  });
  form.addEventListener("submit", startRun);
  updateScenario();
  Promise.all([checkRuntimeDataSources(), loadRuntimeReadiness()]).catch(() => {
    runtimeReadiness = null;
    runtimeSourcesReady = false;
    runtimeSourceBanner.hidden = false;
    runtimeSourceTitle.textContent = "无法确认 Runtime 状态";
    runtimeSourceDetail.textContent = "为保持 fail-closed，所有 Run 已禁用。";
    runButtonLabel.textContent = "无法确认运行数据源";
    updateRunAvailability();
  });
}());

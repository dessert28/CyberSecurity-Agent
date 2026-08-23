"use strict";

const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
const form = document.getElementById("model-form");
const provider = document.getElementById("provider");
const modelName = document.getElementById("model-name");
const apiBaseUrl = document.getElementById("api-base-url");
const apiKey = document.getElementById("api-key");
const saveButton = document.getElementById("save-button");
const testButton = document.getElementById("test-button");
const capabilityTestButton = document.getElementById("capability-test-button");
const message = document.getElementById("operation-message");
const modelTracePath = "/api/v1/admin/model-traces";
const modelTraceList = document.getElementById("model-trace-list");
const modelTraceDetail = document.getElementById("model-trace-detail");
let selectedModelTraceId = null;

const componentLabels = {
  model: "模型连接",
  docker: "Docker",
  task_packs: "TaskPack",
  verifiers: "Verifier",
  tool_registry: "Tool Registry",
};

async function requestJson(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.method && options.method !== "GET") {
    headers.set("Content-Type", "application/json");
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error?.message || "请求未能安全完成。");
  }
  return payload;
}

function setMessage(text, state = "") {
  message.textContent = text;
  message.className = `message ${state}`.trim();
}

function addProviderOption(item) {
  const option = document.createElement("option");
  option.value = item.value;
  option.textContent = item.label;
  provider.appendChild(option);
}

function renderProviders(catalog) {
  provider.replaceChildren();
  catalog.providers.forEach(addProviderOption);
}

function renderConfiguration(config) {
  if (config.provider) provider.value = config.provider;
  modelName.value = config.model_name || "";
  apiBaseUrl.value = config.api_base_url || "";
  apiKey.value = "";

  document.getElementById("configured-status").textContent = config.credential_configured
    ? "已配置密钥"
    : "待配置密钥";
  document.getElementById("current-model").textContent = config.model_name || "未配置";
  document.getElementById("connection-status").textContent = config.connection_succeeded
    ? "结构化检测通过"
    : "未通过检测";
  document.getElementById("console-mode").textContent = config.mode === "competition"
    ? "运行锁定"
    : "部署准备";
  document.getElementById("write-state").textContent = config.writable ? "可配置" : "只读锁定";

  [provider, modelName, apiBaseUrl, apiKey, saveButton].forEach((element) => {
    element.disabled = !config.writable;
  });
  const modelTestingDisabled = !config.credential_configured || !config.writable;
  testButton.disabled = modelTestingDisabled;
  capabilityTestButton.disabled = modelTestingDisabled;
}

async function loadConfiguration() {
  const config = await requestJson("/api/v1/admin/configuration");
  renderConfiguration(config);
  return config;
}

async function loadProviders() {
  renderProviders(await requestJson("/api/v1/admin/providers"));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage("正在保存服务端配置…");
  saveButton.disabled = true;
  const payload = {
    provider: provider.value,
    model_name: modelName.value.trim(),
    api_base_url: apiBaseUrl.value.trim(),
  };
  if (apiKey.value) payload.api_key = apiKey.value;
  try {
    const config = await requestJson("/api/v1/admin/configuration", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderConfiguration(config);
    setMessage("配置已保存。API Key 已转交服务端安全存储。", "success");
    await loadHealth();
  } catch (error) {
    setMessage(error.message, "error");
  } finally {
    apiKey.value = "";
    const config = await loadConfiguration().catch(() => null);
    if (config) saveButton.disabled = !config.writable;
  }
});

async function runModelTest(path, pendingMessage, messages) {
  setMessage(pendingMessage);
  testButton.disabled = true;
  capabilityTestButton.disabled = true;
  try {
    const result = await requestJson(path, {
      method: "POST",
      body: "{}",
    });
    const summary = messages[result.code] || result.message;
    const detail = `${summary}（${result.latency_ms} ms，模型 ${result.model}）`;
    setMessage(detail, result.status === "ok" ? "success" : "error");
    await loadConfiguration();
    await loadHealth();
  } catch (error) {
    setMessage(error.message, "error");
  } finally {
    await loadModelTraces({ selectLatest: true }).catch(() => null);
    const config = await loadConfiguration().catch(() => null);
    const modelTestingDisabled = !config?.writable || !config?.credential_configured;
    testButton.disabled = modelTestingDisabled;
    capabilityTestButton.disabled = modelTestingDisabled;
  }
}

testButton.addEventListener("click", () => runModelTest(
  "/api/v1/admin/connection-test",
  "正在测试模型连接…",
  {
    MODEL_CONNECTION_PASSED: "连接成功；该模型尚未通过结构化能力验证，不能用于正式任务。",
    MODEL_REPLY_EMPTY: "模型没有返回可用的最终回复。",
    MODEL_AUTH_FAILED: "API Key 错误或没有访问该模型的权限。",
    MODEL_NETWORK_ERROR: "无法连接模型服务，请检查网络和 API 地址。",
    MODEL_TIMEOUT: "模型服务响应超时。",
    MODEL_QUOTA_EXCEEDED: "模型账号额度或余额不可用。",
    MODEL_RATE_LIMITED: "模型服务触发了请求频率限制。",
    MODEL_REQUEST_REJECTED: "模型服务拒绝了本次探测请求。",
    MODEL_CHECK_SETUP_FAILED: "模型地址未通过安全检查，或本地连接环境不可用。",
  },
));

capabilityTestButton.addEventListener("click", () => runModelTest(
  "/api/v1/admin/capability-test",
  "正在验证结构化输出能力…",
  {
    MODEL_CHECK_PASSED: "结构化能力验证通过，模型已激活。",
    MODEL_AUTH_FAILED: "API Key 错误或没有访问该模型的权限。",
    MODEL_NETWORK_ERROR: "无法连接模型服务，请检查网络和 API 地址。",
    MODEL_TIMEOUT: "模型服务响应超时。",
    MODEL_QUOTA_EXCEEDED: "模型账号额度或余额不可用。",
    MODEL_RATE_LIMITED: "模型服务触发了请求频率限制。",
    MODEL_REQUEST_REJECTED: "模型服务拒绝了本次探测请求。",
    MODEL_SCHEMA_INVALID: "API 已返回结果，但模型未满足要求的结构化格式。",
    MODEL_STRUCTURED_OUTPUT_INCOMPATIBLE: "API 可以访问，但模型未返回要求的结构化结果。",
    MODEL_CHECK_SETUP_FAILED: "模型地址未通过安全检查，或本地连接环境不可用。",
  },
));

function healthMark(state) {
  if (state === "ready") return "✓";
  if (state === "degraded") return "!";
  return "×";
}

function renderHealth(health) {
  const overall = document.getElementById("overall-health");
  overall.textContent = health.overall_ready
    ? "启动检查全部通过，可以进入任务工作台。"
    : "存在未就绪项目，请在启动任务前处理。";
  overall.className = health.overall_ready ? "overall-health ready" : "overall-health";

  const list = document.getElementById("health-list");
  list.replaceChildren();
  health.checks.forEach((check) => {
    const item = document.createElement("li");
    item.className = `health-item ${check.state}`;
    const mark = document.createElement("span");
    mark.className = "health-mark";
    mark.textContent = healthMark(check.state);
    const body = document.createElement("div");
    const name = document.createElement("span");
    name.className = "health-name";
    name.textContent = componentLabels[check.component] || check.component;
    const detail = document.createElement("span");
    detail.className = "health-detail";
    detail.textContent = check.message;
    body.append(name, detail);
    item.append(mark, body);
    list.appendChild(item);
  });
}

async function loadHealth() {
  try {
    renderHealth(await requestJson("/api/v1/admin/health"));
  } catch (error) {
    document.getElementById("overall-health").textContent = error.message;
  }
}

document.getElementById("refresh-health").addEventListener("click", loadHealth);

const operationLabels = {
  generate_structured: "结构化生成",
  probe_reply: "连接探测",
};

const stageLabels = {
  initial: "初次请求",
  repair: "格式修复",
  retry: "网络重试",
};

function traceTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN", { hour12: false });
}

function traceStatusLabel(status) {
  if (status === "succeeded") return "成功";
  if (status === "failed") return "失败";
  return "进行中";
}

function renderTraceList(traces) {
  modelTraceList.replaceChildren();
  if (!traces.length) {
    const empty = document.createElement("li");
    empty.className = "trace-list-empty";
    empty.textContent = "当前进程暂无调用记录";
    modelTraceList.appendChild(empty);
    return;
  }
  traces.forEach((trace) => {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = `trace-item ${trace.status}`;
    if (trace.trace_id === selectedModelTraceId) button.classList.add("selected");

    const heading = document.createElement("span");
    heading.className = "trace-item-heading";
    const model = document.createElement("strong");
    model.textContent = trace.model;
    const status = document.createElement("span");
    status.className = "trace-status";
    status.textContent = traceStatusLabel(trace.status);
    heading.append(model, status);

    const meta = document.createElement("span");
    meta.className = "trace-item-meta";
    meta.textContent = `${operationLabels[trace.operation] || trace.operation} · ${trace.attempt_count} 步 · ${trace.total_latency_ms} ms`;
    const time = document.createElement("span");
    time.className = "trace-item-time";
    time.textContent = traceTime(trace.started_at);
    button.append(heading, meta, time);
    button.addEventListener("click", () => loadModelTrace(trace.trace_id));
    item.appendChild(button);
    modelTraceList.appendChild(item);
  });
}

function prettyResponse(value) {
  if (value === null || value === undefined) return "（无响应正文）";
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch (_) {
    return value;
  }
}

function createTraceCodeBlock(title, value) {
  const block = document.createElement("section");
  block.className = "trace-code-block";
  const heading = document.createElement("div");
  heading.className = "trace-code-heading";
  const label = document.createElement("strong");
  label.textContent = title;
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "secondary compact copy-button";
  copy.textContent = "复制";
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value);
      copy.textContent = "已复制";
      window.setTimeout(() => { copy.textContent = "复制"; }, 1200);
    } catch (_) {
      copy.textContent = "复制失败";
    }
  });
  heading.append(label, copy);
  const code = document.createElement("pre");
  code.textContent = value;
  block.append(heading, code);
  return block;
}

function renderModelTrace(trace) {
  selectedModelTraceId = trace.trace_id;
  modelTraceDetail.replaceChildren();
  const header = document.createElement("div");
  header.className = "trace-detail-header";
  const title = document.createElement("h3");
  title.textContent = `${trace.model} · ${operationLabels[trace.operation] || trace.operation}`;
  const summary = document.createElement("p");
  summary.textContent = `${traceTime(trace.started_at)} · ${traceStatusLabel(trace.status)} · ${trace.total_latency_ms} ms${trace.error_code ? ` · ${trace.error_code}` : ""}`;
  header.append(title, summary);
  modelTraceDetail.appendChild(header);

  if (!trace.attempts.length) {
    const empty = document.createElement("div");
    empty.className = "trace-empty";
    empty.textContent = "调用在发出 HTTP 请求前结束，没有请求步骤。";
    modelTraceDetail.appendChild(empty);
    return;
  }

  trace.attempts.forEach((attempt) => {
    const card = document.createElement("article");
    card.className = `trace-attempt${attempt.schema_valid === false ? " invalid" : ""}`;
    const heading = document.createElement("div");
    heading.className = "trace-attempt-heading";
    const name = document.createElement("h4");
    name.textContent = `步骤 ${attempt.attempt_no} · ${stageLabels[attempt.stage] || attempt.stage}`;
    const meta = document.createElement("span");
    meta.textContent = `HTTP ${attempt.http_status || "—"} · ${attempt.latency_ms} ms`;
    heading.append(name, meta);
    card.appendChild(heading);
    if (attempt.error) {
      const error = document.createElement("p");
      error.className = "trace-error";
      error.textContent = `${attempt.schema_valid === false ? "Schema 校验失败：" : "错误："}${attempt.error}`;
      card.appendChild(error);
    }
    card.append(
      createTraceCodeBlock("请求 JSON", JSON.stringify(attempt.request_body, null, 2)),
      createTraceCodeBlock("响应正文", prettyResponse(attempt.response_body)),
    );
    modelTraceDetail.appendChild(card);
  });
}

async function loadModelTrace(traceId) {
  selectedModelTraceId = traceId;
  const trace = await requestJson(`${modelTracePath}/${encodeURIComponent(traceId)}`);
  renderModelTrace(trace);
  const listing = await requestJson(modelTracePath);
  renderTraceList(listing.traces);
}

async function loadModelTraces({ selectLatest = false } = {}) {
  const listing = await requestJson(modelTracePath);
  renderTraceList(listing.traces);
  if (!listing.traces.length) {
    selectedModelTraceId = null;
    modelTraceDetail.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "trace-empty";
    empty.textContent = "暂无模型调用记录。完成连接测试、结构化验证或正式任务后在此查看。";
    modelTraceDetail.appendChild(empty);
    return;
  }
  const selectedStillExists = listing.traces.some((trace) => trace.trace_id === selectedModelTraceId);
  const target = selectLatest || !selectedStillExists ? listing.traces[0].trace_id : selectedModelTraceId;
  await loadModelTrace(target);
}

document.getElementById("refresh-model-traces").addEventListener("click", async () => {
  try {
    await loadModelTraces();
  } catch (error) {
    modelTraceDetail.textContent = error.message;
  }
});

document.getElementById("clear-model-traces").addEventListener("click", async () => {
  try {
    await requestJson(modelTracePath, { method: "DELETE" });
    await loadModelTraces();
  } catch (error) {
    modelTraceDetail.textContent = error.message;
  }
});

async function initializeAdminConsole() {
  await loadProviders();
  await Promise.all([loadConfiguration(), loadHealth(), loadModelTraces()]);
}

initializeAdminConsole().catch((error) => {
  setMessage(error.message, "error");
});

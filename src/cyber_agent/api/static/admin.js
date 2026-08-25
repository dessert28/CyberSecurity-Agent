"use strict";

const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
const form = document.getElementById("model-form");
const provider = document.getElementById("provider");
const modelName = document.getElementById("model-name");
const apiBaseUrl = document.getElementById("api-base-url");
const apiKey = document.getElementById("api-key");
const saveButton = document.getElementById("save-button");
const testButton = document.getElementById("test-button");
const message = document.getElementById("operation-message");

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
  testButton.disabled = !config.credential_configured || !config.writable;
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

testButton.addEventListener("click", async () => {
  setMessage("正在执行 API 可达性与结构化输出检测…");
  testButton.disabled = true;
  try {
    const result = await requestJson("/api/v1/admin/connection-test", {
      method: "POST",
      body: "{}",
    });
    const messages = {
      MODEL_CHECK_PASSED: "连接成功，模型已返回符合约束的结构化结果。",
      MODEL_AUTH_FAILED: "API Key 错误或没有访问该模型的权限。",
      MODEL_NETWORK_ERROR: "无法连接模型服务，请检查网络和 API 地址。",
      MODEL_TIMEOUT: "模型服务响应超时。",
      MODEL_QUOTA_EXCEEDED: "模型账号额度或余额不可用。",
      MODEL_RATE_LIMITED: "模型服务触发了请求频率限制。",
      MODEL_REQUEST_REJECTED: "模型服务拒绝了本次探测请求。",
      MODEL_STRUCTURED_OUTPUT_INCOMPATIBLE: "API 可以访问，但模型未返回要求的结构化结果。",
      MODEL_CHECK_SETUP_FAILED: "模型地址未通过安全检查，或本地连接环境不可用。",
    };
    const summary = messages[result.code] || result.message;
    const detail = `${summary}（${result.latency_ms} ms，模型 ${result.model}）`;
    setMessage(detail, result.status === "ok" ? "success" : "error");
    await loadConfiguration();
    await loadHealth();
  } catch (error) {
    setMessage(error.message, "error");
  } finally {
    const config = await loadConfiguration().catch(() => null);
    testButton.disabled = !config?.writable || !config?.credential_configured;
  }
});

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

async function initializeAdminConsole() {
  await loadProviders();
  await Promise.all([loadConfiguration(), loadHealth()]);
}

initializeAdminConsole().catch((error) => {
  setMessage(error.message, "error");
});

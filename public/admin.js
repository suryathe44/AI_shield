const STORAGE_KEYS = {
  token: "ai-shield-admin-token",
  fingerprintSeed: "ai-shield-admin-device-seed",
};

const loginPanel = document.getElementById("adminLoginPanel");
const dashboardPanel = document.getElementById("adminDashboardPanel");
const loginForm = document.getElementById("adminLoginForm");
const loginButton = document.getElementById("adminLoginButton");
const loginStatus = document.getElementById("adminLoginStatus");
const fingerprintText = document.getElementById("fingerprintText");
const blockedIpList = document.getElementById("blockedIpList");
const logsList = document.getElementById("adminLogsList");
const refreshBlockedButton = document.getElementById("refreshBlockedButton");
const refreshLogsButton = document.getElementById("refreshLogsButton");
const deleteAllLogsButton = document.getElementById("deleteAllLogsButton");
const logoutButton = document.getElementById("logoutButton");
const refreshSessionButton = document.getElementById("refreshSessionButton");
const sessionUser = document.getElementById("sessionUser");
const sessionExpires = document.getElementById("sessionExpires");
const sessionLastSeen = document.getElementById("sessionLastSeen");
const sessionIdleTimeout = document.getElementById("sessionIdleTimeout");
const sessionStatus = document.getElementById("adminSessionStatus");

let adminToken = sessionStorage.getItem(STORAGE_KEYS.token) ?? "";
let deviceFingerprint = "";
let inactivityTimer = null;
let absoluteExpiryTimer = null;
let currentSession = null;

function formatDate(value) {
  if (!value) {
    return "-";
  }

  return new Date(value).toLocaleString();
}

function formatMinutes(milliseconds) {
  return `${Math.max(1, Math.round(milliseconds / 60_000))} min`;
}

function setStatus(element, text) {
  element.textContent = text;
}

function showLoginPanel() {
  loginPanel.classList.remove("hidden");
  dashboardPanel.classList.add("hidden");
}

function showDashboard() {
  loginPanel.classList.add("hidden");
  dashboardPanel.classList.remove("hidden");
}

function clearTimers() {
  window.clearTimeout(inactivityTimer);
  window.clearTimeout(absoluteExpiryTimer);
}

function persistToken(token) {
  adminToken = token;
  if (token) {
    sessionStorage.setItem(STORAGE_KEYS.token, token);
    return;
  }

  sessionStorage.removeItem(STORAGE_KEYS.token);
}

function renderBlockedIps(blockedIps) {
  blockedIpList.innerHTML = "";

  if (!blockedIps.length) {
    blockedIpList.innerHTML = '<p class="admin-empty">No blocked IPs.</p>';
    return;
  }

  blockedIps.forEach((entry) => {
    const row = document.createElement("div");
    row.className = "admin-row";
    row.innerHTML = `
      <div>
        <p class="admin-row-title">${entry.ip}</p>
        <p class="admin-row-meta">Attempts: ${entry.attempts} | Blocked: ${formatDate(entry.blockedAt)}</p>
      </div>
      <button class="button-secondary" type="button">Unlock</button>
    `;

    row.querySelector("button").addEventListener("click", async () => {
      await unlockBlockedIp(entry.ip);
    });

    blockedIpList.appendChild(row);
  });
}

function renderLogs(logs) {
  logsList.innerHTML = "";

  if (!logs.length) {
    logsList.innerHTML = '<p class="admin-empty">No secure logs stored.</p>';
    return;
  }

  logs.forEach((entry) => {
    const card = document.createElement("article");
    card.className = "result-card";
    card.innerHTML = `
      <p class="result-label">${entry.classification} | Score ${entry.riskScore}</p>
      <p class="result-meta">${formatDate(entry.createdAt)} | ${entry.source}</p>
      <ul class="signal-list">
        ${(entry.explanation ?? []).map((reason) => `<li>${reason}</li>`).join("")}
      </ul>
      <div class="action-row action-row-wrap admin-actions-top">
        <button class="button-secondary" type="button">Delete</button>
      </div>
    `;

    card.querySelector("button").addEventListener("click", async () => {
      await deleteLog(entry.id);
    });

    logsList.appendChild(card);
  });
}

async function sha256Hex(value) {
  const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function getOrCreateFingerprintSeed() {
  let seed = localStorage.getItem(STORAGE_KEYS.fingerprintSeed);
  if (!seed) {
    seed = crypto.randomUUID();
    localStorage.setItem(STORAGE_KEYS.fingerprintSeed, seed);
  }

  return seed;
}

async function buildDeviceFingerprint() {
  const fingerprintParts = [
    getOrCreateFingerprintSeed(),
    navigator.userAgent,
    navigator.language,
    navigator.platform,
    navigator.vendor,
    String(navigator.hardwareConcurrency ?? "unknown"),
    Intl.DateTimeFormat().resolvedOptions().timeZone,
    `${screen.width}x${screen.height}`,
  ];

  return sha256Hex(fingerprintParts.join("|"));
}

async function apiRequest(url, options = {}) {
  const headers = new Headers(options.headers ?? {});
  headers.set("Content-Type", headers.get("Content-Type") ?? "application/json");
  headers.set("X-Device-Fingerprint", deviceFingerprint);
  if (adminToken) {
    headers.set("Authorization", `Bearer ${adminToken}`);
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "Admin request failed.");
  }

  return payload;
}

function scheduleAutoLogout(session) {
  clearTimers();

  const now = Date.now();
  const idleTimeoutMs = session.idleTimeoutMs ?? 15 * 60_000;
  const absoluteTimeoutMs = Math.max(0, new Date(session.expiresAt).getTime() - now);

  inactivityTimer = window.setTimeout(() => {
    void logout("You were logged out after inactivity.");
  }, idleTimeoutMs);

  absoluteExpiryTimer = window.setTimeout(() => {
    void logout("Your admin session expired.");
  }, absoluteTimeoutMs);
}

function resetInactivityTimer() {
  if (!currentSession) {
    return;
  }

  window.clearTimeout(inactivityTimer);
  inactivityTimer = window.setTimeout(() => {
    void logout("You were logged out after inactivity.");
  }, currentSession.idleTimeoutMs);
}

function bindActivityEvents() {
  ["click", "keydown", "mousemove", "scroll", "touchstart"].forEach((eventName) => {
    window.addEventListener(eventName, resetInactivityTimer, { passive: true });
  });
}

function renderSession(session) {
  currentSession = session;
  sessionUser.textContent = session.username;
  sessionExpires.textContent = formatDate(session.expiresAt);
  sessionLastSeen.textContent = formatDate(session.lastSeenAt);
  sessionIdleTimeout.textContent = formatMinutes(session.idleTimeoutMs);
  setStatus(sessionStatus, "Admin session authenticated.");
  scheduleAutoLogout(session);
  showDashboard();
}

async function refreshSession() {
  const payload = await apiRequest("/api/admin/auth/session", {
    method: "GET",
  });

  renderSession(payload.session);
  return payload.session;
}

async function loadBlockedIps() {
  const payload = await apiRequest("/api/admin/security/blocked", {
    method: "GET",
  });

  renderBlockedIps(payload.blockedIps ?? []);
}

async function loadLogs() {
  const payload = await apiRequest("/api/admin/logs", {
    method: "GET",
  });

  renderLogs(payload.logs ?? []);
}

async function unlockBlockedIp(ip) {
  await apiRequest("/api/admin/security/unlock-ip", {
    method: "POST",
    body: JSON.stringify({ ip }),
  });

  setStatus(sessionStatus, `Unlocked blocked IP ${ip}.`);
  await loadBlockedIps();
}

async function deleteLog(id) {
  await apiRequest(`/api/admin/logs/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });

  await loadLogs();
}

async function deleteAllLogs() {
  await apiRequest("/api/admin/logs", {
    method: "DELETE",
  });

  await loadLogs();
}

async function logout(message = "Admin session closed.") {
  try {
    if (adminToken) {
      await apiRequest("/api/admin/auth/logout", {
        method: "POST",
      });
    }
  } catch {
    // Ignore server logout failures during client cleanup.
  }

  clearTimers();
  persistToken("");
  currentSession = null;
  setStatus(loginStatus, message);
  showLoginPanel();
}

async function handleLogin(event) {
  event.preventDefault();

  loginButton.disabled = true;
  setStatus(loginStatus, "Signing in...");

  try {
    const payload = await apiRequest("/api/admin/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: document.getElementById("adminUsername").value.trim(),
        password: document.getElementById("adminPassword").value,
        otp: document.getElementById("adminOtp").value.trim(),
      }),
    });

    persistToken(payload.token);
    renderSession(payload.session);
    setStatus(sessionStatus, "Authenticated. Loading admin data...");
    await Promise.all([loadBlockedIps(), loadLogs()]);
    setStatus(sessionStatus, "Admin console is ready.");
    loginForm.reset();
  } catch (error) {
    setStatus(loginStatus, error.message);
    showLoginPanel();
  } finally {
    loginButton.disabled = false;
  }
}

async function bootstrap() {
  deviceFingerprint = await buildDeviceFingerprint();
  fingerprintText.textContent = `${deviceFingerprint.slice(0, 20)}...`;
  bindActivityEvents();

  if (!adminToken) {
    showLoginPanel();
    return;
  }

  try {
    await refreshSession();
    await Promise.all([loadBlockedIps(), loadLogs()]);
  } catch (error) {
    persistToken("");
    currentSession = null;
    setStatus(loginStatus, error.message);
    showLoginPanel();
  }
}

loginForm.addEventListener("submit", handleLogin);
logoutButton.addEventListener("click", () => {
  void logout();
});
refreshSessionButton.addEventListener("click", async () => {
  try {
    await refreshSession();
    setStatus(sessionStatus, "Session refreshed.");
  } catch (error) {
    await logout(error.message);
  }
});
refreshBlockedButton.addEventListener("click", async () => {
  try {
    await loadBlockedIps();
    setStatus(sessionStatus, "Blocked IP list refreshed.");
  } catch (error) {
    setStatus(sessionStatus, error.message);
  }
});
refreshLogsButton.addEventListener("click", async () => {
  try {
    await loadLogs();
    setStatus(sessionStatus, "Secure logs refreshed.");
  } catch (error) {
    setStatus(sessionStatus, error.message);
  }
});
deleteAllLogsButton.addEventListener("click", async () => {
  try {
    await deleteAllLogs();
    setStatus(sessionStatus, "All secure logs deleted.");
  } catch (error) {
    setStatus(sessionStatus, error.message);
  }
});

void bootstrap();
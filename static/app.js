const app = document.querySelector("#app");
const toastNode = document.querySelector("#toast");
const categories = [
  "Social Media", "Banking and Finance", "Email", "Education", "Work",
  "Shopping", "Government and Identity", "Entertainment", "Other"
];
const entryTemplates = {
  "Banking": {
    category: "Banking and Finance",
    fields: [
      ["Bank Name", "text", false],
      ["Account Holder", "text", false],
      ["Customer ID", "text", true],
      ["User ID", "text", true],
      ["Net Banking Password", "password", true],
      ["Website URL", "url", false]
    ]
  },
  "Social Media": {
    category: "Social Media",
    fields: [
      ["Platform", "text", false],
      ["Username", "text", false],
      ["Email", "email", false],
      ["Password", "password", true],
      ["Profile URL", "url", false]
    ]
  },
  "Email": {
    category: "Email",
    fields: [
      ["Email Address", "email", false],
      ["Password", "password", true],
      ["Recovery Email", "email", true]
    ]
  },
  "Wi-Fi": {
    category: "Other",
    fields: [
      ["Network Name", "text", false],
      ["Password", "password", true],
      ["Router Address", "text", false]
    ]
  },
  "Government and Identity": {
    category: "Government and Identity",
    fields: [
      ["Document Type", "text", false],
      ["Document Number", "text", true],
      ["Related Website", "url", false],
      ["Notes", "multiline", false]
    ]
  }
};
let authenticated = false;
let currentUser = null;
let registrationEmail = "";
let loginEmail = "";
let loginChallenge = null;
let countdownTimer = null;
let vaultRows = [];
let activeEntryDetail = null;
const revealedDetailFields = new Set();
const revealedEditFields = new Set();

function toast(message) {
  toastNode.textContent = message;
  toastNode.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => toastNode.classList.remove("show"), 3600);
}

function csrfToken() {
  const item = document.cookie.split("; ").find(value => value.startsWith("pm_csrf="));
  return item ? decodeURIComponent(item.slice("pm_csrf=".length)) : "";
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken()) {
    headers["X-CSRF-Token"] = csrfToken();
  }
  let response;
  try {
    response = await fetch(path, {
      ...options,
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store"
    });
  } catch (error) {
    const networkError = new Error(
      "Could not reach the password manager server. Check that it is running at http://127.0.0.1:5000."
    );
    networkError.cause = error;
    throw networkError;
  }
  let data;
  try { data = await response.json(); } catch {
    data = {
      detail: response.status >= 500
        ? `The server encountered an error (${response.status}). Check the VS Code server terminal for details.`
        : `The request failed (${response.status}). Please try again.`
    };
  }
  if (!response.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail.map(item => item.msg).join(". ")
      : data.detail && typeof data.detail === "object"
        ? data.detail.message || "Request failed. Please try again."
        : data.detail || data.message ||
          `The request failed (${response.status}). Check the server terminal for details.`;
    const error = new Error(detail);
    error.status = response.status;
    error.code = data.detail && typeof data.detail === "object" ? data.detail.code : undefined;
    error.accountCreated = data.detail && typeof data.detail === "object"
      ? Boolean(data.detail.account_created)
      : false;
    throw error;
  }
  return data;
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[char]);
}

function nav() {
  return `<header class="topbar">
    <a class="brand" href="/" onclick="goHome(event)"><span class="brand-mark">V</span>Vault</a>
    <div class="nav-actions">${authenticated
      ? `<button class="btn" type="button" onclick="navigate('dashboard')">Dashboard</button>
         <button class="btn" type="button" onclick="logout()">Log out</button>`
      : `<a class="btn" href="#login">Log in</a><a class="btn primary" href="#register">Get started</a>`}
    </div>
  </header>`;
}

function landing() {
  app.innerHTML = `${nav()}
    <main>
      <section class="hero">
        <div>
          <div class="eyebrow">A simpler way to stay secure</div>
          <h1>Your passwords.<br>One <span>secure vault.</span></h1>
          <p class="hero-copy">Keep your digital life organised and protected. Store your passwords, manage your accounts and access everything securely from one place.</p>
          <div class="hero-actions">
            <a class="btn primary" href="#register">Create your free vault</a>
            <a class="btn" href="#login">Already have an account? Log in</a>
          </div>
        </div>
        <div class="hero-visual" aria-label="Illustration of a password manager with fictional masked sample accounts">
          <div class="visual-window">
            <div class="visual-bar"><i class="dot"></i><i class="dot"></i><i class="dot"></i></div>
            <div class="visual-body">
              <div class="visual-side"><i></i><i></i><i></i><i></i><i></i></div>
              <div class="visual-main">
                <h3>Your passwords</h3>
                <div class="sample-login"><span class="sample-icon">A</span><span><strong>Acme Mail</strong><small>alex@example.test · ••••••••••••</small></span></div>
                <div class="sample-login"><span class="sample-icon">N</span><span><strong>Northstar Social</strong><small>alex@example.test · ••••••••••••</small></span></div>
                <div class="sample-login"><span class="sample-icon">C</span><span><strong>Cloud Notes</strong><small>alex@example.test · ••••••••••••</small></span></div>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section class="section soft">
        <div class="section-inner">
          <div class="section-heading"><div class="eyebrow">How it works</div><h2>Three steps to a safer digital life</h2><p>Get started in minutes. Your master password protects the vault; email verification confirms your identity during login.</p></div>
          <div class="steps">
            <article class="card step-card"><div class="step-number">01</div><h3>Create your account</h3><p>Register using your name, email address and a strong master password.</p></article>
            <article class="card step-card"><div class="step-number">02</div><h3>Complete two-step login</h3><p>After your master password is accepted, we email a one-time code to confirm your identity.</p></article>
            <article class="card step-card"><div class="step-number">03</div><h3>Open your vault</h3><p>Enter the email code to finish logging in, then store and organise credentials in your personal encrypted vault.</p></article>
          </div>
        </div>
      </section>
      <section class="section soft"><div class="section-inner"><div class="cta"><div><h2>Make room for peace of mind.</h2><p>Create your personal vault and keep everything organised in one place.</p></div><a class="btn primary" href="#register">Get started</a></div></div></section>
    </main>
    <footer class="footer">Vault · Your passwords, protected.</footer>`;
}

function showFormError(message, success = false) {
  const error = document.querySelector("#formError");
  const notice = document.querySelector("#formNotice");
  if (error) {
    error.textContent = success ? "" : message;
    error.classList.toggle("show", !success && Boolean(message));
  }
  if (notice) {
    notice.textContent = success ? message : "";
    notice.classList.toggle("show", success && Boolean(message));
  }
}

function authPage(kind) {
  stopCountdown();
  const isRegister = kind === "register";
  app.innerHTML = `${nav()}<main class="auth-page"><section class="card auth-card">
    <h1>${isRegister ? "Create your vault" : "Welcome back"}</h1>
    <p>${isRegister ? "Start with a strong master password only you know." : "Enter your credentials to securely unlock your vault."}</p>
    <div id="formError" class="auth-error" role="alert"></div>
    <div id="formNotice" class="auth-success" role="status"></div>
    <form id="authForm" novalidate>
      ${isRegister ? `<div class="field"><label for="fullName">Full name</label><input id="fullName" name="full_name" autocomplete="name" maxlength="100" required></div>` : ""}
      <div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" maxlength="255" required></div>
      <div class="field"><label for="masterPassword">Master password</label>
        <div class="password-input"><input id="masterPassword" name="master_password" type="password" autocomplete="${isRegister ? "new-password" : "current-password"}" minlength="12" maxlength="128" required><button type="button" data-toggle="masterPassword">Show</button></div>
        ${isRegister ? `<div class="password-strength"><span id="strengthBar"></span></div><div class="strength-label" id="strengthLabel">Use at least 12 characters, including a letter and a number.</div>` : ""}
      </div>
      ${isRegister ? `<div class="field"><label for="confirmPassword">Confirm master password</label>
        <div class="password-input"><input id="confirmPassword" name="confirm_password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required><button type="button" data-toggle="confirmPassword">Show</button></div>
        <div id="matchMessage" class="match-message" aria-live="polite"></div></div>` : ""}
      <button id="submitButton" class="btn primary" style="width:100%" type="submit" ${isRegister ? "disabled" : ""}>${isRegister ? "Create account" : "Continue"}</button>
    </form>
    <div class="auth-switch">${isRegister
      ? `Already registered? <a href="#login">Log in</a>`
      : `New to Vault? <a href="#register">Create account</a><br><span>Forgot master password? Coming soon.</span>`}</div>
  </section></main>`;

  const form = document.querySelector("#authForm");
  const master = document.querySelector("#masterPassword");
  const confirm = document.querySelector("#confirmPassword");
  const button = document.querySelector("#submitButton");
  if (!isRegister && loginEmail) {
    document.querySelector("#email").value = loginEmail;
    loginEmail = "";
  }
  document.querySelectorAll("[data-toggle]").forEach(toggle => toggle.addEventListener("click", () => {
    const input = document.getElementById(toggle.dataset.toggle);
    input.type = input.type === "password" ? "text" : "password";
    toggle.textContent = input.type === "password" ? "Show" : "Hide";
  }));

  if (isRegister) {
    const updateValidity = () => {
      const fullName = document.querySelector("#fullName").value.trim();
      const email = document.querySelector("#email").value.trim();
      const strong = passwordIsValid(master.value);
      const matches = confirm.value.length > 0 && master.value === confirm.value;
      const matchNode = document.querySelector("#matchMessage");
      const hasPasswordInput = Boolean(master.value || confirm.value);
      matchNode.textContent = hasPasswordInput ? (matches ? "✓ Passwords match." : "✕ Passwords do not match.") : "";
      matchNode.className = `match-message${hasPasswordInput ? (matches ? " valid" : " invalid") : ""}`;
      setStrength(master.value);
      button.disabled = !(fullName.length >= 2 && validEmail(email) && strong && matches);
    };
    ["input", "change"].forEach(event => {
      document.querySelector("#fullName").addEventListener(event, updateValidity);
      document.querySelector("#email").addEventListener(event, updateValidity);
      master.addEventListener(event, updateValidity);
      confirm.addEventListener(event, updateValidity);
    });
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    showFormError("");
    const formData = new FormData(form);
    const body = Object.fromEntries(formData.entries());
    if (isRegister) {
      body.full_name = body.full_name.trim();
      body.email = body.email.trim().toLowerCase();
      if (body.full_name.length < 2) return showFormError("Enter your name.");
      if (!validEmail(body.email)) return showFormError("Enter a valid email address.");
      if (!passwordIsValid(body.master_password)) return showFormError("Use at least 12 characters with a letter and a number.");
      if (body.master_password !== body.confirm_password) return showFormError("Passwords do not match.");
      await submitForm(button, async () => {
        try {
          const result = await api("/register", { method: "POST", body: JSON.stringify(body) });
          registrationEmail = "";
          loginEmail = result.email || body.email;
          toast(result.message);
          location.hash = "login";
        } catch (error) {
          if (error.status === 409) {
            loginEmail = body.email;
            toast(error.message);
            location.hash = "login";
            return;
          }
          showFormError(error.message);
        }
      }, "Creating account…");
      return;
    }

    body.email = body.email.trim().toLowerCase();
    if (!validEmail(body.email)) return showFormError("Enter a valid email address.");
    await submitForm(button, async () => {
      try {
        loginChallenge = await api("/login", { method: "POST", body: JSON.stringify(body) });
        otpPage("login", loginChallenge.masked_email, loginChallenge.message, loginChallenge.expires_in);
      } catch (error) {
        showFormError(error.message);
      }
    }, "Checking credentials…");
  });
}

function passwordIsValid(password) {
  return password.length >= 12 && password.length <= 128 &&
    /[A-Za-z]/.test(password) && /\d/.test(password);
}

function validEmail(email) {
  return /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+$/i.test(email);
}

function setStrength(password) {
  const bar = document.querySelector("#strengthBar");
  const label = document.querySelector("#strengthLabel");
  if (!bar || !label) return;
  let score = 0;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  bar.style.width = `${score * 25}%`;
  bar.style.background = score < 2 ? "#ef4444" : score < 4 ? "#eab308" : "#22c55e";
  label.textContent = password.length ? ["Very weak", "Weak", "Fair", "Good", "Strong"][score] : "Use at least 12 characters, including a letter and a number.";
}

async function submitForm(button, action, loadingText) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = loadingText;
  try { await action(); }
  finally {
    if (document.body.contains(button)) {
      button.textContent = label;
      if (button.id === "submitButton" && location.hash === "#register") {
        const event = new Event("input", { bubbles: true });
        document.querySelector("#confirmPassword")?.dispatchEvent(event);
      } else {
        button.disabled = false;
      }
    }
  }
}

function stopCountdown() {
  if (countdownTimer) clearInterval(countdownTimer);
  countdownTimer = null;
}

function otpPage(kind, destination, message, expiresIn = 300, deliveryPending = false) {
  stopCountdown();
  const registration = kind === "register";
  const emailShown = registration ? escapeHTML(destination) : escapeHTML(destination);
  app.innerHTML = `${nav()}<main class="auth-page"><section class="card auth-card">
    <h1>${registration ? "Verify your email" : "Check your inbox"}</h1>
    <p>${escapeHTML(message)}<br>${deliveryPending ? "Verification address:" : "Code sent to"} <strong>${emailShown}</strong>.</p>
    <div id="formError" class="auth-error" role="alert"></div>
    <div id="formNotice" class="auth-success" role="status"></div>
    <form id="otpForm">
      <div class="field"><label for="otpCode">Six-digit verification code</label>
        <input id="otpCode" class="otp-input" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" aria-label="Six-digit verification code" required></div>
      <div class="otp-meta"><span id="expiryTimer">Code expires in 05:00</span><button id="resendButton" class="text-button" type="button">Resend code</button></div>
      <button id="verifyButton" class="btn primary" style="width:100%;margin-top:20px" type="submit">Verify email</button>
    </form>
    <div class="auth-switch"><a href="#${registration ? "register" : "login"}">Use a different ${registration ? "email" : "login"}</a></div>
  </section></main>`;
  const form = document.querySelector("#otpForm");
  const codeInput = document.querySelector("#otpCode");
  const verifyButton = document.querySelector("#verifyButton");
  const resendButton = document.querySelector("#resendButton");
  codeInput.focus();
  let remaining = Math.max(0, Number(expiresIn) || 300);
  let resendInProgress = false;
  const paintTimer = () => {
    const min = String(Math.floor(remaining / 60)).padStart(2, "0");
    const sec = String(remaining % 60).padStart(2, "0");
    const timer = document.querySelector("#expiryTimer");
    if (timer) timer.textContent = remaining ? `Code expires in ${min}:${sec}` : "Code expired. Request a new one.";
    resendButton.disabled = resendInProgress;
    resendButton.textContent = resendInProgress ? "Sending…" : "Resend code";
    if (remaining > 0) remaining--;
  };
  paintTimer();
  countdownTimer = setInterval(paintTimer, 1000);

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const code = codeInput.value.trim();
    if (!/^\d{6}$/.test(code)) return showFormError("Enter all six digits.");
    showFormError("");
    await submitForm(verifyButton, async () => {
      try {
        if (registration) {
          await api(`/register/verify?email=${encodeURIComponent(registrationEmail)}`, {
            method: "POST", body: JSON.stringify({ code })
          });
          stopCountdown();
          registrationEmail = "";
          toast("Email verified. Please log in.");
          location.hash = "login";
        } else {
          await api("/login/verify", {
            method: "POST",
            body: JSON.stringify({ challenge_id: loginChallenge.challenge_id, code })
          });
          stopCountdown();
          loginChallenge = null;
          authenticated = true;
          currentUser = await api("/auth/me");
          location.hash = "dashboard";
        }
      } catch (error) {
        showFormError(error.message);
      }
    }, "Verifying…");
  });

  resendButton.addEventListener("click", async () => {
    if (resendInProgress) return;
    resendInProgress = true;
    resendButton.disabled = true;
    resendButton.textContent = "Sending…";
    try {
      const result = registration
        ? await api("/register/resend", { method: "POST", body: JSON.stringify({ email: registrationEmail }) })
        : await api("/login/resend", { method: "POST", body: JSON.stringify({ challenge_id: loginChallenge.challenge_id }) });
      remaining = result.expires_in || 300;
      showFormError(result.message, true);
    } catch (error) {
      showFormError(error.message);
    } finally {
      resendInProgress = false;
      resendButton.disabled = false;
      resendButton.textContent = "Resend code";
    }
  });
}

async function logout() {
  let logoutError = "";
  try {
    await api("/logout", { method: "POST", body: "{}" });
  } catch (error) {
    logoutError = error.message;
  }
  authenticated = false;
  currentUser = null;
  loginChallenge = null;
  registrationEmail = "";
  vaultRows = [];
  activeEntryDetail = null;
  revealedDetailFields.clear();
  revealedEditFields.clear();
  stopCountdown();
  history.replaceState(null, "", "/");
  landing();
  if (logoutError) toast(`Could not confirm server logout: ${logoutError}`);
}

function goHome(event) {
  event?.preventDefault();
  history.replaceState(null, "", "/");
  render();
}

function navigate(route) {
  location.hash = route;
}

function shell(active, body) {
  const categoryLinks = categories.map(category =>
    `<button class="side-link ${active === category ? "active" : ""}" type="button" onclick="openCategory('${escapeHTML(category)}')">${categoryIcon(category)}${escapeHTML(category)}</button>`
  ).join("");
  return `${nav()}<div class="shell"><aside class="sidebar">
    <div class="side-label">Workspace</div>
    <button class="side-link ${active === "dashboard" ? "active" : ""}" type="button" onclick="navigate('dashboard')">◫ Overview</button>
    <button class="side-link ${active === "vault" ? "active" : ""}" type="button" onclick="navigate('vault')">▤ All passwords</button>
    <div class="side-label">Categories</div>${categoryLinks}
    <div class="side-label">Tools</div>
    <button class="side-link ${active === "generator" ? "active" : ""}" type="button" onclick="navigate('generator')">✳ Password generator</button>
    <button class="side-link ${active === "settings" ? "active" : ""}" type="button" onclick="navigate('settings')">⚙ Settings</button>
    <button class="side-link logout" type="button" onclick="logout()">↪ Log out</button>
  </aside><main class="content">${body}</main></div>`;
}

function categoryIcon(category) {
  const icons = {
    "Social Media": "◎", "Banking and Finance": "$", Email: "✉", Education: "▣",
    Work: "▤", Shopping: "◇", "Government and Identity": "▦",
    Entertainment: "▶", Other: "·"
  };
  return `${icons[category] || "·"} `;
}

async function dashboard() {
  try {
    const data = await api("/dashboard");
    app.innerHTML = shell("dashboard", `
      <h1>Good to see you, ${escapeHTML(currentUser?.full_name || data.full_name)}</h1>
      <p class="content-subtitle">Here’s an overview of your secure vault.</p>
      <div class="stats">
        <article class="card stat"><div class="stat-label">Saved credentials</div><strong>${data.total}</strong></article>
        <article class="card stat"><div class="stat-label">Categories in use</div><strong>${data.category_count}</strong></article>
        <article class="card stat"><div class="stat-label">Favourites</div><strong>${data.favourites}</strong></article>
      </div>
      <div class="toolbar"><button class="btn primary" type="button" onclick="openEntry()">＋ Add password</button><button class="btn" type="button" onclick="navigate('generator')">✳ Generate password</button></div>
      <div class="row recent-list"><h2>Recently added</h2><button class="btn" type="button" onclick="navigate('vault')">View all</button></div>
      <div class="credential-grid">${data.recent.map(entry => `
        <article class="card credential-card"><div class="row"><h3>${escapeHTML(entry.title || entry.site_name)}</h3>${entry.favourite ? "<span aria-label='Favourite'>★</span>" : ""}</div>
        <p>${escapeHTML(entry.category)}</p><button class="btn" type="button" onclick="viewCredential(${entry.id})">View credential</button></article>`
      ).join("") || `<div class="card empty-state">Your vault is ready. Add your first credential when you’re ready.</div>`}</div>`);
  } catch (error) { handleAuthError(error); }
}

async function vault(category = "") {
  try {
    const query = category ? `?category=${encodeURIComponent(category)}` : "";
    vaultRows = await api(`/vault${query}`);
    const active = category || "vault";
    app.innerHTML = shell(active, `
      <div class="row"><div><h1>${escapeHTML(category || "All passwords")}</h1><p class="content-subtitle">Credentials saved in your encrypted vault.</p></div><button class="btn primary" type="button" onclick="openEntry()">＋ Add password</button></div>
      <div class="toolbar"><input id="searchBox" type="search" placeholder="Search websites and usernames" aria-label="Search credentials"><button id="favouritesFilter" class="btn" type="button" aria-pressed="false">☆ Favourites</button></div>
      <div id="credentialGrid" class="credential-grid"></div>`);
    document.querySelector("#searchBox").addEventListener("input", renderVaultRows);
    document.querySelector("#favouritesFilter").addEventListener("click", event => {
      const button = event.currentTarget;
      button.setAttribute("aria-pressed", button.getAttribute("aria-pressed") !== "true");
      button.classList.toggle("primary", button.getAttribute("aria-pressed") === "true");
      renderVaultRows();
    });
    renderVaultRows();
  } catch (error) { handleAuthError(error); }
}

function renderVaultRows() {
  const grid = document.querySelector("#credentialGrid");
  if (!grid) return;
  const query = document.querySelector("#searchBox").value.trim().toLowerCase();
  const onlyFavourites = document.querySelector("#favouritesFilter").getAttribute("aria-pressed") === "true";
  const rows = vaultRows.filter(row =>
    (!onlyFavourites || row.favourite) &&
    (!query || row.site_name.toLowerCase().includes(query) || row.username.toLowerCase().includes(query))
  );
  grid.innerHTML = rows.map(row => {
    return `<article class="card credential-card">
      <div class="row"><h3>${escapeHTML(row.title || row.site_name)}</h3><button class="text-button favourite-card-star ${row.favourite ? "selected" : ""}" type="button" onclick="toggleFavourite(${row.id},${!row.favourite})" aria-label="${row.favourite ? "Remove favourite" : "Add favourite"}" aria-pressed="${row.favourite}">${row.favourite ? "★" : "☆"}</button></div>
      ${row.username ? `<p>${escapeHTML(row.username)}</p>` : ""}
      <p>${escapeHTML(row.category)}${row.site_url ? ` · <a href="${safeURL(row.site_url)}" target="_blank" rel="noopener noreferrer">Open website</a>` : ""}</p>
      <div class="credential-actions">
        <button class="btn" type="button" onclick="viewCredential(${row.id})">View</button>
        <button class="btn" type="button" onclick="openEntry(${row.id})">Edit</button>
        <button class="btn danger" type="button" onclick="deleteEntry(${row.id})">Delete</button>
      </div></article>`;
  }).join("") || `<div class="card empty-state">No credentials found. Try another search or add a password.</div>`;
}

function safeURL(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? escapeHTML(url.href) : "#";
  } catch { return "#"; }
}

async function viewCredential(id) {
  try {
    activeEntryDetail = await api(`/vault/${id}`);
    revealedDetailFields.clear();
    renderEntryDetail();
  } catch (error) { toast(error.message); }
}

function renderEntryDetail() {
  if (!activeEntryDetail) return;
  const entry = activeEntryDetail;
  const fields = entry.fields || [];
  const fieldsHTML = fields.length ? fields.map((field, index) => {
    const sensitive = Boolean(field.sensitive || field.type === "password");
    const masked = sensitive && !revealedDetailFields.has(index);
    const valueControl = field.type === "multiline"
      ? `<textarea class="entry-detail-value ${masked ? "secret-mask" : ""}" readonly rows="2" aria-label="${escapeHTML(field.label)}">${escapeHTML(field.value)}</textarea>`
      : `<input class="entry-detail-value" type="${masked ? "password" : "text"}" readonly value="${escapeHTML(field.value)}" aria-label="${escapeHTML(field.label)}">`;
    return `<article class="entry-detail-field">
      <div class="entry-detail-label"><strong>${escapeHTML(field.label)}</strong>${sensitive ? `<span class="sensitive-badge">Sensitive</span>` : ""}</div>
      <div class="entry-detail-control">${valueControl}
        ${sensitive ? `<button class="btn compact" type="button" onclick="toggleDetailReveal(${index})">${masked ? "Show" : "Hide"}</button>` : ""}
        <button class="btn compact" type="button" onclick="copyEntryField(${index})">Copy</button>
      </div>
    </article>`;
  }).join("") : `<p class="muted-copy">This entry has no saved fields.</p>`;
  document.querySelector("#entryDetailOverlay")?.remove();
  app.insertAdjacentHTML("beforeend", `<div class="page-overlay" id="entryDetailOverlay" role="dialog" aria-modal="true" aria-labelledby="entryDetailTitle">
    <section class="card modal modal-wide" id="entryDetailContent">
      <div class="row"><div><h2 id="entryDetailTitle">${escapeHTML(entry.title || entry.site_name)}</h2><p class="entry-detail-category">${escapeHTML(entry.category)}</p></div><button class="btn" type="button" onclick="closeEntryDetail()">Close</button></div>
      ${entry.site_url ? `<p class="entry-detail-link"><a href="${safeURL(entry.site_url)}" target="_blank" rel="noopener noreferrer">Open website</a></p>` : ""}
      <div class="entry-detail-fields">${fieldsHTML}</div>
      <div class="credential-actions"><button class="btn primary" type="button" onclick="editEntryDetail(${entry.id})">Edit entry</button><button class="btn danger" type="button" onclick="deleteEntry(${entry.id})">Delete entry</button></div>
    </section>
  </div>`);
}

function toggleDetailReveal(index) {
  if (revealedDetailFields.has(index)) revealedDetailFields.delete(index);
  else revealedDetailFields.add(index);
  renderEntryDetail();
}

async function copyEntryField(index) {
  const field = activeEntryDetail?.fields?.[index];
  if (!field) return toast("That field is no longer available.");
  try {
    await navigator.clipboard.writeText(field.value);
    toast(`${field.label} copied to the clipboard.`);
  } catch (error) {
    toast(`Could not copy field: ${error.message}`);
  }
}

function closeEntryDetail() {
  document.querySelector("#entryDetailOverlay")?.remove();
  activeEntryDetail = null;
  revealedDetailFields.clear();
}

function editEntryDetail(id) {
  closeEntryDetail();
  openEntry(id);
}

async function toggleFavourite(id, favourite) {
  try {
    if (!await requestEntryEditAuthorization(id)) return;
    await api(`/vault/${id}/favourite?favourite=${favourite}`, { method: "PATCH" });
    await vault(location.hash.startsWith("#category=") ? decodeURIComponent(location.hash.slice(10)) : "");
  } catch (error) { toast(error.message); }
}

async function deleteEntry(id) {
  if (!confirm("Delete this saved credential? This cannot be undone.")) return;
  try {
    if (!await requestEntryEditAuthorization(id)) return;
    await api(`/vault/${id}`, { method: "DELETE" });
    if (activeEntryDetail?.id === id) closeEntryDetail();
    toast("Credential deleted.");
    await vault();
  } catch (error) { toast(error.message); }
}

function requestEntryEditAuthorization(id) {
  return new Promise(resolve => {
    document.querySelector("#entryAuthOverlay")?.remove();
    app.insertAdjacentHTML("beforeend", `<div class="page-overlay" id="entryAuthOverlay" role="dialog" aria-modal="true" aria-labelledby="entryAuthTitle">
      <section class="card modal">
        <div class="row"><h2 id="entryAuthTitle">Confirm your identity</h2><button id="cancelEntryAuth" class="btn" type="button">Cancel</button></div>
        <p>Enter your master password to change this saved entry.</p>
        <div id="entryAuthError" class="auth-error" role="alert"></div>
        <form id="entryAuthForm">
          <div class="field"><label for="entryAuthPassword">Master password</label><input id="entryAuthPassword" type="password" autocomplete="current-password" maxlength="128" required></div>
          <button class="btn primary" type="submit">Verify and continue</button>
        </form>
      </section>
    </div>`);
    const overlay = document.querySelector("#entryAuthOverlay");
    const form = document.querySelector("#entryAuthForm");
    const input = document.querySelector("#entryAuthPassword");
    const button = form.querySelector('button[type="submit"]');
    let completed = false;
    const finish = authorized => {
      if (completed) return;
      completed = true;
      overlay.remove();
      resolve(authorized);
    };

    document.querySelector("#cancelEntryAuth").addEventListener("click", () => finish(false));
    input.focus();
    form.addEventListener("submit", async event => {
      event.preventDefault();
      button.disabled = true;
      const errorNode = document.querySelector("#entryAuthError");
      errorNode.textContent = "";
      errorNode.classList.remove("show");
      const masterPassword = input.value;
      input.value = "";
      try {
        await api(`/vault/${id}/edit-authorize`, {
          method: "POST",
          body: JSON.stringify({ master_password: masterPassword })
        });
        finish(true);
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.classList.add("show");
        input.focus();
      } finally {
        button.disabled = false;
      }
    });
  });
}

async function openEntry(id) {
  if (id && !await requestEntryEditAuthorization(id)) return;
  let entry = {
    title: "", site_name: "", site_url: "", username: "", password: "",
    category: "Other", notes: "", favourite: false,
    fields: [
      { label: "", placeholder: "Username or email", value: "", type: "text", sensitive: false },
      { label: "", placeholder: "Password", value: "", type: "password", sensitive: true }
    ]
  };
  try {
    if (id) entry = await api(`/vault/${id}`);
    revealedEditFields.clear();
    app.insertAdjacentHTML("beforeend", `<div class="page-overlay" id="entryOverlay" role="dialog" aria-modal="true" aria-labelledby="entryFormTitle"><section class="card modal modal-wide">
      <div class="row"><h2 id="entryFormTitle">${id ? "Edit entry" : "Add password"}</h2><button class="btn" type="button" onclick="closeEntry()">Close</button></div>
      <div id="entryError" class="auth-error" role="alert"></div>
      <form id="entryForm"><div class="form-grid">
        <div class="field"><label for="entryTitle">Entry title</label><input id="entryTitle" name="title" maxlength="255" placeholder="e.g. SBI Internet Banking" value="${escapeHTML(entry.title || entry.site_name)}" required></div>
        <div class="field"><label for="siteUrl">Website URL</label><input id="siteUrl" name="site_url" maxlength="500" type="url" value="${escapeHTML(entry.site_url || "")}"></div>
        <div class="field"><label for="entryCategory">Category</label><select id="entryCategory" name="category">${categories.map(category => `<option value="${escapeHTML(category)}" ${category === entry.category ? "selected" : ""}>${escapeHTML(category)}</option>`).join("")}</select></div>
        <div class="field favourite-field"><label for="entryFavourite">Favourite</label><label class="entry-favourite" for="entryFavourite"><input id="entryFavourite" type="checkbox" name="favourite" ${entry.favourite ? "checked" : ""}><span class="favourite-star" aria-hidden="true"></span><span>Mark as favourite</span></label></div>
      </div>
      <div class="field template-field"><label for="entryTemplate">Optional field template</label><select id="entryTemplate"><option value="">Choose a template…</option>${Object.keys(entryTemplates).map(name => `<option value="${escapeHTML(name)}">${escapeHTML(name)}</option>`).join("")}</select></div>
      <section class="entry-fields-section" aria-labelledby="entryFieldsHeading">
        <div class="row entry-fields-heading"><div><h3 id="entryFieldsHeading">Entry fields</h3><p class="muted-copy">Gray example text is a hint. Click a box to enter your own label or value; choose the field type from its menu. Sensitive values are encrypted and hidden by default.</p></div><button class="btn" type="button" onclick="addEntryField()">＋ Add Field</button></div>
        <div id="entryFields"></div>
      </section>
      <p class="security-hint">Do not store CVVs or temporary bank OTPs as permanent vault information.</p>
      <p id="entrySaveHint" class="muted-copy" aria-live="polite"></p>
      <button class="btn primary" type="submit">${id ? "Save changes" : "Save password"}</button></form></section></div>`);
    renderEntryFields(entry.fields || []);
    document.querySelector("#entryTitle").addEventListener("input", updateEntrySubmitState);
    document.querySelector("#entryFields").addEventListener("input", updateEntrySubmitState);
    document.querySelector("#entryTemplate").addEventListener("change", event => {
      if (event.currentTarget.value) applyEntryTemplate(event.currentTarget.value);
      event.currentTarget.value = "";
    });
    document.querySelector("#entryForm").addEventListener("submit", async event => {
      event.preventDefault();
      const form = event.currentTarget;
      const button = form.querySelector('button[type="submit"]');
      const formData = new FormData(form);
      const fields = readEntryFields().filter(field => field.label || field.value);
      if (!fields.some(field => field.value.trim())) {
        const node = document.querySelector("#entryError");
        node.textContent = "Enter a value in at least one field before saving.";
        node.classList.add("show");
        return;
      }
      if (fields.some(field => field.value.trim() && !field.label)) {
        const node = document.querySelector("#entryError");
        node.textContent = "Add a label to each field that has a value.";
        node.classList.add("show");
        return;
      }
      if (!confirm("Are you sure you want to save this entry?")) return;
      button.disabled = true;
      const body = {
        title: String(formData.get("title") || "").trim(),
        site_url: String(formData.get("site_url") || "").trim() || null,
        category: String(formData.get("category") || "Other"),
        favourite: formData.has("favourite"),
        fields: fields.map(({ label, value, type, sensitive }) => ({
          label, value, type, sensitive
        }))
      };
      try {
        await api(id ? `/vault/${id}` : "/vault", {
          method: id ? "PUT" : "POST", body: JSON.stringify(body)
        });
        closeEntry();
        toast(id ? "Credential updated." : "Credential saved.");
        await vault();
      } catch (error) {
        const node = document.querySelector("#entryError");
        node.textContent = error.message;
        node.classList.add("show");
        button.disabled = false;
      }
    });
  } catch (error) { toast(error.message); }
}

function renderEntryFields(fields) {
  const container = document.querySelector("#entryFields");
  if (!container) return;
  const fieldTypes = [
    ["text", "Text"], ["password", "Password"], ["email", "Email"],
    ["url", "URL"], ["number", "Number"], ["multiline", "Multiline text"]
  ];
  container.innerHTML = fields.length ? fields.map((field, index) => {
    const type = fieldTypes.some(([value]) => value === field.type) ? field.type : "text";
    const sensitive = Boolean(field.sensitive || type === "password");
    const revealed = revealedEditFields.has(index);
    const valuePlaceholder = type === "email"
      ? "name@example.com"
      : type === "url"
        ? "https://example.com"
        : type === "number"
          ? "Enter a number"
          : type === "multiline"
            ? "Enter notes"
            : "Enter a value";
    const valueControl = type === "multiline"
      ? `<textarea id="entryFieldValue${index}" data-field-value rows="2" class="${sensitive && !revealed ? "secret-mask" : ""}" maxlength="10000" placeholder="${valuePlaceholder}">${escapeHTML(field.value || "")}</textarea>`
      : `<input id="entryFieldValue${index}" data-field-value type="${sensitive && !revealed ? "password" : type === "password" ? "text" : type}" maxlength="10000" value="${escapeHTML(field.value || "")}" placeholder="${valuePlaceholder}">`;
    const labelPlaceholder = field.placeholder || "e.g. Recovery email";
    return `<article class="entry-field-row" data-field-index="${index}">
      <div class="field"><label for="entryFieldLabel${index}">Field label</label><input id="entryFieldLabel${index}" data-field-label maxlength="100" value="${escapeHTML(field.label || "")}" placeholder="${escapeHTML(labelPlaceholder)}"></div>
      <div class="field"><label for="entryFieldType${index}">Field type</label><select id="entryFieldType${index}" data-field-type>${fieldTypes.map(([value, label]) => `<option value="${value}" ${type === value ? "selected" : ""}>${label}</option>`).join("")}</select></div>
      <div class="field entry-value-field"><label for="entryFieldValue${index}">Value</label><div class="entry-value-control">${valueControl}${sensitive ? `<button class="btn compact" type="button" onclick="toggleEditReveal(${index})">${revealed ? "Hide" : "Show"}</button>` : ""}</div></div>
      <div class="entry-field-actions">
        <label class="sensitive-toggle"><input data-field-sensitive type="checkbox" ${sensitive ? "checked" : ""}> Sensitive</label>
        <div class="field-order-actions"><button class="btn compact" type="button" onclick="moveEntryField(${index},-1)" aria-label="Move field up" ${index === 0 ? "disabled" : ""}>↑</button><button class="btn compact" type="button" onclick="moveEntryField(${index},1)" aria-label="Move field down" ${index === fields.length - 1 ? "disabled" : ""}>↓</button><button class="btn compact danger" type="button" onclick="removeEntryField(${index})" aria-label="Remove field">Remove</button></div>
      </div>
    </article>`;
  }).join("") : `<p class="muted-copy empty-fields">No fields yet. Add a field or choose a template.</p>`;
  container.querySelectorAll("[data-field-type]").forEach((select, index) => {
    select.addEventListener("change", () => changeEntryFieldType(index, select.value));
  });
  container.querySelectorAll("[data-field-sensitive]").forEach((checkbox, index) => {
    checkbox.addEventListener("change", () => changeEntryFieldSensitivity(index, checkbox.checked));
  });
  updateEntrySubmitState();
}

function updateEntrySubmitState() {
  const form = document.querySelector("#entryForm");
  if (!form) return;
  const hasTitle = Boolean(document.querySelector("#entryTitle")?.value.trim());
  const hasFieldValue = readEntryFields().some(field => field.value.trim());
  const ready = hasTitle && hasFieldValue;
  form.querySelector('button[type="submit"]').disabled = !ready;
  const hint = document.querySelector("#entrySaveHint");
  if (hint) {
    hint.textContent = ready
      ? ""
      : hasFieldValue
        ? "Add an entry title to enable saving."
        : "Enter at least one field value to enable saving.";
    hint.hidden = ready;
  }
}

function readEntryFields() {
  return [...document.querySelectorAll("#entryFields .entry-field-row")].map((row, position) => {
    const type = row.querySelector("[data-field-type]").value;
    return {
      label: row.querySelector("[data-field-label]").value.trim(),
      placeholder: row.querySelector("[data-field-label]").placeholder,
      value: row.querySelector("[data-field-value]").value,
      type,
      sensitive: type === "password" || row.querySelector("[data-field-sensitive]").checked,
      position
    };
  });
}

function addEntryField(field = {
  label: "",
  placeholder: "e.g. Recovery email",
  value: "",
  type: "text",
  sensitive: false
}) {
  const fields = readEntryFields();
  fields.push(field);
  revealedEditFields.clear();
  renderEntryFields(fields);
  document.querySelector("#entryFields .entry-field-row:last-child [data-field-label]")?.focus();
}

function changeEntryFieldType(index, type) {
  const fields = readEntryFields();
  if (!fields[index]) return;
  fields[index].type = type;
  if (type === "password") fields[index].sensitive = true;
  revealedEditFields.delete(index);
  renderEntryFields(fields);
}

function changeEntryFieldSensitivity(index, sensitive) {
  const fields = readEntryFields();
  if (!fields[index]) return;
  fields[index].sensitive = fields[index].type === "password" || sensitive;
  revealedEditFields.delete(index);
  renderEntryFields(fields);
}

function toggleEditReveal(index) {
  const fields = readEntryFields();
  if (!fields[index]) return;
  if (revealedEditFields.has(index)) revealedEditFields.delete(index);
  else revealedEditFields.add(index);
  renderEntryFields(fields);
}

function moveEntryField(index, direction) {
  const fields = readEntryFields();
  const target = index + direction;
  if (target < 0 || target >= fields.length) return;
  [fields[index], fields[target]] = [fields[target], fields[index]];
  revealedEditFields.clear();
  renderEntryFields(fields);
}

function removeEntryField(index) {
  const fields = readEntryFields();
  if (!fields[index]) return;
  if (!confirm(`Remove the "${fields[index].label || "untitled"}" field? Save the entry to apply this change.`)) return;
  fields.splice(index, 1);
  revealedEditFields.clear();
  renderEntryFields(fields);
}

function applyEntryTemplate(name) {
  const template = entryTemplates[name];
  if (!template) return;
  const currentFields = readEntryFields();
  if (currentFields.some(field => field.label || field.value) &&
      !confirm("Replace the current fields with this template? You can edit or remove suggested fields afterward.")) return;
  const category = document.querySelector("#entryCategory");
  if (category && categories.includes(template.category)) category.value = template.category;
  revealedEditFields.clear();
  renderEntryFields(template.fields.map(([label, type, sensitive]) => ({
    label: "", placeholder: label, type, sensitive, value: ""
  })));
}

function closeEntry() {
  document.querySelector("#entryOverlay")?.remove();
  revealedEditFields.clear();
}

function openCategory(category) {
  location.hash = `category=${encodeURIComponent(category)}`;
}

async function generator() {
  app.innerHTML = shell("generator", `<h1>Password generator</h1><p class="content-subtitle">Create a strong password using your browser-connected secure generator.</p>
    <section class="card overview-card">
      <div class="generator-output" id="passwordPreview" aria-live="polite">Generating…</div>
      <div class="toolbar"><button class="btn primary" type="button" onclick="generatePassword()">Generate password</button><button class="btn" type="button" onclick="copyGenerated()">Copy</button></div>
      <div class="range-row"><label for="length">Length: <strong id="lengthValue">20</strong></label><input id="length" type="range" min="8" max="64" value="20"></div>
      <div class="option-grid"><label><input id="upper" type="checkbox" checked> Uppercase letters</label><label><input id="lower" type="checkbox" checked> Lowercase letters</label><label><input id="numbers" type="checkbox" checked> Numbers</label><label><input id="symbols" type="checkbox" checked> Special characters</label><label><input id="ambiguous" type="checkbox"> Exclude ambiguous characters</label></div>
    </section>`);
  document.querySelector("#length").addEventListener("input", event => {
    document.querySelector("#lengthValue").textContent = event.currentTarget.value;
  });
  await generatePassword();
}

async function generatePassword() {
  const length = document.querySelector("#length")?.value || "20";
  const options = {
    length,
    uppercase: document.querySelector("#upper")?.checked ?? true,
    lowercase: document.querySelector("#lower")?.checked ?? true,
    numbers: document.querySelector("#numbers")?.checked ?? true,
    symbols: document.querySelector("#symbols")?.checked ?? true,
    ambiguous: !(document.querySelector("#ambiguous")?.checked ?? false)
  };
  try {
    const result = await api(`/generate?${new URLSearchParams(options)}`);
    const preview = document.querySelector("#passwordPreview");
    if (preview) preview.textContent = result.password;
  } catch (error) { handleAuthError(error); }
}

async function copyGenerated() {
  const password = document.querySelector("#passwordPreview")?.textContent;
  if (!password || password === "Generating…") return;
  try {
    await navigator.clipboard.writeText(password);
    toast("Generated password copied.");
  } catch (error) { toast(`Could not copy password: ${error.message}`); }
}

function settings() {
  app.innerHTML = shell("settings", `<h1>Settings</h1><p class="content-subtitle">Update your master password. The vault is re-encrypted and you’ll need to log in again.</p>
    <section class="card overview-card"><h2>Change master password</h2><div id="settingsError" class="auth-error" role="alert"></div>
      <form id="changePasswordForm"><div class="field"><label>Current master password</label><input name="current_password" type="password" minlength="12" required></div>
      <div class="field"><label>New master password</label><input name="new_password" type="password" minlength="12" required></div>
      <div class="field"><label>Confirm new master password</label><input name="confirm_password" type="password" minlength="12" required></div>
      <button class="btn primary" type="submit">Change password</button></form></section>`);
  document.querySelector("#changePasswordForm").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = Object.fromEntries(new FormData(form).entries());
    if (!passwordIsValid(data.new_password)) return settingsError("Use at least 12 characters with a letter and a number.");
    if (data.new_password !== data.confirm_password) return settingsError("New passwords do not match.");
    try {
      const result = await api("/account/change-password", { method: "POST", body: JSON.stringify(data) });
      authenticated = false;
      currentUser = null;
      history.replaceState(null, "", "/");
      landing();
      toast(result.message);
    } catch (error) { settingsError(error.message); }
  });
}

function settingsError(message) {
  const node = document.querySelector("#settingsError");
  node.textContent = message;
  node.classList.add("show");
}

function handleAuthError(error) {
  if (error.status === 401) {
    authenticated = false;
    currentUser = null;
    history.replaceState(null, "", "/");
    landing();
    toast("Your session expired. Log in to unlock your vault.");
  } else {
    toast(error.message);
  }
}

async function render() {
  const route = location.hash.slice(1);
  if (!route || route === "landing") {
    if (authenticated) {
      try { currentUser = await api("/auth/me"); }
      catch { authenticated = false; currentUser = null; }
    }
    landing();
    return;
  }
  if (route === "register" || route === "login") {
    authPage(route);
    return;
  }
  if (!authenticated) {
    try {
      currentUser = await api("/auth/me");
      authenticated = true;
    } catch {
      history.replaceState(null, "", "/");
      landing();
      return;
    }
  }
  if (route === "dashboard") return dashboard();
  if (route === "vault") return vault();
  if (route === "generator") return generator();
  if (route === "settings") return settings();
  if (route.startsWith("category=")) return vault(decodeURIComponent(route.slice("category=".length)));
  history.replaceState(null, "", "/");
  landing();
}

window.addEventListener("hashchange", render);
window.addEventListener("pageshow", event => {
  if (event.persisted && !authenticated && ["#dashboard", "#vault", "#generator", "#settings"].includes(location.hash)) {
    history.replaceState(null, "", "/");
    landing();
  }
});
window.goHome = goHome;
window.navigate = navigate;
window.logout = logout;
window.openEntry = openEntry;
window.closeEntry = closeEntry;
window.openCategory = openCategory;
window.viewCredential = viewCredential;
window.closeEntryDetail = closeEntryDetail;
window.editEntryDetail = editEntryDetail;
window.toggleDetailReveal = toggleDetailReveal;
window.copyEntryField = copyEntryField;
window.addEntryField = addEntryField;
window.toggleEditReveal = toggleEditReveal;
window.moveEntryField = moveEntryField;
window.removeEntryField = removeEntryField;
window.toggleFavourite = toggleFavourite;
window.deleteEntry = deleteEntry;
window.generatePassword = generatePassword;
window.copyGenerated = copyGenerated;
render();

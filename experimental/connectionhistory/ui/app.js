(() => {
  "use strict";

  const pageSize = 50;
  const state = {
    view: "connections",
    offset: 0,
    total: 0,
    timer: null,
  };

  const elements = {
    range: document.querySelector("#range"),
    token: document.querySelector("#token"),
    autoRefresh: document.querySelector("#auto-refresh"),
    refresh: document.querySelector("#refresh"),
    search: document.querySelector("#search"),
    status: document.querySelector("#status"),
    tableHead: document.querySelector("#table-head"),
    tableBody: document.querySelector("#table-body"),
    resultCount: document.querySelector("#result-count"),
    previous: document.querySelector("#previous"),
    next: document.querySelector("#next"),
    page: document.querySelector("#page"),
  };

  elements.token.value = localStorage.getItem("sing-box-history-token") || "";

  function apiBase() {
    return new URL("../", window.location.href);
  }

  function timeQuery() {
    const end = new Date();
    const start = new Date(end.getTime() - Number(elements.range.value) * 3600000);
    return { start: start.toISOString(), end: end.toISOString() };
  }

  async function request(path, params = {}) {
    const url = new URL(path, apiBase());
    const range = timeQuery();
    Object.entries({ ...range, ...params }).forEach(([key, value]) => {
      if (value !== "" && value !== undefined) {
        url.searchParams.set(key, String(value));
      }
    });
    const headers = {};
    const token = elements.token.value.trim();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(url, { headers });
    if (!response.ok) {
      throw new Error(response.status === 401 ? "Unauthorized" : `Request failed: ${response.status}`);
    }
    return response.json();
  }

  function formatBytes(value) {
    if (!Number.isFinite(value) || value <= 0) return "0 B";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
    return `${(value / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function formatTime(value) {
    if (!value) return "-";
    return new Intl.DateTimeFormat(undefined, {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(new Date(value));
  }

  function formatDuration(start, end) {
    const milliseconds = new Date(end).getTime() - new Date(start).getTime();
    if (!Number.isFinite(milliseconds) || milliseconds < 0) return "-";
    if (milliseconds < 1000) return `${milliseconds} ms`;
    if (milliseconds < 60000) return `${(milliseconds / 1000).toFixed(1)} s`;
    if (milliseconds < 3600000) return `${(milliseconds / 60000).toFixed(1)} min`;
    return `${(milliseconds / 3600000).toFixed(1)} h`;
  }

  function escapeHTML(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function setStatus(message, error = false) {
    elements.status.textContent = message;
    elements.status.classList.toggle("error", error);
  }

  async function loadSummary() {
    const [summary, status] = await Promise.all([request("summary"), request("status", {})]);
    document.querySelector("#total-traffic").textContent = formatBytes(summary.upload + summary.download);
    document.querySelector("#traffic-split").textContent =
      `Down ${formatBytes(summary.download)} / Up ${formatBytes(summary.upload)}`;
    document.querySelector("#connections").textContent = summary.connections.toLocaleString();
    document.querySelector("#active").textContent = summary.active.toLocaleString();
    document.querySelector("#database-size").textContent = formatBytes(status.databaseSize);
    document.querySelector("#queue-status").textContent =
      `Queue ${status.queued} / Dropped ${status.droppedOpen + status.droppedClose}`;
  }

  async function loadTrend() {
    const points = await request("trend");
    const total = points.reduce((sum, point) => sum + point.upload + point.download, 0);
    document.querySelector("#trend-total").textContent = formatBytes(total);
    renderTrend(points);
  }

  function renderTrend(points) {
    const svg = document.querySelector("#trend");
    const width = 1000;
    const height = 240;
    const padding = 18;
    const maxValue = Math.max(1, ...points.flatMap((point) => [point.upload, point.download]));
    const x = (index) => padding + (points.length <= 1 ? 0 : index * (width - padding * 2) / (points.length - 1));
    const y = (value) => height - padding - value / maxValue * (height - padding * 2);
    const line = (field) => points.map((point, index) => `${x(index)},${y(point[field])}`).join(" ");
    const grids = [0.25, 0.5, 0.75].map((ratio) => {
      const gridY = padding + ratio * (height - padding * 2);
      return `<line class="grid-line" x1="${padding}" y1="${gridY}" x2="${width - padding}" y2="${gridY}"></line>`;
    }).join("");
    svg.innerHTML = points.length
      ? `${grids}<polyline class="download-line" points="${line("download")}"></polyline><polyline class="upload-line" points="${line("upload")}"></polyline>`
      : grids;
  }

  function renderConnections(page) {
    elements.tableHead.innerHTML = "<tr><th>Closed</th><th>Duration</th><th>Network</th><th>Source</th><th>Destination</th><th>Domain</th><th>Process</th><th>Outbound</th><th>Rule</th><th>Download</th><th>Upload</th></tr>";
    elements.tableBody.innerHTML = page.data.length
      ? page.data.map((record) => `<tr>
          <td>${escapeHTML(formatTime(record.closedAt))}</td>
          <td>${escapeHTML(formatDuration(record.startedAt, record.closedAt))}</td>
          <td>${escapeHTML((record.network || "-").toUpperCase())}</td>
          <td>${escapeHTML(record.sourceIP || "-")}:${escapeHTML(record.sourcePort || "-")}</td>
          <td>${escapeHTML(record.destinationIP || "-")}:${escapeHTML(record.destinationPort || "-")}</td>
          <td>${escapeHTML(record.domain || "-")}</td>
          <td>${escapeHTML(record.process || "-")}</td>
          <td title="${escapeHTML((record.chain || []).join(" > "))}">${escapeHTML(record.outbound || "-")}</td>
          <td>${escapeHTML(record.rule || "-")}</td>
          <td>${formatBytes(record.download)}</td>
          <td>${formatBytes(record.upload)}</td>
        </tr>`).join("")
      : '<tr><td class="empty" colspan="11">No connection records</td></tr>';
  }

  function renderDimensions(page) {
    elements.tableHead.innerHTML = "<tr><th>Value</th><th>Connections</th><th>Download</th><th>Upload</th><th>Total</th></tr>";
    elements.tableBody.innerHTML = page.data.length
      ? page.data.map((item) => `<tr>
          <td>${escapeHTML(item.value)}</td>
          <td>${item.connections.toLocaleString()}</td>
          <td>${formatBytes(item.download)}</td>
          <td>${formatBytes(item.upload)}</td>
          <td>${formatBytes(item.upload + item.download)}</td>
        </tr>`).join("")
      : '<tr><td class="empty" colspan="5">No matching data</td></tr>';
  }

  async function loadTable() {
    const page = await request(state.view, {
      offset: state.offset,
      limit: pageSize,
      search: elements.search.value.trim(),
    });
    state.total = page.total;
    if (state.view === "connections") {
      renderConnections(page);
    } else {
      renderDimensions(page);
    }
    const currentPage = Math.floor(state.offset / pageSize) + 1;
    const pageCount = Math.max(1, Math.ceil(state.total / pageSize));
    elements.resultCount.textContent = `${state.total.toLocaleString()} results`;
    elements.page.textContent = `Page ${currentPage} of ${pageCount}`;
    elements.previous.disabled = state.offset === 0;
    elements.next.disabled = state.offset + pageSize >= state.total;
  }

  async function refresh() {
    elements.refresh.disabled = true;
    setStatus("Loading");
    try {
      await Promise.all([loadSummary(), loadTrend(), loadTable()]);
      setStatus(`Updated ${new Date().toLocaleTimeString()}`);
      localStorage.setItem("sing-box-history-token", elements.token.value.trim());
    } catch (error) {
      setStatus(error.message, true);
    } finally {
      elements.refresh.disabled = false;
    }
  }

  function resetAndRefresh() {
    state.offset = 0;
    refresh();
  }

  document.querySelectorAll(".tabs button").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tabs button").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      state.view = button.dataset.view;
      resetAndRefresh();
    });
  });

  elements.refresh.addEventListener("click", refresh);
  elements.range.addEventListener("change", resetAndRefresh);
  elements.token.addEventListener("change", resetAndRefresh);
  elements.search.addEventListener("input", () => {
    clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(resetAndRefresh, 250);
  });
  elements.previous.addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - pageSize);
    refresh();
  });
  elements.next.addEventListener("click", () => {
    state.offset += pageSize;
    refresh();
  });

  state.timer = setInterval(() => {
    if (elements.autoRefresh.checked && document.visibilityState === "visible") {
      refresh();
    }
  }, 10000);
  refresh();
})();

"use strict";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var state = {
    currentView: 0,
    finalizedView: 0,
    nodeN: 0,
    nodeF: 0,
    totals: {
        mNotarizations: 0,
        lNotarizations: 0,
        nullifications: 0,
        cascadeNullifications: 0,
    },
    /** @type {Map<number, ViewSlot>} */
    viewMap: new Map(),
    /** @type {Array<LogEntry>} */
    logEntries: [],
};

/**
 * @typedef {{
 *   view: number,
 *   leader: number,
 *   voteCount: number,
 *   nullifyCount: number,
 *   mNotarizedAt: number,
 *   lNotarizedAt: number,
 *   nullifiedAt: number,
 *   startedAt: number,
 *   blockHash: string,
 *   txCount: number,
 * }} ViewSlot
 *
 * @typedef {{
 *   time: number,
 *   kind: string,
 *   data: string,
 * }} LogEntry
 */

var MAX_LOG_ENTRIES = 500;
var MAX_TIMELINE_VIEWS = 50;
var MAX_TABLE_ROWS = 50;
var MAX_NOTARIZATION_ROWS = 30;
var VIEW_STRIP_COUNT = 30;

var autoScroll = true;
var renderScheduled = false;

// Cached thresholds derived from nodeN / nodeF
var mThreshold = 0;
var lThreshold = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(epochMs) {
    if (!epochMs) return "--:--:--.---";
    var d = new Date(epochMs);
    var hh = String(d.getHours()).padStart(2, "0");
    var mm = String(d.getMinutes()).padStart(2, "0");
    var ss = String(d.getSeconds()).padStart(2, "0");
    var ms = String(d.getMilliseconds()).padStart(3, "0");
    return hh + ":" + mm + ":" + ss + "." + ms;
}

function truncateHash(hash) {
    if (!hash) return "";
    return hash.substring(0, 12);
}

function viewStatus(slot) {
    if (slot.lNotarizedAt > 0) return "l-notarized";
    if (slot.nullifiedAt > 0) return "nullified";
    if (slot.mNotarizedAt > 0) return "m-notarized";
    if (slot.blockHash && slot.voteCount > 0) return "voting";
    if (slot.blockHash) return "proposed";
    return "in-progress";
}

function badgeHtml(status) {
    var labels = {
        "l-notarized": "L-Notarized",
        "m-notarized": "M-Notarized",
        "nullified": "Nullified",
        "cascade": "Cascade",
        "proposed": "Proposed",
        "voting": "Voting",
        "in-progress": "In Progress",
    };
    var cssMap = {
        "l-notarized": "badge-l-notarized",
        "m-notarized": "badge-m-notarized",
        "nullified": "badge-nullified",
        "cascade": "badge-cascade",
        "proposed": "badge-proposed",
        "voting": "badge-voting",
        "in-progress": "badge-in-progress",
    };
    return '<span class="badge ' + (cssMap[status] || "badge-in-progress") + '">' +
           (labels[status] || status) + '</span>';
}

function recalcThresholds() {
    var n = state.nodeN;
    var f = state.nodeF;
    mThreshold = 2 * f + 1;
    lThreshold = n - f;
}

/**
 * Reconstruct a block hash hex string from the lo/hi u64 halves returned by
 * /api/state.  The Rust side stores u64 pairs; this mirrors
 * ViewSlotSnapshot::block_hash_hex().
 */
function blockHashFromParts(hi, lo) {
    if (hi === 0 && lo === 0) return "";
    // Each u64 is 16 hex chars, zero-padded
    function hexU64(v) {
        var h = v.toString(16);
        while (h.length < 16) h = "0" + h;
        return h;
    }
    return hexU64(hi) + hexU64(lo);
}

// ---------------------------------------------------------------------------
// State mutations
// ---------------------------------------------------------------------------

function ensureViewSlot(view) {
    if (!state.viewMap.has(view)) {
        state.viewMap.set(view, {
            view: view,
            leader: 0,
            voteCount: 0,
            nullifyCount: 0,
            mNotarizedAt: 0,
            lNotarizedAt: 0,
            nullifiedAt: 0,
            startedAt: 0,
            blockHash: "",
            txCount: 0,
        });
    }
    return state.viewMap.get(view);
}

function addLogEntry(kind, data) {
    state.logEntries.push({
        time: Date.now(),
        kind: kind,
        data: data,
    });
    if (state.logEntries.length > MAX_LOG_ENTRIES) {
        state.logEntries.splice(0, state.logEntries.length - MAX_LOG_ENTRIES);
    }
}

function applySnapshot(snap) {
    state.currentView = snap.current_view || 0;
    state.finalizedView = snap.finalized_view || 0;
    state.nodeN = snap.node_n || 0;
    state.nodeF = snap.node_f || 0;
    state.totals.mNotarizations = snap.total_m_notarizations || 0;
    state.totals.lNotarizations = snap.total_l_notarizations || 0;
    state.totals.nullifications = snap.total_nullifications || 0;
    state.totals.cascadeNullifications = snap.total_cascade_nullifications || 0;
    recalcThresholds();

    if (Array.isArray(snap.views)) {
        for (var i = 0; i < snap.views.length; i++) {
            var sv = snap.views[i];
            if (sv.view === 0) continue;
            var slot = ensureViewSlot(sv.view);
            slot.leader = sv.leader || 0;
            slot.voteCount = sv.vote_count || 0;
            slot.nullifyCount = sv.nullify_count || 0;
            slot.mNotarizedAt = sv.m_notarized_at || 0;
            slot.lNotarizedAt = sv.l_notarized_at || 0;
            slot.nullifiedAt = sv.nullified_at || 0;
            slot.startedAt = sv.started_at || 0;
            slot.blockHash = blockHashFromParts(sv.block_hash_hi || 0, sv.block_hash_lo || 0);
            slot.txCount = sv.tx_count || 0;
        }
    }
}

function handleSseEvent(evt) {
    var kind = evt.kind;
    var slot;

    switch (kind) {
        case "current_view_changed":
            state.currentView = evt.view;
            addLogEntry(kind, "view=" + evt.view);
            break;

        case "finalized_view_changed":
            state.finalizedView = evt.view;
            addLogEntry(kind, "view=" + evt.view);
            break;

        case "totals_changed":
            state.totals.mNotarizations = evt.m_notarizations;
            state.totals.lNotarizations = evt.l_notarizations;
            state.totals.nullifications = evt.nullifications;
            state.totals.cascadeNullifications = evt.cascade_nullifications;
            addLogEntry(kind,
                "m=" + evt.m_notarizations +
                " l=" + evt.l_notarizations +
                " null=" + evt.nullifications +
                " cascade=" + evt.cascade_nullifications);
            break;

        case "view_started":
            slot = ensureViewSlot(evt.view);
            slot.leader = evt.leader;
            slot.startedAt = evt.timestamp;
            addLogEntry(kind, "view=" + evt.view + " leader=" + evt.leader);
            break;

        case "vote_count_changed":
            slot = ensureViewSlot(evt.view);
            slot.voteCount = evt.count;
            addLogEntry(kind, "view=" + evt.view + " count=" + evt.count);
            break;

        case "nullify_count_changed":
            slot = ensureViewSlot(evt.view);
            slot.nullifyCount = evt.count;
            addLogEntry(kind, "view=" + evt.view + " count=" + evt.count);
            break;

        case "m_notarization":
            slot = ensureViewSlot(evt.view);
            slot.mNotarizedAt = evt.timestamp;
            if (evt.block_hash) slot.blockHash = evt.block_hash;
            slot.voteCount = evt.vote_count;
            addLogEntry(kind,
                "view=" + evt.view +
                " hash=" + truncateHash(evt.block_hash) +
                " votes=" + evt.vote_count);
            break;

        case "l_notarization":
            slot = ensureViewSlot(evt.view);
            slot.lNotarizedAt = evt.timestamp;
            if (evt.block_hash) slot.blockHash = evt.block_hash;
            slot.voteCount = evt.vote_count;
            addLogEntry(kind,
                "view=" + evt.view +
                " hash=" + truncateHash(evt.block_hash) +
                " votes=" + evt.vote_count);
            break;

        case "nullification":
            slot = ensureViewSlot(evt.view);
            slot.nullifiedAt = evt.timestamp;
            slot.nullifyCount = evt.nullify_count;
            addLogEntry(kind,
                "view=" + evt.view +
                " count=" + evt.nullify_count);
            break;

        case "block_proposed":
            slot = ensureViewSlot(evt.view);
            if (evt.block_hash) slot.blockHash = evt.block_hash;
            slot.txCount = evt.tx_count;
            addLogEntry(kind,
                "view=" + evt.view +
                " hash=" + truncateHash(evt.block_hash) +
                " txs=" + evt.tx_count);
            break;

        default:
            addLogEntry(kind, JSON.stringify(evt));
            break;
    }

    scheduleRender();
}

// ---------------------------------------------------------------------------
// SSE Connection
// ---------------------------------------------------------------------------

var eventSource = null;

function connectSse() {
    if (eventSource) {
        eventSource.close();
    }
    eventSource = new EventSource("/api/events");

    eventSource.onopen = function () {
        var el = document.getElementById("connection-status");
        el.textContent = "Connected";
        el.className = "connection-status connected";
    };

    eventSource.onmessage = function (e) {
        try {
            var data = JSON.parse(e.data);
            handleSseEvent(data);
        } catch (_) {
            // Ignore malformed events
        }
    };

    eventSource.onerror = function () {
        var el = document.getElementById("connection-status");
        el.textContent = "Disconnected";
        el.className = "connection-status disconnected";
    };
}

// ---------------------------------------------------------------------------
// Rendering (batched via requestAnimationFrame)
// ---------------------------------------------------------------------------

function scheduleRender() {
    if (renderScheduled) return;
    renderScheduled = true;
    requestAnimationFrame(function () {
        renderScheduled = false;
        renderAll();
    });
}

function renderAll() {
    renderOverview();
    renderTimeline();
    renderBlocks();
    renderNotarizations();
    renderLogs();
}

// --- Overview ---

function renderOverview() {
    document.getElementById("ov-current-view").textContent = state.currentView;
    document.getElementById("ov-finalized-view").textContent = state.finalizedView;
    document.getElementById("ov-node-n").textContent = state.nodeN || "--";
    document.getElementById("ov-node-f").textContent = state.nodeF || "--";
    document.getElementById("ov-total-m").textContent = state.totals.mNotarizations;
    document.getElementById("ov-total-l").textContent = state.totals.lNotarizations;
    document.getElementById("ov-total-null").textContent = state.totals.nullifications;
    document.getElementById("ov-total-cascade").textContent = state.totals.cascadeNullifications;

    renderViewStrip();
}

function renderViewStrip() {
    var container = document.getElementById("ov-view-strip");
    var current = state.currentView;
    if (current === 0) {
        container.innerHTML = "";
        return;
    }

    var startView = Math.max(1, current - VIEW_STRIP_COUNT + 1);
    var html = "";
    for (var v = startView; v <= current; v++) {
        var slot = state.viewMap.get(v);
        var cls = "in-progress";
        if (slot) {
            var st = viewStatus(slot);
            // Detect cascade: nullified views between two non-nullified views
            // that were nullified without any nullify_count (heuristic: nullifiedAt > 0 but nullifyCount === 0)
            if (st === "nullified" && slot.nullifyCount === 0) {
                cls = "cascade";
            } else {
                cls = st;
            }
        }
        html += '<div class="view-box ' + cls + '" title="View ' + v + '">' + v + '</div>';
    }
    container.innerHTML = html;
}

// --- Timeline ---

function renderTimeline() {
    var container = document.getElementById("timeline-container");
    var views = sortedViewKeys().slice(0, MAX_TIMELINE_VIEWS);
    var n = state.nodeN || 1;

    var html = "";
    for (var i = 0; i < views.length; i++) {
        var slot = state.viewMap.get(views[i]);
        if (!slot) continue;

        var status = viewStatus(slot);
        var votePct = n > 0 ? Math.min(100, (slot.voteCount / n) * 100) : 0;
        var nullPct = n > 0 ? Math.min(100, (slot.nullifyCount / n) * 100) : 0;
        var mPct = n > 0 ? Math.min(100, (mThreshold / n) * 100) : 0;
        var lPct = n > 0 ? Math.min(100, (lThreshold / n) * 100) : 0;

        html += '<div class="timeline-row">';
        html += '<div class="timeline-view">#' + slot.view + '</div>';
        html += '<div class="timeline-leader">Leader ' + slot.leader + '</div>';

        // Vote progress bar
        html += '<div class="progress-bar-wrapper">';
        html += '<div class="progress-bar-label"><span>Votes</span><span>' +
                slot.voteCount + ' / ' + n + '</span></div>';
        html += '<div class="progress-bar">';
        html += '<div class="progress-bar-fill votes" style="width:' + votePct + '%"></div>';
        if (mThreshold > 0) {
            html += '<div class="threshold-marker m-threshold" data-label="M:' +
                    mThreshold + '" style="left:' + mPct + '%"></div>';
        }
        if (lThreshold > 0) {
            html += '<div class="threshold-marker l-threshold" data-label="L:' +
                    lThreshold + '" style="left:' + lPct + '%"></div>';
        }
        html += '</div></div>';

        // Nullify progress bar
        html += '<div class="progress-bar-wrapper">';
        html += '<div class="progress-bar-label"><span>Nullify</span><span>' +
                slot.nullifyCount + ' / ' + n + '</span></div>';
        html += '<div class="progress-bar">';
        html += '<div class="progress-bar-fill nullifies" style="width:' + nullPct + '%"></div>';
        if (mThreshold > 0) {
            html += '<div class="threshold-marker null-threshold" data-label="N:' +
                    mThreshold + '" style="left:' + mPct + '%"></div>';
        }
        html += '</div></div>';

        html += badgeHtml(status);
        html += '</div>';
    }

    container.innerHTML = html;
}

// --- Blocks ---

function renderBlocks() {
    var tbody = document.getElementById("blocks-tbody");
    var views = sortedViewKeys().slice(0, MAX_TABLE_ROWS);

    var html = "";
    for (var i = 0; i < views.length; i++) {
        var slot = state.viewMap.get(views[i]);
        if (!slot || !slot.blockHash) continue;

        var status = viewStatus(slot);
        html += "<tr>";
        html += "<td>" + slot.view + "</td>";
        html += "<td>" + slot.leader + "</td>";
        html += "<td>" + truncateHash(slot.blockHash) + "</td>";
        html += "<td>" + slot.txCount + "</td>";
        html += "<td>" + badgeHtml(status) + "</td>";
        html += "<td>" + formatTimestamp(slot.startedAt) + "</td>";
        html += "</tr>";
    }
    tbody.innerHTML = html;
}

// --- Notarizations ---

function renderNotarizations() {
    var mTbody = document.getElementById("m-not-tbody");
    var lTbody = document.getElementById("l-not-tbody");
    var nTbody = document.getElementById("null-tbody");

    var views = sortedViewKeys();

    var mHtml = "";
    var lHtml = "";
    var nHtml = "";
    var mCount = 0;
    var lCount = 0;
    var nCount = 0;

    for (var i = 0; i < views.length; i++) {
        var slot = state.viewMap.get(views[i]);
        if (!slot) continue;

        if (slot.mNotarizedAt > 0 && mCount < MAX_NOTARIZATION_ROWS) {
            mHtml += "<tr>";
            mHtml += "<td>" + slot.view + "</td>";
            mHtml += "<td>" + truncateHash(slot.blockHash) + "</td>";
            mHtml += "<td>" + slot.voteCount + "</td>";
            mHtml += "<td>" + formatTimestamp(slot.mNotarizedAt) + "</td>";
            mHtml += "</tr>";
            mCount++;
        }

        if (slot.lNotarizedAt > 0 && lCount < MAX_NOTARIZATION_ROWS) {
            lHtml += "<tr>";
            lHtml += "<td>" + slot.view + "</td>";
            lHtml += "<td>" + truncateHash(slot.blockHash) + "</td>";
            lHtml += "<td>" + slot.voteCount + "</td>";
            lHtml += "<td>" + formatTimestamp(slot.lNotarizedAt) + "</td>";
            lHtml += "</tr>";
            lCount++;
        }

        if (slot.nullifiedAt > 0 && nCount < MAX_NOTARIZATION_ROWS) {
            nHtml += "<tr>";
            nHtml += "<td>" + slot.view + "</td>";
            nHtml += "<td>" + slot.nullifyCount + "</td>";
            nHtml += "<td>" + formatTimestamp(slot.nullifiedAt) + "</td>";
            nHtml += "</tr>";
            nCount++;
        }
    }

    mTbody.innerHTML = mHtml;
    lTbody.innerHTML = lHtml;
    nTbody.innerHTML = nHtml;
}

// --- Logs ---

function renderLogs() {
    var container = document.getElementById("log-container");
    var entries = state.logEntries;
    var startIdx = Math.max(0, entries.length - MAX_LOG_ENTRIES);

    var html = "";
    for (var i = startIdx; i < entries.length; i++) {
        var entry = entries[i];
        var kindCss = entry.kind.replace(/_/g, "-");
        html += '<div class="log-entry">';
        html += '<span class="log-time">' + formatTimestamp(entry.time) + '</span>';
        html += '<span class="log-kind ' + kindCss + '">' + entry.kind + '</span>';
        html += '<span class="log-data">' + escapeHtml(entry.data) + '</span>';
        html += '</div>';
    }

    container.innerHTML = html;

    if (autoScroll) {
        container.scrollTop = container.scrollHeight;
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Return view keys sorted descending (most recent first). */
function sortedViewKeys() {
    var keys = [];
    state.viewMap.forEach(function (_val, key) {
        keys.push(key);
    });
    keys.sort(function (a, b) { return b - a; });
    return keys;
}

function escapeHtml(text) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Tab System
// ---------------------------------------------------------------------------

function initTabs() {
    var nav = document.getElementById("tab-nav");
    nav.addEventListener("click", function (e) {
        var btn = e.target.closest(".tab-btn");
        if (!btn) return;
        var tabId = btn.getAttribute("data-tab");

        // Deactivate all
        var buttons = nav.querySelectorAll(".tab-btn");
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].classList.remove("active");
        }
        var panels = document.querySelectorAll(".tab-panel");
        for (var j = 0; j < panels.length; j++) {
            panels[j].classList.remove("active");
        }

        // Activate selected
        btn.classList.add("active");
        var panel = document.getElementById("panel-" + tabId);
        if (panel) panel.classList.add("active");
    });
}

// ---------------------------------------------------------------------------
// Log auto-scroll toggle
// ---------------------------------------------------------------------------

function initLogToggle() {
    var btn = document.getElementById("log-auto-scroll-btn");
    btn.addEventListener("click", function () {
        autoScroll = !autoScroll;
        btn.textContent = "Auto-scroll: " + (autoScroll ? "ON" : "OFF");
        if (autoScroll) {
            btn.classList.remove("paused");
            var container = document.getElementById("log-container");
            container.scrollTop = container.scrollHeight;
        } else {
            btn.classList.add("paused");
        }
    });
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

function init() {
    initTabs();
    initLogToggle();

    // Fetch initial state, then connect SSE
    fetch("/api/state")
        .then(function (res) { return res.json(); })
        .then(function (snap) {
            applySnapshot(snap);
            addLogEntry("init", "loaded snapshot: view=" + snap.current_view +
                        " finalized=" + snap.finalized_view +
                        " n=" + snap.node_n + " f=" + snap.node_f);
            scheduleRender();
            connectSse();
        })
        .catch(function (err) {
            addLogEntry("error", "failed to fetch initial state: " + err.message);
            scheduleRender();
            // Still try SSE even if initial fetch fails
            connectSse();
        });
}

document.addEventListener("DOMContentLoaded", init);

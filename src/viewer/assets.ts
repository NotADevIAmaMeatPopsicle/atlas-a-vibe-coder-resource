import { VIEWER_VERSION } from './types.js';

export const VIEWER_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'">
  <meta name="referrer" content="no-referrer">
  <title>Atlas Run Viewer</title>
  <link rel="stylesheet" href="app.css">
  <script src="atlas-data.js" defer></script>
  <script src="app.js" defer></script>
</head>
<body>
  <a class="skip-link" href="#investigation-heading">Skip to investigation</a>
  <aside class="app-sidebar" aria-label="Atlas workspace navigation">
    <div class="sidebar-brand">
      <span class="brand-mark" aria-hidden="true">A</span>
      <span>Atlas</span>
    </div>
    <p class="sidebar-label">Review workspace</p>
    <nav class="workspace-navigation" aria-label="Viewer sections">
      <button class="workspace-nav-item active" type="button" data-workspace-view="investigation" aria-label="Investigation queue" aria-pressed="true">
        <span aria-hidden="true">◎</span><span>Investigation queue</span><strong id="sidebar-finding-count">0</strong>
      </button>
      <button class="workspace-nav-item" type="button" data-workspace-view="map" aria-label="System map" aria-pressed="false">
        <span aria-hidden="true">◇</span><span>System map</span>
      </button>
      <button class="workspace-nav-item" type="button" data-workspace-view="health" aria-label="Run health" aria-pressed="false">
        <span aria-hidden="true">◉</span><span>Run health</span>
      </button>
      <button class="workspace-nav-item" type="button" data-workspace-view="records" aria-label="Evidence library" aria-pressed="false">
        <span aria-hidden="true">▤</span><span>Evidence library</span>
      </button>
    </nav>
    <p class="sidebar-label saved-view-label">Quick views</p>
    <div class="saved-views" aria-label="Finding shortcuts">
      <button type="button" data-finding-shortcut="high">High impact</button>
      <button type="button" data-finding-shortcut="production">Production paths</button>
      <button type="button" data-finding-shortcut="contracts">Contract drift</button>
    </div>
    <div class="sidebar-target">
      <span>Current target</span>
      <strong id="sidebar-target-id">Loading target…</strong>
      <small><span id="sidebar-file-count">0</span> files indexed</small>
    </div>
    <div class="sidebar-foot">
      <span class="sidebar-avatar" aria-hidden="true">A</span>
      <div><strong>Local review lane</strong><small>No network or source bodies</small></div>
    </div>
  </aside>
  <header class="app-header">
    <div class="header-context">
      <strong id="workspace-title">Investigation brief</strong>
      <span aria-hidden="true">/</span>
      <p id="run-identity" class="run-identity mono wrap">Loading run projection…</p>
    </div>
    <div class="header-actions">
      <p id="viewer-status" class="status" role="status" aria-live="polite"><span class="status-dot" aria-hidden="true"></span>Loading viewer data…</p>
      <button id="print-review" class="button secondary-button" type="button">Print review</button>
      <a class="button secondary-button download" href="dependency-graph.mmd" download aria-label="Download the complete dependency graph as Mermaid">Export Mermaid</a>
      <button id="verify-bundle" class="button primary-button" type="button">Verify bundle</button>
    </div>
  </header>

  <main class="app-main">
    <section class="overview-strip" aria-labelledby="overview-heading">
      <div class="overview-title">
        <p class="eyebrow">Current run evidence</p>
        <h2 id="overview-heading">What this review contains</h2>
        <p>One immutable run. Comparisons require a second verified bundle.</p>
        <p id="overview-health" class="overview-health">Health status loading…</p>
      </div>
      <div class="summary-grid">
        <div class="summary-card finding-summary"><span>Findings</span><strong id="summary-findings">0</strong></div>
        <div class="summary-card"><span>Files</span><strong id="summary-files">0</strong></div>
        <div class="summary-card"><span>Relationships</span><strong id="summary-relationships">0</strong></div>
        <div class="summary-card"><span>Resolved edges</span><strong id="summary-resolved">0</strong></div>
        <div class="summary-card"><span>Diagnostics</span><strong id="summary-diagnostics">0</strong></div>
        <div class="summary-card"><span>Size</span><strong id="summary-bytes">0 B</strong></div>
      </div>
    </section>

    <section id="investigation-workspace" class="investigation-workspace" data-workspace-panel="investigation" aria-labelledby="investigation-heading">
      <aside class="finding-queue-panel" aria-labelledby="investigation-heading">
        <div class="queue-heading">
          <div>
            <p class="eyebrow">Prioritized review</p>
            <h2 id="investigation-heading">Investigation queue</h2>
          </div>
          <span id="finding-queue-count" class="queue-count">0 findings</span>
        </div>
        <div class="queue-controls">
          <div class="search-box finding-search-box">
            <span class="search-icon" aria-hidden="true"></span>
            <label class="visually-hidden" for="finding-filter">Search findings</label>
            <input id="finding-filter" type="search" autocomplete="off" spellcheck="false" placeholder="Search findings or paths">
          </div>
          <div class="queue-filter-row">
            <div>
              <label for="finding-severity-filter">Severity</label>
              <select id="finding-severity-filter"><option value="all">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select>
            </div>
            <div>
              <label for="finding-sort">Sort by</label>
              <select id="finding-sort"><option value="severity">Actionability</option><option value="path">Path</option><option value="mechanism">Mechanism</option></select>
            </div>
          </div>
        </div>
        <details id="disposition-panel" class="disposition-panel" hidden>
          <summary><span>Dispositioned in this run</span><span id="disposition-count" class="count-badge">0</span></summary>
          <div id="disposition-list" class="disposition-list"></div>
        </details>
        <div id="finding-queue" class="finding-queue" role="listbox" aria-label="Prioritized findings"></div>
      </aside>

      <article class="investigation-brief" aria-labelledby="brief-title">
        <div id="brief-empty" class="brief-empty" hidden>
          <span aria-hidden="true">◎</span>
          <h2>No findings in this view</h2>
          <p>Change the queue filters or inspect the run health and evidence library.</p>
        </div>
        <div id="brief-content">
          <div class="brief-heading">
            <span id="brief-ordinal" class="brief-ordinal" aria-hidden="true">01</span>
            <div>
              <div class="brief-kicker"><span id="brief-severity" class="severity-chip">Finding</span><span id="brief-id" class="mono"></span></div>
              <h2 id="brief-title">Loading finding…</h2>
              <p id="brief-anchor" class="brief-anchor mono"></p>
            </div>
          </div>
          <div id="brief-badges" class="brief-badges" aria-label="Finding attributes"></div>

          <div class="brief-story">
            <section class="story-row" aria-labelledby="claim-heading">
              <h3 id="claim-heading">Claim</h3>
              <div class="story-card claim-card">
                <strong id="brief-claim-title"></strong>
                <p id="brief-description"></p>
              </div>
            </section>
            <section class="story-row" aria-labelledby="evidence-heading">
              <h3 id="evidence-heading">Evidence</h3>
              <details class="story-card evidence-card">
                <summary><strong>Supporting artifacts</strong><span id="brief-evidence-count">0 records</span></summary>
                <div id="brief-evidence" class="brief-evidence-list"></div>
              </details>
            </section>
            <section class="story-row" aria-labelledby="impact-heading">
              <h3 id="impact-heading">Impact</h3>
              <div class="story-card impact-card">
                <strong id="brief-impact-title"></strong>
                <p id="brief-impact-summary"></p>
                <dl id="brief-impact-metrics" class="impact-metrics"></dl>
                <p id="brief-limitations" class="brief-limitations"></p>
              </div>
            </section>
            <section class="story-row" aria-labelledby="refutation-heading">
              <h3 id="refutation-heading">Falsifier</h3>
              <div class="story-card refutation-card">
                <p id="brief-refutation"></p>
              </div>
            </section>
            <section class="story-row" aria-labelledby="next-action-heading">
              <h3 id="next-action-heading">Next action</h3>
              <div class="next-action-card">
                <p id="brief-next-validation"></p>
                <div class="next-action-buttons">
                  <button id="open-system-map" class="button secondary-button" type="button">Open system map</button>
                  <button id="open-related-file" class="button primary-button" type="button">Inspect related file</button>
                </div>
              </div>
            </section>
          </div>
        </div>
      </article>

      <aside class="review-context" aria-labelledby="review-context-heading">
        <div class="context-heading">
          <div><p class="eyebrow">Decision support</p><h2 id="review-context-heading">Review context</h2></div>
          <span id="brief-confidence" class="confidence-badge">Unknown</span>
        </div>
        <section class="context-section" aria-labelledby="calibration-heading">
          <div class="context-section-heading"><h3 id="calibration-heading">Severity calibration</h3><span id="brief-calibration-level">Not recorded</span></div>
          <div class="calibration-card">
            <strong id="brief-calibration-title">Calibration unavailable</strong>
            <div id="brief-calibration-scale" class="calibration-scale" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
            <p id="brief-calibration-rationale"></p>
          </div>
        </section>
        <section class="context-section" aria-labelledby="artifact-heading">
          <div class="context-section-heading"><h3 id="artifact-heading">Related artifacts</h3><span id="brief-artifact-count">0 total</span></div>
          <div id="brief-artifacts" class="brief-artifacts"></div>
        </section>
        <section class="context-section" aria-labelledby="mapping-heading">
          <div class="context-section-heading"><h3 id="mapping-heading">Mapping contexts</h3><span id="brief-context-count">0 total</span></div>
          <div id="brief-contexts" class="brief-contexts"></div>
        </section>
        <section class="context-section" aria-labelledby="brief-health-heading">
          <div class="context-section-heading"><h3 id="brief-health-heading">Run health</h3><span id="brief-health-state">Loading</span></div>
          <div class="brief-health-card">
            <div><span>Synthetic controls</span><strong id="brief-synthetic-health">Not recorded</strong></div>
            <div><span>Real-target tier</span><strong id="brief-real-target-health">Not bundled</strong></div>
            <p id="brief-health-note"></p>
            <button class="text-button" type="button" data-open-workspace="health">Review health details</button>
          </div>
        </section>
        <section class="context-section handoff-section" aria-labelledby="handoff-heading">
          <h3 id="handoff-heading">Handoff</h3>
          <p>Export the selected claim, evidence, calibration, limitations, and next validation as Markdown.</p>
          <button id="export-handoff" class="button primary-button full-button" type="button">Generate implementation handoff</button>
          <p id="handoff-status" class="handoff-status" role="status" aria-live="polite"></p>
        </section>
      </aside>
    </section>

    <section class="panel analysis-health-panel" data-workspace-panel="health" aria-labelledby="analysis-health-heading" hidden>
      <div class="analysis-health-heading">
        <div>
          <p class="eyebrow">Regression controls</p>
          <h2 id="analysis-health-heading">Analysis health</h2>
        </div>
        <p id="analysis-health-limitation" class="muted" aria-live="polite"></p>
      </div>
      <div class="health-summary-grid">
        <div class="health-summary-card"><span>Status</span><strong id="analysis-health-state">Loading</strong></div>
        <div class="health-summary-card"><span>Synthetic incident recall</span><strong id="analysis-health-recall">Not recorded</strong></div>
        <div class="health-summary-card"><span>Fixed-case silence</span><strong id="analysis-health-fixed-silence">Not recorded</strong></div>
        <div class="health-summary-card"><span>Rule health</span><strong id="analysis-health-rules">Not recorded</strong></div>
      </div>
      <details class="health-details">
        <summary><span>Control and input details</span><span id="health-detail-count" class="count-badge"></span></summary>
        <div class="health-record-grid">
          <section aria-labelledby="incomplete-inputs-heading">
            <div class="health-record-heading">
              <h3 id="incomplete-inputs-heading">Incomplete target inputs</h3>
              <span id="incomplete-input-count" class="count-badge"></span>
            </div>
            <div class="table-scroll health-table-scroll"><table><thead><tr><th>Rule</th><th>Target accounting</th><th>Reason</th></tr></thead><tbody id="incomplete-inputs"></tbody></table></div>
          </section>
          <section aria-labelledby="disabled-rules-heading">
            <div class="health-record-heading">
              <h3 id="disabled-rules-heading">Disabled rules</h3>
              <span id="disabled-rule-count" class="count-badge"></span>
            </div>
            <div class="table-scroll health-table-scroll"><table><thead><tr><th>Rule</th><th>Controls</th><th>Observations</th></tr></thead><tbody id="disabled-rules"></tbody></table></div>
          </section>
          <section aria-labelledby="health-incidents-heading">
            <div class="health-record-heading">
              <h3 id="health-incidents-heading">Incident regressions</h3>
              <span id="health-incident-count" class="count-badge"></span>
            </div>
            <div class="table-scroll health-table-scroll"><table><thead><tr><th>Family</th><th>Rule</th><th>Broken</th><th>Fixed</th><th>Status</th></tr></thead><tbody id="health-incidents"></tbody></table></div>
          </section>
        </div>
      </details>
    </section>

    <div id="workspace-grid" class="workspace-grid" data-workspace-panel="map" hidden>
      <aside class="panel explorer-panel" aria-labelledby="census-heading">
        <div class="panel-heading">
          <div>
            <p class="eyebrow">Explore</p>
            <h2 id="census-heading">Files</h2>
          </div>
          <kbd aria-label="Keyboard shortcut slash">/</kbd>
        </div>
        <label class="visually-hidden" for="file-filter">Search target-relative file paths</label>
        <div class="search-box">
          <span class="search-icon" aria-hidden="true"></span>
          <input id="file-filter" type="search" autocomplete="off" spellcheck="false" placeholder="Search files and paths">
          <button id="clear-filter" class="icon-button clear-button" type="button" aria-label="Clear file search" title="Clear search">×</button>
        </div>
        <div class="filter-grid">
          <div>
            <label for="kind-filter">Kind</label>
            <select id="kind-filter"><option value="all">All kinds</option></select>
          </div>
          <div>
            <label for="language-filter">Language</label>
            <select id="language-filter"><option value="all">All languages</option></select>
          </div>
        </div>
        <p id="census-limit" class="result-count muted"></p>
        <div id="file-results" class="file-results" role="listbox" aria-label="Matching files"></div>
        <div class="explorer-summary">
          <div><h3>File kinds</h3><ul id="kind-counts" class="count-list"></ul></div>
          <div><h3>Languages</h3><ul id="language-counts" class="count-list compact-count-list"></ul></div>
        </div>
      </aside>

      <section class="panel graph-panel" aria-labelledby="graph-heading">
        <div class="graph-header">
          <div>
            <p class="eyebrow">Interactive map</p>
            <div class="heading-row">
              <h2 id="graph-heading">Dependency topology</h2>
              <span id="graph-counts" class="count-badge" aria-live="polite">0 nodes · 0 edges</span>
            </div>
          </div>
          <div class="graph-actions">
            <label for="relationship-filter">Relationship</label>
            <select id="relationship-filter">
              <option value="all">All relationships</option>
              <option value="static-import">Static imports</option>
              <option value="dynamic-import">Dynamic imports</option>
              <option value="require">Requires</option>
              <option value="export-from">Re-exports</option>
            </select>
            <label for="graph-depth">Depth</label>
            <select id="graph-depth" disabled>
              <option value="1">1 hop</option>
              <option value="2" selected>2 hops</option>
              <option value="3">3 hops</option>
            </select>
            <button id="toggle-graph-focus" class="button secondary-button graph-focus-button" type="button" aria-pressed="false">Focus canvas</button>
          </div>
        </div>
        <div class="mode-bar" role="group" aria-label="Graph view">
          <button class="mode-button active" type="button" data-graph-mode="architecture" aria-pressed="true">Architecture</button>
          <button class="mode-button" type="button" data-graph-mode="neighborhood" aria-pressed="false">Neighborhood</button>
          <button class="mode-button" type="button" data-graph-mode="data-contracts" aria-pressed="false">Data contracts</button>
          <button class="mode-button" type="button" data-graph-mode="findings" aria-pressed="false">Findings map</button>
          <span class="mode-help" id="mode-description">Folders are grouped to reveal the repository’s main dependency flow.</span>
        </div>
        <div id="graph-stage" class="graph-stage">
          <div class="graph-legend" aria-label="Graph legend">
            <p>Legend</p>
            <ul id="graph-legend"></ul>
          </div>
          <svg id="graph-canvas" role="group" aria-labelledby="graph-heading graph-instructions" tabindex="0">
            <defs>
              <pattern id="grid-pattern" width="24" height="24" patternUnits="userSpaceOnUse">
                <circle cx="1" cy="1" r="1"></circle>
              </pattern>
              <marker id="arrow-static" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
              <marker id="arrow-dynamic" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
              <marker id="arrow-require" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
              <marker id="arrow-export" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
              <marker id="arrow-finding" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
              <marker id="arrow-contract-model" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
              <marker id="arrow-contract-storage" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
              <marker id="arrow-muted" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
            </defs>
            <rect id="graph-grid" x="-5000" y="-5000" width="10000" height="10000" fill="url(#grid-pattern)"></rect>
            <g id="graph-viewport">
              <g id="graph-edge-layer"></g>
              <g id="graph-node-layer"></g>
            </g>
          </svg>
          <div id="graph-empty" class="graph-empty" hidden>
            <strong>No connected records</strong>
            <span>Try another filter or select a different file.</span>
          </div>
          <div class="zoom-controls" aria-label="Graph zoom controls">
            <button id="zoom-out" class="icon-button" type="button" aria-label="Zoom out" title="Zoom out">−</button>
            <button id="fit-graph" class="fit-button" type="button">Fit</button>
            <button id="zoom-in" class="icon-button" type="button" aria-label="Zoom in" title="Zoom in">+</button>
          </div>
        </div>
        <p id="graph-instructions" class="graph-caption">Drag empty canvas to pan. Scroll or use the controls to zoom. Select a card to inspect it.</p>
        <p id="graph-limit" class="muted graph-limit" aria-live="polite"></p>
      </section>

      <aside class="panel inspector-panel" aria-labelledby="selected-heading">
        <div class="panel-heading inspector-heading">
          <div>
            <p id="selected-kind" class="eyebrow">Selected file</p>
            <h2 id="selected-heading">Details</h2>
          </div>
          <span id="selected-status" class="selection-dot" aria-hidden="true"></span>
        </div>
        <p id="selected-file-title" class="selection-title mono wrap" aria-live="polite">No file selected.</p>
        <p id="selected-file-metadata" class="selection-meta muted"></p>
        <div id="selected-badges" class="badge-row" aria-label="Selected record attributes"></div>
        <p id="selected-description" class="selection-description"></p>
        <dl id="selected-file-provenance" class="selection-provenance" hidden>
          <div><dt>File ID</dt><dd id="selected-file-id" class="mono wrap"></dd></div>
          <div><dt>Evidence</dt><dd id="selected-file-evidence" class="wrap"></dd></div>
          <div><dt>Lifecycle</dt><dd id="selected-file-lifecycle" class="wrap"></dd></div>
          <div><dt>Uncertainty / limitation</dt><dd id="selected-file-limitation" class="wrap"></dd></div>
        </dl>
        <dl id="selected-finding-details" class="selection-provenance" hidden>
          <div><dt>Mechanism</dt><dd id="selected-finding-mechanism" class="mono wrap"></dd></div>
          <div><dt>Severity calibration</dt><dd id="selected-finding-calibration" class="wrap"></dd></div>
          <div><dt>Calibration rationale</dt><dd id="selected-finding-rationale" class="wrap"></dd></div>
        </dl>
        <details id="selected-mapping-context-section" class="relationship-details" hidden>
          <summary><span>Mapping contexts</span><span id="selected-mapping-context-count" class="count-badge">0</span></summary>
          <div class="table-scroll compact-table-scroll"><table><thead><tr><th>Source</th><th>Compose / service</th><th>Host → container</th><th>Build details</th></tr></thead><tbody id="selected-mapping-contexts"></tbody></table></div>
        </details>
        <details id="selected-finding-instance-section" class="relationship-details" hidden>
          <summary><span>Finding instances</span><span id="selected-finding-instance-count" class="count-badge">0</span></summary>
          <div class="table-scroll compact-table-scroll"><table><thead><tr><th>Anchor</th><th>Signals</th><th>Evidence</th></tr></thead><tbody id="selected-finding-instances"></tbody></table></div>
        </details>
        <details id="selected-finding-evidence-section" class="relationship-details" hidden>
          <summary><span>Finding evidence</span><span id="selected-finding-evidence-count" class="count-badge">0</span></summary>
          <div class="table-scroll compact-table-scroll"><table><thead><tr><th>Producer</th><th>Basis</th><th>Location</th></tr></thead><tbody id="selected-finding-evidence"></tbody></table></div>
        </details>
        <button id="focus-neighborhood" class="button primary-button full-button" type="button">Show dependency neighborhood</button>
        <dl class="selection-stats">
          <div><dt id="selected-stat-one-label">Incoming</dt><dd id="selected-incoming-count">0</dd></div>
          <div><dt id="selected-stat-two-label">Outgoing</dt><dd id="selected-outgoing-count">0</dd></div>
          <div><dt id="selected-stat-three-label">Symbols</dt><dd id="selected-symbol-count">0</dd></div>
        </dl>
        <details id="incoming-relationship-section" class="relationship-details" open>
          <summary><span>Incoming relationships</span><span id="incoming-relationship-summary-count" class="count-badge">0</span></summary>
          <div class="table-scroll compact-table-scroll"><table><thead><tr><th>From</th><th>Type</th><th>Specifier</th><th>State</th><th>To</th><th>Location</th></tr></thead><tbody id="incoming-relationships"></tbody></table></div>
        </details>
        <details id="outgoing-relationship-section" class="relationship-details">
          <summary><span>Outgoing relationships</span><span id="outgoing-relationship-summary-count" class="count-badge">0</span></summary>
          <div class="table-scroll compact-table-scroll"><table><thead><tr><th>From</th><th>Type</th><th>Specifier</th><th>State</th><th>To</th><th>Location</th></tr></thead><tbody id="outgoing-relationships"></tbody></table></div>
        </details>
      </aside>
    </div>

    <section class="panel records-panel" data-workspace-panel="records" aria-labelledby="records-heading" hidden>
      <div class="records-heading">
        <div>
          <p class="eyebrow">Run records</p>
          <h2 id="records-heading">Data tables</h2>
        </div>
        <p>Full-fidelity records for review and audit. Visual maps stay intentionally bounded.</p>
      </div>
      <details open>
        <summary><span>Current graph connections</span><span id="graph-table-count" class="count-badge"></span></summary>
        <div class="table-scroll"><table><thead><tr><th>From</th><th>Type</th><th>Specifier</th><th>State</th><th>To</th></tr></thead><tbody id="graph-edges"></tbody></table></div>
      </details>
      <details>
        <summary><span>File census</span><span class="count-badge">Search-filtered</span></summary>
        <div class="table-scroll"><table><thead><tr><th>Path</th><th>Kind</th><th>Language</th><th>Bytes</th><th>Symbols</th><th>Environment keys</th></tr></thead><tbody id="census-files"></tbody></table></div>
      </details>
      <details>
        <summary><span id="findings-heading">Findings</span><span id="findings-limit" class="count-badge"></span></summary>
        <p class="record-note">The evidence table follows the filters and ordering in the Investigation queue.</p>
        <div class="table-scroll"><table><thead><tr><th>Severity</th><th>Kind</th><th>Instances</th><th>Mechanism</th><th>Contexts</th><th>Calibration</th><th>Category</th><th>Path</th><th>Finding</th><th>Impact context</th><th>Next validation</th></tr></thead><tbody id="findings"></tbody></table></div>
      </details>
      <details>
        <summary><span id="diagnostics-heading">Diagnostics summary</span><span id="diagnostics-limit" class="count-badge"></span></summary>
        <p class="record-note">Grouped by diagnostic code. Select a code to open its detailed records.</p>
        <div class="table-scroll diagnostic-summary-scroll"><table><thead><tr><th>Code</th><th>Total</th><th>Error</th><th>Warning</th><th>Info</th></tr></thead><tbody id="diagnostic-summary"></tbody></table></div>
      </details>
      <details id="diagnostic-details-section">
        <summary><span>Diagnostic details</span><span id="diagnostic-details-count" class="count-badge"></span></summary>
        <div class="record-toolbar diagnostic-toolbar">
          <div class="search-box"><span class="search-icon" aria-hidden="true"></span><label class="visually-hidden" for="diagnostic-filter">Search diagnostic details</label><input id="diagnostic-filter" type="search" autocomplete="off" spellcheck="false" placeholder="Search code, path, or message"></div>
          <div><label for="diagnostic-severity-filter">Severity</label><select id="diagnostic-severity-filter"><option value="all">All severities</option><option value="error">Error</option><option value="warning">Warning</option><option value="info">Info</option></select></div>
        </div>
        <div class="table-scroll"><table><thead><tr><th>Severity</th><th>Code</th><th>Path</th><th>Message</th></tr></thead><tbody id="diagnostics"></tbody></table></div>
      </details>
    </section>
  </main>
  <footer>
    <span>Deterministic projection of Atlas run records.</span>
    <span class="verification-guidance">This browser does not verify bundle hashes. Open <a href="viewer-manifest.json">viewer-manifest.json</a> and run <code>atlas viewer verify &lt;viewer-directory&gt;</code>.</span>
    <span>No source bodies, network requests, or external dependencies.</span>
  </footer>
  <noscript>This viewer requires its bundled local JavaScript. No network resources are used.</noscript>
  <dialog id="verification-dialog" class="verification-dialog" aria-labelledby="verification-title">
    <form method="dialog">
      <div class="dialog-heading"><div><p class="eyebrow">Integrity boundary</p><h2 id="verification-title">Verify this viewer outside the browser</h2></div><button class="icon-button" value="close" aria-label="Close verification instructions">×</button></div>
      <p>The browser renders bundled records but does not verify their hashes. Run the CLI against this directory before treating the projection as verified.</p>
      <code>atlas viewer verify &lt;viewer-directory&gt;</code>
      <div class="dialog-actions"><a href="viewer-manifest.json" class="button secondary-button">Open manifest</a><button class="button primary-button" value="close">Done</button></div>
    </form>
  </dialog>
</body>
</html>
`;

export const VIEWER_CSS = `:root {
  color-scheme: light;
  --canvas: #f7f9fc;
  --panel: #ffffff;
  --panel-subtle: #f8fafc;
  --panel-raised: #ffffff;
  --border: #e3e8ef;
  --border-strong: #cfd8e3;
  --text: #172033;
  --text-soft: #344259;
  --muted: #6b778c;
  --muted-light: #9aa6b6;
  --blue: #356ff6;
  --blue-soft: #edf3ff;
  --violet: #8256d9;
  --violet-soft: #f1ebff;
  --teal: #139c8b;
  --teal-soft: #e8f8f5;
  --orange: #e98a20;
  --orange-soft: #fff3e2;
  --coral: #e45f65;
  --coral-soft: #fff0f1;
  --green: #2f9365;
  --green-soft: #e9f7f0;
  --slate: #697586;
  --slate-soft: #eef2f6;
  --error: #c83d49;
  --shadow-sm: 0 1px 2px rgba(18, 32, 56, .04), 0 5px 18px rgba(18, 32, 56, .035);
  --shadow-md: 0 14px 36px rgba(30, 48, 74, .11);
  --radius: 16px;
  font-family: Inter, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

* { box-sizing: border-box; }
html { min-width: 320px; background: var(--canvas); }
body { margin: 0; background: var(--canvas); color: var(--text); line-height: 1.45; }
button, input, select { font: inherit; }
button, select { cursor: pointer; }
button:focus-visible, input:focus-visible, select:focus-visible, a:focus-visible, summary:focus-visible, [tabindex="0"]:focus-visible {
  outline: 3px solid rgba(59, 111, 245, .28);
  outline-offset: 2px;
}
h1, h2, h3, p { margin-top: 0; }
h1 { margin: 0; font-size: 1.15rem; line-height: 1.1; letter-spacing: -.02em; }
h2 { margin-bottom: 0; font-size: 1.04rem; line-height: 1.3; letter-spacing: -.012em; }
h3 { margin-bottom: 7px; font-size: .76rem; color: var(--text-soft); }
.mono { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }
.wrap { overflow-wrap: anywhere; }
.muted { color: var(--muted); }
.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
.skip-link {
  position: fixed;
  z-index: 100;
  top: 8px;
  left: 8px;
  transform: translateY(-160%);
  border-radius: 8px;
  background: var(--text);
  color: #fff;
  padding: 8px 12px;
}
.skip-link:focus { transform: translateY(0); }

.app-header {
  position: sticky;
  z-index: 20;
  top: 0;
  display: flex;
  min-height: 68px;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 11px clamp(16px, 2.6vw, 36px);
  border-bottom: 1px solid var(--border);
  background: rgba(255, 255, 255, .94);
  backdrop-filter: blur(14px);
  box-shadow: var(--shadow-sm);
}
.brand { display: flex; min-width: 0; align-items: center; gap: 12px; }
.brand-mark {
  display: grid;
  width: 38px;
  height: 38px;
  flex: 0 0 38px;
  place-items: center;
  border-radius: 12px;
  background: linear-gradient(145deg, #3974f5, #5a61e7);
  box-shadow: 0 8px 20px rgba(53, 111, 246, .24);
  color: #fff;
  font-size: 1.02rem;
  font-weight: 750;
}
.brand-line { display: flex; align-items: baseline; gap: 9px; }
.product-label {
  color: var(--muted);
  font-size: .78rem;
  font-weight: 600;
  letter-spacing: .01em;
}
.run-identity {
  max-width: 58vw;
  margin: 4px 0 0;
  color: var(--muted);
  font-size: .68rem;
}
.header-actions { display: flex; flex: none; align-items: center; gap: 12px; }
.status {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 0;
  color: var(--muted);
  font-size: .75rem;
  white-space: nowrap;
}
.status-dot, .selection-dot {
  width: 8px;
  height: 8px;
  flex: 0 0 8px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 0 3px var(--green-soft);
}
.status.loading .status-dot { background: var(--orange); box-shadow: 0 0 0 3px var(--orange-soft); }
.status.error { color: var(--error); }
.status.error .status-dot { background: var(--error); box-shadow: 0 0 0 3px var(--coral-soft); }
.selection-dot.finding { background: var(--coral); box-shadow: 0 0 0 3px var(--coral-soft); }
.button {
  display: inline-flex;
  min-height: 36px;
  align-items: center;
  justify-content: center;
  border: 1px solid transparent;
  border-radius: 9px;
  padding: 7px 12px;
  font-size: .78rem;
  font-weight: 700;
  text-decoration: none;
  transition: border-color .15s ease, background .15s ease, transform .15s ease;
}
.button:active { transform: translateY(1px); }
.secondary-button { border-color: var(--border-strong); background: #fff; color: var(--text-soft); }
.secondary-button:hover { border-color: #b7c3d1; background: var(--panel-subtle); }
.primary-button { background: var(--blue); color: #fff; }
.primary-button:hover { background: #2f61df; }
.full-button { width: 100%; margin: 16px 0; }

.app-main { padding: 16px clamp(12px, 2vw, 28px) 32px; }
.overview-strip {
  display: grid;
  grid-template-columns: minmax(190px, .72fr) minmax(680px, 3.28fr);
  align-items: center;
  gap: 18px;
  max-width: 1800px;
  margin: 0 auto 14px;
}
.overview-title { padding-left: 3px; }
.eyebrow {
  margin-bottom: 5px;
  color: var(--blue);
  font-size: .66rem;
  font-weight: 800;
  letter-spacing: .105em;
  text-transform: uppercase;
}
.summary-grid {
  display: grid;
  overflow: hidden;
  grid-template-columns: repeat(6, minmax(96px, 1fr));
  border: 1px solid var(--border);
  border-radius: 13px;
  background: var(--panel);
  box-shadow: var(--shadow-sm);
}
.summary-card {
  min-height: 60px;
  padding: 10px 13px 9px;
  border-right: 1px solid var(--border);
  background: transparent;
}
.summary-card:last-child { border-right: 0; }
.summary-card span { display: block; color: var(--muted); font-size: .66rem; font-weight: 650; }
.summary-card strong { display: block; margin-top: 2px; font-size: 1.15rem; letter-spacing: -.03em; }
.finding-summary strong { color: var(--coral); }

.analysis-health-panel { max-width: 1800px; margin: 0 auto 12px; overflow: hidden; }
.analysis-health-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 13px 16px;
  border-bottom: 1px solid var(--border);
}
.analysis-health-heading > p { max-width: 780px; margin: 0; font-size: .68rem; text-align: right; }
.health-summary-grid { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); }
.health-summary-card { padding: 10px 16px; border-right: 1px solid var(--border); background: var(--panel-subtle); }
.health-summary-card:last-child { border-right: 0; }
.health-summary-card span { display: block; color: var(--muted); font-size: .64rem; font-weight: 700; }
.health-summary-card strong { display: block; margin-top: 2px; font-size: .92rem; overflow-wrap: anywhere; }
.health-summary-card strong.complete { color: var(--green); }
.health-summary-card strong.incomplete { color: var(--error); }
.health-summary-card strong.legacy-not-recorded { color: var(--muted); }
.health-details { border-top: 1px solid var(--border); }
.health-details > summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 16px;
  background: var(--panel-subtle);
  color: var(--text-soft);
  font-size: .69rem;
  font-weight: 720;
  list-style: none;
}
.health-details > summary::-webkit-details-marker { display: none; }
.health-details > summary::after { color: var(--muted); content: "＋"; }
.health-details[open] > summary::after { content: "−"; }
.health-details > summary .count-badge { margin-left: auto; }
.health-record-grid { display: grid; grid-template-columns: repeat(3, minmax(280px, 1fr)); border-top: 1px solid var(--border); }
.health-record-grid > section + section { border-left: 1px solid var(--border); }
.health-record-heading { display: flex; align-items: center; justify-content: space-between; padding: 9px 12px 3px; }
.health-record-heading h3 { margin: 0; }
.health-table-scroll { max-height: 190px; }

.workspace-grid {
  display: grid;
  grid-template-areas: "explorer graph inspector";
  grid-template-columns: 244px minmax(480px, 1fr) 316px;
  min-height: 690px;
  max-width: 1800px;
  margin: 0 auto;
  gap: 12px;
}
.panel {
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--panel);
  box-shadow: var(--shadow-sm);
}
.explorer-panel { grid-area: explorer; }
.graph-panel { grid-area: graph; }
.inspector-panel { grid-area: inspector; }
.explorer-panel, .inspector-panel { max-height: 790px; overflow: hidden; padding: 16px; }
.inspector-panel { overflow: auto; overscroll-behavior: contain; }
.panel-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
kbd {
  min-width: 24px;
  border: 1px solid var(--border);
  border-bottom-color: var(--border-strong);
  border-radius: 6px;
  background: var(--panel-subtle);
  color: var(--muted);
  padding: 2px 7px;
  font: 600 .68rem "SFMono-Regular", Consolas, monospace;
  text-align: center;
}
.search-box { position: relative; margin-top: 13px; }
.search-icon {
  position: absolute;
  top: 50%;
  left: 12px;
  width: 11px;
  height: 11px;
  transform: translateY(-58%);
  border: 1.7px solid var(--muted-light);
  border-radius: 50%;
  pointer-events: none;
}
.search-icon::after {
  position: absolute;
  right: -4px;
  bottom: -3px;
  width: 5px;
  height: 1.7px;
  transform: rotate(45deg);
  border-radius: 2px;
  background: var(--muted-light);
  content: "";
}
input, select {
  width: 100%;
  border: 1px solid var(--border-strong);
  border-radius: 9px;
  background: #fff;
  color: var(--text);
}
input { height: 39px; padding: 8px 34px 8px 33px; font-size: .78rem; }
input::placeholder { color: var(--muted-light); }
input:hover, select:hover { border-color: #aebbc9; }
input:focus, select:focus { border-color: var(--blue); }
select:disabled, button:disabled { cursor: not-allowed; opacity: .52; }
.clear-button {
  position: absolute;
  top: 50%;
  right: 5px;
  width: 28px;
  height: 28px;
  transform: translateY(-50%);
  border: 0;
  background: transparent;
  color: var(--muted);
  font-size: 1.05rem;
}
.clear-button[hidden] { display: none; }
.filter-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 9px; }
label { display: block; margin-bottom: 4px; color: var(--muted); font-size: .65rem; font-weight: 700; }
select { min-height: 34px; padding: 6px 24px 6px 8px; font-size: .72rem; }
.result-count { margin: 10px 1px 7px; font-size: .68rem; }
.file-results {
  height: 378px;
  overflow: auto;
  overscroll-behavior: contain;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
  scrollbar-color: #c7d1dc transparent;
  scrollbar-width: thin;
}
.file-result {
  display: grid;
  width: 100%;
  grid-template-columns: 6px minmax(0, 1fr) auto;
  align-items: center;
  gap: 9px;
  border: 0;
  border-bottom: 1px solid #edf1f5;
  background: transparent;
  padding: 9px 5px 9px 2px;
  color: var(--text-soft);
  text-align: left;
}
.file-result:hover { background: #f7f9fc; }
.file-result.selected { background: var(--blue-soft); color: #244db7; }
.file-result:focus-visible { position: relative; z-index: 1; }
.file-accent { width: 3px; height: 28px; border-radius: 3px; background: var(--slate); }
.file-result.kind-source .file-accent { background: var(--blue); }
.file-result.kind-test .file-accent { background: var(--violet); }
.file-result.kind-configuration .file-accent { background: var(--orange); }
.file-result.kind-documentation .file-accent { background: var(--teal); }
.file-copy { min-width: 0; }
.file-name, .file-path { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-name { font: 650 .72rem "SFMono-Regular", Consolas, monospace; }
.file-path { margin-top: 2px; color: var(--muted); font: .61rem "SFMono-Regular", Consolas, monospace; }
.file-degree {
  min-width: 23px;
  border-radius: 999px;
  background: var(--slate-soft);
  color: var(--muted);
  padding: 2px 6px;
  font-size: .61rem;
  font-weight: 700;
  text-align: center;
}
.empty-list { padding: 28px 12px; color: var(--muted); font-size: .74rem; text-align: center; }
.explorer-summary { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; padding-top: 12px; }
.count-list { max-height: 86px; overflow: auto; margin: 0; padding: 0; list-style: none; }
.count-list li {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  padding: 2px 0;
  color: var(--muted);
  font-size: .65rem;
}
.count-list strong { color: var(--text-soft); font-size: .64rem; }

.graph-panel {
  display: flex;
  min-height: 690px;
  flex-direction: column;
  overflow: hidden;
  border-color: #d9e1eb;
  box-shadow: 0 1px 2px rgba(18, 32, 56, .04), 0 12px 34px rgba(18, 32, 56, .06);
}
.graph-header {
  display: flex;
  min-height: 78px;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 14px 18px 12px;
  border-bottom: 1px solid var(--border);
}
.heading-row { display: flex; align-items: center; gap: 9px; }
.count-badge {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  background: var(--slate-soft);
  color: var(--muted);
  padding: 3px 8px;
  font-size: .63rem;
  font-weight: 700;
  white-space: nowrap;
}
.graph-actions { display: grid; grid-template-columns: auto 128px auto 76px auto; align-items: center; gap: 5px 7px; }
.graph-actions label { margin: 0; }
.graph-actions select { min-height: 32px; }
.graph-focus-button { min-height: 32px; padding: 5px 10px; white-space: nowrap; }
.mode-bar {
  display: flex;
  min-height: 45px;
  align-items: center;
  gap: 3px;
  padding: 7px 14px;
  border-bottom: 1px solid var(--border);
  background: #fbfcfe;
}
.mode-button {
  min-height: 31px;
  border: 0;
  border-radius: 8px;
  background: transparent;
  color: var(--muted);
  padding: 6px 10px;
  font-size: .7rem;
  font-weight: 720;
}
.mode-button:hover { color: var(--text); background: #eef2f7; }
.mode-button.active {
  background: #fff;
  box-shadow: 0 1px 2px rgba(16, 24, 40, .08), inset 0 0 0 1px rgba(53, 111, 246, .10);
  color: var(--blue);
}
.mode-help {
  min-width: 180px;
  margin-left: auto;
  color: var(--muted);
  font-size: .64rem;
  text-align: right;
}
.graph-stage {
  position: relative;
  min-height: 540px;
  flex: 1;
  overflow: hidden;
  background: linear-gradient(180deg, #fcfdff 0%, #f9fbfe 100%);
}
#graph-canvas { display: block; width: 100%; height: 100%; min-height: 540px; cursor: grab; touch-action: none; }
#graph-canvas.dragging { cursor: grabbing; }
#grid-pattern circle { fill: #dce5ef; opacity: .75; }
#graph-grid { pointer-events: all; }
.graph-legend {
  position: absolute;
  z-index: 4;
  top: 12px;
  left: 12px;
  min-width: 140px;
  max-width: 190px;
  border: 1px solid rgba(213, 222, 232, .88);
  border-radius: 12px;
  background: rgba(255, 255, 255, .95);
  box-shadow: 0 8px 24px rgba(30, 48, 74, .08);
  padding: 10px 11px;
  pointer-events: none;
}
.graph-legend p { margin-bottom: 6px; color: var(--text-soft); font-size: .63rem; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.graph-legend ul { display: grid; gap: 4px; margin: 0; padding: 0; list-style: none; }
.legend-item { display: flex; align-items: center; gap: 7px; color: var(--muted); font-size: .61rem; }
.legend-swatch { width: 10px; height: 10px; flex: 0 0 10px; border-radius: 3px; background: var(--slate); }
.legend-line { width: 18px; height: 0; flex: 0 0 18px; border-top: 2px solid var(--slate); border-radius: 1px; }
.legend-source { background: var(--blue); }
.legend-test { background: var(--violet); }
.legend-config { background: var(--orange); }
.legend-docs { background: var(--teal); }
.legend-external { background: var(--green); }
.legend-unresolved-swatch { background: var(--slate); }
.legend-finding { background: var(--coral); }
.legend-contract { background: var(--coral); }
.legend-model { background: var(--blue); }
.legend-storage { background: var(--teal); }
.legend-static { border-color: var(--blue); }
.legend-dynamic { border-color: var(--violet); }
.legend-model-edge { border-color: var(--blue); }
.legend-storage-edge { border-color: var(--teal); }
.legend-unresolved { border-top-style: dashed; border-color: var(--slate); }
.zoom-controls {
  position: absolute;
  z-index: 4;
  right: 12px;
  bottom: 12px;
  display: flex;
  overflow: hidden;
  border: 1px solid var(--border-strong);
  border-radius: 9px;
  background: #fff;
  box-shadow: var(--shadow-md);
}
.icon-button, .fit-button {
  display: grid;
  min-width: 34px;
  height: 34px;
  place-items: center;
  border: 0;
  border-right: 1px solid var(--border);
  background: #fff;
  color: var(--text-soft);
  font-weight: 700;
}
.zoom-controls button:last-child { border-right: 0; }
.icon-button:hover, .fit-button:hover { background: var(--panel-subtle); }
.fit-button { min-width: 42px; font-size: .66rem; }
.graph-empty {
  position: absolute;
  z-index: 3;
  inset: 0;
  display: grid;
  place-content: center;
  color: var(--muted);
  text-align: center;
  pointer-events: none;
}
.graph-empty[hidden] { display: none; }
.graph-empty strong { color: var(--text-soft); font-size: .88rem; }
.graph-empty span { margin-top: 4px; font-size: .7rem; }
.graph-caption, .graph-limit {
  margin: 0;
  border-top: 1px solid var(--border);
  background: #fff;
  color: var(--muted);
  padding: 7px 13px;
  font-size: .63rem;
}
.graph-limit { border-top: 0; padding-top: 0; }

.graph-edge-path {
  fill: none;
  stroke: var(--slate);
  stroke-width: 1.35;
  stroke-linecap: round;
  opacity: .54;
  vector-effect: non-scaling-stroke;
  transition: opacity .12s ease, stroke-width .12s ease;
}
.edge-static-import { stroke: var(--blue); marker-end: url(#arrow-static); }
.edge-dynamic-import { stroke: var(--violet); marker-end: url(#arrow-dynamic); }
.edge-require { stroke: var(--orange); marker-end: url(#arrow-require); }
.edge-export-from { stroke: var(--teal); marker-end: url(#arrow-export); }
.edge-finding-link { stroke: var(--coral); marker-end: url(#arrow-finding); }
.edge-contract-model { stroke: var(--blue); marker-end: url(#arrow-contract-model); }
.edge-contract-storage { stroke: var(--teal); marker-end: url(#arrow-contract-storage); }
.edge-muted { stroke: var(--slate); marker-end: url(#arrow-muted); }
.graph-edge.unresolved .graph-edge-path, .graph-edge.type-only .graph-edge-path { stroke-dasharray: 5 4; }
.graph-edge.related .graph-edge-path { stroke-width: 2.4; opacity: .95; }
.graph-edge.dimmed { opacity: .12; }
.edge-count {
  fill: var(--text-soft);
  paint-order: stroke;
  stroke: #fbfcfe;
  stroke-width: 4px;
  stroke-linejoin: round;
  font-size: 10px;
  font-weight: 750;
  text-anchor: middle;
}
.edge-label {
  fill: var(--muted);
  paint-order: stroke;
  stroke: #fbfcfe;
  stroke-width: 4px;
  stroke-linejoin: round;
  font-size: 9px;
  font-weight: 650;
  text-anchor: middle;
}

.graph-node { cursor: pointer; transition: opacity .12s ease; }
.graph-node .node-surface {
  fill: #fff;
  stroke: #d7e0eb;
  stroke-width: 1.2;
  filter: drop-shadow(0 4px 7px rgba(26, 45, 72, .095));
  vector-effect: non-scaling-stroke;
}
.graph-node .node-accent { fill: var(--slate); }
.graph-node.kind-source .node-accent { fill: var(--blue); }
.graph-node.kind-test .node-accent { fill: var(--violet); }
.graph-node.kind-configuration .node-accent { fill: var(--orange); }
.graph-node.kind-documentation .node-accent { fill: var(--teal); }
.graph-node.kind-external .node-accent { fill: var(--green); }
.graph-node.kind-unresolved .node-accent { fill: var(--slate); }
.graph-node.kind-finding .node-accent { fill: var(--coral); }
.graph-node.kind-data-contract .node-accent { fill: var(--coral); }
.graph-node.kind-contract-model .node-accent { fill: var(--blue); }
.graph-node.kind-contract-storage .node-accent { fill: var(--teal); }
.graph-node.kind-cluster .node-accent { fill: #6b7c93; }
.node-icon-ring { fill: var(--slate-soft); }
.kind-source .node-icon-ring { fill: var(--blue-soft); }
.kind-test .node-icon-ring { fill: var(--violet-soft); }
.kind-configuration .node-icon-ring { fill: var(--orange-soft); }
.kind-documentation .node-icon-ring { fill: var(--teal-soft); }
.kind-external .node-icon-ring { fill: var(--green-soft); }
.kind-finding .node-icon-ring { fill: var(--coral-soft); }
.kind-data-contract .node-icon-ring { fill: var(--coral-soft); }
.kind-contract-model .node-icon-ring { fill: var(--blue-soft); }
.kind-contract-storage .node-icon-ring { fill: var(--teal-soft); }
.node-icon-dot { fill: var(--slate); }
.kind-source .node-icon-dot { fill: var(--blue); }
.kind-test .node-icon-dot { fill: var(--violet); }
.kind-configuration .node-icon-dot { fill: var(--orange); }
.kind-documentation .node-icon-dot { fill: var(--teal); }
.kind-external .node-icon-dot { fill: var(--green); }
.kind-finding .node-icon-dot { fill: var(--coral); }
.kind-data-contract .node-icon-dot { fill: var(--coral); }
.kind-contract-model .node-icon-dot { fill: var(--blue); }
.kind-contract-storage .node-icon-dot { fill: var(--teal); }
.node-title { fill: var(--text); font: 680 12px "SFMono-Regular", Consolas, monospace; }
.node-subtitle { fill: var(--muted); font: 10px "SFMono-Regular", Consolas, monospace; }
.node-meta { fill: var(--muted); font: 10px Inter, "Segoe UI", sans-serif; }
.node-pill { fill: var(--slate-soft); }
.kind-source .node-pill { fill: var(--blue-soft); }
.kind-test .node-pill { fill: var(--violet-soft); }
.kind-configuration .node-pill { fill: var(--orange-soft); }
.kind-documentation .node-pill { fill: var(--teal-soft); }
.kind-finding .node-pill { fill: var(--coral-soft); }
.kind-data-contract .node-pill { fill: var(--coral-soft); }
.kind-contract-model .node-pill { fill: var(--blue-soft); }
.kind-contract-storage .node-pill { fill: var(--teal-soft); }
.node-pill-text { fill: var(--text-soft); font: 700 9px Inter, "Segoe UI", sans-serif; text-anchor: middle; }
.graph-node:hover .node-surface { stroke: #9eb1c7; filter: drop-shadow(0 7px 12px rgba(26, 45, 72, .13)); }
.graph-node.selected .node-surface {
  stroke: var(--blue);
  stroke-width: 2.2;
  filter: drop-shadow(0 7px 10px rgba(59, 111, 245, .20));
}
.graph-node.kind-finding.selected .node-surface { stroke: var(--coral); }
.graph-node.kind-data-contract.selected .node-surface { stroke: var(--coral); }
.graph-node.related .node-surface { stroke: #8fa8ea; }
.graph-node.dimmed { opacity: .28; }

#arrow-static path { fill: var(--blue); }
#arrow-dynamic path { fill: var(--violet); }
#arrow-require path { fill: var(--orange); }
#arrow-export path { fill: var(--teal); }
#arrow-finding path { fill: var(--coral); }
#arrow-contract-model path { fill: var(--blue); }
#arrow-contract-storage path { fill: var(--teal); }
#arrow-muted path { fill: var(--slate); }

.inspector-panel { overflow: auto; scrollbar-color: #c7d1dc transparent; scrollbar-width: thin; }
.workspace-grid.graph-focus {
  grid-template-areas: "graph";
  grid-template-columns: minmax(0, 1fr);
}
.workspace-grid.graph-focus .explorer-panel,
.workspace-grid.graph-focus .inspector-panel { display: none; }
.workspace-grid.graph-focus .graph-panel { min-height: calc(100vh - 184px); }
.workspace-grid.graph-focus .graph-stage,
.workspace-grid.graph-focus #graph-canvas { min-height: calc(100vh - 334px); }
.inspector-heading { padding-bottom: 12px; border-bottom: 1px solid var(--border); }
.selection-title { margin: 15px 0 6px; color: var(--text); font-size: .79rem; font-weight: 720; line-height: 1.5; }
.selection-meta { margin-bottom: 10px; font-size: .67rem; overflow-wrap: anywhere; }
.badge-row { display: flex; flex-wrap: wrap; gap: 5px; }
.badge {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--slate-soft);
  color: var(--text-soft);
  padding: 3px 7px;
  font-size: .61rem;
  font-weight: 700;
}
.badge.source { border-color: #cedafe; background: var(--blue-soft); color: #3159bb; }
.badge.test { border-color: #decffc; background: var(--violet-soft); color: #6840b3; }
.badge.configuration { border-color: #f5d7ae; background: var(--orange-soft); color: #9e5b0e; }
.badge.documentation { border-color: #bce5df; background: var(--teal-soft); color: #167669; }
.badge.active { border-color: #b8dec7; background: var(--green-soft); color: #277248; }
.badge.mothballed { border-color: #f3c8cb; background: var(--coral-soft); color: #a44047; }
.badge.shared { border-color: #bce5df; background: var(--teal-soft); color: #167669; }
.badge.unknown, .badge.unspecified { border-color: #d7dee7; background: var(--slate-soft); color: #59677a; }
.badge.finding, .badge.data-contract, .badge.high, .badge.medium { border-color: #f3c8cb; background: var(--coral-soft); color: #b5474d; }
.selection-description { margin: 12px 0 0; color: var(--text-soft); font-size: .7rem; line-height: 1.55; }
.selection-provenance {
  display: grid;
  gap: 7px;
  margin: 12px 0 0;
}
.selection-provenance[hidden] { display: none; }
.selection-provenance div { border-left: 2px solid var(--border-strong); padding-left: 8px; }
.selection-provenance dt { color: var(--muted); font-size: .58rem; font-weight: 760; letter-spacing: .025em; text-transform: uppercase; }
.selection-provenance dd { margin: 2px 0 0; color: var(--text-soft); font-size: .65rem; line-height: 1.45; }
.selection-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; margin: 0 0 16px; }
.selection-stats div { border: 1px solid var(--border); border-radius: 9px; background: var(--panel-subtle); padding: 8px; text-align: center; }
.selection-stats dt { color: var(--muted); font-size: .58rem; font-weight: 700; }
.selection-stats dd { margin: 2px 0 0; color: var(--text); font-size: .92rem; font-weight: 750; }
.relationship-details { border-top: 1px solid var(--border); }
.relationship-details summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 10px 1px;
  color: var(--text-soft);
  font-size: .68rem;
  font-weight: 720;
}
.relationship-details summary .count-badge { margin-left: auto; }
.compact-table-scroll { max-height: 230px; border-radius: 7px; }

.records-panel { max-width: 1800px; margin: 12px auto 0; overflow: hidden; }
.records-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 14px 17px;
  border-bottom: 1px solid var(--border);
}
.records-heading > p { max-width: 520px; margin: 0; color: var(--muted); font-size: .69rem; text-align: right; }
.records-panel > details { border-bottom: 1px solid var(--border); }
.records-panel > details:last-child { border-bottom: 0; }
.records-panel > details > summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 11px 17px;
  background: var(--panel-subtle);
  color: var(--text-soft);
  font-size: .74rem;
  font-weight: 720;
  list-style: none;
}
.records-panel > details > summary::-webkit-details-marker { display: none; }
.records-panel > details > summary::after { margin-left: auto; color: var(--muted); content: "＋"; font-size: .88rem; }
.records-panel > details[open] > summary::after { content: "−"; }
.records-panel > details > summary .count-badge { margin-left: auto; }
.record-toolbar {
  display: grid;
  grid-template-columns: minmax(240px, 1fr) minmax(130px, 180px) minmax(130px, 180px);
  align-items: end;
  gap: 10px;
  padding: 11px 13px;
  border-bottom: 1px solid var(--border);
}
.record-toolbar .search-box { margin-top: 0; }
.record-note { margin: 0; padding: 9px 13px; border-bottom: 1px solid var(--border); color: var(--muted); font-size: .68rem; }
.diagnostic-toolbar { grid-template-columns: minmax(240px, 1fr) minmax(130px, 180px); }
.diagnostic-summary-scroll { max-height: 320px; }
.finding-select, .diagnostic-code-button {
  border: 0;
  background: transparent;
  color: #315dc9;
  padding: 0;
  font: inherit;
  font-weight: 700;
  text-align: left;
}
.finding-select:hover, .finding-select:focus-visible,
.diagnostic-code-button:hover, .diagnostic-code-button:focus-visible { text-decoration: underline; }
.table-scroll { max-height: 430px; overflow: auto; overscroll-behavior: contain; }
table { width: 100%; border-collapse: collapse; font-size: .68rem; }
th {
  position: sticky;
  z-index: 2;
  top: 0;
  background: #f3f6f9;
  color: var(--muted);
  font-size: .61rem;
  font-weight: 800;
  letter-spacing: .035em;
  text-align: left;
  text-transform: uppercase;
}
th, td { padding: 8px 10px; border-bottom: 1px solid #edf1f5; vertical-align: top; }
td { max-width: 420px; color: var(--text-soft); overflow-wrap: anywhere; }
tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: #fafbfd; }
.path-button {
  border: 0;
  background: transparent;
  color: #315dc9;
  padding: 0;
  text-align: left;
  font: inherit;
  font-family: "SFMono-Regular", Consolas, monospace;
}
.path-button:hover, .path-button:focus-visible { text-decoration: underline; }
.severity-high, .severity-error { color: var(--error); font-weight: 750; }
.severity-medium, .severity-warning { color: #ae650d; font-weight: 750; }
.severity-low, .severity-info { color: #315dc9; font-weight: 750; }

footer {
  display: flex;
  max-width: 1800px;
  justify-content: space-between;
  gap: 20px;
  margin: 0 auto;
  padding: 16px clamp(16px, 2vw, 28px) 28px;
  color: var(--muted);
  font-size: .63rem;
}
footer .verification-guidance { max-width: 720px; text-align: center; }
footer a { color: #315dc9; font-weight: 700; }
footer code { color: var(--text-soft); font-family: "SFMono-Regular", Consolas, monospace; }
noscript { display: block; margin: 16px; border: 1px solid #f1c6ca; border-radius: 10px; background: var(--coral-soft); color: var(--error); padding: 12px; }

@media (max-width: 1280px) {
  .workspace-grid {
    grid-template-areas:
      "graph graph"
      "explorer inspector";
    grid-template-columns: minmax(0, 1fr) minmax(320px, 1fr);
  }
  .graph-panel { min-height: 650px; }
  .explorer-panel, .inspector-panel { max-height: 600px; }
  .overview-strip { grid-template-columns: 1fr; gap: 8px; }
}
@media (max-width: 860px) {
  .app-header { position: static; align-items: flex-start; }
  .header-actions { align-items: flex-end; flex-direction: column-reverse; }
  .run-identity { max-width: 62vw; }
  .summary-grid { grid-template-columns: repeat(3, 1fr); }
  .summary-card:nth-child(3) { border-right: 0; }
  .summary-card:nth-child(-n+3) { border-bottom: 1px solid var(--border); }
  .health-summary-grid { grid-template-columns: repeat(2, 1fr); }
  .health-summary-card:nth-child(2) { border-right: 0; }
  .health-summary-card:nth-child(-n+2) { border-bottom: 1px solid var(--border); }
  .health-record-grid { grid-template-columns: 1fr; }
  .health-record-grid > section + section { border-top: 1px solid var(--border); border-left: 0; }
  .workspace-grid {
    grid-template-areas:
      "graph"
      "explorer"
      "inspector";
    grid-template-columns: minmax(0, 1fr);
  }
  .graph-panel { min-height: 590px; }
  .explorer-panel { max-height: none; }
  .file-results { height: 220px; }
  .explorer-summary { display: none; }
  .graph-header { align-items: flex-start; flex-direction: column; }
  .graph-actions { width: 100%; grid-template-columns: auto 1fr auto 90px auto; }
  .mode-help { display: none; }
  .inspector-panel { max-height: none; }
  .record-toolbar { grid-template-columns: minmax(0, 1fr) minmax(120px, .45fr); }
  .record-toolbar > :last-child:nth-child(3) { grid-column: 1 / -1; }
}
@media (max-width: 560px) {
  .app-header { gap: 12px; }
  .product-label, .status { display: none; }
  .run-identity { max-width: 54vw; }
  .app-main { padding-top: 12px; }
  .overview-strip { margin-bottom: 10px; }
  .overview-title { display: none; }
  .summary-grid { grid-template-columns: repeat(3, 1fr); }
  .summary-card { min-height: 54px; padding: 8px 9px; }
  .summary-card span { font-size: .59rem; }
  .summary-card strong { font-size: .98rem; }
  .analysis-health-heading { align-items: flex-start; flex-direction: column; gap: 6px; }
  .analysis-health-heading > p { text-align: left; }
  .health-summary-grid { grid-template-columns: 1fr 1fr; }
  .graph-panel { min-height: 535px; }
  .graph-stage, #graph-canvas { min-height: 420px; }
  .mode-bar { overflow-x: auto; scroll-snap-type: x proximity; }
  .mode-button { white-space: nowrap; }
  .mode-button { min-height: 40px; scroll-snap-align: start; }
  .graph-legend { display: none; }
  .graph-actions { grid-template-columns: 1fr; }
  .graph-actions label { display: block; margin: 4px 0 0; }
  .graph-focus-button { grid-column: 1 / -1; }
  .record-toolbar, .diagnostic-toolbar { grid-template-columns: 1fr; }
  .record-toolbar > :last-child:nth-child(3) { grid-column: auto; }
  .records-heading { align-items: flex-start; flex-direction: column; }
  .records-heading > p { text-align: left; }
  .inspector-panel .relationship-details { display: block; width: 100%; }
  .inspector-panel .relationship-details + .relationship-details { margin-left: 0; }
  footer { flex-direction: column; gap: 4px; }
}
/* Investigation Brief shell */
[hidden] { display: none !important; }
:root {
  --canvas: #f3f0e8;
  --panel: #fffefa;
  --panel-subtle: #f6f3ec;
  --panel-raised: #fffefa;
  --border: #ddd7cc;
  --border-strong: #cfc7bb;
  --text: #1f2a26;
  --text-soft: #46534e;
  --muted: #77817c;
  --muted-light: #9aa19d;
  --blue: #31584d;
  --blue-soft: #edf4f0;
  --teal: #2f755f;
  --teal-soft: #e8f3ed;
  --orange: #c4743b;
  --orange-soft: #fff1e6;
  --coral: #b94e45;
  --coral-soft: #fbeae7;
  --green: #2f765f;
  --green-soft: #e8f3ed;
  --shadow-sm: 0 1px 2px rgba(35, 46, 40, .035), 0 5px 18px rgba(35, 46, 40, .03);
  --shadow-md: 0 16px 42px rgba(35, 46, 40, .13);
}
html, body { background: var(--canvas); }
body { min-height: 100vh; }
.app-sidebar {
  position: fixed;
  z-index: 30;
  inset: 0 auto 0 0;
  width: 238px;
  display: flex;
  flex-direction: column;
  padding: 25px 20px 20px;
  color: #dbe2dd;
  background: #203630;
  box-shadow: inset -1px 0 rgba(255, 255, 255, .045);
}
.sidebar-brand { display: flex; align-items: center; gap: 11px; padding-bottom: 27px; color: #fff; font-size: 1.08rem; font-weight: 800; letter-spacing: .02em; text-transform: uppercase; }
.sidebar-brand .brand-mark { width: 33px; height: 33px; flex-basis: 33px; border-radius: 50%; color: #23352f; background: #d8ef70; box-shadow: none; font-size: .78rem; }
.sidebar-label { margin: 0 0 8px; color: #8ca097; font-size: .61rem; font-weight: 800; letter-spacing: .11em; text-transform: uppercase; }
.saved-view-label { margin-top: 27px; }
.workspace-navigation { display: grid; gap: 4px; }
.workspace-nav-item {
  width: 100%; min-height: 43px; display: grid; grid-template-columns: 18px 1fr auto; align-items: center; gap: 9px;
  padding: 0 11px; border: 0; border-radius: 10px; color: #a9b7b1; background: transparent; font-size: .75rem; text-align: left;
}
.workspace-nav-item:hover { color: #f4f6f3; background: rgba(255,255,255,.055); }
.workspace-nav-item.active { color: #fff; background: rgba(255,255,255,.09); box-shadow: inset 3px 0 #d8ef70; }
.workspace-nav-item strong { min-width: 25px; padding: 3px 7px; border-radius: 999px; color: #24352f; background: #d8ef70; font-size: .62rem; text-align: center; }
.saved-views { display: grid; gap: 3px; }
.saved-views button { min-height: 37px; padding: 0 11px; border: 0; border-radius: 8px; color: #9fb0a9; background: transparent; font-size: .72rem; text-align: left; }
.saved-views button:hover { color: #fff; background: rgba(255,255,255,.05); }
.sidebar-target { margin-top: 27px; padding: 13px; border: 1px solid rgba(255,255,255,.12); border-radius: 11px; background: rgba(255,255,255,.055); }
.sidebar-target > span { display: block; color: #8da097; font-size: .58rem; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }
.sidebar-target strong { display: block; margin-top: 8px; color: #fff; font-size: .72rem; overflow-wrap: anywhere; }
.sidebar-target small { display: block; margin-top: 5px; color: #94a59e; font-size: .6rem; }
.sidebar-foot { display: flex; align-items: center; gap: 10px; margin-top: auto; padding-top: 17px; border-top: 1px solid rgba(255,255,255,.11); }
.sidebar-avatar { width: 31px; height: 31px; display: grid; flex: 0 0 31px; place-items: center; border-radius: 50%; color: #24362f; background: #cadbd2; font-size: .66rem; font-weight: 850; }
.sidebar-foot strong, .sidebar-foot small { display: block; }
.sidebar-foot strong { color: #f1f4f1; font-size: .66rem; }
.sidebar-foot small { margin-top: 3px; color: #84978f; font-size: .55rem; }

.app-header {
  min-height: 72px;
  margin-left: 238px;
  padding: 0 27px;
  border-color: var(--border);
  background: rgba(250, 248, 243, .96);
  box-shadow: none;
}
.header-context { display: flex; min-width: 0; align-items: center; gap: 9px; color: var(--muted); font-size: .72rem; }
.header-context > strong { color: var(--text); font-size: .78rem; }
.header-context .run-identity { max-width: 38vw; margin: 0; }
.header-actions { gap: 8px; }
.header-actions .button { min-height: 35px; padding: 7px 12px; font-size: .7rem; }
.primary-button { background: #31584d; }
.primary-button:hover { background: #284b41; }
.app-main { margin-left: 238px; padding: 0; }

.overview-strip {
  min-height: 87px;
  grid-template-columns: minmax(205px, .78fr) minmax(660px, 3.22fr);
  gap: 18px;
  max-width: none;
  margin: 0;
  padding: 14px 27px;
  border-bottom: 1px solid var(--border);
  background: #faf8f3;
}
.overview-title { padding: 0; }
.overview-title .eyebrow { margin-bottom: 4px; }
.overview-title h2 { font-family: Georgia, "Times New Roman", serif; font-size: 1.05rem; font-weight: 600; }
.overview-title > p:last-child { margin: 4px 0 0; color: var(--muted); font-size: .58rem; }
.overview-health { color: #6d5945 !important; font-weight: 750; }
.summary-grid { border: 0; border-radius: 0; background: transparent; box-shadow: none; }
.summary-card { min-height: 51px; padding: 8px 11px; border: 0; border-left: 1px solid var(--border); }
.summary-card span { font-size: .57rem; font-weight: 750; letter-spacing: .05em; text-transform: uppercase; }
.summary-card strong { margin-top: 5px; font-size: 1rem; }

.investigation-workspace {
  display: grid;
  grid-template-columns: minmax(310px, 345px) minmax(500px, 1fr) 320px;
  min-height: calc(100vh - 159px);
  background: #faf8f3;
}
.finding-queue-panel { min-width: 0; padding: 21px 15px 24px 25px; border-right: 1px solid var(--border); background: #f1eee7; }
.queue-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 12px; }
.queue-heading h2 { font-family: Georgia, "Times New Roman", serif; font-size: 1.18rem; font-weight: 600; }
.queue-count { padding-bottom: 2px; color: var(--muted); font-size: .59rem; white-space: nowrap; }
.queue-controls { margin: 15px 0 12px; }
.finding-search-box { margin: 0 0 9px; background: #faf9f5; }
.queue-filter-row { display: grid; grid-template-columns: 1fr 1fr; gap: 7px; }
.queue-filter-row label { display: block; margin: 0 0 4px 2px; color: var(--muted); font-size: .56rem; font-weight: 700; }
.queue-filter-row select { width: 100%; min-height: 32px; border-color: #d7d1c7; border-radius: 7px; background-color: #faf9f5; font-size: .65rem; }
.finding-queue { display: grid; gap: 7px; max-height: calc(100vh - 328px); overflow: auto; padding: 1px 3px 16px 0; overscroll-behavior: contain; }
.disposition-panel { margin: 0 3px 10px 0; border: 1px solid #d8d0c2; border-radius: 8px; background: #fffaf0; }
.disposition-panel > summary { display: flex; align-items: center; gap: 8px; padding: 8px 10px; cursor: pointer; color: #675746; font-size: .57rem; font-weight: 800; list-style: none; }
.disposition-panel > summary::-webkit-details-marker { display: none; }
.disposition-panel > summary .count-badge { margin-left: auto; }
.disposition-list { display: grid; gap: 6px; padding: 0 10px 10px; }
.disposition-item { margin: 0; color: #766a5c; font-size: .54rem; line-height: 1.45; overflow-wrap: anywhere; }
.queue-finding {
  position: relative; width: 100%; display: grid; grid-template-columns: 21px minmax(0, 1fr); gap: 8px;
  min-height: 89px; padding: 13px 11px; border: 1px solid transparent; border-radius: 10px;
  color: var(--text-soft); background: transparent; text-align: left;
}
.queue-finding:hover { border-color: #d8d2c8; background: rgba(255,255,255,.55); }
.queue-finding.selected { border-color: #c9d2cb; background: #fff; box-shadow: 0 5px 18px rgba(44, 62, 53, .065); }
.queue-finding-ordinal { color: #9ba29e; font-family: Georgia, serif; font-size: .63rem; }
.queue-finding-copy { min-width: 0; }
.queue-finding-title { display: block; padding-right: 43px; color: #34413c; font-size: .67rem; font-weight: 760; line-height: 1.42; }
.queue-finding-severity { position: absolute; top: 12px; right: 10px; color: #a3612a; font-size: .54rem; font-weight: 850; letter-spacing: .04em; text-transform: uppercase; }
.queue-finding-severity.high { color: #b14740; }
.queue-finding-severity.low, .queue-finding-severity.info { color: #6f7974; }
.queue-finding-path { display: block; margin-top: 5px; overflow: hidden; color: #8b928e; font-size: .56rem; text-overflow: ellipsis; white-space: nowrap; }
.queue-finding-meta { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 7px; color: #959b97; font-size: .53rem; }
.queue-finding-group-note { display: block; margin-top: 7px; color: #68726d; font-size: .56rem; line-height: 1.4; }
.queue-empty { padding: 28px 15px; border: 1px dashed #cec8bd; border-radius: 10px; color: var(--muted); text-align: center; font-size: .7rem; }

.investigation-brief { min-width: 0; padding: 24px 25px 32px; overflow: auto; background: #faf8f3; }
.brief-empty { min-height: 460px; display: grid; place-items: center; align-content: center; color: var(--muted); text-align: center; }
.brief-empty > span { width: 46px; height: 46px; display: grid; place-items: center; border-radius: 50%; color: #31584d; background: #e7efeb; font-size: 1.2rem; }
.brief-empty h2 { margin-top: 14px; font-family: Georgia, serif; color: var(--text); }
.brief-empty p { max-width: 330px; margin-top: 7px; font-size: .72rem; }
.brief-heading { display: flex; align-items: flex-start; gap: 11px; }
.brief-ordinal { width: 33px; height: 33px; display: grid; flex: 0 0 33px; place-items: center; border-radius: 50%; color: #fff; background: #c5743b; font-family: Georgia, serif; font-size: .68rem; }
.brief-kicker { display: flex; align-items: center; gap: 8px; margin-bottom: 5px; color: var(--muted); font-size: .57rem; }
.severity-chip { padding: 4px 7px; border-radius: 999px; color: #9a5725; background: #fff0e4; font-size: .53rem; font-weight: 850; letter-spacing: .04em; text-transform: uppercase; }
.severity-chip.high { color: #a93e38; background: #fbe9e6; }
.severity-chip.low, .severity-chip.info { color: #5f6b66; background: #eceeea; }
.brief-heading h2 { max-width: 720px; margin: 0; font-family: Georgia, "Times New Roman", serif; font-size: clamp(1.35rem, 2vw, 1.75rem); font-weight: 600; line-height: 1.12; letter-spacing: -.018em; }
.brief-anchor { margin: 8px 0 0; color: #78827d; font-size: .58rem; }
.brief-badges { display: flex; flex-wrap: wrap; gap: 6px; margin: 14px 0 0 44px; }
.brief-badges span { padding: 5px 8px; border-radius: 6px; color: #68736e; background: #eeebe4; font-size: .54rem; font-weight: 700; }
.brief-story { margin-top: 20px; }
.story-row { display: grid; grid-template-columns: 74px minmax(0, 1fr); gap: 12px; margin: 11px 0; }
.story-row > h3 { padding-top: 12px; color: #8a928e; font-size: .55rem; font-weight: 850; letter-spacing: .1em; text-transform: uppercase; }
.story-card { padding: 14px; border: 1px solid #ded8ce; border-radius: 10px; background: #fff; }
.story-card > strong, .story-card-heading strong { display: block; color: #314039; font-size: .67rem; }
.story-card > p { margin: 7px 0 0; color: #66716c; font-size: .61rem; line-height: 1.58; }
.story-card-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.story-card-heading span { color: #8c948f; font-size: .55rem; }
.evidence-card { color: #dfe8e3; border-color: #263b34; background: #263b34; }
.evidence-card .story-card-heading strong { color: #fff; }
.evidence-card .story-card-heading span { color: #a9b8b2; }
.evidence-card > summary { display: flex; align-items: center; justify-content: space-between; gap: 10px; cursor: pointer; list-style: none; }
.evidence-card > summary::-webkit-details-marker { display: none; }
.evidence-card > summary::after { color: #a9b8b2; content: "＋"; }
.evidence-card[open] > summary::after { content: "−"; }
.evidence-card > summary strong { color: #fff; font-size: .67rem; }
.evidence-card > summary span { margin-left: auto; color: #a9b8b2; font-size: .55rem; }
.evidence-card[open] .brief-evidence-list { margin-top: 10px; }
.refutation-card { border-color: #d8c8ad; background: #fffbf3; }
.brief-evidence-list { display: grid; gap: 7px; margin-top: 10px; }
.brief-evidence-item { padding: 9px 10px; border-radius: 7px; background: #1b2c27; }
.brief-evidence-item strong { display: block; overflow-wrap: anywhere; color: #e1ebe6; font-size: .56rem; }
.brief-evidence-item p { margin: 5px 0 0; color: #aebbb6; font-size: .54rem; line-height: 1.45; }
.brief-evidence-more { color: #b7c4bf; font-size: .56rem; }
.impact-card > strong { color: #33423c; }
.impact-metrics { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 11px 0 0; }
.impact-metrics div { min-width: 0; padding: 9px; border-radius: 7px; background: #f5f2ec; }
.impact-metrics dt { color: #969c98; font-size: .49rem; letter-spacing: .06em; text-transform: uppercase; }
.impact-metrics dd { margin: 5px 0 0; overflow-wrap: anywhere; color: #405049; font-size: .58rem; font-weight: 760; }
.brief-limitations { padding-top: 9px; border-top: 1px solid #ebe7df; color: #7e8782 !important; }
.next-action-card { display: flex; align-items: center; gap: 12px; padding: 13px 14px; border: 1px solid #c9d6cf; border-radius: 10px; background: #edf4f0; }
.next-action-card > p { flex: 1; margin: 0; color: #52625b; font-size: .62rem; line-height: 1.5; }
.next-action-buttons { display: flex; gap: 7px; }
.next-action-buttons .button { min-height: 33px; padding: 6px 9px; font-size: .58rem; white-space: nowrap; }

.review-context { min-width: 0; padding: 23px 18px 28px; border-left: 1px solid var(--border); background: #f3f0e9; }
.context-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 10px; }
.context-heading h2 { font-family: Georgia, "Times New Roman", serif; font-size: 1.05rem; font-weight: 600; }
.confidence-badge { padding: 5px 8px; border-radius: 999px; color: #4e655c; background: #e4ede8; font-size: .55rem; font-weight: 800; text-transform: capitalize; }
.context-section { margin-top: 20px; }
.context-section > h3, .context-section-heading h3 { margin: 0; color: #66736d; font-size: .54rem; font-weight: 850; letter-spacing: .09em; text-transform: uppercase; }
.context-section-heading { display: flex; align-items: center; justify-content: space-between; gap: 9px; margin-bottom: 9px; }
.context-section-heading span { color: #8c948f; font-size: .52rem; }
.calibration-card, .brief-health-card, .handoff-section { padding: 12px; border: 1px solid #ddd7cd; border-radius: 9px; background: #fff; }
.calibration-card > strong { display: block; font-size: .64rem; }
.calibration-card > p, .brief-health-card > p, .handoff-section > p { margin: 7px 0 0; color: #76807b; font-size: .54rem; line-height: 1.5; }
.calibration-scale { display: flex; gap: 4px; margin: 10px 0 8px; }
.calibration-scale i { flex: 1; height: 5px; border-radius: 3px; background: #e0dfda; }
.calibration-scale i.on { background: #c87942; }
.brief-artifacts, .brief-contexts { display: grid; gap: 7px; }
.brief-artifact, .brief-context { padding: 9px 10px; border: 1px solid #dfd9cf; border-radius: 8px; background: #fbfaf6; }
.brief-artifact strong, .brief-context strong { display: block; overflow-wrap: anywhere; color: #43514b; font-size: .54rem; }
.brief-artifact span, .brief-context span { display: block; margin-top: 4px; color: #909792; font-size: .5rem; line-height: 1.4; }
.brief-health-card { display: grid; grid-template-columns: 1fr 1fr; gap: 9px; }
.brief-health-card > div { padding: 8px; border-radius: 7px; background: #f6f4ee; }
.brief-health-card span, .brief-health-card strong { display: block; }
.brief-health-card span { color: #929995; font-size: .49rem; text-transform: uppercase; }
.brief-health-card strong { margin-top: 5px; color: #3f4e47; font-size: .59rem; }
.brief-health-card > p, .brief-health-card > button { grid-column: 1 / -1; }
.text-button { width: max-content; padding: 0; border: 0; color: #31584d; background: transparent; font-size: .56rem; font-weight: 800; text-decoration: underline; }
.handoff-section { background: #fff; }
.handoff-section .full-button { min-height: 34px; margin: 11px 0 0; font-size: .58rem; }
.handoff-status { min-height: 1em; }

.analysis-health-panel, .records-panel { max-width: none; margin: 18px 22px; }
.workspace-grid { max-width: none; margin: 18px 22px 24px; }
.analysis-health-panel .analysis-health-heading h2, .records-heading h2, .panel-heading h2, .graph-header h2 { font-family: Georgia, "Times New Roman", serif; font-weight: 600; }
.verification-dialog { width: min(520px, calc(100vw - 32px)); padding: 0; border: 1px solid var(--border-strong); border-radius: 14px; color: var(--text); background: #fffefa; box-shadow: var(--shadow-md); }
.verification-dialog::backdrop { background: rgba(22, 31, 27, .48); backdrop-filter: blur(3px); }
.verification-dialog form { padding: 21px; }
.dialog-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
.dialog-heading h2 { font-family: Georgia, serif; font-size: 1.18rem; font-weight: 600; }
.verification-dialog > form > p { margin: 14px 0; color: var(--text-soft); font-size: .72rem; line-height: 1.55; }
.verification-dialog code { display: block; padding: 12px; border-radius: 8px; color: #dce7e1; background: #203630; font-size: .68rem; overflow-wrap: anywhere; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
footer { margin-left: 238px; border-top: 1px solid var(--border); background: #f3f0e8; }

@media (max-width: 1240px) {
  .app-sidebar { width: 80px; padding: 22px 13px; align-items: center; }
  .sidebar-brand > span:last-child, .sidebar-label, .workspace-nav-item > span:nth-child(2), .workspace-nav-item strong, .saved-views, .sidebar-target, .sidebar-foot > div { display: none; }
  .sidebar-brand { padding-bottom: 24px; }
  .workspace-navigation { width: 100%; }
  .workspace-nav-item { grid-template-columns: 1fr; justify-items: center; padding: 0; font-size: 1rem; }
  .workspace-nav-item.active { box-shadow: inset 3px 0 #d8ef70; }
  .sidebar-foot { justify-content: center; width: 100%; }
  .app-header, .app-main, footer { margin-left: 80px; }
  .investigation-workspace { grid-template-columns: 315px minmax(470px, 1fr); }
  .review-context { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 18px; border-top: 1px solid var(--border); border-left: 0; }
  .context-heading { grid-column: 1 / -1; }
}
@media (max-width: 860px) {
  .app-sidebar { position: relative; width: 100%; min-height: auto; flex-direction: row; align-items: center; gap: 12px; padding: 10px 14px; }
  .sidebar-brand { padding: 0; }
  .workspace-navigation { display: flex; width: auto; flex: 1; gap: 4px; overflow-x: auto; }
  .workspace-nav-item { width: auto; min-width: 44px; padding: 0 12px; }
  .workspace-nav-item.active { box-shadow: inset 0 -3px #d8ef70; }
  .sidebar-foot { width: auto; margin: 0; padding: 0; border: 0; }
  .app-header, .app-main, footer { margin-left: 0; }
  .app-header { top: 0; padding: 0 14px; }
  .header-actions .status, .header-actions .download { display: none; }
  .overview-strip { grid-template-columns: 1fr; padding: 13px 16px; }
  .overview-title { display: block; }
  .summary-grid { grid-template-columns: repeat(3, 1fr); }
  .summary-card:nth-child(4) { border-left: 0; }
  .investigation-workspace { grid-template-columns: 300px minmax(0, 1fr); min-height: auto; }
  .review-context { grid-template-columns: 1fr 1fr; }
  .brief-heading h2 { font-size: 1.28rem; }
  .story-row { grid-template-columns: 62px minmax(0, 1fr); }
  .next-action-card { align-items: stretch; flex-direction: column; }
  .next-action-buttons { justify-content: flex-end; }
}
@media (max-width: 680px) {
  .app-header { min-height: 62px; }
  .header-context > span, .header-context .run-identity, #print-review { display: none; }
  .header-actions { margin-left: auto; }
  .overview-strip { display: block; }
  .overview-title { margin-bottom: 12px; }
  .summary-grid { grid-template-columns: repeat(2, 1fr); }
  .summary-card:nth-child(odd) { border-left: 0; }
  .summary-card:nth-child(even) { border-left: 1px solid var(--border); }
  .investigation-workspace { display: block; }
  .finding-queue-panel { padding: 18px 14px; border-right: 0; border-bottom: 1px solid var(--border); }
  .finding-queue { max-height: 330px; }
  .investigation-brief { padding: 21px 14px 28px; }
  .brief-badges { margin-left: 0; }
  .story-row { display: block; }
  .story-row > h3 { padding: 0; margin: 17px 0 7px; }
  .impact-metrics { grid-template-columns: 1fr; }
  .next-action-buttons { display: grid; grid-template-columns: 1fr; }
  .review-context { display: block; padding: 21px 14px; }
  .workspace-grid, .analysis-health-panel, .records-panel { margin: 12px; }
}
@media print {
  .app-sidebar, .app-header, .overview-strip, .finding-queue-panel, .review-context, footer, .next-action-buttons { display: none !important; }
  .app-main { margin: 0; }
  .investigation-workspace { display: block; min-height: auto; }
  .investigation-brief { overflow: visible; padding: 0; }
  .story-card, .next-action-card { break-inside: avoid; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; }
}
`;

export const VIEWER_APP_JAVASCRIPT = `'use strict';
(function () {
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var TABLE_LIMIT = 500;
  var RELATIONSHIP_TABLE_LIMIT = 160;
  var FILE_LIST_LIMIT = 180;
  var GRAPH_NODE_LIMIT = 72;
  var GRAPH_EDGE_LIMIT = 240;
  var ARCHITECTURE_NODE_LIMIT = 34;
  var FINDING_NODE_LIMIT = 34;
  var DATA_CONTRACT_SUBJECT_LIMIT = 22;
  var FINDING_QUEUE_LIMIT = 180;
  var BRIEF_EVIDENCE_LIMIT = 4;
  var BRIEF_CONTEXT_LIMIT = 4;
  var BRIEF_ARTIFACT_LIMIT = 5;
  var CARD_WIDTH = 220;
  var CARD_HEIGHT = 86;

  function required(id) {
    var element = document.getElementById(id);
    if (!element) throw new Error('Viewer element is missing: ' + id);
    return element;
  }

  function setText(id, value) {
    required(id).textContent = value === undefined || value === null ? '' : String(value);
  }

  function formatNumber(value) {
    return Number(value).toLocaleString('en-US');
  }

  function formatBytes(value) {
    var bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    var amount = bytes / Math.pow(1024, index);
    return (index === 0 ? String(Math.round(amount)) : amount.toFixed(amount >= 10 ? 1 : 2)) + ' ' + units[index];
  }

  function formatRatio(value) {
    if (!value || !Number.isSafeInteger(value.numerator) || !Number.isSafeInteger(value.denominator)) return 'Not recorded';
    var ratio = formatNumber(value.numerator) + ' / ' + formatNumber(value.denominator);
    if (value.denominator === 0) return ratio + ' (n/a)';
    return ratio + ' (' + String(Math.round(value.numerator * 1000 / value.denominator) / 10) + '%)';
  }

  function markdownCode(value) {
    var normalized = String(value === undefined || value === null ? '' : value)
      .replace(/[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200e\\u200f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]/g, function (character) {
        return '\\\\u{' + character.codePointAt(0).toString(16).toUpperCase() + '}';
      })
      .replace(/\\s+/g, ' ')
      .trim();
    var runs = normalized.match(/\\x60+/g) || [];
    var longest = runs.reduce(function (maximum, run) { return Math.max(maximum, run.length); }, 0);
    var fence = String.fromCharCode(96).repeat(longest + 1);
    var padding = normalized.startsWith(String.fromCharCode(96)) || normalized.endsWith(String.fromCharCode(96)) ? ' ' : '';
    return fence + padding + normalized + padding + fence;
  }

  function basename(value) {
    var parts = String(value).split('/');
    return parts[parts.length - 1] || String(value);
  }

  function dirname(value) {
    var parts = String(value).split('/');
    parts.pop();
    return parts.join('/') || '(root)';
  }

  function truncate(value, limit) {
    var text = String(value);
    if (text.length <= limit) return text;
    if (limit < 8) return text.slice(0, limit);
    var left = Math.ceil((limit - 1) * .58);
    var right = limit - left - 1;
    return text.slice(0, left) + '…' + text.slice(text.length - right);
  }

  function fixedClass(value, allowed, fallback) {
    return allowed.indexOf(value) >= 0 ? value : fallback;
  }

  function appendCells(row, values) {
    values.forEach(function (value) {
      var cell = document.createElement('td');
      cell.textContent = value === undefined || value === null ? '' : String(value);
      row.append(cell);
    });
  }

  function emptyRow(body, columns, message) {
    var row = document.createElement('tr');
    var cell = document.createElement('td');
    cell.colSpan = columns;
    cell.textContent = message;
    row.append(cell);
    body.append(row);
  }

  function relationshipLocation(relationship) {
    return relationship.fromPath + ':' + String(relationship.location.line) + ':' + String(relationship.location.column);
  }

  function relationshipType(relationship) {
    return relationship.type + (relationship.typeOnly ? ' [type-only]' : '');
  }

  function validDataContractSubject(subject) {
    if (!subject || typeof subject !== 'object' || subject.kind !== 'data-contract') return undefined;
    var dimensions = ['column-presence', 'column-mapping', 'type-family', 'nullability', 'default', 'enum-members'];
    if (typeof subject.table !== 'string' || !subject.table || typeof subject.column !== 'string' || !subject.column || dimensions.indexOf(subject.dimension) < 0) return undefined;
    var modelStorage = ['prisma', 'sequelize'].indexOf(subject.model) >= 0 &&
      ['sql', 'sequelize-migration'].indexOf(subject.storage) >= 0;
    var provisioningPath = subject.dimension === 'enum-members' &&
      subject.comparison === 'provisioning-path' &&
      subject.migration === 'sequelize-migration' && subject.bootstrap === 'sql-bootstrap';
    if (!modelStorage && !provisioningPath) return undefined;
    return subject;
  }

  function structuredDataContractSubject(finding) {
    return validDataContractSubject(finding && finding.subject);
  }

  function dataContractEndpoints(subject) {
    if (subject.comparison === 'provisioning-path') {
      return {
        comparison: 'provisioning-path',
        left: subject.migration,
        right: subject.bootstrap,
        leftLabel: 'Sequelize migration',
        rightLabel: 'bootstrap SQL',
        leftEdgeLabel: 'migration path declares',
        rightEdgeLabel: 'compared with bootstrap SQL'
      };
    }
    return {
      comparison: 'model-storage',
      left: subject.model,
      right: subject.storage,
      leftLabel: subject.model === 'prisma' ? 'Prisma model' : 'Sequelize model',
      rightLabel: subject.storage === 'sql' ? 'SQL evidence' : 'migration evidence',
      leftEdgeLabel: subject.model + ' declares',
      rightEdgeLabel: subject.storage === 'sql' ? 'compared with SQL' : 'checked in migration'
    };
  }

  function dataContractSubjectEntries(finding) {
    var subject = structuredDataContractSubject(finding);
    if (subject) {
      return [{
        finding: finding,
        subject: subject,
        evidence: finding.evidence,
        path: finding.path,
        relatedPaths: finding.relatedPaths
      }];
    }
    if (!Array.isArray(finding && finding.instances)) return [];
    return finding.instances.flatMap(function (instance) {
      var instanceSubject = validDataContractSubject(instance.subject);
      if (!instanceSubject) return [];
      return [{
        finding: finding,
        subject: instanceSubject,
        evidence: instance.evidence,
        path: instance.path,
        relatedPaths: instance.relatedPaths
      }];
    });
  }

  function findingKind(finding) {
    return finding.kind || 'legacy-not-recorded';
  }

  function findingInstanceCount(finding) {
    return Number.isSafeInteger(finding.instanceCount) && finding.instanceCount > 0 ? finding.instanceCount : 1;
  }

  function findingImpactSummary(finding) {
    var impact = finding.impactContext;
    if (!impact) return 'Legacy finding: static impact context was not recorded.';
    var context = [impact.reachability];
    if (impact.scope) context.push(impact.scope + ' scope');
    if (impact.lifecycle) context.push(impact.lifecycle + ' lifecycle');
    context.push('feature gate ' + impact.featureGate);
    if (impact.entrypoints.length) context.push('entrypoints: ' + impact.entrypoints.join(', '));
    if (impact.mountedSurfaces.length) context.push('surfaces: ' + impact.mountedSurfaces.join(', '));
    context.push(impact.summary);
    context.push('Limitations: ' + impact.limitations.join(' '));
    return context.join(' · ');
  }

  function findingMechanism(finding) {
    return finding.mechanism || 'Not recorded';
  }

  function findingCalibrationSummary(finding) {
    var calibration = finding.severityCalibration;
    if (!calibration) return 'Legacy: calibration not recorded';
    return 'detector ' + calibration.detectorSeverity + ' → reported ' + finding.severity +
      ' · ceiling ' + calibration.ceiling + ' · ' + calibration.basis +
      ' · runtime reachability ' + calibration.runtimeReachability;
  }

  function mappingContextSummary(context) {
    return [
      context.sourceKind,
      context.composePath,
      context.service,
      context.hostRoot + ' → ' + context.containerRoot,
      context.buildContext || '',
      context.dockerfile || '',
      context.workingDirectory || ''
    ].join(' ');
  }

  function findingSearchText(finding) {
    var values = [
      finding.title,
      finding.description,
      finding.refutationCondition,
      finding.reviewId,
      finding.reviewPriority && finding.reviewPriority.band,
      finding.category,
      finding.ruleId,
      finding.severity,
      finding.confidence,
      findingMechanism(finding),
      findingCalibrationSummary(finding),
      finding.severityCalibration && finding.severityCalibration.rationale,
      finding.path,
      finding.relatedPaths.join(' '),
      finding.signals.join(' ')
    ];
    (finding.mappingContexts || []).forEach(function (context) { values.push(mappingContextSummary(context)); });
    (finding.instances || []).forEach(function (instance) {
      values.push(instance.path, instance.relatedPaths.join(' '), instance.signals.join(' '));
    });
    return values.filter(Boolean).join(' ').toLowerCase();
  }

  function severityRank(value) {
    return { high: 4, medium: 3, low: 2, info: 1 }[value] || 0;
  }

  function priorityBandLabel(value) {
    return {
      'production-ungated': 'Production · reachable · ungated',
      'production-gate-unknown': 'Production · gate unknown',
      'production-gated': 'Production · gated',
      cli: 'CLI / operator surface',
      'build-migration-seeder': 'Build / migration / seeder',
      'reachability-incomplete': 'Reachability incomplete',
      test: 'Test / fixture surface',
      inactive: 'Inactive / unreachable'
    }[value] || 'Legacy priority not recorded';
  }

  function baseReviewId(finding) {
    return String(finding.reviewId || '').replace(/:occurrence:[1-9][0-9]*$/, '');
  }

  function compareActionability(left, right) {
    var leftPriority = left.reviewPriority;
    var rightPriority = right.reviewPriority;
    if (leftPriority && rightPriority) {
      return leftPriority.severityRank - rightPriority.severityRank ||
        leftPriority.impactRank - rightPriority.impactRank ||
        leftPriority.confidenceRank - rightPriority.confidenceRank ||
        rightPriority.instanceCount - leftPriority.instanceCount ||
        baseReviewId(left).localeCompare(baseReviewId(right)) ||
        String(left.id).localeCompare(String(right.id));
    }
    return severityRank(right.severity) - severityRank(left.severity) ||
      findingInstanceCount(right) - findingInstanceCount(left) ||
      baseReviewId(left).localeCompare(baseReviewId(right)) ||
      String(left.id).localeCompare(String(right.id));
  }

  function compareFindings(left, right, sort) {
    if (sort === 'path') {
      return String(left.path || left.relatedPaths[0] || '').localeCompare(String(right.path || right.relatedPaths[0] || '')) ||
        severityRank(right.severity) - severityRank(left.severity) || left.title.localeCompare(right.title);
    }
    if (sort === 'mechanism') {
      return findingMechanism(left).localeCompare(findingMechanism(right)) ||
        severityRank(right.severity) - severityRank(left.severity) || left.title.localeCompare(right.title);
    }
    return compareActionability(left, right) || left.title.localeCompare(right.title);
  }

  function findingWorkGroupKey(finding) {
    return [
      finding.ruleId,
      findingMechanism(finding),
      finding.category,
      finding.reviewPriority && finding.reviewPriority.band,
      finding.severity,
      finding.confidence
    ].map(function (value) { return value || ''; }).join('\\u0000');
  }

  // The sort value is passed in rather than read from the render-local control,
  // because this helper lives at module scope and cannot see render bindings.
  function findingQueueGroups(findings, sort) {
    var groups = new Map();
    findings.forEach(function (finding) {
      var key = findingWorkGroupKey(finding);
      var group = groups.get(key);
      if (!group) {
        group = {
          key: key,
          representative: finding,
          findings: [],
          totalInstances: 0,
          anchors: new Set(),
          contextCount: 0
        };
        groups.set(key, group);
      }
      group.findings.push(finding);
      group.totalInstances += findingInstanceCount(finding);
      group.contextCount += (finding.mappingContexts || []).length;
      var anchor = recordAnchor(finding);
      if (anchor) group.anchors.add(anchor);
      (finding.instances || []).slice(0, 4).forEach(function (instance) {
        if (instance.path) group.anchors.add(instance.path);
      });
      if (compareFindings(finding, group.representative, sort) < 0) group.representative = finding;
    });
    return Array.from(groups.values()).sort(function (left, right) {
      return compareFindings(left.representative, right.representative, sort) ||
        right.findings.length - left.findings.length ||
        left.key.localeCompare(right.key);
    });
  }

  function queueGroupLabel(group) {
    var count = group.findings.length;
    if (count === 1) return group.representative.title;
    return group.representative.title + ' (' + formatNumber(count) + ' findings)';
  }

  function queueGroupNote(group) {
    if (group.findings.length === 1) return '';
    var anchors = Array.from(group.anchors).slice(0, 3);
    var remainder = Math.max(0, group.anchors.size - anchors.length);
    return formatNumber(group.findings.length) + ' findings share this rule, mechanism, severity, confidence, and fix shape. ' +
      'Representative anchors: ' + (anchors.length ? anchors.join(', ') : 'none recorded') +
      (remainder ? ', +' + formatNumber(remainder) + ' more' : '') + '.';
  }

  function evidenceLocation(evidence) {
    if (!evidence.path) return 'No path';
    var location = evidence.path;
    if (Number.isSafeInteger(evidence.line)) location += ':' + String(evidence.line);
    if (Number.isSafeInteger(evidence.column)) location += ':' + String(evidence.column);
    return location;
  }

  // Module scope on purpose. This is a pure helper used both by render() and by
  // findingQueueGroups(), which is a module-scope sibling of render(); declaring
  // it inside render() puts it out of scope for the queue grouping path.
  function recordAnchor(record) {
    var anchor = record.path || (record.relatedPaths && record.relatedPaths[0]) || 'No path';
    if (record.location && Number.isSafeInteger(record.location.line)) {
      anchor += ':' + String(record.location.line);
      if (Number.isSafeInteger(record.location.column)) anchor += ':' + String(record.location.column);
    }
    return anchor;
  }

  function dimensionLabel(value) {
    return {
      'column-presence': 'column presence',
      'column-mapping': 'column mapping',
      'type-family': 'type family',
      'nullability': 'nullability',
      'default': 'default',
      'enum-members': 'enum members'
    }[value] || 'contract';
  }

  function svgElement(name, attributes) {
    var element = document.createElementNS(SVG_NS, name);
    Object.keys(attributes || {}).forEach(function (key) {
      element.setAttribute(key, String(attributes[key]));
    });
    return element;
  }

  function svgText(parent, attributes, value) {
    var element = svgElement('text', attributes);
    element.textContent = String(value);
    parent.append(element);
    return element;
  }

  function setStatus(message, kind) {
    var status = required('viewer-status');
    status.className = 'status ' + fixedClass(kind, ['loading', 'ready', 'error'], 'ready');
    var dot = document.createElement('span');
    dot.className = 'status-dot';
    dot.setAttribute('aria-hidden', 'true');
    status.replaceChildren(dot, document.createTextNode(message));
  }

  function renderCountList(id, counts, limit) {
    var list = required(id);
    list.replaceChildren();
    var entries = Object.keys(counts).map(function (key) { return [key, counts[key]]; });
    entries.sort(function (left, right) {
      return Number(right[1]) - Number(left[1]) || String(left[0]).localeCompare(String(right[0]));
    });
    entries.slice(0, limit).forEach(function (entry) {
      var item = document.createElement('li');
      var label = document.createElement('span');
      var count = document.createElement('strong');
      label.textContent = entry[0];
      count.textContent = formatNumber(entry[1]);
      item.append(label, count);
      list.append(item);
    });
    if (entries.length > limit) {
      var remainder = document.createElement('li');
      remainder.textContent = '+' + String(entries.length - limit) + ' more';
      list.append(remainder);
    }
    if (!entries.length) {
      var empty = document.createElement('li');
      empty.textContent = 'None';
      list.append(empty);
    }
  }

  function populateSelect(id, values) {
    var select = required(id);
    values.forEach(function (value) {
      var option = document.createElement('option');
      option.value = value;
      option.textContent = value;
      select.append(option);
    });
  }

  function render(data) {
    var filesById = new Map(data.census.files.map(function (file) { return [file.id, file]; }));
    var filesByPath = new Map(data.census.files.map(function (file) { return [file.path, file]; }));
    var graphNodesById = new Map(data.dependencyGraph.nodes.map(function (node) { return [node.id, node]; }));
    var findingsById = new Map(data.findings.map(function (finding) { return [finding.id, finding]; }));
    var edgesByNode = new Map();
    var fileSearchText = new Map();
    var graphCanvas = required('graph-canvas');
    var graphViewport = required('graph-viewport');
    var graphNodeLayer = required('graph-node-layer');
    var graphEdgeLayer = required('graph-edge-layer');
    var fileFilter = required('file-filter');
    var kindFilter = required('kind-filter');
    var languageFilter = required('language-filter');
    var relationshipFilter = required('relationship-filter');
    var graphDepth = required('graph-depth');
    var workspaceGrid = required('workspace-grid');
    var graphFocusButton = required('toggle-graph-focus');
    var findingFilter = required('finding-filter');
    var findingSeverityFilter = required('finding-severity-filter');
    var findingSort = required('finding-sort');
    var diagnosticFilter = required('diagnostic-filter');
    var diagnosticSeverityFilter = required('diagnostic-severity-filter');

    data.census.files.forEach(function (file) {
      fileSearchText.set(file.id, [
        file.path,
        file.kind,
        file.language,
        file.symbols.join(' '),
        file.environmentVariables.join(' ')
      ].join(' ').toLowerCase());
    });
    data.dependencyGraph.edges.forEach(function (edge) {
      var sourceEdges = edgesByNode.get(edge.source) || [];
      sourceEdges.push(edge);
      edgesByNode.set(edge.source, sourceEdges);
      if (edge.target !== edge.source) {
        var targetEdges = edgesByNode.get(edge.target) || [];
        targetEdges.push(edge);
        edgesByNode.set(edge.target, targetEdges);
      }
    });

    function compareFileRelevance(left, right) {
      var leftDegree = left.incoming.length + left.outgoing.length;
      var rightDegree = right.incoming.length + right.outgoing.length;
      if (rightDegree !== leftDegree) return rightDegree - leftDegree;
      if (left.path < right.path) return -1;
      if (left.path > right.path) return 1;
      return 0;
    }

    var initialFiles = data.census.files.slice().sort(compareFileRelevance);
    var initialFindings = data.findings.slice().sort(function (left, right) {
      return compareFindings(left, right, 'severity');
    });
    var state = {
      selectedFileId: initialFiles.length ? initialFiles[0].id : undefined,
      selectedFindingId: initialFindings.length ? initialFindings[0].id : undefined,
      graphSelectionActive: false,
      graphMode: 'architecture',
      workspaceView: 'investigation',
      filteredFiles: data.census.files.slice(),
      currentGraph: { nodes: [], edges: [], mode: 'architecture', totalNodes: 0, totalEdges: 0, limited: false },
      positions: new Map(),
      graphBounds: { x: 0, y: 0, width: 1, height: 1 },
      transform: { x: 0, y: 0, scale: 1 },
      filterFrame: 0,
      findingFilterFrame: 0,
      diagnosticFilterFrame: 0,
      drag: undefined
    };

    setText('run-identity', data.run.targetId + ' · ' + data.run.runId + ' · ' + data.run.snapshotId);
    setText('sidebar-target-id', data.run.targetId);
    setText('sidebar-file-count', formatNumber(data.summary.files));
    setText('sidebar-finding-count', formatNumber(data.summary.findings));
    setText('summary-files', formatNumber(data.summary.files));
    setText('summary-relationships', formatNumber(data.summary.relationships));
    setText('summary-resolved', formatNumber(data.summary.resolvedRelationships));
    setText('summary-findings', formatNumber(data.summary.findings));
    setText('summary-diagnostics', formatNumber(data.summary.diagnostics));
    setText('summary-bytes', formatBytes(data.summary.totalBytes));
    renderCountList('kind-counts', data.census.byKind, 6);
    renderCountList('language-counts', data.census.byLanguage, 6);
    populateSelect('kind-filter', Object.keys(data.census.byKind).sort());
    populateSelect('language-filter', Object.keys(data.census.byLanguage).sort());

    function incompleteReasonDiagnostics(ruleId) {
      var codesByRule = {
        'contract/seeded-dictionary-id-coupling-v1': [
          'OPERATIONAL_SEED_DICTIONARY_SOURCE_REQUIRED',
          'OPERATIONAL_SEED_DICTIONARY_SOURCE_UNRESOLVED',
          'OPERATIONAL_SEED_DICTIONARY_INCOMPLETE',
          'OPERATIONAL_SEED_DICTIONARY_UNAVAILABLE'
        ],
        'latent/accidental-protection-v1': [
          'OPERATIONAL_ACCIDENTAL_PROTECTION_INPUT_INCOMPLETE',
          'OPERATIONAL_SOURCE_PARSE_INCOMPLETE'
        ]
      };
      var codes = codesByRule[ruleId] || [];
      return data.diagnostics.filter(function (diagnostic) { return codes.indexOf(diagnostic.code) >= 0; });
    }

    function renderDispositionSummary() {
      var applied = data.diagnostics.filter(function (diagnostic) {
        return diagnostic.code === 'FINDING_DISPOSITION_APPLIED';
      }).sort(function (left, right) { return left.id.localeCompare(right.id); });
      var panel = required('disposition-panel');
      var list = required('disposition-list');
      panel.hidden = !applied.length;
      list.replaceChildren();
      setText('disposition-count', formatNumber(applied.length));
      applied.forEach(function (diagnostic) {
        var item = document.createElement('p');
        item.className = 'disposition-item';
        var disposition = diagnostic.disposition;
        item.textContent = disposition
          ? (disposition.title || disposition.findingId || 'Finding') + ' · ' + disposition.disposition +
            ' · ' + disposition.reviewer + ' · ' + disposition.date +
            (disposition.evidence && disposition.evidence.length ? ' · ' + disposition.evidence.join('; ') : '')
          : diagnostic.message;
        list.append(item);
      });
    }

    function renderAnalysisHealth() {
      var health = data.analysisHealth;
      var disabledRulesBody = required('disabled-rules');
      var incidentsBody = required('health-incidents');
      var incompleteInputsBody = required('incomplete-inputs');
      disabledRulesBody.replaceChildren();
      incidentsBody.replaceChildren();
      incompleteInputsBody.replaceChildren();
      if (health.state === 'legacy-not-recorded') {
        setText('overview-health', 'Health: legacy run; analysis coverage was not recorded.');
        setText('analysis-health-state', 'Legacy: not recorded');
        required('analysis-health-state').className = 'legacy-not-recorded';
        setText('analysis-health-recall', 'Not recorded');
        setText('analysis-health-fixed-silence', 'Not recorded');
        setText('analysis-health-rules', 'Not recorded');
        setText('analysis-health-limitation', health.limitation);
        setText('disabled-rule-count', 'Not recorded');
        setText('health-incident-count', 'Not recorded');
        setText('incomplete-input-count', 'Not recorded');
        setText('health-detail-count', 'Legacy run');
        setText('brief-health-state', 'Not recorded');
        setText('brief-synthetic-health', 'Not recorded');
        setText('brief-real-target-health', 'Not bundled');
        setText('brief-health-note', health.limitation);
        emptyRow(incompleteInputsBody, 3, 'Target input completeness was not recorded for this legacy run.');
        emptyRow(disabledRulesBody, 3, 'Rule health was not recorded for this legacy run.');
        emptyRow(incidentsBody, 5, 'Incident regressions were not recorded for this legacy run.');
        return;
      }
      var disabledRules = health.rules.filter(function (rule) { return rule.state === 'disabled'; });
      var incompleteInputs = health.rules.filter(function (rule) {
        return rule.target && rule.target.inputStatus === 'incomplete';
      });
      var enabledRules = health.rules.length - disabledRules.length;
      var apiBoundaryCodes = [
        'API_CONTRACT_COMPARISON_UNCERTAIN',
        'API_CONTRACT_DYNAMIC_CLIENT_BASE',
        'API_CONTRACT_DYNAMIC_CLIENT_METHOD',
        'API_CONTRACT_DYNAMIC_CLIENT_ROUTE',
        'API_CONTRACT_DYNAMIC_SERVER_ROUTE'
      ];
      var apiBoundaryCount = data.diagnostics.filter(function (diagnostic) {
        return apiBoundaryCodes.indexOf(diagnostic.code) >= 0;
      }).length;
      setText(
        'overview-health',
        'Health: ' + health.status + '. ' + formatNumber(incompleteInputs.length) +
          ' rule input' + (incompleteInputs.length === 1 ? '' : 's') + ' incomplete; ' +
          formatNumber(apiBoundaryCount) + ' API comparison' + (apiBoundaryCount === 1 ? '' : 's') +
          ' outside the supported static boundary.'
      );
      setText('analysis-health-state', health.status);
      required('analysis-health-state').className = fixedClass(health.status, ['complete', 'incomplete'], 'incomplete');
      setText('analysis-health-recall', formatRatio(health.recall));
      setText('analysis-health-fixed-silence', formatRatio(health.fixedCaseSilence));
      setText('analysis-health-rules', formatNumber(enabledRules) + ' / ' + formatNumber(health.rules.length) + ' enabled');
      setText('brief-health-state', health.status);
      setText('brief-synthetic-health', formatRatio(health.recall));
      setText(
        'brief-real-target-health',
        health.realTargetEvaluation ? 'Separate report' : 'Not recorded'
      );
      setText(
        'brief-health-note',
        health.status === 'complete'
          ? 'Static controls are complete. Runtime impact and real-target results are not established by this browser projection.'
          : formatNumber(incompleteInputs.length) + ' target input' + (incompleteInputs.length === 1 ? ' is' : 's are') +
            ' incomplete. Synthetic controls do not establish runtime impact, and real-target results are not bundled.'
      );
      var realTargetNote = health.realTargetEvaluation
        ? ' Real-target recall is not recorded in this run; use the separate ' + health.realTargetEvaluation.reportContract + ' report.'
        : '';
      var incompleteInputNote = incompleteInputs.length
        ? ' ' + formatNumber(incompleteInputs.length) + ' rule' + (incompleteInputs.length === 1 ? ' has' : 's have') + ' incomplete target input; expand control and input details for the reasons.'
        : '';
      setText(
        'analysis-health-limitation',
        health.status === 'complete'
          ? 'Recorded by ' + health.producer.id + ' v' + health.producer.version + '. Static controls do not establish runtime impact.' + realTargetNote
          : 'Analysis health is incomplete.' + incompleteInputNote + ' Disabled-rule findings are suppressed until their controls pass.' + realTargetNote
      );
      setText(
        'health-detail-count',
        formatNumber(incompleteInputs.length) + ' incomplete input' + (incompleteInputs.length === 1 ? '' : 's') +
          ' · ' + formatNumber(disabledRules.length) + ' disabled · ' + formatNumber(health.incidents.length) + ' incidents'
      );
      setText('incomplete-input-count', formatNumber(incompleteInputs.length) + ' incomplete');
      incompleteInputs.forEach(function (rule) {
        var target = rule.target;
        var reasons = incompleteReasonDiagnostics(rule.ruleId);
        var reasonText = reasons.length
          ? reasons.map(function (diagnostic) {
              return diagnostic.code + ': ' + diagnostic.message + (diagnostic.path ? ' [' + diagnostic.path + ']' : '');
            }).join(' · ')
          : 'Required target inputs were unavailable or unsupported; no scoped reason diagnostic was recorded.';
        var row = document.createElement('tr');
        appendCells(row, [
          rule.ruleId,
          formatNumber(target.detectedObservations) + ' detected · ' +
            formatNumber(target.uncertainObservations) + ' uncertain · ' +
            formatNumber(target.findingInstances) + ' finding instances',
          reasonText
        ]);
        incompleteInputsBody.append(row);
      });
      if (!incompleteInputs.length) emptyRow(incompleteInputsBody, 3, 'All recorded target inputs are complete.');
      setText('disabled-rule-count', formatNumber(disabledRules.length) + ' disabled');
      disabledRules.forEach(function (rule) {
        var row = document.createElement('tr');
        appendCells(row, [
          rule.ruleId,
          formatNumber(rule.controls.passed) + ' / ' + formatNumber(rule.controls.total) + ' passed',
          formatNumber(rule.controls.observedObservations) + ' / ' + formatNumber(rule.controls.expectedObservations) + ' expected'
        ]);
        disabledRulesBody.append(row);
      });
      if (!disabledRules.length) emptyRow(disabledRulesBody, 3, 'No analysis rules were disabled.');
      setText('health-incident-count', formatNumber(health.incidents.length) + ' total');
      health.incidents.slice(0, TABLE_LIMIT).forEach(function (incident) {
        var row = document.createElement('tr');
        appendCells(row, [
          incident.family,
          incident.ruleId,
          incident.broken.outcome + ' (' + formatNumber(incident.broken.observed) + ' / ≥' + formatNumber(incident.broken.expectedMinimum) + ')',
          incident.fixed.outcome + ' (' + formatNumber(incident.fixed.observed) + ' / ≤' + formatNumber(incident.fixed.expectedMaximum) + ')',
          incident.status
        ]);
        incidentsBody.append(row);
      });
      if (!health.incidents.length) emptyRow(incidentsBody, 5, 'No incident regressions were recorded.');
      if (health.incidents.length > TABLE_LIMIT) {
        emptyRow(incidentsBody, 5, 'Table limited to ' + formatNumber(TABLE_LIMIT) + ' incident regressions.');
      }
    }

    function appendPathCell(row, pathValue) {
      var cell = document.createElement('td');
      var file = filesByPath.get(pathValue);
      if (!file) {
        cell.textContent = pathValue || '';
        row.append(cell);
        return;
      }
      var button = document.createElement('button');
      button.type = 'button';
      button.className = 'path-button';
      button.textContent = pathValue;
      button.addEventListener('click', function () { selectFile(file.id, true); });
      cell.append(button);
      row.append(cell);
    }

    function renderRelationships(bodyId, relationships) {
      var body = required(bodyId);
      body.replaceChildren();
      relationships.slice(0, RELATIONSHIP_TABLE_LIMIT).forEach(function (relationship) {
        var row = document.createElement('tr');
        appendPathCell(row, relationship.fromPath);
        appendCells(row, [
          relationshipType(relationship),
          relationship.specifier,
          relationship.resolution
        ]);
        appendPathCell(row, relationship.toPath || '');
        appendCells(row, [relationshipLocation(relationship)]);
        body.append(row);
      });
      if (!relationships.length) emptyRow(body, 6, 'No relationships in this direction.');
      if (relationships.length > RELATIONSHIP_TABLE_LIMIT) {
        emptyRow(body, 6, 'Additional relationships are available in the complete Mermaid export.');
      }
    }

    function renderRelationshipSection(direction, relationships) {
      renderRelationships(direction + '-relationships', relationships);
      setText(direction + '-relationship-summary-count', formatNumber(relationships.length));
      required(direction + '-relationship-section').open = relationships.length > 0;
    }

    function renderBadges(items) {
      var container = required('selected-badges');
      container.replaceChildren();
      items.forEach(function (item) {
        var badge = document.createElement('span');
        badge.className = 'badge ' + fixedClass(item.kind, [
          'source', 'test', 'configuration', 'documentation', 'other',
          'finding', 'data-contract', 'high', 'medium', 'low', 'info',
          'active', 'mothballed', 'shared', 'unknown', 'unspecified'
        ], 'other');
        badge.textContent = item.text;
        container.append(badge);
      });
    }

    function relatedFindingPaths(finding) {
      var values = [];
      if (finding.path) values.push(finding.path);
      finding.relatedPaths.forEach(function (pathValue) {
        if (values.indexOf(pathValue) < 0) values.push(pathValue);
      });
      return values;
    }

    function hideFindingDetails() {
      required('selected-finding-details').hidden = true;
      required('selected-mapping-context-section').hidden = true;
      required('selected-finding-instance-section').hidden = true;
      required('selected-finding-evidence-section').hidden = true;
    }

    function renderFindingDetails(finding) {
      var calibration = finding.severityCalibration;
      var contexts = finding.mappingContexts || [];
      var instances = finding.instances || [];
      var evidence = finding.evidence || [];
      required('selected-finding-details').hidden = false;
      setText('selected-finding-mechanism', findingMechanism(finding));
      setText('selected-finding-calibration', findingCalibrationSummary(finding));
      setText(
        'selected-finding-rationale',
        calibration ? calibration.rationale : 'This legacy finding predates static severity calibration.'
      );

      var contextSection = required('selected-mapping-context-section');
      var contextBody = required('selected-mapping-contexts');
      contextSection.hidden = !contexts.length;
      contextSection.open = contexts.length > 0;
      contextBody.replaceChildren();
      contexts.forEach(function (context) {
        var row = document.createElement('tr');
        appendCells(row, [
          context.sourceKind,
          context.composePath + ' · ' + context.service,
          context.hostRoot + ' → ' + context.containerRoot,
          [
            context.buildContext ? 'context ' + context.buildContext : '',
            context.dockerfile ? 'Dockerfile ' + context.dockerfile : '',
            context.workingDirectory ? 'working directory ' + context.workingDirectory : ''
          ].filter(Boolean).join(' · ') || 'Not applicable'
        ]);
        contextBody.append(row);
      });
      setText('selected-mapping-context-count', formatNumber(contexts.length));

      var instanceSection = required('selected-finding-instance-section');
      var instanceBody = required('selected-finding-instances');
      instanceSection.hidden = !instances.length;
      instanceBody.replaceChildren();
      instances.forEach(function (instance) {
        var row = document.createElement('tr');
        appendCells(row, [
          recordAnchor(instance),
          instance.signals.join(', ') || 'None recorded',
          formatNumber(instance.evidence.length) + ' evidence record' + (instance.evidence.length === 1 ? '' : 's')
        ]);
        instanceBody.append(row);
      });
      setText('selected-finding-instance-count', formatNumber(instances.length));

      var evidenceSection = required('selected-finding-evidence-section');
      var evidenceBody = required('selected-finding-evidence');
      evidenceSection.hidden = !evidence.length;
      evidenceBody.replaceChildren();
      evidence.forEach(function (entry) {
        var row = document.createElement('tr');
        appendCells(row, [
          entry.producer + ' v' + entry.producerVersion + ' · level ' + String(entry.level),
          entry.basis,
          evidenceLocation(entry)
        ]);
        evidenceBody.append(row);
      });
      setText('selected-finding-evidence-count', formatNumber(evidence.length));
    }

    function appendBriefBadge(container, value) {
      var badge = document.createElement('span');
      badge.textContent = value;
      container.append(badge);
    }

    function appendImpactMetric(container, label, value) {
      var wrapper = document.createElement('div');
      var term = document.createElement('dt');
      var description = document.createElement('dd');
      term.textContent = label;
      description.textContent = value;
      wrapper.append(term, description);
      container.append(wrapper);
    }

    function briefEvidenceRecords(finding) {
      var values = [];
      var seen = new Set();
      function add(entry) {
        var key = [entry.producer, entry.producerVersion, entry.basis, evidenceLocation(entry)].join('|');
        if (seen.has(key)) return;
        seen.add(key);
        values.push(entry);
      }
      (finding.evidence || []).forEach(add);
      (finding.instances || []).forEach(function (instance) { (instance.evidence || []).forEach(add); });
      return values;
    }

    function renderInvestigationBrief(finding, ordinal) {
      var empty = required('brief-empty');
      var content = required('brief-content');
      var relatedFileButton = required('open-related-file');
      var exportButton = required('export-handoff');
      if (!finding) {
        empty.hidden = false;
        content.hidden = true;
        relatedFileButton.disabled = true;
        exportButton.disabled = true;
        return;
      }
      empty.hidden = true;
      content.hidden = false;
      exportButton.disabled = false;
      setText('brief-ordinal', String(ordinal + 1).padStart(2, '0'));
      setText('brief-severity', finding.severity);
      required('brief-severity').className = 'severity-chip ' + fixedClass(finding.severity, ['high', 'medium', 'low', 'info'], 'info');
      setText('brief-id', finding.reviewId || finding.id);
      setText('brief-title', finding.title);
      setText('brief-anchor', recordAnchor(finding) + ' · ' + finding.ruleId);
      setText('brief-claim-title', finding.title);
      setText('brief-description', finding.description);
      setText('brief-confidence', finding.confidence + ' confidence');

      var badges = required('brief-badges');
      badges.replaceChildren();
      appendBriefBadge(badges, findingKind(finding));
      appendBriefBadge(badges, finding.category);
      appendBriefBadge(badges, priorityBandLabel(finding.reviewPriority && finding.reviewPriority.band));
      appendBriefBadge(badges, formatNumber(findingInstanceCount(finding)) + ' instance' + (findingInstanceCount(finding) === 1 ? '' : 's'));
      appendBriefBadge(badges, findingMechanism(finding));

      var evidence = briefEvidenceRecords(finding);
      var evidenceContainer = required('brief-evidence');
      evidenceContainer.replaceChildren();
      evidence.slice(0, BRIEF_EVIDENCE_LIMIT).forEach(function (entry) {
        var card = document.createElement('div');
        card.className = 'brief-evidence-item';
        var title = document.createElement('strong');
        var detail = document.createElement('p');
        title.textContent = evidenceLocation(entry);
        detail.textContent = entry.producer + ' v' + entry.producerVersion + ' · level ' + String(entry.level) + ' · ' + entry.basis;
        card.append(title, detail);
        evidenceContainer.append(card);
      });
      if (!evidence.length) {
        var noEvidence = document.createElement('p');
        noEvidence.className = 'brief-evidence-more';
        noEvidence.textContent = 'No evidence references were recorded for this finding.';
        evidenceContainer.append(noEvidence);
      } else if (evidence.length > BRIEF_EVIDENCE_LIMIT) {
        var moreEvidence = document.createElement('p');
        moreEvidence.className = 'brief-evidence-more';
        moreEvidence.textContent = '+' + formatNumber(evidence.length - BRIEF_EVIDENCE_LIMIT) + ' more evidence records in the Evidence library';
        evidenceContainer.append(moreEvidence);
      }
      setText('brief-evidence-count', formatNumber(evidence.length) + ' record' + (evidence.length === 1 ? '' : 's'));

      var impact = finding.impactContext;
      setText('brief-impact-title', impact ? impact.summary : 'Static impact context was not recorded for this legacy finding.');
      setText(
        'brief-impact-summary',
        impact
          ? 'Atlas classified this as ' + impact.reachability +
            (impact.scope ? ' in ' + impact.scope + ' scope' : '') +
            '. Feature-gate evidence is ' + impact.featureGate + '.'
          : 'Treat the impact as unknown until the related path and runtime context are reviewed.'
      );
      var metrics = required('brief-impact-metrics');
      metrics.replaceChildren();
      appendImpactMetric(metrics, 'Reachability', impact ? impact.reachability : 'unknown');
      appendImpactMetric(metrics, 'Scope', impact && impact.scope ? impact.scope : 'not recorded');
      appendImpactMetric(
        metrics,
        'Blast radius',
        impact ? formatNumber(impact.entrypoints.length + (impact.entrypointRemainder || 0)) + ' entrypoint' +
          (impact.entrypoints.length + (impact.entrypointRemainder || 0) === 1 ? '' : 's') :
          formatNumber(relatedFindingPaths(finding).length) + ' related path' + (relatedFindingPaths(finding).length === 1 ? '' : 's')
      );
      setText(
        'brief-limitations',
        impact && impact.limitations.length
          ? 'Limits: ' + impact.limitations.join(' ')
          : 'Limit: static evidence does not establish deployed traffic, runtime execution, or user impact.'
      );
      setText(
        'brief-refutation',
        finding.refutationCondition ||
          'A reviewer demonstrates that the cited static relationship is not part of the effective target behavior.'
      );
      setText('brief-next-validation', finding.nextValidation);

      var calibration = finding.severityCalibration;
      setText('brief-calibration-level', finding.severity);
      setText(
        'brief-calibration-title',
        calibration
          ? calibration.detectorSeverity + ' detector → ' + finding.severity + ' reported · ceiling ' + calibration.ceiling
          : 'Calibration not recorded'
      );
      setText(
        'brief-calibration-rationale',
        calibration
          ? calibration.rationale + ' Runtime reachability: ' + calibration.runtimeReachability + '.'
          : 'This legacy finding predates static severity calibration.'
      );
      required('brief-calibration-scale').querySelectorAll('i').forEach(function (segment, index) {
        segment.classList.toggle('on', index < severityRank(finding.severity));
      });

      var artifacts = [];
      var artifactPaths = new Set();
      function addArtifact(pathValue, note) {
        if (!pathValue || artifactPaths.has(pathValue)) return;
        artifactPaths.add(pathValue);
        artifacts.push({ path: pathValue, note: note });
      }
      addArtifact(finding.path, 'Primary finding anchor');
      evidence.forEach(function (entry) { addArtifact(entry.path, 'Evidence from ' + entry.producer); });
      finding.relatedPaths.forEach(function (pathValue) { addArtifact(pathValue, 'Related analysis path'); });
      var artifactContainer = required('brief-artifacts');
      artifactContainer.replaceChildren();
      artifacts.slice(0, BRIEF_ARTIFACT_LIMIT).forEach(function (artifact) {
        var card = document.createElement('div');
        card.className = 'brief-artifact';
        var pathLabel = document.createElement('strong');
        var note = document.createElement('span');
        pathLabel.className = 'mono';
        pathLabel.textContent = artifact.path;
        note.textContent = artifact.note;
        card.append(pathLabel, note);
        artifactContainer.append(card);
      });
      if (!artifacts.length) {
        var noArtifacts = document.createElement('div');
        noArtifacts.className = 'brief-artifact';
        noArtifacts.textContent = 'No target-relative artifact path was recorded.';
        artifactContainer.append(noArtifacts);
      }
      setText('brief-artifact-count', formatNumber(artifacts.length) + ' total');

      var contexts = finding.mappingContexts || [];
      var contextContainer = required('brief-contexts');
      contextContainer.replaceChildren();
      contexts.slice(0, BRIEF_CONTEXT_LIMIT).forEach(function (context) {
        var card = document.createElement('div');
        card.className = 'brief-context';
        var contextTitle = document.createElement('strong');
        var contextDetail = document.createElement('span');
        contextTitle.textContent = context.service + ' · ' + context.sourceKind;
        contextDetail.textContent = context.hostRoot + ' → ' + context.containerRoot + ' · ' + context.composePath;
        card.append(contextTitle, contextDetail);
        contextContainer.append(card);
      });
      if (!contexts.length) {
        var noContexts = document.createElement('div');
        noContexts.className = 'brief-context';
        var noContextsTitle = document.createElement('strong');
        var noContextsText = document.createElement('span');
        noContextsTitle.textContent = 'No mapping contexts recorded';
        noContextsText.textContent = 'This is an explicit absence in the bundled finding, not evidence that no runtime mapping exists.';
        noContexts.append(noContextsTitle, noContextsText);
        contextContainer.append(noContexts);
      }
      setText('brief-context-count', formatNumber(contexts.length) + ' total');

      relatedFileButton.disabled = !relatedFindingPaths(finding).some(function (pathValue) { return filesByPath.has(pathValue); });
    }

    function renderSelected() {
      var focusButton = required('focus-neighborhood');
      if (state.selectedFindingId) {
          var finding = findingsById.get(state.selectedFindingId);
        if (finding) {
          var paths = relatedFindingPaths(finding);
          var subject = structuredDataContractSubject(finding);
          var subjectEntries = dataContractSubjectEntries(finding);
          setText('selected-kind', subjectEntries.length ? 'Selected data contract' : 'Selected finding');
          setText('selected-file-title', finding.title);
          setText(
            'selected-file-metadata',
            subject
              ? subject.table + '.' + subject.column + ' · ' + dimensionLabel(subject.dimension)
              : subjectEntries.length
                ? formatNumber(subjectEntries.length) + ' structured contract subjects · ' + finding.ruleId
              : finding.category + ' · ' + finding.ruleId
          );
          setText(
            'selected-description',
            finding.description + ' Impact: ' + findingImpactSummary(finding) + ' Next validation: ' + finding.nextValidation
          );
          required('selected-file-provenance').hidden = true;
          renderFindingDetails(finding);
          var findingBadges = [
            { text: finding.severity, kind: finding.severity },
            { text: findingKind(finding), kind: 'finding' },
            { text: formatNumber(findingInstanceCount(finding)) + ' instances', kind: 'finding' },
            { text: finding.confidence + ' confidence', kind: 'finding' },
            { text: finding.status, kind: 'finding' },
            { text: formatNumber(paths.length) + ' related files', kind: 'finding' }
          ];
          if (subject) {
            var subjectEndpoints = dataContractEndpoints(subject);
            findingBadges.push(
              { text: subjectEndpoints.leftLabel, kind: 'data-contract' },
              { text: subjectEndpoints.rightLabel, kind: 'data-contract' }
            );
          }
          renderBadges(findingBadges);
          setText('selected-stat-one-label', 'Paths');
          setText('selected-stat-two-label', 'Contexts');
          setText('selected-stat-three-label', 'Signals');
          setText('selected-incoming-count', paths.length);
          setText('selected-outgoing-count', (finding.mappingContexts || []).length);
          setText('selected-symbol-count', finding.signals.length);
          required('incoming-relationship-section').hidden = true;
          required('outgoing-relationship-section').hidden = true;
          renderRelationshipSection('incoming', []);
          renderRelationshipSection('outgoing', []);
          focusButton.textContent = paths.some(function (pathValue) { return filesByPath.has(pathValue); })
            ? 'Open first related file'
            : 'Keep finding in focus';
          focusButton.disabled = !paths.some(function (pathValue) { return filesByPath.has(pathValue); });
          required('selected-status').className = 'selection-dot finding';
          return;
        }
      }

      var file = filesById.get(state.selectedFileId);
      hideFindingDetails();
      required('incoming-relationship-section').hidden = false;
      required('outgoing-relationship-section').hidden = false;
      setText('selected-stat-one-label', 'Incoming');
      setText('selected-stat-two-label', 'Outgoing');
      setText('selected-stat-three-label', 'Symbols');
      setText('selected-kind', 'Selected file');
      required('selected-status').className = 'selection-dot';
      focusButton.textContent = 'Show dependency neighborhood';
      focusButton.disabled = !file;
      if (!file) {
        setText('selected-file-title', 'No file selected.');
        setText('selected-file-metadata', '');
        setText('selected-description', 'Choose a file or graph card to inspect run metadata and relationships.');
        required('selected-file-provenance').hidden = true;
        setText('selected-incoming-count', 0);
        setText('selected-outgoing-count', 0);
        setText('selected-symbol-count', 0);
        renderBadges([]);
        renderRelationshipSection('incoming', []);
        renderRelationshipSection('outgoing', []);
        return;
      }
      setText('selected-file-title', file.path);
      setText('selected-file-metadata', formatBytes(file.bytes) + ' · SHA-256 ' + file.sha256);
      required('selected-file-provenance').hidden = false;
      setText('selected-file-id', file.id);
      setText(
        'selected-file-evidence',
        file.evidence.producer + ' v' + file.evidence.producerVersion +
          ' · ' + file.evidence.basis + ' · level ' + String(file.evidence.level)
      );
      setText(
        'selected-file-lifecycle',
        file.lifecycle.state +
          (file.lifecycle.ruleId ? ' · rule ' + file.lifecycle.ruleId : '') +
          ' · ' + file.lifecycle.basis
      );
      setText(
        'selected-file-limitation',
        file.lifecycle.uncertainty + ' · ' + file.lifecycle.limitation
      );
      var descriptionParts = [];
      if (file.symbols.length) descriptionParts.push(formatNumber(file.symbols.length) + ' indexed symbols');
      if (file.environmentVariables.length) descriptionParts.push(formatNumber(file.environmentVariables.length) + ' environment keys');
      setText(
        'selected-description',
        descriptionParts.length
          ? descriptionParts.join(' · ') + '.'
          : 'No symbols or environment keys were indexed for this file.'
      );
      renderBadges([
        { text: file.kind, kind: file.kind },
        { text: file.language, kind: file.kind },
        { text: file.lifecycle.state + ' lifecycle', kind: file.lifecycle.state }
      ]);
      setText('selected-incoming-count', formatNumber(file.incoming.length));
      setText('selected-outgoing-count', formatNumber(file.outgoing.length));
      setText('selected-symbol-count', formatNumber(file.symbols.length));
      renderRelationshipSection('incoming', file.incoming);
      renderRelationshipSection('outgoing', file.outgoing);
    }

    function fileMatches(file, includeSearch) {
      if (kindFilter.value !== 'all' && file.kind !== kindFilter.value) return false;
      if (languageFilter.value !== 'all' && file.language !== languageFilter.value) return false;
      if (!includeSearch) return true;
      var tokens = fileFilter.value.trim().toLowerCase().split(' ').filter(Boolean);
      if (!tokens.length) return true;
      var text = fileSearchText.get(file.id) || '';
      return tokens.every(function (token) { return text.includes(token); });
    }

    function renderFileSelection() {
      required('file-results').querySelectorAll('.file-result').forEach(function (element) {
        var isSelected = element.getAttribute('data-file-id') === state.selectedFileId;
        element.classList.toggle('selected', isSelected);
        element.setAttribute('aria-selected', String(isSelected));
      });
    }

    function renderFileBrowser() {
      var results = required('file-results');
      results.replaceChildren();
      state.filteredFiles.slice(0, FILE_LIST_LIMIT).forEach(function (file) {
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'file-result kind-' + fixedClass(file.kind, [
          'source', 'test', 'configuration', 'documentation', 'other'
        ], 'other');
        button.setAttribute('role', 'option');
        button.setAttribute('data-file-id', file.id);
        button.setAttribute('aria-selected', String(file.id === state.selectedFileId));
        button.title = file.path;
        var accent = document.createElement('span');
        accent.className = 'file-accent';
        accent.setAttribute('aria-hidden', 'true');
        var copy = document.createElement('span');
        copy.className = 'file-copy';
        var name = document.createElement('span');
        name.className = 'file-name';
        name.textContent = basename(file.path);
        var pathValue = document.createElement('span');
        pathValue.className = 'file-path';
        pathValue.textContent = dirname(file.path);
        copy.append(name, pathValue);
        var degree = document.createElement('span');
        degree.className = 'file-degree';
        degree.textContent = formatNumber(file.incoming.length + file.outgoing.length);
        degree.title = 'Total relationships';
        button.append(accent, copy, degree);
        button.addEventListener('click', function () { selectFile(file.id, true); });
        results.append(button);
      });
      if (!state.filteredFiles.length) {
        var empty = document.createElement('p');
        empty.className = 'empty-list';
        empty.textContent = 'No files match these filters.';
        results.append(empty);
      }
      var suffix = state.filteredFiles.length > FILE_LIST_LIMIT
        ? ' · top ' + formatNumber(FILE_LIST_LIMIT) + ' by connectivity'
        : '';
      setText('census-limit', formatNumber(state.filteredFiles.length) + ' matching files' + suffix);
      required('clear-filter').hidden = !fileFilter.value;
    }

    function renderCensusTable() {
      var body = required('census-files');
      body.replaceChildren();
      state.filteredFiles.slice(0, TABLE_LIMIT).forEach(function (file) {
        var row = document.createElement('tr');
        appendPathCell(row, file.path);
        appendCells(row, [
          file.kind,
          file.language,
          formatBytes(file.bytes),
          file.symbols.length,
          file.environmentVariables.length
        ]);
        body.append(row);
      });
      if (!state.filteredFiles.length) emptyRow(body, 6, 'No files match these filters.');
      if (state.filteredFiles.length > TABLE_LIMIT) {
        emptyRow(body, 6, 'Table limited to ' + formatNumber(TABLE_LIMIT) + ' rows. Refine the file filters to inspect more.');
      }
    }

    function relationshipAllowed(edge) {
      return relationshipFilter.value === 'all' || edge.type === relationshipFilter.value;
    }

    function clusterKey(pathValue) {
      var parts = String(pathValue).split('/').filter(Boolean);
      if (parts.length <= 1) return '(root)';
      var first = parts[0];
      var twoLevelRoots = ['app', 'apps', 'features', 'modules', 'packages', 'services', 'src'];
      if (parts.length > 2 && twoLevelRoots.indexOf(first) >= 0) return first + '/' + parts[1];
      return first;
    }

    function dominantKind(counts) {
      var kinds = ['source', 'test', 'configuration', 'documentation', 'other'];
      kinds.sort(function (left, right) {
        return Number(counts[right] || 0) - Number(counts[left] || 0);
      });
      return kinds[0] || 'other';
    }

    function topologicalRanks(nodes, edges) {
      var indegree = new Map(nodes.map(function (node) { return [node.id, 0]; }));
      var outgoing = new Map();
      var ranks = new Map(nodes.map(function (node) { return [node.id, 0]; }));
      edges.forEach(function (edge) {
        if (edge.source === edge.target || !indegree.has(edge.source) || !indegree.has(edge.target)) return;
        indegree.set(edge.target, Number(indegree.get(edge.target)) + 1);
        var values = outgoing.get(edge.source) || [];
        values.push(edge);
        outgoing.set(edge.source, values);
      });
      var queue = nodes.filter(function (node) { return indegree.get(node.id) === 0; })
        .map(function (node) { return node.id; })
        .sort();
      var processed = new Set();
      while (queue.length) {
        var id = queue.shift();
        if (processed.has(id)) continue;
        processed.add(id);
        (outgoing.get(id) || []).forEach(function (edge) {
          ranks.set(edge.target, Math.min(5, Math.max(Number(ranks.get(edge.target)), Number(ranks.get(id)) + 1)));
          indegree.set(edge.target, Number(indegree.get(edge.target)) - 1);
          if (indegree.get(edge.target) === 0) {
            queue.push(edge.target);
            queue.sort();
          }
        });
      }
      nodes.forEach(function (node) {
        if (!processed.has(node.id)) {
          var incident = edges.filter(function (edge) { return edge.source === node.id || edge.target === node.id; });
          var hasIncoming = incident.some(function (edge) { return edge.target === node.id && edge.source !== node.id; });
          var hasOutgoing = incident.some(function (edge) { return edge.source === node.id && edge.target !== node.id; });
          ranks.set(node.id, hasIncoming && !hasOutgoing ? 3 : hasOutgoing && !hasIncoming ? 0 : 2);
        }
        node.rank = Number(ranks.get(node.id));
      });
    }

    function architectureGraph() {
      var fileIds = new Set(state.filteredFiles.map(function (file) { return file.id; }));
      var groups = new Map();

      function ensureGroup(key, label, syntheticKind) {
        var group = groups.get(key);
        if (!group) {
          group = {
            id: 'cluster:' + key,
            label: label,
            fileIds: [],
            kinds: {},
            kind: syntheticKind || 'other',
            internalEdges: 0,
            degree: 0
          };
          groups.set(key, group);
        }
        return group;
      }

      state.filteredFiles.forEach(function (file) {
        var key = 'files:' + clusterKey(file.path);
        var group = ensureGroup(key, clusterKey(file.path));
        group.fileIds.push(file.id);
        group.kinds[file.kind] = Number(group.kinds[file.kind] || 0) + 1;
      });

      function groupForNode(nodeId) {
        var file = filesById.get(nodeId);
        if (file) return groups.get('files:' + clusterKey(file.path));
        var graphNode = graphNodesById.get(nodeId);
        if (!graphNode) return undefined;
        if (graphNode.kind === 'external-package') {
          var packageName = String(graphNode.label).split(' ')[0];
          if (packageName.startsWith('@')) packageName = String(graphNode.label).split('/').slice(0, 2).join('/');
          return ensureGroup('external:' + packageName, packageName, 'external');
        }
        if (graphNode.kind === 'unresolved-internal') return ensureGroup('unresolved', 'Unresolved references', 'unresolved');
        return ensureGroup('unsupported', 'Unsupported references', 'unresolved');
      }

      var rawEdges = [];
      data.dependencyGraph.edges.forEach(function (edge) {
        if (!relationshipAllowed(edge) || !fileIds.has(edge.source)) return;
        if (filesById.has(edge.target) && !fileIds.has(edge.target)) return;
        var sourceGroup = groupForNode(edge.source);
        var targetGroup = groupForNode(edge.target);
        if (!sourceGroup || !targetGroup) return;
        sourceGroup.degree += 1;
        targetGroup.degree += 1;
        if (sourceGroup.id === targetGroup.id) {
          sourceGroup.internalEdges += 1;
          return;
        }
        rawEdges.push({
          source: sourceGroup.id,
          target: targetGroup.id,
          type: edge.type,
          typeOnly: Boolean(edge.typeOnly),
          resolution: edge.resolution,
          count: 1,
          specifier: edge.specifier
        });
      });

      groups.forEach(function (group) {
        if (group.fileIds.length) group.kind = dominantKind(group.kinds);
      });
      var selectedClusterId;
      var selectedFile = filesById.get(state.selectedFileId);
      if (selectedFile) selectedClusterId = 'cluster:files:' + clusterKey(selectedFile.path);
      var rankedGroups = Array.from(groups.values()).sort(function (left, right) {
        var leftSelected = left.id === selectedClusterId ? 1 : 0;
        var rightSelected = right.id === selectedClusterId ? 1 : 0;
        return rightSelected - leftSelected ||
          (right.fileIds.length + right.degree) - (left.fileIds.length + left.degree) ||
          left.label.localeCompare(right.label);
      });
      var totalNodes = rankedGroups.length;
      var keepCount = totalNodes > ARCHITECTURE_NODE_LIMIT ? ARCHITECTURE_NODE_LIMIT - 1 : ARCHITECTURE_NODE_LIMIT;
      var kept = rankedGroups.slice(0, keepCount);
      var omitted = rankedGroups.slice(keepCount);
      var keptIds = new Set(kept.map(function (group) { return group.id; }));
      var other;
      if (omitted.length) {
        other = {
          id: 'cluster:other',
          label: 'Other areas',
          fileIds: omitted.flatMap(function (group) { return group.fileIds; }),
          kinds: {},
          kind: 'cluster',
          internalEdges: omitted.reduce(function (sum, group) { return sum + group.internalEdges; }, 0),
          degree: omitted.reduce(function (sum, group) { return sum + group.degree; }, 0)
        };
        kept.push(other);
      }

      function remapGroup(id) {
        return keptIds.has(id) ? id : other ? other.id : undefined;
      }

      var mergedEdges = new Map();
      rawEdges.forEach(function (edge) {
        var source = remapGroup(edge.source);
        var target = remapGroup(edge.target);
        if (!source || !target || source === target) return;
        var key = source + '\\u0000' + target + '\\u0000' + edge.type + '\\u0000' + edge.resolution + '\\u0000' + String(edge.typeOnly);
        var merged = mergedEdges.get(key);
        if (merged) {
          merged.count += edge.count;
        } else {
          mergedEdges.set(key, {
            id: 'aggregate:' + String(mergedEdges.size),
            source: source,
            target: target,
            type: edge.type,
            typeOnly: edge.typeOnly,
            resolution: edge.resolution,
            count: edge.count,
            specifier: 'aggregated records'
          });
        }
      });
      var allEdges = Array.from(mergedEdges.values()).sort(function (left, right) {
        return right.count - left.count || left.source.localeCompare(right.source) || left.target.localeCompare(right.target);
      });
      var visibleEdges = allEdges.slice(0, GRAPH_EDGE_LIMIT);
      var nodes = kept.map(function (group) {
        var fileCount = group.fileIds.length;
        var metaParts = [];
        if (fileCount) metaParts.push(formatNumber(fileCount) + (fileCount === 1 ? ' file' : ' files'));
        if (group.internalEdges) metaParts.push(formatNumber(group.internalEdges) + ' internal links');
        if (!metaParts.length) metaParts.push(formatNumber(group.degree) + ' references');
        return {
          id: group.id,
          label: group.label,
          subtitle: group.kind === 'external' ? 'external package' : 'repository area',
          meta: metaParts.join(' · '),
          pill: group.kind,
          kind: group.kind,
          fileIds: group.fileIds
        };
      });
      topologicalRanks(nodes, visibleEdges);
      return {
        mode: 'architecture',
        nodes: nodes,
        edges: visibleEdges,
        totalNodes: totalNodes,
        totalEdges: allEdges.length,
        limited: totalNodes > nodes.length || allEdges.length > visibleEdges.length
      };
    }

    function displayNode(graphNode, rank) {
      var file = filesById.get(graphNode.id);
      if (file) {
        return {
          id: graphNode.id,
          label: basename(file.path),
          subtitle: dirname(file.path),
          meta: formatNumber(file.incoming.length) + ' in · ' + formatNumber(file.outgoing.length) + ' out',
          pill: file.kind,
          kind: file.kind,
          fileId: file.id,
          rank: rank
        };
      }
      var syntheticKind = graphNode.kind === 'external-package' ? 'external' : 'unresolved';
      return {
        id: graphNode.id,
        label: graphNode.label,
        subtitle: graphNode.kind.replaceAll('-', ' '),
        meta: 'Synthetic dependency target',
        pill: syntheticKind,
        kind: syntheticKind,
        rank: rank
      };
    }

    function neighborhoodGraph() {
      var selectedId = state.selectedFileId;
      if (!selectedId || !graphNodesById.has(selectedId)) {
        return { mode: 'neighborhood', nodes: [], edges: [], totalNodes: 0, totalEdges: 0, limited: false };
      }
      var depthLimit = Math.max(1, Math.min(3, Number(graphDepth.value) || 2));
      var ranks = new Map([[selectedId, 0]]);
      var distances = new Map([[selectedId, 0]]);
      var queue = [selectedId];
      var limited = false;
      while (queue.length) {
        var current = queue.shift();
        var distance = Number(distances.get(current));
        if (distance >= depthLimit) continue;
        var incident = (edgesByNode.get(current) || []).filter(relationshipAllowed);
        for (var edgeIndex = 0; edgeIndex < incident.length; edgeIndex += 1) {
          var edge = incident[edgeIndex];
          var neighbor = edge.source === current ? edge.target : edge.source;
          if (distances.has(neighbor)) continue;
          if (distances.size >= GRAPH_NODE_LIMIT) {
            limited = true;
            break;
          }
          distances.set(neighbor, distance + 1);
          var direction = edge.source === current ? 1 : -1;
          ranks.set(neighbor, Number(ranks.get(current)) + direction);
          queue.push(neighbor);
        }
      }
      var ids = new Set(distances.keys());
      var allEdges = data.dependencyGraph.edges.filter(function (edge) {
        return relationshipAllowed(edge) && ids.has(edge.source) && ids.has(edge.target);
      });
      if (allEdges.length > GRAPH_EDGE_LIMIT) limited = true;
      var visibleEdges = allEdges.slice(0, GRAPH_EDGE_LIMIT).map(function (edge) {
        return {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          type: edge.type,
          typeOnly: Boolean(edge.typeOnly),
          resolution: edge.resolution,
          count: 1,
          specifier: edge.specifier
        };
      });
      var nodes = Array.from(ids).map(function (id) {
        return displayNode(graphNodesById.get(id), Number(ranks.get(id)));
      });
      return {
        mode: 'neighborhood',
        nodes: nodes,
        edges: visibleEdges,
        totalNodes: ids.size,
        totalEdges: allEdges.length,
        limited: limited
      };
    }

    function findingScore(finding) {
      return { high: 4, medium: 3, low: 2, info: 1 }[finding.severity] || 0;
    }

    function findingsGraph() {
      var query = fileFilter.value.trim().toLowerCase();
      var tokens = query.split(' ').filter(Boolean);
      var eligibleFiles = new Set(data.census.files.filter(function (file) {
        return fileMatches(file, false);
      }).map(function (file) { return file.id; }));
      var matchingFindings = data.findings.filter(function (finding) {
        var paths = relatedFindingPaths(finding);
        var hasEligiblePath = !paths.length || paths.some(function (pathValue) {
          var file = filesByPath.get(pathValue);
          return file && eligibleFiles.has(file.id);
        });
        if (!hasEligiblePath) return false;
        if (!tokens.length) return true;
        var text = [
          finding.title,
          finding.description,
          finding.category,
          finding.ruleId,
          finding.severity,
          paths.join(' ')
        ].join(' ').toLowerCase();
        return tokens.every(function (token) { return text.includes(token); });
      }).sort(function (left, right) {
        return findingScore(right) - findingScore(left) || left.id.localeCompare(right.id);
      });
      var visibleFindings = matchingFindings.slice(0, FINDING_NODE_LIMIT);
      var nodes = [];
      var edges = [];
      var addedFiles = new Set();
      visibleFindings.forEach(function (finding) {
        var findingNodeId = 'finding:' + finding.id;
        nodes.push({
          id: findingNodeId,
          label: finding.title,
          subtitle: finding.category,
          meta: finding.confidence + ' confidence',
          pill: finding.severity,
          kind: 'finding',
          findingId: finding.id,
          rank: 0
        });
      });
      visibleFindings.forEach(function (finding) {
        var findingNodeId = 'finding:' + finding.id;
        relatedFindingPaths(finding).forEach(function (pathValue) {
          var file = filesByPath.get(pathValue);
          if (!file || !eligibleFiles.has(file.id)) return;
          if (!addedFiles.has(file.id) && nodes.length < GRAPH_NODE_LIMIT) {
            nodes.push(displayNode(graphNodesById.get(file.id), 1));
            addedFiles.add(file.id);
          }
          if (addedFiles.has(file.id) && edges.length < GRAPH_EDGE_LIMIT) {
            edges.push({
              id: findingNodeId + ':' + file.id,
              source: findingNodeId,
              target: file.id,
              type: 'finding-link',
              resolution: 'resolved',
              count: 1,
              specifier: finding.category
            });
          }
        });
      });
      return {
        mode: 'findings',
        nodes: nodes,
        edges: edges,
        totalNodes: matchingFindings.length + addedFiles.size,
        totalEdges: edges.length,
        limited: matchingFindings.length > visibleFindings.length || nodes.length >= GRAPH_NODE_LIMIT || edges.length >= GRAPH_EDGE_LIMIT
      };
    }

    function dataContractEvidencePaths(entry) {
      var leftPaths = new Set();
      var rightPaths = new Set();
      var endpoints = dataContractEndpoints(entry.subject);
      entry.evidence.forEach(function (evidence) {
        if (!evidence.path) return;
        var leftEvidence = endpoints.comparison === 'provisioning-path'
          ? evidence.basis === 'literal-sequelize-migration-column'
          : entry.subject.model === 'prisma'
            ? evidence.basis === 'literal-prisma-model-field'
            : evidence.basis === 'literal-sequelize-model-attribute';
        if (leftEvidence) leftPaths.add(evidence.path);
        else rightPaths.add(evidence.path);
      });
      if (!leftPaths.size && entry.path) leftPaths.add(entry.path);
      if (!rightPaths.size) {
        entry.relatedPaths.forEach(function (pathValue) { rightPaths.add(pathValue); });
      }
      return { leftPaths: leftPaths, rightPaths: rightPaths };
    }

    function dataContractsGraph() {
      var tokens = fileFilter.value.trim().toLowerCase().split(' ').filter(Boolean);
      var eligibleFiles = new Set(data.census.files.filter(function (file) {
        return fileMatches(file, false);
      }).map(function (file) { return file.id; }));
      var contractFindings = [];
      data.findings.forEach(function (finding) {
        dataContractSubjectEntries(finding).forEach(function (entry) {
          var endpoints = dataContractEndpoints(entry.subject);
          var evidencePaths = entry.evidence.map(function (evidence) { return evidence.path; }).filter(Boolean);
          var hasEligiblePath = !evidencePaths.length || evidencePaths.some(function (pathValue) {
            var file = filesByPath.get(pathValue);
            return file && eligibleFiles.has(file.id);
          });
          if (!hasEligiblePath) return;
          if (tokens.length) {
            var searchable = [
              entry.subject.table,
              entry.subject.column,
              entry.subject.dimension,
              endpoints.comparison,
              endpoints.left,
              endpoints.right,
              finding.title,
              finding.description,
              finding.ruleId,
              evidencePaths.join(' ')
            ].join(' ').toLowerCase();
            if (!tokens.every(function (token) { return searchable.includes(token); })) return;
          }
          contractFindings.push(entry);
        });
      });
      contractFindings.sort(function (left, right) {
        return findingScore(right.finding) - findingScore(left.finding) ||
          left.subject.table.localeCompare(right.subject.table) ||
          left.subject.column.localeCompare(right.subject.column) ||
          left.finding.id.localeCompare(right.finding.id);
      });

      var grouped = new Map();
      contractFindings.forEach(function (entry) {
        var endpoints = dataContractEndpoints(entry.subject);
        var key = JSON.stringify([
          endpoints.comparison,
          endpoints.left,
          endpoints.right,
          entry.subject.table,
          entry.subject.column
        ]);
        var group = grouped.get(key);
        if (!group) {
          group = {
            key: key,
            subject: entry.subject,
            endpoints: endpoints,
            findings: [],
            dimensions: new Set(),
            leftPaths: new Set(),
            rightPaths: new Set()
          };
          grouped.set(key, group);
        }
        if (!group.findings.some(function (finding) { return finding.id === entry.finding.id; })) {
          group.findings.push(entry.finding);
        }
        group.dimensions.add(entry.subject.dimension);
        var sides = dataContractEvidencePaths(entry);
        sides.leftPaths.forEach(function (pathValue) { group.leftPaths.add(pathValue); });
        sides.rightPaths.forEach(function (pathValue) { group.rightPaths.add(pathValue); });
      });
      var dimensionOrder = ['column-presence', 'column-mapping', 'type-family', 'nullability', 'default', 'enum-members'];
      var allGroups = Array.from(grouped.values()).map(function (group) {
        group.dimensionList = Array.from(group.dimensions).sort(function (left, right) {
          return dimensionOrder.indexOf(left) - dimensionOrder.indexOf(right);
        });
        return group;
      }).sort(function (left, right) {
        return findingScore(right.findings[0]) - findingScore(left.findings[0]) ||
          left.subject.table.localeCompare(right.subject.table) ||
          left.subject.column.localeCompare(right.subject.column);
      });
      var visibleGroups = allGroups.slice(0, DATA_CONTRACT_SUBJECT_LIMIT);
      var nodes = [];
      var edges = [];
      var evidenceNodes = new Map();
      var contractNodeIds = new Map();
      var totalEvidenceNodes = new Set();
      var totalEdges = 0;
      allGroups.forEach(function (group) {
        group.leftPaths.forEach(function (pathValue) {
          totalEvidenceNodes.add('left:' + group.endpoints.left + ':' + pathValue);
        });
        group.rightPaths.forEach(function (pathValue) {
          totalEvidenceNodes.add('right:' + group.endpoints.right + ':' + pathValue);
        });
        totalEdges += group.leftPaths.size + group.rightPaths.size;
      });

      visibleGroups.forEach(function (group, index) {
        var nodeId = 'data-contract:' + String(index);
        contractNodeIds.set(group.key, nodeId);
        nodes.push({
          id: nodeId,
          label: group.subject.table,
          subtitle: group.subject.column,
          meta: group.dimensionList.map(dimensionLabel).join(' · '),
          pill: group.findings[0].severity,
          kind: 'data-contract',
          findingIds: group.findings.map(function (finding) { return finding.id; }),
          rank: 1
        });
      });

      function ensureEvidenceNode(side, pathValue, group) {
        var sideType = side === 'left' ? group.endpoints.left : group.endpoints.right;
        var key = JSON.stringify([side, sideType, pathValue]);
        var existing = evidenceNodes.get(key);
        if (existing) return existing;
        if (nodes.length >= GRAPH_NODE_LIMIT) return undefined;
        var file = filesByPath.get(pathValue);
        var endpointLabel = side === 'left' ? group.endpoints.leftLabel : group.endpoints.rightLabel;
        var pill = sideType === 'sql' || sideType === 'sql-bootstrap'
          ? 'SQL'
          : sideType === 'sequelize-migration'
            ? 'migration'
            : sideType;
        var node = {
          id: 'data-evidence:' + String(evidenceNodes.size),
          label: basename(pathValue),
          subtitle: endpointLabel.endsWith('evidence') ? endpointLabel : endpointLabel + ' evidence',
          meta: '1 linked contract',
          pill: pill,
          kind: side === 'left' ? 'contract-model' : 'contract-storage',
          fileId: file ? file.id : undefined,
          rank: side === 'left' ? 0 : 2,
          linkCount: 0
        };
        evidenceNodes.set(key, node);
        nodes.push(node);
        return node;
      }

      visibleGroups.forEach(function (group) {
        var contractNodeId = contractNodeIds.get(group.key);
        var dimensionText = group.dimensionList.map(dimensionLabel).join(', ');
        group.leftPaths.forEach(function (pathValue) {
          if (edges.length >= GRAPH_EDGE_LIMIT) return;
          var evidenceNode = ensureEvidenceNode('left', pathValue, group);
          if (!evidenceNode) return;
          evidenceNode.linkCount += 1;
          edges.push({
            id: 'contract-model:' + String(edges.length),
            source: evidenceNode.id,
            target: contractNodeId,
            type: 'contract-model',
            label: group.endpoints.leftEdgeLabel,
            resolution: 'resolved',
            count: 1,
            specifier: dimensionText
          });
        });
        group.rightPaths.forEach(function (pathValue) {
          if (edges.length >= GRAPH_EDGE_LIMIT) return;
          var evidenceNode = ensureEvidenceNode('right', pathValue, group);
          if (!evidenceNode) return;
          evidenceNode.linkCount += 1;
          edges.push({
            id: 'contract-storage:' + String(edges.length),
            source: contractNodeId,
            target: evidenceNode.id,
            type: 'contract-storage',
            label: group.endpoints.rightEdgeLabel,
            resolution: 'resolved',
            count: 1,
            specifier: dimensionText
          });
        });
      });
      evidenceNodes.forEach(function (node) {
        node.meta = formatNumber(node.linkCount) + (node.linkCount === 1 ? ' linked contract' : ' linked contracts');
      });
      return {
        mode: 'data-contracts',
        nodes: nodes,
        edges: edges,
        totalNodes: allGroups.length + totalEvidenceNodes.size,
        totalEdges: totalEdges,
        totalSubjects: allGroups.length,
        visibleSubjects: visibleGroups.length,
        limited: allGroups.length > visibleGroups.length ||
          nodes.length >= GRAPH_NODE_LIMIT ||
          edges.length >= GRAPH_EDGE_LIMIT
      };
    }

    function layoutGraph(graph) {
      var rankGroups = new Map();
      graph.nodes.forEach(function (node) {
        var rank = Number.isFinite(node.rank) ? node.rank : 0;
        var values = rankGroups.get(rank) || [];
        values.push(node);
        rankGroups.set(rank, values);
      });
      var ranks = Array.from(rankGroups.keys()).sort(function (left, right) { return left - right; });
      var maxRows = Math.max(5, Math.ceil(Math.sqrt(Math.max(graph.nodes.length, 1)) * 1.35));
      var columns = [];
      ranks.forEach(function (rank) {
        var values = rankGroups.get(rank).slice().sort(function (left, right) {
          return left.label.localeCompare(right.label);
        });
        for (var index = 0; index < values.length; index += maxRows) {
          columns.push(values.slice(index, index + maxRows));
        }
      });
      var actualRows = Math.max(1, columns.reduce(function (maximum, column) {
        return Math.max(maximum, column.length);
      }, 0));
      var columnStep = CARD_WIDTH + 110;
      var rowStep = CARD_HEIGHT + 34;
      var positions = new Map();
      columns.forEach(function (column, columnIndex) {
        var offset = (actualRows - column.length) * rowStep / 2;
        column.forEach(function (node, rowIndex) {
          positions.set(node.id, {
            x: 44 + columnIndex * columnStep,
            y: 42 + offset + rowIndex * rowStep,
            width: CARD_WIDTH,
            height: CARD_HEIGHT
          });
        });
      });
      state.positions = positions;
      state.graphBounds = {
        x: 0,
        y: 0,
        width: Math.max(1, (Math.max(columns.length, 1) - 1) * columnStep + CARD_WIDTH + 88),
        height: Math.max(1, actualRows * rowStep + 84)
      };
    }

    function edgeClass(type) {
      return {
        'static-import': 'edge-static-import',
        'dynamic-import': 'edge-dynamic-import',
        'require': 'edge-require',
        'export-from': 'edge-export-from',
        'finding-link': 'edge-finding-link',
        'contract-model': 'edge-contract-model',
        'contract-storage': 'edge-contract-storage'
      }[type] || 'edge-muted';
    }

    function nodeClass(kind) {
      return 'kind-' + fixedClass(kind, [
        'source', 'test', 'configuration', 'documentation', 'other',
        'external', 'unresolved', 'finding', 'cluster',
        'data-contract', 'contract-model', 'contract-storage'
      ], 'other');
    }

    function drawEdge(edge, index) {
      var source = state.positions.get(edge.source);
      var target = state.positions.get(edge.target);
      if (!source || !target) return;
      var sameColumn = Math.abs(source.x - target.x) < 4;
      var sourceOnLeft = source.x <= target.x;
      var startX = sourceOnLeft ? source.x + source.width : source.x;
      var endX = sourceOnLeft ? target.x : target.x + target.width;
      var startY = source.y + source.height / 2;
      var endY = target.y + target.height / 2;
      var pathData;
      var labelX;
      var labelY;
      if (sameColumn) {
        var bend = source.x + source.width + 48 + (index % 4) * 9;
        pathData = 'M ' + String(startX) + ' ' + String(startY) +
          ' C ' + String(bend) + ' ' + String(startY) + ', ' +
          String(bend) + ' ' + String(endY) + ', ' +
          String(endX) + ' ' + String(endY);
        labelX = bend;
        labelY = (startY + endY) / 2;
      } else {
        var middle = (startX + endX) / 2;
        pathData = 'M ' + String(startX) + ' ' + String(startY) +
          ' C ' + String(middle) + ' ' + String(startY) + ', ' +
          String(middle) + ' ' + String(endY) + ', ' +
          String(endX) + ' ' + String(endY);
        labelX = middle;
        labelY = (startY + endY) / 2 - 4;
      }
      var group = svgElement('g', {
        class: 'graph-edge' +
          (edge.resolution !== 'resolved' ? ' unresolved' : '') +
          (edge.typeOnly ? ' type-only' : ''),
        'data-source': edge.source,
        'data-target': edge.target
      });
      var title = svgElement('title');
      title.textContent = (edge.label || relationshipType(edge)) + ' · ' + edge.resolution +
        (edge.count > 1 ? ' · ' + formatNumber(edge.count) + ' records' : '') +
        (edge.specifier ? ' · ' + edge.specifier : '');
      var path = svgElement('path', {
        class: 'graph-edge-path ' + edgeClass(edge.type),
        d: pathData
      });
      group.append(title, path);
      if (state.currentGraph.mode === 'architecture' && edge.count > 1) {
        svgText(group, { class: 'edge-count', x: labelX, y: labelY }, formatNumber(edge.count));
      } else if (state.currentGraph.mode === 'data-contracts' || state.currentGraph.edges.length <= 32) {
        svgText(
          group,
          { class: 'edge-label', x: labelX, y: labelY },
          truncate(
            edge.label || (edge.type === 'finding-link' ? 'relates to' : relationshipType(edge)),
            22
          )
        );
      }
      graphEdgeLayer.append(group);
    }

    function drawNode(node) {
      var position = state.positions.get(node.id);
      if (!position) return;
      var group = svgElement('g', {
        class: 'graph-node ' + nodeClass(node.kind),
        transform: 'translate(' + String(position.x) + ' ' + String(position.y) + ')',
        tabindex: '0',
        role: 'button',
        'aria-label': node.label + '. ' + node.subtitle + '. ' + node.meta,
        'data-node-id': node.id
      });
      var title = svgElement('title');
      title.textContent = node.label + ' · ' + node.subtitle + ' · ' + node.meta;
      var surface = svgElement('rect', { class: 'node-surface', x: 0, y: 0, width: CARD_WIDTH, height: CARD_HEIGHT, rx: 10 });
      var accent = svgElement('rect', { class: 'node-accent', x: 0, y: 0, width: 5, height: CARD_HEIGHT, rx: 3 });
      var iconRing = svgElement('circle', { class: 'node-icon-ring', cx: 22, cy: 22, r: 10 });
      var iconDot = svgElement('circle', { class: 'node-icon-dot', cx: 22, cy: 22, r: 4 });
      group.append(title, surface, accent, iconRing, iconDot);
      svgText(group, { class: 'node-title', x: 39, y: 20 }, truncate(node.label, 25));
      svgText(group, { class: 'node-subtitle', x: 39, y: 37 }, truncate(node.subtitle, 29));
      svgText(group, { class: 'node-meta', x: 13, y: 69 }, truncate(node.meta, 31));
      var pillText = truncate(node.pill, 14);
      var pillWidth = Math.max(38, Math.min(82, 16 + pillText.length * 5.4));
      group.append(svgElement('rect', {
        class: 'node-pill',
        x: CARD_WIDTH - pillWidth - 10,
        y: 49,
        width: pillWidth,
        height: 18,
        rx: 9
      }));
      svgText(group, {
        class: 'node-pill-text',
        x: CARD_WIDTH - pillWidth / 2 - 10,
        y: 61.5
      }, pillText);
      function activate() {
        if (node.findingIds && node.findingIds.length) {
          selectFinding(node.findingIds[0]);
        } else if (node.findingId) {
          selectFinding(node.findingId);
        } else if (node.fileId) {
          selectFile(node.fileId, false);
        } else if (node.fileIds && node.fileIds.length) {
          var selectedIsInside = node.fileIds.indexOf(state.selectedFileId) >= 0;
          var clusterFileId = selectedIsInside ? state.selectedFileId : node.fileIds.slice().sort(function (leftId, rightId) {
            var left = filesById.get(leftId);
            var right = filesById.get(rightId);
            var leftDegree = left ? left.incoming.length + left.outgoing.length : 0;
            var rightDegree = right ? right.incoming.length + right.outgoing.length : 0;
            if (rightDegree !== leftDegree) return rightDegree - leftDegree;
            return left && right ? left.path.localeCompare(right.path) : leftId.localeCompare(rightId);
          })[0];
          selectFile(clusterFileId, true);
        }
      }
      group.addEventListener('click', activate);
      group.addEventListener('keydown', function (event) {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          activate();
        }
      });
      graphNodeLayer.append(group);
    }

    function selectedGraphNodeId() {
      if (!state.graphSelectionActive && state.currentGraph.mode === 'architecture') return undefined;
      if (state.selectedFindingId && state.currentGraph.mode === 'findings') {
        return 'finding:' + state.selectedFindingId;
      }
      if (state.selectedFindingId && state.currentGraph.mode === 'data-contracts') {
        var contract = state.currentGraph.nodes.find(function (node) {
          return node.findingIds && node.findingIds.indexOf(state.selectedFindingId) >= 0;
        });
        if (contract) return contract.id;
      }
      var direct = state.currentGraph.nodes.find(function (node) { return node.fileId === state.selectedFileId; });
      if (direct) return direct.id;
      var cluster = state.currentGraph.nodes.find(function (node) {
        return node.fileIds && node.fileIds.indexOf(state.selectedFileId) >= 0;
      });
      return cluster ? cluster.id : undefined;
    }

    function updateGraphSelection() {
      var selectedNodeId = selectedGraphNodeId();
      var relatedIds = new Set();
      state.currentGraph.edges.forEach(function (edge) {
        if (edge.source === selectedNodeId) relatedIds.add(edge.target);
        if (edge.target === selectedNodeId) relatedIds.add(edge.source);
      });
      graphNodeLayer.querySelectorAll('.graph-node').forEach(function (element) {
        var id = element.getAttribute('data-node-id');
        var selected = Boolean(selectedNodeId) && id === selectedNodeId;
        var related = Boolean(selectedNodeId) && relatedIds.has(id);
        element.classList.toggle('selected', selected);
        element.classList.toggle('related', related);
        element.classList.toggle('dimmed', Boolean(selectedNodeId) && !selected && !related);
      });
      graphEdgeLayer.querySelectorAll('.graph-edge').forEach(function (element) {
        var related = Boolean(selectedNodeId) && (
          element.getAttribute('data-source') === selectedNodeId ||
          element.getAttribute('data-target') === selectedNodeId
        );
        element.classList.toggle('related', related);
        element.classList.toggle('dimmed', Boolean(selectedNodeId) && !related);
      });
    }

    function renderLegend() {
      var list = required('graph-legend');
      list.replaceChildren();
      var items;
      if (state.currentGraph.mode === 'data-contracts') {
        items = [
          ['swatch legend-model', 'Model evidence'],
          ['swatch legend-contract', 'Table / column contract'],
          ['swatch legend-storage', 'Migration / SQL evidence'],
          ['line legend-model-edge', 'Model declaration'],
          ['line legend-storage-edge', 'Storage comparison']
        ];
      } else if (state.currentGraph.mode === 'findings') {
        items = [
          ['swatch legend-finding', 'Finding'],
          ['swatch legend-source', 'Related file'],
          ['line legend-static', 'Finding link']
        ];
      } else {
        items = [
          ['swatch legend-source', 'Source'],
          ['swatch legend-test', 'Test'],
          ['swatch legend-config', 'Configuration'],
          ['swatch legend-docs', 'Documentation'],
          ['swatch legend-external', 'External package'],
          ['swatch legend-unresolved-swatch', 'Unresolved target'],
          ['line legend-static', 'Static import'],
          ['line legend-dynamic', 'Dynamic import'],
          ['line legend-unresolved', 'Unresolved / type-only']
        ];
      }
      items.forEach(function (item) {
        var row = document.createElement('li');
        row.className = 'legend-item';
        var visual = document.createElement('span');
        var parts = item[0].split(' ');
        visual.className = (parts[0] === 'swatch' ? 'legend-swatch ' : 'legend-line ') + parts[1];
        visual.setAttribute('aria-hidden', 'true');
        var label = document.createElement('span');
        label.textContent = item[1];
        row.append(visual, label);
        list.append(row);
      });
    }

    function graphNodeLabel(id) {
      var node = state.currentGraph.nodes.find(function (candidate) { return candidate.id === id; });
      return node ? node.label : id;
    }

    function renderGraphTable() {
      var body = required('graph-edges');
      body.replaceChildren();
      state.currentGraph.edges.slice(0, TABLE_LIMIT).forEach(function (edge) {
        var row = document.createElement('tr');
        appendCells(row, [
          graphNodeLabel(edge.source),
          (edge.label || relationshipType(edge)) + (edge.count > 1 ? ' × ' + formatNumber(edge.count) : ''),
          edge.specifier,
          edge.resolution,
          graphNodeLabel(edge.target)
        ]);
        body.append(row);
      });
      if (!state.currentGraph.edges.length) emptyRow(body, 5, 'No connections in the current graph view.');
      setText('graph-table-count', formatNumber(state.currentGraph.edges.length) + ' visible');
    }

    function applyTransform() {
      graphViewport.setAttribute(
        'transform',
        'translate(' + String(state.transform.x) + ' ' + String(state.transform.y) + ') scale(' + String(state.transform.scale) + ')'
      );
    }

    function fitGraph() {
      var width = Math.max(320, graphCanvas.clientWidth);
      var height = Math.max(360, graphCanvas.clientHeight);
      var bounds = state.graphBounds;
      var scale = Math.min(1.12, (width - 44) / bounds.width, (height - 44) / bounds.height);
      if (!Number.isFinite(scale) || scale <= 0) scale = 1;
      state.transform.scale = Math.max(.12, scale);
      state.transform.x = (width - bounds.width * state.transform.scale) / 2 - bounds.x * state.transform.scale;
      state.transform.y = (height - bounds.height * state.transform.scale) / 2 - bounds.y * state.transform.scale;
      applyTransform();
    }

    function setGraphFocus(active) {
      workspaceGrid.classList.toggle('graph-focus', active);
      graphFocusButton.setAttribute('aria-pressed', String(active));
      graphFocusButton.textContent = active ? 'Exit focus' : 'Focus canvas';
      requestAnimationFrame(fitGraph);
    }

    function renderGraph() {
      if (state.graphMode === 'neighborhood') state.currentGraph = neighborhoodGraph();
      else if (state.graphMode === 'findings') state.currentGraph = findingsGraph();
      else if (state.graphMode === 'data-contracts') state.currentGraph = dataContractsGraph();
      else state.currentGraph = architectureGraph();
      layoutGraph(state.currentGraph);
      graphEdgeLayer.replaceChildren();
      graphNodeLayer.replaceChildren();
      state.currentGraph.edges.forEach(drawEdge);
      state.currentGraph.nodes.forEach(drawNode);
      required('graph-empty').hidden = state.currentGraph.nodes.length > 0;
      setText('graph-counts',
        formatNumber(state.currentGraph.nodes.length) + ' nodes · ' +
        formatNumber(state.currentGraph.edges.length) + ' edges'
      );
      var limitText;
      if (state.currentGraph.mode === 'architecture') {
        limitText = 'Aggregated from ' + formatNumber(state.filteredFiles.length) + ' matching files. ';
      } else if (state.currentGraph.mode === 'neighborhood') {
        limitText = 'Showing up to ' + graphDepth.value + ' hops from the selected file. ';
      } else if (state.currentGraph.mode === 'data-contracts') {
        limitText = 'Showing ' + formatNumber(state.currentGraph.visibleSubjects) + ' of ' +
          formatNumber(state.currentGraph.totalSubjects) +
          ' structured table / column contract subjects between their compared source endpoints. ';
      } else {
        limitText = 'Findings are connected only to verified related file paths. ';
      }
      limitText += state.currentGraph.limited
        ? 'The visual is capped for clarity; tables and the Mermaid export retain the broader record set.'
        : 'All records in this focused view are shown.';
      setText('graph-limit', limitText);
      renderLegend();
      renderGraphTable();
      updateGraphSelection();
      requestAnimationFrame(fitGraph);
    }

    function setGraphMode(mode) {
      state.graphMode = fixedClass(mode, ['architecture', 'neighborhood', 'data-contracts', 'findings'], 'architecture');
      document.querySelectorAll('[data-graph-mode]').forEach(function (button) {
        var active = button.getAttribute('data-graph-mode') === state.graphMode;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', String(active));
      });
      graphDepth.disabled = state.graphMode !== 'neighborhood';
      relationshipFilter.disabled = state.graphMode === 'data-contracts' || state.graphMode === 'findings';
      setText('graph-heading', {
        architecture: 'Dependency topology',
        neighborhood: 'Dependency neighborhood',
        'data-contracts': 'Data contract projection',
        findings: 'Finding relationships'
      }[state.graphMode]);
      setText('mode-description', {
        architecture: 'Folders are grouped to reveal the repository’s main dependency flow.',
        neighborhood: 'Incoming and outgoing dependencies radiate from the selected file.',
        'data-contracts': 'Table and column contracts bridge typed model evidence to migrations or SQL.',
        findings: 'Findings connect to the verified file paths they describe.'
      }[state.graphMode]);
      renderGraph();
    }

    function setWorkspaceView(view) {
      state.workspaceView = fixedClass(view, ['investigation', 'map', 'health', 'records'], 'investigation');
      document.querySelectorAll('[data-workspace-panel]').forEach(function (panel) {
        panel.hidden = panel.getAttribute('data-workspace-panel') !== state.workspaceView;
      });
      document.querySelectorAll('[data-workspace-view]').forEach(function (button) {
        var active = button.getAttribute('data-workspace-view') === state.workspaceView;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', String(active));
      });
      setText('workspace-title', {
        investigation: 'Investigation brief',
        map: 'System map',
        health: 'Run health',
        records: 'Evidence library'
      }[state.workspaceView]);
      if (state.workspaceView === 'map') requestAnimationFrame(fitGraph);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function selectFile(id, revealNeighborhood) {
      if (!filesById.has(id)) return;
      state.selectedFileId = id;
      state.selectedFindingId = undefined;
      state.graphSelectionActive = true;
      renderSelected();
      renderFileSelection();
      if (revealNeighborhood) {
        setGraphMode('neighborhood');
      } else {
        updateGraphSelection();
      }
    }

    function selectFinding(id) {
      if (!findingsById.has(id)) return;
      state.selectedFindingId = id;
      state.graphSelectionActive = true;
      renderSelected();
      renderFindingsTable();
      updateGraphSelection();
    }

    function refreshFilteredViews() {
      state.filteredFiles = data.census.files
        .filter(function (file) { return fileMatches(file, true); })
        .sort(compareFileRelevance);
      renderFileBrowser();
      renderCensusTable();
      renderGraph();
    }

    function scheduleFilteredViews() {
      if (state.filterFrame) cancelAnimationFrame(state.filterFrame);
      state.filterFrame = requestAnimationFrame(function () {
        state.filterFrame = 0;
        refreshFilteredViews();
      });
    }

    function visibleFindings() {
      var tokens = findingFilter.value.trim().toLowerCase().split(/\\s+/).filter(Boolean);
      return data.findings.filter(function (finding) {
        if (findingSeverityFilter.value !== 'all' && finding.severity !== findingSeverityFilter.value) return false;
        var searchText = findingSearchText(finding);
        return tokens.every(function (token) { return searchText.includes(token); });
      }).sort(function (left, right) { return compareFindings(left, right, findingSort.value); });
    }

    function focusQueueFinding(id) {
      var button = Array.from(required('finding-queue').querySelectorAll('.queue-finding')).find(function (candidate) {
        return candidate.getAttribute('data-finding-id') === id;
      });
      if (button) button.focus();
    }

    function renderFindingsTable() {
      var allVisible = visibleFindings();
      var queueGroups = findingQueueGroups(allVisible, findingSort.value);
      var queueVisible = queueGroups.slice(0, FINDING_QUEUE_LIMIT);
      var tableVisible = allVisible.slice(0, TABLE_LIMIT);
      if (!allVisible.some(function (finding) { return finding.id === state.selectedFindingId; })) {
        state.selectedFindingId = allVisible.length ? allVisible[0].id : undefined;
        renderSelected();
      }

      var queue = required('finding-queue');
      queue.replaceChildren();
      queueVisible.forEach(function (group, index) {
        var finding = group.representative;
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'queue-finding';
        button.setAttribute('role', 'option');
        button.setAttribute('data-finding-id', finding.id);
        var selected = finding.id === state.selectedFindingId;
        button.classList.toggle('selected', selected);
        button.setAttribute('aria-selected', String(selected));
        var ordinal = document.createElement('span');
        ordinal.className = 'queue-finding-ordinal';
        ordinal.textContent = String(index + 1).padStart(2, '0');
        var copy = document.createElement('span');
        copy.className = 'queue-finding-copy';
        var title = document.createElement('span');
        title.className = 'queue-finding-title';
        title.textContent = queueGroupLabel(group);
        var severity = document.createElement('span');
        severity.className = 'queue-finding-severity ' + fixedClass(finding.severity, ['high', 'medium', 'low', 'info'], 'info');
        severity.textContent = finding.severity;
        var pathValue = document.createElement('span');
        pathValue.className = 'queue-finding-path mono';
        pathValue.textContent = recordAnchor(finding);
        var meta = document.createElement('span');
        meta.className = 'queue-finding-meta';
        [
          priorityBandLabel(finding.reviewPriority && finding.reviewPriority.band),
          formatNumber(group.totalInstances) + ' instance' + (group.totalInstances === 1 ? '' : 's'),
          formatNumber(group.contextCount) + ' context' + (group.contextCount === 1 ? '' : 's'),
          finding.confidence + ' confidence'
        ].forEach(function (value) {
          var item = document.createElement('span');
          item.textContent = value;
          meta.append(item);
        });
        var groupNote = document.createElement('span');
        groupNote.className = 'queue-finding-group-note';
        groupNote.textContent = queueGroupNote(group);
        copy.append(title, severity, pathValue, meta);
        if (groupNote.textContent) copy.append(groupNote);
        button.append(ordinal, copy);
        button.addEventListener('click', function () {
          selectFinding(finding.id);
          focusQueueFinding(finding.id);
        });
        queue.append(button);
      });
      if (!queueVisible.length) {
        var empty = document.createElement('p');
        empty.className = 'queue-empty';
        empty.textContent = 'No findings match this view.';
        queue.append(empty);
      }
      if (queueGroups.length > FINDING_QUEUE_LIMIT) {
        var queueLimit = document.createElement('p');
        queueLimit.className = 'queue-empty';
        queueLimit.textContent = 'Queue limited to ' + formatNumber(FINDING_QUEUE_LIMIT) + ' work groups. Refine the filters to review more.';
        queue.append(queueLimit);
      }
      setText('finding-queue-count', formatNumber(queueGroups.length) + ' groups · ' + formatNumber(allVisible.length) + ' findings');

      var body = required('findings');
      body.replaceChildren();
      tableVisible.forEach(function (finding) {
        var row = document.createElement('tr');
        if (finding.id === state.selectedFindingId) row.className = 'selected-record-row';
        var severityCell = document.createElement('td');
        severityCell.className = 'severity-' + fixedClass(finding.severity, ['info', 'low', 'medium', 'high'], 'info');
        severityCell.textContent = finding.severity;
        row.append(severityCell);
        appendCells(row, [
          findingKind(finding),
          formatNumber(findingInstanceCount(finding)),
          findingMechanism(finding),
          formatNumber((finding.mappingContexts || []).length),
          findingCalibrationSummary(finding),
          finding.category,
          recordAnchor(finding)
        ]);
        var findingCell = document.createElement('td');
        var findingButton = document.createElement('button');
        findingButton.type = 'button';
        findingButton.className = 'finding-select';
        findingButton.textContent = finding.title + ': ' + finding.description;
        findingButton.addEventListener('click', function () {
          selectFinding(finding.id);
          setWorkspaceView('investigation');
        });
        findingCell.append(findingButton);
        row.append(findingCell);
        appendCells(row, [findingImpactSummary(finding), finding.nextValidation]);
        body.append(row);
      });
      if (!tableVisible.length) emptyRow(body, 11, 'No findings match the Investigation queue filters.');
      if (allVisible.length > TABLE_LIMIT) emptyRow(body, 11, 'Table limited to ' + formatNumber(TABLE_LIMIT) + ' findings.');
      setText('findings-limit', formatNumber(allVisible.length) + ' shown · ' + formatNumber(data.findings.length) + ' total');

      var selectedFinding = state.selectedFindingId ? findingsById.get(state.selectedFindingId) : undefined;
      var selectedIndex = selectedFinding ? Math.max(0, allVisible.findIndex(function (finding) { return finding.id === selectedFinding.id; })) : 0;
      renderInvestigationBrief(selectedFinding, selectedIndex);
    }

    function filteredDiagnostics() {
      var tokens = diagnosticFilter.value.trim().toLowerCase().split(/\\s+/).filter(Boolean);
      return data.diagnostics.filter(function (diagnostic) {
        if (diagnosticSeverityFilter.value !== 'all' && diagnostic.severity !== diagnosticSeverityFilter.value) return false;
        var text = [diagnostic.code, diagnostic.path || '', diagnostic.message].join(' ').toLowerCase();
        return tokens.every(function (token) { return text.includes(token); });
      });
    }

    function renderDiagnosticSummary() {
      var grouped = new Map();
      data.diagnostics.forEach(function (diagnostic) {
        var group = grouped.get(diagnostic.code) || { total: 0, error: 0, warning: 0, info: 0 };
        group.total += 1;
        group[diagnostic.severity] += 1;
        grouped.set(diagnostic.code, group);
      });
      var entries = Array.from(grouped.entries()).sort(function (left, right) {
        return right[1].error - left[1].error || right[1].warning - left[1].warning || right[1].total - left[1].total || left[0].localeCompare(right[0]);
      });
      var body = required('diagnostic-summary');
      body.replaceChildren();
      entries.forEach(function (entry) {
        var row = document.createElement('tr');
        var codeCell = document.createElement('td');
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'diagnostic-code-button mono';
        button.textContent = entry[0];
        button.addEventListener('click', function () {
          diagnosticFilter.value = entry[0];
          required('diagnostic-details-section').open = true;
          renderDiagnosticsTable();
          diagnosticFilter.focus();
        });
        codeCell.append(button);
        row.append(codeCell);
        appendCells(row, [entry[1].total, entry[1].error, entry[1].warning, entry[1].info]);
        body.append(row);
      });
      if (!entries.length) emptyRow(body, 5, 'No diagnostics were recorded.');
      setText('diagnostics-limit', formatNumber(entries.length) + ' codes · ' + formatNumber(data.diagnostics.length) + ' records');
    }

    function renderDiagnosticsTable() {
      var filtered = filteredDiagnostics();
      var visible = filtered.slice(0, TABLE_LIMIT);
      var body = required('diagnostics');
      body.replaceChildren();
      visible.forEach(function (diagnostic) {
        var row = document.createElement('tr');
        var severity = document.createElement('td');
        severity.className = 'severity-' + fixedClass(diagnostic.severity, ['info', 'warning', 'error'], 'info');
        severity.textContent = diagnostic.severity;
        row.append(severity);
        appendCells(row, [diagnostic.code, diagnostic.path || '', diagnostic.message]);
        body.append(row);
      });
      if (!visible.length) emptyRow(body, 4, 'No diagnostic details match these filters.');
      if (filtered.length > TABLE_LIMIT) emptyRow(body, 4, 'Table limited to ' + formatNumber(TABLE_LIMIT) + ' diagnostics. Refine the filters to inspect more.');
      setText('diagnostic-details-count', formatNumber(filtered.length) + ' matching');
    }

    function scheduleFindingViews() {
      if (state.findingFilterFrame) cancelAnimationFrame(state.findingFilterFrame);
      state.findingFilterFrame = requestAnimationFrame(function () {
        state.findingFilterFrame = 0;
        renderFindingsTable();
      });
    }

    function scheduleDiagnosticViews() {
      if (state.diagnosticFilterFrame) cancelAnimationFrame(state.diagnosticFilterFrame);
      state.diagnosticFilterFrame = requestAnimationFrame(function () {
        state.diagnosticFilterFrame = 0;
        renderDiagnosticsTable();
      });
    }

    function selectedFinding() {
      return state.selectedFindingId ? findingsById.get(state.selectedFindingId) : undefined;
    }

    function exportSelectedFinding() {
      var finding = selectedFinding();
      if (!finding) return;
      var impact = finding.impactContext;
      var calibration = finding.severityCalibration;
      var evidence = briefEvidenceRecords(finding);
      var lines = [
        '# Atlas implementation handoff: ' + markdownCode(finding.title),
        '',
        '> Noncanonical review aid generated from the bundled Atlas run. Verify the viewer bundle externally before relying on it.',
        '',
        '- Finding: ' + markdownCode(finding.id),
        '- Review ID: ' + markdownCode(finding.reviewId || 'legacy-not-recorded'),
        '- Run: ' + markdownCode(data.run.runId),
        '- Snapshot: ' + markdownCode(data.run.snapshotId),
        '- Severity: ' + markdownCode(finding.severity),
        '- Confidence: ' + markdownCode(finding.confidence),
        '- Rule: ' + markdownCode(finding.ruleId),
        '- Mechanism: ' + markdownCode(findingMechanism(finding)),
        '- Actionability: ' + markdownCode(priorityBandLabel(finding.reviewPriority && finding.reviewPriority.band)),
        '- Anchor: ' + markdownCode(recordAnchor(finding)),
        '',
        '## Claim',
        '',
        markdownCode(finding.description),
        '',
        '## Falsifier',
        '',
        markdownCode(finding.refutationCondition || 'A reviewer demonstrates that the cited static relationship is not part of the effective target behavior.'),
        '',
        '## Impact and limitations',
        '',
        markdownCode(impact ? impact.summary : 'Static impact context was not recorded.'),
        '',
        impact && impact.limitations.length ? impact.limitations.map(function (value) { return '- ' + markdownCode(value); }).join(String.fromCharCode(10)) : '- Static evidence does not establish runtime execution or user impact.',
        '',
        '## Severity calibration',
        '',
        calibration ? markdownCode(calibration.rationale) + ' Detector: ' + markdownCode(calibration.detectorSeverity) + '; ceiling: ' + markdownCode(calibration.ceiling) + '; runtime: ' + markdownCode(calibration.runtimeReachability) + '.' : 'Calibration was not recorded.',
        '',
        '## Evidence',
        '',
        evidence.length ? evidence.map(function (entry) { return '- ' + markdownCode(evidenceLocation(entry)) + ' — ' + markdownCode(entry.producer) + ' v' + markdownCode(entry.producerVersion) + ': ' + markdownCode(entry.basis); }).join(String.fromCharCode(10)) : '- No evidence references recorded.',
        '',
        '## Mapping contexts',
        '',
        (finding.mappingContexts || []).length ? finding.mappingContexts.map(function (context) { return '- ' + markdownCode(context.service) + ': ' + markdownCode(context.hostRoot) + ' → ' + markdownCode(context.containerRoot) + ' (' + markdownCode(context.sourceKind) + ', ' + markdownCode(context.composePath) + ')'; }).join(String.fromCharCode(10)) : '- No mapping contexts recorded in this finding.',
        '',
        '## Next validation',
        '',
        markdownCode(finding.nextValidation),
        ''
      ];
      var content = lines.join(String.fromCharCode(10));
      var blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var link = document.createElement('a');
      link.href = url;
      link.download = 'atlas-' + finding.id.replace(/[^A-Za-z0-9._-]+/g, '-').toLowerCase() + '-handoff.md';
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setText('handoff-status', 'Handoff generated for ' + finding.id + '.');
    }

    document.querySelectorAll('[data-graph-mode]').forEach(function (button) {
      button.addEventListener('click', function () { setGraphMode(button.getAttribute('data-graph-mode')); });
    });
    document.querySelectorAll('[data-workspace-view]').forEach(function (button) {
      button.addEventListener('click', function () { setWorkspaceView(button.getAttribute('data-workspace-view')); });
    });
    document.querySelectorAll('[data-open-workspace]').forEach(function (button) {
      button.addEventListener('click', function () { setWorkspaceView(button.getAttribute('data-open-workspace')); });
    });
    document.querySelectorAll('[data-finding-shortcut]').forEach(function (button) {
      button.addEventListener('click', function () {
        var shortcut = button.getAttribute('data-finding-shortcut');
        findingSeverityFilter.value = shortcut === 'high' ? 'high' : 'all';
        findingFilter.value = shortcut === 'production' ? 'production' : shortcut === 'contracts' ? 'contract' : '';
        setWorkspaceView('investigation');
        renderFindingsTable();
        findingFilter.focus();
      });
    });
    fileFilter.addEventListener('input', scheduleFilteredViews);
    kindFilter.addEventListener('change', refreshFilteredViews);
    languageFilter.addEventListener('change', refreshFilteredViews);
    findingFilter.addEventListener('input', scheduleFindingViews);
    findingSeverityFilter.addEventListener('change', renderFindingsTable);
    findingSort.addEventListener('change', renderFindingsTable);
    diagnosticFilter.addEventListener('input', scheduleDiagnosticViews);
    diagnosticSeverityFilter.addEventListener('change', renderDiagnosticsTable);
    required('finding-queue').addEventListener('keydown', function (event) {
      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
      var buttons = Array.from(required('finding-queue').querySelectorAll('.queue-finding'));
      var current = event.target.closest && event.target.closest('.queue-finding');
      var index = buttons.indexOf(current);
      if (index < 0 || !buttons.length) return;
      event.preventDefault();
      var nextIndex = event.key === 'ArrowDown' ? Math.min(buttons.length - 1, index + 1) : Math.max(0, index - 1);
      var nextId = buttons[nextIndex].getAttribute('data-finding-id');
      selectFinding(nextId);
      focusQueueFinding(nextId);
    });
    required('verify-bundle').addEventListener('click', function () {
      var dialog = required('verification-dialog');
      if (typeof dialog.showModal === 'function') dialog.showModal();
      else dialog.setAttribute('open', '');
    });
    required('print-review').addEventListener('click', function () { window.print(); });
    required('export-handoff').addEventListener('click', exportSelectedFinding);
    required('open-system-map').addEventListener('click', function () {
      var finding = selectedFinding();
      if (!finding) return;
      setWorkspaceView('map');
      setGraphMode(dataContractSubjectEntries(finding).length ? 'data-contracts' : 'findings');
    });
    required('open-related-file').addEventListener('click', function () {
      var finding = selectedFinding();
      if (!finding) return;
      var relatedFile = relatedFindingPaths(finding).map(function (pathValue) { return filesByPath.get(pathValue); }).find(Boolean);
      if (!relatedFile) return;
      selectFile(relatedFile.id, true);
      setWorkspaceView('map');
    });
    relationshipFilter.addEventListener('change', renderGraph);
    graphDepth.addEventListener('change', function () {
      if (state.graphMode === 'neighborhood') renderGraph();
    });
    required('clear-filter').addEventListener('click', function () {
      fileFilter.value = '';
      fileFilter.focus();
      refreshFilteredViews();
    });
    required('focus-neighborhood').addEventListener('click', function () {
      if (state.selectedFindingId) {
        var finding = findingsById.get(state.selectedFindingId);
        var relatedFile = finding && relatedFindingPaths(finding).map(function (pathValue) {
          return filesByPath.get(pathValue);
        }).find(Boolean);
        if (relatedFile) {
          selectFile(relatedFile.id, true);
          setWorkspaceView('map');
        }
        return;
      }
      if (state.selectedFileId) {
        setGraphMode('neighborhood');
        setWorkspaceView('map');
      }
    });
    required('fit-graph').addEventListener('click', fitGraph);
    graphFocusButton.addEventListener('click', function () {
      setGraphFocus(!workspaceGrid.classList.contains('graph-focus'));
    });

    function zoomBy(factor, centerX, centerY) {
      var oldScale = state.transform.scale;
      var nextScale = Math.max(.12, Math.min(3.2, oldScale * factor));
      var x = centerX === undefined ? graphCanvas.clientWidth / 2 : centerX;
      var y = centerY === undefined ? graphCanvas.clientHeight / 2 : centerY;
      var worldX = (x - state.transform.x) / oldScale;
      var worldY = (y - state.transform.y) / oldScale;
      state.transform.scale = nextScale;
      state.transform.x = x - worldX * nextScale;
      state.transform.y = y - worldY * nextScale;
      applyTransform();
    }

    required('zoom-in').addEventListener('click', function () { zoomBy(1.2); });
    required('zoom-out').addEventListener('click', function () { zoomBy(1 / 1.2); });
    graphCanvas.addEventListener('wheel', function (event) {
      event.preventDefault();
      var bounds = graphCanvas.getBoundingClientRect();
      zoomBy(event.deltaY < 0 ? 1.12 : 1 / 1.12, event.clientX - bounds.left, event.clientY - bounds.top);
    }, { passive: false });
    graphCanvas.addEventListener('pointerdown', function (event) {
      if (event.target !== graphCanvas && event.target !== required('graph-grid')) return;
      state.drag = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        graphX: state.transform.x,
        graphY: state.transform.y
      };
      graphCanvas.setPointerCapture(event.pointerId);
      graphCanvas.classList.add('dragging');
    });
    graphCanvas.addEventListener('pointermove', function (event) {
      if (!state.drag || state.drag.pointerId !== event.pointerId) return;
      state.transform.x = state.drag.graphX + event.clientX - state.drag.startX;
      state.transform.y = state.drag.graphY + event.clientY - state.drag.startY;
      applyTransform();
    });
    function endDrag(event) {
      if (!state.drag || state.drag.pointerId !== event.pointerId) return;
      state.drag = undefined;
      graphCanvas.classList.remove('dragging');
    }
    graphCanvas.addEventListener('pointerup', endDrag);
    graphCanvas.addEventListener('pointercancel', endDrag);
    graphCanvas.addEventListener('keydown', function (event) {
      if (event.target !== graphCanvas) return;
      var handled = true;
      if (event.key === '+' || event.key === '=') zoomBy(1.2);
      else if (event.key === '-') zoomBy(1 / 1.2);
      else if (event.key === '0') fitGraph();
      else if (event.key === 'ArrowLeft') state.transform.x += 36;
      else if (event.key === 'ArrowRight') state.transform.x -= 36;
      else if (event.key === 'ArrowUp') state.transform.y += 36;
      else if (event.key === 'ArrowDown') state.transform.y -= 36;
      else handled = false;
      if (handled) {
        event.preventDefault();
        applyTransform();
      }
    });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && workspaceGrid.classList.contains('graph-focus')) {
        event.preventDefault();
        setGraphFocus(false);
        return;
      }
      var activeSearch = state.workspaceView === 'investigation' ? findingFilter : fileFilter;
      if (event.key === '/' && document.activeElement !== activeSearch && !event.ctrlKey && !event.metaKey && !event.altKey) {
        event.preventDefault();
        activeSearch.focus();
      }
      if (event.key === 'Escape' && document.activeElement === activeSearch && activeSearch.value) {
        activeSearch.value = '';
        if (activeSearch === findingFilter) renderFindingsTable();
        else refreshFilteredViews();
      }
    });

    renderAnalysisHealth();
    renderDispositionSummary();
    renderFindingsTable();
    renderDiagnosticSummary();
    renderDiagnosticsTable();
    renderSelected();
    refreshFilteredViews();
    setWorkspaceView('investigation');
    setStatus('Bundled run data loaded', 'ready');
  }

  try {
    setStatus('Loading viewer data…', 'loading');
    var encoded = globalThis.__ATLAS_VIEWER_DATA_B64__;
    if (typeof encoded !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
      throw new Error('Bundled viewer data is missing or malformed.');
    }
    delete globalThis.__ATLAS_VIEWER_DATA_B64__;
    var binary = atob(encoded);
    var bytes = Uint8Array.from(binary, function (character) { return character.charCodeAt(0); });
    var data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (data.schemaVersion !== 1 || data.viewerVersion !== '${VIEWER_VERSION}') {
      throw new Error('Viewer data version is not supported.');
    }
    render(data);
  } catch (error) {
    setStatus('Unable to load this viewer: ' + (error instanceof Error ? error.message : String(error)), 'error');
  }
}());
`;

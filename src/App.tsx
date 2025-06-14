import { createSignal, onCleanup, onMount, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import "./App.css";

function App() {
  const [suricataProgress, setSuricataProgress] = createSignal(0);
  const [npcapProgress, setNpcapProgress] = createSignal(0);
  const [eveboxProgress, setEveboxProgress] = createSignal(0);
  const [downloadingSuricata, setDownloadingSuricata] = createSignal(false);
  const [downloadingNpcap, setDownloadingNpcap] = createSignal(false);
  const [downloadingEvebox, setDownloadingEvebox] = createSignal(false);
  const [networkInterfaces, setNetworkInterfaces] = createSignal<string[]>([]);
  const [selectedInterface, setSelectedInterface] = createSignal("");
  const [suricataRunning, setSuricataRunning] = createSignal(false);
  const [suricataOutput, setSuricataOutput] = createSignal<string[]>([]);
  const [eveEvents, setEveEvents] = createSignal<any[]>([]);
  const [activeTab, setActiveTab] = createSignal<
    "output" | "events" | "alerts" | "metrics" | "evebox"
  >("output");
  const [interfaceDropdownOpen, setInterfaceDropdownOpen] = createSignal(false);
  const [updatingRules, setUpdatingRules] = createSignal(false);
  const [rulesUpdateProgress, setRulesUpdateProgress] = createSignal(0);
  const [rulesUpdateDetails, setRulesUpdateDetails] = createSignal<{
    url?: string;
    downloaded?: number;
    total?: number;
    current_source?: number;
    total_sources?: number;
  }>({});
  const [latestStatsEvent, setLatestStatsEvent] = createSignal<any>(null);
  const [hideZeroValues, setHideZeroValues] = createSignal(false);
  const [statsKeyFilter, setStatsKeyFilter] = createSignal("");
  const [eveboxRunning, setEveboxRunning] = createSignal(false);
  const [eveboxOutput, setEveboxOutput] = createSignal<string[]>([]);

  // Helper functions to parse interface string
  const parseInterface = (interfaceStr: string) => {
    const parts = interfaceStr.split(" - ");
    return {
      name: parts[0] || "",
      ip: parts[1] || "",
      guid: parts[2] || "",
    };
  };

  const getInterfaceDisplay = (interfaceStr: string) => {
    const { name, ip } = parseInterface(interfaceStr);
    return `${name} - ${ip}`;
  };

  // Helper function to format bytes
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  // Helper function to flatten JSON objects
  const flattenObject = (
    obj: any,
    prefix: string = "",
  ): { [key: string]: any } => {
    const flattened: { [key: string]: any } = {};

    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const newKey = prefix ? `${prefix}.${key}` : key;

        if (obj[key] === null || obj[key] === undefined) {
          flattened[newKey] = obj[key];
        } else if (typeof obj[key] === "object" && !Array.isArray(obj[key])) {
          Object.assign(flattened, flattenObject(obj[key], newKey));
        } else if (Array.isArray(obj[key])) {
          flattened[newKey] = JSON.stringify(obj[key]);
        } else {
          flattened[newKey] = obj[key];
        }
      }
    }

    return flattened;
  };

  // Set up event listeners for download progress
  const unlistenSuricata = listen<number>(
    "download-progress-suricata",
    (event) => {
      setSuricataProgress(event.payload);
    },
  );

  const unlistenNpcap = listen<number>("download-progress-npcap", (event) => {
    setNpcapProgress(event.payload);
  });

  const unlistenEvebox = listen<number>("download-progress-evebox", (event) => {
    setEveboxProgress(event.payload);
  });

  const unlistenOutput = listen<{ type: string; line: string }>(
    "suricata-output",
    (event) => {
      setSuricataOutput((prev) => {
        const newOutput = [...prev, event.payload.line];
        // Keep only last 1000 lines
        if (newOutput.length > 1000) {
          return newOutput.slice(-1000);
        }
        return newOutput;
      });

      // Always auto-scroll
      setTimeout(() => {
        const outputDiv = document.getElementById("suricata-output-panel");
        if (outputDiv) {
          outputDiv.scrollTop = outputDiv.scrollHeight;
        }
      }, 10);
    },
  );

  const unlistenEveJson = listen<any>("eve-json-event", (event) => {
    // Update latest stats event if it's a stats event
    if (event.payload.event_type === "stats") {
      setLatestStatsEvent(event.payload);
    }

    setEveEvents((prev) => {
      const newEvents = [...prev, event.payload];
      // Keep only last 300 events
      if (newEvents.length > 300) {
        return newEvents.slice(-300);
      }
      return newEvents;
    });

    // Auto-scroll events panel if on events tab
    if (activeTab() === "events") {
      setTimeout(() => {
        const eventsDiv = document.getElementById("eve-events-panel");
        if (eventsDiv) {
          eventsDiv.scrollTop = eventsDiv.scrollHeight;
        }
      }, 10);
    }

    // Auto-scroll alerts panel if on alerts tab and event is an alert
    if (activeTab() === "alerts" && event.payload.event_type === "alert") {
      setTimeout(() => {
        const alertsDiv = document.getElementById("eve-alerts-panel");
        if (alertsDiv) {
          alertsDiv.scrollTop = alertsDiv.scrollHeight;
        }
      }, 10);
    }
  });

  const unlistenRulesUpdate = listen<{
    type: string;
    message?: string;
    progress?: number;
    url?: string;
    downloaded?: number;
    total?: number;
    current_source?: number;
    total_sources?: number;
  }>("rules-update-progress", (event) => {
    if (
      event.payload.type === "download" &&
      event.payload.progress !== undefined
    ) {
      setRulesUpdateProgress(event.payload.progress);
      setRulesUpdateDetails({
        url: event.payload.url,
        downloaded: event.payload.downloaded,
        total: event.payload.total,
        current_source: rulesUpdateDetails().current_source,
        total_sources: rulesUpdateDetails().total_sources,
      });
    } else if (event.payload.type === "info") {
      setSuricataOutput((prev) => [
        ...prev,
        `[Rules Update] ${event.payload.message}`,
      ]);
      if (event.payload.current_source !== undefined) {
        setRulesUpdateDetails({
          ...rulesUpdateDetails(),
          current_source: event.payload.current_source,
          total_sources: event.payload.total_sources,
        });
      }
      // Auto-scroll output
      setTimeout(() => {
        const outputDiv = document.getElementById("suricata-output-panel");
        if (outputDiv) {
          outputDiv.scrollTop = outputDiv.scrollHeight;
        }
      }, 10);
    } else if (event.payload.type === "complete") {
      setSuricataOutput((prev) => [
        ...prev,
        `[Rules Update] ${event.payload.message}`,
      ]);
      setUpdatingRules(false);
      setRulesUpdateProgress(0);
      setRulesUpdateDetails({});
      // Auto-scroll output
      setTimeout(() => {
        const outputDiv = document.getElementById("suricata-output-panel");
        if (outputDiv) {
          outputDiv.scrollTop = outputDiv.scrollHeight;
        }
      }, 10);
    }
  });

  const unlistenEveboxOutput = listen<{ type: string; line: string }>(
    "evebox-output",
    (event) => {
      setEveboxOutput((prev) => {
        const newOutput = [...prev, event.payload.line];
        // Keep only last 1000 lines
        if (newOutput.length > 1000) {
          return newOutput.slice(-1000);
        }
        return newOutput;
      });

      // Always auto-scroll
      setTimeout(() => {
        const outputDiv = document.getElementById("evebox-output-panel");
        if (outputDiv) {
          outputDiv.scrollTop = outputDiv.scrollHeight;
        }
      }, 10);
    },
  );

  // Clean up listeners
  onCleanup(async () => {
    (await unlistenSuricata)();
    (await unlistenNpcap)();
    (await unlistenEvebox)();
    (await unlistenOutput)();
    (await unlistenEveJson)();
    (await unlistenRulesUpdate)();
    (await unlistenEveboxOutput)();
  });

  // Load network interfaces on mount
  onMount(async () => {
    try {
      const interfaces = await invoke<string[]>("get_network_interfaces");
      setNetworkInterfaces(interfaces);
      // Only select interfaces with GUID
      const interfacesWithGuid = interfaces.filter((iface) => {
        const parsed = parseInterface(iface);
        return (
          parsed.guid &&
          parsed.guid.trim() !== "" &&
          parsed.guid !== "GUID not found"
        );
      });
      if (interfacesWithGuid.length > 0) {
        setSelectedInterface(interfacesWithGuid[0]);
      }
    } catch (error) {
      console.error("Failed to get network interfaces:", error);
    }

    // Check Suricata and EveBox status periodically
    const checkStatus = async () => {
      try {
        const isRunning = await invoke<boolean>("check_suricata_status");
        setSuricataRunning(isRunning);
      } catch (error) {
        console.error("Failed to check Suricata status:", error);
      }

      try {
        const isEveboxRunning = await invoke<boolean>("check_evebox_status");
        setEveboxRunning(isEveboxRunning);
      } catch (error) {
        console.error("Failed to check EveBox status:", error);
      }
    };

    // Check immediately
    checkStatus();

    // Check every 2 seconds
    const interval = setInterval(checkStatus, 2000);

    // Clean up interval on unmount
    onCleanup(() => clearInterval(interval));
  });

  const appWindow = getCurrentWindow();

  return (
    <>
      <nav class="navbar">
        <div class="navbar-content">
          <div class="navbar-left">
            <div class="navbar-brand">
              <span class="navbar-logo">🦫</span>
              <span class="navbar-title">Meerkat Desktop</span>
            </div>
          </div>

          <div class="navbar-center"></div>

          <div class="navbar-right">
            <div class="navbar-controls">
              <button
                class={`navbar-btn control-btn ${suricataRunning() ? "stop" : "start"}`}
                onClick={async () => {
                  if (suricataRunning()) {
                    // Stop Suricata
                    try {
                      console.log("Stopping Suricata...");
                      const result = await invoke("stop_suricata_with_output");
                      console.log(result);
                      // Stop tailing eve.json
                      await invoke("stop_eve_json_tail");
                    } catch (error) {
                      console.error("Failed to stop Suricata:", error);
                      alert(`Failed to stop Suricata: ${error}`);
                    }
                  } else {
                    // Start Suricata
                    try {
                      console.log("Starting Suricata...");
                      setSuricataOutput([]);
                      setEveEvents([]);
                      const result = await invoke(
                        "start_suricata_with_output",
                        {
                          selectedInterface: selectedInterface(),
                        },
                      );
                      console.log(result);
                      // Start tailing eve.json
                      await invoke("start_eve_json_tail");
                    } catch (error) {
                      console.error("Failed to start Suricata:", error);
                      alert(`Failed to start Suricata: ${error}`);
                    }
                  }
                }}
              >
                {suricataRunning() ? (
                  <>
                    Stop
                    <br />
                    Suricata
                  </>
                ) : (
                  <>
                    Start
                    <br />
                    Suricata
                  </>
                )}
              </button>
              <button
                class={`navbar-btn control-btn ${updatingRules() ? "updating" : "update-rules"}`}
                onClick={async () => {
                  try {
                    // Switch to Output tab
                    setActiveTab("output");
                    setUpdatingRules(true);
                    setRulesUpdateProgress(0);
                    setRulesUpdateDetails({});
                    setSuricataOutput((prev) => [
                      ...prev,
                      "[Rules Update] Starting rules update...",
                    ]);
                    const result = await invoke("update_rules");
                    console.log(result);
                  } catch (error) {
                    console.error("Failed to update rules:", error);
                    setSuricataOutput((prev) => [
                      ...prev,
                      `[Rules Update] Error: ${error}`,
                    ]);
                    setUpdatingRules(false);
                    setRulesUpdateProgress(0);
                  }
                }}
                disabled={updatingRules()}
              >
                {updatingRules() ? (
                  <span style={{ "white-space": "nowrap" }}>
                    {rulesUpdateDetails().current_source &&
                    rulesUpdateDetails().total_sources
                      ? `[${rulesUpdateDetails().current_source}/${rulesUpdateDetails().total_sources}] `
                      : ""}
                    {rulesUpdateProgress()}%
                  </span>
                ) : (
                  <>
                    Update
                    <br />
                    Rules
                  </>
                )}
              </button>
              <button
                class={`navbar-btn control-btn ${eveboxRunning() ? "evebox" : "evebox"}`}
                onClick={async () => {
                  if (eveboxRunning()) {
                    // Open EveBox in browser
                    try {
                      await invoke("open_evebox_url");
                    } catch (error) {
                      console.error("Failed to open EveBox:", error);
                      alert(`Failed to open EveBox: ${error}`);
                    }
                  } else {
                    // Start EveBox
                    try {
                      console.log("Starting EveBox...");
                      setEveboxOutput([]);
                      const result = await invoke("start_evebox_with_output");
                      console.log(result);
                    } catch (error) {
                      console.error("Failed to start EveBox:", error);
                      alert(`Failed to start EveBox: ${error}`);
                    }
                  }
                }}
              >
                {eveboxRunning() ? (
                  <>
                    Goto
                    <br />
                    EveBox
                  </>
                ) : (
                  <>
                    Start
                    <br />
                    EveBox
                  </>
                )}
              </button>
            </div>
            <div class="navbar-install-dropdown">
              <div class="dropdown">
                <button class="navbar-btn dropdown-toggle">
                  Install
                  <svg
                    class="dropdown-arrow"
                    width="12"
                    height="12"
                    viewBox="0 0 12 12"
                  >
                    <path fill="currentColor" d="M6 8L2 4h8z" />
                  </svg>
                </button>
                <div class="dropdown-menu">
                  <button
                    class="dropdown-item"
                    onClick={async () => {
                      try {
                        setDownloadingSuricata(true);
                        setSuricataProgress(0);
                        const result = await invoke("install_suricata");
                        console.log(result);
                      } catch (error) {
                        console.error("Failed to install Suricata:", error);
                      } finally {
                        setDownloadingSuricata(false);
                        setSuricataProgress(0);
                      }
                    }}
                    disabled={downloadingSuricata()}
                  >
                    <span class="dropdown-item-text">
                      Suricata
                      {downloadingSuricata() && (
                        <span class="download-progress">
                          {" "}
                          ({suricataProgress()}%)
                        </span>
                      )}
                    </span>
                  </button>
                  <button
                    class="dropdown-item"
                    onClick={async () => {
                      try {
                        setDownloadingNpcap(true);
                        setNpcapProgress(0);
                        const result = await invoke("install_npcap");
                        console.log(result);
                      } catch (error) {
                        console.error("Failed to install NPCap:", error);
                      } finally {
                        setDownloadingNpcap(false);
                        setNpcapProgress(0);
                      }
                    }}
                    disabled={downloadingNpcap()}
                  >
                    <span class="dropdown-item-text">
                      NPCap
                      {downloadingNpcap() && (
                        <span class="download-progress">
                          {" "}
                          ({npcapProgress()}%)
                        </span>
                      )}
                    </span>
                  </button>
                  <button
                    class="dropdown-item"
                    onClick={async () => {
                      try {
                        setDownloadingEvebox(true);
                        setEveboxProgress(0);
                        const result = await invoke("install_evebox");
                        console.log(result);
                      } catch (error) {
                        console.error("Failed to install EveBox:", error);
                      } finally {
                        setDownloadingEvebox(false);
                        setEveboxProgress(0);
                      }
                    }}
                    disabled={downloadingEvebox()}
                  >
                    <span class="dropdown-item-text">
                      EveBox
                      {downloadingEvebox() && (
                        <span class="download-progress">
                          {" "}
                          ({eveboxProgress()}%)
                        </span>
                      )}
                    </span>
                  </button>
                </div>
              </div>
            </div>

            {/* Interface Selector Dropdown */}
            <div class="navbar-dropdown">
              <button
                class={`navbar-dropdown-toggle ${interfaceDropdownOpen() ? "active" : ""}`}
                onClick={() =>
                  setInterfaceDropdownOpen(!interfaceDropdownOpen())
                }
              >
                <svg
                  class="icon"
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                >
                  <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                  <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
                  <line x1="12" y1="22.08" x2="12" y2="12"></line>
                </svg>
                <span>
                  {selectedInterface()
                    ? getInterfaceDisplay(selectedInterface())
                    : "Select Interface"}
                </span>
                <svg
                  class="chevron"
                  width="12"
                  height="12"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                >
                  <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
              </button>
              <div
                class={`navbar-dropdown-menu ${interfaceDropdownOpen() ? "show" : ""}`}
              >
                <For
                  each={networkInterfaces().filter((iface) => {
                    const parsed = parseInterface(iface);
                    return (
                      parsed.guid &&
                      parsed.guid.trim() !== "" &&
                      parsed.guid !== "GUID not found"
                    );
                  })}
                >
                  {(iface) => {
                    const parsed = parseInterface(iface);
                    return (
                      <button
                        class={`dropdown-item ${selectedInterface() === iface ? "selected" : ""}`}
                        onClick={() => {
                          setSelectedInterface(iface);
                          setInterfaceDropdownOpen(false);
                        }}
                      >
                        <div class="interface-item">
                          <div class="interface-name">{parsed.name}</div>
                          <div class="interface-details">
                            <span class="interface-ip">{parsed.ip}</span>
                            <span class="interface-guid">{parsed.guid}</span>
                          </div>
                        </div>
                      </button>
                    );
                  }}
                </For>
              </div>
            </div>

            <div class="window-controls">
              <button
                class="window-control minimize"
                onClick={() => appWindow.minimize()}
                aria-label="Minimize"
              >
                <svg width="10" height="1" viewBox="0 0 10 1">
                  <rect fill="currentColor" width="10" height="1" />
                </svg>
              </button>
              <button
                class="window-control maximize"
                onClick={() => appWindow.toggleMaximize()}
                aria-label="Maximize"
              >
                <svg width="10" height="10" viewBox="0 0 10 10">
                  <path fill="currentColor" d="M0,0v10h10V0H0z M9,9H1V1h8V9z" />
                </svg>
              </button>
              <button
                class="window-control close"
                onClick={() => appWindow.close()}
                aria-label="Close"
              >
                <svg width="10" height="10" viewBox="0 0 10 10">
                  <path
                    fill="currentColor"
                    d="M10,0.91L9.09,0L5,4.09L0.91,0L0,0.91L4.09,5L0,9.09L0.91,10L5,5.91L9.09,10L10,9.09L5.91,5L10,0.91z"
                  />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main class="container">
        <div class="control-section output-section">
          <div class="tabs-header">
            <button
              class={`tab-button ${activeTab() === "output" ? "active" : ""}`}
              onClick={() => {
                setActiveTab("output");
                // Scroll output to bottom when switching to output tab
                setTimeout(() => {
                  const outputDiv = document.getElementById(
                    "suricata-output-panel",
                  );
                  if (outputDiv) {
                    outputDiv.scrollTop = outputDiv.scrollHeight;
                  }
                }, 10);
              }}
            >
              Output
            </button>
            <button
              class={`tab-button ${activeTab() === "events" ? "active" : ""}`}
              onClick={() => {
                setActiveTab("events");
                // Scroll events to bottom when switching to events tab
                setTimeout(() => {
                  const eventsDiv = document.getElementById("eve-events-panel");
                  if (eventsDiv) {
                    eventsDiv.scrollTop = eventsDiv.scrollHeight;
                  }
                }, 10);
              }}
            >
              Events
            </button>
            <button
              class={`tab-button ${activeTab() === "alerts" ? "active" : ""}`}
              onClick={() => {
                setActiveTab("alerts");
                // Scroll alerts to bottom when switching to alerts tab
                setTimeout(() => {
                  const alertsDiv = document.getElementById("eve-alerts-panel");
                  if (alertsDiv) {
                    alertsDiv.scrollTop = alertsDiv.scrollHeight;
                  }
                }, 10);
              }}
            >
              Alerts
            </button>
            <button
              class={`tab-button ${activeTab() === "metrics" ? "active" : ""}`}
              onClick={() => {
                setActiveTab("metrics");
              }}
            >
              Metrics
            </button>
            <button
              class={`tab-button ${activeTab() === "evebox" ? "active" : ""}`}
              onClick={() => {
                setActiveTab("evebox");
                // Scroll evebox output to bottom when switching to evebox tab
                setTimeout(() => {
                  const outputDiv = document.getElementById(
                    "evebox-output-panel",
                  );
                  if (outputDiv) {
                    outputDiv.scrollTop = outputDiv.scrollHeight;
                  }
                }, 10);
              }}
            >
              EveBox
            </button>
          </div>

          <Show when={activeTab() === "output"}>
            <div id="suricata-output-panel" class="output-panel">
              <For each={suricataOutput()}>
                {(line) => <div class="output-line">{line}</div>}
              </For>
              <Show when={updatingRules() && rulesUpdateDetails().url}>
                <div class="rules-update-progress">
                  <div class="progress-url">{rulesUpdateDetails().url}</div>
                  <div class="progress-bar-container">
                    <div
                      class="progress-bar"
                      style={{ width: `${rulesUpdateProgress()}%` }}
                    />
                  </div>
                  <div class="progress-details">
                    <Show
                      when={
                        rulesUpdateDetails().downloaded &&
                        rulesUpdateDetails().total
                      }
                    >
                      <span>
                        {formatBytes(rulesUpdateDetails().downloaded!)} /{" "}
                        {formatBytes(rulesUpdateDetails().total!)}
                      </span>
                    </Show>
                    <span>{rulesUpdateProgress()}%</span>
                  </div>
                </div>
              </Show>
            </div>
          </Show>

          <Show when={activeTab() === "events"}>
            <div id="eve-events-panel" class="output-panel events-panel">
              <For
                each={eveEvents().filter(
                  (event) => event.event_type !== "stats",
                )}
              >
                {(event) => (
                  <div class="event-item">
                    <div class="event-timestamp">
                      {event.timestamp || "No timestamp"}
                    </div>
                    <div class="event-type">
                      {event.event_type || "Unknown"}
                    </div>
                    <pre class="event-details">{JSON.stringify(event)}</pre>
                  </div>
                )}
              </For>
            </div>
          </Show>

          <Show when={activeTab() === "alerts"}>
            <div id="eve-alerts-panel" class="output-panel events-panel">
              <For
                each={eveEvents().filter(
                  (event) => event.event_type === "alert",
                )}
              >
                {(event) => (
                  <div class="event-item alert-item">
                    <div class="event-timestamp">
                      {event.timestamp || "No timestamp"}
                    </div>
                    <div class="event-type">
                      Alert: {event.alert?.signature || "Unknown"}
                    </div>
                    <div class="alert-severity">
                      Severity: {event.alert?.severity || "Unknown"}
                    </div>
                    <pre class="event-details">{JSON.stringify(event)}</pre>
                  </div>
                )}
              </For>
            </div>
          </Show>

          <Show when={activeTab() === "metrics"}>
            <div id="eve-stats-panel" class="output-panel stats-panel">
              <Show
                when={latestStatsEvent()}
                fallback={<div class="no-stats">No stats available yet</div>}
              >
                <div class="stats-controls">
                  <input
                    type="text"
                    class="stats-filter-input"
                    placeholder="Filter keys..."
                    value={statsKeyFilter()}
                    onInput={(e) => setStatsKeyFilter(e.currentTarget.value)}
                  />
                  <label class="stats-checkbox-label">
                    <input
                      type="checkbox"
                      checked={hideZeroValues()}
                      onChange={(e) =>
                        setHideZeroValues(e.currentTarget.checked)
                      }
                    />
                    Hide zero values
                  </label>
                </div>
                <div class="stats-table">
                  <table>
                    <thead>
                      <tr>
                        <th>Metric</th>
                        <th>Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For
                        each={Object.entries(
                          flattenObject(latestStatsEvent()),
                        ).filter(([key, value]) => {
                          // Hide event_type key
                          if (key === "event_type") return false;

                          // Apply key filter
                          if (
                            statsKeyFilter() &&
                            !key
                              .toLowerCase()
                              .includes(statsKeyFilter().toLowerCase())
                          ) {
                            return false;
                          }

                          // Apply zero value filter
                          if (
                            hideZeroValues() &&
                            (value === 0 || value === "0")
                          ) {
                            return false;
                          }

                          return true;
                        })}
                      >
                        {([key, value]) => (
                          <tr>
                            <td class="stats-key">{key}</td>
                            <td class="stats-value">{String(value)}</td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
            </div>
          </Show>

          <Show when={activeTab() === "evebox"}>
            <div id="evebox-output-panel" class="output-panel">
              <For each={eveboxOutput()}>
                {(line) => <div class="output-line">{line}</div>}
              </For>
            </div>
          </Show>
        </div>

        <footer class="app-footer">
          <div class="footer-content">
            <div class="footer-left">
              <span
                class="status-indicator"
                classList={{
                  running: suricataRunning(),
                  stopped: !suricataRunning(),
                }}
              >
                <span class="status-dot"></span>
                {suricataRunning() ? "Suricata running" : "Suricata stopped"}
              </span>
              <span
                class="status-indicator"
                classList={{
                  running: eveboxRunning(),
                  stopped: !eveboxRunning(),
                }}
              >
                <span class="status-dot"></span>
                {eveboxRunning() ? "EveBox running" : "EveBox stopped"}
              </span>
            </div>
            <div class="footer-right">
              <span class="footer-warning">
                ⚠️ EXPERIMENTAL - Use at your own risk
              </span>
              <span class="footer-version">v0.1.0</span>
            </div>
          </div>
        </footer>
      </main>
    </>
  );
}

export default App;

document.addEventListener("DOMContentLoaded", () => {
  const panel = document.querySelector("[data-agent-dashboard]");
  if (!panel) return;

  const status = panel.querySelector("[data-agent-status]");
  const eventsBody = panel.querySelector("[data-agent-events]");
  const onlineValue = panel.querySelector("[data-agent-online]");
  const connectedValue = panel.querySelector("[data-agent-count]");
  const alertValue = panel.querySelector("[data-agent-alert-count]");
  const filterForm = panel.querySelector("[data-agent-filter-form]");
  const filterInput = panel.querySelector("[data-agent-filter]");
  const clearFilter = panel.querySelector("[data-agent-clear-filter]");
  const eventsWrap = panel.querySelector("[data-agent-events-wrap]");
  const statsWrap = panel.querySelector("[data-agent-stats-wrap]");
  const statsBody = panel.querySelector("[data-agent-stats]");
  const statsHeading = panel.querySelector("[data-agent-stats-heading]");
  let activeFilter = "";

  const cell = (row, value, className, fieldName) => {
    const element = document.createElement("td");
    if (className) element.className = className;
    if (fieldName) element.dataset.field = fieldName;
    element.textContent = value == null ? "" : String(value);
    row.append(element);
    return element;
  };

  const displayTime = (value) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  };

  const showMessage = (message) => {
    const row = document.createElement("tr");
    const messageCell = cell(row, message);
    messageCell.colSpan = panel.querySelector("thead tr")?.children.length || 6;
    eventsBody.replaceChildren(row);
  };

  const renderEvents = (events, displayFields) => {
    statsWrap.hidden = true;
    eventsWrap.hidden = false;
    const selectedFields = Array.isArray(displayFields) ? new Set(displayFields) : null;
    panel.querySelectorAll("[data-field]").forEach((element) => {
      element.hidden = selectedFields ? !selectedFields.has(element.dataset.field) : false;
    });
    if (!events.length) {
      showMessage(activeFilter ? "No events match this query. Try changing the filter." : "No events received yet. Connect a Windows agent to show real device activity here.");
      return;
    }
    const rows = events.map((event) => {
      const row = document.createElement("tr");
      cell(row, event.agent_name, null, "device");
      if (Object.hasOwn(event, "account_email")) cell(row, event.account_email, null, "account_email");
      cell(row, event.event_id, null, "event_id");
      cell(row, event.log_source, null, "log_source");
      cell(row, event.record_id, null, "record_id");
      cell(row, event.event_name, null, "event_name");
      cell(row, event.source_port ? `${event.source_ip}:${event.source_port}` : event.source_ip, null, "source_address");
      cell(row, event.destination_port ? `${event.destination_ip}:${event.destination_port}` : event.destination_ip, null, "destination_address");
      cell(row, [event.network_direction, event.network_protocol].filter(Boolean).join(" / ") || "Not present", null, "network_context");
      const severity = cell(row, event.alert_level, null, "alert_level");
      if (["High", "Medium", "Low", "Info", "Event"].includes(event.alert_level)) {
        severity.classList.add("agent-severity", `agent-severity-${event.alert_level.toLowerCase()}`);
      }
      severity.title = event.alert_text || "";
      cell(row, displayTime(event.event_time), null, "event_time");
      const detailsCell = cell(row, "", null, "details");
      const details = document.createElement("details");
      details.className = "agent-event-details";
      const summary = document.createElement("summary");
      summary.textContent = "View";
      const detailText = document.createElement("p");
      detailText.textContent = event.alert_level === "Event"
        ? "No alert rule matched this event."
        : (event.alert_text || "Review this event in Windows Event Viewer.");
      details.append(summary, detailText);
      detailsCell.append(details);
      return row;
    });
    eventsBody.replaceChildren(...rows);
  };

  const renderStats = (stats, fieldName) => {
    eventsWrap.hidden = true;
    statsWrap.hidden = false;
    statsHeading.textContent = `${fieldName || "Group"} (grouped results)`;
    if (!stats.length) {
      const row = document.createElement("tr");
      const empty = cell(row, "No matching results");
      empty.colSpan = 2;
      statsBody.replaceChildren(row);
      return;
    }
    const rows = stats.map((item) => {
      const row = document.createElement("tr");
      cell(row, item.group_value);
      cell(row, item.count);
      return row;
    });
    statsBody.replaceChildren(...rows);
  };

  const refresh = async () => {
    try {
      const url = new URL(panel.dataset.apiUrl, window.location.href);
      if (activeFilter) url.searchParams.set("q", activeFilter);
      const response = await fetch(url, { credentials: "same-origin", cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(response.status === 401 ? "Sign in again to view your agent feed." : (data.error || "Agent feed is temporarily unavailable."));
      onlineValue.textContent = data.online;
      connectedValue.textContent = data.connected;
      alertValue.textContent = data.alerts_24h;
      if (Array.isArray(data.stats)) renderStats(data.stats, data.stats_field);
      else renderEvents(Array.isArray(data.events) ? data.events : [], data.display_fields);
      status.textContent = data.connected === 0
        ? "No Windows agent is connected. Create a token and start the agent on your Windows PC."
        : `${data.online} device(s) online; ${Array.isArray(data.stats) ? data.stats.length + " grouped result(s)" : data.events.length + " matching event(s)"}; refreshed just now.`;
      status.classList.toggle("agent-feed-online", data.online > 0);
      status.classList.toggle("agent-feed-warning", data.connected > data.online);
    } catch (error) {
      status.textContent = error.message || "Agent feed is temporarily unavailable.";
      status.classList.remove("agent-feed-online");
      status.classList.add("agent-feed-warning");
      statsWrap.hidden = true;
      eventsWrap.hidden = false;
      showMessage(error.message || "Agent feed is temporarily unavailable.");
    }
  };

  filterForm.addEventListener("submit", (event) => {
    event.preventDefault();
    activeFilter = filterInput.value.trim();
    refresh();
  });
  clearFilter.addEventListener("click", () => {
    filterInput.value = "";
    activeFilter = "";
    refresh();
  });

  refresh();
  window.setInterval(refresh, 15000);
});

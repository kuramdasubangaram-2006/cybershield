document.addEventListener("DOMContentLoaded", () => {
  const panel = document.querySelector("[data-agent-dashboard]");
  if (!panel) return;

  const status = panel.querySelector("[data-agent-status]");
  const eventsBody = panel.querySelector("[data-agent-events]");
  const onlineValue = panel.querySelector("[data-agent-online]");
  const connectedValue = panel.querySelector("[data-agent-count]");
  const alertValue = panel.querySelector("[data-agent-alert-count]");

  const cell = (row, value, className) => {
    const element = document.createElement("td");
    if (className) element.className = className;
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

  const renderEvents = (events) => {
    if (!events.length) {
      showMessage("No events received yet. Connect a Windows agent to show real device activity here.");
      return;
    }
    const rows = events.map((event) => {
      const row = document.createElement("tr");
      cell(row, event.agent_name);
      if (Object.hasOwn(event, "account_email")) cell(row, event.account_email);
      cell(row, event.event_name);
      cell(row, event.source_port ? `${event.source_ip}:${event.source_port}` : event.source_ip);
      cell(row, event.destination_port ? `${event.destination_ip}:${event.destination_port}` : event.destination_ip);
      cell(row, [event.network_direction, event.network_protocol].filter(Boolean).join(" / ") || "Not present");
      const severity = cell(row, event.alert_level);
      if (["High", "Medium", "Low", "Info", "Event"].includes(event.alert_level)) {
        severity.classList.add("agent-severity", `agent-severity-${event.alert_level.toLowerCase()}`);
      }
      severity.title = event.alert_text || "";
      cell(row, displayTime(event.event_time));
      return row;
    });
    eventsBody.replaceChildren(...rows);
  };

  const refresh = async () => {
    try {
      const response = await fetch(panel.dataset.apiUrl, { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 401 ? "Sign in again to view your agent feed." : "Agent feed is temporarily unavailable.");
      const data = await response.json();
      onlineValue.textContent = data.online;
      connectedValue.textContent = data.connected;
      alertValue.textContent = data.alerts_24h;
      renderEvents(Array.isArray(data.events) ? data.events : []);
      status.textContent = data.connected === 0
        ? "No Windows agent is connected. Create a token and start the agent on your Windows PC."
        : `${data.online} device(s) online; refreshed just now.`;
      status.classList.toggle("agent-feed-online", data.online > 0);
      status.classList.toggle("agent-feed-warning", data.connected > data.online);
    } catch (error) {
      status.textContent = error.message || "Agent feed is temporarily unavailable.";
      status.classList.remove("agent-feed-online");
      status.classList.add("agent-feed-warning");
    }
  };

  refresh();
  window.setInterval(refresh, 15000);
});

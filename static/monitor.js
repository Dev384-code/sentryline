"use strict";
let seen = new Set(); let initialized = false;
document.getElementById("notification-permission").addEventListener("click", async () => {
 if (!("Notification" in window)) return;
 const permission = await Notification.requestPermission();
 document.getElementById("notification-permission").textContent = permission === "granted" ? "Browser notifications enabled" : "Browser notifications unavailable";
});
async function refresh() {
 try {
  const response = await fetch("/api/monitor", {cache:"no-store"});
  if (!response.ok) throw new Error("Status request failed");
  const data = await response.json();
  document.getElementById("monitor-state").textContent = data.health === "error" ? "Collection error" : data.collecting ? "Reading Windows events…" : data.health === "waiting_for_events" ? "Waiting for new supported events" : data.running ? "Monitoring" : "Stopped";
  document.getElementById("monitor-error").textContent = data.error || "";
  document.getElementById("monitor-poll").textContent = `Last poll: ${data.last_poll || "Not started"} · Retained events: ${data.retained_events || 0}`;
  document.getElementById("monitor-health-detail").textContent = `Last batch: ${data.last_batch_events || 0} supported events · Channel records scanned: ${data.records_scanned || 0} · Backlog: ${data.backlog_records || 0} channel record IDs · Read time: ${data.poll_elapsed_seconds}s`;
  const diagnostic = data.diagnostic;
  document.getElementById("monitor-diagnostic").textContent = !diagnostic ? "Use Check access to test permissions and recent event availability." : diagnostic.ok ? `Access check ${diagnostic.at}: Security log readable. Recent supported events: ${diagnostic.details.recent_supported_events}. Login successes: ${diagnostic.details.recent_counts["4624"]}, failures: ${diagnostic.details.recent_counts["4625"]}, process events: ${diagnostic.details.recent_counts["4688"]}. Process events with command lines: ${diagnostic.details.process_events_with_command_line}. ${diagnostic.details.note}` : `Access check ${diagnostic.at}: ${diagnostic.error}`;
  const metrics=data.metrics;
  document.getElementById("rate-attempts").textContent=metrics.attempts_per_second_60.toFixed(3);
  document.getElementById("rate-failures").textContent=metrics.failures_per_second_60.toFixed(3);
  document.getElementById("rate-peak").textContent=metrics.peak_attempts_in_one_second;
  document.getElementById("rate-counts").textContent=`${metrics.failures_last_60s} / ${metrics.successes_last_60s}`;
  document.getElementById("activity-freshness").textContent=`Event-time window as of ${metrics.as_of}. Last successful collection: ${data.last_success || "none"}. ${data.running && !data.error ? "" : "Collection is stopped or failing; rates reflect saved evidence and may be incomplete."} ${data.backlog_records ? "Backlog remains; current rates may be undercounted." : ""}`;
  document.getElementById("rate-rule").textContent=`Brute-force rule: at least ${metrics.threshold} failures from the same source address on the same host within ${metrics.window_minutes} minutes triggers critical review; ${metrics.threshold*2} triggers escalation. This is a review threshold, not proof of compromise.`;
  const bars=document.getElementById("attempt-bars");bars.replaceChildren();const max=Math.max(1,...metrics.seconds);
  metrics.seconds.forEach((count,index)=>{const bar=document.createElement("span");bar.style.height=Math.max(2,count/max*54)+"px";bar.title=`${59-index} seconds ago: ${count} attempts`;bars.append(bar);});
  const sources=document.getElementById("rate-sources");sources.replaceChildren();
  const labels={source_unavailable:"Cannot assess source rule: address missing",escalated:"Escalation threshold met · critical review",threshold_met:"Brute-force threshold met · critical review",below_threshold:"Below this rule threshold"};
  for(const source of metrics.sources){const row=document.createElement("tr");for(const value of [`${source.host} / ${source.ip}`,source.failures,source.failures_per_second_60.toFixed(3),source.peak_failures_in_one_second,labels[source.signal]]){const cell=document.createElement("td");cell.textContent=value;row.append(cell);}sources.append(row);}
  if(!metrics.sources.length){const row=document.createElement("tr");const cell=document.createElement("td");cell.colSpan=5;cell.textContent="No collected failures in the current rule window. This does not establish machine safety.";row.append(cell);sources.append(row);}
  document.getElementById("rate-caveats").textContent=`Missing-source failures: ${metrics.unknown_source_failures}. Excluded service logons: ${metrics.service_logons_excluded}. Unusable events: ${metrics.invalid_events}. Future-dated events: ${metrics.future_events}. Showing ${metrics.sources.length} of ${metrics.source_count} sources.`;
  const link = document.getElementById("monitor-report"); link.hidden = !data.latest_run;
  if (data.latest_run) link.href = "/report?run=" + encodeURIComponent(data.latest_run);
  const list = document.getElementById("monitor-notifications"); list.replaceChildren();
  for (const item of [...data.notifications].reverse()) {
   const p = document.createElement("p"); p.textContent = `${item.severity.toUpperCase()} · ${item.at} · ${item.message}`; list.append(p);
   if (initialized && !seen.has(item.key) && "Notification" in window && Notification.permission === "granted") new Notification("Sentryline: " + item.severity, {body:item.message});
   seen.add(item.key);
  }
  if (!data.notifications.length) list.textContent = "No high or critical notifications recorded. This does not establish that the machine is safe.";
  const gaps = document.getElementById("monitor-gaps"); gaps.replaceChildren();
  for (const item of data.gaps) { const p=document.createElement("p");p.textContent=item.at+" · "+item.message;gaps.append(p); }
  initialized=true;
 } catch (error) { document.getElementById("monitor-error").textContent="Unable to refresh collector status. Check the server connection."; }
 setTimeout(refresh,5000);
}
refresh();

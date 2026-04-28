const cpuValue = document.getElementById("cpu-value");
const ramValue = document.getElementById("ram-value");
const timeValue = document.getElementById("time-value");
const cpuBar = document.getElementById("cpu-bar");
const ramBar = document.getElementById("ram-bar");
const cpuStatus = document.getElementById("cpu-status");
const ramStatus = document.getElementById("ram-status");
const threatLevel = document.getElementById("threat-level");
const attemptCount = document.getElementById("attempt-count");
const securityEvents = document.getElementById("security-events");
const securitySource = document.getElementById("security-source");
const securityInsight = document.getElementById("security-insight");
const securityCard = document.querySelector(".security-card");

function updateMeter(element, value) {
    const normalizedValue = Math.max(0, Math.min(100, value));
    element.style.width = `${normalizedValue}%`;
}

function updateStatus(element, value) {
    element.classList.remove("warn", "hot");

    if (value >= 85) {
        element.textContent = "Critical";
        element.classList.add("hot");
        return;
    }

    if (value >= 65) {
        element.textContent = "Elevated";
        element.classList.add("warn");
        return;
    }

    element.textContent = "Nominal";
}

function updateThreatLevel(level) {
    threatLevel.classList.remove("low", "warn", "hot");
    securityCard.classList.remove("threat-low", "threat-medium", "threat-high");
    threatLevel.textContent = level;

    if (level === "HIGH") {
        threatLevel.classList.add("hot");
        securityCard.classList.add("threat-high");
        return;
    }

    if (level === "MEDIUM") {
        threatLevel.classList.add("warn");
        securityCard.classList.add("threat-medium");
        return;
    }

    threatLevel.classList.add("low");
    securityCard.classList.add("threat-low");
}

function createEventRow(event) {
    const row = document.createElement("div");
    row.className = "event-row";
    if (event.rapid) {
        row.classList.add("rapid");
    }

    const eventMeta = document.createElement("div");
    eventMeta.className = "event-meta";

    const eventType = document.createElement("span");
    eventType.textContent = event.type;

    const eventTime = document.createElement("time");
    eventTime.textContent = event.timestamp;

    const eventAccount = document.createElement("span");
    eventAccount.className = "event-account";
    eventAccount.textContent = `Account: ${event.account || "Unknown"}`;

    const eventDelta = document.createElement("span");
    eventDelta.className = "event-delta";
    eventDelta.textContent = event.rapid ? `Rapid: ${event.delta}` : event.delta;

    const eventIp = document.createElement("span");
    eventIp.className = "event-ip";
    eventIp.textContent = event.ip && event.ip !== "N/A" ? event.ip : "No IP";

    eventMeta.append(eventType, eventTime, eventAccount, eventDelta);
    row.append(eventMeta, eventIp);

    return row;
}

function updateSecurityPanel(security) {
    const events = security?.events || [];
    const recentAttempts = security?.recent_attempts ?? events.length;

    attemptCount.textContent = security?.attempts ?? 0;
    securitySource.textContent = `Source: ${security?.source || "unavailable"}`;
    updateThreatLevel(security?.threat_level || "LOW");
    securityInsight.textContent = security?.rapid_detected
        ? `Rapid repeated attempts detected across ${recentAttempts} recent events.`
        : `${recentAttempts} recent failed login events analyzed.`;
    securityEvents.replaceChildren();

    if (!events.length) {
        const emptyState = document.createElement("p");
        emptyState.className = "empty-events";
        emptyState.textContent = "No matching security events found.";
        securityEvents.append(emptyState);
        return;
    }

    events.forEach((event) => {
        securityEvents.append(createEventRow(event));
    });
}

async function loadStats() {
    try {
        const response = await fetch("/api/stats");
        if (!response.ok) {
            throw new Error("Stats request failed");
        }

        const stats = await response.json();

        const cpu = Math.round(stats.cpu);
        const ram = Math.round(stats.ram);

        cpuValue.textContent = `${cpu}%`;
        ramValue.textContent = `${ram}%`;
        timeValue.textContent = stats.time;

        updateMeter(cpuBar, cpu);
        updateMeter(ramBar, ram);
        updateStatus(cpuStatus, cpu);
        updateStatus(ramStatus, ram);
        updateSecurityPanel(stats.security);
    } catch (error) {
        timeValue.textContent = "Offline";
        cpuStatus.textContent = "Offline";
        ramStatus.textContent = "Offline";
        cpuStatus.classList.add("hot");
        ramStatus.classList.add("hot");
        threatLevel.textContent = "Offline";
        threatLevel.classList.add("hot");
        securityCard.classList.add("threat-high");
        securityInsight.textContent = "Security event analysis offline.";
    }
}

loadStats();
setInterval(loadStats, 2000);

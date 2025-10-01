function getCSRFToken() {
  // Look for the token in a hidden input or a meta tag
  const tokenInput = document.querySelector("input[name=csrf_token]");
  if (tokenInput) {
    return tokenInput.value;
  }
  const meta = document.querySelector("meta[name=csrf-token]");
  return meta ? meta.getAttribute("content") : "";
}

function initCalendar(elId, resources, events, slotMin, slotMax, currentUser) {
  const el = document.getElementById(elId);
  const calendar = new FullCalendar.Calendar(el, {
    schedulerLicenseKey: "GPL-My-Project-Is-Open-Source",
    locale: "de",
    height: "auto",
    nowIndicator: true,
    allDaySlot: false,
    slotMinTime: slotMin,
    slotMaxTime: slotMax,
    selectable: true,
    datesAboveResources: true,
    groupByResource: true,
    resources: resources,
    views: {
      resourceTimeGridWeek: {
        type: "resourceTimeGrid",
        duration: { days: 7 },
        buttonText: "Woche"
      }
    },
    initialView: "resourceTimeGridWeek",
    events: events,

    // Selection → open modal
    select: function (info) {
      const modal = new bootstrap.Modal(document.getElementById("confirmModal"));
      document.getElementById("confirmText").textContent =
        `Buchung von ${info.startStr} bis ${info.endStr} für Gerät ${info.resource.title}?`;

      const confirmBtn = document.getElementById("confirmBtn");
      confirmBtn.onclick = async () => {
        const response = await fetch("/book", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCSRFToken()   // 🔹 Send CSRF token here
          },
          body: JSON.stringify({
            start: info.startStr,
            end: info.endStr,
            appliance_id: info.resource.id
          })
        });

        const result = await response.json();
        if (result.success) {
          calendar.addEvent({
            title: currentUser,
            start: info.startStr,
            end: info.endStr,
            resourceId: info.resource.id
          });
        } else {
          alert("Fehler: " + (result.error || "Unbekannt"));
        }
        modal.hide();
      };

      modal.show();
    },

    // Click on event → show details
    eventClick: function (info) {
      alert(
        `Buchung von ${info.event.title}\n` +
        `Von: ${info.event.start.toLocaleString()}\n` +
        `Bis: ${info.event.end.toLocaleString()}`
      );
    }
  });

  calendar.render();
}

window.initTwoCalendars = function (
  washerResources,
  dryerResources,
  washerEvents,
  dryerEvents,
  slotMin,
  slotMax,
  currentUser
) {
  initCalendar("calendar-washer", washerResources, washerEvents, slotMin, slotMax, currentUser);
  initCalendar("calendar-dryer", dryerResources, dryerEvents, slotMin, slotMax, currentUser);
};

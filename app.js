const currentPage = document.body.dataset.page;
const navItems = document.querySelectorAll(".nav-item");
let currentUserProfile = null;

navItems.forEach((item) => {
  const isActive = item.dataset.page === currentPage;
  item.classList.toggle("active", isActive);
  if (isActive) {
    item.setAttribute("aria-current", "page");
  } else {
    item.removeAttribute("aria-current");
  }
});

async function parseApiResponse(response, fallbackMessage) {
  if (response.ok) {
    return response.json();
  }
  if (response.status === 401) {
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }
  let message = fallbackMessage;
  try {
    const data = await response.json();
    if (data && data.error) message = data.error;
  } catch (error) {
    // Ignore JSON parse errors
  }
  throw new Error(message);
}

const topupChartEl = document.getElementById("topup-bar-chart");

if (topupChartEl) {
  const airtimeApprovedChartEl = document.getElementById("airtime-approved-bar-chart");
  const fundsApprovedChartEl = document.getElementById("funds-approved-bar-chart");
  const yearTagEl = document.getElementById("dashboard-year-tag");
  const airtimeHeadEl = document.getElementById("airtime-recipient-monthly-head");
  const airtimeBodyEl = document.getElementById("airtime-recipient-monthly-body");
  const airtimeEmptyEl = document.getElementById("airtime-recipient-monthly-empty");
  const fundsHeadEl = document.getElementById("funds-recipient-monthly-head");
  const fundsBodyEl = document.getElementById("funds-recipient-monthly-body");
  const fundsEmptyEl = document.getElementById("funds-recipient-monthly-empty");
  const dashboardTabs = document.querySelectorAll("[data-dashboard-tab]");
  const dashboardPanels = document.querySelectorAll("[data-dashboard-panel]");

  const formatAmount = (value) =>
    new Intl.NumberFormat("en-US", {
      minimumFractionDigits: 0,
      maximumFractionDigits: 2,
    }).format(Number(value) || 0);

  const renderBarChart = (container, rows, valueKey, toneClass) => {
    if (!container) return;
    const maxValue = rows.reduce(
      (max, row) => Math.max(max, Number(row[valueKey]) || 0),
      0
    );
    const safeMax = maxValue <= 0 ? 1 : maxValue;

    container.innerHTML = rows
      .map((row) => {
        const value = Number(row[valueKey]) || 0;
        const heightPercent = Math.max(2, (value / safeMax) * 100);
        return `
          <div class="bar-slot">
            <div class="bar-value">${formatAmount(value)}</div>
            <div class="bar-track">
              <div class="bar-fill ${toneClass}" style="--target-height:${heightPercent}%"></div>
            </div>
            <div class="bar-label">${row.label}</div>
          </div>
        `;
      })
      .join("");
  };

  const renderRecipientMatrix = (months, rows, headEl, bodyEl, emptyEl) => {
    if (!headEl || !bodyEl || !emptyEl) return;

    headEl.innerHTML = `
      <tr>
        <th>Recipient</th>
        ${months.map((month) => `<th>${month.label}</th>`).join("")}
        <th>Total</th>
      </tr>
    `;

    if (!rows.length) {
      bodyEl.innerHTML = "";
      emptyEl.style.display = "block";
      return;
    }

    emptyEl.style.display = "none";
    bodyEl.innerHTML = rows
      .map((row) => {
        const monthlyCells = months
          .map((month) => {
            const value = Number(row.monthly_totals?.[String(month.month_no)] || 0);
            return `<td>${value > 0 ? formatAmount(value) : "-"}</td>`;
          })
          .join("");

        return `
          <tr>
            <td>${row.recipient_name}</td>
            ${monthlyCells}
            <td>${formatAmount(row.row_total)}</td>
          </tr>
        `;
      })
      .join("");
  };

  const setDashboardTab = (tabKey) => {
    dashboardTabs.forEach((button) => {
      button.classList.toggle("active-tab", button.dataset.dashboardTab === tabKey);
    });
    dashboardPanels.forEach((panel) => {
      panel.classList.toggle("active-panel", panel.dataset.dashboardPanel === tabKey);
    });
  };

  const loadDashboard = async () => {
    try {
      const response = await fetch("/api/dashboard");
      const payload = await parseApiResponse(response, "Unable to load dashboard.");
      const months = Array.isArray(payload.months) ? payload.months : [];

      if (yearTagEl) {
        yearTagEl.textContent = String(payload.year || new Date().getFullYear());
      }

      renderBarChart(topupChartEl, months, "topups", "topups");
      renderBarChart(airtimeApprovedChartEl, months, "approved_airtime", "approved");
      renderBarChart(fundsApprovedChartEl, months, "approved_funds", "approved");
      renderRecipientMatrix(months, payload.airtime?.recipient_matrix || [], airtimeHeadEl, airtimeBodyEl, airtimeEmptyEl);
      renderRecipientMatrix(months, payload.funds?.recipient_matrix || [], fundsHeadEl, fundsBodyEl, fundsEmptyEl);
    } catch (error) {
      window.alert(error.message || "Unable to load dashboard.");
    }
  };

  dashboardTabs.forEach((button) => {
    button.addEventListener("click", () => {
      setDashboardTab(button.dataset.dashboardTab);
    });
  });

  setDashboardTab("airtime");
  loadDashboard();
}

const initRecipientsModule = (config) => {
  const {
    apiBase,
    formId,
    nameInputId,
    phoneInputId,
    carrierSelectId,
    submitButtonId,
    cancelButtonId,
    titleId,
    subtitleId,
    tableBodyId,
    emptyStateId,
    countBadgeId,
    searchInputId,
    pageSizeSelectId,
    paginationId,
    uploadModalId,
    openUploadModalId,
    downloadTemplateId,
    uploadFormId,
    uploadFileId,
    uploadFeedbackId,
    uploadProcessingId,
    uploadSubmitId,
    uploadSubmitLabelFallback,
    subtitleDefault,
    deleteConfirmLabel,
  } = config;

  const recipientForm = document.getElementById(formId);
  if (!recipientForm) return;

  let recipients = [];
  let editingRecipientId = null;
  let isSaving = false;
  const phonePattern = /^\+250\d{9}$/;

  const nameInput = document.getElementById(nameInputId);
  const phoneInput = document.getElementById(phoneInputId);
  const carrierSelect = document.getElementById(carrierSelectId);
  const submitButton = document.getElementById(submitButtonId);
  const cancelButton = document.getElementById(cancelButtonId);
  const titleEl = document.getElementById(titleId);
  const subtitleEl = document.getElementById(subtitleId);
  const tableBody = document.getElementById(tableBodyId);
  const emptyState = document.getElementById(emptyStateId);
  const countBadge = document.getElementById(countBadgeId);
  const searchInput = document.getElementById(searchInputId);
  const pageSizeSelect = document.getElementById(pageSizeSelectId);
  const paginationEl = document.getElementById(paginationId);
  const uploadModal = document.getElementById(uploadModalId);
  const openUploadModalButton = document.getElementById(openUploadModalId);
  const downloadTemplateButton = document.getElementById(downloadTemplateId);
  const uploadModalCloseButtons = uploadModal?.querySelectorAll("[data-close]");
  const uploadForm = document.getElementById(uploadFormId);
  const uploadFileInput = document.getElementById(uploadFileId);
  const uploadFeedback = document.getElementById(uploadFeedbackId);
  const uploadProcessing = document.getElementById(uploadProcessingId);
  const uploadSubmitButton = document.getElementById(uploadSubmitId);
  const uploadSubmitLabel = uploadSubmitButton?.textContent || uploadSubmitLabelFallback;
  const MAX_UPLOAD_ROWS = 50;
  const expectedTemplateHeaders = ["name", "phone number", "carier"];
  let currentPageIndex = 1;
  let pageSize = Number(pageSizeSelect?.value || 8);
  let searchTerm = "";

  const setSavingState = (saving) => {
    isSaving = saving;
    submitButton.disabled = saving;
    submitButton.textContent = saving
      ? editingRecipientId === null
        ? "Saving..."
        : "Updating..."
      : editingRecipientId === null
      ? "Add recipient"
      : "Save changes";
  };

  const resetForm = () => {
    recipientForm.reset();
    if (carrierSelect) carrierSelect.value = "MTN";
    editingRecipientId = null;
    titleEl.textContent = "New recipient";
    subtitleEl.textContent = subtitleDefault;
    cancelButton.hidden = true;
    setSavingState(false);
    phoneInput.setCustomValidity("");
  };

  const clearUploadFeedback = () => {
    if (!uploadFeedback) return;
    uploadFeedback.hidden = true;
    uploadFeedback.classList.remove("error", "success");
    uploadFeedback.innerHTML = "";
  };

  const showUploadFeedback = (type, title, items = []) => {
    if (!uploadFeedback) return;

    uploadFeedback.innerHTML = "";
    uploadFeedback.classList.remove("error", "success");
    uploadFeedback.classList.add(type);

    const message = document.createElement("p");
    message.textContent = title;
    uploadFeedback.appendChild(message);

    if (items.length > 0) {
      const list = document.createElement("ul");
      items.forEach((item) => {
        const listItem = document.createElement("li");
        listItem.textContent = item;
        list.appendChild(listItem);
      });
      uploadFeedback.appendChild(list);
    }

    uploadFeedback.hidden = false;
  };

  const setUploadSubmittingState = (submitting) => {
    if (uploadSubmitButton) {
      uploadSubmitButton.disabled = submitting;
      uploadSubmitButton.textContent = submitting ? "Uploading..." : uploadSubmitLabel;
    }
    if (uploadFileInput) uploadFileInput.disabled = submitting;
    if (downloadTemplateButton) downloadTemplateButton.disabled = submitting;
    if (uploadProcessing) uploadProcessing.hidden = !submitting;
    if (uploadForm) uploadForm.setAttribute("aria-busy", submitting ? "true" : "false");
  };

  const resetUploadModalState = () => {
    uploadForm?.reset();
    clearUploadFeedback();
    setUploadSubmittingState(false);
  };

  const openUploadModal = () => {
    if (!uploadModal) return;
    resetUploadModalState();
    uploadModal.classList.add("active");
    uploadModal.setAttribute("aria-hidden", "false");
  };

  const closeUploadModal = () => {
    if (!uploadModal) return;
    uploadModal.classList.remove("active");
    uploadModal.setAttribute("aria-hidden", "true");
    resetUploadModalState();
  };

  const downloadTemplateFile = () => {
    const csvContent = "Name,Phone Number,Carier\\r\\n";
    const blob = new Blob([`\uFEFF${csvContent}`], {
      type: "text/csv;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "recipients template.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const readFileAsText = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(new Error("Unable to read the CSV file."));
      reader.readAsText(file);
    });

  const parseCsvRows = (csvText) => {
    const rows = [];
    const text = String(csvText || "").replace(/^\uFEFF/, "");
    let cell = "";
    let row = [];
    let inQuotes = false;

    for (let index = 0; index < text.length; index += 1) {
      const char = text[index];
      const nextChar = text[index + 1];

      if (char === '"') {
        if (inQuotes && nextChar === '"') {
          cell += '"';
          index += 1;
        } else {
          inQuotes = !inQuotes;
        }
        continue;
      }

      if (char === "," && !inQuotes) {
        row.push(cell);
        cell = "";
        continue;
      }

      if ((char === "\\n" || char === "\\r") && !inQuotes) {
        if (char === "\\r" && nextChar === "\\n") {
          index += 1;
        }
        row.push(cell);
        rows.push(row);
        row = [];
        cell = "";
        continue;
      }

      cell += char;
    }

    if (cell.length > 0 || row.length > 0) {
      row.push(cell);
      rows.push(row);
    }

    return rows;
  };

  const normalizeCarrierValue = (value) => {
    const lowered = String(value || "").trim().toLowerCase();
    if (lowered === "mtn") return "MTN";
    if (lowered === "airtel") return "Airtel";
    return null;
  };

  const validateCsvRecipients = (rows) => {
    const errors = [];
    const validRecords = [];
    const skippedDuplicates = [];
    const toRowPreview = (name, phone, carrier) =>
      `${name || "(blank)"} | ${phone || "(blank)"} | ${carrier || "(blank)"}`;

    if (!rows.length) {
      errors.push("The CSV file is empty.");
      return { errors, validRecords, skippedDuplicates };
    }

    const header = (rows[0] || []).map((item) => String(item || "").trim().toLowerCase());
    const isValidHeader = expectedTemplateHeaders.every(
      (expectedHeader, idx) => (header[idx] || "") === expectedHeader
    );
    if (!isValidHeader) {
      errors.push("Header row must be exactly: Name, Phone Number, Carier.");
      return { errors, validRecords, skippedDuplicates };
    }

    const dataRows = rows
      .slice(1)
      .map((row) => row.map((cell) => String(cell || "").trim()))
      .filter((row) => row.some((cell) => cell !== ""));

    if (dataRows.length === 0) {
      errors.push("Add at least one recipient row before uploading.");
      return { errors, validRecords, skippedDuplicates };
    }

    if (dataRows.length > MAX_UPLOAD_ROWS) {
      errors.push(`Only ${MAX_UPLOAD_ROWS} records are allowed per upload.`);
    }

    const existingPhones = new Set(
      recipients.map((item) => String(item.phoneNumber || "").trim())
    );
    const filePhones = new Set();

    dataRows.forEach((row, rowIndex) => {
      const lineNumber = rowIndex + 2;
      const name = row[0] || "";
      const phoneInput = (row[1] || "").replace(/\s+/g, "");
      const carrierInput = row[2] || "";
      const rowErrors = [];
      const preview = toRowPreview(name, row[1], carrierInput);

      if (!name) {
        rowErrors.push("Name is required.");
      } else if (name.length > 25) {
        rowErrors.push("Name must be 25 characters or fewer.");
      }

      if (!/^7\d{8}$/.test(phoneInput)) {
        rowErrors.push("Phone Number must start with 7 and contain exactly 9 digits.");
      }

      const carrier = normalizeCarrierValue(carrierInput);
      if (!carrier) {
        rowErrors.push("Carier must be MTN or Airtel.");
      }

      if (/^7\d{8}$/.test(phoneInput)) {
        const fullPhone = `+250${phoneInput}`;
        if (existingPhones.has(fullPhone)) {
          skippedDuplicates.push(
            `Row ${lineNumber} [${preview}]: Skipped duplicate (already exists).`
          );
        } else if (filePhones.has(fullPhone)) {
          skippedDuplicates.push(
            `Row ${lineNumber} [${preview}]: Skipped duplicate (repeated in file).`
          );
        } else if (rowErrors.length === 0) {
          filePhones.add(fullPhone);
          validRecords.push({
            lineNumber,
            name,
            phone: fullPhone,
            carrier,
          });
        }
      }

      if (rowErrors.length > 0) {
        errors.push(`Row ${lineNumber} [${preview}]: ${rowErrors.join(" ")}`);
      }
    });

    return { errors, validRecords, skippedDuplicates };
  };

  const uploadValidRecipients = async (records) => {
    const uploadErrors = [];
    const skippedDuplicates = [];

    for (const record of records) {
      try {
        await createRecipient({
          name: record.name,
          phone: record.phone,
          carrier: record.carrier,
        });
      } catch (error) {
        if (String(error.message || "").includes("already exists")) {
          skippedDuplicates.push(
            `Row ${record.lineNumber} [${record.name}]: Skipped duplicate (already exists).`
          );
        } else {
          uploadErrors.push(
            `Row ${record.lineNumber} [${record.name}]: ${error.message || "Upload failed."}`
          );
        }
      }
    }

    return { uploadErrors, skippedDuplicates };
  };

  const renderTable = (rows) => {
    tableBody.innerHTML = rows
      .map(
        (recipient) => `
          <tr>
            <td>${recipient.fullName}</td>
            <td>${recipient.phoneNumber}</td>
            <td>${recipient.carrier}</td>
            <td>
              <div class="table-actions">
                <button class="ghost small" data-action="edit" data-id="${recipient.id}">
                  Edit
                </button>
                <button class="danger small" data-action="delete" data-id="${recipient.id}">
                  Delete
                </button>
              </div>
            </td>
          </tr>
        `
      )
      .join("");
  };

  const getFilteredRecipients = () => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return recipients;
    return recipients.filter((recipient) => {
      return (
        recipient.fullName.toLowerCase().includes(term) ||
        recipient.phoneNumber.toLowerCase().includes(term) ||
        recipient.carrier.toLowerCase().includes(term)
      );
    });
  };

  const renderPagination = (totalItems) => {
    const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
    if (currentPageIndex > totalPages) currentPageIndex = totalPages;

    const maxButtons = 5;
    let startPage = Math.max(1, currentPageIndex - Math.floor(maxButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxButtons - 1);
    if (endPage - startPage + 1 < maxButtons) {
      startPage = Math.max(1, endPage - maxButtons + 1);
    }

    const numberButtons = [];
    for (let page = startPage; page <= endPage; page += 1) {
      numberButtons.push(`
        <button
          class="ghost small page-number ${page === currentPageIndex ? "active-page" : ""}"
          data-page="${page}"
        >
          ${page}
        </button>
      `);
    }

    paginationEl.innerHTML = `
      <button class="ghost small" data-page="prev" ${currentPageIndex === 1 ? "disabled" : ""}>
        Prev
      </button>
      <div class="page-buttons">${numberButtons.join("")}</div>
      <div class="page-info">Page ${currentPageIndex} of ${totalPages}</div>
      <button class="ghost small" data-page="next" ${currentPageIndex === totalPages ? "disabled" : ""}>
        Next
      </button>
    `;
  };

  const renderRecipientsView = () => {
    const filtered = getFilteredRecipients();
    const totalItems = filtered.length;

    if (searchTerm) {
      countBadge.textContent = `${totalItems} match${totalItems === 1 ? "" : "es"}`;
    } else {
      countBadge.textContent = `${totalItems} total`;
    }

    const startIndex = (currentPageIndex - 1) * pageSize;
    const pageItems = filtered.slice(startIndex, startIndex + pageSize);

    renderTable(pageItems);

    const hasRecipients = filtered.length > 0;
    emptyState.style.display = hasRecipients ? "none" : "block";
    emptyState.textContent = searchTerm
      ? "No recipients match your search."
      : "No recipients yet.";

    renderPagination(totalItems);
  };

  const normalizeRecipient = (item) => ({
    id: Number(item.id),
    fullName: item.name,
    phoneNumber: item.phone,
    carrier: item.carrier,
  });

  const loadRecipients = async () => {
    try {
      const response = await fetch(apiBase);
      const data = await parseApiResponse(response, "Unable to load recipients.");
      recipients = data.map(normalizeRecipient);
      renderRecipientsView();
    } catch (error) {
      window.alert(error.message || "Something went wrong loading recipients.");
    }
  };

  const createRecipient = async (payload) => {
    const response = await fetch(apiBase, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return parseApiResponse(response, "Unable to add recipient.");
  };

  const updateRecipient = async (id, payload) => {
    const response = await fetch(`${apiBase}/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return parseApiResponse(response, "Unable to update recipient.");
  };

  const deleteRecipient = async (id) => {
    const response = await fetch(`${apiBase}/${id}`, {
      method: "DELETE",
    });
    return parseApiResponse(response, "Unable to delete recipient.");
  };

  const isValidPhone = (value) => phonePattern.test(value);

  phoneInput.addEventListener("input", () => {
    phoneInput.setCustomValidity("");
  });

  if (searchInput) {
    searchInput.addEventListener("input", () => {
      searchTerm = searchInput.value.trim();
      currentPageIndex = 1;
      renderRecipientsView();
    });
  }

  if (pageSizeSelect) {
    pageSizeSelect.addEventListener("change", () => {
      pageSize = Number(pageSizeSelect.value);
      currentPageIndex = 1;
      renderRecipientsView();
    });
  }

  recipientForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!recipientForm.reportValidity()) return;
    if (isSaving) return;

    const phoneValue = phoneInput.value.trim();
    if (!isValidPhone(phoneValue)) {
      phoneInput.setCustomValidity("Use the Rwanda format: +250 followed by 9 digits.");
      phoneInput.reportValidity();
      return;
    }

    const payload = {
      name: nameInput.value.trim(),
      phone: phoneValue,
      carrier: carrierSelect.value,
    };

    setSavingState(true);

    const action =
      editingRecipientId === null
        ? createRecipient(payload)
        : updateRecipient(editingRecipientId, payload);

    action
      .then(() => loadRecipients())
      .then(() => resetForm())
      .catch((error) => {
        window.alert(error.message || "Unable to save recipient.");
        setSavingState(false);
      });
  });

  cancelButton.addEventListener("click", resetForm);

  tableBody.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;

    const id = Number(button.dataset.id);
    const recipient = recipients.find((item) => item.id === id);
    if (!recipient) return;

    if (button.dataset.action === "edit") {
      editingRecipientId = id;
      nameInput.value = recipient.fullName;
      phoneInput.value = recipient.phoneNumber;
      carrierSelect.value = recipient.carrier;
      titleEl.textContent = "Edit recipient";
      subtitleEl.textContent = "Update the details and save your changes.";
      cancelButton.hidden = false;
      nameInput.focus();
    }

    if (button.dataset.action === "delete") {
      const confirmed = window.confirm(
        `Delete ${recipient.fullName} from the ${deleteConfirmLabel} list?`
      );
      if (!confirmed) return;

      deleteRecipient(id)
        .then(() => loadRecipients())
        .then(() => {
          if (editingRecipientId === id) {
            resetForm();
          }
        })
        .catch((error) => {
          window.alert(error.message || "Unable to delete recipient.");
        });
    }
  });

  if (paginationEl) {
    paginationEl.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-page]");
      if (!button || button.disabled) return;

      const target = button.dataset.page;
      if (target === "prev") {
        currentPageIndex = Math.max(1, currentPageIndex - 1);
      } else if (target === "next") {
        currentPageIndex += 1;
      } else {
        currentPageIndex = Number(target);
      }

      renderRecipientsView();
    });
  }

  openUploadModalButton?.addEventListener("click", openUploadModal);
  downloadTemplateButton?.addEventListener("click", downloadTemplateFile);
  uploadModalCloseButtons?.forEach((button) => {
    button.addEventListener("click", closeUploadModal);
  });

  uploadModal?.addEventListener("click", (event) => {
    if (event.target.classList.contains("modal-backdrop")) {
      closeUploadModal();
    }
  });

  uploadForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!uploadForm) return;

    clearUploadFeedback();
    const file = uploadFileInput?.files?.[0];
    if (!file) {
      showUploadFeedback("error", "Please select a CSV file to upload.");
      return;
    }

    setUploadSubmittingState(true);

    try {
      const csvText = await readFileAsText(file);
      const rows = parseCsvRows(csvText);
      const { errors, validRecords, skippedDuplicates } = validateCsvRecipients(rows);

      if (errors.length > 0) {
        showUploadFeedback("error", "Fix the following issues before uploading:", errors);
        setUploadSubmittingState(false);
        return;
      }

      const { uploadErrors, skippedDuplicates: uploadSkipped } =
        await uploadValidRecipients(validRecords);
      const allSkipped = [...skippedDuplicates, ...uploadSkipped];

      if (uploadErrors.length > 0) {
        showUploadFeedback("error", "Some records failed to upload:", uploadErrors);
      } else {
        showUploadFeedback(
          "success",
          `Upload complete. Uploaded ${
            Math.max(0, validRecords.length - allSkipped.length)
          } recipient${validRecords.length - allSkipped.length === 1 ? "" : "s"} and skipped ${
            allSkipped.length
          } duplicate${allSkipped.length === 1 ? "" : "s"}.`,
          allSkipped
        );
      }

      await loadRecipients();
      if (uploadErrors.length === 0) {
        uploadForm.reset();
      }
    } catch (error) {
      showUploadFeedback("error", error.message || "Unable to upload recipients.");
    } finally {
      setUploadSubmittingState(false);
    }
  });

  resetForm();
  loadRecipients();
};

initRecipientsModule({
  apiBase: "/api/recipients",
  formId: "recipient-form",
  nameInputId: "recipient-name",
  phoneInputId: "recipient-phone",
  carrierSelectId: "recipient-carrier",
  submitButtonId: "recipient-submit",
  cancelButtonId: "recipient-cancel",
  titleId: "recipient-form-title",
  subtitleId: "recipient-form-subtitle",
  tableBodyId: "recipient-table-body",
  emptyStateId: "recipient-empty",
  countBadgeId: "recipient-count",
  searchInputId: "recipient-search",
  pageSizeSelectId: "recipient-page-size",
  paginationId: "recipient-pagination",
  uploadModalId: "recipient-upload-modal",
  openUploadModalId: "open-recipient-upload-modal",
  downloadTemplateId: "download-recipient-template",
  uploadFormId: "recipient-upload-form",
  uploadFileId: "recipient-upload-file",
  uploadFeedbackId: "recipient-upload-feedback",
  uploadProcessingId: "recipient-upload-processing",
  uploadSubmitId: "recipient-upload-submit",
  uploadSubmitLabelFallback: "Upload recipients",
  subtitleDefault: "Add someone who should receive airtime.",
  deleteConfirmLabel: "recipients",
});

initRecipientsModule({
  apiBase: "/api/funds-recipients",
  formId: "funds-recipient-form",
  nameInputId: "funds-recipient-name",
  phoneInputId: "funds-recipient-phone",
  carrierSelectId: "funds-recipient-carrier",
  submitButtonId: "funds-recipient-submit",
  cancelButtonId: "funds-recipient-cancel",
  titleId: "funds-recipient-form-title",
  subtitleId: "funds-recipient-form-subtitle",
  tableBodyId: "funds-recipient-table-body",
  emptyStateId: "funds-recipient-empty",
  countBadgeId: "funds-recipient-count",
  searchInputId: "funds-recipient-search",
  pageSizeSelectId: "funds-recipient-page-size",
  paginationId: "funds-recipient-pagination",
  uploadModalId: "funds-recipient-upload-modal",
  openUploadModalId: "open-funds-recipient-upload-modal",
  downloadTemplateId: "funds-download-recipient-template",
  uploadFormId: "funds-recipient-upload-form",
  uploadFileId: "funds-recipient-upload-file",
  uploadFeedbackId: "funds-recipient-upload-feedback",
  uploadProcessingId: "funds-recipient-upload-processing",
  uploadSubmitId: "funds-recipient-upload-submit",
  uploadSubmitLabelFallback: "Upload recipients",
  subtitleDefault: "Add someone who should receive funds.",
  deleteConfirmLabel: "funds recipients",
});
const scheduleModal = document.getElementById("schedule-modal");

if (scheduleModal) {
  const API_BASE = "/api/recipients";
  const openModalButton = document.getElementById("open-schedule-modal");
  const closeButtons = scheduleModal.querySelectorAll("[data-close]");
  const scheduleForm = document.getElementById("schedule-form");
  const dateInput = document.getElementById("schedule-date");
  const descriptionInput = document.getElementById("schedule-description");
  const searchInput = document.getElementById("schedule-recipient-search");
  const listEl = document.getElementById("schedule-recipient-list");
  const selectedEl = document.getElementById("schedule-selected-list");
  const totalEl = document.getElementById("schedule-total");
  const scheduleTableBody = document.getElementById("schedule-table-body");
  const scheduleEmpty = document.getElementById("schedule-empty");
  const scheduleCount = document.getElementById("schedule-count");
  const filterButtons = document.querySelectorAll("#schedule-filters button");
  const scheduleSubmitButton = scheduleForm?.querySelector("button[type='submit']");
  const approveModal = document.getElementById("schedule-approve-modal");
  const approveBody = document.getElementById("approve-recipient-body");
  const approveDate = document.getElementById("approve-date");
  const approveDesc = document.getElementById("approve-desc");
  const approveTotalRecipients = document.getElementById("approve-total-recipients");
  const approveTotalAmount = document.getElementById("approve-total-amount");
  const approveConfirm = document.getElementById("approve-confirm");
  const approveDelete = document.getElementById("approve-delete");
  const editModal = document.getElementById("schedule-edit-modal");
  const editForm = document.getElementById("schedule-edit-form");
  const editList = document.getElementById("schedule-edit-list");
  const editDate = document.getElementById("edit-date");
  const editDesc = document.getElementById("edit-desc");
  const editTotalRecipients = document.getElementById("edit-total-recipients");
  const editTotalAmount = document.getElementById("edit-total-amount");
  const editSaveButton = document.getElementById("schedule-edit-save");

  const SCHEDULES_API = "/api/schedules";
  let recipients = [];
  let selectedRecipients = new Map();
  let searchTerm = "";
  let isLoading = false;
  let schedules = [];
  let activeFilter = "pending";
  let isSavingSchedule = false;
  let approvingScheduleId = null;
  let editingScheduleId = null;
  let editingRows = [];

  const formatDateLocal = (date) => {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  };

  const setCurrentDate = () => {
    if (!dateInput) return;
    dateInput.value = formatDateLocal(new Date());
  };

  const formatAmount = (value) => {
    const amount = Number(value) || 0;
    return new Intl.NumberFormat("en-US").format(amount);
  };

  const resetScheduleForm = () => {
    scheduleForm.reset();
    searchTerm = "";
    if (searchInput) searchInput.value = "";
    selectedRecipients = new Map();
    setCurrentDate();
    renderLists();
    if (scheduleSubmitButton) scheduleSubmitButton.disabled = false;
  };

  const normalizeRecipient = (item) => ({
    id: Number(item.id),
    name: item.name,
    phone: item.phone,
    carrier: item.carrier,
  });

  const loadRecipients = async () => {
    try {
      isLoading = true;
      renderLists();
      const response = await fetch(API_BASE);
      const data = await parseApiResponse(
        response,
        "Unable to load recipients."
      );
      recipients = data.map(normalizeRecipient);
    } catch (error) {
      window.alert(error.message || "Unable to load recipients.");
    } finally {
      isLoading = false;
      renderLists();
    }
  };

  const loadSchedules = async () => {
    if (!scheduleTableBody) return;
    try {
      const response = await fetch(SCHEDULES_API);
      const data = await parseApiResponse(
        response,
        "Unable to load schedules."
      );
      schedules = data;
      renderScheduleTable();
    } catch (error) {
      window.alert(error.message || "Unable to load schedules.");
    }
  };

  const createSchedule = async (payload) => {
    const response = await fetch(SCHEDULES_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return parseApiResponse(response, "Unable to save schedule.");
  };

  const updateSchedule = async (scheduleId, payload) => {
    const response = await fetch(`${SCHEDULES_API}/${scheduleId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return parseApiResponse(response, "Unable to update schedule.");
  };

  const deleteSchedule = async (scheduleId) => {
    const response = await fetch(`${SCHEDULES_API}/${scheduleId}`, {
      method: "DELETE",
    });
    return parseApiResponse(response, "Unable to delete schedule.");
  };

  const approveSchedule = async (scheduleId) => {
    const response = await fetch(`${SCHEDULES_API}/${scheduleId}/approve`, {
      method: "POST",
    });
    return parseApiResponse(response, "Unable to approve schedule.");
  };

  const renderScheduleTable = () => {
    if (!scheduleTableBody) return;
    const filtered = schedules.filter(
      (schedule) => schedule.status === activeFilter
    );

    scheduleTableBody.innerHTML = filtered
      .map((schedule) => {
        const statusLabel = schedule.status || "pending";
        const displayLabel =
          statusLabel.charAt(0).toUpperCase() + statusLabel.slice(1);
        let actions = '<div class="row-actions">';
        if (schedule.can_edit) {
          actions += `
            <button class="ghost small" data-action="edit" data-id="${schedule.id}">
              Edit
            </button>
          `;
        }
        if (schedule.can_approve) {
          actions += `
            <button class="primary small" data-action="approve" data-id="${schedule.id}">
              Approve
            </button>
          `;
        }
        if (schedule.can_delete) {
          actions += `
            <button class="danger small" data-action="delete" data-id="${schedule.id}">
              Delete
            </button>
          `;
        }
        if (!schedule.can_edit && !schedule.can_approve && !schedule.can_delete) {
          actions += `
            <button class="ghost small" disabled title="Schedule locked">
              Locked
            </button>
          `;
        }
        actions += "</div>";

        return `
          <tr>
            <td>${schedule.as_date}</td>
            <td>${schedule.as_desc}</td>
            <td>${schedule.as_total_recipients}</td>
            <td>${formatAmount(schedule.as_total_amount)}</td>
            <td><span class="status-pill ${statusLabel}">${displayLabel}</span></td>
            <td>${actions}</td>
          </tr>
        `;
      })
      .join("");

    if (scheduleEmpty) {
      scheduleEmpty.style.display = filtered.length === 0 ? "block" : "none";
    }
    if (scheduleCount) {
      scheduleCount.textContent = `${filtered.length} ${activeFilter}`;
    }
  };

  const setActiveFilter = (status) => {
    activeFilter = status;
    filterButtons.forEach((button) => {
      button.classList.toggle("active-filter", button.dataset.status === status);
    });
    renderScheduleTable();
  };

  const getFilteredRecipients = () => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return recipients;
    return recipients.filter((recipient) => {
      return (
        recipient.name.toLowerCase().includes(term) ||
        recipient.phone.toLowerCase().includes(term) ||
        recipient.carrier.toLowerCase().includes(term)
      );
    });
  };

  const renderAvailableList = () => {
    if (isLoading) {
      listEl.innerHTML = '<div class="empty-hint">Loading recipients...</div>';
      return;
    }

    const filtered = getFilteredRecipients().filter(
      (recipient) => !selectedRecipients.has(recipient.id)
    );
    if (filtered.length === 0) {
      listEl.innerHTML = searchTerm
        ? '<div class="empty-hint">No recipients found.</div>'
        : '<div class="empty-hint">No recipients available.</div>';
      return;
    }

    listEl.innerHTML = filtered
      .map((recipient) => {
        return `
          <div class="picker-item">
            <div class="picker-meta">
              <strong>${recipient.name}</strong>
              <span>${recipient.phone} · ${recipient.carrier}</span>
            </div>
            <div class="picker-actions">
              <button
                type="button"
                class="ghost small"
                data-action="add"
                data-id="${recipient.id}"
              >
                Add
              </button>
            </div>
          </div>
        `;
      })
      .join("");
  };

  const updateScheduleTotal = () => {
    if (!totalEl) return;
    const totalAmount = Array.from(selectedRecipients.values()).reduce(
      (sum, recipient) => {
        const amount = Number(recipient.amount);
        if (Number.isNaN(amount)) return sum;
        return sum + amount;
      },
      0
    );

    const formatted = new Intl.NumberFormat("en-US").format(totalAmount);
    totalEl.textContent = `Total: ${formatted}`;
  };

  const renderSelectedList = () => {
    if (selectedRecipients.size === 0) {
      selectedEl.innerHTML = '<div class="empty-hint">No recipients selected.</div>';
      if (totalEl) totalEl.textContent = "Total: 0";
      return;
    }

    const selectedItems = Array.from(selectedRecipients.values());

    selectedEl.innerHTML = selectedItems
      .map(
        (recipient) => `
          <div class="picker-item">
            <div class="picker-meta">
              <strong>${recipient.name}</strong>
              <span>${recipient.phone} · ${recipient.carrier}</span>
            </div>
            <div class="picker-actions">
              <input
                type="number"
                class="amount-input"
                data-id="${recipient.id}"
                min="1"
                step="1"
                placeholder="Amount"
                value="${recipient.amount ?? ""}"
                required
              />
              <button
                type="button"
                class="danger small"
                data-action="remove"
                data-id="${recipient.id}"
              >
                Remove
              </button>
            </div>
          </div>
        `
      )
      .join("");

    updateScheduleTotal();
  };

  const renderLists = () => {
    renderAvailableList();
    renderSelectedList();
  };

  const openModal = () => {
    scheduleModal.classList.add("active");
    scheduleModal.setAttribute("aria-hidden", "false");
    setCurrentDate();
    descriptionInput.focus();
  };

  const closeModal = () => {
    scheduleModal.classList.remove("active");
    scheduleModal.setAttribute("aria-hidden", "true");
    isSavingSchedule = false;
    resetScheduleForm();
    if (scheduleSubmitButton) scheduleSubmitButton.disabled = false;
  };

  const openApproveModal = async (scheduleId) => {
    if (!approveModal) return;
    approvingScheduleId = scheduleId;
    approveModal.classList.add("active");
    approveModal.setAttribute("aria-hidden", "false");
    approveBody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';

    try {
      const response = await fetch(`${SCHEDULES_API}/${scheduleId}`);
      const schedule = await parseApiResponse(
        response,
        "Unable to load schedule."
      );

      approveDate.textContent = schedule.as_date;
      approveDesc.textContent = schedule.as_desc;
      approveTotalRecipients.textContent = schedule.as_total_recipients;
      approveTotalAmount.textContent = formatAmount(schedule.as_total_amount);

      approveBody.innerHTML = schedule.recipients
        .map(
          (recipient) => `
            <tr>
              <td>${recipient.name}</td>
              <td>${recipient.phone}</td>
              <td>${recipient.carrier}</td>
              <td>${formatAmount(recipient.airtime_amount)}</td>
            </tr>
          `
        )
        .join("");
    } catch (error) {
      window.alert(error.message || "Unable to load schedule.");
      closeApproveModal();
    }
  };

  const closeApproveModal = () => {
    if (!approveModal) return;
    approveModal.classList.remove("active");
    approveModal.setAttribute("aria-hidden", "true");
    approvingScheduleId = null;
  };

  const updateEditTotal = () => {
    const total = editingRows.reduce(
      (sum, item) => sum + (Number(item.airtime_amount) || 0),
      0
    );
    if (editTotalAmount) editTotalAmount.textContent = formatAmount(total);
  };

  const renderEditRows = () => {
    if (!editList) return;
    if (editingRows.length === 0) {
      editList.innerHTML = '<div class="empty-hint">No recipients to edit.</div>';
      if (editTotalAmount) editTotalAmount.textContent = "0";
      return;
    }

    editList.innerHTML = editingRows
      .map(
        (item) => `
          <div class="schedule-edit-row">
            <div class="schedule-edit-meta">
              <strong>${item.name}</strong>
              <span>${item.phone} · ${item.carrier}</span>
            </div>
            <input
              type="number"
              min="1"
              step="1"
              required
              data-recipient-id="${item.recipient_id}"
              value="${item.airtime_amount}"
            />
          </div>
        `
      )
      .join("");

    updateEditTotal();
  };

  const closeEditModal = () => {
    if (!editModal) return;
    editModal.classList.remove("active");
    editModal.setAttribute("aria-hidden", "true");
    editingScheduleId = null;
    editingRows = [];
    if (editList) editList.innerHTML = "";
    if (editSaveButton) {
      editSaveButton.disabled = false;
      editSaveButton.textContent = "Save amounts";
    }
  };

  const openEditModal = async (scheduleId) => {
    if (!editModal) return;
    editingScheduleId = scheduleId;
    editModal.classList.add("active");
    editModal.setAttribute("aria-hidden", "false");
    if (editList) {
      editList.innerHTML = '<div class="empty-hint">Loading schedule...</div>';
    }

    try {
      const response = await fetch(`${SCHEDULES_API}/${scheduleId}`);
      const schedule = await parseApiResponse(
        response,
        "Unable to load schedule."
      );

      if (!schedule.can_edit) {
        window.alert("Only pending schedules can be edited.");
        closeEditModal();
        return;
      }

      if (editDate) editDate.textContent = schedule.as_date;
      if (editDesc) editDesc.textContent = schedule.as_desc;
      if (editTotalRecipients) {
        editTotalRecipients.textContent = schedule.as_total_recipients;
      }

      editingRows = (schedule.recipients || []).map((item) => ({
        recipient_id: Number(item.recipient_id),
        name: item.name,
        phone: item.phone,
        carrier: item.carrier,
        airtime_amount: Number(item.airtime_amount),
      }));
      renderEditRows();
    } catch (error) {
      window.alert(error.message || "Unable to load schedule.");
      closeEditModal();
    }
  };

  const openCreateModal = () => {
    resetScheduleForm();
    openModal();
    loadRecipients();
  };

  openModalButton?.addEventListener("click", openCreateModal);

  closeButtons.forEach((button) => {
    button.addEventListener("click", closeModal);
  });

  if (approveModal) {
    const approveCloseButtons = approveModal.querySelectorAll("[data-close]");
    approveCloseButtons.forEach((button) => {
      button.addEventListener("click", closeApproveModal);
    });

    approveModal.addEventListener("click", (event) => {
      if (event.target.classList.contains("modal-backdrop")) {
        closeApproveModal();
      }
    });
  }

  if (editModal) {
    const editCloseButtons = editModal.querySelectorAll("[data-close-edit]");
    editCloseButtons.forEach((button) => {
      button.addEventListener("click", closeEditModal);
    });

    editModal.addEventListener("click", (event) => {
      if (event.target.classList.contains("modal-backdrop")) {
        closeEditModal();
      }
    });
  }

  scheduleModal.addEventListener("click", (event) => {
    if (event.target.classList.contains("modal-backdrop")) {
      closeModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && scheduleModal.classList.contains("active")) {
      closeModal();
    }
    if (event.key === "Escape" && approveModal?.classList.contains("active")) {
      closeApproveModal();
    }
    if (event.key === "Escape" && editModal?.classList.contains("active")) {
      closeEditModal();
    }
  });

  if (filterButtons.length > 0) {
    filterButtons.forEach((button) => {
      button.addEventListener("click", () => {
        setActiveFilter(button.dataset.status);
      });
    });
  }

  if (scheduleTableBody) {
    scheduleTableBody.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-action]");
      if (!button || button.disabled) return;
      const scheduleId = Number(button.dataset.id);
      if (!scheduleId) return;

      if (button.dataset.action === "edit") {
        openEditModal(scheduleId);
      }

      if (button.dataset.action === "approve") {
        openApproveModal(scheduleId);
      }

      if (button.dataset.action === "delete") {
        const confirmed = window.confirm(
          "Delete this schedule? The recipients will also be removed."
        );
        if (!confirmed) return;

        deleteSchedule(scheduleId)
          .then(() => loadSchedules())
          .catch((error) => {
            window.alert(error.message || "Unable to delete schedule.");
          });
      }
    });
  }

  approveConfirm?.addEventListener("click", () => {
    if (!approvingScheduleId) return;
    approveConfirm.disabled = true;
    approveSchedule(approvingScheduleId)
      .then(() => {
        closeApproveModal();
        loadSchedules();
      })
      .catch((error) => {
        window.alert(error.message || "Unable to approve schedule.");
      })
      .finally(() => {
        approveConfirm.disabled = false;
      });
  });

  approveDelete?.addEventListener("click", () => {
    if (!approvingScheduleId) return;
    const confirmed = window.confirm(
      "Delete this schedule? The recipients will also be removed."
    );
    if (!confirmed) return;

    approveDelete.disabled = true;
    deleteSchedule(approvingScheduleId)
      .then(() => {
        closeApproveModal();
        loadSchedules();
      })
      .catch((error) => {
        window.alert(error.message || "Unable to delete schedule.");
      })
      .finally(() => {
        approveDelete.disabled = false;
      });
  });

  searchInput?.addEventListener("input", () => {
    searchTerm = searchInput.value.trim();
    renderAvailableList();
  });

  listEl.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action='add']");
    if (!button) return;
    const id = Number(button.dataset.id);
    if (selectedRecipients.has(id)) return;
    const recipient = recipients.find((item) => item.id === id);
    if (!recipient) return;
    selectedRecipients.set(id, { ...recipient, amount: "" });
    renderLists();
  });

  selectedEl.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action='remove']");
    if (!button) return;
    const id = Number(button.dataset.id);
    selectedRecipients.delete(id);
    renderLists();
  });

  selectedEl.addEventListener("input", (event) => {
    const input = event.target.closest("input[data-id]");
    if (!input) return;
    const id = Number(input.dataset.id);
    const recipient = selectedRecipients.get(id);
    if (!recipient) return;
    recipient.amount = input.value;
    selectedRecipients.set(id, recipient);
    updateScheduleTotal();
  });

  editList?.addEventListener("input", (event) => {
    const input = event.target.closest("input[data-recipient-id]");
    if (!input) return;
    const recipientId = Number(input.dataset.recipientId);
    const row = editingRows.find((item) => item.recipient_id === recipientId);
    if (!row) return;
    row.airtime_amount = input.value;
    updateEditTotal();
  });

  editForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!editingScheduleId || !Array.isArray(editingRows) || editingRows.length === 0) {
      window.alert("No schedule selected for editing.");
      return;
    }

    const invalid = editingRows.find((item) => Number(item.airtime_amount) <= 0);
    if (invalid) {
      window.alert("Each recipient amount must be greater than 0.");
      return;
    }

    if (editSaveButton) {
      editSaveButton.disabled = true;
      editSaveButton.textContent = "Saving...";
    }

    const payload = {
      recipients: editingRows.map((item) => ({
        recipient_id: item.recipient_id,
        airtime_amount: Number(item.airtime_amount),
      })),
    };

    updateSchedule(editingScheduleId, payload)
      .then(() => {
        closeEditModal();
        loadSchedules();
      })
      .catch((error) => {
        window.alert(error.message || "Unable to update schedule.");
      })
      .finally(() => {
        if (editSaveButton) {
          editSaveButton.disabled = false;
          editSaveButton.textContent = "Save amounts";
        }
      });
  });

  scheduleForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!scheduleForm.reportValidity()) return;
    if (isSavingSchedule) return;
    if (selectedRecipients.size === 0) {
      window.alert("Select at least one recipient.");
      return;
    }

    const missingAmount = Array.from(selectedRecipients.values()).find(
      (recipient) => !recipient.amount || Number(recipient.amount) <= 0
    );
    if (missingAmount) {
      window.alert("Enter an airtime amount for each selected recipient.");
      return;
    }

    const payload = {
      as_date: dateInput.value,
      as_desc: descriptionInput.value.trim(),
      recipients: Array.from(selectedRecipients.values()).map((recipient) => ({
        recipient_id: recipient.id,
        airtime_amount: Number(recipient.amount),
      })),
    };

    isSavingSchedule = true;
    if (scheduleSubmitButton) scheduleSubmitButton.disabled = true;

    createSchedule(payload)
      .then(() => {
        closeModal();
        loadSchedules();
      })
      .catch((error) => {
        window.alert(error.message || "Unable to save schedule.");
        isSavingSchedule = false;
        if (scheduleSubmitButton) scheduleSubmitButton.disabled = false;
      });
  });

  resetScheduleForm();
  loadSchedules();
}


const fundsScheduleModal = document.getElementById("funds-schedule-modal");

if (fundsScheduleModal) {
  const FUNDS_RECIPIENTS_API = "/api/funds-recipients";
  const openFundsScheduleButton = document.getElementById("open-funds-schedule-modal");
  const closeButtons = fundsScheduleModal.querySelectorAll("[data-close]");
  const fundsScheduleForm = document.getElementById("funds-schedule-form");
  const fundsDateInput = document.getElementById("funds-schedule-date");
  const fundsDescriptionInput = document.getElementById("funds-schedule-description");
  const fundsSearchInput = document.getElementById("funds-schedule-recipient-search");
  const fundsListEl = document.getElementById("funds-schedule-recipient-list");
  const fundsSelectedEl = document.getElementById("funds-schedule-selected-list");
  const fundsTotalEl = document.getElementById("funds-schedule-total");
  const fundsScheduleTableBody = document.getElementById("funds-schedule-table-body");
  const fundsScheduleEmpty = document.getElementById("funds-schedule-empty");
  const fundsScheduleCount = document.getElementById("funds-schedule-count");
  const fundsFilterButtons = document.querySelectorAll("#funds-schedule-filters button");
  const fundsScheduleSubmitButton = fundsScheduleForm?.querySelector("button[type='submit']");
  const fundsApproveModal = document.getElementById("funds-schedule-approve-modal");
  const fundsApproveBody = document.getElementById("funds-approve-recipient-body");
  const fundsApproveDate = document.getElementById("funds-approve-date");
  const fundsApproveDesc = document.getElementById("funds-approve-desc");
  const fundsApproveTotalRecipients = document.getElementById("funds-approve-total-recipients");
  const fundsApproveTotalAmount = document.getElementById("funds-approve-total-amount");
  const fundsApproveConfirm = document.getElementById("funds-approve-confirm");
  const fundsApproveDelete = document.getElementById("funds-approve-delete");
  const fundsEditModal = document.getElementById("funds-schedule-edit-modal");
  const fundsEditForm = document.getElementById("funds-schedule-edit-form");
  const fundsEditList = document.getElementById("funds-schedule-edit-list");
  const fundsEditDate = document.getElementById("funds-edit-date");
  const fundsEditDesc = document.getElementById("funds-edit-desc");
  const fundsEditTotalRecipients = document.getElementById("funds-edit-total-recipients");
  const fundsEditTotalAmount = document.getElementById("funds-edit-total-amount");
  const fundsEditSaveButton = document.getElementById("funds-schedule-edit-save");

  const FUNDS_SCHEDULES_API = "/api/funds-schedules";
  let recipients = [];
  let selectedFundsRecipients = new Map();
  let searchTerm = "";
  let isFundsLoading = false;
  let fundsSchedules = [];
  let fundsActiveFilter = "pending";
  let isSavingFundsSchedule = false;
  let approvingFundsScheduleId = null;
  let editingFundsScheduleId = null;
  let editingRows = [];

  const formatFundsDateLocal = (date) => {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  };

  const setFundsCurrentDate = () => {
    if (!fundsDateInput) return;
    fundsDateInput.value = formatFundsDateLocal(new Date());
  };

  const formatFundsAmount = (value) => {
    const amount = Number(value) || 0;
    return new Intl.NumberFormat("en-US").format(amount);
  };

  const resetScheduleForm = () => {
    fundsScheduleForm.reset();
    searchTerm = "";
    if (fundsSearchInput) fundsSearchInput.value = "";
    selectedFundsRecipients = new Map();
    setFundsCurrentDate();
    renderFundsLists();
    if (fundsScheduleSubmitButton) fundsScheduleSubmitButton.disabled = false;
  };

  const normalizeRecipient = (item) => ({
    id: Number(item.id),
    name: item.name,
    phone: item.phone,
    carrier: item.carrier,
  });

  const loadRecipients = async () => {
    try {
      isFundsLoading = true;
      renderFundsLists();
      const response = await fetch(FUNDS_RECIPIENTS_API);
      const data = await parseApiResponse(
        response,
        "Unable to load recipients."
      );
      recipients = data.map(normalizeRecipient);
    } catch (error) {
      window.alert(error.message || "Unable to load recipients.");
    } finally {
      isFundsLoading = false;
      renderFundsLists();
    }
  };

  const loadFundsSchedules = async () => {
    if (!fundsScheduleTableBody) return;
    try {
      const response = await fetch(FUNDS_SCHEDULES_API);
      const data = await parseApiResponse(
        response,
        "Unable to load fundsSchedules."
      );
      fundsSchedules = data;
      renderFundsScheduleTable();
    } catch (error) {
      window.alert(error.message || "Unable to load fundsSchedules.");
    }
  };

  const createFundsSchedule = async (payload) => {
    const response = await fetch(FUNDS_SCHEDULES_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return parseApiResponse(response, "Unable to save schedule.");
  };

  const updateFundsSchedule = async (scheduleId, payload) => {
    const response = await fetch(`${FUNDS_SCHEDULES_API}/${scheduleId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return parseApiResponse(response, "Unable to update schedule.");
  };

  const deleteFundsSchedule = async (scheduleId) => {
    const response = await fetch(`${FUNDS_SCHEDULES_API}/${scheduleId}`, {
      method: "DELETE",
    });
    return parseApiResponse(response, "Unable to delete schedule.");
  };

  const approveFundsSchedule = async (scheduleId) => {
    const response = await fetch(`${FUNDS_SCHEDULES_API}/${scheduleId}/approve`, {
      method: "POST",
    });
    return parseApiResponse(response, "Unable to approve schedule.");
  };

  const renderFundsScheduleTable = () => {
    if (!fundsScheduleTableBody) return;
    const filtered = fundsSchedules.filter(
      (schedule) => schedule.status === fundsActiveFilter
    );

    fundsScheduleTableBody.innerHTML = filtered
      .map((schedule) => {
        const statusLabel = schedule.status || "pending";
        const displayLabel =
          statusLabel.charAt(0).toUpperCase() + statusLabel.slice(1);
        let actions = '<div class="row-actions">';
        if (schedule.can_edit) {
          actions += `
            <button class="ghost small" data-action="edit" data-id="${schedule.id}">
              Edit
            </button>
          `;
        }
        if (schedule.can_approve) {
          actions += `
            <button class="primary small" data-action="approve" data-id="${schedule.id}">
              Approve
            </button>
          `;
        }
        if (schedule.can_delete) {
          actions += `
            <button class="danger small" data-action="delete" data-id="${schedule.id}">
              Delete
            </button>
          `;
        }
        if (!schedule.can_edit && !schedule.can_approve && !schedule.can_delete) {
          actions += `
            <button class="ghost small" disabled title="Schedule locked">
              Locked
            </button>
          `;
        }
        actions += "</div>";

        return `
          <tr>
            <td>${schedule.fs_date}</td>
            <td>${schedule.fs_desc}</td>
            <td>${schedule.fs_total_recipients}</td>
            <td>${formatFundsAmount(schedule.fs_total_amount)}</td>
            <td><span class="status-pill ${statusLabel}">${displayLabel}</span></td>
            <td>${actions}</td>
          </tr>
        `;
      })
      .join("");

    if (fundsScheduleEmpty) {
      fundsScheduleEmpty.style.display = filtered.length === 0 ? "block" : "none";
    }
    if (fundsScheduleCount) {
      fundsScheduleCount.textContent = `${filtered.length} ${fundsActiveFilter}`;
    }
  };

  const setFundsActiveFilter = (status) => {
    fundsActiveFilter = status;
    fundsFilterButtons.forEach((button) => {
      button.classList.toggle("active-filter", button.dataset.status === status);
    });
    renderFundsScheduleTable();
  };

  const getFilteredFundsRecipients = () => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return recipients;
    return recipients.filter((recipient) => {
      return (
        recipient.name.toLowerCase().includes(term) ||
        recipient.phone.toLowerCase().includes(term) ||
        recipient.carrier.toLowerCase().includes(term)
      );
    });
  };

  const renderFundsAvailableList = () => {
    if (isFundsLoading) {
      fundsListEl.innerHTML = '<div class="empty-hint">Loading recipients...</div>';
      return;
    }

    const filtered = getFilteredFundsRecipients().filter(
      (recipient) => !selectedFundsRecipients.has(recipient.id)
    );
    if (filtered.length === 0) {
      fundsListEl.innerHTML = searchTerm
        ? '<div class="empty-hint">No recipients found.</div>'
        : '<div class="empty-hint">No recipients available.</div>';
      return;
    }

    fundsListEl.innerHTML = filtered
      .map((recipient) => {
        return `
          <div class="picker-item">
            <div class="picker-meta">
              <strong>${recipient.name}</strong>
              <span>${recipient.phone} · ${recipient.carrier}</span>
            </div>
            <div class="picker-actions">
              <button
                type="button"
                class="ghost small"
                data-action="add"
                data-id="${recipient.id}"
              >
                Add
              </button>
            </div>
          </div>
        `;
      })
      .join("");
  };

  const updateFundsScheduleTotal = () => {
    if (!fundsTotalEl) return;
    const totalAmount = Array.from(selectedFundsRecipients.values()).reduce(
      (sum, recipient) => {
        const amount = Number(recipient.amount);
        if (Number.isNaN(amount)) return sum;
        return sum + amount;
      },
      0
    );

    const formatted = new Intl.NumberFormat("en-US").format(totalAmount);
    fundsTotalEl.textContent = `Total: ${formatted}`;
  };

  const renderFundsSelectedList = () => {
    if (selectedFundsRecipients.size === 0) {
      fundsSelectedEl.innerHTML = '<div class="empty-hint">No recipients selected.</div>';
      if (fundsTotalEl) fundsTotalEl.textContent = "Total: 0";
      return;
    }

    const selectedItems = Array.from(selectedFundsRecipients.values());

    fundsSelectedEl.innerHTML = selectedItems
      .map(
        (recipient) => `
          <div class="picker-item">
            <div class="picker-meta">
              <strong>${recipient.name}</strong>
              <span>${recipient.phone} · ${recipient.carrier}</span>
            </div>
            <div class="picker-actions">
              <input
                type="number"
                class="amount-input"
                data-id="${recipient.id}"
                min="1"
                step="1"
                placeholder="Amount"
                value="${recipient.amount ?? ""}"
                required
              />
              <button
                type="button"
                class="danger small"
                data-action="remove"
                data-id="${recipient.id}"
              >
                Remove
              </button>
            </div>
          </div>
        `
      )
      .join("");

    updateFundsScheduleTotal();
  };

  const renderFundsLists = () => {
    renderFundsAvailableList();
    renderFundsSelectedList();
  };

  const openModal = () => {
    fundsScheduleModal.classList.add("active");
    fundsScheduleModal.setAttribute("aria-hidden", "false");
    setFundsCurrentDate();
    fundsDescriptionInput.focus();
  };

  const closeFundsScheduleModal = () => {
    fundsScheduleModal.classList.remove("active");
    fundsScheduleModal.setAttribute("aria-hidden", "true");
    isSavingFundsSchedule = false;
    resetScheduleForm();
    if (fundsScheduleSubmitButton) fundsScheduleSubmitButton.disabled = false;
  };

  const openFundsApproveModal = async (scheduleId) => {
    if (!fundsApproveModal) return;
    approvingFundsScheduleId = scheduleId;
    fundsApproveModal.classList.add("active");
    fundsApproveModal.setAttribute("aria-hidden", "false");
    fundsApproveBody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';

    try {
      const response = await fetch(`${FUNDS_SCHEDULES_API}/${scheduleId}`);
      const schedule = await parseApiResponse(
        response,
        "Unable to load schedule."
      );

      fundsApproveDate.textContent = schedule.fs_date;
      fundsApproveDesc.textContent = schedule.fs_desc;
      fundsApproveTotalRecipients.textContent = schedule.fs_total_recipients;
      fundsApproveTotalAmount.textContent = formatFundsAmount(schedule.fs_total_amount);

      fundsApproveBody.innerHTML = schedule.recipients
        .map(
          (recipient) => `
            <tr>
              <td>${recipient.name}</td>
              <td>${recipient.phone}</td>
              <td>${recipient.carrier}</td>
              <td>${formatFundsAmount(recipient.fund_amount)}</td>
            </tr>
          `
        )
        .join("");
    } catch (error) {
      window.alert(error.message || "Unable to load schedule.");
      closeFundsApproveModal();
    }
  };

  const closeFundsApproveModal = () => {
    if (!fundsApproveModal) return;
    fundsApproveModal.classList.remove("active");
    fundsApproveModal.setAttribute("aria-hidden", "true");
    approvingFundsScheduleId = null;
  };

  const updateFundsEditTotal = () => {
    const total = editingRows.reduce(
      (sum, item) => sum + (Number(item.fund_amount) || 0),
      0
    );
    if (fundsEditTotalAmount) fundsEditTotalAmount.textContent = formatFundsAmount(total);
  };

  const renderFundsEditRows = () => {
    if (!fundsEditList) return;
    if (editingRows.length === 0) {
      fundsEditList.innerHTML = '<div class="empty-hint">No recipients to edit.</div>';
      if (fundsEditTotalAmount) fundsEditTotalAmount.textContent = "0";
      return;
    }

    fundsEditList.innerHTML = editingRows
      .map(
        (item) => `
          <div class="schedule-edit-row">
            <div class="schedule-edit-meta">
              <strong>${item.name}</strong>
              <span>${item.phone} · ${item.carrier}</span>
            </div>
            <input
              type="number"
              min="1"
              step="1"
              required
              data-recipient-id="${item.recipient_id}"
              value="${item.fund_amount}"
            />
          </div>
        `
      )
      .join("");

    updateFundsEditTotal();
  };

  const closeFundsEditModal = () => {
    if (!fundsEditModal) return;
    fundsEditModal.classList.remove("active");
    fundsEditModal.setAttribute("aria-hidden", "true");
    editingFundsScheduleId = null;
    editingRows = [];
    if (fundsEditList) fundsEditList.innerHTML = "";
    if (fundsEditSaveButton) {
      fundsEditSaveButton.disabled = false;
      fundsEditSaveButton.textContent = "Save amounts";
    }
  };

  const openFundsEditModal = async (scheduleId) => {
    if (!fundsEditModal) return;
    editingFundsScheduleId = scheduleId;
    fundsEditModal.classList.add("active");
    fundsEditModal.setAttribute("aria-hidden", "false");
    if (fundsEditList) {
      fundsEditList.innerHTML = '<div class="empty-hint">Loading schedule...</div>';
    }

    try {
      const response = await fetch(`${FUNDS_SCHEDULES_API}/${scheduleId}`);
      const schedule = await parseApiResponse(
        response,
        "Unable to load schedule."
      );

      if (!schedule.can_edit) {
        window.alert("Only pending fundsSchedules can be edited.");
        closeFundsEditModal();
        return;
      }

      if (fundsEditDate) fundsEditDate.textContent = schedule.fs_date;
      if (fundsEditDesc) fundsEditDesc.textContent = schedule.fs_desc;
      if (fundsEditTotalRecipients) {
        fundsEditTotalRecipients.textContent = schedule.fs_total_recipients;
      }

      editingRows = (schedule.recipients || []).map((item) => ({
        recipient_id: Number(item.recipient_id),
        name: item.name,
        phone: item.phone,
        carrier: item.carrier,
        fund_amount: Number(item.fund_amount),
      }));
      renderFundsEditRows();
    } catch (error) {
      window.alert(error.message || "Unable to load schedule.");
      closeFundsEditModal();
    }
  };

  const openFundsCreateModal = () => {
    resetScheduleForm();
    openModal();
    loadRecipients();
  };

  openFundsScheduleButton?.addEventListener("click", openFundsCreateModal);

  closeButtons.forEach((button) => {
    button.addEventListener("click", closeFundsScheduleModal);
  });

  if (fundsApproveModal) {
    const approveCloseButtons = fundsApproveModal.querySelectorAll("[data-close]");
    approveCloseButtons.forEach((button) => {
      button.addEventListener("click", closeFundsApproveModal);
    });

    fundsApproveModal.addEventListener("click", (event) => {
      if (event.target.classList.contains("modal-backdrop")) {
        closeFundsApproveModal();
      }
    });
  }

  if (fundsEditModal) {
    const editCloseButtons = fundsEditModal.querySelectorAll("[data-close-edit]");
    editCloseButtons.forEach((button) => {
      button.addEventListener("click", closeFundsEditModal);
    });

    fundsEditModal.addEventListener("click", (event) => {
      if (event.target.classList.contains("modal-backdrop")) {
        closeFundsEditModal();
      }
    });
  }

  fundsScheduleModal.addEventListener("click", (event) => {
    if (event.target.classList.contains("modal-backdrop")) {
      closeFundsScheduleModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && fundsScheduleModal.classList.contains("active")) {
      closeFundsScheduleModal();
    }
    if (event.key === "Escape" && fundsApproveModal?.classList.contains("active")) {
      closeFundsApproveModal();
    }
    if (event.key === "Escape" && fundsEditModal?.classList.contains("active")) {
      closeFundsEditModal();
    }
  });

  if (fundsFilterButtons.length > 0) {
    fundsFilterButtons.forEach((button) => {
      button.addEventListener("click", () => {
        setFundsActiveFilter(button.dataset.status);
      });
    });
  }

  if (fundsScheduleTableBody) {
    fundsScheduleTableBody.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-action]");
      if (!button || button.disabled) return;
      const scheduleId = Number(button.dataset.id);
      if (!scheduleId) return;

      if (button.dataset.action === "edit") {
        openFundsEditModal(scheduleId);
      }

      if (button.dataset.action === "approve") {
        openFundsApproveModal(scheduleId);
      }

      if (button.dataset.action === "delete") {
        const confirmed = window.confirm(
          "Delete this schedule? The recipients will also be removed."
        );
        if (!confirmed) return;

        deleteFundsSchedule(scheduleId)
          .then(() => loadFundsSchedules())
          .catch((error) => {
            window.alert(error.message || "Unable to delete schedule.");
          });
      }
    });
  }

  fundsApproveConfirm?.addEventListener("click", () => {
    if (!approvingFundsScheduleId) return;
    fundsApproveConfirm.disabled = true;
    approveFundsSchedule(approvingFundsScheduleId)
      .then(() => {
        closeFundsApproveModal();
        loadFundsSchedules();
      })
      .catch((error) => {
        window.alert(error.message || "Unable to approve schedule.");
      })
      .finally(() => {
        fundsApproveConfirm.disabled = false;
      });
  });

  fundsApproveDelete?.addEventListener("click", () => {
    if (!approvingFundsScheduleId) return;
    const confirmed = window.confirm(
      "Delete this schedule? The recipients will also be removed."
    );
    if (!confirmed) return;

    fundsApproveDelete.disabled = true;
    deleteFundsSchedule(approvingFundsScheduleId)
      .then(() => {
        closeFundsApproveModal();
        loadFundsSchedules();
      })
      .catch((error) => {
        window.alert(error.message || "Unable to delete schedule.");
      })
      .finally(() => {
        fundsApproveDelete.disabled = false;
      });
  });

  fundsSearchInput?.addEventListener("input", () => {
    searchTerm = fundsSearchInput.value.trim();
    renderFundsAvailableList();
  });

  fundsListEl.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action='add']");
    if (!button) return;
    const id = Number(button.dataset.id);
    if (selectedFundsRecipients.has(id)) return;
    const recipient = recipients.find((item) => item.id === id);
    if (!recipient) return;
    selectedFundsRecipients.set(id, { ...recipient, amount: "" });
    renderFundsLists();
  });

  fundsSelectedEl.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action='remove']");
    if (!button) return;
    const id = Number(button.dataset.id);
    selectedFundsRecipients.delete(id);
    renderFundsLists();
  });

  fundsSelectedEl.addEventListener("input", (event) => {
    const input = event.target.closest("input[data-id]");
    if (!input) return;
    const id = Number(input.dataset.id);
    const recipient = selectedFundsRecipients.get(id);
    if (!recipient) return;
    recipient.amount = input.value;
    selectedFundsRecipients.set(id, recipient);
    updateFundsScheduleTotal();
  });

  fundsEditList?.addEventListener("input", (event) => {
    const input = event.target.closest("input[data-recipient-id]");
    if (!input) return;
    const recipientId = Number(input.dataset.recipientId);
    const row = editingRows.find((item) => item.recipient_id === recipientId);
    if (!row) return;
    row.fund_amount = input.value;
    updateFundsEditTotal();
  });

  fundsEditForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!editingFundsScheduleId || !Array.isArray(editingRows) || editingRows.length === 0) {
      window.alert("No schedule selected for editing.");
      return;
    }

    const invalid = editingRows.find((item) => Number(item.fund_amount) <= 0);
    if (invalid) {
      window.alert("Each recipient amount must be greater than 0.");
      return;
    }

    if (fundsEditSaveButton) {
      fundsEditSaveButton.disabled = true;
      fundsEditSaveButton.textContent = "Saving...";
    }

    const payload = {
      recipients: editingRows.map((item) => ({
        recipient_id: item.recipient_id,
        fund_amount: Number(item.fund_amount),
      })),
    };

    updateFundsSchedule(editingFundsScheduleId, payload)
      .then(() => {
        closeFundsEditModal();
        loadFundsSchedules();
      })
      .catch((error) => {
        window.alert(error.message || "Unable to update schedule.");
      })
      .finally(() => {
        if (fundsEditSaveButton) {
          fundsEditSaveButton.disabled = false;
          fundsEditSaveButton.textContent = "Save amounts";
        }
      });
  });

  fundsScheduleForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!fundsScheduleForm.reportValidity()) return;
    if (isSavingFundsSchedule) return;
    if (selectedFundsRecipients.size === 0) {
      window.alert("Select at least one recipient.");
      return;
    }

    const missingAmount = Array.from(selectedFundsRecipients.values()).find(
      (recipient) => !recipient.amount || Number(recipient.amount) <= 0
    );
    if (missingAmount) {
      window.alert("Enter an funds amount for each selected recipient.");
      return;
    }

    const payload = {
      fs_date: fundsDateInput.value,
      fs_desc: fundsDescriptionInput.value.trim(),
      recipients: Array.from(selectedFundsRecipients.values()).map((recipient) => ({
        recipient_id: recipient.id,
        fund_amount: Number(recipient.amount),
      })),
    };

    isSavingFundsSchedule = true;
    if (fundsScheduleSubmitButton) fundsScheduleSubmitButton.disabled = true;

    createFundsSchedule(payload)
      .then(() => {
        closeFundsScheduleModal();
        loadFundsSchedules();
      })
      .catch((error) => {
        window.alert(error.message || "Unable to save schedule.");
        isSavingFundsSchedule = false;
        if (fundsScheduleSubmitButton) fundsScheduleSubmitButton.disabled = false;
      });
  });

  resetScheduleForm();
  loadFundsSchedules();
}

const topupModal = document.getElementById("topup-modal");

if (topupModal) {
  const WALLET_API = "/api/wallet";
  const openTopupButton = document.getElementById("open-topup-modal");
  const closeButtons = topupModal.querySelectorAll("[data-close]");
  const topupForm = document.getElementById("topup-form");
  const amountInput = document.getElementById("topup-amount");
  const methodSelect = document.getElementById("topup-method");
  const phoneInput = document.getElementById("topup-phone");
  const feeLabelEl = document.getElementById("topup-fee-label");
  const feeEl = document.getElementById("topup-fee");
  const totalEl = document.getElementById("topup-total");
  const creditEl = document.getElementById("topup-credit");
  const walletBalanceEl = document.getElementById("wallet-balance");
  const walletTotalInEl = document.getElementById("wallet-total-in");
  const walletTotalOutEl = document.getElementById("wallet-total-out");
  const walletPendingInitBodyEl = document.getElementById("wallet-pending-init-body");
  const walletPendingInitEmptyEl = document.getElementById("wallet-pending-init-empty");
  const walletTransactionGroupsEl = document.getElementById("wallet-transactions-groups");
  const walletEmptyState = document.getElementById("wallet-transactions-empty");
  const topupLoader = document.getElementById("topup-loader");
  const topupLoaderText = document.getElementById("topup-loader-text");
  const topupResultModal = document.getElementById("topup-result-modal");
  const topupResultTitle = document.getElementById("topup-result-title");
  const topupResultMessage = document.getElementById("topup-result-message");
  const topupResultCloseButtons = topupResultModal?.querySelectorAll("[data-close]") || [];
  const manualValidateModal = document.getElementById("manual-validate-modal");
  const openManualValidateButton = document.getElementById("open-manual-validate-modal");
  const manualValidateForm = document.getElementById("manual-validate-form");
  const manualValidateInput = document.getElementById("manual-transaction-ref");
  const manualValidateSubmit = document.getElementById("manual-validate-submit");
  const manualValidateCloseButtons =
    manualValidateModal?.querySelectorAll("[data-close-manual]") || [];
  const submitButton = topupForm?.querySelector("button[type='submit']");
  let isSubmittingTopup = false;
  let isSubmittingManualValidation = false;
  const phonePattern = /^250\d{9}$/;
  const defaultPlatformFeePercentage = 10;
  const validatingPendingTransactions = new Set();

  const formatAmount = (value) => {
    const amount = Number(value) || 0;
    return new Intl.NumberFormat("en-US", {
      minimumFractionDigits: 0,
      maximumFractionDigits: 2,
    }).format(amount);
  };

  const formatPercentage = (value) =>
    new Intl.NumberFormat("en-US", {
      minimumFractionDigits: 0,
      maximumFractionDigits: 2,
    }).format(Number(value) || 0);

  const getPlatformFeePercentage = () => {
    const value = Number(currentUserProfile?.platform_fee_percentage);
    if (!Number.isFinite(value)) return defaultPlatformFeePercentage;
    if (value < 0) return 0;
    if (value > 100) return 100;
    return value;
  };

  const updateSummary = () => {
    const rawAmount = Number(amountInput.value);
    const amount = Number.isFinite(rawAmount) ? rawAmount : 0;
    const feePercentage = getPlatformFeePercentage();
    const fee = amount * (feePercentage / 100);
    const total = amount + fee;

    if (feeLabelEl) {
      feeLabelEl.textContent = `Platform fee (${formatPercentage(feePercentage)}%)`;
    }
    feeEl.textContent = formatAmount(fee);
    totalEl.textContent = formatAmount(total);
    creditEl.textContent = formatAmount(amount);
  };

  const setTopupLoading = (isLoading, message) => {
    if (!topupLoader) return;
    topupLoader.hidden = !isLoading;
    if (topupLoaderText) {
      topupLoaderText.textContent = message || "Processing payment...";
    }
    const modalButtons = topupModal.querySelectorAll("button");
    const modalFields = topupModal.querySelectorAll("input, select, textarea");
    modalButtons.forEach((button) => {
      button.disabled = isLoading;
    });
    modalFields.forEach((field) => {
      field.disabled = isLoading;
    });
  };

  const openResultModal = (title, message) => {
    if (!topupResultModal) return;
    if (topupResultTitle) topupResultTitle.textContent = title;
    if (topupResultMessage) topupResultMessage.textContent = message;
    topupResultModal.hidden = false;
    topupResultModal.classList.add("active");
    topupResultModal.setAttribute("aria-hidden", "false");
  };

  const closeResultModal = () => {
    if (!topupResultModal) return;
    topupResultModal.classList.remove("active");
    topupResultModal.setAttribute("aria-hidden", "true");
    topupResultModal.hidden = true;
  };

  const setManualValidationSubmitting = (isSubmitting) => {
    isSubmittingManualValidation = isSubmitting;
    if (manualValidateSubmit) {
      manualValidateSubmit.disabled = isSubmitting;
      manualValidateSubmit.textContent = isSubmitting ? "Validating..." : "Validate";
    }
    if (manualValidateInput) {
      manualValidateInput.disabled = isSubmitting;
    }
    manualValidateCloseButtons.forEach((button) => {
      button.disabled = isSubmitting;
    });
  };

  const openManualValidationModal = () => {
    if (!manualValidateModal) return;
    manualValidateForm?.reset();
    setManualValidationSubmitting(false);
    manualValidateModal.hidden = false;
    manualValidateModal.classList.add("active");
    manualValidateModal.setAttribute("aria-hidden", "false");
    manualValidateInput?.focus();
  };

  const closeManualValidationModal = (options = {}) => {
    const { force = false } = options;
    if (!manualValidateModal || (!force && isSubmittingManualValidation)) return;
    manualValidateModal.classList.remove("active");
    manualValidateModal.setAttribute("aria-hidden", "true");
    manualValidateModal.hidden = true;
  };

  const renderWallet = (payload) => {
    const transactions = Array.isArray(payload.transactions)
      ? payload.transactions
      : [];
    const pendingInitializations = Array.isArray(payload.pending_initializations)
      ? payload.pending_initializations
      : [];
    const totalIn = transactions
      .filter((tx) => tx.trans_type === "in")
      .reduce((sum, tx) => sum + Number(tx.trans_amount || 0), 0);
    const totalOut = transactions
      .filter((tx) => tx.trans_type === "out")
      .reduce((sum, tx) => sum + Number(tx.trans_amount || 0), 0);

    if (walletBalanceEl) walletBalanceEl.textContent = formatAmount(payload.balance || 0);
    if (walletTotalInEl) walletTotalInEl.textContent = formatAmount(totalIn);
    if (walletTotalOutEl) walletTotalOutEl.textContent = formatAmount(totalOut);

    if (walletPendingInitBodyEl) {
      walletPendingInitBodyEl.innerHTML = pendingInitializations
        .map((item) => {
          const isValidating = validatingPendingTransactions.has(Number(item.id));
          return `
            <tr>
              <td>${item.internal_transaction_ref_number}</td>
              <td>${formatAmount(item.amount)}</td>
              <td>${formatAmount(item.platform_fee)}</td>
              <td>${formatAmount(item.total_charge)}</td>
              <td>${item.method}</td>
              <td>${item.phone_number}</td>
              <td>${item.created_at}</td>
              <td>
                <button
                  type="button"
                  class="primary small"
                  data-action="validate-pending"
                  data-id="${item.id}"
                  data-transaction-id="${item.internal_transaction_ref_number}"
                  ${isValidating ? "disabled" : ""}
                >
                  ${isValidating ? "Validating..." : "Validate"}
                </button>
              </td>
            </tr>
          `;
        })
        .join("");
    }

    if (walletPendingInitEmptyEl) {
      walletPendingInitEmptyEl.style.display =
        pendingInitializations.length === 0 ? "block" : "none";
    }

    if (!walletTransactionGroupsEl) return;
    const monthFormatter = new Intl.DateTimeFormat("en-US", {
      month: "long",
      year: "numeric",
    });
    const now = new Date();
    const currentMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;

    const groups = new Map();
    transactions.forEach((tx) => {
      const parsed = new Date(String(tx.created_at || "").replace(" ", "T"));
      const validDate = Number.isNaN(parsed.getTime()) ? new Date() : parsed;
      const monthNo = validDate.getMonth() + 1;
      const monthKey = `${validDate.getFullYear()}-${String(monthNo).padStart(2, "0")}`;
      const monthLabel = monthFormatter.format(validDate);

      if (!groups.has(monthKey)) {
        groups.set(monthKey, {
          key: monthKey,
          label: monthLabel,
          transactions: [],
          totalIn: 0,
          totalOut: 0,
        });
      }

      const group = groups.get(monthKey);
      const amount = Number(tx.trans_amount || 0);
      if (tx.trans_type === "in") group.totalIn += amount;
      else group.totalOut += amount;
      group.transactions.push(tx);
    });

    const orderedGroups = Array.from(groups.values()).sort((a, b) => b.key.localeCompare(a.key));
    walletTransactionGroupsEl.innerHTML = orderedGroups
      .map((group) => {
        const rows = group.transactions
          .map((tx) => {
            const type = tx.trans_type === "in" ? "in" : "out";
            const label = type === "in" ? "In" : "Out";
            const sign = type === "in" ? "+" : "-";
            return `
              <tr>
                <td>${tx.id}</td>
                <td><span class="status-pill ${type}">${label}</span></td>
                <td>${tx.trans_ref}</td>
                <td>${sign}${formatAmount(tx.trans_amount)}</td>
                <td>${formatAmount(tx.platform_fee || 0)}</td>
                <td>${tx.created_at}</td>
              </tr>
            `;
          })
          .join("");

        const shouldOpen = group.key === currentMonthKey ? "open" : "";
        return `
          <details class="wallet-month-group" ${shouldOpen}>
            <summary>
              <span class="wallet-month-title">${group.label}</span>
              <span class="wallet-month-totals">
                In: ${formatAmount(group.totalIn)} · Out: ${formatAmount(group.totalOut)}
              </span>
            </summary>
            <div class="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Reference</th>
                    <th>Amount</th>
                    <th>Platform Fee</th>
                    <th>Date</th>
                  </tr>
                </thead>
                <tbody>${rows}</tbody>
              </table>
            </div>
          </details>
        `;
      })
      .join("");

    if (walletEmptyState) {
      walletEmptyState.style.display = transactions.length === 0 ? "block" : "none";
    }
  };

  const loadWallet = async () => {
    try {
      const response = await fetch(WALLET_API);
      const payload = await parseApiResponse(response, "Unable to load wallet.");
      renderWallet(payload);
    } catch (error) {
      window.alert(error.message || "Unable to load wallet.");
    }
  };

  const submitTopup = async (payload) => {
    const response = await fetch("/api/wallet/topup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return parseApiResponse(response, "Unable to top up wallet.");
  };

  const checkTopupStatus = async (transactionId) => {
    const response = await fetch("/api/wallet/topup/status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transaction_id: transactionId }),
    });
    return parseApiResponse(response, "Unable to check transaction status.");
  };

  const manualValidateTopup = async (transactionId) => {
    const response = await fetch("/api/wallet/topup/manual-validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transaction_id: transactionId }),
    });
    return parseApiResponse(response, "Unable to validate the transaction manually.");
  };

  const showValidationResult = (transactionId, statusPayload) => {
    const status = String(statusPayload?.status || "pending");
    const message = statusPayload?.message || "Transaction status retrieved.";
    const statusLabel = status.charAt(0).toUpperCase() + status.slice(1);
    openResultModal(
      `Validation result · ${statusLabel}`,
      `Reference: ${transactionId}. ${message}`
    );
  };

  const openModal = () => {
    topupModal.classList.add("active");
    topupModal.setAttribute("aria-hidden", "false");
    if (!methodSelect.value) methodSelect.value = "Mobile Money - MTN";
    if (phoneInput && currentUserProfile?.phone) {
      const rawPhone = String(currentUserProfile.phone || "").trim();
      phoneInput.value = rawPhone.startsWith("+") ? rawPhone.slice(1) : rawPhone;
    }
    setTopupLoading(false);
    updateSummary();
    amountInput.focus();
  };

  const closeModal = (options = {}) => {
    const { force = false } = options;
    if (!force && topupLoader && !topupLoader.hidden) return;
    topupModal.classList.remove("active");
    topupModal.setAttribute("aria-hidden", "true");
    topupForm.reset();
    methodSelect.value = "Mobile Money - MTN";
    setTopupLoading(false);
    updateSummary();
    isSubmittingTopup = false;
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = "Top up";
    }
  };

  openTopupButton?.addEventListener("click", openModal);
  openManualValidateButton?.addEventListener("click", openManualValidationModal);

  closeButtons.forEach((button) => {
    button.addEventListener("click", () => closeModal());
  });

  manualValidateCloseButtons.forEach((button) => {
    button.addEventListener("click", closeManualValidationModal);
  });

  topupResultCloseButtons.forEach((button) => {
    button.addEventListener("click", closeResultModal);
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest("#topup-result-modal [data-close]")) return;
    closeResultModal();
  });

  topupResultModal?.addEventListener("click", (event) => {
    if (event.target.classList.contains("modal-backdrop")) {
      closeResultModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && topupResultModal?.classList.contains("active")) {
      closeResultModal();
    }
    if (event.key === "Escape" && manualValidateModal?.classList.contains("active")) {
      closeManualValidationModal();
    }
  });

  topupModal.addEventListener("click", (event) => {
    if (event.target.classList.contains("modal-backdrop")) {
      event.preventDefault();
    }
  });

  manualValidateModal?.addEventListener("click", (event) => {
    if (event.target.classList.contains("modal-backdrop")) {
      closeManualValidationModal();
    }
  });

  manualValidateInput?.addEventListener("input", () => {
    const digitsOnly = (manualValidateInput.value || "").replace(/\D/g, "").slice(0, 20);
    if (manualValidateInput.value !== digitsOnly) {
      manualValidateInput.value = digitsOnly;
    }
  });

  manualValidateForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (isSubmittingManualValidation) return;
    const transactionId = String(manualValidateInput?.value || "").replace(/\D/g, "");
    if (!/^\d{20}$/.test(transactionId)) {
      window.alert("Transaction Reference Number must contain exactly 20 digits.");
      return;
    }

    setManualValidationSubmitting(true);
    manualValidateTopup(transactionId)
      .then((statusPayload) => {
        closeManualValidationModal({ force: true });
        showValidationResult(transactionId, statusPayload);
        loadWallet();
      })
      .catch((error) => {
        openResultModal(
          "Manual validation failed",
          error.message || "Unable to validate the transaction right now."
        );
      })
      .finally(() => {
        setManualValidationSubmitting(false);
      });
  });

  amountInput.addEventListener("input", updateSummary);

  topupForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!topupForm.reportValidity()) return;
    if (isSubmittingTopup) return;

    const phoneRaw = phoneInput?.value?.trim() || "";
    const normalizedPhone = phoneRaw.startsWith("+") ? phoneRaw.slice(1) : phoneRaw;
    if (!phonePattern.test(normalizedPhone)) {
      window.alert("Phone number must start with 250 and contain 12 digits total.");
      return;
    }
    if (phoneInput && phoneInput.value !== normalizedPhone) {
      phoneInput.value = normalizedPhone;
    }

    const amount = Number(amountInput.value);
    if (!Number.isFinite(amount) || amount <= 0) {
      window.alert("Enter a valid topup amount.");
      return;
    }

    isSubmittingTopup = true;
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = "Processing...";
    }
    setTopupLoading(true, "Initiating payment...");

    submitTopup({
      amount,
      method: methodSelect.value,
      phone: normalizedPhone,
    })
      .then((data) => {
        if (!data.transaction_id) {
          throw new Error("Unable to start the payment. Please try again.");
        }
        closeModal({ force: true });
        openResultModal(
          "Top up initialized",
          data.message ||
            "Transaction is pending. Use Validate in the pending table to check status."
        );
        loadWallet();
      })
      .catch((error) => {
        setTopupLoading(false);
        window.alert(error.message || "Unable to top up wallet.");
      })
      .finally(() => {
        isSubmittingTopup = false;
        if (submitButton && (!topupLoader || topupLoader.hidden)) {
          submitButton.disabled = false;
          submitButton.textContent = "Top up";
        }
      });
  });

  walletPendingInitBodyEl?.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action='validate-pending']");
    if (!button || button.disabled) return;

    const initId = Number(button.dataset.id);
    const transactionId = String(button.dataset.transactionId || "").trim();
    if (!initId || !transactionId) return;

    validatingPendingTransactions.add(initId);
    button.disabled = true;
    button.textContent = "Validating...";

    try {
      const statusPayload = await checkTopupStatus(transactionId);
      showValidationResult(transactionId, statusPayload);
    } catch (error) {
      openResultModal(
        "Validation failed",
        error.message || "Unable to validate the transaction right now."
      );
    } finally {
      validatingPendingTransactions.delete(initId);
      loadWallet();
    }
  });

  updateSummary();
  document.addEventListener("faranga-profile-updated", updateSummary);
  loadWallet();
}

const signupForm = document.getElementById("signup-form");

if (signupForm) {
  const accountTypeInputs = signupForm.querySelectorAll(
    "input[name='account_type']"
  );
  const individualSection = signupForm.querySelector(
    "[data-account='individual']"
  );
  const businessSection = signupForm.querySelector("[data-account='business']");
  const messageEl = document.getElementById("signup-message");

  const updateAccountType = () => {
    const selected = signupForm.querySelector(
      "input[name='account_type']:checked"
    )?.value;
    const isBusiness = selected === "business";
    businessSection.hidden = !isBusiness;
    individualSection.hidden = isBusiness;

    businessSection.querySelectorAll("input").forEach((input) => {
      input.required = isBusiness && input.type !== "file";
    });
    const businessFile = businessSection.querySelector("input[type='file']");
    if (businessFile) {
      businessFile.required = isBusiness;
    }

    individualSection.querySelectorAll("input").forEach((input) => {
      input.required = !isBusiness;
    });
  };

  accountTypeInputs.forEach((input) => {
    input.addEventListener("change", updateAccountType);
  });

  signupForm.addEventListener("submit", (event) => {
    const password = signupForm.querySelector("input[name='password']")?.value;
    const confirm = signupForm.querySelector(
      "input[name='confirm_password']"
    )?.value;
    if (password && password.length < 8) {
      event.preventDefault();
      if (messageEl) {
        messageEl.textContent = "Password must be at least 8 characters.";
        messageEl.hidden = false;
      }
      return;
    }
    if (password !== confirm) {
      event.preventDefault();
      if (messageEl) {
        messageEl.textContent = "Passwords do not match.";
        messageEl.hidden = false;
      }
    }
  });

  const params = new URLSearchParams(window.location.search);
  if (params.has("error") && messageEl) {
    messageEl.textContent = params.get("error") || "Unable to sign up.";
    messageEl.hidden = false;
  }

  updateAccountType();
}

const loginForm = document.getElementById("login-form");

if (loginForm) {
  const messageEl = document.getElementById("login-message");
  const params = new URLSearchParams(window.location.search);
  if (params.has("error") && messageEl) {
    messageEl.textContent = params.get("error") || "Unable to log in.";
    messageEl.hidden = false;
  }
}

const passwordUpdateForm = document.getElementById("password-update-form");

if (passwordUpdateForm) {
  const currentPasswordInput = document.getElementById("current-password");
  const newPasswordInput = document.getElementById("new-password");
  const confirmNewPasswordInput = document.getElementById("confirm-new-password");
  const feedbackEl = document.getElementById("password-update-feedback");
  const submitButton = document.getElementById("password-update-submit");

  const showFeedback = (type, message) => {
    if (!feedbackEl) return;
    feedbackEl.hidden = false;
    feedbackEl.textContent = message;
    feedbackEl.classList.remove("success", "error");
    feedbackEl.classList.add(type);
  };

  passwordUpdateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!passwordUpdateForm.reportValidity()) return;

    const currentPassword = currentPasswordInput?.value || "";
    const newPassword = newPasswordInput?.value || "";
    const confirmPassword = confirmNewPasswordInput?.value || "";

    if (newPassword !== confirmPassword) {
      showFeedback("error", "New password and confirmation do not match.");
      return;
    }
    if (newPassword.length < 8) {
      showFeedback("error", "New password must be at least 8 characters.");
      return;
    }
    if (newPassword === currentPassword) {
      showFeedback("error", "New password must be different from current password.");
      return;
    }

    submitButton.disabled = true;
    submitButton.textContent = "Updating...";

    try {
      const response = await fetch("/api/me/password", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });
      await parseApiResponse(response, "Unable to update password.");
      passwordUpdateForm.reset();
      showFeedback("success", "Password updated successfully.");
    } catch (error) {
      showFeedback("error", error.message || "Unable to update password.");
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = "Update Password";
    }
  });
}

const protectedPage = document.body?.dataset.page;

if (protectedPage) {
  const accountUrl = "/api/me";
  const logoutUrl = "/logout";
  const sessionTimeoutDisabled = true;
  const inactivityLimit = 15 * 60 * 1000;
  const warningDuration = 1 * 60 * 1000;
  const warningDelay = inactivityLimit - warningDuration;
  let warningTimer = null;
  let logoutTimer = null;
  let countdownTimer = null;
  let warningDeadline = null;
  let warningVisible = false;
  let skipLogout = false;
  const sidebarFooter = document.querySelector(".sidebar-footer");

  const warningModal = document.createElement("div");
  warningModal.className = "modal session-timeout-modal";
  warningModal.id = "session-timeout-modal";
  warningModal.setAttribute("aria-hidden", "true");
  warningModal.innerHTML = `
    <div class="modal-backdrop"></div>
    <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="session-timeout-title">
      <div class="modal-header">
        <div>
          <span class="modal-kicker">Session expiring</span>
          <h2 id="session-timeout-title">Still there?</h2>
        </div>
      </div>
      <p class="session-timeout-message">
        You will be automatically logged out in
        <strong class="session-timeout-countdown">1:00</strong>
        due to inactivity.
      </p>
      <div class="form-actions modal-footer-actions session-timeout-actions">
        <button type="button" class="primary" id="stay-logged-in-button">Stay logged in</button>
      </div>
    </div>
  `;
  document.body.appendChild(warningModal);

  const stayLoggedInButton = document.getElementById("stay-logged-in-button");
  const countdownEl = warningModal.querySelector(".session-timeout-countdown");
  const escapeHtml = (value) =>
    String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");

  const renderUserPanel = (profile) => {
    if (!sidebarFooter) return;
    const name = escapeHtml(profile?.display_name || "User");
    const email = escapeHtml(profile?.email || "");

    sidebarFooter.innerHTML = `
      <div class="sidebar-user">
        <span class="sidebar-user-label">Signed in as</span>
        <strong class="sidebar-user-name" title="${name}">${name}</strong>
        ${email ? `<small class="sidebar-user-email" title="${email}">${email}</small>` : ""}
      </div>
      <button type="button" class="ghost small sidebar-logout-button" id="sidebar-logout-button">
        Log out
      </button>
    `;

    document
      .getElementById("sidebar-logout-button")
      ?.addEventListener("click", logoutAndRedirect);
  };

  const loadCurrentUser = async () => {
    if (!sidebarFooter) return;
    sidebarFooter.innerHTML = '<p class="sidebar-user-loading">Loading account...</p>';

    try {
      const response = await fetch(accountUrl, { credentials: "same-origin" });
      const profile = await parseApiResponse(response, "Unable to load account.");
      currentUserProfile = profile;
      document.dispatchEvent(new CustomEvent("faranga-profile-updated"));
      renderUserPanel(profile);
      const topupPhoneInput = document.getElementById("topup-phone");
      if (topupPhoneInput && profile?.phone) {
        const rawPhone = String(profile.phone || "").trim();
        topupPhoneInput.value = rawPhone.startsWith("+") ? rawPhone.slice(1) : rawPhone;
      }
    } catch (error) {
      sidebarFooter.innerHTML = `
        <button type="button" class="ghost small sidebar-logout-button" id="sidebar-logout-button">
          Log out
        </button>
      `;
      document
        .getElementById("sidebar-logout-button")
        ?.addEventListener("click", logoutAndRedirect);
    }
  };

  const formatCountdown = (remainingMs) => {
    const totalSeconds = Math.max(0, Math.ceil(remainingMs / 1000));
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return `${minutes}:${String(seconds).padStart(2, "0")}`;
  };

  const clearCountdown = () => {
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
  };

  const updateCountdown = () => {
    if (!warningVisible || !warningDeadline) return;
    const remainingMs = warningDeadline - Date.now();
    countdownEl.textContent = formatCountdown(remainingMs);
    if (remainingMs <= 0) {
      clearCountdown();
    }
  };

  const hideWarning = () => {
    warningVisible = false;
    warningDeadline = null;
    warningModal.classList.remove("active");
    warningModal.setAttribute("aria-hidden", "true");
    clearCountdown();
  };

  const showWarning = () => {
    warningVisible = true;
    warningDeadline = Date.now() + warningDuration;
    warningModal.classList.add("active");
    warningModal.setAttribute("aria-hidden", "false");
    updateCountdown();
    clearCountdown();
    countdownTimer = setInterval(updateCountdown, 1000);
    stayLoggedInButton?.focus();
  };

  const clearInactivityTimeouts = () => {
    if (warningTimer) {
      clearTimeout(warningTimer);
      warningTimer = null;
    }
    if (logoutTimer) {
      clearTimeout(logoutTimer);
      logoutTimer = null;
    }
  };

  const logoutAndRedirect = () => {
    hideWarning();
    clearInactivityTimeouts();
    skipLogout = true;
    fetch(logoutUrl, {
      method: "POST",
      credentials: "same-origin",
      keepalive: true,
    }).finally(() => {
      window.location.href = "/login";
    });
  };

  const resetInactivity = () => {
    hideWarning();
    clearInactivityTimeouts();
    warningTimer = setTimeout(showWarning, warningDelay);
    logoutTimer = setTimeout(logoutAndRedirect, inactivityLimit);
  };

  const handleActivity = () => {
    if (warningVisible) {
      return;
    }
    resetInactivity();
  };

  loadCurrentUser();

  if (!sessionTimeoutDisabled) {
    ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach((eventName) => {
      document.addEventListener(eventName, handleActivity, { passive: true });
    });

    stayLoggedInButton?.addEventListener("click", resetInactivity);

    document.addEventListener("click", (event) => {
      const link = event.target.closest("a[href]");
      if (!link) return;
      const url = new URL(link.href, window.location.href);
      if (url.origin === window.location.origin && link.target !== "_blank") {
        skipLogout = true;
      }
    });

    window.addEventListener("pagehide", () => {
      if (skipLogout) {
        skipLogout = false;
        return;
      }
      hideWarning();
      if (navigator.sendBeacon) {
        navigator.sendBeacon(logoutUrl);
      } else {
        fetch(logoutUrl, { method: "POST", credentials: "same-origin", keepalive: true });
      }
    });

    resetInactivity();
  }
}

const form = document.getElementById("lookup-form");
const statusEl = document.getElementById("status");
const resultSection = document.getElementById("result-section");
const resultEl = document.getElementById("result");
const historyBody = document.querySelector("#history-table tbody");
const refreshHistoryButton = document.getElementById("refresh-history");

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const value = document.getElementById("value").value.trim();
  const provider = document.getElementById("provider").value;

  if (!value) return;

  setLoading(true);
  statusEl.textContent = "Consultando...";
  statusEl.className = "status";

  try {
    const response = await fetch("/api/lookup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        value,
        provider,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      renderError(data.error || data.detail || "Erro na consulta.");
      return;
    }

    if (!data.success) {
      renderError(data.error || "Erro na consulta.");
      return;
    }

    renderResult(data.result);
    await loadHistory();
  } catch (error) {
    renderError("Falha ao comunicar com o servidor.");
  } finally {
    setLoading(false);
  }
});

refreshHistoryButton.addEventListener("click", loadHistory);
document.addEventListener("DOMContentLoaded", loadHistory);

function setLoading(loading) {
  const button = form.querySelector("button[type=submit]");
  button.disabled = loading;
  button.textContent = loading ? "Consultando..." : "Consultar";
}

function renderError(message) {
  if (typeof message === "object") {
    try {
      message = JSON.stringify(message);
    } catch {
      message = "Erro na consulta.";
    }
  }

  statusEl.textContent = message;
  statusEl.className = "status error";
  resultSection.classList.add("hidden");
}

function renderResult(result) {
  statusEl.textContent = "Consulta concluída.";
  statusEl.className = "status";
  resultSection.classList.remove("hidden");

  const riskClass = normalizeRisk(result.risk_level);
  const details = [];

  if (result.provider === "otx") {
    details.push(`<h3>Pulses</h3>${renderPulses(result.reputation?.pulses || [])}`);

    if (result.reputation?.references?.length) {
      details.push(`
        <h3>Referências</h3>
        <ul>
          ${result.reputation.references
            .slice(0, 5)
            .map((ref) => `<li>${escapeHtml(ref)}</li>`)
            .join("")}
        </ul>
      `);
    }
  }

  if (result.provider === "virustotal") {
    details.push(renderStats(result.reputation?.last_analysis_stats || {}));
  }

  if (result.additional && Object.keys(result.additional).length) {
    details.push(`
      <h3>Detalhes adicionais</h3>
      <pre>${escapeHtml(JSON.stringify(result.additional, null, 2))}</pre>
    `);
  }

  resultEl.innerHTML = `
    <div class="kv">
      <div>Indicador</div>
      <div>${escapeHtml(result.indicator)}</div>

      <div>Tipo</div>
      <div>${escapeHtml(result.indicator_type)}</div>

      <div>Fonte</div>
      <div>${escapeHtml(result.provider)}</div>

      <div>Risco</div>
      <div>
        <span class="badge ${riskClass}">
          ${escapeHtml(result.risk_level || "indefinido")}
        </span>
      </div>

      <div>Veredito</div>
      <div>${escapeHtml(result.verdict || "")}</div>

      <div>Resumo</div>
      <div>${escapeHtml(result.summary || "")}</div>
    </div>

    ${details.join("")}
  `;
}

function renderPulses(pulses) {
  if (!pulses.length) {
    return "<p>Nenhum pulse detalhado retornado.</p>";
  }

  return `
    <table>
      <thead>
        <tr>
          <th>Nome</th>
          <th>Criado</th>
          <th>TLP</th>
          <th>Tags</th>
        </tr>
      </thead>
      <tbody>
        ${pulses
          .map(
            (pulse) => `
              <tr>
                <td>${escapeHtml(pulse.name || "")}</td>
                <td>${escapeHtml(pulse.created || "")}</td>
                <td>${escapeHtml(pulse.tlp || "")}</td>
                <td>${escapeHtml((pulse.tags || []).slice(0, 6).join(", "))}</td>
              </tr>
            `
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function renderStats(stats) {
  const entries = Object.entries(stats);

  if (!entries.length) {
    return "<p>Sem estatísticas de análise.</p>";
  }

  return `
    <table>
      <thead>
        <tr>
          <th>Categoria</th>
          <th>Quantidade</th>
        </tr>
      </thead>
      <tbody>
        ${entries
          .map(
            ([key, value]) => `
              <tr>
                <td>${escapeHtml(key)}</td>
                <td>${escapeHtml(String(value))}</td>
              </tr>
            `
          )
          .join("")}
      </tbody>
    </table>
  `;
}

async function loadHistory() {
  try {
    const response = await fetch("/api/history?limit=50");
    const data = await response.json();
    const items = data.items || [];

    if (!items.length) {
      historyBody.innerHTML = `
        <tr>
          <td colspan="6">Nenhuma consulta ainda.</td>
        </tr>
      `;
      return;
    }

    historyBody.innerHTML = items
      .map((item) => {
        const riskClass = normalizeRisk(item.risk_level);

        return `
          <tr>
            <td>${formatDate(item.created_at)}</td>
            <td>${escapeHtml(item.indicator)}</td>
            <td>${escapeHtml(item.indicator_type)}</td>
            <td>${escapeHtml(item.provider)}</td>
            <td>${item.success ? "Sucesso" : "Erro"}</td>
            <td>
              ${
                item.risk_level
                  ? `<span class="badge ${riskClass}">${escapeHtml(item.risk_level)}</span>`
                  : "-"
              }
            </td>
          </tr>
        `;
      })
      .join("");
  } catch (error) {
    historyBody.innerHTML = `
      <tr>
        <td colspan="6">Erro ao carregar histórico.</td>
      </tr>
    `;
  }
}

function normalizeRisk(risk) {
  return (risk || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}

function formatDate(iso) {
  if (!iso) return "-";

  return new Date(iso).toLocaleString("pt-BR");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
const form = document.getElementById("inspect-form");
const agent = document.getElementById("agent-dir");
const allowed = document.getElementById("allowed-root");
const button = document.getElementById("submit");
const status = document.getElementById("status");
const count = document.getElementById("count");
const warnings = document.getElementById("warnings");
const list = document.getElementById("skills");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  status.textContent = "正在检查，请稍候…";
  count.textContent = "检查中";
  warnings.textContent = "";
  list.replaceChildren();
  try {
    const result = await window.__TAURI__.core.invoke("inspect_inventory", {
      agentDir: agent.value,
      allowedRoot: allowed.value,
    });
    count.textContent = result.skills.length + " 个技能";
    status.textContent = result.complete ? "检查完成。结果来自本机指定目录。" : "检查未完全完成，请查看下方提示。";
    warnings.textContent = result.warnings.join("\n");
    for (const skill of result.skills) {
      const li = document.createElement("li");
      const name = document.createElement("strong");
      const kind = document.createElement("span");
      name.textContent = skill.name;
      kind.textContent = skill.symlink ? "允许的目录链接" : "普通目录";
      li.append(name, kind);
      list.append(li);
    }
  } catch (error) {
    status.textContent = "检查失败，请确认目录后重试。";
    count.textContent = "未完成";
    warnings.textContent = String(error);
  } finally {
    button.disabled = false;
  }
});

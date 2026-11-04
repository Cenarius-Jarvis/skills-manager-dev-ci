import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { devicesInspectLocal, type LocalInventory } from "../lib/tauri";

/** Local diagnostic only. It never sends instructions or publishes inventory. */
export function LocalInventoryPreview() {
  const { t } = useTranslation();
  const [path, setPath] = useState("");
  const [root, setRoot] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LocalInventory | null>(null);
  const [error, setError] = useState("");
  async function inspect(event: FormEvent) {
    event.preventDefault();
    if (!path.trim() || loading) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      setResult(await devicesInspectLocal(path.trim(), root.trim() ? [root.trim()] : []));
    } catch {
      setError(t("localInventory.failed"));
    } finally {
      setLoading(false);
    }
  }
  return (
    <details className="app-panel p-4" data-testid="local-inventory">
      <summary className="cursor-pointer font-medium">{t("localInventory.title")}</summary>
      <p className="mt-2 text-[13px] text-muted">{t("localInventory.hint")}</p>
      <form className="mt-3 flex flex-col gap-3" onSubmit={(event) => void inspect(event)}>
        <label className="flex flex-col gap-1" htmlFor="local-inventory-path">
          <span className="text-[13px]">{t("localInventory.path")}</span>
          <input id="local-inventory-path" className="app-input" value={path} onChange={(event) => setPath(event.target.value)} />
        </label>
        <label className="flex flex-col gap-1" htmlFor="local-inventory-root">
          <span className="text-[13px]">{t("localInventory.allowed")}</span>
          <input id="local-inventory-root" className="app-input" value={root} onChange={(event) => setRoot(event.target.value)} />
        </label>
        <button className="app-button-primary self-start" type="submit" disabled={!path.trim() || loading}>
          {loading ? t("localInventory.loading") : t("localInventory.run")}
        </button>
      </form>
      {error && <p role="alert" className="mt-3 text-red-600 dark:text-red-400">{error}</p>}
      {result && <div className="mt-3" aria-live="polite">
        <p className="text-[13px]">{result.complete ? t("localInventory.complete") : t("localInventory.incomplete")}</p>
        {!result.complete && <ul className="mt-2 text-[13px] text-amber-600 dark:text-amber-400">{result.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul>}
        {result.skills.length === 0 ? (result.complete ? <p className="mt-2 text-[13px] text-muted">{t("localInventory.empty")}</p> : null) : <ul className="mt-2 text-[13px]">{result.skills.map((skill) => <li key={skill.name}>{skill.name} · {skill.symlink ? t("localInventory.link") : t("localInventory.directory")}</li>)}</ul>}
      </div>}
    </details>
  );
}

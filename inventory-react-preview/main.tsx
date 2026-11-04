import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { LocalInventoryPreview } from "../src/components/LocalInventoryPreview";
import zh from "../src/i18n/zh.json";
import "../src/index.css";

// Standalone i18n initialization does not call getSettings or use app startup.
const translation = {
  ...zh,
  localInventory: {
    ...zh.localInventory,
    hint: "只检查手动指定的目录，不同步或部署技能。请使用本机测试目录；网络路径可能触发系统网络访问。",
  },
};
await i18n.use(initReactI18next).init({
  resources: { zh: { translation } },
  lng: "zh",
  interpolation: { escapeValue: false },
});
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <main className="h-full overflow-auto p-6">
      <div className="app-page app-page-narrow">
        <header className="app-page-header">
          <h1 className="app-page-title">设备 · 只读清单组件预览</h1>
          <p className="app-page-subtitle">本测试使用正式设备页的清单组件，但不提供完整设备页或跨机同步功能。</p>
        </header>
        <LocalInventoryPreview />
      </div>
    </main>
  </StrictMode>,
);

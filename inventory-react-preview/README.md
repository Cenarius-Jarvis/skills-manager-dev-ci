# Isolated inventory component preview

This is an isolated test shell rendering the same LocalInventoryPreview React component used on the normal Devices page. It calls the same read-only inventory inspector through its own single registered Tauri command. It is not the normal application or remote synchronization.

Use a newly created local sample directory containing a child directory with a SKILL.md file. The scanner only checks metadata and does not read skill contents. It does not initialize the regular application's library or deploy skills. Network filesystem paths can involve operating system network access and should not be used for this local test. The WebView runtime may write its own cache.

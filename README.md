# 📝 LocalNotion

A self-hosted Notion-like workspace that runs entirely on your machine.

## Features
- 📄 Unlimited pages with nested subpages
- ✏️ Rich block editor (headings, bullets, todos, code, callouts, quotes, dividers)
- ⊞ Inline databases / tables with custom columns (text, number, select, checkbox)
- 🖱️ Drag & drop to reorder blocks and pages
- 🌙 Dark & light themes
- 💾 All data persisted in a local SQLite database (`instance/notion.db`)
- ⚡ `/` command menu to insert any block type
- 🔢 Sidebar page tree with collapsible nesting

---

## Setup

### 1. Install Python dependencies

```bash
cd notion-clone
pip install -r requirements.txt
```

### 2. Run the server

```bash
python app.py
```

### 3. Open in your browser

Navigate to: **http://127.0.0.1:5000**

---

## Project Layout

```
notion-clone/
├── app.py              ← Flask backend + SQLite models
├── requirements.txt
├── instance/
│   └── notion.db       ← Your data lives here (auto-created)
├── templates/
│   └── index.html
└── static/
    ├── css/style.css
    └── js/app.js
```

## Backup

Just copy `instance/notion.db` to back up all your pages and databases.

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Open block-type command menu |
| `Enter` | New block |
| `Backspace` (empty block) | Delete block |
| `↑ / ↓` | Navigate blocks or slash menu |
| `Shift+Enter` | Line break inside a block |

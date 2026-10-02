# Changelog

All notable changes to this project are documented here. The project follows Semantic Versioning; finding
codes (`svg.script`, `archive.bomb_size`, ...) and the `ScanResult` / `Policy` fields are part of the
compatibility contract.

## 0.1.0 — 2026-10-02

First release.

- Pure-Python magic-number sniffer (`upload_guard.detect`) covering ~120 formats with
  second-stage refinement for RIFF, ISO-BMFF (`ftyp`), EBML, ZIP-based (OOXML/ODF/EPUB/JAR/APK)
  and OLE2 (DOC/XLS/PPT/MSG/MSI) containers, plus browser-style text sniffing
  (SVG/HTML/XML/JSON/PHP/shell/PEM/vCard/iCalendar).
- Extension consistency checks with alias handling and allow/deny rules
  (`image/*`, `application/pdf`, `.docx`, `category:archive`).
- Filename safety checks (path traversal, null bytes, control and bidi-override characters,
  reserved names, dangerous/double extensions) and `sanitize_filename()`.
- SVG scanner/sanitiser (`scan_svg`, `sanitize_svg`) removing scripts, event handlers,
  script URIs, foreign objects, external references, dangerous CSS, entity declarations and
  processing instructions.
- Archive inspection for ZIP (including nested archives, overlapping entries, size verification,
  symlinks, Zip Slip) and gzip/bzip2/xz/tar via bounded streaming decompression (Tar Slip,
  symlink escapes, device nodes).
- Polyglot detection: embedded secondary signatures and trailing data after PNG/JPEG/GIF/PDF
  end markers.
- `UploadGuard` / `Policy` orchestrator with severity-based rejection and `ScanResult`.
- Duck-typed adapters for bytes, paths, file objects, FastAPI/Starlette `UploadFile`,
  Django `UploadedFile` and Werkzeug/Flask `FileStorage`; stream positions are restored.
- Framework helpers: `integrations.fastapi` (`validate_upload`, `Guarded`),
  `integrations.django` (`UploadGuardValidator`, `validate_upload`),
  `integrations.flask` (`validate_upload`).
- `upload_guard` CLI (`scan`, `detect`).

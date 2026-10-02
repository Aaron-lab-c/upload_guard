# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub Security Advisories ("Report a vulnerability") on the
repository rather than in public issues. We aim to acknowledge within 3 business days.

## Threat model

### Assets
- **The server** that receives uploads (its filesystem, memory and CPU).
- **Other users' browsers** that later download or render what was uploaded.
- **Downstream consumers** of stored files (image processors, archive extractors, office converters).

### In scope — what the library defends against

| Threat | Mitigation |
|---|---|
| Executable / script disguised with a harmless extension (`cute.png` is a PE, `shell.jpg` is PHP) | Type is decided from content (magic numbers, browser-style text sniffing), never from the extension or `Content-Type`. Allow-lists are evaluated against the detected type; executables and scripts are blocked by default. |
| Stored XSS through "images" or "text" that a browser renders as HTML/SVG | Text that a browser would sniff as HTML is classified `text/html`; SVGs are sanitised (scripts, event handlers, `javascript:`/`data:text/html` URIs, `<foreignObject>`, HTML elements, external references, dangerous CSS) or rejected. |
| XML entity attacks in SVG (billion laughs, XXE) | `<!ENTITY>` declarations are rejected before parsing; DOCTYPE and processing instructions are stripped so the XML parser never sees them. |
| Decompression bombs (ZIP, gzip, bzip2, xz, tar, DOCX/XLSX/PPTX/ODF) | Declared sizes and ratios from the central directory; nested archives inspected recursively within bounds; overlapping-entry bombs detected; optional real decompression with a hard output cap; gzip/bzip2/xz/tar are streamed through a bounded decompressor that never buffers more than 64 KiB. |
| Zip Slip / Tar Slip (`../`, absolute paths, symlinks pointing outside) | Every member path and link target is checked; symlinks and device nodes are flagged. |
| Path traversal and filesystem tricks via the filename | `../`, separators, drive letters, null bytes, control characters, reserved device names, trailing dots/spaces, `.htaccess`/`web.config` are flagged; `sanitize_filename()` yields a safe basename. |
| Extension spoofing with Unicode (RTLO `invoice_‮gnp.exe`) and double extensions (`shell.php.jpg`) | Bidi-override and zero-width characters are CRITICAL findings; executable inner extensions are flagged. |
| Polyglot files (GIFAR, PDF+ZIP, image with appended PHP) | Secondary format signatures inside the file and data appended after PNG/JPEG/GIF/PDF end markers are reported. |
| The validator itself as a DoS vector | Fixed read sizes (2 KiB sniff, 1 MiB polyglot scan, 64 KiB tail), bounded decompression, element/depth caps for SVG, size limits enforced before content checks, non-seekable inputs spooled with a cap. |

### Out of scope

- Vulnerabilities in downstream parsers (image decoders, PDF renderers, office suites). Detection is
  signature-based; a well-formed header followed by a malicious payload for a specific decoder is still
  "a PNG". Pair with a decoder-level check (e.g. Pillow `Image.verify()`) when that matters.
- Contents of encrypted ZIP entries, 7z, RAR and Zstandard archives (identified, not inspected).
- Malware scanning / antivirus. upload_guard checks structure and intent, not signatures of known malware.
- Serving uploaded files safely (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`,
  a separate origin for user content). These remain the application's responsibility.
- Authorisation and quota decisions about *who* may upload *how much*.

## Operational recommendations

- Store files under the **detected** extension (`result.extension`) and the sanitised name
  (`result.safe_filename`), never under the client-supplied path.
- Serve user uploads from a separate origin with `X-Content-Type-Options: nosniff` and, for anything
  not meant to be rendered inline, `Content-Disposition: attachment`.
- If you accept SVG, keep `sanitize_svg=True` and store `result.sanitized`, or exclude `image/svg+xml`
  from `allowed` entirely.
- Set `max_size` and `ArchiveLimits` to what your service can actually afford to process.

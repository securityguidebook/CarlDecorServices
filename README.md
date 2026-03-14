# Carl Decor CRM Portal — Security Architecture

> **Live site:** [securityguidebook.github.io/carldecor-crm-portal](https://securityguidebook.github.io/carldecor-crm-portal/)  
> **Stack:** Vanilla HTML/CSS/JS · GitHub Pages · Static hosting  
> **Purpose:** Client-facing CRM landing page for a handyman business (Auckland, NZ), built and security-hardened as a practical cybersecurity portfolio project.

---

## Project Summary

This project demonstrates the application of real-world web security controls to a client-facing, form-based website. The site collects customer quote requests, making the contact form the primary attack surface. Each control below was deliberately chosen to address a specific threat, implemented from scratch without third-party security plugins, and is documented here with reasoning — not just a feature list.

---

## Threat Model

| Asset | Threat | Attack Vector | Control Implemented | Residual Risk |
|---|---|---|---|---|
| Contact form | Cross-Site Scripting (XSS) | Malicious input in name/description fields rendered as HTML | Input sanitization + Content Security Policy | Low — CSP blocks inline execution even if sanitization is bypassed |
| Contact form | Spam / bot submissions | Automated form filling by bots | Honeypot field + client-side rate limiting | Low — server-side rate limiting (Formspree/Cloudflare) is the authoritative layer |
| Page content | Clickjacking | Site embedded in a malicious iframe to capture clicks | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` | Negligible |
| Outbound links | Referrer leakage | Full URL sent in `Referer` header to third-party destinations | `Referrer-Policy: strict-origin-when-cross-origin` | Negligible |
| CDN assets | Supply chain / MITM | Tampered scripts served from compromised CDN | Crossorigin attribute on font requests; SRI hashes (planned) | Low |
| Browser APIs | Privacy / capability abuse | Page silently accessing camera, mic, payment APIs | `Permissions-Policy` disabling unused APIs | Negligible |
| MIME types | MIME sniffing attacks | Browser misinterpreting response content type | `X-Content-Type-Options: nosniff` | Negligible |
| Form endpoint | Data interception | Credentials or form data sent over HTTP | HTTPS enforced by GitHub Pages (TLS 1.2/1.3) | Negligible |

---

## Controls Implemented

### 1. Content Security Policy (CSP)

**Threat addressed:** Cross-Site Scripting (XSS), data exfiltration, unauthorised resource loading.

CSP is declared via `<meta http-equiv>` (the GitHub Pages equivalent of a server header), restricting what resources the browser will load and execute.

```html
<meta http-equiv="Content-Security-Policy"
  content="
    default-src 'self';
    script-src  'self' 'nonce-CARLDECOR2026' https://challenges.cloudflare.com;
    style-src   'self' 'unsafe-inline' https://fonts.googleapis.com;
    font-src    'self' https://fonts.gstatic.com;
    img-src     'self' data: https://images.unsplash.com;
    frame-src   https://challenges.cloudflare.com;
    connect-src 'self' https://formspree.io;
    object-src  'none';
    base-uri    'self';
    form-action 'self' https://formspree.io;
  " />
```

**Directive decisions:**
- `default-src 'self'` — deny-by-default; all unlisted resource types are blocked
- `script-src` uses a **nonce** (`nonce-CARLDECOR2026`) so only the inline script block with the matching nonce executes — injected scripts have no nonce and are blocked
- `object-src 'none'` — blocks Flash and plugin-based XSS entirely
- `base-uri 'self'` — prevents base tag injection attacks that redirect relative URLs
- `form-action` — restricts where form data can be sent, blocking data exfiltration via form hijacking

**Limitation / next step:** Nonce values should be randomly generated per-request server-side (e.g. via Cloudflare Workers). A static nonce is an improvement over no CSP but is not cryptographically strong. This is documented in [Future Work](#future-work).

---

### 2. Input Sanitization

**Threat addressed:** Stored/reflected XSS via user-controlled form input.

All form values are sanitized client-side before submission using a custom `Security.sanitize()` function. This encodes the five characters that enable HTML injection:

```javascript
sanitize(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}
```

**Why client-side sanitization is defense-in-depth, not the primary control:**  
Client-side JS can be bypassed by anyone using curl or intercepting requests. The canonical defence is server-side sanitization at the point of storage/rendering. Here it serves as an early filter and as a visible, documentable security layer. When integrated with Formspree or a backend, server-side sanitization should be added.

---

### 3. Input Validation

**Threat addressed:** Malformed data, oversized payloads, unexpected input types.

Each field is validated against an allowlist pattern before submission. An invalid allowlisted service value (e.g. injected via DevTools) is rejected before the payload is constructed:

```javascript
validators: {
  name:        v => v.length >= 2 && v.length <= 100 && /^[a-zA-Z\s'\-\.]+$/.test(v),
  email:       v => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v) && v.length <= 254,
  phone:       v => /^[\d\s\+\-\(\)]{7,20}$/.test(v),
  service:     v => ['plumbing','electrical','maintenance','furniture',
                     'painting','tiling','other'].includes(v),
  description: v => v.length >= 10 && v.length <= 2000,
},
```

HTML `maxlength` attributes are also set on all inputs as a secondary constraint.

---

### 4. Honeypot Anti-Spam Field

**Threat addressed:** Automated bot form submissions.

A hidden `<input>` field (`#website`) is present in the DOM but invisible to real users via CSS (`opacity: 0; height: 0; pointer-events: none`). Automated bots that traverse the DOM and fill all fields will populate this field. The submission handler checks for a non-empty honeypot value and silently drops the submission — deliberately showing a fake success message so the bot doesn't know it was detected and doesn't retry with different strategies.

```javascript
isBot() {
  const hp = document.getElementById('website');
  return hp && hp.value.length > 0;
}

// In submit handler:
if (Security.isBot()) {
  successMsg.style.display = 'block'; // fake success
  form.reset();
  return; // silently dropped
}
```

**Why silent rejection?** Returning an error tells the bot its detection was triggered, allowing it to adapt. Silent drop is the standard practice.

---

### 5. Client-Side Rate Limiting

**Threat addressed:** Rapid repeat submissions, spam floods, simple DoS against the form endpoint.

Submission timestamps are tracked in-memory. If more than 3 submissions occur within a 60-second window, further submissions are blocked and a visible warning is shown:

```javascript
rateLimit: {
  MAX_SUBMISSIONS: 3,
  TIME_WINDOW_MS:  60 * 1000,
  timestamps: [],
  check() {
    const now = Date.now();
    this.timestamps = this.timestamps.filter(t => now - t < this.TIME_WINDOW_MS);
    if (this.timestamps.length >= this.MAX_SUBMISSIONS) return false;
    this.timestamps.push(now);
    return true;
  }
}
```

**Limitation acknowledged:** In-memory rate limiting resets on page refresh. The authoritative layer is server-side — Formspree enforces its own submission limits; a Cloudflare Workers backend could enforce IP-based rate limiting with KV storage. This client layer reduces load on the backend.

---

### 6. Anti-Clickjacking Headers

**Threat addressed:** UI redressing / clickjacking — where an attacker embeds the site in a transparent iframe to hijack user clicks.

```html
<meta http-equiv="X-Frame-Options" content="DENY" />
```

CSP also includes `frame-ancestors 'none'` via the `frame-src` directive. Both are set as defense-in-depth since browser support for each varies across older versions.

---

### 7. MIME Sniffing Prevention

**Threat addressed:** Browser MIME-type confusion attacks where a response with an incorrect `Content-Type` is executed as a different type (e.g. a text file executed as JavaScript).

```html
<meta http-equiv="X-Content-Type-Options" content="nosniff" />
```

---

### 8. Referrer Policy

**Threat addressed:** Leaking full URLs (including query parameters) to third-party domains via the HTTP `Referer` header when a user follows an outbound link.

```html
<meta name="referrer" content="strict-origin-when-cross-origin" />
```

This sends only the origin (not the path) on cross-origin requests, and the full URL only on same-origin requests.

---

### 9. Permissions Policy

**Threat addressed:** Malicious scripts silently accessing browser APIs (camera, microphone, payment) the site has no legitimate need for.

```html
<meta http-equiv="Permissions-Policy"
      content="camera=(), microphone=(), geolocation=(), payment=()" />
```

Empty parentheses `()` explicitly deny access to these APIs for all origins, including the page itself.

---

### 10. HTTPS / TLS

**Threat addressed:** Man-in-the-middle attacks, credential and form data interception in transit.

GitHub Pages enforces HTTPS automatically with a valid TLS certificate (Let's Encrypt). HSTS (HTTP Strict Transport Security) is set by GitHub at the infrastructure level, ensuring the browser will not attempt an HTTP connection even if a user types `http://`. No additional configuration required.

---

### 11. Double-Submission Prevention

**Threat addressed:** Race conditions from users clicking submit multiple times, causing duplicate entries.

The submit button is disabled and its label changed to "Sending…" immediately on the first valid submission. It is re-enabled only after the response resolves.

---

### 12. CAPTCHA Integration Point (Cloudflare Turnstile)

The form includes a clearly marked integration point for Cloudflare Turnstile — a privacy-respecting, challenge-free CAPTCHA alternative. The Turnstile script is included (commented out pending a site key) and the form's CSP `script-src` and `frame-src` already whitelist `challenges.cloudflare.com` in anticipation of activation.

Turnstile was chosen over reCAPTCHA v2 because: it requires no user interaction for legitimate users, it does not track users across sites, and it is free with a Cloudflare account.

---

## Security Headers — Verification

To verify the headers are active on the live site, run either of these tools:

| Tool | URL |
|---|---|
| SecurityHeaders.com | `https://securityheaders.com/?q=securityguidebook.github.io/carldecor-crm-portal` |
| Mozilla Observatory | `https://observatory.mozilla.org/analyze/securityguidebook.github.io` |

> **Note:** Meta-tag equivalents of security headers are partially parsed by these tools. Server-sent headers (possible via `_headers` on Netlify or `vercel.json`) achieve higher scores and are the recommended production approach.

---

## Repository Structure

```
carldecor-crm-portal/
├── index.html          # Main page — all security controls implemented here
├── README.md           # This file — security architecture documentation
└── img/                # (To be added) Job photos, before/after images
```

---

## Future Work

The following improvements represent the next iteration of hardening. Documenting known gaps is a sign of security maturity, not weakness.

| Priority | Control | Reason Not Yet Implemented |
|---|---|---|
| High | Server-side input sanitization & validation | Requires a backend (Cloudflare Workers or similar) |
| High | Cryptographically random CSP nonce per request | Requires server-side rendering; static GitHub Pages cannot generate per-request nonces |
| High | IP-based server-side rate limiting | Requires backend (Cloudflare Workers + KV store) |
| Medium | Subresource Integrity (SRI) on Google Fonts | Font URLs include version hashes; SRI hash must be pre-computed and kept in sync |
| Medium | Cloudflare Turnstile CAPTCHA activation | Pending Cloudflare account and site key |
| Medium | HSTS `preload` directive | Requires domain ownership and submission to the HSTS preload list |
| Low | Cookie security flags (`HttpOnly`, `SameSite`, `Secure`) | No cookies are currently set; relevant if session management is added |
| Low | OWASP ZAP scan in GitHub Actions CI | Would automate regression testing for new security issues on each push |

---

## Skills Demonstrated

- Threat modelling for a real client-facing web application
- Content Security Policy design and nonce-based script allowlisting
- XSS mitigation via input sanitization and output encoding
- Anti-automation techniques (honeypot, rate limiting, CAPTCHA integration)
- Security header configuration and their browser behaviour
- Defense-in-depth layering (multiple controls covering the same threat)
- Honest documentation of limitations and residual risk

---

*Built by [securityguidebook](https://github.com/securityguidebook) — a cybersecurity portfolio project demonstrating practical web security hardening on a live client site.*

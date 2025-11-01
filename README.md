# 🔒 Token Security Experiment

**Secure vs Insecure Token Storage in Web Applications: A Demonstration of HttpOnly Cookies vs Client-Side Storage**

A practical security experiment demonstrating XSS-based token theft vulnerabilities and HttpOnly cookie protection.

---

## 📋 Overview

This experiment demonstrates why storing authentication tokens in `localStorage` or `sessionStorage` is dangerous and how **HttpOnly cookies** provide superior protection against Cross-Site Scripting (XSS) attacks.

**Real-World Context:**  
In September 2018, British Airways suffered a security breach affecting 380,000 customers, resulting in a **£183 million fine**. The attack exploited tokens stored in localStorage - the exact vulnerability this experiment demonstrates.

---

## 🎯 Learning Objectives

- Understand XSS-based token theft attacks
- Compare localStorage vs HttpOnly cookie security
- Learn industry best practices for web authentication
- Demonstrate practical vulnerability exploitation

**Target Audience:** Undergraduate computer security students

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- **Node.js** 14 or higher ([Download here](https://nodejs.org/))
- **Web Browser** with DevTools (Chrome, Firefox, or Edge)

### Installation

```bash
# Clone the repository
git clone https://github.com/malakh727/token-security-experiment.git
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

### Step 1: Setup Authentication (Insecure Method)

1. Click **"Login (Insecure - JSON Token)"**
2. Click **"Store Token in localStorage"**
3. Open DevTools (F12) → Application → Local Storage
4. Observe the stored token

### Step 2: Setup Authentication (Secure Method)

1. Click **"Login (Secure - HttpOnly Cookie)"**
2. Open DevTools → Application → Cookies
3. Notice the **HttpOnly** flag is checked ✓

### Step 3: Execute XSS Attack Simulation

1. Click **"Execute XSS Attack on localStorage"**
   - **Result:** 🔴 **ATTACK SUCCESSFUL** - Token stolen!
2. Click **"Execute XSS Attack on HttpOnly Cookie"**
   - **Result:** 🟢 **ATTACK FAILED** - Token protected!

### Step 4: Verify Protection

1. Click both "Access" buttons to confirm legitimate use works
2. Inspect security flags in DevTools → Cookies tab

---

## 📊 Results

| Storage Method      | XSS Attack Result | Security Rating |
| ------------------- | ----------------- | --------------- |
| **localStorage**    | ❌ Token Stolen   | 🔴 VULNERABLE   |
| **sessionStorage**  | ❌ Token Stolen   | 🔴 VULNERABLE   |
| **HttpOnly Cookie** | ✅ Protected      | 🟢 SECURE       |

**Conclusion:** HttpOnly cookies prevent JavaScript-based token theft even when XSS vulnerabilities exist.

---

## 🌍 Real-World Examples

### British Airways (2018)

- **Attack:** XSS injection stealing payment data from localStorage
- **Impact:** 380,000 customers affected
- **Cost:** £183 million fine + lawsuits
- **Prevention:** HttpOnly cookies would have blocked token theft

### Other Major Incidents

- **MySpace Samy Worm (2005):** 1M+ profiles infected via localStorage XSS
- **TweetDeck (2014):** Self-retweeting worm exploiting token storage
- **Magecart Attacks (2018-Present):** 100,000+ e-commerce sites compromised

All exploited localStorage. All preventable with HttpOnly cookies.

---

## 🛡️ Security Best Practices

### ✅ DO:

- Store authentication tokens in **HttpOnly cookies**
- Set `Secure` flag (HTTPS only)
- Set `SameSite=Strict` (prevent CSRF)
- Implement short session timeouts (1-2 hours)
- Use Content Security Policy (CSP)

### ❌ DON'T:

- Store sensitive tokens in localStorage/sessionStorage
- Trust client-side storage for authentication
- Assume XSS vulnerabilities won't be exploited

### Implementation Example

```javascript
// ❌ INSECURE
res.json({ token: "abc123" });
// Client: localStorage.setItem('token', token)

// ✅ SECURE
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

## 🔧 Technical Details

### Technologies Used

- **Backend:** Node.js, Express.js
- **Frontend:** HTML5, JavaScript (Vanilla)
- **Middleware:** cookie-parser, cors
- **Testing:** Browser DevTools

### Server Endpoints

| Endpoint                  | Method | Purpose                     |
| ------------------------- | ------ | --------------------------- |
| `/api/login-insecure`     | POST   | Returns JSON token          |
| `/api/login-secure`       | POST   | Sets HttpOnly cookie        |
| `/api/protected-insecure` | GET    | Validates token from header |
| `/api/protected-secure`   | GET    | Validates HttpOnly cookie   |

### Security Flags Explained

- **HttpOnly:** Prevents JavaScript access to cookie
- **Secure:** Cookie only sent over HTTPS
- **SameSite:** Prevents CSRF attacks
  - `Strict`: Cookie never sent cross-site
  - `Lax`: Cookie sent on top-level navigation
  - `None`: Cookie sent everywhere (requires Secure)

---

## 📚 Documentation

**Full documentation available:** [`docs/report.pdf`](docs/report.pdf)

**Contents:**

1. Objective & Learning Outcomes
2. System Setup Instructions
3. Required Tools & Software
4. Step-by-Step Experiment Guide
5. Results & Analysis
6. Real-World Case Studies
7. Security Best Practices
8. References

---

## 🎓 Educational Use

This experiment is designed for:

- Computer Security courses
- Web Development security modules
- Penetration testing workshops
- Security awareness training

**Note:** This is a safe, educational demonstration performed in a controlled local environment. No actual attacks are performed on external systems.

---

## 📖 References

1. [OWASP - Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
2. [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
3. [MDN Web Docs - HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
4. [British Airways Data Breach (ICO Report)](https://baways.com/)
5. [OWASP Top 10 Web Application Security Risks](https://owasp.org/Top10/)

---

_"Security is not a product, but a process." - Bruce Schneier_

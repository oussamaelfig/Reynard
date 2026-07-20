# Business Logic Vulnerabilities Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Logic flaws arise from flawed assumptions about how users interact with the
> app. No single payload — you exploit the *rules*, not the parser.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Model the Intended Workflow
- Enumerate every multi-step flow: checkout, registration, password change,
  role assignment, discounts, funds transfer.
- For each step, ask: "What does the server *assume* the client already did?"

### 1.2 Hunt for Trust Boundaries
- Client-side-only validation (price, quantity, role in a hidden field)
- Values the server trusts from the request (email domain, `isAdmin`, price)
- Steps that can be skipped, reordered, or repeated

---

## Phase 2: Exploitation Techniques

### 2.1 Parameter Tampering
- Negative or huge quantities, negative price, currency mismatch
- Change `price`, `total`, `role`, `userId` in the request the client sends
```
POST /cart  quantity=-1
POST /checkout  price=0
```

### 2.2 Excessive Trust in Client Input
- App infers privilege/discount from a field you control (e.g. `roleid=1`,
  `email=x@target-internal.com` grants staff access).

### 2.3 Broken/Skippable Workflow Steps
- Jump straight to the confirmation endpoint without paying.
- Reuse a coupon/gift beyond its intended limit (see race_conditions.md).
- Complete purchase, then add more items before the order finalizes.

### 2.4 Flawed Assumptions & Edge Cases
- Overflow numeric limits (integer wrap on quantity -> negative total).
- Truncation: an email length cap truncates `attacker@evil.com.target.com`
  down to a trusted domain.
- Inconsistent validation between endpoints for the "same" value.

### 2.5 Authentication/Authorization Logic
- 2FA/step-up that can be omitted; discount tiers based on unverified data.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Excessive trust in client-side controls**: resend with tampered `price`.
- **High-level logic flaw**: negative quantity to reduce the total.
- **Inconsistent security controls**: register with a trusted email domain.
- **Flawed enforcement of business rules**: stack two discount codes.
- **Low-level logic flaw**: integer overflow on quantity.
- **Authentication bypass via encryption oracle** / **email truncation**: abuse
  length limits or padding oracles to reach a trusted state.

---

## Phase 4: Tools & Automation
- Burp Repeater to replay and mutate individual steps.
- Compare the *client-enforced* rules (JS) against server enforcement.
- Diff responses when a required step is skipped vs performed.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Value re-validated server-side | Find a second endpoint that trusts it |
| Step cannot be skipped | Try reordering or repeating instead |
| No obvious flaw | Attack numeric edges (negatives, overflow, truncation) |

## Success Criteria
- [ ] Achieved an outcome the workflow was meant to prevent (free/underpriced
      purchase, privilege gain, limit bypass)
- [ ] Lab shows "solved"

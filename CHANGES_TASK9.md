# Task 9 — Landing-page auth flow restructure

This task replaces the single "Send Code" landing CTA (plus the small
"Use a password instead" link) with two equally weighted buttons:
**Sign Up** and **Sign In**. Each button consults the new Supabase RPC
`public.email_account_status(p_email)` so the user is never silently
shunted into the wrong path (e.g. creating a fresh account when one
already exists, or being told "no account" when one does).

> The SQL migration that creates `email_account_status` was applied to
> the Supabase project separately by the user before these front-end
> changes. No DB changes ship in this commit.

---

## Files touched

| File | What changed |
|------|--------------|
| `app.js` | Auth section rewritten (see line refs below); dead `ldp_pw_prompt_dismissed_v1` machinery removed; mandatory post-OTP password setup; new `emailAccountStatus()` RPC helper; new `lpSignUp`, `lpSignIn`, `lpSignInWithCode`; rewritten `lpForgotPassword`, `lpSignInWithPassword`, `lpShowPasswordStep`, `lpShowSetPasswordStep`; legacy `lpSendOTP` + `lpSkipPassword` deleted; Pranav string at app.js:695 replaced. |
| `index.html` | `lp-step-email` rebuilt with `Sign Up` + `Sign In` buttons next to the email input; password step copy + link labels updated; skip button removed from set-password step. |
| `styles.css` | Added `.ics-modal-overlay.show { display: flex; }` (Profile modal fix). Added `.lp-auth-row` / `.lp-auth-btns` / `.lp-auth-btn` for the two-button layout. |

### Key app.js line references (post-change)

- `~165-185` — `onAuthStateChange` no longer reads `ldp_pw_prompt_dismissed_v1`; routes to mandatory set-password step on signup / forgot-password / password-fallback contexts.
- `~422-602` — Task 9 helpers and the two button entry points (`emailAccountStatus`, `_sendOtpForContext`, `lpSignUp`, `lpSignIn`).
- `~673-707` — `lpResendOTP` resends in the stored context (`signup` keeps `shouldCreateUser:true`; everyone else `false`).
- `~712-735` — `lpShowPasswordStep(opts)` shows the password field; uses `opts.hasPassword` to render the inline "your account doesn't have a password yet" hint for the legacy edge case.
- `~737-797` — `lpSignInWithPassword` no longer auto-creates accounts. For accounts without a password, a failed `signInWithPassword` redirects to OTP with `password_fallback` context and `_ldp_forceSetPassword=true`.
- `~801-806` — `lpSignInWithCode` (the "Login using code instead?" link).
- `~810-816` — `lpForgotPassword` rewritten — sends OTP with `forgot_password` context, sets `_ldp_forceSetPassword=true`.
- `~822-840` — `lpShowSetPasswordStep(mode, opts)` accepts `opts.force`; the belt-and-suspenders `currentUser.user_metadata.has_password===true` early return is preserved, but is bypassed when `opts.force` is true.
- `~695` — Pranav string replaced with `"Check your email — we sent a verification code. Enter it above to finish signing in."`.

### Key index.html line references (post-change)

- `~45-55` — new email + two-button row (Sign Up / Sign In). Old `Send Code →` button and `Use a password instead` link are gone.
- `~57-69` — password step: header is "Sign in to <email>"; the misleading "New here? Just enter a password — we'll create your account." line is removed; the two action links below the password field are now **Login using code instead?** and **Forgot password?**, plus a "Use a different email" back-link.
- `~84-91` — set-password step has no skip button.

### Key styles.css line references (post-change)

- `~625` — `.ics-modal-overlay.show { display: flex; }` (Profile modal fix).
- `~730-744` — `.lp-auth-row`, `.lp-auth-btns`, `.lp-auth-btn` plus a mobile media query stacking the buttons under the email field.

---

## Before / after auth flow per user state

### A. New user (no account) — Sign Up

```
Before: email → Send Code → OTP → set-password (skippable) → dashboard
After:  email → Sign Up → whitelist + RPC (account_exists=false)
        → OTP step → verify → MANDATORY set-password → dashboard
```

### B. Existing user with password — Sign In (password path)

```
Before: email → Send Code → OTP → dashboard
        (or) Use-a-password-instead → password field → signInWithPassword → dashboard
After:  email → Sign In → whitelist + RPC (account_exists=true, has_password=true)
        → password field → signInWithPassword → dashboard
```

### C. Existing user with password — Sign In via code

```
Before: not really a separate sub-flow.
After:  email → Sign In → password field → "Login using code instead?"
        → OTP step (signin_code) → verify → dashboard
        (set-password step is skipped by the belt-and-suspenders check
        because has_password === true and _ldp_forceSetPassword is false.)
```

### D. Existing user — Forgot password

```
Before: email → password step → Forgot password → cleared dismissed flag
        → user clicked Send Code → OTP → optional set-password.
After:  email → Sign In → password field → "Forgot password?"
        → OTP step (forgot_password, _ldp_forceSetPassword=true)
        → verify → MANDATORY set-password (force=true, bypasses
        has_password belt-and-suspenders) → dashboard
```

### E. Existing user without a password (legacy edge case)

```
Before: password-signup path could create a new auth.users row at the
        same email if Supabase had Confirm-email OFF — unsafe.
After:  email → Sign In → RPC says account_exists=true, has_password=false
        → password field shown anyway with an inline hint
          "Your account doesn't have a password yet. We'll send you a code to set one."
        → user submits → signInWithPassword fails →
        auto-redirect to OTP (password_fallback, _ldp_forceSetPassword=true)
        → verify → MANDATORY set-password → dashboard.
```

---

## Mandatory password setup — what changed

`lpShowSetPasswordStep(mode, opts)` now takes a second arg.

- The belt-and-suspenders guard (`if currentUser.user_metadata.has_password === true → onSignIn()`) is preserved. It still skips the prompt for returning users signing in via the code-instead path.
- It is bypassed when `opts.force === true`, which is set by the
  forgot-password and password-fallback paths.
- The Skip button is removed from the DOM and `lpSkipPassword()` is
  deleted from `app.js`.
- All reads and writes of `localStorage` key `ldp_pw_prompt_dismissed_v1` are removed (previously at app.js lines 184, 668, 726, 801, 823, 2052, 2224).

---

## Diagnostic logs

Per task spec, the following are now emitted (kept in place pending a
follow-up cleanup):

- `[auth] signup attempt: <email> account_exists: <bool>`
- `[auth] signin attempt: <email> account_exists: <bool> has_password: <bool>`
- `[auth] OTP sent to: <email> context: <signup|signin_code|forgot_password|password_fallback>`
- `[auth] mandatory password setup shown for: <email>`
- `[auth] RPC email_account_status failed: <err>`
- `[auth] password signin failed, redirecting to OTP: <email>` (legacy / has_password=false case)
- `[auth] password signin failed: <email>` (wrong-password case)

---

## Manual test plan (matches spec scenarios A–I)

### A. New user signup
1. In a fresh browser, open the landing page.
2. Type `test123@alumni.esade.edu` into the email field.
3. Click **Sign Up**. Expect inline "Code sent" message.
4. Check inbox, copy the 8-digit code.
5. Paste into the OTP field, click **Verify →**.
6. The set-password step appears with **no skip button**.
7. Type a password ≥ 8 chars, click **Save Password →**.
8. Land in the dashboard.

### B. Repeat signup with the same email
1. Sign out.
2. Type `test123@alumni.esade.edu` again, click **Sign Up**.
3. Expect inline error **"You already have an account. Use Sign In."**
4. Confirm no OTP email arrived in the inbox.

### C. Existing user with password signs in by password
1. Type `shrey.singhal@alumni.esade.edu`, click **Sign In**.
2. Password field appears (with no "no password yet" hint).
3. Enter the correct password, click **Sign In →**.
4. Land in the dashboard.

### D. Existing user signs in by code
1. Same email, click **Sign In** → password field.
2. Click **Login using code instead?**
3. Inbox receives an 8-digit code.
4. Enter the code, click **Verify →**.
5. Land in the dashboard directly — **no set-password step** is shown.

### E. Forgot password
1. Same email, click **Sign In** → password field.
2. Click **Forgot password?**
3. Inbox receives an 8-digit code.
4. Enter the code, click **Verify →**.
5. The set-password step appears (mandatory — no skip).
6. Type a new password, click **Save Password →**. Land in the dashboard.
7. Sign out and sign back in with the new password to confirm it took.

### F. Non-whitelisted email
1. Type `test@gmail.com`, click either **Sign Up** or **Sign In**.
2. The whitelist error message appears.
3. Confirm in DevTools Network tab that **no RPC** to `rpc/email_account_status` and **no auth call** went out.

### G. Sign In with a brand-new email
1. Type `nobody-here-yet@hec.edu`, click **Sign In**.
2. Expect inline error **"No account found. Use Sign Up to create one."**
3. No OTP sent.

### H. Profile modal
1. Sign in (any account).
2. Click the **Profile** button in the topbar.
3. The modal appears centered, with a backdrop blur. Name and school fields are prefilled.
4. Type in the school field — autocomplete dropdown opens; clicking an option populates it.
5. Click the close (×) or click outside the modal — it closes cleanly.

### I. Pranav grep
From the repo root, run:

```sh
grep -i pranav app.js index.html styles.css
```

Expect zero matches. (Verified at task completion.)

---

## Edge cases observed / decisions

1. **Legacy `has_password=false` users.** Per spec we still show the
   password field as the default Sign In view. The hint message warns
   them, and the submit-failure handler routes them through OTP with
   forced password setup. This means a wrong-password attempt on such
   an account inevitably triggers an OTP email — acceptable trade-off
   because such accounts are vanishingly rare.

2. **`shouldCreateUser`.** Set to `true` only when the context is
   `signup`. Existing-user paths (`signin_code`, `forgot_password`,
   `password_fallback`) pass `false` so a future Supabase config change
   can't allow these paths to spawn ghost accounts.

3. **Resend in the right context.** `lpResendOTP` re-uses the stored
   `_otpContext` (set by `_sendOtpForContext`) so a resend during a
   signin_code flow doesn't accidentally flip into a `shouldCreateUser`
   request.

4. **Belt-and-suspenders preserved.** The `has_password === true` early
   return inside `lpShowSetPasswordStep` is **not** removed. The
   forgot-password path bypasses it through the new `opts.force` arg.
   This keeps the function safe to call from anywhere without
   accidentally re-prompting a returning user.

5. **`onAuthStateChange` no longer reads the dismissed flag.** Before
   Task 9 a user who skipped the prompt once would never see it again.
   That accommodation is gone — password setup is now part of the
   signup contract, full stop, with the belt-and-suspenders preventing
   re-prompts for users who already have a password.

6. **Enter key on the email field.** Pressing Enter now invokes
   `lpSignIn()` (returning users dominate). Sign Up still requires an
   explicit click; the friction is intentional, mirroring "are you
   sure you want a new account".

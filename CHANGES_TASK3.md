# Task 3 — Fix: OTP sign-in incorrectly shows set-password prompt for returning users

## What changed and where

### 1. `onAuthStateChange` handler (app.js ~line 177)

The primary guard. When `_ldp_lastSigninWasOtp` is true (i.e., the user just
verified an OTP code), we now check `currentUser.user_metadata.has_password`
before deciding whether to show the set-password prompt:

```js
if(currentUser?.user_metadata?.has_password === true){
  // fall through to onSignIn() below
} else {
  const dismissed = localStorage.getItem('ldp_pw_prompt_dismissed_v1') === 'true';
  if(!dismissed){
    lpShowSetPasswordStep('after_otp');
    return;
  }
}
```

Comparison is `=== true` (strict) so that `undefined` and `false` both
continue to the prompt, preserving the first-time-user experience.

### 2. `lpShowSetPasswordStep()` (app.js ~line 740)

Belt-and-suspenders guard at the top of the function:

```js
if(currentUser?.user_metadata?.has_password === true){
  console.warn('[lpShowSetPasswordStep] set-password step called but user already has password — skipping');
  onSignIn();
  return;
}
```

Calls `onSignIn()` instead of just returning, so the user lands on the
dashboard rather than being stuck on the landing page.

### 3. `lpVerifyOTP()` — diagnostic log (app.js ~line 537)

After `verifyOtp` resolves successfully (and `onAuthStateChange` has already
updated `currentUser`):

```js
console.log('[lpVerifyOTP] post-verify, has_password:', currentUser?.user_metadata?.has_password);
```

Lets you see the exact value in DevTools during testing.

### 4. `onSignIn()` — no change needed

`onSignIn()` renders the dashboard and does not contain any password prompt.
No guard was required there.

---

## Logic flow for the three scenarios

### A. Returning user with password, signs in via OTP → no prompt → dashboard

1. User enters email, clicks "Send Code" → OTP email arrives.
2. User enters 6-digit code, `lpVerifyOTP()` runs.
3. `window._ldp_lastSigninWasOtp = true` is set before `verifyOtp`.
4. Supabase verifies OTP; `onAuthStateChange` fires synchronously with the
   new session. `currentUser` is populated with `user_metadata.has_password === true`.
5. Handler sees `_ldp_lastSigninWasOtp === true`, checks `has_password`:
   `=== true` → **falls through**, skips the `dismissed` / `lpShowSetPasswordStep` branch.
6. `await onSignIn()` runs → user lands on dashboard. ✓

### B. Returning user with password, signs in via password → no prompt → dashboard

1. User enters email + password, submits password form.
2. `lpSignInWithPassword()` (unchanged) calls `sb.auth.signInWithPassword()`.
3. `_ldp_lastSigninWasOtp` is never set, so the OTP branch in
   `onAuthStateChange` is never entered.
4. `await onSignIn()` runs normally → dashboard. ✓
   (This was already correct before Task 3.)

### C. Brand new user via OTP, no password yet → prompt shown (correct behavior)

1. New user enters email, verifies OTP code.
2. `onAuthStateChange` fires; `currentUser.user_metadata.has_password` is
   `undefined` (flag not set yet).
3. `undefined === true` is `false` → enters the `else` branch.
4. Checks `localStorage` for dismissal; not dismissed → calls
   `lpShowSetPasswordStep('after_otp')`.
5. Prompt renders. User can set a password (which will call `lpSetPassword()`
   and set `has_password = true`) or skip. ✓

---

## How to test manually

### Scenario A
1. Use an account that has previously set a password (`has_password === true`).
2. Open DevTools → Console tab.
3. Click "Sign in with email code" on the landing page; enter email, submit.
4. Enter the 6-digit code from the email.
5. **Expect**: Console shows `[lpVerifyOTP] post-verify, has_password: true`.
6. **Expect**: The "Set a password?" screen does NOT appear.
7. **Expect**: Dashboard loads directly.

### Scenario B
1. Same account.
2. Click "Use a password instead", enter credentials.
3. **Expect**: Dashboard loads directly — no prompt. (Unchanged behavior.)

### Scenario C
1. Use a brand-new email that has never signed in before (or an account where
   you manually cleared `user_metadata.has_password` in Supabase dashboard).
2. Sign in via OTP code.
3. **Expect**: Console shows `[lpVerifyOTP] post-verify, has_password: undefined`.
4. **Expect**: "You're signed in. Set a password to skip the code next time?" prompt appears.
5. Set a password → `has_password` is written to `true` → dashboard loads.

// ═══════════════ STATE ═══════════════
// Auto-migrate: if stored programs < built-in count, wipe cache and use fresh data
(function migrateProgramCache(){
  try {
    const stored = JSON.parse(localStorage.getItem('ldps_progs'));
    if(stored && stored.length < DP.length){
      localStorage.removeItem('ldps_progs');
    }
  } catch(e){ localStorage.removeItem('ldps_progs'); }
})();

// ─── Supabase Auth + Data Layer ──────────────────────────────────
const SUPA_URL = 'https://kqtarrgtxqpamlfrkgiv.supabase.co';
const SUPA_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtxdGFycmd0eHFwYW1sZnJrZ2l2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg1MDMxNzksImV4cCI6MjA5NDA3OTE3OX0.D6Foh3F2gS0d1lpWEHuc5incL-9LDW__17qRony9X2U';
// NOTE on key safety: The Supabase anon key is designed to be public.
// Real security is enforced by Row Level Security (RLS) policies on each
// table — see migrations.sql. Verify RLS is enabled before sharing widely.
const sb = supabase.createClient(SUPA_URL, SUPA_KEY);
let currentUser = null;
let userProfile = null;

// ─── .edu validation ─────────────────────────────────────────────
// Allow standard .edu TLDs plus school-specific domains used by major MBA programs.
// Phase 15: removed EDU_DOMAIN_PATTERNS (the .edu / .ac.uk regex fallback)
// and the schoolKeywords fuzzy fallback. Now ONLY the explicit whitelist
// below grants access. This prevents random .edu domains (e.g. madeup.edu)
// or keyword-matching domains from bypassing the gate just because they
// look school-ish. To add a new school: append it to EDU_DOMAIN_WHITELIST.
//
// User-facing impact: students at schools not in the whitelist see a clear
// error pointing them at hello@ldpscout.com to request their school be added.
const EDU_DOMAIN_WHITELIST = [
  'insead.edu',          // matched by .edu — listed for clarity
  'mbs.edu',             // Mannheim (mbs.de also valid)
  'mbs.de',
  'bocconi.it',          // SDA Bocconi
  'bocconi.education',
  'unibocconi.it',
  'bocconialumni.it',    // Bocconi alumni
  'studbocconi.it',      // Bocconi students
  'imd.org',             // IMD
  'iese.edu',
  'student.ie.edu',
  'ie.edu',
  'ceibs.edu',
  'whu.edu',
  'frankfurt-school.de',
  'novasbe.pt',
  'ucp.pt',              // Católica Lisbon
  'unisg.ch',            // St. Gallen
  'rsm.nl',
  'london.edu',          // LBS
  // ─── European MBA schools with non-.edu domains ───
  'edhec.com',           // EDHEC Business School
  'student.edhec.com',
  'emlyon.com',          // emlyon business school
  'em-lyon.com',
  'grenoble-em.com',     // Grenoble École de Management
  'skema.edu',           // SKEMA
  'audencia.com',        // Audencia
  'neoma-bs.fr',         // NEOMA Business School
  'kedgebs.com',         // KEDGE Business School
  'escp.eu',             // ESCP Business School
  'student.escp.eu',
  'vlerick.com',         // Vlerick Business School
  'tias.edu',            // TIAS (matched by .edu — listed for clarity)
  'alba.edu.gr',         // ALBA (matched by .edu — listed for clarity)
  'hhl.de',              // HHL Leipzig
  'ebs.edu',             // EBS Universität
  'wbs.ac.uk',           // Warwick (matched by .ac.uk — listed for clarity)
  'cranfield.ac.uk',     // Cranfield (matched by .ac.uk)
  'imperial.ac.uk',      // Imperial (matched by .ac.uk)
  'oxford.edu',          // Oxford (matched by .edu — listed for clarity)
  'sbs.ox.ac.uk',        // Oxford Saïd specific
  'cam.ac.uk',           // Cambridge (matched by .ac.uk)
  'jbs.cam.ac.uk',       // Cambridge Judge specific
  'hec.ca',              // HEC Montréal
  'ivey.ca',             // Ivey (Western)
  'rotman.utoronto.ca',  // Rotman
  'smith.queensu.ca',    // Smith (Queen's)
  'sauder.ubc.ca',       // Sauder (UBC)
  'schulich.yorku.ca',   // Schulich (York)
  'iima.ac.in',          // IIM Ahmedabad
  'iimb.ac.in',          // IIM Bangalore
  'iimc.ac.in',          // IIM Calcutta
  'isb.edu',             // ISB Hyderabad
  'sp.edu.sg',           // Singapore Polytechnic / SP Jain
  'nus.edu.sg',          // NUS
  'ntu.edu.sg',          // NTU / Nanyang
  'smu.edu.sg',          // SMU Singapore
  'mbs.edu.au',          // Melbourne Business School
  'agsm.edu.au',         // AGSM (UNSW)
  // ─── Previously matched by EDU_DOMAIN_PATTERNS (.edu, .ac.uk) ───
  // Phase 15: removed the pattern fallback to prevent random .edu domains
  // from passing the gate. These entries must now be listed explicitly.
  'esade.edu',           // ESADE Business School
  'alumni.esade.edu',    // ESADE alumni
  'hec.edu',             // HEC Paris
];

function isValidEduEmail(email){
  if(!email || !email.includes('@')) return false;
  const domain = email.split('@')[1].toLowerCase().trim();
  if(!domain) return false;
  // Phase 15: strict whitelist-only. No pattern fallback, no keyword fuzzy match.
  // If a legitimate user's school is missing, they should email hello@ldpscout.com
  // and we'll add it within 24 hours.
  return EDU_DOMAIN_WHITELIST.includes(domain);
}

async function initAuth() {
  // ─── Handle magic-link callback from URL hash ─────────────────
  // When user clicks the magic link, Supabase redirects back with tokens in the URL hash:
  //   #access_token=...&refresh_token=...&type=magiclink
  // OR with an error:
  //   #error=access_denied&error_code=otp_expired&error_description=...
  // We must handle both BEFORE calling getSession().

  const hash = window.location.hash;

  // Check for auth error in URL (expired link, already-used link)
  if(hash.includes('error=')){
    const params = new URLSearchParams(hash.substring(1));
    const errCode = params.get('error_code') || '';
    const errDesc = params.get('error_description') || '';
    // Clean the URL so refreshing doesn't re-show the error
    history.replaceState(null, '', window.location.pathname);
    // Show a user-friendly message on the landing page
    setTimeout(()=>{
      const msg = document.getElementById('lp-signup-msg');
      if(msg){
        if(errCode === 'otp_expired'){
          msg.innerHTML = '⚠️ That link has expired or was already used. Please request a new one below. <span style="font-size:11px;color:var(--text3);display:block;margin-top:4px">School email systems sometimes pre-scan links, which can invalidate them. Try clicking the link as soon as it arrives.</span>';
        } else {
          msg.innerHTML = '⚠️ Sign-in failed: ' + (errDesc || 'unknown error') + '. Please try again.';
        }
        msg.classList.add('err');
        msg.style.display = 'block';
      }
    }, 200);
  }

  // Check for successful auth tokens in URL hash
  if(hash.includes('access_token=')){
    // Let Supabase client parse the hash and establish the session
    // This is handled automatically by supabase.createClient() detecting the hash,
    // but we need to wait for the auth state change event rather than calling getSession() immediately.
    // Clean the URL
    history.replaceState(null, '', window.location.pathname);
  }

  // Now get session (will work if user was already signed in from a prior visit,
  // or if the hash tokens were just parsed above)
  try {
    const { data: { session } } = await sb.auth.getSession();
    currentUser = session?.user ?? null;
  } catch(e){
    console.warn('Supabase getSession failed:', e);
    currentUser = null;
  }

  // Listen for auth state changes (handles the async token exchange from magic link)
  sb.auth.onAuthStateChange(async (event, session) => {
    const wasSignedIn = !!currentUser;
    currentUser = session?.user ?? null;
    updateAuthUI();
    if(currentUser && !wasSignedIn){
      // Just signed in — hide landing, load data, show app
      // Clean URL hash if it still has tokens
      if(window.location.hash.includes('access_token')){
        history.replaceState(null, '', window.location.pathname);
      }
      // Phase 14 (revised): if this was an OTP signin and the user hasn't
      // dismissed the password prompt before, hold them on the landing page
      // to offer setting a password. The user is already authenticated;
      // updateUser({password}) works without an email round-trip.
      if(window._ldp_lastSigninWasOtp){
        window._ldp_lastSigninWasOtp = false;
        const dismissed = localStorage.getItem('ldp_pw_prompt_dismissed_v1') === 'true';
        if(!dismissed){
          lpShowSetPasswordStep('after_otp');
          return;
        }
      }
      await onSignIn();
    } else if(!currentUser && wasSignedIn){
      // Just signed out — show landing
      onSignOut();
    }
  });

  updateAuthUI();
  // On initial load: if already signed in, hide landing + load data
  if(currentUser){
    await onSignIn();
  } else {
    showLanding();
  }
}

function showLanding(){
  document.getElementById('landing-overlay').classList.add('open');
}
function hideLanding(){
  document.getElementById('landing-overlay').classList.remove('open');
}

// ═══════════════════════════════════════════════════════════════════
// PHASE 12: SUPABASE PROGRAMS FETCH
// ═══════════════════════════════════════════════════════════════════
// Fetches the 48 programs from the Supabase `programs` table on each
// sign-in, replacing the localStorage-cached or hardcoded DP[] array.
//
// Mapping (DB column → DP[] field):
//   company       → org
//   program_name  → name
//   industry      → sector
//   function      → fn
//   location      → loc
//   geo, status, deadline, dlnote, visa, url, tags, notes → same name
//
// Fallback order:
//   1. Supabase fresh (if user is online and DB is reachable)
//   2. localStorage cache (set by persist() on previous successful fetch)
//   3. Hardcoded DP[] array (last resort, always present in HTML)
//
// Reserved word note: `function` is a JS keyword, so DB field access
// uses bracket notation: row['function'].
// ═══════════════════════════════════════════════════════════════════
async function fetchProgramsFromSupabase() {
  try {
    if (!sb) {
      console.warn('[LDP Scout] Supabase client (sb) not available');
      return false;
    }

    const { data, error } = await sb
      .from('programs')
      .select('id, company, program_name, industry, function, location, geo, status, deadline, dlnote, visa, url, tags, notes')
      .order('id', { ascending: true });

    if (error) {
      console.error('[LDP Scout] Supabase programs fetch error:', error.message);
      return false;
    }

    if (!data || data.length === 0) {
      console.warn('[LDP Scout] No programs returned from Supabase');
      return false;
    }

    // Map DB columns → DP[] field names
    progs = data.map(row => ({
      id:       row.id,
      name:     row.program_name || '',
      org:      row.company || '',
      geo:      row.geo || '',
      loc:      row.location || '',
      fn:       row['function'] || '',  // bracket: 'function' is a JS reserved word
      sector:   row.industry || '',
      status:   row.status || '',
      deadline: row.deadline || '',     // null from DB → '' for code that does `if(p.deadline)`
      dlnote:   row.dlnote || '',
      visa:     row.visa === true,
      tags:     Array.isArray(row.tags) ? row.tags : [],
      notes:    row.notes || '',
      url:      row.url || '',
    }));

    // Refresh the localStorage cache so future page-loads have a fresh fallback
    try { localStorage.setItem('ldps_progs', JSON.stringify(progs)); } catch(e) {}

    progsLoadedFromDb = true;
    console.log(`[LDP Scout] ✓ Loaded ${progs.length} programs from Supabase`);
    return true;

  } catch (e) {
    console.error('[LDP Scout] Exception in fetchProgramsFromSupabase:', e);
    return false;
  }
}

async function onSignIn(){
  hideLanding();
  // Load profile, applications, resume — all from Supabase
  await loadUserProfile();
  await loadUserApplications();
  await loadUserResume();
  // Phase 12: refresh programs from Supabase (falls back to localStorage/DP[] if it fails)
  await fetchProgramsFromSupabase();
  renderPrograms();
  renderApplications();
  // Phase 2: trigger first-run onboarding if neither timestamp is set
  if(onbShouldShow()) onbOpen();
  // Phase 3: apply per-page info-card dismissal state from userProfile
  initInfoCards();
  // Phase 7: render onboarding progress strip + AI Fit attention dot
  renderProgressStrip();
  updateFitTabIndicator();
}

function onSignOut(){
  apps = [];
  userProfile = null;
  resumeText = '';
  resumeLastScanAt = null;   // Phase 7
  showLanding();
  // Clear UI (null-guard — these elements may not exist before sign-in)
  const kb = document.getElementById('app-kanban');
  if(kb) kb.innerHTML='';
  const aiResults = document.getElementById('aifit-results-container');
  if(aiResults) aiResults.innerHTML='';
  // Phase 13: also reset the AI Fit Scan view back to pre-scan state
  const preView = document.getElementById('aifit-view-pre');
  const postView = document.getElementById('aifit-view-post');
  if(preView) preView.style.display = 'block';
  if(postView) postView.style.display = 'none';
  // Reset the upload box too so a returning visitor starts fresh
  const fileDisplay = document.getElementById('aifit-file-display');
  const emptyDisplay = document.getElementById('aifit-empty-display');
  const uploadBox = document.getElementById('aifit-upload-box');
  const fileInput = document.getElementById('resume-file-input');
  const analyzeBtn = document.getElementById('analyze-btn');
  if(fileDisplay) fileDisplay.style.display = 'none';
  if(emptyDisplay) emptyDisplay.style.display = 'block';
  if(uploadBox) uploadBox.classList.remove('has-file');
  if(fileInput) fileInput.value = '';
  if(analyzeBtn){ analyzeBtn.disabled = true; analyzeBtn.textContent = '✦ Analyse My Fit'; }
  // Phase 7: hide progress strip + clear AI Fit attention dot on sign-out
  const ps = document.getElementById('progress-strip');
  if(ps) ps.style.display = 'none';
  document.querySelectorAll('.nav-tab.needs-attention').forEach(t => t.classList.remove('needs-attention'));
  // Clear landing-page auth state so the previous user's OTP isn't sitting there
  const otpInput = document.getElementById('lp-otp-input');
  const emailInput = document.getElementById('lp-email');
  const otpStep = document.getElementById('lp-step-otp');
  const emailStep = document.getElementById('lp-step-email');
  const signupMsg = document.getElementById('lp-signup-msg');
  const verifyBtn = document.getElementById('lp-verify-btn');
  const signupBtn = document.getElementById('lp-signup-btn');
  if(otpInput) otpInput.value = '';
  if(emailInput) emailInput.value = '';
  if(otpStep) otpStep.style.display = 'none';
  if(emailStep) emailStep.style.display = 'block';
  if(signupMsg){ signupMsg.style.display = 'none'; signupMsg.textContent = ''; }
  if(verifyBtn){ verifyBtn.disabled = false; verifyBtn.textContent = 'Verify →'; }
  if(signupBtn){ signupBtn.disabled = false; signupBtn.textContent = 'Send Code →'; }
  // Phase 14: also reset the password + set-password steps
  const pwStep = document.getElementById('lp-step-password');
  const setPwStep = document.getElementById('lp-step-set-password');
  const pwInput = document.getElementById('lp-pw-input');
  const newPwInput = document.getElementById('lp-new-pw-input');
  const pwSigninBtn = document.getElementById('lp-pw-signin-btn');
  const setPwBtn = document.getElementById('lp-set-pw-btn');
  if(pwStep) pwStep.style.display = 'none';
  if(setPwStep) setPwStep.style.display = 'none';
  if(pwInput) pwInput.value = '';
  if(newPwInput) newPwInput.value = '';
  if(pwSigninBtn){ pwSigninBtn.disabled = false; pwSigninBtn.textContent = 'Sign In →'; }
  if(setPwBtn){ setPwBtn.disabled = false; setPwBtn.textContent = 'Save Password →'; }
}

function updateAuthUI() {
  const btn = document.getElementById('auth-btn');
  const userInfo = document.getElementById('user-info');
  const setPwBtn = document.getElementById('acct-set-pw-btn');
  if (currentUser) {
    if (btn) btn.textContent = 'Sign Out';
    if (userInfo) userInfo.textContent = currentUser.email;
    if (setPwBtn) {
      // Phase 15: flip "Set password" → "Change password" based on user_metadata flag.
      // The flag is written by lpSetPassword and saveAccountPassword after a successful
      // updateUser({password}). Stored in Supabase's auth.users.user_metadata JSON column,
      // so it syncs across devices and survives sign-outs.
      const hasPw = !!(currentUser.user_metadata && currentUser.user_metadata.has_password);
      setPwBtn.textContent = hasPw ? 'Change password' : 'Set password';
      setPwBtn.title = hasPw
        ? 'Change your password'
        : 'Set a password so you can sign in without a code next time';
      setPwBtn.style.display = 'inline-block';
    }
  } else {
    if (btn) btn.textContent = 'Sign In';
    if (userInfo) userInfo.textContent = '';
    if (setPwBtn) setPwBtn.style.display = 'none';
  }
}

async function handleAuth() {
  if (currentUser) {
    await sb.auth.signOut();
  } else {
    showLanding();
    setTimeout(()=>{ const el=document.getElementById('lp-email'); if(el) el.focus(); },150);
  }
}

// ─── Landing page sign-up — OTP code flow ────────────────────────
// Step 1: User enters .edu email → we send an 8-digit OTP code via email.
// Step 2: User enters the code → we verify it → signed in.
// No magic link = no Safe Links consuming the token.

let _otpEmail = ''; // stash the email between steps

async function lpSendOTP(){
  const emailInput = document.getElementById('lp-email');
  const btn = document.getElementById('lp-signup-btn');
  const msg = document.getElementById('lp-signup-msg');
  const email = (emailInput.value||'').trim();

  msg.style.display = 'none';
  msg.classList.remove('ok','err');

  if(!email){
    msg.textContent = 'Please enter your school email.';
    msg.classList.add('err');
    msg.style.display = 'block';
    return;
  }
  if(!isValidEduEmail(email)){
    msg.innerHTML = '⚠️ Please use your school email. LDP Scout is currently invite-only for MBA students.<br><span style="font-size:11px;color:var(--text3)">Accepted examples: you@esade.edu · you@hec.edu · you@london.edu. School not in our list? Email <a href="mailto:hello@ldpscout.com" style="color:var(--blue)">hello@ldpscout.com</a> and we\'ll add it within 24 hours.</span>';
    msg.classList.add('err');
    msg.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Sending...';

  try {
    // Send OTP (8-digit code) via email — no redirect URL needed
    const { error } = await sb.auth.signInWithOtp({
      email,
      options: {
        shouldCreateUser: true  // auto-create user if first time
      }
    });
    if(error){
      msg.textContent = error.message || 'Could not send code. Please try again.';
      msg.classList.add('err');
      msg.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Send Code →';
      return;
    }

    // Success — show OTP input step
    _otpEmail = email;
    document.getElementById('lp-otp-email-display').textContent = email;
    document.getElementById('lp-step-email').style.display = 'none';
    document.getElementById('lp-step-otp').style.display = 'block';
    msg.innerHTML = '✓ <strong>Code sent!</strong> Check your inbox for an 8-digit code from <strong>LDP Scout</strong> (noreply@ldpscout.com). School emails can take 1-3 minutes.';
    msg.classList.add('ok');
    msg.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Send Code →';
    // Focus the OTP input
    setTimeout(()=>{ document.getElementById('lp-otp-input').focus(); }, 200);

  } catch(err){
    msg.textContent = err.message || 'Unexpected error. Please try again.';
    msg.classList.add('err');
    msg.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Send Code →';
  }
}

async function lpVerifyOTP(){
  const code = (document.getElementById('lp-otp-input').value||'').trim().replace(/\s/g,'');
  const btn = document.getElementById('lp-verify-btn');
  const msg = document.getElementById('lp-signup-msg');

  msg.style.display = 'none';
  msg.classList.remove('ok','err');

  if(!code || code.length < 6){
    msg.textContent = 'Please enter the full code from your email.';
    msg.classList.add('err');
    msg.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Verifying...';

  // CRITICAL: set the flag BEFORE calling verifyOtp. Supabase's
  // onAuthStateChange listener fires synchronously when the session
  // is established, which can happen DURING the await below. If we
  // set this flag after the await, the listener has already run with
  // the flag still undefined and dropped the user into the dashboard
  // without showing the post-OTP password prompt.
  window._ldp_lastSigninWasOtp = true;

  try {
    const { data, error } = await sb.auth.verifyOtp({
      email: _otpEmail,
      token: code,
      type: 'email'
    });

    if(error){
      // Failed verify — reset the flag so any future password attempt
      // doesn't accidentally trigger the OTP-only prompt path.
      window._ldp_lastSigninWasOtp = false;
      let errMsg = error.message || 'Invalid code.';
      if(errMsg.toLowerCase().includes('expired')){
        errMsg = 'That code has expired. Click "Resend code" to get a new one.';
      } else if(errMsg.toLowerCase().includes('invalid')){
        errMsg = 'Invalid code — please double-check and try again.';
      }
      msg.textContent = errMsg;
      msg.classList.add('err');
      msg.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Verify →';
      return;
    }

    // Success — user is now signed in. The auth listener has already
    // fired and (because the flag was set before this call) either
    // showed the set-password prompt OR loaded the dashboard.
    msg.innerHTML = '✓ <strong>Signed in!</strong>';
    msg.classList.add('ok');
    msg.style.display = 'block';

  } catch(err){
    window._ldp_lastSigninWasOtp = false;
    msg.textContent = err.message || 'Verification failed. Please try again.';
    msg.classList.add('err');
    msg.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Verify →';
  }
}

async function lpResendOTP(){
  const msg = document.getElementById('lp-signup-msg');
  const resendBtn = document.getElementById('lp-resend-btn');
  msg.style.display = 'none';
  msg.classList.remove('ok','err');

  if(!_otpEmail) return;

  resendBtn.textContent = 'Sending...';
  resendBtn.disabled = true;

  try {
    const { error } = await sb.auth.signInWithOtp({
      email: _otpEmail,
      options: { shouldCreateUser: true }
    });
    if(error){
      msg.textContent = error.message;
      msg.classList.add('err');
    } else {
      msg.innerHTML = '✓ New code sent to <strong>'+_otpEmail+'</strong>. Check your inbox.';
      msg.classList.add('ok');
      document.getElementById('lp-otp-input').value = '';
      document.getElementById('lp-otp-input').focus();
    }
    msg.style.display = 'block';
  } catch(e){
    msg.textContent = 'Could not resend. Wait a moment and try again.';
    msg.classList.add('err');
    msg.style.display = 'block';
  }
  resendBtn.textContent = 'Resend code';
  resendBtn.disabled = false;
}

// ─── PASSWORD AUTH (Phase 14) ────────────────────────────────────
// Reuses Supabase Auth's native email+password — no schema changes,
// same auth.users table as the OTP flow.

function lpShowPasswordStep(){
  const emailInput = document.getElementById('lp-email');
  const email = (emailInput.value || '').trim().toLowerCase();
  const msg = document.getElementById('lp-signup-msg');
  msg.style.display = 'none';
  msg.classList.remove('ok','err');

  // Require a valid-looking email first — same validator the OTP path uses
  if(!email || !isValidEduEmail(email)){
    msg.innerHTML = '⚠️ Please enter your school email first (e.g. you@esade.edu). School not in our list? Email <a href="mailto:hello@ldpscout.com" style="color:var(--blue)">hello@ldpscout.com</a>.';
    msg.classList.add('err');
    msg.style.display = 'block';
    emailInput.focus();
    return;
  }

  document.getElementById('lp-pw-email-display').textContent = email;
  document.getElementById('lp-step-email').style.display = 'none';
  document.getElementById('lp-step-otp').style.display = 'none';
  document.getElementById('lp-step-set-password').style.display = 'none';
  document.getElementById('lp-step-password').style.display = 'block';
  setTimeout(()=>{ const el=document.getElementById('lp-pw-input'); if(el) el.focus(); }, 100);
}

async function lpSignInWithPassword(){
  const email = (document.getElementById('lp-email').value || '').trim().toLowerCase();
  const password = document.getElementById('lp-pw-input').value || '';
  const btn = document.getElementById('lp-pw-signin-btn');
  const msg = document.getElementById('lp-signup-msg');
  msg.style.display = 'none';
  msg.classList.remove('ok','err');

  if(!password || password.length < 8){
    msg.textContent = 'Password must be at least 8 characters.';
    msg.classList.add('err');
    msg.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in...';

  try {
    // Try signing in first (returning user with existing password)
    const signIn = await sb.auth.signInWithPassword({ email, password });
    if(!signIn.error){
      // Returning user — success. Auth listener handles the rest.
      msg.innerHTML = '✓ <strong>Signed in!</strong> Loading your dashboard...';
      msg.classList.add('ok');
      msg.style.display = 'block';
      return;
    }

    // Sign-in failed. Most likely either (a) new user — no account yet, or
    // (b) wrong password. Try sign-up: if it creates the account, they're new.
    // If sign-up complains "user already exists", they had an account but the
    // password they typed was wrong.
    btn.textContent = 'Creating account...';
    const signUp = await sb.auth.signUp({ email, password });
    if(signUp.error){
      const errText = (signUp.error.message || '').toLowerCase();
      if(errText.includes('already') || errText.includes('registered') || errText.includes('exists')){
        // Account exists. Two sub-cases (Supabase doesn't tell us which):
        //   (a) Password is genuinely wrong
        //   (b) User has only ever signed in via OTP — no password set yet
        // (b) is by far the more common case for our user base. Auto-route
        // them to OTP so they can sign in and set a password. Clear the
        // dismissed flag so the post-OTP set-password prompt fires.
        localStorage.removeItem('ldp_pw_prompt_dismissed_v1');
        msg.innerHTML = 'This email is already registered, but we couldn\'t sign you in with that password. <strong>Sending you a code instead</strong> — you\'ll be able to set a new password once you\'re in.';
        msg.classList.add('ok');
        msg.style.display = 'block';
        // Switch to the OTP step and fire lpSendOTP automatically
        document.getElementById('lp-step-password').style.display = 'none';
        document.getElementById('lp-step-email').style.display = 'block';
        // Trigger OTP send after a short delay so the user reads the message
        setTimeout(()=>{ lpSendOTP(); }, 700);
        btn.disabled = false;
        btn.textContent = 'Sign In →';
        return;
      } else {
        msg.textContent = signUp.error.message || 'Could not create account.';
      }
      msg.classList.add('err');
      msg.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Sign In →';
      return;
    }

    // signUp succeeded. With "Confirm email" OFF in Supabase, the user has
    // a session immediately. The auth listener picks up SIGNED_IN and
    // routes them into the dashboard. With "Confirm email" ON, signUp
    // succeeds but returns no session — surface that case explicitly.
    if(!signUp.data?.session){
      msg.innerHTML = '⚠️ Almost there — Supabase is set to require email confirmation. Either confirm via the email we just sent, or ask Pranav to turn off "Confirm email" in Supabase.';
      msg.classList.add('err');
      msg.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Sign In →';
      return;
    }
    msg.innerHTML = '✓ <strong>Account created.</strong> Loading your dashboard...';
    msg.classList.add('ok');
    msg.style.display = 'block';
  } catch(err){
    msg.textContent = err.message || 'Unexpected error. Please try again.';
    msg.classList.add('err');
    msg.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Sign In →';
  }
}

// Phase 14 (revised): forgot-password no longer sends an email.
// School mail servers pre-scan links and burn the reset token, plus the
// default Supabase email template is ugly and slow. Instead, route the
// user to the OTP flow — once signed in via code, they can set a new
// password via the post-OTP prompt (which appears on next sign-in since
// the dismissed flag is per-browser).
function lpForgotPassword(){
  const msg = document.getElementById('lp-signup-msg');
  msg.style.display = 'none';
  msg.classList.remove('ok','err');

  // Clear the dismissed flag so the post-OTP set-password step shows again
  localStorage.removeItem('ldp_pw_prompt_dismissed_v1');

  // Hide the password step, show the email step so the user can request a code
  document.getElementById('lp-step-password').style.display = 'none';
  document.getElementById('lp-step-email').style.display = 'block';
  // Don't wipe the email — keep it so the user just clicks Continue
  msg.innerHTML = '<strong>Sign in with a code</strong> — we\'ll let you set a new password once you\'re in.';
  msg.classList.add('ok');
  msg.style.display = 'block';
  const emailInput = document.getElementById('lp-email');
  if(emailInput) emailInput.focus();
}

// Called after a successful OTP verify, to offer setting a password
// so the user doesn't need a fresh code next time.
function lpShowSetPasswordStep(mode){
  // mode currently always 'after_otp' — the 'reset' branch was removed when
  // we dropped the email-based password reset flow (school mail scanners
  // were burning the reset tokens before users could click them).
  const headline = document.getElementById('lp-set-pw-headline');
  const skipBtn = document.getElementById('lp-skip-pw-btn');
  headline.innerHTML = '<strong>You\'re signed in.</strong> Set a password to skip the code next time? <span style="color:var(--text3);font-weight:400">— optional, you can always sign in with a code instead.</span>';
  skipBtn.style.display = '';
  document.getElementById('lp-step-email').style.display = 'none';
  document.getElementById('lp-step-otp').style.display = 'none';
  document.getElementById('lp-step-password').style.display = 'none';
  document.getElementById('lp-step-set-password').style.display = 'block';
  setTimeout(()=>{ const el=document.getElementById('lp-new-pw-input'); if(el) el.focus(); }, 100);
}

async function lpSetPassword(){
  const newPw = document.getElementById('lp-new-pw-input').value || '';
  const btn = document.getElementById('lp-set-pw-btn');
  const msg = document.getElementById('lp-signup-msg');
  msg.style.display = 'none';
  msg.classList.remove('ok','err');

  if(newPw.length < 8){
    msg.textContent = 'Password must be at least 8 characters.';
    msg.classList.add('err');
    msg.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    // User is already authenticated (we got here right after OTP success),
    // so updateUser({password}) just attaches a password to their existing
    // Supabase Auth row. No email round-trip needed.
    // Phase 15: also write user_metadata.has_password=true so the topbar
    // button flips to "Change password" everywhere this user signs in.
    const { data: updateData, error } = await sb.auth.updateUser({
      password: newPw,
      data: { has_password: true }
    });
    if(error){
      msg.textContent = error.message || 'Could not save password.';
      msg.classList.add('err');
      msg.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Save Password →';
      return;
    }
    // Phase 15: refresh currentUser locally so updateAuthUI flips the button label
    // when the dashboard renders next (without waiting for next sign-in).
    if(updateData?.user) currentUser = updateData.user;
    // Save the dismissed flag so this prompt doesn't show again on this browser
    localStorage.setItem('ldp_pw_prompt_dismissed_v1', 'true');
    msg.innerHTML = '✓ <strong>Password saved.</strong> Loading your dashboard...';
    msg.classList.add('ok');
    msg.style.display = 'block';
    document.getElementById('lp-new-pw-input').value = '';
    // Hand off to onSignIn to actually load the dashboard
    setTimeout(async ()=>{
      document.getElementById('lp-step-set-password').style.display = 'none';
      await onSignIn();
    }, 600);
  } catch(err){
    msg.textContent = err.message || 'Unexpected error.';
    msg.classList.add('err');
    msg.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Save Password →';
  }
}

async function lpSkipPassword(){
  // User declined to set a password — remember the choice so we don't ask again
  // on this browser, then continue to the dashboard.
  localStorage.setItem('ldp_pw_prompt_dismissed_v1', 'true');
  document.getElementById('lp-step-set-password').style.display = 'none';
  await onSignIn();
}

function lpBackToEmail(){
  _otpEmail = '';
  document.getElementById('lp-step-email').style.display = 'block';
  document.getElementById('lp-step-otp').style.display = 'none';
  document.getElementById('lp-step-password').style.display = 'none';
  document.getElementById('lp-step-set-password').style.display = 'none';
  document.getElementById('lp-signup-msg').style.display = 'none';
  document.getElementById('lp-otp-input').value = '';
  const pw = document.getElementById('lp-pw-input'); if(pw) pw.value = '';
  document.getElementById('lp-email').focus();
}

function showAuthModal() {
  // Used by topbar Sign In button — just show the landing page
  showLanding();
  setTimeout(()=>{ const el=document.getElementById('lp-email'); if(el) el.focus(); },150);
}

// ════════════════════════════════════════════════════════════════
// SUPABASE DATA LAYER — profiles, applications, resumes
// ════════════════════════════════════════════════════════════════

async function loadUserProfile(){
  if(!currentUser) return;
  try {
    const { data, error } = await sb.from('user_profiles').select('*').eq('user_id', currentUser.id).maybeSingle();
    if(error) throw error;
    if(data){
      userProfile = {
        full_name:   data.full_name,
        school_key:  data.school_key,
        school_label:data.school_label,
        mba_year:    data.mba_year,
        target_geos: data.target_geos || [],
        target_fns:  data.target_fns || [],
        goals_note:  data.goals_note,
        // For backward-compat with old code referencing userProfile.schools
        schools:     data.school_key ? [data.school_key] : [],
        // Phase 1 additions
        onboarding_completed_at: data.onboarding_completed_at || null,
        onboarding_skipped_at:   data.onboarding_skipped_at   || null,
        tours_completed:         data.tours_completed         || [],
        hints_dismissed:         data.hints_dismissed         || [],
        digest_opt_in:           !!data.digest_opt_in
      };
      activeAlumniSchool = data.school_key || activeAlumniSchool;
    } else {
      // First-time user — create a stub profile row
      const stub = { user_id: currentUser.id, email: currentUser.email };
      await sb.from('user_profiles').upsert(stub, {onConflict:'user_id'});
      userProfile = {
        schools: [],
        onboarding_completed_at: null,
        onboarding_skipped_at:   null,
        tours_completed:         [],
        hints_dismissed:         [],
        digest_opt_in:           false
      };
    }
  } catch(e){
    console.warn('loadUserProfile failed:', e);
    userProfile = {
      schools: [],
      onboarding_completed_at: null,
      onboarding_skipped_at:   null,
      tours_completed:         [],
      hints_dismissed:         [],
      digest_opt_in:           false
    };
  }
}

async function saveUserProfile(updates){
  if(!currentUser) return;
  try {
    // Check if a row exists for this user
    const { data: existing, error: fetchErr } = await sb
      .from('user_profiles')
      .select('user_id')
      .eq('user_id', currentUser.id)
      .maybeSingle();
    if(fetchErr) throw fetchErr;

    if(existing){
      // Row exists — update only the supplied columns
      const { error } = await sb
        .from('user_profiles')
        .update(updates)
        .eq('user_id', currentUser.id);
      if(error) throw error;
    } else {
      // First write — insert with stub fields plus the supplied updates
      const payload = { user_id: currentUser.id, email: currentUser.email, ...updates };
      const { error } = await sb.from('user_profiles').insert(payload);
      if(error) throw error;
    }
    // Refresh the in-memory copy
    await loadUserProfile();
    // Phase 7: profile state may have changed — re-render onboarding progress
    renderProgressStrip();
  } catch(e){
    console.error('saveUserProfile failed:', e);
    toast('Could not save profile — check connection.');
  }
}

async function markTourCompleted(tourKey){
  if(!currentUser || !userProfile) return;
  const current = userProfile.tours_completed || [];
  if(current.includes(tourKey)) return;  // idempotent
  await saveUserProfile({ tours_completed: [...current, tourKey] });
  // Phase 7: completing the alumni tour ticks the "first search" step (saveUserProfile already
  // re-rendered the strip transitively, but call again to be defensive against future refactors)
  renderProgressStrip();
}

async function markHintDismissed(hintKey){
  if(!currentUser || !userProfile) return;
  const current = userProfile.hints_dismissed || [];
  if(current.includes(hintKey)) return;  // idempotent
  await saveUserProfile({ hints_dismissed: [...current, hintKey] });
}

// ─── PHASE 3: INFO CARDS ───
// Each .info-card has a data-hint-key. Dismissal state is persisted in
// userProfile.hints_dismissed (Supabase). A matching .info-card-reopen[data-hint-key]
// span in the page header toggles back the card.

function _setInfoCardState(key, dismissed){
  document.querySelectorAll(`.info-card[data-hint-key="${key}"]`).forEach(el=>{
    el.setAttribute('data-dismissed', dismissed ? 'true' : 'false');
  });
  document.querySelectorAll(`.info-card-reopen[data-hint-key="${key}"]`).forEach(el=>{
    el.classList.toggle('show', dismissed);
  });
}

function initInfoCards(){
  const dismissedKeys = (userProfile && userProfile.hints_dismissed) || [];
  document.querySelectorAll('.info-card[data-hint-key]').forEach(card=>{
    const key = card.getAttribute('data-hint-key');
    _setInfoCardState(key, dismissedKeys.includes(key));
  });
}

async function dismissInfoCard(key){
  _setInfoCardState(key, true);
  await markHintDismissed(key);
}

async function reopenInfoCard(key){
  _setInfoCardState(key, false);
  if(!currentUser || !userProfile) return;
  await saveUserProfile({ hints_dismissed: (userProfile.hints_dismissed || []).filter(x => x !== key) });
}

// ─── PHASE 7: SMART BANNER, PROGRESS STRIP, AI FIT TAB INDICATOR ───
// Three coordinated UI affordances that react to user state changes:
//   renderFitBanner()        — three-state banner on Programs (no resume / stale / fresh)
//   renderProgressStrip()    — 4-step onboarding strip under topbar, hidden when complete
//   updateFitTabIndicator()  — coral pulsing dot on AI Fit nav tab when no resume on file

const FIT_BANNER_STALE_DAYS = 30;

function _daysSince(iso){
  if(!iso) return null;
  const t = new Date(iso).getTime();
  if(isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86400000);
}

function renderFitBanner(){
  const mount = document.getElementById('fit-banner-mount');
  if(!mount) return;

  // State 1: no resume — original CTA
  if(!resumeText){
    mount.innerHTML = `<div class="fit-prompt-banner" onclick="showPage('aifit')" title="Go to AI Fit Scan">
      <div class="fpb-icon">✦</div>
      <div class="fpb-text"><strong>Fit column powered by AI.</strong> Upload your résumé on the AI Fit Scan tab to get personalised tier rankings, gap analysis, and coaching across all programs — results sync back here automatically.</div>
      <div class="fpb-cta">Scan My Résumé →</div>
    </div>`;
    return;
  }

  const days = _daysSince(resumeLastScanAt);

  // Edge case: resume exists but never scanned (last_scan_at null) — prompt to run first scan
  if(days === null){
    mount.innerHTML = `<div class="fit-prompt-banner stale" onclick="showPage('aifit')" title="Run your first AI fit scan">
      <div class="fpb-icon">✦</div>
      <div class="fpb-text"><strong>Your résumé is on file — but you haven't scanned it yet.</strong> Run an AI fit scan to populate tier rankings across all 48 programs.</div>
      <div class="fpb-cta">Run Scan →</div>
    </div>`;
    return;
  }

  // State 2: scan is stale (>30 days)
  if(days > FIT_BANNER_STALE_DAYS){
    mount.innerHTML = `<div class="fit-prompt-banner stale" onclick="showPage('aifit')" title="Re-run AI fit scan">
      <div class="fpb-icon">✦</div>
      <div class="fpb-text"><strong>Your scan is ${days} days old.</strong> Re-run to refresh fit scores — programs change, and so does your résumé.</div>
      <div class="fpb-cta">Re-scan →</div>
    </div>`;
    return;
  }

  // State 3: scan is fresh — hide entirely
  mount.innerHTML = '';
}

function renderProgressStrip(){
  const strip = document.getElementById('progress-strip');
  if(!strip) return;

  // Not signed in? Hide.
  if(!currentUser){ strip.style.display = 'none'; return; }

  const profileDone     = !!(userProfile && userProfile.full_name && userProfile.school_key);
  const resumeDone      = !!resumeText;
  const searchDone      = !!(userProfile && (userProfile.tours_completed || []).includes('alumni'));
  const applicationDone = Array.isArray(apps) && apps.length > 0;

  // All four done? Hide the strip entirely — user has graduated past onboarding.
  if(profileDone && resumeDone && searchDone && applicationDone){
    strip.style.display = 'none';
    return;
  }

  const stateMap = { profile:profileDone, resume:resumeDone, search:searchDone, application:applicationDone };
  strip.querySelectorAll('.ps-step').forEach(el => {
    const k = el.getAttribute('data-step');
    el.classList.toggle('on', !!stateMap[k]);
  });
  strip.style.display = 'flex';
}

function updateFitTabIndicator(){
  // Coral pulsing dot on AI Fit tab when no resume on file.
  // Selector matches the inline onclick="showPage('aifit')" tab.
  document.querySelectorAll('.nav-tab').forEach(tab => {
    const onclickAttr = tab.getAttribute('onclick') || '';
    if(onclickAttr.includes("showPage('aifit')")){
      tab.classList.toggle('needs-attention', !resumeText && !!currentUser);
    }
  });
}

// ─── PHASE 4: GUIDED PRODUCT TOURS ───
// Vanilla coachmark engine. First visit to each tab (after onboarding) auto-runs the
// tour for that tab. Completion is synced via userProfile.tours_completed (Supabase).
// "Tour this page" links inside info cards re-run on demand.

const TOURS = {
  programs: [
    {target:'#prog-stats',         title:'Pipeline at a glance',  body:'Snapshot of all 48 LDPs by status — open, rolling, watch-list, and closed. Updates as you filter below.'},
    {target:'.filter-row',         title:'Filter and search',     body:'Cut the list by geography, function, status, or type. The search box matches program names, firms, and keywords.'},
    {target:'.thead',              title:'Sortable columns',      body:'Click any column header to sort. The Fit column is powered by the AI Fit Scanner once you upload a résumé.'},
    {target:'.prow:first-child',   title:'Open program details',  body:'Click any row to open full details — deadline, location, fit reasoning. The program name links straight to the official careers page.'}
  ],
  aifit: [
    {target:'#aifit-upload-box',  title:'Upload your résumé', body:'Drop in a PDF, DOCX, or plain-text file (max 5MB). Processed via a secure proxy — never stored, never shared.'},
    {target:'#analyze-btn',  title:'Run the analysis',   body:'Two-step scan: tier classification first, then a gap analysis across 6 dimensions per program.'},
    {target:'#aifit-results-container',   title:'Tier-ranked results',body:'Results land here and sync back into the Fit column on the Programs tab. Re-run anytime with an updated résumé.'}
  ],
  alumni: [
    {target:'#alumni-school-wrap',                 title:'Pick your school', body:'We use this to scope LinkedIn searches to your own alumni network — that\u2019s the warm-intro lever.'},
    {target:'#al-sector-list',                     title:'Filter by industry vertical', body:'Tick one or more sectors to narrow the feed to programs that match your background.'},
    {target:'#alumni-search-rows .al-card:first-child', title:'Two ways to act on each program', body:'Click "Draft Message" for 3 ready-to-paste 300-character LinkedIn connection templates. Click "+ Add to Networking" to log the program in your pipeline at the Networking stage — deadline and org auto-filled.'}
  ],
  applications: [
    {target:'.add-btn',     title:'Log a new application', body:'Click here to add an application. Fill in the program name, stage (defaults to Shortlisted), deadline, and notes.'},
    {target:'#app-kanban',  title:'Move cards through the funnel', body:'Seven stages: Shortlisted \u2192 Networking \u2192 Drafting \u2192 Applied \u2192 Interview \u2192 Offer (or Rejected). Drag a card between columns to update its stage, or click a card to edit dates and notes.'}
  ],
  deadlines: [
    {target:'.dl-timeline',    title:'Urgency-sorted timeline', body:'Red = act now, amber = approaching, grey = comfortable. The list re-sorts itself as dates roll.'},
    {target:'.pipeline-toggle',title:'All vs My pipeline',          body:'Toggle between every tracked deadline and just the ones tied to applications you\u2019ve logged. The same toggle on the Programs tab is shared — flip it once, both pages filter together.'},
    {target:'.dl-bulk-export', title:'Export your pipeline to calendar', body:'Drops every dated deadline from your pipeline into a single ICS file — open it once in Google, Outlook, or Apple Calendar and every program lands with 30/7/1-day reminders pre-built.'}
  ]
};

let _tourKey = null;
let _tourQueue = [];
let _tourIdx = 0;
// Phase 14: 30-second stack lock prevents tours from chaining when a user
// hops between tabs quickly. Also tracked: per-tour seen flag in localStorage,
// used as fallback when userProfile (Supabase-backed tours_completed) hasn't
// loaded yet on a fresh browser session.
let _lastTourTime = 0;
const TOUR_SEEN_LS_PREFIX = 'ldp_tour_seen_';

function _isTourSeen(pageKey){
  const dbSeen = (userProfile?.tours_completed || []).includes(pageKey);
  let lsSeen = false;
  try { lsSeen = localStorage.getItem(TOUR_SEEN_LS_PREFIX + pageKey + '_v1') === '1'; } catch(e){}
  return dbSeen || lsSeen;
}

// Gated auto-trigger for the first-visit tour on a given page.
// Called from showPage() for non-aifit pages immediately, and from the AI Fit
// dwell timer (10s after entering that page if the user hasn't uploaded yet).
function maybeAutoTour(pageKey){
  if(_tourKey) return;                                       // already running
  if(!currentUser) return;                                   // not signed in
  if(!TOURS[pageKey]) return;                                // unknown page
  if(_isTourSeen(pageKey)) return;                           // already seen (Supabase OR LS)
  if(document.querySelector('.overlay.open')) return;        // another modal is up (e.g. onboarding)
  // 30-second stack lock: if another tour just ended, don't immediately start a new one
  if(Date.now() - _lastTourTime < 30000) return;
  _lastTourTime = Date.now();
  tourStart(pageKey);
}

// ─── AI Fit dwell timer (Phase 14, Priority 4) ───────────────────
// AI Fit page is special: the natural first action is "upload your resume".
// We don't want to interrupt that with a tour, so we only auto-trigger the
// aifit tour if the user lingers on the page for ~10s without uploading.
// State machine:
//   showPage('aifit')          → startAifitDwell()      // arm the 10s timer
//   handleFileUpload (success) → clearAifitDwell()      // user is engaged
//   runAIAnalysis start        → _aifitScanning = true  // scan in progress
//   runAIAnalysis end (finally)→ _aifitScanning = false
//   showPage(any non-aifit)    → clearAifitDwell()      // left the page
let _aifitDwellTimer = null;
let _aifitScanning   = false;

function startAifitDwell(){
  clearAifitDwell();
  if(!currentUser) return;
  if(_aifitScanning) return;                                       // scan in progress
  if(_isTourSeen('aifit')) return;                                 // already toured
  _aifitDwellTimer = setTimeout(() => {
    _aifitDwellTimer = null;
    if(_aifitScanning) return;                                     // race: scan started in the 10s window
    maybeAutoTour('aifit');
  }, 10000);
}

function clearAifitDwell(){
  if(_aifitDwellTimer){
    clearTimeout(_aifitDwellTimer);
    _aifitDwellTimer = null;
  }
}

function tourStart(pageKey){
  if(!TOURS[pageKey]){ console.warn('tourStart: unknown pageKey', pageKey); return; }
  _tourKey = pageKey;
  _tourQueue = TOURS[pageKey];
  _tourIdx = 0;
  document.getElementById('tour-backdrop').classList.add('on');
  tourShow();
}

function tourShow(){
  if(_tourIdx >= _tourQueue.length){ tourEnd(true); return; }
  const step = _tourQueue[_tourIdx];

  // Scope to the currently active page so generic selectors like ".add-btn"
  // (which appears on multiple pages) resolve to the right element.
  const scoped = '.page.active ' + step.target;
  const target = document.querySelector(scoped) || document.querySelector(step.target);

  // Missing target → silently skip this step. Phase-5 selectors that don't exist
  // yet take this path automatically.
  if(!target){ tourNext(); return; }

  // Phase 14: also skip targets that exist but have no rendered size — happens
  // when the element is inside a display:none parent (e.g. AI Fit Scan's
  // post-scan results container before the user has run a scan).
  const _r = target.getBoundingClientRect();
  if(_r.width === 0 && _r.height === 0){ tourNext(); return; }

  // Scroll into view if needed (instant, so geometry below is accurate)
  let rect = target.getBoundingClientRect();
  if(rect.top < 60 || rect.bottom > window.innerHeight - 60){
    target.scrollIntoView({block:'center', inline:'nearest'});
    rect = target.getBoundingClientRect();
  }

  const PAD = 8;
  const spot = document.getElementById('tour-spotlight');
  spot.style.display = 'block';
  spot.style.top    = (rect.top    - PAD) + 'px';
  spot.style.left   = (rect.left   - PAD) + 'px';
  spot.style.width  = (rect.width  + PAD*2) + 'px';
  spot.style.height = (rect.height + PAD*2) + 'px';

  // Tooltip content
  const tip = document.getElementById('tour-tooltip');
  document.getElementById('tour-tooltip-title').textContent = step.title;
  document.getElementById('tour-tooltip-body').textContent  = step.body;
  document.getElementById('tour-step-count').textContent    = (_tourIdx + 1) + ' / ' + _tourQueue.length;
  document.getElementById('tour-next-btn').textContent      = (_tourIdx === _tourQueue.length - 1) ? 'Done' : 'Next';

  // Show tooltip first so we can measure it
  tip.style.display = 'block';
  tip.style.visibility = 'hidden';
  tip.style.top = '0px';
  tip.style.left = '0px';
  const tipH = tip.offsetHeight || 140;
  const tipW = tip.offsetWidth  || 300;

  const MARGIN = 12;
  const VPAD = 20;
  let top  = rect.bottom + PAD + MARGIN;       // default: below target
  if(top + tipH > window.innerHeight - VPAD){  // off-screen below → place above
    top = rect.top - PAD - MARGIN - tipH;
  }
  if(top < VPAD) top = VPAD;

  let left = rect.left;
  const maxLeft = window.innerWidth - 320;     // spec: viewport - 320
  if(left > maxLeft) left = maxLeft;
  if(left < VPAD) left = VPAD;

  tip.style.top  = top  + 'px';
  tip.style.left = left + 'px';
  tip.style.visibility = 'visible';
}

function tourNext(){
  _tourIdx++;
  if(_tourIdx >= _tourQueue.length){ tourEnd(true); return; }
  tourShow();
}

function tourSkip(){
  tourEnd(false);
}

async function tourEnd(completed){
  const key = _tourKey;
  document.getElementById('tour-backdrop').classList.remove('on');
  document.getElementById('tour-spotlight').style.display = 'none';
  document.getElementById('tour-tooltip').style.display   = 'none';
  _tourKey = null;
  _tourQueue = [];
  _tourIdx = 0;
  // Mark seen in localStorage on BOTH complete and skip so auto-trigger doesn't re-fire
  // on the next visit. The manual "Tour this page →" link calls tourStart() directly,
  // bypassing this gate, so users can always re-run if they want.
  if(key){
    try { localStorage.setItem(TOUR_SEEN_LS_PREFIX + key + '_v1', '1'); } catch(e){}
    // Reset stack lock — 30s window starts NOW, not when the tour was opened
    _lastTourTime = Date.now();
  }
  if(completed && key){
    await markTourCompleted(key);
  }
}

async function loadUserApplications(){
  if(!currentUser){ apps = []; return; }
  try {
    const { data, error } = await sb.from('user_applications').select('*').eq('user_id', currentUser.id).order('created_at',{ascending:false});
    if(error) throw error;
    // Map DB rows → in-memory shape used by render functions
    apps = (data||[]).map(r=>({
      id: r.id,                  // UUID now, not a Date.now() number
      _db: true,                 // marker that this came from DB
      program_id: r.program_id,
      name: r.name,
      org: r.org||'',
      geo: r.geo||'',
      status: r.status||'networking',
      date: r.applied_on||'',
      deadline: r.deadline||'',
      next: r.next_step||'',
      contact: r.contact||'',
      notes: r.notes||''
    }));
  } catch(e){
    console.warn('loadUserApplications failed:', e);
    apps = [];
  }
}

async function saveApplicationToDB(app){
  if(!currentUser) return null;
  const row = {
    user_id:    currentUser.id,
    program_id: app.program_id || null,
    name:       app.name,
    org:        app.org || null,
    geo:        app.geo || null,
    status:     app.status || 'networking',
    applied_on: app.date || null,
    deadline:   app.deadline || null,
    next_step:  app.next || null,
    contact:    app.contact || null,
    notes:      app.notes || null
  };
  try {
    if(app.id && app._db){
      // Update existing
      const { error } = await sb.from('user_applications').update(row).eq('id', app.id).eq('user_id', currentUser.id);
      if(error) throw error;
      // Phase 7: edits don't change apps.length, but defensive re-render is cheap
      renderProgressStrip();
      return app.id;
    } else {
      // Insert new
      const { data, error } = await sb.from('user_applications').insert(row).select('id').single();
      if(error) throw error;
      // Phase 7: the caller (saveApp) updates apps[] AFTER we return, so this render sees
      // stale apps[].length. The saveApp caller also re-renders post-cache-update, which is
      // the authoritative final state. Keeping this hook for spec compliance + defense in depth.
      renderProgressStrip();
      return data.id;
    }
  } catch(e){
    console.error('saveApplicationToDB failed:', e);
    toast('Could not save to cloud — please check your connection.');
    return null;
  }
}

async function deleteApplicationFromDB(id){
  if(!currentUser) return;
  try {
    const { error } = await sb.from('user_applications').delete().eq('id', id).eq('user_id', currentUser.id);
    if(error) throw error;
  } catch(e){
    console.error('deleteApplicationFromDB failed:', e);
    toast('Could not delete from cloud — please refresh.');
  }
}

async function loadUserResume(){
  if(!currentUser){ resumeText = ''; resumeLastScanAt = null; return; }
  try {
    const { data, error } = await sb.from('user_resumes').select('*').eq('user_id', currentUser.id).maybeSingle();
    if(error) throw error;
    if(data){
      resumeText = data.raw_text || '';
      resumeLastScanAt = data.last_scan_at || null;   // Phase 7
      // Surface saved resume in the Phase 13 AI Fit Scan UI
      if(data.file_name){
        const fileDisplay  = document.getElementById('aifit-file-display');
        const emptyDisplay = document.getElementById('aifit-empty-display');
        const fileInfo     = document.getElementById('aifit-file-info');
        const uploadBox    = document.getElementById('aifit-upload-box');
        const btn          = document.getElementById('analyze-btn');
        if(fileInfo) fileInfo.textContent = `${data.file_name} · Saved`;
        if(fileDisplay)  fileDisplay.style.display = 'block';
        if(emptyDisplay) emptyDisplay.style.display = 'none';
        if(uploadBox)    uploadBox.classList.add('has-file');
        if(btn)          btn.disabled = false;
      }
    } else {
      resumeText = '';
      resumeLastScanAt = null;
    }
  } catch(e){
    console.warn('loadUserResume failed:', e);
    resumeText = '';
    resumeLastScanAt = null;
  }
}

async function saveResumeToDB(rawText, fileName){
  if(!currentUser) return;
  try {
    const row = {
      user_id:     currentUser.id,
      file_name:   fileName || null,
      raw_text:    rawText,
      char_count:  rawText.length,
      uploaded_at: new Date().toISOString()
    };
    const { error } = await sb.from('user_resumes').upsert(row, {onConflict:'user_id'});
    if(error) throw error;
    // Phase 7: a new upload resets the scan timestamp; resume step now complete.
    resumeLastScanAt = null;
    renderProgressStrip();
    updateFitTabIndicator();
    renderFitBanner();
  } catch(e){
    console.error('saveResumeToDB failed:', e);
    toast('Resume saved locally but cloud sync failed — please retry.');
  }
}

async function saveScanToHistory(result){
  if(!currentUser) return;
  try {
    await sb.from('user_scan_history').insert({
      user_id: currentUser.id,
      result: result,
      resume_chars: resumeText.length,
      program_count: progs.length
    });
    // Mark resume last-scanned
    const nowIso = new Date().toISOString();
    await sb.from('user_resumes').update({ last_scan_at: nowIso }).eq('user_id', currentUser.id);
    // Phase 7: keep in-memory mirror in sync; refresh the smart banner
    resumeLastScanAt = nowIso;
    renderFitBanner();
  } catch(e){
    console.warn('saveScanToHistory failed (non-blocking):', e);
  }
}
// ────────────────────────────────────────────────────────────────

// ═══════════════ PHASE 2: ONBOARDING STATE MACHINE ═══════════════
let _onbStep = 1;
let _onbResumeFile = null;
let _onbSchoolKey = null;
let _onbSchoolLabel = null;

function onbShouldShow(){
  return !!(currentUser && userProfile && !userProfile.onboarding_completed_at && !userProfile.onboarding_skipped_at);
}

function onbOpen(){
  // Reset state each time we open (no mid-state persistence between sessions — by design)
  _onbStep = 1;
  _onbResumeFile = null;
  _onbSchoolKey = null;
  _onbSchoolLabel = null;
  // Phase 8: auto-detect school from the user's login email (e.g. alumni.esade.edu → ESADE)
  // User can still override on step 2 — this just removes the dropdown friction for ~95% of users.
  if(currentUser?.email){
    const detectedKey = detectSchoolFromEmail(currentUser.email);
    if(detectedKey){
      const obj = ALL_MBA_SCHOOLS.find(s => s.key === detectedKey);
      if(obj){
        _onbSchoolKey   = obj.key;
        _onbSchoolLabel = obj.label;
      }
    }
  }
  // Pre-fill name from existing profile if present (rare — only if a partial save happened earlier)
  const nameEl = document.getElementById('onb-name');
  if(nameEl) nameEl.value = userProfile?.full_name || '';
  const fileDisp = document.getElementById('onb-file-name-display');
  if(fileDisp){ fileDisp.style.display='none'; fileDisp.textContent=''; }
  const status = document.getElementById('onb-step3-status');
  if(status) status.textContent = '';
  const uz = document.getElementById('onb-upload-zone');
  if(uz) uz.classList.remove('has-file');
  const fi = document.getElementById('onb-resume-file-input');
  if(fi) fi.value = '';
  onbRenderSchoolOpts('');
  onbUpdateSchoolDisplay();
  document.getElementById('ov-onboard').classList.add('open');
  onbGoto(1);
  setTimeout(()=>{ const n=document.getElementById('onb-name'); if(n) n.focus(); }, 50);
}

function onbClose(){
  document.getElementById('ov-onboard').classList.remove('open');
}

function onbGoto(step){
  _onbStep = step;
  for(let i=1; i<=3; i++){
    const panel = document.getElementById('onb-panel-'+i);
    if(panel) panel.style.display = (i===step) ? 'block' : 'none';
    const ind = document.getElementById('onb-step-ind-'+i);
    if(ind) ind.classList.toggle('on', i<=step);
  }
  // Phase 8: when arriving at step 2, show the auto-detect banner if we pre-selected a school
  if(step === 2){
    const banner = document.getElementById('onb-school-autodetect');
    const msg    = document.getElementById('onb-school-autodetect-msg');
    if(banner && msg){
      if(_onbSchoolKey){
        msg.textContent = `${_onbSchoolLabel || _onbSchoolKey} — click below to change.`;
        banner.style.display = 'block';
      } else {
        banner.style.display = 'none';
      }
    }
  }
  // Bars light up when the step they CONNECT INTO is reached
  for(let i=1; i<=2; i++){
    const bar = document.getElementById('onb-bar-'+i);
    if(bar) bar.classList.toggle('on', step > i);
  }
  // Adjust button labels for final step
  const nextBtn = document.getElementById('onb-next-btn');
  if(nextBtn){
    nextBtn.textContent = (step === 3) ? '✦ Scan my résumé' : 'Next →';
    nextBtn.disabled = (step === 3 && !_onbResumeFile);
    nextBtn.style.opacity = nextBtn.disabled ? '0.5' : '1';
  }
}

async function onbNext(){
  if(_onbStep === 1){
    const val = (document.getElementById('onb-name').value || '').trim();
    if(!val){ toast('Please enter your name to continue.'); return; }
    await saveUserProfile({ full_name: val });
    onbGoto(2);
  } else if(_onbStep === 2){
    if(!_onbSchoolKey){ toast('Please pick your school to continue.'); return; }
    await saveUserProfile({ school_key: _onbSchoolKey, school_label: _onbSchoolLabel });
    activeAlumniSchool = _onbSchoolKey;
    onbGoto(3);
  } else if(_onbStep === 3){
    if(!_onbResumeFile){
      // Nothing to scan — user must use Skip
      toast('Add a résumé to scan, or click "Skip for now".');
      return;
    }
    const nextBtn = document.getElementById('onb-next-btn');
    const skipBtn = document.getElementById('onb-skip-btn');
    const status = document.getElementById('onb-step3-status');
    nextBtn.disabled = true; nextBtn.style.opacity='0.5';
    skipBtn.disabled = true; skipBtn.style.opacity='0.5';
    if(status) status.textContent = 'Parsing your résumé…';
    try {
      // Reuse the AI Fit pipeline directly — populates resumeText and persists to Supabase
      await handleFileUpload({ target:{ files:[_onbResumeFile] } });
      if(!resumeText || resumeText.length < 200){
        throw new Error('Could not extract enough text from this résumé. Please try a different file.');
      }
      if(status) status.textContent = 'Analysing fit across all programs…';
      await runAIAnalysis();
      await onbComplete();
      showPage('aifit');
    } catch(err){
      console.error('Onboarding scan failed:', err);
      if(status) status.textContent = '⚠ ' + (err.message || 'Scan failed — you can retry from the AI Fit Scan tab.');
      nextBtn.disabled = false; nextBtn.style.opacity='1';
      skipBtn.disabled = false; skipBtn.style.opacity='1';
    }
  }
}

async function onbSkip(){
  await saveUserProfile({ onboarding_skipped_at: new Date().toISOString() });
  onbClose();
  showPage('programs');
}

async function onbComplete(){
  await saveUserProfile({ onboarding_completed_at: new Date().toISOString() });
  onbClose();
}

function onbHandleFileSelect(event){
  const file = event.target.files[0];
  if(!file) return;
  if(file.size > 5*1024*1024){
    toast('File too large — please use a file under 5MB.');
    event.target.value = '';
    return;
  }
  _onbResumeFile = file;
  const nd = document.getElementById('onb-file-name-display');
  const uz = document.getElementById('onb-upload-zone');
  if(nd){ nd.textContent = '✓ ' + file.name; nd.style.display='block'; }
  if(uz) uz.classList.add('has-file');
  const nextBtn = document.getElementById('onb-next-btn');
  if(nextBtn){ nextBtn.disabled = false; nextBtn.style.opacity='1'; }
  const status = document.getElementById('onb-step3-status');
  if(status) status.textContent = '';
}

// ── Onboarding school dropdown (mirrors renderAlumniSchoolOpts but with onb-* IDs) ──
function onbRenderSchoolOpts(q){
  // Thin wrapper that reuses the ALL_MBA_SCHOOLS data source from renderAlumniSchoolOpts
  const container = document.getElementById('onb-school-opts');
  if(!container) return;
  const filtered = ALL_MBA_SCHOOLS.filter(s => !q || s.label.toLowerCase().includes(q.toLowerCase()));
  container.innerHTML = filtered.map(s => `
    <div onclick="onbPickSchool('${s.key}')" style="padding:9px 14px;font-size:12px;cursor:pointer;color:${_onbSchoolKey===s.key?'var(--accent)':'var(--text)'};background:${_onbSchoolKey===s.key?'var(--accent-bg)':'transparent'};border-bottom:1px solid var(--border);transition:background .1s"
      onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background='${_onbSchoolKey===s.key?'var(--accent-bg)':'transparent'}'">
      ${s.label}${_onbSchoolKey===s.key?' ✓':''}
    </div>`).join('');
}

function onbToggleSchoolDrop(){
  const drop = document.getElementById('onb-school-drop');
  if(!drop) return;
  const open = drop.style.display !== 'none';
  drop.style.display = open ? 'none' : 'block';
  if(!open){
    const fi = document.getElementById('onb-school-filter');
    if(fi){ fi.value=''; onbRenderSchoolOpts(''); fi.focus(); }
  }
}

function onbFilterSchoolDrop(){
  const q = (document.getElementById('onb-school-filter')||{}).value||'';
  onbRenderSchoolOpts(q);
}

function onbUpdateSchoolDisplay(){
  const el = document.getElementById('onb-school-display');
  if(!el) return;
  el.textContent = _onbSchoolLabel || 'Select your school';
  el.style.color = _onbSchoolKey ? 'var(--text)' : 'var(--text3)';
}

function onbPickSchool(key){
  const schoolObj = ALL_MBA_SCHOOLS.find(s=>s.key===key);
  _onbSchoolKey = key;
  _onbSchoolLabel = schoolObj?.label || key;
  document.getElementById('onb-school-drop').style.display = 'none';
  onbUpdateSchoolDisplay();
}

// Close onboarding school dropdown when clicking outside
document.addEventListener('click', e => {
  const wrap = document.getElementById('onb-school-wrap');
  if(wrap && !wrap.contains(e.target)){
    const drop = document.getElementById('onb-school-drop');
    if(drop) drop.style.display = 'none';
  }
});
// ────────────────────────────────────────────────────────────────

let progs = JSON.parse(localStorage.getItem('ldps_progs')||'null')||JSON.parse(JSON.stringify(DP));
let progsLoadedFromDb = false;  // Phase 12: tracks if progs was refreshed from Supabase this session
let alum  = JSON.parse(localStorage.getItem('ldps_alum') ||'null')||JSON.parse(JSON.stringify(DA));
let apps  = [];                       // loaded from Supabase on sign-in
// userProfile is declared in the auth section above and populated by loadUserProfile()
let selectedSchools = [];
let eId   = {prog:null,alumni:null,app:null};
// Phase 10: filter state — each dimension is a Set of selected values.
// Empty Set = no filter (equivalent to "All"). asc/ast remain single-value for Alumni.
let F = {
  geo:  new Set(),
  fn:   new Set(),
  st:   new Set(),
  asc:  'all',
  ast:  'all',
  // Sort state for Programs table: column key + direction. null = default (unsorted).
  sortKey: null,
  sortDir: 'asc'   // 'asc' | 'desc'
};
let resumeText = '';
// Phase 7: ISO timestamp of last AI fit scan, or null. Mirrors user_resumes.last_scan_at.
// Used by renderFitBanner to decide stale/fresh state. Kept separate from userProfile because
// it sources from a different table (user_resumes) with its own update lifecycle.
let resumeLastScanAt = null;
let isUnlocked = true; // paywall removed

function persist(){
  // Only program cache + alumni search cards live in localStorage now.
  // Applications and resume are saved server-side in Supabase.
  localStorage.setItem('ldps_progs',JSON.stringify(progs));
  localStorage.setItem('ldps_alum', JSON.stringify(alum));
}

// ═══════════════ ONBOARDING ═══════════════
const ALL_MBA_SCHOOLS = [
  {key:'esade',label:'ESADE Business School',li:'esade'},
  {key:'hec',label:'HEC Paris',li:'hec-paris'},
  {key:'insead',label:'INSEAD',li:'insead'},
  {key:'lbs',label:'London Business School (LBS)',li:'london-business-school'},
  {key:'iese',label:'IESE Business School',li:'iese-business-school'},
  {key:'ie',label:'IE Business School',li:'ie-business-school'},
  {key:'oxford',label:'Oxford Saïd Business School',li:'said-business-school'},
  {key:'cambridge',label:'Cambridge Judge Business School',li:'cambridge-judge-business-school'},
  {key:'bocconi',label:'SDA Bocconi School of Management',li:'sda-bocconi-school-of-management'},
  {key:'mannheim',label:'Mannheim Business School',li:'mannheim-business-school'},
  {key:'wbs',label:'Warwick Business School',li:'warwick-business-school'},
  {key:'imperial',label:'Imperial College Business School',li:'imperial-college-business-school'},
  {key:'cranfield',label:'Cranfield School of Management',li:'cranfield-school-of-management'},
  {key:'rsm',label:'Rotterdam School of Management (RSM)',li:'rotterdam-school-of-management'},
  {key:'tias',label:'TIAS School for Business and Society',li:'tias-school-for-business-and-society'},
  {key:'vlerick',label:'Vlerick Business School',li:'vlerick-business-school'},
  {key:'alba',label:'ALBA Graduate Business School',li:'alba-graduate-business-school'},
  {key:'edhec',label:'EDHEC Business School',li:'edhec-business-school'},
  {key:'emlyon',label:'emlyon business school',li:'emlyon-business-school'},
  {key:'grenoble',label:'Grenoble École de Management',li:'grenoble-ecole-de-management'},
  {key:'skema',label:'SKEMA Business School',li:'skema-business-school'},
  {key:'audencia',label:'Audencia Business School',li:'audencia'},
  {key:'neoma',label:'NEOMA Business School',li:'neoma-business-school'},
  {key:'kedge',label:'KEDGE Business School',li:'kedge-business-school'},
  {key:'escp',label:'ESCP Business School',li:'escp-europe'},
  {key:'ebs',label:'EBS Universität für Wirtschaft und Recht',li:'ebs-university'},
  {key:'whu',label:'WHU – Otto Beisheim School of Management',li:'whu-otto-beisheim-school-of-management'},
  {key:'hws',label:'HHL Leipzig Graduate School of Management',li:'hhl-leipzig-graduate-school-of-management'},
  {key:'frankfurt',label:'Frankfurt School of Finance & Management',li:'frankfurt-school-of-finance-management'},
  {key:'stgallen',label:'University of St. Gallen (HSG)',li:'university-of-st-gallen'},
  {key:'imd',label:'IMD Business School',li:'imd-business-school'},
  {key:'lisbon',label:'Nova SBE / Católica Lisbon',li:'nova-sbe'},
  {key:'ceibs',label:'CEIBS (China Europe International Business School)',li:'ceibs'},
  {key:'kellogg_mba',label:'Kellogg School of Management',li:'kellogg-school-of-management'},
  {key:'wharton',label:'The Wharton School',li:'the-wharton-school'},
  {key:'booth',label:'University of Chicago Booth',li:'university-of-chicago-booth-school-of-business'},
  {key:'columbia',label:'Columbia Business School',li:'columbia-business-school'},
  {key:'other',label:'Other / Not listed',li:null},
];
const SCHOOL_LABELS=Object.fromEntries(ALL_MBA_SCHOOLS.map(s=>[s.key,s.label]));
const SCHOOL_LI_IDS=Object.fromEntries(ALL_MBA_SCHOOLS.map(s=>[s.key,s.li]));

// ═══ PHASE 8: EMAIL DOMAIN → SCHOOL AUTO-DETECT ═══
// Used during onboarding to pre-select the user's school based on their login email
// (e.g. shrey.singhal@alumni.esade.edu → 'esade'). User can still override on step 2.
// Covers school primary domains, student variants, and alumni variants where known.
const SCHOOL_DOMAIN_MAP = {
  // ESADE
  'esade.edu':'esade', 'alumni.esade.edu':'esade',
  // HEC Paris
  'hec.edu':'hec', 'hec.fr':'hec',
  // INSEAD
  'insead.edu':'insead',
  // London Business School
  'london.edu':'lbs',
  // IESE
  'iese.edu':'iese', 'iese.net':'iese',
  // IE Business School
  'ie.edu':'ie', 'student.ie.edu':'ie', 'alumni.ie.edu':'ie',
  // Oxford Saïd
  'sbs.ox.ac.uk':'oxford', 'said.ox.ac.uk':'oxford', 'ox.ac.uk':'oxford',
  // Cambridge Judge
  'jbs.cam.ac.uk':'cambridge', 'cam.ac.uk':'cambridge',
  // Bocconi
  'unibocconi.it':'bocconi', 'sdabocconi.it':'bocconi',
  // Mannheim
  'mannheim-business-school.com':'mannheim',
  // Warwick
  'wbs.ac.uk':'wbs', 'warwick.ac.uk':'wbs',
  // Imperial
  'imperial.ac.uk':'imperial',
  // Cranfield
  'cranfield.ac.uk':'cranfield',
  // Rotterdam (RSM)
  'rsm.nl':'rsm', 'eur.nl':'rsm',
  // Vlerick
  'vlerick.com':'vlerick',
  // EDHEC
  'edhec.com':'edhec', 'edhec.edu':'edhec',
  // emlyon
  'em-lyon.com':'emlyon', 'emlyon.com':'emlyon',
  // ESCP
  'escp.eu':'escp',
  // WHU
  'whu.edu':'whu',
  // HHL Leipzig
  'hhl.de':'hws',
  // Frankfurt School
  'frankfurt-school.de':'frankfurt',
  // St. Gallen
  'unisg.ch':'stgallen', 'student.unisg.ch':'stgallen',
  // IMD
  'imd.org':'imd',
  // Nova SBE / Católica Lisbon
  'novasbe.pt':'lisbon', 'ucp.pt':'lisbon',
  // CEIBS
  'ceibs.edu':'ceibs',
  // US M7
  'kellogg.northwestern.edu':'kellogg_mba', 'northwestern.edu':'kellogg_mba',
  'wharton.upenn.edu':'wharton', 'upenn.edu':'wharton',
  'chicagobooth.edu':'booth',
  'gsb.columbia.edu':'columbia', 'columbia.edu':'columbia',
};

function detectSchoolFromEmail(email){
  if(!email || typeof email !== 'string') return null;
  const at = email.lastIndexOf('@');
  if(at < 0) return null;
  let domain = email.slice(at+1).toLowerCase().trim();
  // Try the full domain first, then progressively shorter suffixes.
  // e.g. "alumni.esade.edu" → try whole, then "esade.edu"
  while(domain && domain.includes('.')){
    if(SCHOOL_DOMAIN_MAP[domain]) return SCHOOL_DOMAIN_MAP[domain];
    domain = domain.slice(domain.indexOf('.')+1);
  }
  return null;
}

// ═══════════════ SCHOOL DROPDOWN ═══════════════
function filterSchoolDropdown(){
  const q = document.getElementById('ob-school-search').value.toLowerCase();
  renderSchoolDropdown(q);
  openSchoolDropdown();
}
function openSchoolDropdown(){
  const dd = document.getElementById('ob-school-dropdown');
  if(dd) { renderSchoolDropdown(document.getElementById('ob-school-search').value.toLowerCase()); dd.classList.add('open'); }
}
function closeSchoolDropdown(){
  const dd = document.getElementById('ob-school-dropdown');
  if(dd) dd.classList.remove('open');
}
function renderSchoolDropdown(q=''){
  const dd = document.getElementById('ob-school-dropdown');
  if(!dd) return;
  const filtered = ALL_MBA_SCHOOLS.filter(s => !selectedSchools.includes(s.key) && (!q || s.label.toLowerCase().includes(q)));
  dd.innerHTML = filtered.length === 0
    ? `<div class="school-opt" style="color:var(--text3);cursor:default">No schools found — try a different name</div>`
    : filtered.map(s => `<div class="school-opt" onclick="addSchool('${s.key}')">${s.label}</div>`).join('');
}
function addSchool(key){
  if(!selectedSchools.includes(key)) selectedSchools.push(key);
  document.getElementById('ob-school-search').value = '';
  renderSchoolDropdown('');
  renderSelectedSchools();
  closeSchoolDropdown();
}
function removeSchool(key){
  selectedSchools = selectedSchools.filter(s => s !== key);
  renderSelectedSchools();
  renderSchoolDropdown('');
}
function renderSelectedSchools(){
  const el = document.getElementById('ob-selected-schools');
  if(!el) return;
  el.innerHTML = selectedSchools.map(s => `<span class="selected-school-tag">${SCHOOL_LABELS[s]||s}<button onclick="removeSchool('${s}')" title="Remove">×</button></span>`).join('');
}
// Legacy toggleSchool — kept for any remaining references
function toggleSchool(btn){ addSchool(btn.getAttribute('data-school')); }

// ═══════════════ ICS MODAL ═══════════════
let _icsItem = null;
function openICSModal(item){
  _icsItem = item;
  const title = document.getElementById('ics-modal-title');
  const sub = document.getElementById('ics-modal-sub');
  if(title) title.textContent = `Deadline reminder — ${item.name}`;
  if(sub) sub.textContent = `${item.org} · ${new Date(item.deadline).toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'})}`;
  document.getElementById('ics-modal-overlay').classList.add('open');
}
function confirmICS(mode){
  document.getElementById('ics-modal-overlay').classList.remove('open');
  if(_icsItem) downloadICS(_icsItem, mode);
}

// ─── In-app Set/Change Password (Phase 14) ───────────────────────
// Lets a signed-in user attach or change their password at any time,
// without going through the OTP+post-OTP-prompt path. Uses Supabase's
// updateUser({password}) which works against the active session.

function openSetPasswordModal(){
  if(!currentUser){
    toast('Please sign in first.');
    return;
  }
  const overlay = document.getElementById('setpw-modal-overlay');
  const title = document.getElementById('setpw-modal-title');
  const sub = document.getElementById('setpw-modal-sub');
  const msg = document.getElementById('setpw-msg');
  const input1 = document.getElementById('setpw-input');
  const input2 = document.getElementById('setpw-input2');
  const btn = document.getElementById('setpw-save-btn');
  // Reset state
  if(msg){ msg.style.display = 'none'; msg.textContent = ''; msg.style.background = ''; msg.style.color = ''; }
  if(input1) input1.value = '';
  if(input2) input2.value = '';
  if(btn){ btn.disabled = false; btn.textContent = 'Save password'; }
  // Title copy: differentiates first-time-set vs change for the user
  if(title) title.textContent = 'Set or change your password';
  if(sub) sub.textContent = `Signed in as ${currentUser.email}. Set a password so you can sign in without a code next time.`;
  overlay.classList.add('open');
  setTimeout(()=>{ if(input1) input1.focus(); }, 100);
}

function closeSetPasswordModal(){
  document.getElementById('setpw-modal-overlay').classList.remove('open');
}

async function saveAccountPassword(){
  const input1 = document.getElementById('setpw-input');
  const input2 = document.getElementById('setpw-input2');
  const msg = document.getElementById('setpw-msg');
  const btn = document.getElementById('setpw-save-btn');
  const pw1 = (input1.value || '');
  const pw2 = (input2.value || '');

  msg.style.display = 'none';
  msg.textContent = '';

  if(pw1.length < 8){
    msg.textContent = 'Password must be at least 8 characters.';
    msg.style.display = 'block';
    msg.style.background = 'var(--coral-bg)';
    msg.style.color = 'var(--coral)';
    return;
  }
  if(pw1 !== pw2){
    msg.textContent = 'The two passwords don\u2019t match.';
    msg.style.display = 'block';
    msg.style.background = 'var(--coral-bg)';
    msg.style.color = 'var(--coral)';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    // Phase 15: write has_password=true so updateAuthUI flips the label to
    // "Change password" — both for this device immediately and for any other
    // device this user signs in on (Supabase syncs user_metadata).
    const { data: updateData, error } = await sb.auth.updateUser({
      password: pw1,
      data: { has_password: true }
    });
    if(error){
      msg.textContent = error.message || 'Could not save password.';
      msg.style.display = 'block';
      msg.style.background = 'var(--coral-bg)';
      msg.style.color = 'var(--coral)';
      btn.disabled = false;
      btn.textContent = 'Save password';
      return;
    }
    // Phase 15: refresh local user + flip button label live
    if(updateData?.user) currentUser = updateData.user;
    updateAuthUI();
    // Success — also flag the post-OTP prompt as dismissed so the user
    // doesn't get re-prompted on their next OTP signin
    try { localStorage.setItem('ldp_pw_prompt_dismissed_v1', 'true'); } catch(e){}
    msg.textContent = '✓ Password saved. You can sign in with this password next time.';
    msg.style.display = 'block';
    msg.style.background = 'var(--accent-bg)';
    msg.style.color = 'var(--accent)';
    btn.disabled = false;
    btn.textContent = 'Save password';
    setTimeout(()=>{
      closeSetPasswordModal();
      toast('✦ Password saved');
    }, 1200);
  } catch(err){
    msg.textContent = err.message || 'Unexpected error.';
    msg.style.display = 'block';
    msg.style.background = 'var(--coral-bg)';
    msg.style.color = 'var(--coral)';
    btn.disabled = false;
    btn.textContent = 'Save password';
  }
}

// Click-outside-to-close for the setpw modal
document.addEventListener('DOMContentLoaded', ()=>{
  const o = document.getElementById('setpw-modal-overlay');
  if(o){
    o.addEventListener('click', e=>{
      if(e.target === o) closeSetPasswordModal();
    });
  }
});

// Phase 2 cleanup: removed no-op stubs saveOnboarding / skipOnboarding / applyProfile / dismissPaywall.
// Onboarding now lives in the onb* state machine; paywall was removed (isUnlocked = true).

// ═══════════════ NAV ═══════════════
const PAGE_ORDER=['programs','aifit','alumni','applications','deadlines'];
function showPage(id){
  // Hard-gate: must be signed in to access any tab
  if(!currentUser){
    showLanding();
    setTimeout(()=>{ const el=document.getElementById('lp-email'); if(el) el.focus(); },150);
    return;
  }
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  const idx=PAGE_ORDER.indexOf(id);
  const tabs=document.querySelectorAll('.nav-tab');
  if(idx>=0&&tabs[idx]) tabs[idx].classList.add('active');
  
  ({programs:renderPrograms,alumni:()=>{initAlumniSchoolDrop();renderAlumniSectorList();renderAlumniSearch();},applications:renderApplications,deadlines:renderDeadlines,aifit:()=>{}})[id]?.();

  // Phase 4 / Phase 14: first-visit auto-tour wiring.
  // - aifit page → dwell timer (10s with no upload → tour). Special-cased because
  //   the natural first action on AI Fit is "upload resume", and we don't want to
  //   interrupt that with a tour. Only show the tour if the user actually stalls.
  // - All other pages → fire maybeAutoTour() immediately (with 600ms render-settle delay).
  //   Gated by: not-already-seen (Supabase tours_completed OR localStorage),
  //   no other modal open, 30s stack lock between tours.
  if(id === 'aifit'){
    startAifitDwell();
  } else {
    clearAifitDwell();   // leaving the aifit page → kill pending dwell timer
    setTimeout(() => maybeAutoTour(id), 600);
  }
}

// Legacy stub — the new lpSignUp() (defined above in auth section) handles signup.
// Kept here so any onclick handlers in old DOM nodes don't error.
function enterApp(){
  if(currentUser){
    hideLanding();
  } else {
    showLanding();
    setTimeout(()=>{ const el=document.getElementById('lp-email'); if(el) el.focus(); },150);
  }
}

// ═══════════════ FILTERS ═══════════════
// Phase 10: setF toggles a value in/out of the filter Set. The "All" pill clears the Set.
// Alumni filters (asc/ast) remain single-value — they're string fields not Sets.
function setF(dim, btn){
  const val = btn.getAttribute('data-'+dim);
  if(dim === 'asc' || dim === 'ast'){
    // Alumni-side filters: single-value behaviour unchanged
    F[dim] = val;
    document.querySelectorAll('[data-'+dim+']').forEach(b => b.classList.remove('on'));
    btn.classList.add('on');
    renderAlumni();
    return;
  }
  // Programs-side filters: multi-select via Set
  if(val === 'all'){
    F[dim].clear();
  } else if(F[dim].has(val)){
    F[dim].delete(val);
  } else {
    F[dim].add(val);
  }
  _syncFilterPills(dim);
  _persistFilterState();
  renderPrograms();
}

// Reflect the current Set state into the UI pills for a given dimension
function _syncFilterPills(dim){
  const sel = F[dim];
  document.querySelectorAll('[data-'+dim+']').forEach(b => {
    const v = b.getAttribute('data-'+dim);
    if(v === 'all') b.classList.toggle('on', sel.size === 0);
    else            b.classList.toggle('on', sel.has(v));
  });
}

// Clickable stat cards — toggle membership in the status filter Set
function statClick(status){
  if(F.st.has(status)){
    F.st.delete(status);
  } else {
    F.st.add(status);
  }
  _syncFilterPills('st');
  _persistFilterState();
  renderPrograms();
}

function toggleVisaFilter(btn){
  window._visaOnly = !window._visaOnly;
  btn.classList.toggle('on', window._visaOnly);
  _persistFilterState();
  renderPrograms();
}

function fitClick(){
  window._fitOnly = !window._fitOnly;
  _persistFilterState();
  renderPrograms();
}

function clearAll(){
  F.geo.clear(); F.fn.clear(); F.st.clear();
  F.sortKey = null; F.sortDir = 'asc';
  window._fitOnly = false;
  window._visaOnly = false;
  const vp = document.getElementById('visa-pill'); if(vp) vp.classList.remove('on');
  ['geo','fn','st'].forEach(_syncFilterPills);
  const ps = document.getElementById('prog-search'); if(ps) ps.value = '';
  // Also clear the shared pipeline filter — "Clear filters" should mean ALL filters off.
  // This is a SHARED state with the Deadlines page; that's the documented design.
  if(_pipelineFilter){
    _pipelineFilter = false;
    try { localStorage.setItem('ldp_pipeline_filter_v1', '0'); } catch(e){}
    _syncPipelineToggleUI();
  }
  _persistFilterState();
  renderPrograms();
}

// Phase 10: clicking a sortable header toggles sort. Same column → flip direction.
// Different column → start with ascending. Clicking the active column when descending
// → clear sort (back to default order).
function sortBy(key){
  if(F.sortKey === key){
    if(F.sortDir === 'asc')       F.sortDir = 'desc';
    else if(F.sortDir === 'desc'){ F.sortKey = null; F.sortDir = 'asc'; }
  } else {
    F.sortKey = key;
    F.sortDir = 'asc';
  }
  _persistFilterState();
  renderPrograms();
}

// Phase 10: persist filter + sort + search across tab switches and reloads.
// Search box value is also captured so coming back to Programs preserves the query.
function _persistFilterState(){
  try {
    const ps = document.getElementById('prog-search');
    const state = {
      geo: [...F.geo],
      fn:  [...F.fn],
      st:  [...F.st],
      sortKey: F.sortKey,
      sortDir: F.sortDir,
      fitOnly:  !!window._fitOnly,
      visaOnly: !!window._visaOnly,
      search:  ps ? ps.value : ''
    };
    localStorage.setItem('ldps_prog_filters', JSON.stringify(state));
  } catch {}
}

function _restoreFilterState(){
  try {
    const raw = localStorage.getItem('ldps_prog_filters');
    if(!raw) return;
    const s = JSON.parse(raw);
    F.geo = new Set(Array.isArray(s.geo) ? s.geo : []);
    F.fn  = new Set(Array.isArray(s.fn)  ? s.fn  : []);
    F.st  = new Set(Array.isArray(s.st)  ? s.st  : []);
    F.sortKey = s.sortKey || null;
    F.sortDir = (s.sortDir === 'desc') ? 'desc' : 'asc';
    window._fitOnly  = !!s.fitOnly;
    window._visaOnly = !!s.visaOnly;
    const ps = document.getElementById('prog-search');
    if(ps && typeof s.search === 'string') ps.value = s.search;
    const vp = document.getElementById('visa-pill'); if(vp) vp.classList.toggle('on', window._visaOnly);
    ['geo','fn','st'].forEach(_syncFilterPills);
  } catch {}
}

// Verified badge helper
const VERIFIED_DATE = 'May 2026';
function verifiedBadge(p){
  // All built-in programs are verified May 2026; user-added have no verified date
  if(p.id && p.id <= 42 && p.id >= 1){
    return `<span class="verified-badge vb-fresh" title="Data verified ${VERIFIED_DATE} — sourced from official careers pages">✓ Verified ${VERIFIED_DATE}</span>`;
  }
  return '';
}

function renderPrograms(){
  _syncPipelineToggleUI();   // keep the Programs pill in lockstep with shared state
  // Phase 7: smart banner reflects resume + scan freshness
  renderFitBanner();
  const q=(document.getElementById('prog-search')||{}).value?.toLowerCase()||'';
  // Phase 10: persist search text whenever this runs (oninput → renderPrograms)
  _persistFilterState();
  let list=progs.filter(p=>{
    // Multi-select: an empty Set = no filter active = pass everything for that dimension.
    if(F.geo.size && !F.geo.has(p.geo))    return false;
    if(F.fn.size  && !F.fn.has(p.fn))      return false;
    if(F.st.size  && !F.st.has(p.status))  return false;
    if(window._fitOnly && (+p.fit||0) < 4) return false;
    if(window._visaOnly && !p.visa)        return false;
    // Universal pipeline filter — shared with Deadlines page
    if(_pipelineFilter && !_findAppForProgram(p)) return false;
    if(q && !p.name.toLowerCase().includes(q) && !p.org.toLowerCase().includes(q) && !(p.notes||'').toLowerCase().includes(q)) return false;
    return true;
  });

  // Phase 10: apply user-selected sort if any. Default order (no sort) keeps original DP[] order.
  if(F.sortKey){
    const TIER_RANK = {BEST_FIT:5, STRONG_FIT:4, ACHIEVABLE:3, LONG_SHOT:2, NOT_FIT:1};
    const STATUS_RANK = {open:1, rolling:2, watch:3, closed:4};
    const cmp = (a, b) => {
      let av, bv;
      switch(F.sortKey){
        case 'name':     av=(a.name||'').toLowerCase(); bv=(b.name||'').toLowerCase(); break;
        case 'org':      av=(a.org||'').toLowerCase();  bv=(b.org||'').toLowerCase();  break;
        case 'fn':       av=`${a.fn||''} ${a.sector||''}`.toLowerCase(); bv=`${b.fn||''} ${b.sector||''}`.toLowerCase(); break;
        case 'loc':      av=(a.loc||a.geo||'').toLowerCase(); bv=(b.loc||b.geo||'').toLowerCase(); break;
        case 'deadline':
          // Treat rolling/missing deadlines as far-future for asc, near-past for desc.
          av = a.deadline ? new Date(a.deadline).getTime() : Number.POSITIVE_INFINITY;
          bv = b.deadline ? new Date(b.deadline).getTime() : Number.POSITIVE_INFINITY;
          break;
        case 'status':   av = STATUS_RANK[a.status]||99; bv = STATUS_RANK[b.status]||99; break;
        case 'fit':
          // Sort by AI tier first (if scanned), then by static fit stars.
          av = a.aiTier ? TIER_RANK[a.aiTier] : (+a.fit||0);
          bv = b.aiTier ? TIER_RANK[b.aiTier] : (+b.fit||0);
          // Higher tier first when asc — so users see Best Fit at top.
          // Invert here so the dir flip below makes intuitive sense.
          av = -av; bv = -bv;
          break;
        default: return 0;
      }
      if(av < bv) return -1;
      if(av > bv) return  1;
      return 0;
    };
    list.sort(cmp);
    if(F.sortDir === 'desc') list.reverse();
  }

  const sm={open:['b-open','Open'],rolling:['b-rolling','Rolling'],watch:['b-watch','Watch'],closed:['b-closed','Closed']};
  const fitTier=(n,p)=>{
    if(p.aiTier){
      const map={BEST_FIT:['ft-best','Best Fit'],STRONG_FIT:['ft-strong','Strong'],ACHIEVABLE:['ft-good','Achievable'],LONG_SHOT:['ft-partial','Long Shot'],NOT_FIT:['ft-stretch','Not a Fit']};
      const [cls,lbl]=map[p.aiTier]||['ft-stretch','—'];
      return `<span class="fit-tier ${cls}" title="${p.aiReason||''}">✦ ${lbl}</span>`;
    }
    if(n>=5) return '<span class="fit-tier ft-best">Best Fit</span>';
    if(n>=4) return '<span class="fit-tier ft-strong">Strong</span>';
    if(n>=3) return '<span class="fit-tier ft-good">Good</span>';
    if(n>=2) return '<span class="fit-tier ft-partial">Partial</span>';
    return '<span class="fit-tier ft-stretch">Stretch</span>';
  };

  // Phase 9: count line is prominent when filters narrow the result set
  const metaEl = document.getElementById('prog-meta');
  if(metaEl){
    if(list.length === progs.length){
      metaEl.className = 'results-meta';
      metaEl.textContent = `Showing all ${progs.length} programs`;
    } else {
      metaEl.className = 'results-meta filtered';
      metaEl.innerHTML = `<span><strong>${list.length}</strong> of ${progs.length} programs match your filters</span>
        <button class="results-meta-clear" onclick="clearAll()">Clear filters</button>`;
    }
  }

  document.getElementById('prog-list').innerHTML=list.length===0
    ?'<div class="empty">No programs match your filters. <button onclick="clearAll()" style="background:none;border:none;color:var(--blue);cursor:pointer;text-decoration:underline">Clear all filters</button></div>'
    :list.map(p=>{
      const [bc,bl]=sm[p.status]||['b-closed','—'];
      const dl=p.deadline?new Date(p.deadline).toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'}):(p.dlnote||'—');
      return `<div class="prow">
        <div>
          <div class="pname">${p.url?`<a href="${p.url}" target="_blank" rel="noopener noreferrer" style="color:var(--text);text-decoration:none;border-bottom:1px solid var(--border2);padding-bottom:1px" onmouseover="this.style.borderColor='var(--accent)';this.style.color='var(--accent)'" onmouseout="this.style.borderColor='var(--border2)';this.style.color='var(--text)'">${p.name}</a>`:p.name}</div>
          <div class="porg">${p.org}${p.visa?` <span style="font-size:10px;color:var(--teal);font-weight:600;margin-left:4px">✓ Visa</span>`:''}</div>
          <div class="tags">${(p.tags||[]).map(t=>`<span class="tag">${t}</span>`).join('')}${verifiedBadge(p)}</div>
        </div>
        <div class="cell">${cap(p.fn)} · ${cap(p.sector)}</div>
        <div class="cell">${p.loc||p.geo}</div>
        <div class="cell mono" style="font-size:10px;line-height:1.5">${dl}</div>
        <div><span class="badge ${bc}">${bl}</span></div>
        <div>
          ${p.aiTier ? fitTier(+p.fit||3,p) : `<span onclick="showPage('aifit')" title="Scan your résumé to see your fit for this program" style="cursor:pointer;font-size:10px;color:var(--text3);border-bottom:1px dashed var(--border2)">Scan résumé</span>`}
        </div>
        <div>
          ${p.deadline ? `<button class="ics-btn" onclick="openICSModal(${JSON.stringify({name:p.name,org:p.org,deadline:p.deadline,type:'program'}).replace(/"/g,'&quot;')})">📅 Set</button>` : `<span style="font-size:10px;color:var(--text3)">—</span>`}
        </div>
        <div>
          ${(() => {
            // Phase 14: Pipeline column — quick-add to user's application pipeline.
            // Default stage is 'shortlisted' (matches the AI Fit "+ Shortlist" button).
            // If already in pipeline, show the current stage as read-only confirmation.
            const existingApp = _findAppForProgram(p);
            if(existingApp){
              const stage = existingApp.status || 'shortlisted';
              const stageLabel = stage.charAt(0).toUpperCase() + stage.slice(1);
              return `<span class="prow-pipe-saved" title="In your pipeline (${stageLabel}). Manage on the My Applications tab.">✓ ${stageLabel}</span>`;
            }
            return `<button class="prow-pipe-btn" onclick="addProgramToApplications(${p.id}, 'shortlisted')" title="Save to your pipeline at the Shortlisted stage">+ Shortlist</button>`;
          })()}
        </div>
        <div class="abts">
          <button class="bsm" onclick="editP(${p.id})">Edit</button>
          <button class="bsm del" onclick="delP(${p.id})">Del</button>
        </div>
      </div>`;
    }).join('');

  // Stats — with active state
  const open=progs.filter(p=>p.status==='open').length;
  const rolling=progs.filter(p=>p.status==='rolling').length;
  const watch=progs.filter(p=>p.status==='watch').length;
  const highFit=progs.filter(p=>(+p.fit||0)>=4).length;
  const fitActive=window._fitOnly?'sc-active':'';
  const anyFilterActive = F.geo.size>0 || F.fn.size>0 || F.st.size>0 || window._fitOnly || window._visaOnly || q.length>0;

  document.getElementById('prog-stats').innerHTML=`
    <div class="stat-card sc-total ${anyFilterActive?'sc-active':''}" onclick="clearAll()" title="Click to clear all filters">
      <div class="stat-num">${progs.length}</div>
      <div class="stat-lbl">Total Programs</div>
      <div class="stat-hint">Clear filters</div>
    </div>
    <div class="stat-card sc-open ${F.st.has('open')?'sc-active':''}" onclick="statClick('open')" title="Filter: Open now">
      <div class="stat-num cg">${open}</div>
      <div class="stat-lbl">Open Now</div>
      <div class="stat-hint">Click to filter</div>
    </div>
    <div class="stat-card sc-rolling ${F.st.has('rolling')?'sc-active':''}" onclick="statClick('rolling')" title="Filter: Rolling">
      <div class="stat-num cb">${rolling}</div>
      <div class="stat-lbl">Rolling</div>
      <div class="stat-hint">Click to filter</div>
    </div>
    <div class="stat-card sc-watch ${F.st.has('watch')?'sc-active':''}" onclick="statClick('watch')" title="Filter: Watch / prep">
      <div class="stat-num ca">${watch}</div>
      <div class="stat-lbl">Watch / Prep</div>
      <div class="stat-hint">Click to filter</div>
    </div>
    <div class="stat-card sc-fit ${fitActive}" onclick="fitClick()" title="Filter: High-fit programs only">
      <div class="stat-num cgo">${highFit}</div>
      <div class="stat-lbl">★★★★+ Fit</div>
      <div class="stat-hint">Click to filter</div>
    </div>`;

  // Phase 10: sync sort arrows on the table headers
  document.querySelectorAll('.th.sortable').forEach(th => {
    const key = th.getAttribute('data-sort-key');
    const arrow = th.querySelector('.th-arrow');
    if(key === F.sortKey){
      th.classList.add('sorted');
      if(arrow) arrow.textContent = F.sortDir === 'asc' ? '▲' : '▼';
    } else {
      th.classList.remove('sorted');
      if(arrow) arrow.textContent = '▼';
    }
  });

  // Mobile card view (uses same filtered+sorted list as the desktop table)
  const cards = document.getElementById('prog-cards');
  const table = document.getElementById('prog-table');
  if (cards) {
    if (window.innerWidth <= 768) {
      table.style.display = 'none';
      cards.style.display = 'flex';
      cards.innerHTML = list.map(p => `
        <div class="prog-card">
          <div class="prog-card-title">${p.name}</div>
          <div class="prog-card-org">${p.org}${p.visa?' <span style="color:var(--accent);font-size:11px;">✓ Visa</span>':''}</div>
          <div class="prog-card-meta">
            <span>📍 ${p.loc}</span>
            <span>⏰ ${p.dlnote||p.deadline||'Rolling'}</span>
          </div>
          <div class="prog-card-tags">${(p.tags||[]).map(t=>`<span class="tag">${t}</span>`).join('')}</div>
          <div class="prog-card-actions">
            <button onclick="window.open('${p.url}','_blank')">Apply →</button>
            <button onclick="openM('prog',${p.id})">Edit</button>
          </div>
        </div>`).join('');
    } else {
      table.style.display = '';
      cards.style.display = 'none';
    }
  }

}

// ═══════════════ ALUMNI TAB — SCHOOL DROPDOWN + TABLE ═══════════════
let activeAlumniSchool = null;

function initAlumniSchoolDrop(){
  // Set default from profile
  if(!activeAlumniSchool && userProfile?.schools?.length){
    activeAlumniSchool = userProfile.schools[0];
  }
  updateAlumniSchoolDisplay();
  renderAlumniSchoolOpts('');
}

function updateAlumniSchoolDisplay(){
  const el = document.getElementById('alumni-school-display');
  if(!el) return;
  el.textContent = activeAlumniSchool ? (SCHOOL_LABELS[activeAlumniSchool]||activeAlumniSchool) : 'Select your school';
  el.style.color = activeAlumniSchool ? 'var(--text)' : 'var(--text3)';
}

function toggleAlumniSchoolDrop(){
  const drop = document.getElementById('alumni-school-drop');
  if(!drop) return;
  const open = drop.style.display !== 'none';
  drop.style.display = open ? 'none' : 'block';
  if(!open){
    const fi = document.getElementById('alumni-school-filter');
    if(fi){ fi.value=''; renderAlumniSchoolOpts(''); fi.focus(); }
  }
}

function filterAlumniSchoolDrop(){
  const q = (document.getElementById('alumni-school-filter')||{}).value||'';
  renderAlumniSchoolOpts(q);
}

function renderAlumniSchoolOpts(q){
  const container = document.getElementById('alumni-school-opts');
  if(!container) return;
  const filtered = ALL_MBA_SCHOOLS.filter(s => !q || s.label.toLowerCase().includes(q.toLowerCase()));
  container.innerHTML = filtered.map(s => `
    <div onclick="pickAlumniSchool('${s.key}')" style="padding:9px 14px;font-size:12px;cursor:pointer;color:${activeAlumniSchool===s.key?'var(--accent)':'var(--text)'};background:${activeAlumniSchool===s.key?'var(--accent-bg)':'transparent'};border-bottom:1px solid var(--border);transition:background .1s"
      onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background='${activeAlumniSchool===s.key?'var(--accent-bg)':'transparent'}'">
      ${s.label}${activeAlumniSchool===s.key?' ✓':''}
    </div>`).join('');
}

async function pickAlumniSchool(key){
  // Single selection — clicking the same school deselects, clicking another switches
  activeAlumniSchool = (activeAlumniSchool === key) ? null : key;
  document.getElementById('alumni-school-drop').style.display = 'none';
  updateAlumniSchoolDisplay();
  renderAlumniSearch();
  // Persist to profile so next session remembers it
  if(currentUser && activeAlumniSchool){
    const schoolObj = ALL_MBA_SCHOOLS.find(s=>s.key===activeAlumniSchool);
    await saveUserProfile({
      school_key: activeAlumniSchool,
      school_label: schoolObj?.label || activeAlumniSchool
    });
  }
}

// Close dropdown when clicking outside
document.addEventListener('click', e => {
  const wrap = document.getElementById('alumni-school-wrap');
  if(wrap && !wrap.contains(e.target)){
    const drop = document.getElementById('alumni-school-drop');
    if(drop) drop.style.display = 'none';
  }
});

// Legacy — kept so init calls don't break
function renderSchoolPills(){ initAlumniSchoolDrop(); }
function setAlumniSchool(school){ pickAlumniSchool(school); }

// ═══ PHASE 11: ALUMNI FINDER — sidebar filters + card-based feed ═══

// Sector multi-select state. Empty Set = no filter (show all).
let _alumniSectors = new Set();

// All sectors that appear in our DP[] data, with display labels.
const ALUMNI_SECTORS = [
  {key:'tech',       label:'Tech & Innovation'},
  {key:'finance',    label:'Finance'},
  {key:'consulting', label:'Consulting'},
  {key:'consumer',   label:'Consumer & Retail'},
  {key:'healthcare', label:'Healthcare'},
  {key:'industrial', label:'Industrial'},
  {key:'logistics',  label:'Logistics'},
  {key:'energy',     label:'Energy'},
  {key:'sovereign',  label:'Sovereign / Public'},
];

function renderAlumniSectorList(){
  const el = document.getElementById('al-sector-list');
  if(!el) return;
  el.innerHTML = ALUMNI_SECTORS.map(s => {
    const isOn = _alumniSectors.has(s.key);
    return `<div class="al-sector-row ${isOn?'on':''}" onclick="toggleAlumniSector('${s.key}')" data-sector="${s.key}">
      <span class="al-sector-check">${isOn?'✓':''}</span>
      <span>${s.label}</span>
    </div>`;
  }).join('');
}

function toggleAlumniSector(sector){
  if(_alumniSectors.has(sector)) _alumniSectors.delete(sector);
  else                            _alumniSectors.add(sector);
  renderAlumniSectorList();
  renderAlumniSearch();
}

// Check if a program is already in the user's pipeline (apps[]).
// Match by program_id (preferred) OR by case-insensitive name (fallback for legacy apps).
function _findAppForProgram(p){
  if(!p) return null;
  return apps.find(a =>
    (a.program_id && a.program_id === p.id) ||
    ((a.name||'').toLowerCase().trim() === (p.name||'').toLowerCase().trim() &&
     (a.org ||'').toLowerCase().trim() === (p.org ||'').toLowerCase().trim())
  );
}

// Add a tracked program to My Applications. Stage defaults to 'networking'
// (the Alumni Finder use case). The AI Fit Scan passes 'shortlisted' instead.
async function addProgramToApplications(progId, stage){
  stage = stage || 'networking';
  const p = progs.find(x => x.id === progId);
  if(!p){ toast('Program not found'); return; }
  const existing = _findAppForProgram(p);
  if(existing){
    toast(`Already in your pipeline (${existing.status})`);
    return;
  }
  const geoLabel = ({europe:'Europe', uae:'UAE / Gulf', global:'Global'})[p.geo] || p.geo || '';
  // Sensible default next-step tailored to where the app starts
  const nextByStage = {
    shortlisted: 'Decide whether to pursue — research alumni',
    networking:  'Find alumni and reach out'
  };
  const a = {
    id: null,
    _db: false,
    program_id: p.id,
    name: p.name,
    org: p.org,
    geo: geoLabel,
    status: stage,
    date: new Date().toISOString().split('T')[0],
    deadline: p.deadline || '',
    next: nextByStage[stage] || '',
    contact: '',
    notes: ''
  };
  const newId = await saveApplicationToDB(a);
  if(!newId){ toast('Could not save — please try again'); return; }
  a.id = newId; a._db = true;
  apps.unshift(a);
  if(typeof renderApplications === 'function') renderApplications();
  if(typeof renderProgressStrip === 'function') renderProgressStrip();
  renderAlumniSearch();   // re-render so the button flips to "✓ In Applications"
  if(typeof renderPrograms === 'function') renderPrograms();  // Phase 14: refresh Programs Pipeline column
  const stageLabel = stage.charAt(0).toUpperCase() + stage.slice(1);
  toast(`✓ ${p.org} added to Applications (${stageLabel})`);
}

function renderAlumniSearch(){
  const container = document.getElementById('alumni-search-rows');
  if(!container) return;
  const q = (document.getElementById('alumni-prog-search')||{}).value?.toLowerCase()||'';
  const school = activeAlumniSchool;
  const slug = school ? SCHOOL_LI_IDS[school] : null;
  const schoolLabel = school ? (SCHOOL_LABELS[school]||school) : null;
  const schoolShort = schoolLabel ? schoolLabel.split(' ')[0].replace(/[(),]/g,'') : null;

  const filtered = progs.filter(p => {
    // Sidebar sector filter (multi-select)
    if(_alumniSectors.size > 0 && !_alumniSectors.has(p.sector)) return false;
    // Search box filter
    if(!q) return true;
    return p.name.toLowerCase().includes(q) ||
      p.org.toLowerCase().includes(q) ||
      (p.fn||'').includes(q) ||
      (p.sector||'').includes(q) ||
      (p.loc||'').toLowerCase().includes(q) ||
      (p.tags||[]).some(t=>t.toLowerCase().includes(q));
  });

  // Update count in header
  const countEl = document.getElementById('alumni-count');
  if(countEl){
    const schoolBit = schoolShort ? ` · ${schoolShort}` : '';
    countEl.textContent = filtered.length === progs.length
      ? `${progs.length} programs${schoolBit}`
      : `${filtered.length} of ${progs.length} programs${schoolBit}`;
  }

  if(!filtered.length){
    container.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">🔍</div>
      <div class="empty-state-title">No programs match</div>
      <div class="empty-state-body">Try clearing sector filters or broadening the search.</div>
    </div>`;
    return;
  }

  const STATUS_MAP = {open:['s-open','OPEN'], rolling:['s-rolling','ROLLING'], watch:['s-watch','OPENING SOON'], closed:['s-closed','CLOSED']};

  container.innerHTML = `<div style="display:flex;flex-direction:column;gap:10px">${filtered.map(p => {
    const orgEnc = encodeURIComponent(p.org);
    const schoolEnc = schoolLabel ? encodeURIComponent(schoolLabel) : '';
    const schoolShortEnc = schoolShort ? encodeURIComponent(schoolShort) : '';

    // ─── Two LinkedIn searches (Phase 11 spec: role search dropped) ───
    // Search A (company-side angle): broad people search with both keywords.
    //   Approximates "company page → employees → filter by school".
    //   We can't link directly to a company /people/ tab because we don't have LinkedIn company slugs.
    // Search B (school-side angle): school's verified alumni page filtered by company keyword.
    let searchChips = '';
    if(slug){
      const schoolToCompanyUrl = `https://www.linkedin.com/school/${slug}/people/?keywords=${orgEnc}`;
      const companySideUrl     = `https://www.linkedin.com/search/results/people/?keywords=${schoolShortEnc}%20${orgEnc}`;
      searchChips = `
        <a href="${schoolToCompanyUrl}" target="_blank" rel="noopener noreferrer" class="al-mini-chip school" title="Open ${schoolLabel}'s alumni page filtered for ${p.org}">
          <span class="al-mini-chip-star">★</span><span>${schoolShort} alumni at ${p.org}</span><span class="al-mini-chip-arrow">↗</span>
        </a>
        <a href="${companySideUrl}" target="_blank" rel="noopener noreferrer" class="al-mini-chip school" title="LinkedIn people search for ${p.org} employees mentioning ${schoolShort}">
          <span class="al-mini-chip-star">★</span><span>${p.org} people from ${schoolShort}</span><span class="al-mini-chip-arrow">↗</span>
        </a>`;
    } else {
      const broadUrl = `https://www.linkedin.com/search/results/people/?keywords=${orgEnc}`;
      searchChips = `
        <a href="${broadUrl}" target="_blank" rel="noopener noreferrer" class="al-mini-chip" title="Broad LinkedIn search">
          <span>Anyone at ${p.org}</span><span class="al-mini-chip-arrow">↗</span>
        </a>
        <span class="al-card-empty-school">Pick your school in the sidebar to unlock alumni-filtered searches</span>`;
    }

    // ─── Two action buttons ───
    // Primary: Draft Message → existing openConnectMessage modal (requires school)
    // Secondary: Add to Applications → addProgramToApplications (works with or without school)
    const draftBtn = slug
      ? `<button class="al-btn-primary" onclick='openConnectMessage(${JSON.stringify({org:p.org, role:p.name, prog:p.name, school:schoolLabel}).replace(/'/g,"&#39;")})'>📋 Draft Message</button>`
      : `<button class="al-btn-primary" disabled title="Pick your school in the sidebar first">📋 Draft Message</button>`;

    const existingApp = _findAppForProgram(p);
    const addBtn = existingApp
      ? `<button class="al-btn-secondary added" disabled title="Already in your pipeline as ${existingApp.status}">✓ In Applications</button>`
      : `<button class="al-btn-secondary" onclick="addProgramToApplications(${p.id}, 'networking')">+ Add to Networking</button>`;

    // Status pill
    const [statusCls, statusLbl] = STATUS_MAP[p.status] || ['s-closed','—'];

    // Logo block — org initial (since we don't have actual logos)
    const initial = (p.org||'?').charAt(0).toUpperCase();

    // Tags row
    const dlText = p.deadline
      ? `<span><strong>Deadline:</strong> ${new Date(p.deadline).toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'})}</span>`
      : (p.dlnote ? `<span><strong>Deadline:</strong> ${p.dlnote}</span>` : '');

    return `<div class="al-card">
      <div class="al-card-logo">${initial}</div>
      <div class="al-card-body">
        <div class="al-card-row1">
          <div class="al-card-title">${p.url?`<a href="${p.url}" target="_blank" rel="noopener noreferrer">${p.name}</a>`:p.name}</div>
          <span class="al-card-status ${statusCls}">${statusLbl}</span>
        </div>
        <div class="al-card-meta">${p.org} · ${p.loc || p.geo || ''}</div>
        <div class="al-card-tags">
          <span><strong>Type:</strong> ${cap(p.fn)} · ${cap(p.sector)}</span>
          ${dlText}
        </div>
        <div class="al-card-search-row">${searchChips}</div>
      </div>
      <div class="al-card-actions">
        ${draftBtn}
        ${addBtn}
      </div>
    </div>`;
  }).join('')}</div>`;
}

// ─── Connection request template modal ───────────────────────────
function openConnectMessage(ctx){
  // ctx = { org, role, prog, school }
  const userName = (userProfile?.full_name) || '{Your name}';
  const userSchool = ctx.school || '{Your school}';

  // Build 3 message variants — different angles, all ≤300 chars for LinkedIn connect note
  const v1 = `Hi {Their first name}, I'm ${userName}, an MBA at ${userSchool}. I'm exploring the ${ctx.prog} for next year and noticed your path into ${ctx.org}. Would you have 20 minutes for a quick call? I'd love to learn what made the difference for you. Thanks!`;
  const v2 = `Hi {Their first name}, fellow ${userSchool} {if alumni, else: an MBA from ${userSchool}}. I'm researching ${ctx.org}'s ${ctx.role || ctx.prog} and your background looks like exactly the path I'm hoping for. Open to a 15-min call? Any insight on the application process would mean a lot.`;
  const v3 = `Hi {Their first name}, I'm an ${userSchool} MBA preparing to apply to ${ctx.prog}. Coming from {your background — e.g. PE healthcare}, I'd value your honest take on the role fit. Could we connect for 20 minutes when convenient? Happy to work around your schedule.`;

  const trim = s => s.length > 300 ? s.substring(0, 297) + '...' : s;
  const html = `
    <div class="overlay open" id="ov-connect" style="z-index:9000" onclick="if(event.target===this) this.remove()">
      <div class="modal" style="max-width:580px;width:92vw">
        <button class="mclose" onclick="document.getElementById('ov-connect').remove()">×</button>
        <div class="mtitle">LinkedIn connection request — ${ctx.org}</div>
        <div style="font-size:12px;color:var(--text2);margin:-6px 0 16px;line-height:1.6">
          LinkedIn limits connection notes to <strong>300 characters</strong>. Pick a variant, edit the {placeholders} for the specific person, then send.
        </div>
        ${[{label:'① Curious & humble',msg:v1},{label:'② Shared-school angle',msg:v2},{label:'③ Background-led',msg:v3}].map((opt,i)=>{
          const msg = trim(opt.msg);
          const safe = msg.replace(/'/g,"\\'").replace(/"/g,'&quot;');
          return `
          <div style="background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:10px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
              <div style="font-size:12px;font-weight:600;color:var(--accent)">${opt.label}</div>
              <div style="font-size:10px;color:var(--text3);font-family:var(--mono)">${msg.length}/300 chars</div>
            </div>
            <textarea id="connect-msg-${i}" style="width:100%;min-height:96px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px;font-size:12px;font-family:var(--sans);color:var(--text);line-height:1.55;resize:vertical;outline:none">${msg}</textarea>
            <div style="display:flex;gap:8px;margin-top:8px">
              <button onclick="copyConnectMsg(${i})" class="li-btn" style="font-size:11px;padding:6px 14px;cursor:pointer">📋 Copy to clipboard</button>
              <button onclick="openLinkedInSchoolSearch('${(ctx.org||'').replace(/'/g,"\\'")}')" class="gbtn" style="font-size:11px;padding:6px 14px;cursor:pointer">Open LinkedIn search ↗</button>
            </div>
          </div>`;
        }).join('')}
        <div style="font-size:11px;color:var(--text3);margin-top:12px;line-height:1.6">
          <strong style="color:var(--text2)">Tip:</strong> Always personalize {Their first name} and any other placeholder. Generic copy-paste hurts your reply rate. Aim to send within 60 seconds of reading their profile so the message feels intentional, not bulk.
        </div>
      </div>
    </div>`;
  // Remove any prior modal
  const existing = document.getElementById('ov-connect');
  if(existing) existing.remove();
  document.body.insertAdjacentHTML('beforeend', html);
}

async function copyConnectMsg(idx){
  const el = document.getElementById('connect-msg-'+idx);
  if(!el) return;
  try {
    await navigator.clipboard.writeText(el.value);
    toast('✓ Message copied — paste it into the LinkedIn connect note');
  } catch {
    // Fallback for older browsers
    el.select(); document.execCommand('copy');
    toast('✓ Message copied');
  }
}

function openLinkedInSchoolSearch(org){
  const slug = activeAlumniSchool ? SCHOOL_LI_IDS[activeAlumniSchool] : null;
  const url = slug
    ? `https://www.linkedin.com/school/${slug}/people/?keywords=${encodeURIComponent(org)}`
    : `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(org)}`;
  window.open(url, '_blank', 'noopener,noreferrer');
}

// renderAlumni — no-op, contact tracking moved to My Applications
function renderAlumni(){ }

// ═══════════════ APPLICATIONS ═══════════════

// ─── PHASE 8: KANBAN DRAG-AND-DROP ───
// Desktop-only drag-drop to move cards between stages. Mobile users still tap-to-edit.
// Optimistic UI: status updates locally first, persists to Supabase, reverts on failure.
let _draggingAppId = null;
let _dropInFlight  = false;

function dragAppStart(e, appId){
  _draggingAppId = appId;
  e.currentTarget.classList.add('dragging');
  if(e.dataTransfer){
    e.dataTransfer.effectAllowed = 'move';
    // Firefox requires setData() to initiate the drag
    try { e.dataTransfer.setData('text/plain', String(appId)); } catch {}
  }
}

function dragAppEnd(e){
  e.currentTarget.classList.remove('dragging');
  document.querySelectorAll('.kcol.drag-over').forEach(c => c.classList.remove('drag-over'));
  _draggingAppId = null;
}

function dragColOver(e){
  if(!_draggingAppId) return;
  e.preventDefault();                          // required to enable drop
  if(e.dataTransfer) e.dataTransfer.dropEffect = 'move';
  e.currentTarget.classList.add('drag-over');
}

function dragColLeave(e){
  // Only remove highlight if leaving the column itself, not crossing into a child element
  if(!e.currentTarget.contains(e.relatedTarget)){
    e.currentTarget.classList.remove('drag-over');
  }
}

async function dropApp(e, stage){
  e.preventDefault();
  e.currentTarget.classList.remove('drag-over');
  if(_dropInFlight || _draggingAppId == null) return;
  const appId = _draggingAppId;
  const app = apps.find(a => String(a.id) === String(appId));
  if(!app)                  return;            // ghost drag — ignore
  if(app.status === stage)  return;            // dropped on same column — no-op
  _dropInFlight = true;
  const prevStatus = app.status;
  app.status = stage;
  renderApplications();                        // optimistic UI update
  try {
    const newId = await saveApplicationToDB(app);
    if(!newId){ throw new Error('save failed'); }
    toast(`Moved to ${stage.charAt(0).toUpperCase()+stage.slice(1)}`);
  } catch(err){
    console.error('drop persist failed:', err);
    app.status = prevStatus;                   // revert in-memory state
    renderApplications();
    toast('Could not save — change reverted');
  } finally {
    _dropInFlight = false;
  }
}

function renderApplications(){
  const q=(document.getElementById('app-search')||{}).value?.toLowerCase()||'';
  const fa=apps.filter(a=>!q||a.name.toLowerCase().includes(q)||(a.org||'').toLowerCase().includes(q));
  const act=apps.filter(a=>!['offer','rejected'].includes(a.status)).length;
  document.getElementById('app-sub').textContent=`${act} active · ${apps.length} total tracked`;

  // Phase 9: first-time empty state — no applications at all yet
  if(apps.length === 0){
    document.getElementById('app-kanban').innerHTML = `
      <div class="empty-state" style="grid-column:1 / -1">
        <div class="empty-state-icon">📋</div>
        <div class="empty-state-title">No applications yet</div>
        <div class="empty-state-body">
          Track each LDP you're pursuing here. Pick a program from the Programs tab,
          shortlist one from the AI Fit Scan, or log one manually with the button below.
          Drag cards as you progress: Shortlisted → Networking → Drafting → Applied → Interview → Offer.
        </div>
        <button class="empty-state-cta" onclick="openM('app')">+ Log your first application</button>
        <div><button class="empty-state-secondary" onclick="showPage('programs')">Browse the 48 programs first →</button></div>
      </div>`;
    return;
  }

  const stages=[
    {key:'shortlisted',label:'Shortlisted',  color:'var(--gold)'},
    {key:'networking',label:'Networking',   color:'var(--blue)'},
    {key:'drafting',  label:'Drafting',     color:'var(--purple)'},
    {key:'applied',   label:'Applied',      color:'var(--amber)'},
    {key:'interview', label:'Interview 🎤', color:'var(--accent)'},
    {key:'offer',     label:'Offer 🎉',     color:'var(--teal)'},
    {key:'rejected',  label:'Rejected',     color:'var(--text3)'}
  ];
  document.getElementById('app-kanban').innerHTML=stages.map(s=>{
    const cards=fa.filter(a=>a.status===s.key);
    // Phase 9: compute today once for the days-until-deadline badges in this column
    const _today = new Date(); _today.setHours(0,0,0,0);
    return `<div class="kcol" data-stage="${s.key}" ondragover="dragColOver(event)" ondragleave="dragColLeave(event)" ondrop="dropApp(event,'${s.key}')">
      <div class="khd" style="color:${s.color}">${s.label}<span class="kct">${cards.length}</span></div>
      ${cards.length===0?`<div style="font-size:11px;color:var(--text3);text-align:center;padding-top:14px;padding-bottom:8px">—</div>`:''}
      ${cards.map(a=>{
        // Build the days-until-deadline badge (Phase 9)
        let daysBadge = '';
        if(a.deadline){
          const dl = new Date(a.deadline); dl.setHours(0,0,0,0);
          const days = Math.round((dl - _today)/86400000);
          let cls, lbl;
          if(days < 0)        { cls='past'; lbl = Math.abs(days)+'d ago'; }
          else if(days === 0) { cls='urg';  lbl = 'Today!'; }
          else if(days === 1) { cls='urg';  lbl = '1 day left'; }
          else if(days <= 7)  { cls='urg';  lbl = days+' days left'; }
          else if(days <= 30) { cls='soon'; lbl = days+' days left'; }
          else                { cls='ok';   lbl = days+' days left'; }
          daysBadge = `<div class="apdays ${cls}">${lbl}</div>`;
        }
        return `<div class="apcard" draggable="true" data-app-id="${a.id}"
            ondragstart="dragAppStart(event,'${String(a.id).replace(/'/g,"\\'")}')"
            ondragend="dragAppEnd(event)"
            onclick="editAp('${String(a.id).replace(/'/g,"\\'")}')">
          <div class="apct">${a.name}</div>
          <div class="apco">${a.org||''}${a.geo?' · '+a.geo:''}</div>
          ${a.next?`<div class="apnx">→ ${a.next}</div>`:''}
          ${a.contact?`<div style="font-size:10px;color:var(--text3);margin-top:4px">👤 ${a.contact}</div>`:''}
          ${a.deadline?`<div class="apdl">Due: ${new Date(a.deadline).toLocaleDateString('en-GB',{day:'numeric',month:'short'})}</div>`:''}
          ${daysBadge}
        </div>`;
      }).join('')}
      <div class="kcol-drop-hint">Drop here to move to <strong>${s.label}</strong></div>
    </div>`;
  }).join('');
}

// ═══════════════ DEADLINES ═══════════════
// ─── PHASE 5: DEADLINES PLANNING HUB ───
// Builds a unified item list from progs (canonical) + apps (free-standing only).
// Each item carries metadata: rolling, inPipeline, appStatus, dlnote.
// Render path: buildDeadlineItems → filter by scope → renderDLTimeline + buckets.

// Universal "My Pipeline" filter — shared state across Programs and Deadlines pages.
// Kanban (Applications page) is NOT affected — it always shows pipeline by definition.
// State is persisted to localStorage so the filter survives reloads and tab switches.
let _pipelineFilter = false;   // false = show All, true = show only items in user's pipeline

// Restore from localStorage on script load (safe: localStorage already exists in browser)
try { _pipelineFilter = localStorage.getItem('ldp_pipeline_filter_v1') === '1'; } catch(e){ _pipelineFilter = false; }

function togglePipelineFilter(){
  _pipelineFilter = !_pipelineFilter;
  try { localStorage.setItem('ldp_pipeline_filter_v1', _pipelineFilter ? '1' : '0'); } catch(e){}
  _syncPipelineToggleUI();
  // Re-render whichever page is currently active. The other page re-syncs on its next render.
  const active = document.querySelector('.page.active');
  if(active?.id === 'page-programs')  renderPrograms();
  if(active?.id === 'page-deadlines') renderDeadlines();
}

// Keep every .pipeline-toggle button in lockstep (called from toggle + render funcs)
function _syncPipelineToggleUI(){
  document.querySelectorAll('.pipeline-toggle').forEach(b => {
    b.classList.toggle('on', _pipelineFilter);
    b.textContent = _pipelineFilter ? '✓ My Pipeline' : 'My Pipeline';
  });
}

function buildDeadlineItems(){
  const items = [];
  const matchedAppIds = new Set();

  // 1. Canonical: programs (with or without a fixed deadline)
  for(const p of progs){
    const hasDate   = !!p.deadline;
    const isRolling = !hasDate && (p.status === 'rolling' || /rolling/i.test(p.dlnote || ''));
    if(!hasDate && !isRolling) continue;   // no deadline info at all

    const pname = (p.name || '').toLowerCase().trim();
    const app = apps.find(a =>
      (a.program_id && a.program_id === p.id) ||
      (a.name && pname && a.name.toLowerCase().trim() === pname)
    );
    if(app) matchedAppIds.add(app.id);

    items.push({
      name: p.name,
      org:  p.org || '',
      date: hasDate ? new Date(p.deadline) : null,
      deadline: p.deadline || '',
      type: 'program',
      rolling: isRolling,
      inPipeline: !!app,
      appStatus: app ? app.status : null,
      dlnote: p.dlnote || ''
    });
  }

  // 2. Free-standing applications (not linked back to any program)
  for(const a of apps){
    if(matchedAppIds.has(a.id)) continue;
    if(!a.deadline) continue;
    items.push({
      name: a.name,
      org:  a.org || '',
      date: new Date(a.deadline),
      deadline: a.deadline,
      type: 'application',
      rolling: false,
      inPipeline: true,
      appStatus: a.status,
      dlnote: ''
    });
  }

  return items;
}

function nudgeFor(item){
  const days = item._days;  // set by bucketize for dated items
  if(!item.inPipeline && !item.rolling){
    return {tone:'info', text:'Not in your pipeline — add to Applications'};
  }
  if(item.rolling && !item.inPipeline){
    return {tone:'warn', text:'Rolling — apply ASAP, no fixed deadline'};
  }
  if(item.appStatus === 'networking' && typeof days === 'number' && days <= 30 && days >= 0){
    return {tone:'warn', text:'Apply this week — networking time is up'};
  }
  if(item.appStatus === 'applied' && typeof days === 'number' && days < 0){
    return {tone:'info', text:'Deadline passed — follow up?'};
  }
  return null;
}

function bucketize(items){
  const today = new Date(); today.setHours(0,0,0,0);
  const buckets = {rolling:[], week:[], month:[], next60:[], later:[]};
  for(const it of items){
    if(it.rolling){ buckets.rolling.push(it); continue; }
    if(!it.date) continue;
    const days = Math.round((it.date - today) / 86400000);
    it._days = days;
    if(days < 0)        buckets.week.push(it);    // past-due (already filtered to applied-in-pipeline upstream)
    else if(days <= 7)  buckets.week.push(it);
    else if(days <= 30) buckets.month.push(it);
    else if(days <= 60) buckets.next60.push(it);
    else                buckets.later.push(it);
  }
  ['week','month','next60','later'].forEach(k => buckets[k].sort((a,b) => a.date - b.date));
  buckets.rolling.sort((a,b) => (a.name||'').localeCompare(b.name||''));
  return buckets;
}

function _dayLabel(days){
  if(days === 0)  return 'TODAY!';
  if(days === 1)  return '1 day';
  if(days === -1) return '1 day ago';
  if(days < 0)    return `${Math.abs(days)} days ago`;
  return `${days} days`;
}
function _dayClass(days){
  if(days < 0)      return 'urg';
  if(days <= 14)    return 'urg';
  if(days <= 45)    return 'soon';
  return 'ok';
}
function _fmtDate(d){
  return d.toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'});
}

function _icsPayload(item){
  // Build a clean payload for openICSModal — date-only items use the deadline string,
  // rolling items have no calendar payload (button suppressed for those).
  return {name:item.name, org:item.org, deadline:item.deadline, type:item.type};
}

function _renderRow(item){
  const days  = item._days;
  const cls   = (typeof days === 'number') ? _dayClass(days) : '';
  const lbl   = (typeof days === 'number') ? _dayLabel(days) : '—';
  const dateLabel = item.rolling
    ? 'Rolling'
    : (item.date ? _fmtDate(item.date) : '—');
  const nudge = nudgeFor(item);
  const nudgeHtml = nudge
    ? `<div class="dl-nudge dl-nudge-${nudge.tone}">${nudge.text}</div>`
    : '';
  const actionsHtml = item.rolling
    ? `<span style="font-size:10px;color:var(--text3)">${(item.dlnote||'').replace(/</g,'&lt;') || 'No fixed date'}</span>`
    : `<button class="ics-btn" onclick='openICSModal(${JSON.stringify(_icsPayload(item)).replace(/'/g,"&#39;")})' title="Add to calendar">📅 Set reminder</button>`;

  return `<div class="dlitem">
    <div class="dldate">${dateLabel}</div>
    <div style="flex:1;min-width:0">
      <div class="dlname">${item.name}</div>
      <div class="dlorg">${item.org}</div>
      ${nudgeHtml}
    </div>
    <div class="dldays ${cls}">${lbl}</div>
    <div class="dlitem-actions">${actionsHtml}</div>
  </div>`;
}

function _renderBucket({key, label, items, open}){
  const count = items.length;
  if(count === 0) return '';
  const rows = items.map(_renderRow).join('');
  return `<details class="dl-bucket" data-bucket="${key}"${open ? ' open' : ''}>
    <summary>${label}<span class="dl-bucket-count">${count}</span></summary>
    <div class="dl-bucket-rows">${rows}</div>
  </details>`;
}

function renderDLTimeline(items){
  const container = document.getElementById('dl-timeline');
  if(!container) return;
  const today = new Date(); today.setHours(0,0,0,0);

  const dated = items
    .filter(i => !i.rolling && i.date)
    .map(i => {
      const days = (typeof i._days === 'number') ? i._days : Math.round((i.date - today)/86400000);
      return {...i, _days: days};
    })
    .filter(i => i._days >= 0 && i._days <= 90);

  const axis = `<div class="dl-tl-axis">
    <span class="dl-tl-tick">Today</span>
    <span class="dl-tl-tick">+30d</span>
    <span class="dl-tl-tick">+60d</span>
    <span class="dl-tl-tick">+90d</span>
  </div>`;

  if(dated.length === 0){
    container.innerHTML = `<div class="dl-tl-empty">No deadlines in the next 90 days.</div>${axis}`;
    return;
  }

  const markers = dated.map(i => {
    const pct = Math.max(0, Math.min(100, (i._days / 90) * 100));
    const color = i._days <= 7  ? 'var(--coral)'
                : i._days <= 30 ? 'var(--amber)'
                : i._days <= 60 ? 'var(--gold)'
                : 'var(--accent)';
    const safe = (i.name || '').replace(/"/g,'&quot;');
    return `<div class="dl-tl-marker" style="left:${pct.toFixed(1)}%;background:${color}" title="${safe} — ${i._days}d"></div>`;
  }).join('');

  container.innerHTML = `<div class="dl-tl-track">${markers}</div>${axis}`;
}

function renderDeadlines(){
  _syncPipelineToggleUI();   // keep the Deadlines pill in lockstep with shared state
  let items = buildDeadlineItems();

  // Scope filter — shared with the Programs tab
  if(_pipelineFilter){
    items = items.filter(i => i.inPipeline);
  }

  // Drop past-due noise (keep past-due ONLY for applied items in the pipeline → follow-up nudge)
  const today = new Date(); today.setHours(0,0,0,0);
  items = items.filter(i => {
    if(i.rolling) return true;
    if(!i.date) return false;
    if(i.date >= today) return true;
    return i.inPipeline && i.appStatus === 'applied';
  });

  // Bucketize (also stamps _days on each dated item)
  const b = bucketize(items);

  // Timeline (90-day strip)
  renderDLTimeline(items);

  // Empty state across the board?
  const totalRows = b.rolling.length + b.week.length + b.month.length + b.next60.length + b.later.length;
  const bucketsEl = document.getElementById('dl-buckets');
  if(!bucketsEl) return;

  if(totalRows === 0){
    bucketsEl.innerHTML = `<div class="empty">${_pipelineFilter
      ? 'No deadlines tied to your pipeline yet. Add deadlines on the Applications tab, or turn off <strong>My Pipeline</strong> to see every tracked deadline.'
      : 'No upcoming deadlines tracked. Add deadline dates on the Programs tab.'}</div>`;
    return;
  }

  bucketsEl.innerHTML = [
    _renderBucket({key:'week',    label:'This week (≤7 days)',         items:b.week,    open:true}),
    _renderBucket({key:'month',   label:'This month (8–30 days)',      items:b.month,   open:true}),
    _renderBucket({key:'next60',  label:'Next 60 days (31–60 days)',   items:b.next60,  open:true}),
    _renderBucket({key:'rolling', label:'Rolling — no fixed deadline', items:b.rolling, open:true}),
    _renderBucket({key:'later',   label:'Later (60+ days out)',        items:b.later,   open:false})
  ].join('');
}

// Phase 14: pipeline-only export (the original exportAllDeadlines is kept
// because some internal callers still use it, but the UI button only fires
// this wrapper now — nobody actually wants to bulk-export all 48 LDPs).
function exportMyPipelineDeadlines(){
  const prev = _pipelineFilter;
  _pipelineFilter = true;
  try {
    exportAllDeadlines();
  } finally {
    _pipelineFilter = prev;
  }
}

function exportAllDeadlines(){
  let items = buildDeadlineItems();
  if(_pipelineFilter) items = items.filter(i => i.inPipeline);

  // Bulk export covers only DATED, future items (calendar entries need a date)
  const today = new Date(); today.setHours(0,0,0,0);
  const dated = items.filter(i => !i.rolling && i.date && i.date >= today);

  if(dated.length === 0){
    if(_pipelineFilter){
      toast('Nothing dated in your pipeline yet — log an application with a deadline first, or check the Programs tab for rolling deadlines.');
    } else {
      toast('Nothing dated to export — rolling items don\u2019t have a fixed date.');
    }
    return;
  }

  const fmt = d => d.toISOString().replace(/[-:]/g,'').split('.')[0] + 'Z';
  const now = fmt(new Date());
  const todayStr = new Date().toISOString().split('T')[0];

  const sanitize = s => String(s||'').replace(/\\/g,'\\\\').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/\r?\n/g,'\\n');

  const events = dated.map((it, idx) => {
    const dl = new Date(it.deadline);
    const dateStr = dl.toISOString().split('T')[0].replace(/-/g,'');
    const uid = `ldpscout-bulk-${Date.now()}-${idx}@ldpscout.app`;
    const sumName = sanitize(it.name);
    const sumOrg  = sanitize(it.org);
    return [
      'BEGIN:VEVENT',
      `UID:${uid}`,
      `DTSTART;VALUE=DATE:${dateStr}`,
      `DTEND;VALUE=DATE:${dateStr}`,
      `DTSTAMP:${now}`,
      `SUMMARY:DEADLINE: ${sumName} (${sumOrg})`,
      `DESCRIPTION:Application deadline tracked via LDP Scout.`,
      'BEGIN:VALARM','TRIGGER:-P30D','ACTION:DISPLAY',`DESCRIPTION:30 days until ${sumName} deadline`,'END:VALARM',
      'BEGIN:VALARM','TRIGGER:-P7D','ACTION:DISPLAY',`DESCRIPTION:7 days until ${sumName} deadline`,'END:VALARM',
      'BEGIN:VALARM','TRIGGER:-P1D','ACTION:DISPLAY',`DESCRIPTION:Tomorrow: ${sumName} deadline — submit today!`,'END:VALARM',
      'END:VEVENT'
    ].join('\r\n');
  });

  const ics = [
    'BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//LDP Scout//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH',
    ...events,
    'END:VCALENDAR'
  ].join('\r\n');

  const blob = new Blob([ics], {type:'text/calendar;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ldp-deadlines-${todayStr}.ics`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(`📅 Exported ${dated.length} deadline${dated.length===1?'':'s'} — open the file to import into your calendar`);
}

function downloadICS(item, mode='multi'){
  const dl=new Date(item.deadline);
  const fmt=d=>{const s=d.toISOString().replace(/[-:]/g,'').split('.')[0]+'Z';return s;};
  const uid=`ldpscout-${Date.now()}@ldpscout.app`;
  const now=fmt(new Date());
  const dateStr=dl.toISOString().split('T')[0].replace(/-/g,'');

  const alarmMulti=`BEGIN:VALARM\nTRIGGER:-P30D\nACTION:DISPLAY\nDESCRIPTION:30 days until ${item.name} deadline — start your application\nEND:VALARM\nBEGIN:VALARM\nTRIGGER:-P7D\nACTION:DISPLAY\nDESCRIPTION:7 days until ${item.name} deadline — final review\nEND:VALARM\nBEGIN:VALARM\nTRIGGER:-P1D\nACTION:DISPLAY\nDESCRIPTION:Tomorrow: ${item.name} deadline — submit today!\nEND:VALARM`;
  const alarmSingle=`BEGIN:VALARM\nTRIGGER:-P7D\nACTION:DISPLAY\nDESCRIPTION:7 days until: ${item.name} deadline\nEND:VALARM`;
  const alarms=mode==='multi'?alarmMulti:alarmSingle;

  const lines=[
    'BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//LDP Scout//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH',
    'BEGIN:VEVENT',`UID:${uid}`,`DTSTART;VALUE=DATE:${dateStr}`,`DTEND;VALUE=DATE:${dateStr}`,
    `DTSTAMP:${now}`,`SUMMARY:DEADLINE: ${item.name} (${item.org})`,
    `DESCRIPTION:Application deadline tracked via LDP Scout.`,
    ...alarms.split('\n'),
    'END:VEVENT','END:VCALENDAR'
  ];
  const ics=lines.join('\r\n');
  const blob=new Blob([ics],{type:'text/calendar;charset=utf-8'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=`ldp-${item.org.toLowerCase().replace(/\s+/g,'-')}.ics`;
  a.click();
  toast('📅 Calendar file downloaded — open it to import into Google Calendar, Outlook, or Apple Calendar');
}

// ═══════════════ AI FILE PARSING (PDF.js + Mammoth) ═══════════════
async function extractTextFromFile(file){
  const type = file.type;
  const name = file.name.toLowerCase();

  // Plain text
  if(type === 'text/plain' || name.endsWith('.txt')){
    return await file.text();
  }

  // DOCX — via mammoth.js
  if(type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' || name.endsWith('.docx')){
    if(typeof mammoth === 'undefined') throw new Error('DOCX parser not loaded. Please refresh and try again.');
    const arrayBuffer = await file.arrayBuffer();
    const result = await mammoth.extractRawText({arrayBuffer});
    return result.value;
  }

  // PDF — via pdf.js
  if(type === 'application/pdf' || name.endsWith('.pdf')){
    if(typeof pdfjsLib === 'undefined') throw new Error('PDF parser not loaded. Please refresh and try again.');
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.16.105/pdf.worker.min.js';
    const arrayBuffer = await file.arrayBuffer();
    const pdf = await pdfjsLib.getDocument({data: arrayBuffer}).promise;
    let text = '';
    for(let i = 1; i <= pdf.numPages; i++){
      const page = await pdf.getPage(i);
      const content = await page.getTextContent();
      text += content.items.map(item => item.str).join(' ') + '\n';
    }
    return text;
  }

  // Legacy .doc — attempt text extraction fallback
  if(name.endsWith('.doc')){
    throw new Error('Legacy .doc format not supported. Please save as .docx or .pdf and try again.');
  }

  throw new Error('Unsupported file format. Please upload PDF, DOCX, or TXT.');
}

async function handleFileUpload(event){
  const file = event.target.files[0];
  if(!file) return;
  // User is engaged with the page → cancel any pending aifit tour dwell timer.
  // Even if the file fails to parse, picking a file shows intent.
  clearAifitDwell();
  if(file.size > 5*1024*1024){alert('File too large — please use a file under 5MB.');return;}

  const fileDisplay = document.getElementById('aifit-file-display');
  const emptyDisplay = document.getElementById('aifit-empty-display');
  const fileInfo = document.getElementById('aifit-file-info');
  const uploadBox = document.getElementById('aifit-upload-box');
  const analyzeBtn = document.getElementById('analyze-btn');

  // Show loading state
  fileDisplay.style.display = 'block';
  emptyDisplay.style.display = 'none';
  fileInfo.textContent = `⏳ Parsing ${file.name}...`;
  uploadBox.classList.add('has-file');
  analyzeBtn.disabled = true;

  try {
    const text = await extractTextFromFile(file);

    if(!text || text.trim().length < 200){
      throw new Error('Could not extract enough text from this file. Try a different format or check the file is not scanned/image-based.');
    }

    resumeText = text.trim();
    const sizeKB = Math.round(file.size / 1024);
    fileInfo.textContent = `${file.name} · ${sizeKB} KB`;
    analyzeBtn.disabled = false;

    // Persist resume to Supabase (overwrites previous resume for this user)
    if(currentUser){
      saveResumeToDB(resumeText, file.name).then(()=>{
        // Keep the same display — file is ready
      });
    }

  } catch(err){
    alert(err.message);
    // Reset to empty state
    fileDisplay.style.display = 'none';
    emptyDisplay.style.display = 'block';
    uploadBox.classList.remove('has-file');
    analyzeBtn.disabled = true;
  }
}

function clearAIFitFile(event){
  event.stopPropagation();
  document.getElementById('resume-file-input').value = '';
  document.getElementById('aifit-file-display').style.display = 'none';
  document.getElementById('aifit-empty-display').style.display = 'block';
  document.getElementById('aifit-upload-box').classList.remove('has-file');
  document.getElementById('analyze-btn').disabled = true;
  resumeText = '';
}

function pdf_format_label(file){
  const n = file.name.toLowerCase();
  if(n.endsWith('.pdf')) return 'PDF parsed via pdf.js';
  if(n.endsWith('.docx')) return 'DOCX parsed via mammoth.js';
  return 'Text file';
}

// drag and drop
const uzEl=document.getElementById('aifit-upload-box');
if(uzEl){
  uzEl.addEventListener('dragover',e=>{e.preventDefault();uzEl.classList.add('drag');});
  uzEl.addEventListener('dragleave',()=>uzEl.classList.remove('drag'));
  uzEl.addEventListener('drop',e=>{
    e.preventDefault();uzEl.classList.remove('drag');
    const f=e.dataTransfer.files[0];
    if(f) handleFileUpload({target:{files:e.dataTransfer.files}});
  });
}

async function runAIAnalysis(){

  if(!resumeText){alert('Please upload your resume first.');return;}

  // Phase 14: gate the aifit dwell timer for the duration of the scan
  _aifitScanning = true;
  clearAifitDwell();

  // Vercel proxy handles the API key — no key needed in the browser
  const PROXY_URL = 'https://ldp-proxy.vercel.app/api/scan';

  const btn=document.getElementById('analyze-btn');
  btn.disabled=true;btn.textContent='Analysing...';
  // Phase 13: switch to post-scan view so the spinner has a visible container
  document.getElementById('aifit-view-pre').style.display = 'none';
  document.getElementById('aifit-view-post').style.display = 'block';
  document.getElementById('aifit-results-container').innerHTML=`<div class="spin-wrap"><div class="spinner"></div><div class="spin-label">Step 1 of 2: Matching your profile against ${progs.length} programs...</div></div>`;

  // Cap resume at 4000 chars to stay within token budget
  const resumeSnippet = resumeText.substring(0, 4000);

  // Compact program list
  const progSummary = progs.map(p=>`${p.id}|${p.name}|${p.org}|${p.fn}|${p.sector}|${p.geo}|${p.status}`).join('\n');

  try {
    // ─── CALL 1: Tier classification only ─────────────────────────
    // Smaller, focused output → much less likely to truncate
    const tierSys = `You are an expert MBA career advisor specialising in Leadership Development Programs. Classify EVERY program into one of 5 tiers based on the resume.

TIERS:
- BEST_FIT: Direct match, apply now
- STRONG_FIT: Solid match, tailor and apply
- ACHIEVABLE: Relevant but needs positioning
- LONG_SHOT: Gaps exist, worth trying with network
- NOT_FIT: Structural mismatch, skip

CRITICAL: Every program ID must appear in exactly ONE tier. Respond ONLY with raw valid JSON. No markdown, no code fences, no preamble.

Schema:
{"profile_summary":"2-sentence summary of candidate","tiers":{"BEST_FIT":[{"id":N,"reason":"<25 word reason citing specific resume evidence"}],"STRONG_FIT":[...],"ACHIEVABLE":[...],"LONG_SHOT":[...],"NOT_FIT":[{"id":N,"reason":"string"}]}}`;

    const tierUsr = `RESUME:\n${resumeSnippet}\n\nPROGRAMS (ID|Name|Org|Function|Sector|Geo|Status):\n${progSummary}`;

    const tierRes = await fetch(PROXY_URL, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        model:'claude-sonnet-4-5',
        max_tokens: 4000,
        system: tierSys,
        messages: [{role:'user', content: tierUsr}]
      })
    });

    if(!tierRes.ok){
      const errText = await tierRes.text();
      throw new Error(`Tier classification failed (${tierRes.status}): ${errText.substring(0,200)}`);
    }
    const tierData = await tierRes.json();
    if(tierData.error) throw new Error(typeof tierData.error === 'object' ? JSON.stringify(tierData.error) : tierData.error);

    const tierRaw = tierData.content?.filter(b=>b.type==='text').map(b=>b.text).join('') || '';
    const tierParsed = extractJSON(tierRaw, 'tier classification');

    // ─── CALL 2: Gap analysis + suggestions ───────────────────────
    document.getElementById('aifit-results-container').innerHTML=`<div class="spin-wrap"><div class="spinner"></div><div class="spin-label">Step 2 of 2: Generating your gap analysis + coaching suggestions...</div></div>`;

    // Build a compact summary of which programs landed where, for context
    const tierContext = Object.entries(tierParsed.tiers||{})
      .map(([tier, items]) => `${tier}: ${(items||[]).length} programs`)
      .join(' · ');

    const gapSys = `You are an expert MBA career advisor. Given the resume and which LDP tiers the candidate landed in, produce a gap analysis and tailored resume suggestions.

GAP ANALYSIS — rate each dimension as Strong (clear evidence) | Medium (some evidence) | Weak (gap):
leadership_evidence | international_exposure | operations_depth | quantitative_rigor | cross_functional | entrepreneurial_impact

Each dimension needs: rating (one of the three labels), evidence (specific resume quote or paraphrase, <20 words), tip (one actionable improvement, <25 words).

SUGGESTIONS: Exactly 6 specific resume/positioning improvements. Each names which 1-3 programs it most helps and has a priority (high/medium/low).

CRITICAL: Respond ONLY with raw valid JSON. No markdown, no preamble.

Schema:
{"gap_analysis":{"leadership_evidence":{"rating":"Strong","evidence":"string","tip":"string"},"international_exposure":{...},"operations_depth":{...},"quantitative_rigor":{...},"cross_functional":{...},"entrepreneurial_impact":{...}},"suggestions":[{"title":"string","body":"<40 word improvement","priority":"high","helps_programs":"Program A, Program B"}]}`;

    const gapUsr = `RESUME:\n${resumeSnippet}\n\nTIER CONTEXT: ${tierContext}\nPROFILE SUMMARY: ${tierParsed.profile_summary || 'N/A'}`;

    const gapRes = await fetch(PROXY_URL, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        model:'claude-sonnet-4-5',
        max_tokens: 3000,
        system: gapSys,
        messages: [{role:'user', content: gapUsr}]
      })
    });

    if(!gapRes.ok){
      const errText = await gapRes.text();
      throw new Error(`Gap analysis failed (${gapRes.status}): ${errText.substring(0,200)}`);
    }
    const gapData = await gapRes.json();
    if(gapData.error) throw new Error(typeof gapData.error === 'object' ? JSON.stringify(gapData.error) : gapData.error);

    const gapRaw = gapData.content?.filter(b=>b.type==='text').map(b=>b.text).join('') || '';
    const gapParsed = extractJSON(gapRaw, 'gap analysis');

    // ─── Merge and render ────────────────────────────────────────
    const merged = {
      profile_summary: tierParsed.profile_summary,
      tiers: tierParsed.tiers,
      gap_analysis: gapParsed.gap_analysis,
      suggestions: gapParsed.suggestions
    };

    renderAIResults(merged);

    // Save to scan history (non-blocking)
    if(currentUser) saveScanToHistory(merged);

  } catch(err){
    document.getElementById('aifit-results-container').innerHTML=`<div class="empty">
      <div style="font-size:24px;margin-bottom:12px">⚠️</div>
      <div style="font-weight:500;margin-bottom:6px">${err.message}</div>
      <div style="font-size:11px;color:var(--text3);margin-top:8px">If this keeps happening, try refreshing the page.</div>
      <button onclick="runAIAnalysis()" style="margin-top:12px;padding:8px 16px;background:var(--accent);color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:12px">Try Again</button>
    </div>`;
  } finally {
    // Defensive: always reset button state, even if rendering above throws
    btn.disabled=false;btn.textContent='✦ Re-analyse';
    _aifitScanning = false;
  }
}

// Helper: robust JSON extraction (strips markdown fences + finds {…} envelope)
function extractJSON(raw, label){
  let clean = (raw||'').trim();
  // Strip markdown fences if present
  clean = clean.replace(/^```(?:json)?\s*/i,'').replace(/\s*```\s*$/,'').trim();
  // Find first { and last } in case model adds preamble/postamble
  const firstBrace = clean.indexOf('{');
  const lastBrace = clean.lastIndexOf('}');
  if(firstBrace === -1 || lastBrace === -1){
    throw new Error(`AI returned unexpected format for ${label}. Try again.`);
  }
  clean = clean.substring(firstBrace, lastBrace + 1);
  try {
    return JSON.parse(clean);
  } catch(jsonErr){
    console.error(`JSON parse failed for ${label}, raw response:`, raw.substring(0,500));
    throw new Error(`${label} response was malformed. This is usually a one-off — please try again.`);
  }
}

function showApiKeyPrompt(){
  document.getElementById('aifit-view-pre').style.display = 'none';
  document.getElementById('aifit-view-post').style.display = 'block';
  document.getElementById('aifit-results-container').innerHTML=`
    <div style="background:var(--bg2);border:1px solid var(--border2);border-radius:var(--radius);padding:28px;max-width:520px;margin:0 auto;text-align:center;box-shadow:var(--shadow-md)">
      <div style="font-size:28px;margin-bottom:12px">🔑</div>
      <div style="font-family:var(--serif);font-size:18px;margin-bottom:8px">API Key Required</div>
      <div style="font-size:13px;color:var(--text2);line-height:1.65;margin-bottom:20px">
        To run the AI scanner, you need an Anthropic API key. Get one free at 
        <a href="https://console.anthropic.com" target="_blank" style="color:var(--blue)">console.anthropic.com</a> 
        — a typical analysis costs ~$0.01.
      </div>
      <input id="api-key-input" type="password" placeholder="sk-ant-..." 
        style="width:100%;padding:10px 13px;border:1px solid var(--border2);border-radius:8px;font-family:var(--mono);font-size:12px;background:var(--bg3);outline:none;margin-bottom:12px">
      <button onclick="setApiKey()" 
        style="width:100%;padding:11px;background:var(--accent);color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;font-family:var(--sans)">
        Save Key &amp; Analyse →
      </button>
      <div style="font-size:10px;color:var(--text3);margin-top:10px">Your key is stored only in this browser session — never saved permanently.</div>
    </div>`;
}

function setApiKey(){
  const key=document.getElementById('api-key-input').value.trim();
  if(!key||!key.startsWith('sk-')){alert('Please enter a valid Anthropic API key (starts with sk-)');return;}
  window.LDP_API_KEY=key;
  sessionStorage.setItem('ldp_key',key);
  toast('Key saved ✓ — running analysis...');
  setTimeout(()=>runAIAnalysis(),300);
}

function syncAIResultsToPrograms(result){
  // Map tier to fit score
  const tierScore={BEST_FIT:5,STRONG_FIT:4,ACHIEVABLE:3,LONG_SHOT:2,NOT_FIT:1};
  Object.entries(tierScore).forEach(([tier,score])=>{
    (result.tiers[tier]||[]).forEach(item=>{
      const prog=progs.find(p=>p.id==item.id);
      if(prog){
        prog.fit=score;
        prog.aiTier=tier;
        prog.aiReason=item.reason;
      }
    });
  });
  persist();
  toast('✦ AI results synced to Programs tab');
}

function renderAIResults(result){
  // Sync results to programs table (for Fit column)
  syncAIResultsToPrograms(result);
  
  // Switch to post-scan view
  document.getElementById('aifit-view-pre').style.display = 'none';
  document.getElementById('aifit-view-post').style.display = 'block';
  
  const pm = {};
  progs.forEach(p => { pm[p.id] = p; });
  
  // Count programs per tier
  const tierCounts = {
    BEST_FIT: (result.tiers?.BEST_FIT || []).length,
    STRONG_FIT: (result.tiers?.STRONG_FIT || []).length,
    ACHIEVABLE: (result.tiers?.ACHIEVABLE || []).length,
    LONG_SHOT: (result.tiers?.LONG_SHOT || []).length,
    NOT_FIT: (result.tiers?.NOT_FIT || []).length
  };
  
  const totalScanned = tierCounts.BEST_FIT + tierCounts.STRONG_FIT + tierCounts.ACHIEVABLE + tierCounts.LONG_SHOT + tierCounts.NOT_FIT;
  const scanDate = new Date().toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric'});
  
  // Build HTML
  let html = '';
  
  // Summary strip
  html += `<div class="aifit-summary-strip">
    <div class="aifit-summary-left">
      <span class="aifit-summary-total">${totalScanned} programs scanned</span>
      <div class="aifit-summary-tiers">
        <span class="aifit-summary-tier-best">${tierCounts.BEST_FIT} Best</span>
        <span class="aifit-summary-tier-strong">${tierCounts.STRONG_FIT} Strong</span>
        <span class="aifit-summary-tier-achievable">${tierCounts.ACHIEVABLE} Achievable</span>
        <span class="aifit-summary-tier-long">${tierCounts.LONG_SHOT} Long Shot</span>
        <span class="aifit-summary-tier-not">${tierCounts.NOT_FIT} Not Fit</span>
      </div>
    </div>
    <div class="aifit-summary-right">
      <span class="aifit-summary-date">Scan · ${scanDate}</span>
      <button class="aifit-rescan-btn" onclick="rescanAIFit()">Re-scan</button>
    </div>
  </div>`;
  
  // Tier sections
  const tierConfigs = [
    {key:'BEST_FIT', label:'Best Fit', badge:'Tier 1', badgeClass:'aifit-tier-badge-best', defaultOpen:true},
    {key:'STRONG_FIT', label:'Strong Fit', badge:'Tier 2', badgeClass:'aifit-tier-badge-strong', defaultOpen:true},
    {key:'ACHIEVABLE', label:'Achievable', badge:'Tier 3', badgeClass:'aifit-tier-badge-achievable', defaultOpen:false},
    {key:'LONG_SHOT', label:'Long Shot', badge:'Tier 4', badgeClass:'aifit-tier-badge-long', defaultOpen:false},
    {key:'NOT_FIT', label:'Not Fit', badge:'Tier 5', badgeClass:'aifit-tier-badge-not', defaultOpen:false}
  ];
  
  tierConfigs.forEach(tc => {
    const items = (result.tiers || {})[tc.key] || [];
    if(!items.length) return;
    
    const isOpen = tc.defaultOpen;
    const tierId = `tier-${tc.key}`;
    
    html += `<div class="aifit-tier-section">
      <div class="aifit-tier-header" onclick="toggleAIFitTier('${tc.key}')">
        <div class="aifit-tier-header-left">
          <h2 class="aifit-tier-title">${tc.label}</h2>
          <span class="aifit-tier-count">${items.length} program${items.length !== 1 ? 's' : ''}</span>
        </div>
        <div class="aifit-tier-header-right">
          <span class="aifit-tier-badge ${tc.badgeClass}">${tc.badge}</span>
          <span class="aifit-tier-arrow ${isOpen ? 'open' : ''}" id="arrow-${tc.key}">▾</span>
        </div>
      </div>
      <div class="aifit-tier-cards" id="${tierId}" style="display:${isOpen ? 'flex' : 'none'}">
        ${items.map(item => {
          const p = pm[item.id];
          if(!p) return '';
          
          const initial = (p.org || '?').charAt(0).toUpperCase();
          
          // Tags: show sector, geo, visa
          const tags = [];
          if(p.sector) tags.push(cap(p.sector));
          if(p.geo) tags.push(cap(p.geo));
          if(p.visa) tags.push('Visa');
          
          return `<div class="aifit-program-card">
            <div class="aifit-program-card-left">
              <div class="aifit-program-initial">${initial}</div>
              <div class="aifit-program-info">
                <div class="aifit-program-name">${p.name}</div>
                <div class="aifit-program-reason">${item.reason}</div>
              </div>
            </div>
            <div class="aifit-program-card-right">
              <div class="aifit-program-tags">
                ${tags.map(t => `<span class="aifit-program-tag">${t}</span>`).join('')}
              </div>
              <button class="aifit-program-save-btn" onclick="addProgramToApplications(${p.id}, 'shortlisted')">+ Shortlist</button>
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  });
  
  // Gap Analysis Panel
  if(result.gap_analysis){
    const gapLabels = {
      cross_functional: {label:'Cross-Functional'},
      quantitative_rigor: {label:'Quantitative Rigor'},
      leadership_evidence: {label:'Leadership Evidence'},
      operations_depth: {label:'Operations Depth'},
      entrepreneurial_impact: {label:'Entrep. Impact'},
      international_exposure: {label:'International'}
    };
    
    html += `<div class="aifit-gap-panel">
      <div class="aifit-gap-header">
        <h2 class="aifit-gap-title">Gap Analysis Profile</h2>
        <span class="aifit-gap-count">6 dimensions</span>
      </div>
      <div class="aifit-gap-grid">
        ${Object.entries(gapLabels).map(([key, meta]) => {
          const g = result.gap_analysis[key];
          if(!g) return '';
          const ratingClass = g.rating === 'Strong' ? 'aifit-gap-rating-strong' : 
                             g.rating === 'Medium' ? 'aifit-gap-rating-medium' : 
                             'aifit-gap-rating-weak';
          return `<div class="aifit-gap-card">
            <div class="aifit-gap-card-header">
              <span class="aifit-gap-label">${meta.label}</span>
              <span class="aifit-gap-rating ${ratingClass}">${g.rating}</span>
            </div>
            <p class="aifit-gap-tip">${g.tip}</p>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }
  
  // Strategic Coaching Section
  if(result.suggestions?.length){
    const priorityDotClass = {high:'aifit-priority-dot-high', medium:'aifit-priority-dot-medium', low:'aifit-priority-dot-low'};
    const priorityLabel = {high:'High', medium:'Medium', low:'Low'};
    
    html += `<div class="aifit-coaching-section">
      <div class="aifit-coaching-header">
        <h2 class="aifit-coaching-title">Strategic Coaching</h2>
        <span class="aifit-coaching-count">${result.suggestions.length} suggestion${result.suggestions.length !== 1 ? 's' : ''}</span>
      </div>
      <div class="aifit-coaching-grid">
        ${result.suggestions.map(s => {
          const dotClass = priorityDotClass[s.priority] || priorityDotClass.medium;
          const priLabel = priorityLabel[s.priority] || 'Medium';
          
          // Parse helps_programs string into array of tier tags
          const helpsTags = [];
          if(s.helps_programs){
            if(s.helps_programs.includes('BEST_FIT')) helpsTags.push({label:'BEST_FIT', class:'aifit-coaching-helps-tag-best'});
            if(s.helps_programs.includes('STRONG_FIT')) helpsTags.push({label:'STRONG_FIT', class:'aifit-coaching-helps-tag-strong'});
            if(s.helps_programs.includes('ACHIEVABLE')) helpsTags.push({label:'ACHIEVABLE', class:'aifit-coaching-helps-tag-achievable'});
          }
          
          return `<div class="aifit-coaching-card">
            <div>
              <div class="aifit-coaching-priority">
                <span class="${dotClass}"></span>
                <span class="aifit-priority-label">Priority: ${priLabel}</span>
              </div>
              <h3 class="aifit-coaching-card-title">${s.title}</h3>
              <p class="aifit-coaching-card-body">${s.body}</p>
            </div>
            <div class="aifit-coaching-helps">
              ${helpsTags.map(t => `<span class="aifit-coaching-helps-tag ${t.class}">${t.label}</span>`).join('')}
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }
  
  document.getElementById('aifit-results-container').innerHTML = html;
}

// Toggle tier open/closed
const aifitTierState = {BEST_FIT:true, STRONG_FIT:true, ACHIEVABLE:false, LONG_SHOT:false, NOT_FIT:false};
function toggleAIFitTier(tierKey){
  aifitTierState[tierKey] = !aifitTierState[tierKey];
  const tierEl = document.getElementById(`tier-${tierKey}`);
  const arrowEl = document.getElementById(`arrow-${tierKey}`);
  if(tierEl){
    tierEl.style.display = aifitTierState[tierKey] ? 'flex' : 'none';
  }
  if(arrowEl){
    if(aifitTierState[tierKey]){
      arrowEl.classList.add('open');
    } else {
      arrowEl.classList.remove('open');
    }
  }
}

// Re-scan button — swap back to pre-scan view, reflect actual upload state
function rescanAIFit(){
  document.getElementById('aifit-view-post').style.display = 'none';
  document.getElementById('aifit-view-pre').style.display = 'block';
  const btn = document.getElementById('analyze-btn');
  btn.textContent = '✦ Analyse My Fit';
  // Only enable if there's a resume actually in memory; otherwise force-disable
  btn.disabled = !(resumeText && resumeText.trim().length >= 200);
}

// ═══════════════ MODALS ═══════════════
function openM(type,data={}){
  eId[type==='prog'?'prog':type==='alumni'?'alumni':'app']=data.id||null;
  if(type==='prog'){
    sv('pi-name',data.name||'');sv('pi-org',data.org||'');sv('pi-url',data.url||'');
    sv('pi-geo',data.geo||'europe');sv('pi-loc',data.loc||'');sv('pi-fn',data.fn||'strategy');
    sv('pi-sector',data.sector||'other');sv('pi-status',data.status||'watch');
    sv('pi-deadline',data.deadline||'');sv('pi-dlnote',data.dlnote||'');
    sv('pi-fit',String(data.fit||'4'));sv('pi-notes',data.notes||'');
    sv('pi-tags',(data.tags||[]).join(', '));
    sv('pi-visa',data.visa?'yes':'');
  }
  if(type==='alumni'){
    sv('ai-name',data.name||'');sv('ai-school',data.school||'esade');
    sv('ai-firm',data.firm||'');sv('ai-role',data.role||'');sv('ai-li',data.li||'');
    sv('ai-prog',data.prog||'');sv('ai-loc',data.loc||'');sv('ai-status',data.status||'identified');
    sv('ai-notes',data.notes||'');
  }
  if(type==='app'){
    // Phase 9: populate program-name autocomplete from the 48 tracked programs.
    // User can type freely (custom program) OR pick from the dropdown — picking auto-fills other empty fields.
    const dl = document.getElementById('prog-suggestions');
    if(dl){
      dl.innerHTML = progs.map(p =>
        `<option value="${(p.name||'').replace(/"/g,'&quot;')}">${(p.org||'').replace(/"/g,'&quot;')}</option>`
      ).join('');
    }
    sv('aps-name',data.name||'');sv('aps-org',data.org||'');sv('aps-geo',data.geo||'');
    sv('aps-status',data.status||'shortlisted');
    sv('aps-date',data.date||new Date().toISOString().split('T')[0]);
    sv('aps-deadline',data.deadline||'');sv('aps-next',data.next||'');
    sv('aps-contact',data.contact||'');sv('aps-notes',data.notes||'');
  }
  document.getElementById('ov-'+type).classList.add('open');
}
function closeM(type){document.getElementById('ov-'+type).classList.remove('open');}
function sv(id,val){const e=document.getElementById(id);if(e)e.value=val;}
function gv(id){const e=document.getElementById(id);return e?e.value.trim():'';}

// Phase 9: when the user picks a tracked program from the Application modal's autocomplete,
// fill in any EMPTY adjacent fields (org, geo, deadline). Never overwrite fields the user has typed.
function autoFillFromProgram(name){
  const target = (name || '').trim().toLowerCase();
  if(!target) return;
  const p = progs.find(x => (x.name||'').toLowerCase() === target);
  if(!p) return;   // free-typed custom name — leave fields alone
  const orgEl = document.getElementById('aps-org');
  const geoEl = document.getElementById('aps-geo');
  const dlEl  = document.getElementById('aps-deadline');
  // Map internal geo keys to friendly labels for the free-text geo field
  const geoLabel = ({europe:'Europe', uae:'UAE / Gulf', global:'Global'})[p.geo] || p.geo || '';
  const filled = [];
  if(orgEl && !orgEl.value.trim() && p.org)      { orgEl.value = p.org;       filled.push('Org'); }
  if(geoEl && !geoEl.value.trim() && geoLabel)   { geoEl.value = geoLabel;    filled.push('Geo'); }
  if(dlEl  && !dlEl.value         && p.deadline) { dlEl.value  = p.deadline;  filled.push('Deadline'); }
  if(filled.length){
    toast(`Auto-filled from ${p.org}: ${filled.join(' · ')}`);
  }
}

// ═══════════════ SAVE ═══════════════
function saveProg(){
  const p={id:eId.prog||Date.now(),name:gv('pi-name'),org:gv('pi-org'),url:gv('pi-url'),geo:gv('pi-geo'),
    loc:gv('pi-loc'),fn:gv('pi-fn'),sector:gv('pi-sector'),status:gv('pi-status'),
    deadline:gv('pi-deadline'),dlnote:gv('pi-dlnote'),fit:gv('pi-fit'),notes:gv('pi-notes'),
    visa:gv('pi-visa')==='yes',
    tags:gv('pi-tags').split(',').map(t=>t.trim()).filter(Boolean)};
  if(!p.name){alert('Program name required.');return;}
  if(eId.prog){const i=progs.findIndex(x=>x.id===eId.prog);i>=0?progs[i]=p:progs.push(p);}
  else progs.push(p);
  persist();closeM('prog');renderPrograms();toast('Program saved ✓');
}
function saveAlumni(){
  const a={id:eId.alumni||Date.now(),name:gv('ai-name'),school:gv('ai-school'),firm:gv('ai-firm'),
    role:gv('ai-role'),li:gv('ai-li'),prog:gv('ai-prog'),loc:gv('ai-loc'),status:gv('ai-status'),notes:gv('ai-notes')};
  if(!a.name){alert('Name required.');return;}
  if(eId.alumni){const i=alum.findIndex(x=>x.id===eId.alumni);i>=0?alum[i]=a:alum.push(a);}
  else alum.push(a);
  persist();closeM('alumni');renderAlumni();toast('Contact saved ✓');
}
async function saveApp(){
  if(!currentUser){
    toast('Please sign in to save applications.');
    showLanding();
    return;
  }
  const a={
    id: eId.app || null,
    _db: !!eId.app,            // true if we're editing an existing DB row
    program_id: null,
    name:gv('aps-name'), org:gv('aps-org'), geo:gv('aps-geo'),
    status:gv('aps-status'), date:gv('aps-date'), deadline:gv('aps-deadline'),
    next:gv('aps-next'), contact:gv('aps-contact'), notes:gv('aps-notes')
  };
  if(!a.name){alert('Program/role name required.');return;}

  // Persist to Supabase
  const newId = await saveApplicationToDB(a);
  if(!newId){ return; }   // toast already shown by saveApplicationToDB
  a.id = newId;
  a._db = true;

  // Update in-memory cache
  if(eId.app){
    const i = apps.findIndex(x=>x.id===eId.app);
    if(i>=0) apps[i] = a; else apps.unshift(a);
  } else {
    apps.unshift(a);
  }
  closeM('app');
  renderApplications();
  // Phase 7: apps[] now reflects the new application — re-render the progress strip
  // with fresh state (this overrides the stale render done inside saveApplicationToDB).
  renderProgressStrip();
  toast('Application saved ✓');
}

// ═══════════════ EDIT / DELETE ═══════════════
function editP(id){openM('prog',progs.find(p=>p.id===id)||{});}
function delP(id){if(confirm('Remove this program?')){progs=progs.filter(p=>p.id!==id);persist();renderPrograms();toast('Removed');}}
function editA(id){openM('alumni',alum.find(a=>a.id===id)||{});}
function delA(id){if(confirm('Remove this contact?')){alum=alum.filter(a=>a.id!==id);persist();renderAlumni();toast('Removed');}}
function editAp(id){openM('app',apps.find(a=>String(a.id)===String(id))||{});}
async function delCurrentApp(){
  if(eId.app && confirm('Delete this application?')){
    await deleteApplicationFromDB(eId.app);
    apps = apps.filter(a=>a.id!==eId.app);
    closeM('app');
    renderApplications();
    toast('Application deleted');
  }
}

// ═══════════════ HELPERS ═══════════════
function cap(s){return s?s.charAt(0).toUpperCase()+s.slice(1):'';}
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500);}

// Close modals on outside click
document.querySelectorAll('.overlay').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)o.classList.remove('open');}));

// Phase 4: keep the active tour step pinned to its target on viewport resize
window.addEventListener('resize', () => {
  if(_tourQueue.length && _tourIdx < _tourQueue.length) tourShow();
});

// ─── Init ────────────────────────────────────────────────────────
// Populate freshness badge (topbar + landing)
const _freshEl = document.getElementById('freshness-date');
if(_freshEl) _freshEl.textContent = DATA_LAST_VERIFIED_LABEL;
const _lpStamp = document.getElementById('lp-verified-stamp');
if(_lpStamp) _lpStamp.textContent = `Programs verified ${DATA_LAST_VERIFIED_LABEL}`;
const _lpProgs = document.getElementById('lp-stat-progs');
if(_lpProgs) _lpProgs.textContent = progs.length;
const _lpMock = document.getElementById('lp-mock-count');
if(_lpMock) _lpMock.textContent = progs.length;

// Show landing by default; initAuth() will hide it if user is already signed in.
document.getElementById('landing-overlay').classList.add('open');

window._fitOnly=false;
window._visaOnly=false;

// Populate alumni modal school select from full list
const aiSchoolSel = document.getElementById('ai-school');
if(aiSchoolSel){
  aiSchoolSel.innerHTML = ALL_MBA_SCHOOLS.map(s=>`<option value="${s.key}">${s.label}</option>`).join('') +
    '<option value="both">Multiple schools</option>';
}

// Close ICS modal on outside click
document.getElementById('ics-modal-overlay').addEventListener('click',e=>{
  if(e.target===document.getElementById('ics-modal-overlay')) document.getElementById('ics-modal-overlay').classList.remove('open');
});

// Boot: initialise auth (which decides whether to show landing or main app)
initAuth();
// Phase 10: restore saved filter+sort state before the first render
_restoreFilterState();
renderPrograms();

// Set dynamic program count in topbar stats
const pcEl=document.getElementById('prog-count');
if(pcEl) pcEl.textContent=progs.length;

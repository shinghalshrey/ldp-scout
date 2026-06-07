#!/usr/bin/env node
/**
 * generate-dashboard.js — LDP Scout pilot analytics generator
 * -----------------------------------------------------------------------------
 * Queries Supabase with the SERVICE ROLE key and regenerates `dashboard.html`
 * from the pilot-analytics template, swapping in fresh data.
 *
 * USAGE
 *   PowerShell:  $env:SUPABASE_SERVICE_KEY="<service_role_key>"; node generate-dashboard.js
 *   bash/zsh:    SUPABASE_SERVICE_KEY="<service_role_key>" node generate-dashboard.js
 *
 * ENV VARS
 *   SUPABASE_SERVICE_KEY  (required) Supabase service_role key. The ANON key will
 *                         NOT work — RLS restricts user tables to the owning user,
 *                         and this dashboard needs every row. service_role bypasses RLS.
 *   COHORT_START          (optional) ISO date (YYYY-MM-DD). Only users who signed up
 *                         on/after this date are counted, which keeps the "pilot cohort"
 *                         narrative accurate. Default: 2026-05-26 (the launch invite).
 *                         Set COHORT_START=all to include EVERY user (literal COUNT(*)).
 *   DASHBOARD_OUT         (optional) Output path. Default: ./dashboard.html (next to this script).
 *
 * NOTES
 *   - Requires @supabase/supabase-js (already present under Desktop\node_modules;
 *     if missing run:  npm install @supabase/supabase-js).
 *   - Geo / traffic-source / site-visitor / events numbers come from GA4, NOT Supabase.
 *     Those cells are left as clearly-marked static placeholders (see PLACEHOLDERS below).
 *   - Each query is wrapped in try/catch: if one fails it's logged and that section
 *     renders empty/zero rather than crashing the whole run.
 *   - The generated dashboard contains individual user names + activity (PII). Do not
 *     commit/deploy it to a public URL without access control.
 *   - Architecture: fetchAll (I/O) -> computeDashboardData (pure) -> renderHtml (pure).
 *     The two pure functions are exported so the output can be unit-tested with mock data.
 * -----------------------------------------------------------------------------
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const SUPABASE_URL = 'https://kqtarrgtxqpamlfrkgiv.supabase.co';
const OUT_PATH = process.env.DASHBOARD_OUT || path.join(__dirname, 'dashboard.html');

const COHORT_START_RAW = process.env.COHORT_START != null ? process.env.COHORT_START : '2026-05-26';
const COHORT_START =
  COHORT_START_RAW && COHORT_START_RAW.trim() && COHORT_START_RAW.trim().toLowerCase() !== 'all'
    ? COHORT_START_RAW.trim()
    : null;

const PAGE = 1000;

// ---------------------------------------------------------------------------
// Helpers (pure)
// ---------------------------------------------------------------------------
const esc = (s) =>
  String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const pct = (n, d) => (d ? (Math.round((n / d) * 1000) / 10).toFixed(1) : '0.0');

const fmtDay = (iso) =>
  iso ? new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }) : '—';

const fmtDayLong = (d) => d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

function median(arr) {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// ---------------------------------------------------------------------------
// Data access
// ---------------------------------------------------------------------------
/** Fetch every row from a table (paginated). On error: log + return []. */
async function fetchAll(supabase, table, columns) {
  const rows = [];
  try {
    for (let from = 0; ; from += PAGE) {
      const { data, error } = await supabase.from(table).select(columns).range(from, from + PAGE - 1);
      if (error) throw error;
      if (!data || data.length === 0) break;
      rows.push(...data);
      if (data.length < PAGE) break;
    }
    return rows;
  } catch (err) {
    console.error(`  ! query failed for "${table}": ${err.message || err}. Section will be empty.`);
    return [];
  }
}

// ===========================================================================
// computeDashboardData — pure transform of raw rows -> template view-model.
//   raw  = { profilesAll, resumes, scans, apps, contacts, programs }
//   opts = { cohortStart: 'YYYY-MM-DD'|null, now: Date }
// ===========================================================================
function computeDashboardData(raw, opts) {
  const { profilesAll = [], resumes = [], scans = [], apps = [], contacts = [], programs = [] } = raw;
  const cohortStart = opts && opts.cohortStart ? opts.cohortStart : null;
  const now = (opts && opts.now) || new Date();

  // ---- Cohort scope ----
  const cohortStartDate = cohortStart ? new Date(`${cohortStart}T00:00:00Z`) : null;
  const inCohort = (p) => !cohortStartDate || (p.created_at && new Date(p.created_at) >= cohortStartDate);
  const profiles = profilesAll.filter(inCohort);
  const cohortIds = new Set(profiles.map((p) => p.user_id));
  const within = (r) => cohortIds.has(r.user_id);

  const resumesC = resumes.filter(within);
  const scansC = scans.filter(within);
  const appsC = apps.filter(within);
  const contactsC = contacts.filter(within);

  // ---- Per-user aggregates ----
  const resumeUsers = new Set(resumesC.map((r) => r.user_id));
  const scanCount = new Map();
  const firstScan = new Map();
  for (const s of scansC) {
    scanCount.set(s.user_id, (scanCount.get(s.user_id) || 0) + 1);
    if (s.created_at) {
      const t = new Date(s.created_at).getTime();
      if (!firstScan.has(s.user_id) || t < firstScan.get(s.user_id)) firstScan.set(s.user_id, t);
    }
  }
  const appCount = new Map();
  const appProgs = new Map(); // user_id -> [program display names]
  for (const a of appsC) {
    appCount.set(a.user_id, (appCount.get(a.user_id) || 0) + 1);
    const list = appProgs.get(a.user_id) || [];
    const nm = a.name || a.org || 'Untitled';
    if (!list.includes(nm)) list.push(nm);
    appProgs.set(a.user_id, list);
  }
  const programById = new Map(programs.map((p) => [p.id, p]));

  const usersWithScan = (id) => (scanCount.get(id) || 0) > 0;
  const usersWithApp = (id) => (appCount.get(id) || 0) > 0;

  // ---- Headline numbers ----
  const totalUsers = profiles.length;
  const resumesUploaded = resumeUsers.size;
  const scansCompleted = scansC.length;
  const appsLogged = appsC.length;
  const contactsLogged = contactsC.length;
  const activated = profiles.filter((p) => usersWithScan(p.user_id) && usersWithApp(p.user_id)).length;
  const activeTrackers = profiles.filter((p) => usersWithApp(p.user_id)).length;

  // ---- Activation funnel (mutually exclusive, exhaustive) ----
  let f4 = 0, f3 = 0, f2 = 0, f1 = 0; // activated / scanned-no-app / uploaded-not-scanned / signed-up-only
  for (const p of profiles) {
    const hasScan = usersWithScan(p.user_id);
    const hasApp = usersWithApp(p.user_id);
    const hasResume = resumeUsers.has(p.user_id);
    if (hasScan && hasApp) f4++;
    else if (hasScan) f3++;
    else if (hasResume) f2++;
    else f1++;
  }
  const funnelStages = [
    { label: '1 · Signed up only', cls: 'fb-1', count: f1, pct: pct(f1, totalUsers) },
    { label: '2 · Uploaded résumé', cls: 'fb-2', count: f2, pct: pct(f2, totalUsers) },
    { label: '3 · Scanned, no apps', cls: 'fb-3', count: f3, pct: pct(f3, totalUsers) },
    { label: '4 · Fully activated', cls: 'fb-4', count: f4, pct: pct(f4, totalUsers) },
  ];
  const funnelHtml = funnelStages
    .map(
      (s) => `        <div class="funnel-item">
          <div class="funnel-label">${s.label}</div>
          <div class="funnel-bar-wrap"><div class="funnel-bar ${s.cls}" style="width:${s.pct}%">${s.count > 0 ? `<span>${s.count}</span>` : ''}</div></div>
          <div class="funnel-pct">${s.pct}%</div>
        </div>`
    )
    .join('\n');
  const scanToAppPct = pct(f4, f4 + f3);

  // ---- Signups by day ----
  const dayCounts = new Map();
  for (const p of profiles) {
    if (!p.created_at) continue;
    const key = new Date(p.created_at).toISOString().slice(0, 10);
    const cur = dayCounts.get(key) || { date: fmtDay(p.created_at), count: 0, key };
    cur.count++;
    dayCounts.set(key, cur);
  }
  const signupsByDay = [...dayCounts.values()].sort((a, b) => a.key.localeCompare(b.key));
  const reminderKey = cohortStart || (signupsByDay[0] && signupsByDay[0].key);
  for (const day of signupsByDay) if (day.key === reminderKey) day.note = 'reminder';
  signupsByDay.forEach((day) => { delete day.key; });

  // cohort span
  const signupTimes = profiles.map((p) => p.created_at).filter(Boolean).map((c) => new Date(c));
  const firstSignup = signupTimes.length ? new Date(Math.min(...signupTimes)) : null;
  const lastSignup = signupTimes.length ? new Date(Math.max(...signupTimes)) : null;
  const cohortDays =
    firstSignup && lastSignup
      ? Math.max(1, Math.round((lastSignup - firstSignup) / 86400000) + 1)
      : signupsByDay.length;
  const firstLabel = firstSignup ? fmtDay(firstSignup.toISOString()) : '—';
  const lastLabel = lastSignup ? fmtDay(lastSignup.toISOString()) : '—';
  const peak = signupsByDay.reduce((a, b) => (b.count > (a ? a.count : -1) ? b : a), null);

  // ---- Median time-to-scan ----
  const signupByUser = new Map(profiles.map((p) => [p.user_id, p.created_at ? new Date(p.created_at).getTime() : null]));
  const deltas = [];
  for (const [uid, fs0] of firstScan.entries()) {
    const su = signupByUser.get(uid);
    if (su != null && fs0 >= su) deltas.push(fs0 - su);
  }
  const med = median(deltas);
  let medVal = '—', medUnit = '';
  if (med != null) {
    const min = med / 60000;
    if (min < 90) { medVal = min.toFixed(1); medUnit = 'min'; }
    else { const hr = min / 60; if (hr < 48) { medVal = hr.toFixed(1); medUnit = 'hr'; } else { medVal = (hr / 24).toFixed(1); medUnit = 'days'; } }
  }

  // ---- School breakdown ----
  const schoolMap = new Map();
  for (const p of profiles) {
    const key = (p.school_key || '').trim().toLowerCase();
    const g = schoolMap.get(key) || {
      key,
      label: key ? (p.school_label && p.school_label.trim() ? p.school_label.trim() : key.toUpperCase()) : 'Unattributed',
      users: 0, uploaded: 0, scanned: 0, logged: 0,
    };
    g.users++;
    if (resumeUsers.has(p.user_id)) g.uploaded++;
    if (usersWithScan(p.user_id)) g.scanned++;
    if (usersWithApp(p.user_id)) g.logged++;
    schoolMap.set(key, g);
  }
  const schoolGroups = [...schoolMap.values()].sort((a, b) => (a.key === '' ? 1 : b.key === '' ? -1 : b.users - a.users));
  const schoolRowsHtml = schoolGroups
    .map((g) => {
      const unattr = g.key === '';
      const nameCell = unattr
        ? `<strong style="color:var(--text3)">Unattributed</strong>`
        : `<strong>${esc(g.label)}</strong>`;
      const cls = unattr ? ' class="td-right td-muted"' : ' class="td-right"';
      return `          <tr><td>${nameCell}</td><td${cls}>${g.users}</td><td${cls}>${g.uploaded}</td><td${cls}>${g.scanned}</td><td${cls}>${g.logged}</td></tr>`;
    })
    .join('\n');
  const schoolSub =
    schoolGroups
      .map((g) => `${g.users} ${g.key === '' ? 'unattributed' : esc(g.key.toUpperCase())}`)
      .join(' · ') || '—';

  // ---- Onboarding status ----
  let onbCompleted = 0, onbSkipped = 0, onbIncomplete = 0;
  for (const p of profiles) {
    if (p.onboarding_completed_at) onbCompleted++;
    else if (p.onboarding_skipped_at) onbSkipped++;
    else onbIncomplete++;
  }
  const skipPct = pct(onbSkipped, totalUsers);

  // ---- Most-tracked programs (distinct users per program) ----
  const progAgg = new Map();
  const customKeys = new Set();
  for (const a of appsC) {
    let key, company, name, fn, geo;
    if (a.program_id != null && programById.has(a.program_id)) {
      const pr = programById.get(a.program_id);
      key = `p${a.program_id}`;
      company = pr.company; name = pr.program_name; fn = pr.function; geo = pr.geo;
    } else {
      key = `c:${(a.org || '').toLowerCase()}|${(a.name || '').toLowerCase()}`;
      company = a.org; name = a.name; fn = a.fn; geo = a.geo;
      customKeys.add(key);
    }
    const g = progAgg.get(key) || { company, name, fn, geo, users: new Set(), apps: 0 };
    g.users.add(a.user_id);
    g.apps++;
    progAgg.set(key, g);
  }
  const customCount = customKeys.size;
  const totalDistinctPrograms = progAgg.size;
  const topPrograms = [...progAgg.values()]
    .map((g) => ({
      company: esc(g.company || '—'),
      name: esc(g.name || '—'),
      fn: esc(g.fn || '—'),
      geo: esc(g.geo || '—'),
      users: g.users.size,
      _apps: g.apps,
    }))
    .sort((a, b) => b.users - a.users || b._apps - a._apps)
    .slice(0, 20)
    .map((g, i) => ({ rank: i + 1, company: g.company, name: g.name, fn: g.fn, geo: g.geo, users: g.users }));
  const topProg = topPrograms[0];
  const customNote = `${customCount} custom program${customCount === 1 ? '' : 's'} added${customCount === 0 ? ' — catalog covered everyone' : ''}`;
  const progFooter =
    (topProg
      ? `<strong style="color:var(--green)">${topProg.company}</strong> — ${topProg.name} leads with ${topProg.users} student${topProg.users === 1 ? '' : 's'} tracking. `
      : '') +
    `${totalDistinctPrograms} distinct program${totalDistinctPrograms === 1 ? '' : 's'} tracked across the cohort${customCount > 0 ? `, including ${customCount} custom` : ''}.`;

  // ---- Power users (top 5 by app count) ----
  const ranked = profiles
    .map((p) => ({ name: p.full_name || (p.email ? p.email.split('@')[0] : 'Unknown'), apps: appCount.get(p.user_id) || 0 }))
    .filter((u) => u.apps > 0)
    .sort((a, b) => b.apps - a.apps);
  const top5 = ranked.slice(0, 5);
  const sumTop5 = top5.reduce((s, u) => s + u.apps, 0);
  const powerItemsHtml = top5
    .map((u) => `      <div class="power-item"><div class="power-name">${esc(u.name)}</div><div class="power-stat">${u.apps}</div><div class="power-lbl">applications</div></div>`)
    .join('\n');
  const powerIntro =
    `${top5.length} user${top5.length === 1 ? '' : 's'} drive most of the application volume — together they account for <strong style="color:var(--green)">${sumTop5} of ${appsLogged}</strong> applications logged (${pct(sumTop5, appsLogged)}%). ` +
    `Across the cohort, ${contactsLogged} networking contact${contactsLogged === 1 ? '' : 's'} ${contactsLogged === 1 ? 'has' : 'have'} been logged.`;

  // ---- Individual user rows (newest first) ----
  const users = [...profiles]
    .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))
    .map((p) => {
      const onb = p.onboarding_completed_at ? 'Completed' : p.onboarding_skipped_at ? 'Skipped' : 'Incomplete';
      let progs = (appProgs.get(p.user_id) || []).map((n) => esc(n));
      if (progs.length > 8) { const extra = progs.length - 7; progs = progs.slice(0, 7).concat(`+${extra} more`); }
      return {
        name: esc(p.full_name || (p.email ? p.email.split('@')[0] : '—')),
        school: (p.school_key || '').trim().toLowerCase() || '—',
        date: fmtDay(p.created_at),
        onb,
        resume: resumeUsers.has(p.user_id) ? 'Yes' : 'No',
        scans: scanCount.get(p.user_id) || 0,
        apps: appCount.get(p.user_id) || 0,
        programs: progs,
      };
    });

  // ---- Labels / prose ----
  const todayLabel = fmtDayLong(now);
  const cohortWindow = cohortStart
    ? `Cohort window: ${firstLabel} – ${lastLabel} 2026 · ESADE student pilot`
    : `All registered users · live Supabase data`;
  const signupKicker =
    (peak ? `<strong>${peak.date}:</strong> ${peak.count} signup${peak.count === 1 ? '' : 's'} on the busiest day. ` : '') +
    `${totalUsers} signup${totalUsers === 1 ? '' : 's'} across ${cohortDays} day${cohortDays === 1 ? '' : 's'}` +
    (cohortStart ? `, since the launch invite went out on ${firstLabel}.` : '.');
  const funnelKicker =
    `<strong>${pct(f4, totalUsers)}%</strong> activate fully — scanned a résumé and logged at least one application. ` +
    `Of those who scan, ${scanToAppPct}% go on to log applications. The <strong>${pct(f1, totalUsers)}%</strong> who sign up and stop is the primary leak to address.`;
  const contextNarrative =
    `This dashboard summarises ${cohortStart ? `the cohort that joined since the launch invite went out on ${firstLabel}` : 'all registered users'}. ` +
    (cohortStart ? 'Earlier signups (pre-launch testers and friends) are excluded so the numbers reflect the real student response. ' : '') +
    `${totalUsers} student${totalUsers === 1 ? ' has' : 's have'} signed up${cohortStart ? ` in ${cohortDays} days` : ''}, and ${activeTrackers} ${activeTrackers === 1 ? 'is' : 'are'} actively tracking applications.`;
  const footerLine = `LDP Scout Pilot · ${cohortStart ? `Cohort ${firstLabel}–${lastLabel} 2026` : 'All users'} · Internal analytics from Supabase · Generated ${todayLabel}`;

  return {
    // scalars for summary
    totalUsers, totalProfiles: profilesAll.length, resumesUploaded, scansCompleted,
    appsLogged, contactsLogged, activated, cohortStart,
    // view-model for renderHtml
    todayLabel, cohortDays, cohortWindow, contextNarrative,
    schoolSub, activatedPct: pct(activated, totalUsers),
    resumesPct: pct(resumesUploaded, totalUsers),
    avgPerActive: activeTrackers ? (appsLogged / activeTrackers).toFixed(1) : '0.0',
    medVal, medUnit, signupKicker, funnelHtml, funnelKicker,
    powerIntro, powerItemsHtml, schoolRowsHtml,
    onbCompleted, onbSkipped, onbIncomplete, skipPct,
    customNote, progFooter, footerLine,
    signupsByDay, topPrograms, users,
  };
}

// ---------------------------------------------------------------------------
// main — fetch -> compute -> render -> write -> summarise
// ---------------------------------------------------------------------------
async function main() {
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
  if (!SERVICE_KEY) {
    console.error('ERROR: SUPABASE_SERVICE_KEY environment variable is required (service_role key, not anon).');
    console.error('  PowerShell:  $env:SUPABASE_SERVICE_KEY="<key>"; node generate-dashboard.js');
    console.error('  bash:        SUPABASE_SERVICE_KEY="<key>" node generate-dashboard.js');
    process.exit(1);
  }

  let createClient;
  try {
    ({ createClient } = require('@supabase/supabase-js'));
  } catch (e) {
    console.error('ERROR: @supabase/supabase-js is not installed. Run:  npm install @supabase/supabase-js');
    process.exit(1);
  }

  const supabase = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  console.log(`Generating dashboard from ${SUPABASE_URL} ...`);

  const [profilesAll, resumes, scans, apps, contacts, programs] = await Promise.all([
    fetchAll(supabase, 'user_profiles', 'user_id,email,full_name,school_key,school_label,created_at,onboarding_completed_at,onboarding_skipped_at'),
    fetchAll(supabase, 'user_resumes', 'user_id,uploaded_at'),
    fetchAll(supabase, 'user_scan_history', 'id,user_id,created_at'),
    fetchAll(supabase, 'user_applications', 'id,user_id,program_id,name,org,fn,geo,status,created_at'),
    fetchAll(supabase, 'user_contacts', 'id,user_id'),
    fetchAll(supabase, 'programs', 'id,company,program_name,function,geo'),
  ]);

  const d = computeDashboardData(
    { profilesAll, resumes, scans, apps, contacts, programs },
    { cohortStart: COHORT_START, now: new Date() }
  );

  const html = renderHtml(d);
  try {
    fs.writeFileSync(OUT_PATH, html, 'utf8');
  } catch (err) {
    console.error(`ERROR: could not write ${OUT_PATH}: ${err.message}`);
    process.exit(1);
  }

  console.log('');
  console.log(`Cohort filter: ${COHORT_START ? `signups on/after ${COHORT_START}` : 'ALL users (COUNT(*))'} — ${d.totalUsers} of ${d.totalProfiles} total profiles.`);
  console.log(`Output: ${OUT_PATH}`);
  console.log(`Dashboard generated: ${d.totalUsers} users, ${d.resumesUploaded} resumes, ${d.scansCompleted} scans, ${d.appsLogged} apps`);
  console.log(`  (also: ${d.contactsLogged} contacts · ${d.activated} fully activated · ${d.topPrograms.length} programs ranked)`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error('FATAL:', err);
    process.exit(1);
  });
}

module.exports = { computeDashboardData, renderHtml, fetchAll };

// ===========================================================================
// HTML template — CSS / layout / Chart.js config are byte-for-byte from the
// original template. Only data arrays + KPI values are interpolated (${...}).
// PLACEHOLDERS (GA4, not Supabase): "Site visitors", the conversion badge,
// "Traffic & reach" tables (sources + geo), and the events strip. These are
// intentionally left as static numbers — update them from GA4 if needed.
// ===========================================================================
function renderHtml(d) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LDP Scout — Pilot Analytics</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --green:   #2D4A3E;
    --teal:    #4A8C7F;
    --teal-lt: #7BB5A8;
    --cream:   #F4F1EB;
    --cream2:  #EDE9E1;
    --sand:    #E5E0D5;
    --text:    #1C2B26;
    --text2:   #4A5E58;
    --text3:   #8A9E98;
    --border:  #D8D2C6;
    --white:   #FDFCF9;
    --warn:    #C0562A;
    --warn-bg: #FDF0EB;
    --good:    #2D7A4F;
    --good-bg: #EBF5EF;
    --serif:   'Playfair Display', Georgia, serif;
    --sans:    'DM Sans', system-ui, sans-serif;
  }

  body { font-family: var(--sans); background: var(--cream); color: var(--text); line-height: 1.5; min-height: 100vh; }

  .dash-header { background: var(--green); padding: 28px 48px 24px; display: flex; align-items: flex-end; justify-content: space-between; border-bottom: 3px solid var(--teal); }
  .dash-logo { display: flex; align-items: baseline; gap: 6px; }
  .dash-logo-ldp { font-family: var(--sans); font-weight: 600; font-size: 20px; color: #fff; letter-spacing: -0.02em; }
  .dash-logo-scout { font-family: var(--serif); font-style: italic; font-size: 20px; color: var(--teal-lt); }
  .dash-title { font-family: var(--serif); font-size: 26px; font-weight: 400; color: #fff; margin-top: 4px; }
  .dash-subtitle { font-size: 13px; color: var(--teal-lt); margin-top: 2px; }
  .dash-date { font-size: 12px; color: var(--teal-lt); text-align: right; }
  .dash-date strong { display: block; font-size: 15px; color: #fff; font-weight: 500; }

  .dash-body { max-width: 1280px; margin: 0 auto; padding: 36px 40px 60px; }

  .context-note { background: var(--green); margin: 0 0 28px; border-radius: 10px; overflow: hidden; }
  .context-note-inner { padding: 28px 32px 24px; }
  .context-eyebrow { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; color: var(--teal-lt); margin-bottom: 12px; }
  .context-body { font-size: 14px; color: rgba(255,255,255,0.85); line-height: 1.7; max-width: 820px; margin-bottom: 10px; }
  .context-body:last-of-type { margin-bottom: 16px; }
  .context-cta { display: inline-block; font-size: 13px; font-weight: 600; color: #fff; background: var(--teal); padding: 8px 18px; border-radius: 6px; text-decoration: none; transition: opacity .15s; }
  .context-cta:hover { opacity: .85; }

  .kpi-row { display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px; margin-bottom: 28px; }
  .kpi-card { background: var(--white); border: 1px solid var(--border); border-radius: 10px; padding: 18px 18px 16px; position: relative; overflow: hidden; }
  .kpi-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--teal); }
  .kpi-card.accent::before { background: var(--green); }
  .kpi-card.good::before   { background: var(--good); }
  .kpi-label { font-size: 10.5px; font-weight: 500; text-transform: uppercase; letter-spacing: .06em; color: var(--text3); margin-bottom: 8px; }
  .kpi-value { font-family: var(--serif); font-size: 36px; font-weight: 600; color: var(--text); line-height: 1; }
  .kpi-sub   { font-size: 11.5px; color: var(--text2); margin-top: 6px; line-height: 1.4; }
  .kpi-badge { display: inline-block; font-size: 10.5px; font-weight: 600; padding: 2px 8px; border-radius: 20px; margin-top: 6px; }
  .kpi-badge.good { background: var(--good-bg); color: var(--good); }

  .section-label { font-family: var(--serif); font-style: italic; font-size: 18px; color: var(--green); margin-bottom: 14px; display: flex; align-items: center; gap: 10px; }
  .section-label::after { content: ''; flex: 1; height: 1px; background: var(--border); }

  .chart-row { display: grid; grid-template-columns: 1.6fr 1fr; gap: 20px; margin-bottom: 28px; }
  .chart-card { background: var(--white); border: 1px solid var(--border); border-radius: 10px; padding: 24px 26px; }
  .chart-card-title { font-size: 13px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 18px; }
  .chart-wrap { position: relative; }

  .funnel { display: flex; flex-direction: column; gap: 12px; padding-top: 4px; }
  .funnel-item { display: flex; align-items: center; gap: 12px; }
  .funnel-label { font-size: 12px; color: var(--text2); width: 155px; flex-shrink: 0; }
  .funnel-bar-wrap { flex: 1; background: var(--cream2); border-radius: 4px; height: 28px; overflow: hidden; }
  .funnel-bar { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 10px; transition: width .6s ease; }
  .funnel-bar span { font-size: 12px; font-weight: 600; color: #fff; white-space: nowrap; }
  .funnel-pct { font-size: 13px; font-weight: 600; color: var(--text); width: 42px; text-align: right; flex-shrink: 0; }
  .fb-1 { background: var(--sand); } .fb-1 span { color: var(--text2); }
  .fb-2 { background: var(--teal-lt); }
  .fb-3 { background: var(--teal); }
  .fb-4 { background: var(--green); }

  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }

  .power-card { background: var(--white); border: 1px solid var(--border); border-radius: 10px; padding: 22px 24px; margin-bottom: 28px; }
  .power-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-top: 16px; }
  .power-item { background: var(--cream); border-radius: 8px; padding: 14px 14px 12px; text-align: center; }
  .power-name { font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 8px; min-height: 36px; line-height: 1.3; }
  .power-stat { font-family: var(--serif); font-size: 30px; color: var(--green); font-weight: 600; line-height: 1; }
  .power-lbl { font-size: 10.5px; color: var(--text3); margin-top: 4px; text-transform: uppercase; letter-spacing: .05em; }

  .table-card { background: var(--white); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  .table-card-header { padding: 16px 22px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
  .table-card-header h3 { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: var(--text2); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th { padding: 10px 16px; text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: var(--text3); background: var(--cream); border-bottom: 1px solid var(--border); white-space: nowrap; }
  tbody tr { border-bottom: 1px solid var(--cream2); transition: background .1s; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--cream); }
  tbody td { padding: 10px 16px; color: var(--text); vertical-align: middle; }
  .td-muted { color: var(--text3); font-size: 12px; }
  .td-right { text-align: right; }

  .pill { display: inline-block; font-size: 10.5px; font-weight: 600; padding: 2px 9px; border-radius: 20px; white-space: nowrap; }
  .pill-green  { background: var(--good-bg); color: var(--good); }
  .pill-teal   { background: #E5F2EF;        color: var(--teal); }
  .pill-orange { background: var(--warn-bg); color: var(--warn); }
  .pill-grey   { background: var(--cream2);  color: var(--text2); }
  .pill-sand   { background: var(--sand);    color: var(--text2); }

  .prog-bar-wrap { display: flex; align-items: center; gap: 8px; }
  .prog-bar-track { flex: 1; height: 6px; background: var(--cream2); border-radius: 3px; min-width: 60px; }
  .prog-bar-fill  { height: 100%; border-radius: 3px; background: var(--teal); }

  .onb-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; padding: 18px 22px 20px; }
  .onb-item { text-align: center; padding: 14px 10px; background: var(--cream); border-radius: 8px; }
  .onb-num  { font-family: var(--serif); font-size: 32px; color: var(--green); font-weight: 600; line-height: 1; }
  .onb-lbl  { font-size: 11px; color: var(--text2); margin-top: 5px; font-weight: 500; }

  .user-table-wrap { margin-bottom: 28px; }
  .dot-yes { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--good); margin-right: 5px; vertical-align: middle; }
  .dot-no  { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--border); margin-right: 5px; vertical-align: middle; }
  .app-tags { display: flex; flex-wrap: wrap; gap: 3px; max-width: 380px; }
  .app-tag  { font-size: 10px; background: var(--cream); border: 1px solid var(--border); border-radius: 3px; padding: 1px 6px; color: var(--text2); white-space: nowrap; }

  .kicker { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--cream2); font-size: 11.5px; color: var(--text2); line-height: 1.7; }
  .kicker strong { color: var(--green); }

  .dash-footer { text-align: center; padding: 16px; font-size: 11.5px; color: var(--text3); border-top: 1px solid var(--border); margin-top: 8px; }

  @media (max-width: 1100px) {
    .kpi-row { grid-template-columns: repeat(3, 1fr); }
    .power-grid { grid-template-columns: repeat(2, 1fr); }
    .chart-row, .two-col { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="dash-header">
  <div>
    <div class="dash-logo">
      <span class="dash-logo-ldp">LDP</span>
      <span class="dash-logo-scout">Scout</span>
    </div>
    <div class="dash-title">Pilot Analytics</div>
    <div class="dash-subtitle">${d.cohortWindow}</div>
  </div>
  <div class="dash-date">
    <strong>${d.todayLabel}</strong>
    ${d.totalUsers} users · ${d.cohortDays} days of data
  </div>
</div>

<div class="dash-body">

  <div class="context-note">
    <div class="context-note-inner">
      <div class="context-eyebrow">A note from Shrey</div>
      <p class="context-body">
        LDP Scout is a tool I built for ESADE MBA students navigating Leadership Development Program applications. It brings together a verified catalog of MBA-specific LDPs across Europe and beyond, résumé-based fit scoring, alumni search, and deadline tracking — all in one place.
      </p>
      <p class="context-body">
        ${d.contextNarrative}
      </p>
      <p class="context-body">
        I'm sharing this with you to keep you in the loop, and to explore whether LDP Scout could be something the Careers team feels comfortable pointing students toward — particularly those asking about LDP applications. Happy to walk you through the product directly if that's easier.
      </p>
      <a href="https://ldpscout.com" class="context-cta" target="_blank">Visit ldpscout.com →</a>
    </div>
  </div>

  <div class="section-label">Headline metrics</div>
  <div class="kpi-row">
    <div class="kpi-card">
      <div class="kpi-label">Site visitors</div>
      <div class="kpi-value">56</div>
      <div class="kpi-sub">Unique users since launch <span style="color:var(--text3)">(GA4)</span></div>
    </div>
    <div class="kpi-card accent">
      <div class="kpi-label">Signups</div>
      <div class="kpi-value">${d.totalUsers}</div>
      <span class="kpi-badge good">50% conversion</span>
      <div class="kpi-sub">${d.schoolSub}</div>
    </div>
    <div class="kpi-card good">
      <div class="kpi-label">Fully activated</div>
      <div class="kpi-value">${d.activated}</div>
      <span class="kpi-badge good">${d.activatedPct}% of signups</span>
      <div class="kpi-sub">Scanned + logged app</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Résumé uploaded</div>
      <div class="kpi-value">${d.resumesUploaded}</div>
      <div class="kpi-sub">${d.resumesPct}% of signups · ${d.scansCompleted} scans run</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Applications logged</div>
      <div class="kpi-value">${d.appsLogged}</div>
      <div class="kpi-sub">Avg ${d.avgPerActive} per active user</div>
    </div>
    <div class="kpi-card good">
      <div class="kpi-label">Median time to scan</div>
      <div class="kpi-value">${d.medVal}<span style="font-size:18px;font-weight:400;color:var(--text2)"> ${d.medUnit}</span></div>
      <div class="kpi-sub">From signup to first AI scan</div>
    </div>
  </div>

  <div class="section-label">Acquisition &amp; activation</div>
  <div class="chart-row">
    <div class="chart-card">
      <div class="chart-card-title">Daily signups since launch</div>
      <div class="chart-wrap" style="height:230px"><canvas id="signupChart"></canvas></div>
      <div class="kicker">
        ${d.signupKicker}
      </div>
    </div>
    <div class="chart-card">
      <div class="chart-card-title">Activation funnel</div>
      <div class="funnel">
${d.funnelHtml}
      </div>
      <div class="kicker">
        ${d.funnelKicker}
      </div>
    </div>
  </div>

  <div class="section-label">Traffic &amp; reach <span style="font-family:var(--sans);font-style:normal;font-size:11px;color:var(--text3);font-weight:400">· GA4 placeholder data</span></div>
  <div class="two-col">
    <div class="table-card">
      <div class="table-card-header"><h3>Where users came from</h3></div>
      <table>
        <thead><tr><th>Source</th><th class="td-right">Users</th><th class="td-right">Share</th></tr></thead>
        <tbody>
          <tr><td><strong>Direct</strong> <span class="td-muted" style="font-size:11px">(WhatsApp, typed URL)</span></td><td class="td-right"><strong>53</strong></td><td class="td-right">94.6%</td></tr>
          <tr><td><strong>Google</strong> <span class="td-muted" style="font-size:11px">organic search</span></td><td class="td-right">2</td><td class="td-right">3.6%</td></tr>
          <tr><td><strong>Teams</strong> <span class="td-muted" style="font-size:11px">link preview</span></td><td class="td-right">1</td><td class="td-right">1.8%</td></tr>
        </tbody>
      </table>
      <div style="padding:12px 16px;font-size:11.5px;color:var(--text2);border-top:1px solid var(--cream2);line-height:1.6">
        <strong style="color:var(--green)">95% direct</strong> traffic confirms the WhatsApp invite was the primary acquisition channel. WhatsApp strips referrer headers, so it appears as "direct" in analytics.
      </div>
    </div>

    <div class="table-card">
      <div class="table-card-header"><h3>Where users are located</h3></div>
      <table>
        <thead><tr><th>Country</th><th class="td-right">Users</th><th>Distribution</th></tr></thead>
        <tbody id="geo-tbody"></tbody>
      </table>
      <div style="padding:12px 16px;font-size:11.5px;color:var(--text2);border-top:1px solid var(--cream2);line-height:1.6">
        Reflects ESADE's international cohort. US traffic (9 visitors) is excluded — most resolves to AWS infrastructure scanning, not real users.
      </div>
    </div>
  </div>

  <div class="table-card" style="margin-bottom:28px;padding:18px 24px;display:grid;grid-template-columns:repeat(4,1fr);gap:12px;align-items:center">
    <div>
      <div class="kpi-label" style="margin-bottom:4px">Total events tracked</div>
      <div style="font-family:var(--serif);font-size:24px;color:var(--green);font-weight:600;line-height:1">631</div>
    </div>
    <div>
      <div class="kpi-label" style="margin-bottom:4px">Tab views</div>
      <div style="font-family:var(--serif);font-size:24px;color:var(--green);font-weight:600;line-height:1">158 <span style="font-size:12px;color:var(--text3);font-family:var(--sans);font-weight:400">· 2.8 per user</span></div>
    </div>
    <div>
      <div class="kpi-label" style="margin-bottom:4px">Avg engagement</div>
      <div style="font-family:var(--serif);font-size:24px;color:var(--green);font-weight:600;line-height:1">2m 17s <span style="font-size:12px;color:var(--text3);font-family:var(--sans);font-weight:400">per user</span></div>
    </div>
    <div>
      <div class="kpi-label" style="margin-bottom:4px">First visits captured</div>
      <div style="font-family:var(--serif);font-size:24px;color:var(--green);font-weight:600;line-height:1">56 <span style="font-size:12px;color:var(--text3);font-family:var(--sans);font-weight:400">unique sessions</span></div>
    </div>
  </div>

  <div class="section-label">Power users</div>
  <div class="power-card">
    <div style="font-size:12.5px;color:var(--text2);line-height:1.6">
      ${d.powerIntro}
    </div>
    <div class="power-grid">
${d.powerItemsHtml}
    </div>
  </div>

  <div class="section-label">Cohort breakdown</div>
  <div class="two-col">
    <div class="table-card">
      <div class="table-card-header"><h3>By school</h3></div>
      <table>
        <thead>
          <tr><th>School</th><th class="td-right">Users</th><th class="td-right">Uploaded</th><th class="td-right">Scanned</th><th class="td-right">Logged app</th></tr>
        </thead>
        <tbody>
${d.schoolRowsHtml}
        </tbody>
      </table>
      <div style="padding:12px 16px;font-size:11.5px;color:var(--text2);border-top:1px solid var(--cream2)">
        Cohort breakdown by detected school. Rows marked <strong style="color:var(--text3)">Unattributed</strong> signed up but their school field didn't resolve — usually a profile-detection edge case.
      </div>
    </div>

    <div class="table-card">
      <div class="table-card-header"><h3>Onboarding status</h3></div>
      <div class="onb-grid">
        <div class="onb-item"><div class="onb-num">${d.onbCompleted}</div><div class="onb-lbl">Completed</div></div>
        <div class="onb-item"><div class="onb-num" style="color:var(--warn)">${d.onbSkipped}</div><div class="onb-lbl">Skipped</div></div>
        <div class="onb-item"><div class="onb-num" style="color:var(--text3)">${d.onbIncomplete}</div><div class="onb-lbl">Incomplete</div></div>
      </div>
      <div style="padding:0 22px 18px;font-size:11.5px;color:var(--text2);line-height:1.7">
        <strong>Completed</strong> = stepped through the full onboarding flow.<br>
        <strong>Skipped</strong> = dismissed the flow on entry.<br>
        <strong>Incomplete</strong> = abandoned mid-flow.<br>
        <span style="color:var(--text3);font-style:italic">${d.skipPct}% skip rate — worth a copy revisit if the value of onboarding isn't clear pre-entry.</span>
      </div>
    </div>
  </div>

  <div class="section-label">Most-tracked programs</div>
  <div class="table-card" style="margin-bottom:28px">
    <div class="table-card-header">
      <h3>Programs by user count</h3>
      <span style="font-size:12px;color:var(--text3)">${d.customNote}</span>
    </div>
    <table>
      <thead><tr><th>#</th><th>Company</th><th>Program</th><th>Function</th><th>Geography</th><th>Users tracking</th></tr></thead>
      <tbody id="prog-tbody"></tbody>
    </table>
    <div style="padding:12px 22px;font-size:11.5px;color:var(--text2);border-top:1px solid var(--cream2);line-height:1.6">
      ${d.progFooter}
    </div>
  </div>

  <div class="section-label">Individual user activity</div>
  <div class="table-card user-table-wrap">
    <div class="table-card-header"><h3>All ${d.totalUsers} users — ordered by signup date</h3></div>
    <div style="overflow-x:auto">
      <table>
        <thead><tr><th>Name</th><th>School</th><th>Signed up</th><th>Onboarding</th><th>Résumé</th><th>Scans</th><th>Apps</th><th>Programs tracked</th></tr></thead>
        <tbody id="user-tbody"></tbody>
      </table>
    </div>
  </div>

</div>

<div class="dash-footer">${d.footerLine}</div>

<script>
const signupsByDay = ${JSON.stringify(d.signupsByDay)};

const topPrograms = ${JSON.stringify(d.topPrograms)};

const users = ${JSON.stringify(d.users)};

new Chart(document.getElementById('signupChart').getContext('2d'), {
  type: 'bar',
  data: {
    labels: signupsByDay.map(d => d.date),
    datasets: [{
      data: signupsByDay.map(d => d.count),
      backgroundColor: signupsByDay.map(d => d.note === 'reminder' ? '#2D4A3E' : '#7BB5A8'),
      borderRadius: 4,
      borderSkipped: false,
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: ctx => \` \${ctx.raw} user\${ctx.raw !== 1 ? 's' : ''}\`,
          title: ctx => ctx[0].label + (signupsByDay[ctx[0].dataIndex] && signupsByDay[ctx[0].dataIndex].note === 'reminder' ? ' — launch reminder' : '')
        }
      }
    },
    scales: {
      x: { grid: { display: false }, ticks: { font: { family: "'DM Sans'", size: 11 }, color: '#8A9E98' } },
      y: { grid: { color: '#EDE9E1' }, ticks: { stepSize: 2, font: { family: "'DM Sans'", size: 11 }, color: '#8A9E98' }, border: { display: false } }
    }
  }
});

const geoData = [
  { country:'Spain',   users:20 },
  { country:'India',   users:14 },
  { country:'Nigeria', users:4  },
  { country:'Ireland', users:3  },
  { country:'UK',      users:2  },
  { country:'France',  users:1  },
];
const geoMax = Math.max(...geoData.map(g => g.users));
const geoTbody = document.getElementById('geo-tbody');
geoData.forEach(g => {
  const width = (g.users / geoMax) * 100;
  geoTbody.innerHTML += \`<tr>
    <td><strong>\${g.country}</strong></td>
    <td class="td-right"><strong>\${g.users}</strong></td>
    <td><div class="prog-bar-wrap" style="max-width:160px"><div class="prog-bar-track"><div class="prog-bar-fill" style="width:\${width}%"></div></div></div></td>
  </tr>\`;
});

const progTbody = document.getElementById('prog-tbody');
const maxUsers = Math.max(...topPrograms.map(p => p.users));
topPrograms.forEach(p => {
  const width = (p.users / maxUsers) * 100;
  progTbody.innerHTML += \`<tr>
    <td class="td-muted">\${p.rank}</td>
    <td><strong>\${p.company}</strong></td>
    <td>\${p.name}</td>
    <td><span class="pill pill-teal">\${p.fn}</span></td>
    <td><span class="pill pill-sand">\${p.geo}</span></td>
    <td><div class="prog-bar-wrap"><div class="prog-bar-track"><div class="prog-bar-fill" style="width:\${width}%"></div></div><span style="font-size:13px;font-weight:600;color:var(--text);min-width:14px;text-align:right">\${p.users}</span></div></td>
  </tr>\`;
});

const userTbody = document.getElementById('user-tbody');
users.forEach(u => {
  const onbPill = u.onb === 'Completed' ? 'pill-green' : u.onb === 'Skipped' ? 'pill-orange' : 'pill-grey';
  const schoolPill = u.school === 'esade' ? 'pill-teal' : u.school === 'edhec' ? 'pill-green' : 'pill-sand';
  const progHtml = u.programs.length
    ? \`<div class="app-tags">\${u.programs.map(p => \`<span class="app-tag">\${p}</span>\`).join('')}</div>\`
    : \`<span class="td-muted">—</span>\`;
  userTbody.innerHTML += \`<tr>
    <td><strong>\${u.name}</strong></td>
    <td><span class="pill \${schoolPill}">\${u.school}</span></td>
    <td class="td-muted">\${u.date}</td>
    <td><span class="pill \${onbPill}">\${u.onb}</span></td>
    <td>\${u.resume === 'Yes' ? '<span class="dot-yes"></span>Yes' : '<span class="dot-no"></span>No'}</td>
    <td style="font-weight:\${u.scans>0?'600':'400'};color:\${u.scans>0?'var(--green)':'var(--text3)'}">\${u.scans}</td>
    <td style="font-weight:\${u.apps>0?'600':'400'};color:\${u.apps>0?'var(--green)':'var(--text3)'}">\${u.apps || '—'}</td>
    <td>\${progHtml}</td>
  </tr>\`;
});
</script>
</body>
</html>
`;
}

@echo off
REM Wrapper for the daily scheduled dashboard regen (see grant_service_role.sql / CHANGES_TASK_DASHBOARD.md).
REM Reads SUPABASE_SERVICE_KEY from the user environment (set once via: setx SUPABASE_SERVICE_KEY "<key>").
REM Logs each run to dashboard-gen.log (gitignored). %~dp0 = this file's folder, so it works from any cwd.
cd /d "%~dp0"
REM Fallback: if the scheduled-task host didn't inherit the env var, read the persisted User-scope value.
if "%SUPABASE_SERVICE_KEY%"=="" for /f "usebackq delims=" %%K in (`powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable('SUPABASE_SERVICE_KEY','User')"`) do set "SUPABASE_SERVICE_KEY=%%K"
echo. >> dashboard-gen.log
echo [%date% %time%] running generate-dashboard.js >> dashboard-gen.log
node generate-dashboard.js >> dashboard-gen.log 2>&1

username is: admin
password is: 123456

These are questions for developing the audit module that need to be answered by me
Critical Questions:

  1. Inline vs Online Modes - What's the difference?

  - Inline: Does this mean we read a config file that the user uploads (offline analysis)?
  - Online: Does this mean we connect via SSH in real-time and run commands?

  Or does it mean something else?

  ---
  2. Service Menu - Same workflow?

  For services (Apache, IIS, Active Directory, SQL Server):
  - Do we also SSH into a server and run commands to check these services?
  - Or is this a different type of check?

  Example: If user selects "Apache", do we:
  - SSH into a Linux server → Run httpd -V, check Apache config files?
  - Or something different?

  ---
  3. SSH Credentials - Storage?

  - Option A: User enters username/password each time (not stored)
  - Option B: Store credentials encrypted in database for reuse
  - Which do you prefer?

  ---
  4. CIS Templates - Predefined or Customizable?

  - Should we have built-in CIS benchmarks (e.g., CIS Cisco IOS Benchmark v4.1.1) that users cannot modify?
  - Or should users be able to create/edit their own security checks?

  ---
  5. Audit History - Track Multiple Runs?

  - Should we keep history of audits? (e.g., "Run on Dec 10 - 45 passed, 5 failed", "Run on Dec 14 - 47 passed, 3 failed")
  - Or just show the latest result only?

  ---
  6. Results Display - What Details?

  When showing the CIS table with green/red indicators, should we show:
  - ✅ Check number (e.g., "1.1.1")
  - ✅ Check description (e.g., "Ensure password encryption is enabled")
  - ✅ Status (Pass/Fail) with green/red color
  - ✅ Actual command output (what the device returned)?
  - ✅ Expected output (what it should be)?
  - ✅ Severity level (Critical/High/Medium/Low)?

  Which of these do you want?


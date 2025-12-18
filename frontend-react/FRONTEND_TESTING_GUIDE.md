# Frontend Testing Guide - CIS Benchmark Table

## Quick Testing Without Cisco Device

You can now test the CIS Benchmark table feature without needing a real Cisco device or SSH connection.

## Steps to Test

### 1. Start the Frontend

```bash
cd /home/zi/Desktop/main_app/netease/frontend-react
npm run dev
```

### 2. Navigate to Auditing Page

- Open browser and go to: `http://localhost:5173` (or your dev server URL)
- Log in with test credentials (admin/123456)
- Click on **Auditing** in the navigation menu

### 3. Load Demo Data

Instead of filling in asset and credentials, simply click the **"Load Demo Data"** button.

This will:
- Load a simulated audit session with 82 CIS checks
- Show compliance score of 90.24% (74 passed, 8 failed)
- Populate both "Detailed View" and "CIS Benchmark Table" views

### 4. Test View Toggle

After loading demo data, you'll see two toggle buttons:
- **Detailed View**: Shows traditional audit results table
- **CIS Benchmark Table**: Shows CIS format with Yes/No checkboxes

Click each button to switch between views.

### 5. Verify CIS Benchmark Table Features

In the CIS Benchmark Table view, verify:

#### Header Section
- Benchmark version: "CIS Cisco IOS 15 Benchmark v4.1.1"
- Asset name: "Demo-CoreSwitch"
- IP address: "192.168.100.1"
- Audit date and time

#### Summary Cards
- **Compliance**: 90.2% (green badge)
- **Passed**: 74 checks
- **Failed**: 8 checks
- **Total**: 82 checks

#### Table Format
- Section numbers (1.1.1, 1.1.2, etc.)
- Recommendation text
- Set Correctly column with:
  - ☑ Yes (green background) - for passed checks
  - ☐ No (red background) - for failed checks
  - \- N/A (gray) - for not applicable

#### Failed Rows Highlighting
Failed checks (☐ No) should have a light red row background.

Example failed checks in demo data:
- Section 1.1.3: Enable 'aaa authentication enable default'
- Section 1.1.8: Set 'aaa accounting connection'
- Section 1.1.9: Set 'aaa accounting exec'
- Section 1.1.10: Set 'aaa accounting network'
- Section 1.2.4: Set 'access-class' for 'line vty'
- Section 1.3.1: Set 'banner exec'
- Section 2.1.1.1.5: Set SSH timeout to 60 seconds
- Section 2.2.1: Set 'logging on'

## Demo Data Details

The demo data includes:

### Mock Audit Session
```javascript
{
  session_id: 999,
  asset_name: "Demo-CoreSwitch",
  target_ip: "192.168.100.1",
  device_type: "cisco_ios",
  status: "completed",
  compliance: {
    total_checks: 82,
    passed: 74,
    failed: 8,
    errors: 0,
    compliance_pct: 90.24,
    weighted_compliance_pct: 92.15
  }
}
```

### All 82 CIS Sections
The mock data includes all sections from the official CIS Benchmark:
- **Section 1**: Management Plane (31 checks)
- **Section 2**: Control Plane (26 checks)
- **Section 3**: Data Plane (25 checks)

## Files Modified for Demo Mode

1. **`src/pages/Auditing/Auditing.jsx`**
   - Added `handleLoadDemoData()` function
   - Added "Load Demo Data" button
   - Imports mock data from `mockCISData.js`

2. **`src/pages/Auditing/CISBenchmarkTable.jsx`**
   - Detects session ID 999 as demo mode
   - Uses `mockCISTable` data instead of API call

3. **`src/pages/Auditing/mockCISData.js`**
   - Contains complete mock audit session
   - Contains 40 sample detailed results
   - Contains all 82 CIS sections with realistic pass/fail distribution

## Testing Real API (When Available)

When you have access to a real Cisco device:

1. Select an asset from the dropdown
2. Enter SSH credentials
3. Click **"Execute Audit"** button
4. Wait for audit to complete
5. Switch to "CIS Benchmark Table" view

The real API endpoint is: `GET /api/audit/sessions/{session_id}/cis-table`

## Color Coding Reference

### Compliance Badges
- **Green** (#28a745): ≥90% compliance - Excellent
- **Yellow** (#ffc107): 70-89% compliance - Good
- **Red** (#dc3545): <70% compliance - Needs attention

### Checkboxes
- **☑ Yes**: Green background (#d4edda) - Check passed
- **☐ No**: Red background (#f8d7da), row highlighted - Check failed
- **\- N/A**: Gray background (#e2e3e5) - Not applicable

## Browser Compatibility

Tested and working on:
- Chrome 120+
- Firefox 120+
- Safari 17+
- Edge 120+

## Print/Export

The CIS Benchmark Table is print-ready:
1. Switch to "CIS Benchmark Table" view
2. Use browser print (Ctrl+P / Cmd+P)
3. Select "Save as PDF" or print directly

The table layout is optimized for A4/Letter paper sizes.

## Troubleshooting

### Issue: "Load Demo Data" button doesn't work
**Solution**: Check browser console for errors. Make sure `mockCISData.js` is in the same directory.

### Issue: CIS table shows "Loading..."
**Solution**: Demo mode uses session ID 999. Verify the session_id in state is 999.

### Issue: No checkboxes showing
**Solution**: Check if `set_correctly` values are boolean (true/false) or null.

## Next Steps

After verifying the frontend works with demo data, you can:
1. Deploy to the server (172.16.200.90)
2. Test with real Cisco devices
3. Generate PDF reports
4. Add email notification features
5. Implement scheduled audits

---

**Quick Start Command**:
```bash
cd /home/zi/Desktop/main_app/netease/frontend-react
npm run dev
# Then click "Load Demo Data" button in Auditing page
```

# Visual Testing Guide - Multi-Device Audit Selection

## What You'll See in the Browser

### 1. Device Type Dropdown (Top of Form)
```
┌─────────────────────────────────────────────────────────┐
│ Device Type *                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Cisco Router/Switch                               ▼ │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

Dropdown options:
  • Cisco Router/Switch
  • FortiGate Firewall
  • Linux Server (Coming Soon)        [DISABLED]
  • Windows Server (Coming Soon)      [DISABLED]
  • Apache Web Server (Coming Soon)   [DISABLED]
```

---

### 2. When "Cisco Router/Switch" is Selected

```
┌─────────────────────────────────────────────────────────┐
│ Device Type *                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Cisco Router/Switch                               ▼ │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────┐ ┌─────────────────────────┐
│ Select Asset *              │ │ Job Name *              │
│ ┌─────────────────────────┐ │ │ ┌─────────────────────┐ │
│ │ select                ▼ │ │ │ │                     │ │
│ └─────────────────────────┘ │ │ └─────────────────────┘ │
└─────────────────────────────┘ └─────────────────────────┘

┌─────────────────────────────┐ ┌─────────────────────────┐
│ Username *                  │ │ Enable Password         │
│ ┌─────────────────────────┐ │ │ ┌─────────────────────┐ │
│ │ SSH username           │ │ │ │ ••••••••            │ │
│ └─────────────────────────┘ │ │ └─────────────────────┘ │
└─────────────────────────────┘ └─────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Password *                                              │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ ••••••••                                            │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

                    [cancel]  [Next]
```

---

### 3. When "FortiGate Firewall" is Selected

```
┌─────────────────────────────────────────────────────────┐
│ Device Type *                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ FortiGate Firewall                                ▼ │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────┐ ┌─────────────────────────┐
│ Select Asset *              │ │ Job Name *              │
│ ┌─────────────────────────┐ │ │ ┌─────────────────────┐ │
│ │ select                ▼ │ │ │ │                     │ │
│ └─────────────────────────┘ │ │ └─────────────────────┘ │
└─────────────────────────────┘ └─────────────────────────┘

┌─────────────────────────────┐ ┌─────────────────────────┐
│ Username *                  │ │ VDOM (Optional)         │
│ ┌─────────────────────────┐ │ │ ┌─────────────────────┐ │
│ │ SSH username           │ │ │ │ Virtual Domain      │ │
│ └─────────────────────────┘ │ │ └─────────────────────┘ │
└─────────────────────────────┘ └─────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Password *                                              │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ ••••••••                                            │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

                    [cancel]  [Next]
```

**Key Difference:** "Enable Password" is replaced with "VDOM (Optional)"

---

### 4. When "Linux Server" is Selected (or Windows/Apache)

```
┌─────────────────────────────────────────────────────────┐
│ Device Type *                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Linux Server (Coming Soon)                        ▼ │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────┐ ┌─────────────────────────┐
│ Select Asset *              │ │ Job Name *              │
│ ┌─────────────────────────┐ │ │ ┌─────────────────────┐ │
│ │ select                ▼ │ │ │ │                     │ │
│ └─────────────────────────┘ │ │ └─────────────────────┘ │
└─────────────────────────────┘ └─────────────────────────┘

╔═════════════════════════════════════════════════════════╗
║                    ⚠️ WARNING                           ║
║                                                         ║
║  🚧 Linux Server auditing is coming soon!              ║
║                                                         ║
║  Please select Cisco or FortiGate for now.             ║
╚═════════════════════════════════════════════════════════╝
  Yellow/amber background with warning icon
```

**No credential fields shown** - Just the warning message

---

## Test Checklist

### ✅ Visual Tests

1. **Device Type Dropdown**
   - [ ] Dropdown appears at the top of the form
   - [ ] Shows all 5 device types
   - [ ] Unimplemented devices show "(Coming Soon)"
   - [ ] Unimplemented devices are grayed out/disabled

2. **Cisco Selection**
   - [ ] Username field appears
   - [ ] Password field appears (full width)
   - [ ] Enable Password field appears
   - [ ] All fields have proper labels
   - [ ] Required fields marked with red asterisk

3. **FortiGate Selection**
   - [ ] Username field appears
   - [ ] Password field appears (full width)
   - [ ] VDOM field appears (not Enable Password)
   - [ ] VDOM shows proper placeholder text
   - [ ] VDOM is not marked as required

4. **Linux/Windows/Apache Selection**
   - [ ] Coming soon message appears
   - [ ] Message has yellow/amber background
   - [ ] Message shows construction emoji 🚧
   - [ ] Message shows device type name
   - [ ] No credential fields shown
   - [ ] Submit button should be blocked

5. **Field Switching**
   - [ ] Switch from Cisco to FortiGate → Fields update immediately
   - [ ] Switch from Cisco to Linux → Warning message appears
   - [ ] Switch from Linux back to Cisco → Fields reappear
   - [ ] Field values are preserved when switching back

### ✅ Functional Tests

6. **Validation**
   - [ ] Cannot submit without selecting asset (Cisco/FortiGate)
   - [ ] Cannot submit without job name (Cisco/FortiGate)
   - [ ] Cannot submit without username (Cisco/FortiGate)
   - [ ] Cannot submit without password (Cisco/FortiGate)
   - [ ] Can submit without Enable Password (Cisco)
   - [ ] Can submit without VDOM (FortiGate)
   - [ ] Cannot submit Linux/Windows/Apache (shows error)

7. **API Routing**
   - [ ] Cisco audit hits: `/api/audit/cisco/execute`
   - [ ] FortiGate audit hits: `/api/fortinet/audit/execute`
   - [ ] Check browser Network tab for correct endpoint

8. **Form Submission**
   - [ ] Cisco audit starts successfully
   - [ ] FortiGate audit starts successfully
   - [ ] Proper data sent to backend
   - [ ] Progress indicator shows
   - [ ] Results display correctly

---

## Expected Browser Behavior

### Dropdown Interaction
- Click dropdown → All 5 options appear
- Hover over "Linux Server (Coming Soon)" → Grayed out, no hover effect
- Click on grayed out option → Does nothing (disabled)
- Click Cisco/FortiGate → Selection works normally

### Field Animation
- When switching device types:
  - Fields should disappear/appear smoothly
  - No layout jumping or flickering
  - Form maintains its overall structure
  - Coming soon message slides in when applicable

### Validation Feedback
- Empty required field + submit → Red border on field + error message below
- Invalid device type + submit → Error message under dropdown
- Fill required fields → Submit button becomes active

### API Communication
- Open browser DevTools (F12)
- Go to Network tab
- Submit Cisco audit → See POST to `/api/audit/cisco/execute`
- Submit FortiGate audit → See POST to `/api/fortinet/audit/execute`
- Check request payload → Includes device-specific fields

---

## Common Issues to Check

❌ **If dropdown doesn't show:**
- Check browser console for JavaScript errors
- Verify `deviceTypes` array is defined
- Check if React is rendering the component

❌ **If fields don't change:**
- Check `formData.device_type` is being updated
- Verify conditional rendering logic
- Check React state updates in browser DevTools

❌ **If coming soon message doesn't appear:**
- Verify array check: `["linux", "windows", "apache"].includes()`
- Check CSS class `.coming-soon-message` exists
- Inspect element to see if div is in DOM

❌ **If validation doesn't work:**
- Check `validate()` function runs on submit
- Verify conditional validation logic
- Check error state updates

❌ **If wrong API endpoint called:**
- Check Redux thunk endpoint logic
- Verify deviceType parameter passed correctly
- Check browser Network tab for actual request

---

## Success Criteria

✅ All 10 visual tests pass
✅ All 8 functional tests pass
✅ No console errors
✅ No layout issues
✅ Smooth user experience
✅ Correct API routing

---

## Screenshots to Capture

1. `device_dropdown_open.png` - Dropdown showing all 5 options
2. `cisco_form.png` - Form with Cisco selected
3. `fortigate_form.png` - Form with FortiGate selected
4. `linux_coming_soon.png` - Form with Linux + warning message
5. `validation_error.png` - Form with validation errors
6. `network_tab_cisco.png` - Network tab showing Cisco endpoint
7. `network_tab_fortigate.png` - Network tab showing FortiGate endpoint

---

**Testing URL:** http://localhost:5173
**Login:** admin / 123456
**Test Duration:** ~10 minutes for complete testing

Good luck with your testing! 🚀

# CIS Benchmark Frontend - UI Preview

## Auditing Page Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  Security Auditing - Cisco CIS Compliance                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ Execute Audit                                                  │  │
│  │                                                                │  │
│  │  [Select Asset ▼]  [SSH Username]  [SSH Password]  [Enable]   │  │
│  │                                                                │  │
│  │                                 [Execute Audit]                │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  [ Detailed View ]  [ CIS Benchmark Table ]  ← Toggle Buttons │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │  │
│  │  │ 95.1%    │  │ 95.7%    │  │    4     │  │    0     │      │  │
│  │  │Compliance│  │ Weighted │  │  Failed  │  │  Errors  │      │  │
│  │  │ 78 of 82 │  │  Score   │  │  Checks  │  │          │      │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │  │
│  │                                                                │  │
│  │  Asset: CoreSwitch01    IP: 192.168.1.1                       │  │
│  │  Date: 2025-12-18 10:30                                       │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## View 1: Detailed View (Default)

```
┌─────────────────────────────────────────────────────────────────────┐
│  Detailed Results (82 checks)                                        │
├──────────┬─────────┬────────────────────────────────┬─────────┬─────┤
│ Check ID │ Status  │ Check Title                    │Severity │Level│
├──────────┼─────────┼────────────────────────────────┼─────────┼─────┤
│IOS-L1-001│ ✓ PASS  │ Use 'enable secret' only       │  high   │ L1  │
│IOS-L1-002│ ✓ PASS  │ Console & VTY exec-timeout     │ medium  │ L1  │
│IOS-L1-003│ ✗ FAIL  │ VTY restricted by access-class │  high   │ L1  │
│IOS-L1-010│ ✓ PASS  │ Telnet disabled; SSH only      │  high   │ L1  │
│   ...    │   ...   │             ...                │   ...   │ ... │
└──────────┴─────────┴────────────────────────────────┴─────────┴─────┘
```

## View 2: CIS Benchmark Table

```
┌─────────────────────────────────────────────────────────────────────┐
│  CIS Cisco IOS 15 Benchmark v4.1.1                                   │
│  Asset: CoreSwitch01    IP: 192.168.1.1    Date: 2025-12-18        │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │  95.1%   │  │    78    │  │    4     │  │    82    │           │
│  │Compliance│  │  Passed  │  │  Failed  │  │  Total   │           │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────┬────────────────────────────────────┬──────────────┐   │
│  │ Section │ Recommendation                     │Set Correctly │   │
│  ├─────────┼────────────────────────────────────┼──────────────┤   │
│  │ 1.1.1   │ Enable 'aaa new-model'             │  ☑ Yes       │   │
│  │ 1.1.2   │ Enable 'aaa authentication login'  │  ☑ Yes       │   │
│  │ 1.1.3   │ Enable 'aaa auth enable default'   │  ☐ No        │   │
│  │ 1.1.4   │ Set 'login auth for 'line con 0'   │  ☑ Yes       │   │
│  │ 1.1.5   │ Set 'login auth for 'line tty'     │  ☑ Yes       │   │
│  │ 1.1.6   │ Set 'login auth for 'line vty'     │  ☑ Yes       │   │
│  │ 1.1.7   │ Set 'aaa accounting commands 15'   │  ☑ Yes       │   │
│  │ 1.1.8   │ Set 'aaa accounting connection'    │  ☐ No        │   │
│  │ 1.1.9   │ Set 'aaa accounting exec'          │  ☐ No        │   │
│  │ 1.1.10  │ Set 'aaa accounting network'       │  ☐ No        │   │
│  │ 1.1.11  │ Set 'aaa accounting system'        │  ☑ Yes       │   │
│  │ 1.2.1   │ Set 'privilege 1' for local users  │  ☑ Yes       │   │
│  │ 1.2.2   │ Set 'transport input ssh' for vty  │  ☑ Yes       │   │
│  │   ...   │              ...                   │    ...       │   │
│  │ 3.3.4.1 │ Set 'neighbor password'            │  ☑ Yes       │   │
│  └─────────┴────────────────────────────────────┴──────────────┘   │
│                                                                       │
│  [Rows with ☐ No are highlighted in light red]                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Color Scheme

### Compliance Badges
- **Green** (#28a745): ≥90% compliance
- **Yellow** (#ffc107): 70-89% compliance
- **Red** (#dc3545): <70% compliance

### Table Checkboxes
- **☑ Yes**: Green background (#d4edda)
- **☐ No**: Red background (#f8d7da), row highlighted
- **- N/A**: Gray background (#e2e3e5)

### Toggle Buttons
- **Active**: White background with shadow
- **Inactive**: Transparent, gray text
- **Hover**: Light gray background

## Mobile Responsive

```
┌──────────────────────┐
│ Security Auditing    │
├──────────────────────┤
│ [Select Asset ▼]     │
│ [Username]           │
│ [Password]           │
│ [Enable Secret]      │
│ [Execute Audit]      │
├──────────────────────┤
│ [Detailed View]      │
│ [CIS Benchmark Table]│
├──────────────────────┤
│ ┌──────┐ ┌──────┐   │
│ │95.1% │ │  78  │   │
│ │Score │ │Passed│   │
│ └──────┘ └──────┘   │
│ ┌──────┐ ┌──────┐   │
│ │  4   │ │  82  │   │
│ │Failed│ │Total │   │
│ └──────┘ └──────┘   │
├──────────────────────┤
│ 1.1.1  ☑ Yes        │
│ Enable 'aaa new...'  │
├──────────────────────┤
│ 1.1.2  ☑ Yes        │
│ Enable 'aaa auth...' │
└──────────────────────┘
```

## Key Features

1. **Simple Toggle** - One-click switch between views
2. **Color Coded** - Visual feedback for compliance levels
3. **Scrollable Table** - Sticky header for easy navigation
4. **Print Ready** - Clean layout for PDF export
5. **Lightweight** - No heavy frameworks, fast loading
6. **Responsive** - Works on all screen sizes

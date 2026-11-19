# CRISP Assessment Report

Generated: 2026-11-19 15:14:02.128723

Assessment ID: 2
Assessment Start: 2026-11-19 05:16:03.818844
Assessment End: 2026-11-19 05:34:35.453016
Assessment Status: Completed

## Assessment Summary

Assets Evaluated: 1230
Verified Findings: 20

## Verified Vulnerability Findings

### CVE-2025-24477

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS heap-based buffer overflow privilege escalation

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

A heap-based buffer overflow in FortiOS 7.2.4 through 7.2.12 (the NVD summary says 7.2.11) that lets an attacker escalate privileges.

**Affected Versions:**

- 7.2.4 to 7.2.12

**Supporting Evidence:**

- Vendor match: the asset vendor is Fortinet and the vulnerability affects Fortinet FortiOS.
- Platform relationship: FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Version applicability: asset version 7.2.10 is within the affected range 7.2.4 to 7.2.12 (inclusive per the provided start and end values).
- The conflicting upper bound (7.2.11 vs 7.2.12) does not affect this asset, because 7.2.10 falls below both values.
- CVE identifier provided: CVE-2025-24477, described as a heap-based buffer overflow allowing privilege escalation.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for verification.
- Confirm the FortiOS firmware version and build of Firewall-01 from authoritative inventory records.
- Consult the Fortinet PSIRT advisory for CVE-2025-24477 to confirm the affected range, fixed version, and any required configuration preconditions.
- Plan an upgrade to a FortiOS release that the vendor advisory identifies as fixed (above the affected 7.2.x range), following change management.
- Restrict administrative access to the device to trusted management networks pending remediation.
- Obtain CVSS, KEV, and exploitation intelligence to prioritize remediation.

---

### CVE-2025-22254

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS improper privilege management

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

An Improper Privilege Management vulnerability (CWE-269) in FortiOS 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, which matches the vulnerability vendor (FortiOS is a Fortinet product).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 falls within the published affected range of 7.2.0 through 7.2.10.
- The vulnerability description explicitly states FortiOS 7.2.0 through 7.2.10, which places 7.2.10 at the inclusive upper bound.
- CWE-269 Improper Privilege Management is identified in the provided intelligence.

**Recommendations:**

- Confirm the running FortiOS version and build from authoritative inventory or management records (e.g., FortiManager) without interacting with the device outside approved processes.
- Review the Fortinet PSIRT advisory for CVE-2025-22254 to confirm the affected range, fixed version (likely 7.2.11 or later), and any configuration prerequisites.
- Obtain CVSS, exploitation, and CISA KEV status to prioritize remediation.
- Determine whether Firewall-01 management interfaces are public-facing to assess exposure.
- Forward to the CRISP Quality Assurance Agent for final verification.
- If confirmed, plan an upgrade to a fixed FortiOS release through the organization's change management process.

---

### CVE-2025-58325

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS incorrect provision of specified functionality allows local command execution

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

An Incorrect Provision of Specified Functionality vulnerability (CWE-684) in FortiOS 7.2.5 through 7.2.10. A local authenticated attacker may be able to run system commands.

**Affected Versions:**

- 7.2.5 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vendor of the vulnerable product FortiOS.
- Asset product is FortiGate-80F, a FortiGate appliance that runs FortiOS.
- Asset version is 7.2.10, which falls within the affected range of 7.2.5 (start) through 7.2.10 (end).
- The CVE description explicitly lists FortiOS 7.2.5 through 7.2.10 as affected, which includes 7.2.10.
- CVE-2025-58325 is CWE-684 and allows a local authenticated attacker to run system commands.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for final verification.
- Confirm the running FortiOS version and build from authoritative inventory or configuration records, without interacting with the device.
- Obtain the Fortinet PSIRT advisory for CVE-2025-58325 to confirm the affected range, fixed version, and CVSS score.
- Plan an upgrade to the vendor-specified fixed FortiOS release through the organization's change management process.
- Restrict and review local and administrative access to the firewall, since exploitation requires local authenticated access.
- Check CISA KEV and threat intelligence for exploitation status to prioritize remediation.

---

### CVE-2024-52965

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS missing critical step in authentication

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

A missing critical step in authentication vulnerability (CWE-304) in FortiOS. The affected 7.2 versions are 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vulnerability vendor (FortiOS is Fortinet's operating system).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 is within the affected range 7.2.0 through 7.2.10.
- The vulnerability description explicitly lists 7.2.10 as the last affected 7.2 version, so the upper bound is inclusive.
- CVE-2024-52965 is described as a missing critical step in authentication (CWE-304) in FortiOS.

**Recommendations:**

- Confirm through read-only inventory records that the FortiGate-80F runs FortiOS 7.2.10, including the build number.
- Review the Fortinet PSIRT advisory for CVE-2024-52965 to identify the fixed version (likely 7.2.11 or later) and any feature or configuration prerequisites.
- Obtain CVSS, exploitation, and KEV status to prioritize remediation.
- Determine the asset's exposure (public-facing management or authentication interfaces) to assess risk.
- Forward this determination to the CRISP Quality Assurance Agent for final verification.

---

### CVE-2025-24477

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS heap-based buffer overflow privilege escalation

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

A heap-based buffer overflow in FortiOS 7.2.4 through 7.2.12 (the NVD summary says 7.2.11) that lets an attacker escalate privileges.

**Affected Versions:**

- 7.2.4 to 7.2.12

**Supporting Evidence:**

- Vendor match: the asset vendor is Fortinet and the vulnerability affects Fortinet FortiOS.
- Platform relationship: FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Version applicability: asset version 7.2.10 is within the affected range 7.2.4 to 7.2.12 (inclusive per the provided start and end values).
- The conflicting upper bound (7.2.11 vs 7.2.12) does not affect this asset, because 7.2.10 falls below both values.
- CVE identifier provided: CVE-2025-24477, described as a heap-based buffer overflow allowing privilege escalation.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for verification.
- Confirm the FortiOS firmware version and build of Firewall-01 from authoritative inventory records.
- Consult the Fortinet PSIRT advisory for CVE-2025-24477 to confirm the affected range, fixed version, and any required configuration preconditions.
- Plan an upgrade to a FortiOS release that the vendor advisory identifies as fixed (above the affected 7.2.x range), following change management.
- Restrict administrative access to the device to trusted management networks pending remediation.
- Obtain CVSS, KEV, and exploitation intelligence to prioritize remediation.

---

### CVE-2025-22254

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS improper privilege management

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

An Improper Privilege Management vulnerability (CWE-269) in FortiOS 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, which matches the vulnerability vendor (FortiOS is a Fortinet product).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 falls within the published affected range of 7.2.0 through 7.2.10.
- The vulnerability description explicitly states FortiOS 7.2.0 through 7.2.10, which places 7.2.10 at the inclusive upper bound.
- CWE-269 Improper Privilege Management is identified in the provided intelligence.

**Recommendations:**

- Confirm the running FortiOS version and build from authoritative inventory or management records (e.g., FortiManager) without interacting with the device outside approved processes.
- Review the Fortinet PSIRT advisory for CVE-2025-22254 to confirm the affected range, fixed version (likely 7.2.11 or later), and any configuration prerequisites.
- Obtain CVSS, exploitation, and CISA KEV status to prioritize remediation.
- Determine whether Firewall-01 management interfaces are public-facing to assess exposure.
- Forward to the CRISP Quality Assurance Agent for final verification.
- If confirmed, plan an upgrade to a fixed FortiOS release through the organization's change management process.

---

### CVE-2025-58325

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS incorrect provision of specified functionality allows local command execution

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

An Incorrect Provision of Specified Functionality vulnerability (CWE-684) in FortiOS 7.2.5 through 7.2.10. A local authenticated attacker may be able to run system commands.

**Affected Versions:**

- 7.2.5 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vendor of the vulnerable product FortiOS.
- Asset product is FortiGate-80F, a FortiGate appliance that runs FortiOS.
- Asset version is 7.2.10, which falls within the affected range of 7.2.5 (start) through 7.2.10 (end).
- The CVE description explicitly lists FortiOS 7.2.5 through 7.2.10 as affected, which includes 7.2.10.
- CVE-2025-58325 is CWE-684 and allows a local authenticated attacker to run system commands.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for final verification.
- Confirm the running FortiOS version and build from authoritative inventory or configuration records, without interacting with the device.
- Obtain the Fortinet PSIRT advisory for CVE-2025-58325 to confirm the affected range, fixed version, and CVSS score.
- Plan an upgrade to the vendor-specified fixed FortiOS release through the organization's change management process.
- Restrict and review local and administrative access to the firewall, since exploitation requires local authenticated access.
- Check CISA KEV and threat intelligence for exploitation status to prioritize remediation.

---

### CVE-2024-52965

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS missing critical step in authentication

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

A missing critical step in authentication vulnerability (CWE-304) in FortiOS. The affected 7.2 versions are 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vulnerability vendor (FortiOS is Fortinet's operating system).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 is within the affected range 7.2.0 through 7.2.10.
- The vulnerability description explicitly lists 7.2.10 as the last affected 7.2 version, so the upper bound is inclusive.
- CVE-2024-52965 is described as a missing critical step in authentication (CWE-304) in FortiOS.

**Recommendations:**

- Confirm through read-only inventory records that the FortiGate-80F runs FortiOS 7.2.10, including the build number.
- Review the Fortinet PSIRT advisory for CVE-2024-52965 to identify the fixed version (likely 7.2.11 or later) and any feature or configuration prerequisites.
- Obtain CVSS, exploitation, and KEV status to prioritize remediation.
- Determine the asset's exposure (public-facing management or authentication interfaces) to assess risk.
- Forward this determination to the CRISP Quality Assurance Agent for final verification.

---

### CVE-2025-24477

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS heap-based buffer overflow privilege escalation

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

A heap-based buffer overflow in FortiOS 7.2.4 through 7.2.12 (the NVD summary says 7.2.11) that lets an attacker escalate privileges.

**Affected Versions:**

- 7.2.4 to 7.2.12

**Supporting Evidence:**

- Vendor match: the asset vendor is Fortinet and the vulnerability affects Fortinet FortiOS.
- Platform relationship: FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Version applicability: asset version 7.2.10 is within the affected range 7.2.4 to 7.2.12 (inclusive per the provided start and end values).
- The conflicting upper bound (7.2.11 vs 7.2.12) does not affect this asset, because 7.2.10 falls below both values.
- CVE identifier provided: CVE-2025-24477, described as a heap-based buffer overflow allowing privilege escalation.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for verification.
- Confirm the FortiOS firmware version and build of Firewall-01 from authoritative inventory records.
- Consult the Fortinet PSIRT advisory for CVE-2025-24477 to confirm the affected range, fixed version, and any required configuration preconditions.
- Plan an upgrade to a FortiOS release that the vendor advisory identifies as fixed (above the affected 7.2.x range), following change management.
- Restrict administrative access to the device to trusted management networks pending remediation.
- Obtain CVSS, KEV, and exploitation intelligence to prioritize remediation.

---

### CVE-2025-22254

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS improper privilege management

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

An Improper Privilege Management vulnerability (CWE-269) in FortiOS 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, which matches the vulnerability vendor (FortiOS is a Fortinet product).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 falls within the published affected range of 7.2.0 through 7.2.10.
- The vulnerability description explicitly states FortiOS 7.2.0 through 7.2.10, which places 7.2.10 at the inclusive upper bound.
- CWE-269 Improper Privilege Management is identified in the provided intelligence.

**Recommendations:**

- Confirm the running FortiOS version and build from authoritative inventory or management records (e.g., FortiManager) without interacting with the device outside approved processes.
- Review the Fortinet PSIRT advisory for CVE-2025-22254 to confirm the affected range, fixed version (likely 7.2.11 or later), and any configuration prerequisites.
- Obtain CVSS, exploitation, and CISA KEV status to prioritize remediation.
- Determine whether Firewall-01 management interfaces are public-facing to assess exposure.
- Forward to the CRISP Quality Assurance Agent for final verification.
- If confirmed, plan an upgrade to a fixed FortiOS release through the organization's change management process.

---

### CVE-2025-58325

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS incorrect provision of specified functionality allows local command execution

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

An Incorrect Provision of Specified Functionality vulnerability (CWE-684) in FortiOS 7.2.5 through 7.2.10. A local authenticated attacker may be able to run system commands.

**Affected Versions:**

- 7.2.5 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vendor of the vulnerable product FortiOS.
- Asset product is FortiGate-80F, a FortiGate appliance that runs FortiOS.
- Asset version is 7.2.10, which falls within the affected range of 7.2.5 (start) through 7.2.10 (end).
- The CVE description explicitly lists FortiOS 7.2.5 through 7.2.10 as affected, which includes 7.2.10.
- CVE-2025-58325 is CWE-684 and allows a local authenticated attacker to run system commands.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for final verification.
- Confirm the running FortiOS version and build from authoritative inventory or configuration records, without interacting with the device.
- Obtain the Fortinet PSIRT advisory for CVE-2025-58325 to confirm the affected range, fixed version, and CVSS score.
- Plan an upgrade to the vendor-specified fixed FortiOS release through the organization's change management process.
- Restrict and review local and administrative access to the firewall, since exploitation requires local authenticated access.
- Check CISA KEV and threat intelligence for exploitation status to prioritize remediation.

---

### CVE-2024-52965

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS missing critical step in authentication

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** ()

**Description:**

A missing critical step in authentication vulnerability (CWE-304) in FortiOS. The affected 7.2 versions are 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vulnerability vendor (FortiOS is Fortinet's operating system).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 is within the affected range 7.2.0 through 7.2.10.
- The vulnerability description explicitly lists 7.2.10 as the last affected 7.2 version, so the upper bound is inclusive.
- CVE-2024-52965 is described as a missing critical step in authentication (CWE-304) in FortiOS.

**Recommendations:**

- Confirm through read-only inventory records that the FortiGate-80F runs FortiOS 7.2.10, including the build number.
- Review the Fortinet PSIRT advisory for CVE-2024-52965 to identify the fixed version (likely 7.2.11 or later) and any feature or configuration prerequisites.
- Obtain CVSS, exploitation, and KEV status to prioritize remediation.
- Determine the asset's exposure (public-facing management or authentication interfaces) to assess risk.
- Forward this determination to the CRISP Quality Assurance Agent for final verification.

---

### CVE-2025-24477

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS heap-based buffer overflow privilege escalation

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** (None,)

**Description:**

A heap-based buffer overflow in FortiOS 7.2.4 through 7.2.12 (the NVD summary says 7.2.11) that lets an attacker escalate privileges.

**Affected Versions:**

- 7.2.4 to 7.2.12

**Supporting Evidence:**

- Vendor match: the asset vendor is Fortinet and the vulnerability affects Fortinet FortiOS.
- Platform relationship: FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Version applicability: asset version 7.2.10 is within the affected range 7.2.4 to 7.2.12 (inclusive per the provided start and end values).
- The conflicting upper bound (7.2.11 vs 7.2.12) does not affect this asset, because 7.2.10 falls below both values.
- CVE identifier provided: CVE-2025-24477, described as a heap-based buffer overflow allowing privilege escalation.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for verification.
- Confirm the FortiOS firmware version and build of Firewall-01 from authoritative inventory records.
- Consult the Fortinet PSIRT advisory for CVE-2025-24477 to confirm the affected range, fixed version, and any required configuration preconditions.
- Plan an upgrade to a FortiOS release that the vendor advisory identifies as fixed (above the affected 7.2.x range), following change management.
- Restrict administrative access to the device to trusted management networks pending remediation.
- Obtain CVSS, KEV, and exploitation intelligence to prioritize remediation.

---

### CVE-2025-22254

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS improper privilege management

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** (None,)

**Description:**

An Improper Privilege Management vulnerability (CWE-269) in FortiOS 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, which matches the vulnerability vendor (FortiOS is a Fortinet product).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 falls within the published affected range of 7.2.0 through 7.2.10.
- The vulnerability description explicitly states FortiOS 7.2.0 through 7.2.10, which places 7.2.10 at the inclusive upper bound.
- CWE-269 Improper Privilege Management is identified in the provided intelligence.

**Recommendations:**

- Confirm the running FortiOS version and build from authoritative inventory or management records (e.g., FortiManager) without interacting with the device outside approved processes.
- Review the Fortinet PSIRT advisory for CVE-2025-22254 to confirm the affected range, fixed version (likely 7.2.11 or later), and any configuration prerequisites.
- Obtain CVSS, exploitation, and CISA KEV status to prioritize remediation.
- Determine whether Firewall-01 management interfaces are public-facing to assess exposure.
- Forward to the CRISP Quality Assurance Agent for final verification.
- If confirmed, plan an upgrade to a fixed FortiOS release through the organization's change management process.

---

### CVE-2025-58325

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS incorrect provision of specified functionality allows local command execution

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** (None,)

**Description:**

An Incorrect Provision of Specified Functionality vulnerability (CWE-684) in FortiOS 7.2.5 through 7.2.10. A local authenticated attacker may be able to run system commands.

**Affected Versions:**

- 7.2.5 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vendor of the vulnerable product FortiOS.
- Asset product is FortiGate-80F, a FortiGate appliance that runs FortiOS.
- Asset version is 7.2.10, which falls within the affected range of 7.2.5 (start) through 7.2.10 (end).
- The CVE description explicitly lists FortiOS 7.2.5 through 7.2.10 as affected, which includes 7.2.10.
- CVE-2025-58325 is CWE-684 and allows a local authenticated attacker to run system commands.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for final verification.
- Confirm the running FortiOS version and build from authoritative inventory or configuration records, without interacting with the device.
- Obtain the Fortinet PSIRT advisory for CVE-2025-58325 to confirm the affected range, fixed version, and CVSS score.
- Plan an upgrade to the vendor-specified fixed FortiOS release through the organization's change management process.
- Restrict and review local and administrative access to the firewall, since exploitation requires local authenticated access.
- Check CISA KEV and threat intelligence for exploitation status to prioritize remediation.

---

### CVE-2024-52965

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS missing critical step in authentication

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** (None,)

**Description:**

A missing critical step in authentication vulnerability (CWE-304) in FortiOS. The affected 7.2 versions are 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vulnerability vendor (FortiOS is Fortinet's operating system).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 is within the affected range 7.2.0 through 7.2.10.
- The vulnerability description explicitly lists 7.2.10 as the last affected 7.2 version, so the upper bound is inclusive.
- CVE-2024-52965 is described as a missing critical step in authentication (CWE-304) in FortiOS.

**Recommendations:**

- Confirm through read-only inventory records that the FortiGate-80F runs FortiOS 7.2.10, including the build number.
- Review the Fortinet PSIRT advisory for CVE-2024-52965 to identify the fixed version (likely 7.2.11 or later) and any feature or configuration prerequisites.
- Obtain CVSS, exploitation, and KEV status to prioritize remediation.
- Determine the asset's exposure (public-facing management or authentication interfaces) to assess risk.
- Forward this determination to the CRISP Quality Assurance Agent for final verification.

---

### CVE-2025-24477

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS heap-based buffer overflow privilege escalation

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** (None,)

**Description:**

A heap-based buffer overflow in FortiOS 7.2.4 through 7.2.12 (the NVD summary says 7.2.11) that lets an attacker escalate privileges.

**Affected Versions:**

- 7.2.4 to 7.2.12

**Supporting Evidence:**

- Vendor match: the asset vendor is Fortinet and the vulnerability affects Fortinet FortiOS.
- Platform relationship: FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Version applicability: asset version 7.2.10 is within the affected range 7.2.4 to 7.2.12 (inclusive per the provided start and end values).
- The conflicting upper bound (7.2.11 vs 7.2.12) does not affect this asset, because 7.2.10 falls below both values.
- CVE identifier provided: CVE-2025-24477, described as a heap-based buffer overflow allowing privilege escalation.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for verification.
- Confirm the FortiOS firmware version and build of Firewall-01 from authoritative inventory records.
- Consult the Fortinet PSIRT advisory for CVE-2025-24477 to confirm the affected range, fixed version, and any required configuration preconditions.
- Plan an upgrade to a FortiOS release that the vendor advisory identifies as fixed (above the affected 7.2.x range), following change management.
- Restrict administrative access to the device to trusted management networks pending remediation.
- Obtain CVSS, KEV, and exploitation intelligence to prioritize remediation.

---

### CVE-2025-22254

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS improper privilege management

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** (None,)

**Description:**

An Improper Privilege Management vulnerability (CWE-269) in FortiOS 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, which matches the vulnerability vendor (FortiOS is a Fortinet product).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 falls within the published affected range of 7.2.0 through 7.2.10.
- The vulnerability description explicitly states FortiOS 7.2.0 through 7.2.10, which places 7.2.10 at the inclusive upper bound.
- CWE-269 Improper Privilege Management is identified in the provided intelligence.

**Recommendations:**

- Confirm the running FortiOS version and build from authoritative inventory or management records (e.g., FortiManager) without interacting with the device outside approved processes.
- Review the Fortinet PSIRT advisory for CVE-2025-22254 to confirm the affected range, fixed version (likely 7.2.11 or later), and any configuration prerequisites.
- Obtain CVSS, exploitation, and CISA KEV status to prioritize remediation.
- Determine whether Firewall-01 management interfaces are public-facing to assess exposure.
- Forward to the CRISP Quality Assurance Agent for final verification.
- If confirmed, plan an upgrade to a fixed FortiOS release through the organization's change management process.

---

### CVE-2025-58325

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS incorrect provision of specified functionality allows local command execution

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** (None,)

**Description:**

An Incorrect Provision of Specified Functionality vulnerability (CWE-684) in FortiOS 7.2.5 through 7.2.10. A local authenticated attacker may be able to run system commands.

**Affected Versions:**

- 7.2.5 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vendor of the vulnerable product FortiOS.
- Asset product is FortiGate-80F, a FortiGate appliance that runs FortiOS.
- Asset version is 7.2.10, which falls within the affected range of 7.2.5 (start) through 7.2.10 (end).
- The CVE description explicitly lists FortiOS 7.2.5 through 7.2.10 as affected, which includes 7.2.10.
- CVE-2025-58325 is CWE-684 and allows a local authenticated attacker to run system commands.

**Recommendations:**

- Forward to the CRISP Quality Assurance Agent for final verification.
- Confirm the running FortiOS version and build from authoritative inventory or configuration records, without interacting with the device.
- Obtain the Fortinet PSIRT advisory for CVE-2025-58325 to confirm the affected range, fixed version, and CVSS score.
- Plan an upgrade to the vendor-specified fixed FortiOS release through the organization's change management process.
- Restrict and review local and administrative access to the firewall, since exploitation requires local authenticated access.
- Check CISA KEV and threat intelligence for exploitation status to prioritize remediation.

---

### CVE-2024-52965

**Asset:** Firewall-01

**Vendor:** Fortinet

**Product:** FortiGate-80F

**Installed Version:** 7.2.10

**Title:** FortiOS missing critical step in authentication

**Severity:** Unknown

**CVSS Score:** None

**Exploit Status:** None

**CISA KEV:** False

**Priority:** (None,)

**Description:**

A missing critical step in authentication vulnerability (CWE-304) in FortiOS. The affected 7.2 versions are 7.2.0 through 7.2.10.

**Affected Versions:**

- 7.2.0 to 7.2.10

**Supporting Evidence:**

- Asset vendor is Fortinet, matching the vulnerability vendor (FortiOS is Fortinet's operating system).
- Asset product FortiGate-80F is a FortiGate appliance that runs FortiOS.
- Asset version 7.2.10 is within the affected range 7.2.0 through 7.2.10.
- The vulnerability description explicitly lists 7.2.10 as the last affected 7.2 version, so the upper bound is inclusive.
- CVE-2024-52965 is described as a missing critical step in authentication (CWE-304) in FortiOS.

**Recommendations:**

- Confirm through read-only inventory records that the FortiGate-80F runs FortiOS 7.2.10, including the build number.
- Review the Fortinet PSIRT advisory for CVE-2024-52965 to identify the fixed version (likely 7.2.11 or later) and any feature or configuration prerequisites.
- Obtain CVSS, exploitation, and KEV status to prioritize remediation.
- Determine the asset's exposure (public-facing management or authentication interfaces) to assess risk.
- Forward this determination to the CRISP Quality Assurance Agent for final verification.

---


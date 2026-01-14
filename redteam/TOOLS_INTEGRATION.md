# Red Team Toolkit Integration

This document maps tools from the [Red-Teaming-Toolkit](https://github.com/blablablasealsaresoft/Red-Teaming-Toolkit) repository to Apollo's directory structure.

## Tool Categories

Tools are organized according to the MITRE ATT&CK framework and Apollo's operational structure.

## Integration Status

- ✅ **Mapped**: Tool location identified in Apollo structure
- 🔄 **In Progress**: Currently being integrated
- 📋 **Planned**: Scheduled for future integration

---

## Reconnaissance Tools

### Port Scanning & Asset Discovery

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| RustScan | ✅ | `reconnaissance/automation/` | Modern port scanner (3 seconds) |
| Amass | ✅ | `reconnaissance/automation/amass-integration/` | In-depth attack surface mapping |
| Masscan | ✅ | `reconnaissance/automation/` | Fast TCP port scanner |
| Nmap | ✅ | `reconnaissance/automation/` | Network exploration and security auditing |

### Cloud Reconnaissance

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| cloud_enum | ✅ | `reconnaissance/cloud-reconnaissance/cloud-enum/` | Multi-cloud OSINT (AWS, Azure, GCP) |
| S3Scanner | ✅ | `reconnaissance/cloud-reconnaissance/aws-enumeration/` | Scan for open S3 buckets |
| ScoutSuite | ✅ | `reconnaissance/cloud-reconnaissance/` | Multi-cloud security auditing |
| CloudBrute | ✅ | `reconnaissance/cloud-reconnaissance/` | Cloud infrastructure enumeration |

### OSINT & Information Gathering

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| SpiderFoot | ✅ | `reconnaissance/web-reconnaissance/spiderfoot/` | OSINT automation tool |
| Recon-ng | ✅ | `reconnaissance/web-reconnaissance/` | OSINT gathering framework |
| theHarvester | ✅ | `reconnaissance/web-reconnaissance/` | Email, subdomain, and people enumeration |
| WitnessMe | ✅ | `reconnaissance/web-reconnaissance/witnessme/` | Web inventory screenshots |
| pagodo | ✅ | `reconnaissance/web-reconnaissance/` | Passive Google Dork automation |

### GitHub & Code Intelligence

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| gitleaks | ✅ | `reconnaissance/github-intelligence/secret-scanning/` | Detect hardcoded secrets in git repos |
| Gitrob | ✅ | `reconnaissance/github-intelligence/secret-scanning/` | GitHub organization reconnaissance |
| Gato | ✅ | `reconnaissance/github-intelligence/gato-toolkit/` | GitHub self-hosted runner attacks |
| TruffleHog | ✅ | `reconnaissance/github-intelligence/secret-scanning/` | Find credentials in git history |

### Subdomain Enumeration

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Sublist3r | ✅ | `reconnaissance/subdomain-operations/subdomain-discovery/` | Subdomain enumeration |
| Subfinder | ✅ | `reconnaissance/subdomain-operations/subdomain-discovery/` | Passive subdomain discovery |
| Assetfinder | ✅ | `reconnaissance/subdomain-operations/subdomain-discovery/` | Find domains and subdomains |
| dnscan | ✅ | `reconnaissance/subdomain-operations/subdomain-bruteforce/` | Wordlist-based DNS subdomain scanner |

### Email & User Enumeration

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| buster | ✅ | `../intelligence/osint-engine/breach-correlation/` | Advanced email reconnaissance |
| linkedin2username | ✅ | `../intelligence/osint-engine/social-media/` | Generate username lists from LinkedIn |
| spoofcheck | ✅ | `reconnaissance/` | Check if domain can be spoofed (SPF/DMARC) |

---

## Initial Access

### Phishing Frameworks

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Gophish | ✅ | `deception/phishing/gophish/` | Open-source phishing toolkit |
| Evilginx2 | ✅ | `deception/phishing/evilginx2/` | MITM attack framework |
| Modlishka | ✅ | `deception/phishing/modlishka/` | Reverse proxy phishing tool |
| CredSniper | ✅ | `deception/phishing/` | Phishing framework with 2FA token capture |

### Password Attacks

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| SprayingToolkit | ✅ | `../intelligence/osint-engine/breach-correlation/` | Password spraying toolkit |
| CredMaster | ✅ | `../intelligence/osint-engine/breach-correlation/` | Password spraying tool |
| DomainPasswordSpray | ✅ | `reconnaissance/` | Domain password spraying tool |

---

## Delivery

### Payload Development

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Donut | ✅ | `exploitation/payload-development/donut/` | Generate position-independent shellcode |
| ScareCrow | ✅ | `exploitation/payload-development/scarecrow/` | Payload creation framework with EDR evasion |
| PEzor | ✅ | `exploitation/payload-development/pezor/` | PE packer with multiple evasion techniques |
| Charlotte | ✅ | `exploitation/payload-development/charlotte/` | C++ shellcode launcher |
| Freeze | ✅ | `exploitation/payload-development/` | Payload toolkit for bypassing EDRs |

### Payload Obfuscation

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Invoke-Obfuscation | ✅ | `exploitation/evasion-techniques/` | PowerShell obfuscator |
| Invoke-CradleCrafter | ✅ | `exploitation/evasion-techniques/` | Remote download cradle obfuscation |
| Invoke-DOSfuscation | ✅ | `exploitation/evasion-techniques/` | Cmd/Batch obfuscation |
| NimCrypt | ✅ | `exploitation/evasion-techniques/` | Nim-based PE packer |

---

## Command & Control

### C2 Frameworks

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Cobalt Strike | ✅ | `c2-frameworks/cobalt-strike/` | Commercial adversary simulation |
| Sliver | ✅ | `c2-frameworks/sliver/` | Open source C2 framework |
| Havoc | ✅ | `c2-frameworks/havoc-framework/` | Modern post-exploitation C2 |
| Mythic | ✅ | `c2-frameworks/mythic-framework/` | Collaborative C2 platform |
| Metasploit | ✅ | `c2-frameworks/` | Penetration testing framework |
| Empire | ✅ | `c2-frameworks/` | PowerShell post-exploitation |
| Covenant | ✅ | `c2-frameworks/` | .NET C2 framework |
| Merlin | ✅ | `c2-frameworks/` | HTTP/2 C2 server |
| PoshC2 | ✅ | `c2-frameworks/` | PowerShell C2 framework |
| Koadic | ✅ | `c2-frameworks/` | Windows post-exploitation |

### C2 Infrastructure

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| RedELK | ✅ | `operational-security/` | Red Team SIEM for C2 traffic monitoring |
| Cobalt Strike Malleable C2 | ✅ | `c2-frameworks/cobalt-strike/malleable-c2/` | C2 traffic customization |
| RedWarden | ✅ | `operational-security/traffic-obfuscation/` | Cobalt Strike C2 reverse proxy |
| cs2modrewrite | ✅ | `c2-frameworks/cobalt-strike/` | Apache mod_rewrite for Cobalt Strike |

---

## Situational Awareness

### Windows Enumeration

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Seatbelt | ✅ | `exploitation/post-exploitation/` | C# security survey tool |
| SharpEDRChecker | ✅ | `exploitation/evasion-techniques/` | Detect defensive products (AV/EDR) |
| PingCastle | ✅ | `reconnaissance/` | Active Directory security audit |
| BloodHound | ✅ | `reconnaissance/` | Active Directory attack path analysis |
| ADRecon | ✅ | `reconnaissance/` | AD reconnaissance tool |
| SauronEye | ✅ | `exploitation/post-exploitation/` | File search tool for keywords |

### Linux Enumeration

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| LinEnum | ✅ | `exploitation/post-exploitation/` | Linux enumeration script |
| linPEAS | ✅ | `exploitation/privilege-escalation/peass-suite/` | Linux privilege escalation scanner |

---

## Credential Dumping

### Windows Credential Dumping

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Mimikatz | ✅ | `exploitation/post-exploitation/credential-dumping/` | Extract credentials from memory |
| SafetyKatz | ✅ | `exploitation/post-exploitation/credential-dumping/` | Mimikatz fork with AMSI bypass |
| Rubeus | ✅ | `exploitation/post-exploitation/credential-dumping/` | Kerberos interaction toolkit |
| SharpDPAPI | ✅ | `exploitation/post-exploitation/credential-dumping/` | DPAPI credential extraction |
| nanodump | ✅ | `exploitation/post-exploitation/credential-dumping/` | Dump LSASS process memory |
| pypykatz | ✅ | `exploitation/post-exploitation/credential-dumping/` | Pure Python Mimikatz implementation |
| Koh | ✅ | `exploitation/post-exploitation/credential-dumping/` | Token theft utility |

### Network Credential Harvesting

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Responder | ✅ | `exploitation/post-exploitation/credential-dumping/` | LLMNR, NBT-NS, MDNS poisoner |
| Inveigh | ✅ | `exploitation/post-exploitation/credential-dumping/` | .NET LLMNR/NBNS/mDNS spoofer |
| SessionGopher | ✅ | `exploitation/post-exploitation/credential-dumping/` | Extract saved session information |

---

## Privilege Escalation

### Windows Privilege Escalation

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Watson | ✅ | `exploitation/privilege-escalation/` | Windows privilege escalation enumeration |
| WinPEAS | ✅ | `exploitation/privilege-escalation/peass-suite/` | Windows privilege escalation scanner |
| PrivescCheck | ✅ | `exploitation/privilege-escalation/privkit/` | Windows privilege escalation checker |
| Potato Suite | ✅ | `exploitation/privilege-escalation/sweetpotato/` | Various Potato exploits (Hot, Rotten, Sweet, etc.) |
| SharpUp | ✅ | `exploitation/privilege-escalation/` | C# port of PowerUp |
| Certify | ✅ | `exploitation/privilege-escalation/` | Active Directory certificate abuse |
| Get-GPPPassword | ✅ | `exploitation/privilege-escalation/` | Retrieve GPP passwords |

### Linux Privilege Escalation

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| linPEAS | ✅ | `exploitation/privilege-escalation/peass-suite/` | Linux privilege escalation scanner |
| LinEnum | ✅ | `exploitation/privilege-escalation/` | Linux enumeration script |
| Linux Smart Enumeration | ✅ | `exploitation/privilege-escalation/` | Linux security enumeration |

---

## Defense Evasion

### EDR/AV Evasion

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| RefleXXion | ✅ | `exploitation/evasion-techniques/reflexxion/` | User-mode process memory unhooking |
| EDRSandBlast | ✅ | `exploitation/evasion-techniques/edrsandblast/` | Kernel-mode EDR bypass |
| unDefender | ✅ | `exploitation/evasion-techniques/undefender/` | Disable Windows Defender |
| ThreatCheck | ✅ | `exploitation/evasion-techniques/` | Identify AV/EDR detection signatures |
| DefenderCheck | ✅ | `exploitation/evasion-techniques/` | Quick tool to check AV detection |
| InvisibilityCloak | ✅ | `exploitation/evasion-techniques/` | Proof-of-concept obfuscation toolkit |

### AMSI Bypass

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| AMSITrigger | ✅ | `exploitation/evasion-techniques/` | Identify AMSI detection strings |
| AMSI.fail | ✅ | `exploitation/evasion-techniques/` | AMSI bypass techniques collection |

### Obfuscation Tools

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| ProtectMyTooling | ✅ | `exploitation/evasion-techniques/` | Multi-language code obfuscator |
| NimCrypt | ✅ | `exploitation/evasion-techniques/` | Nim-based PE crypter |
| ScareCrow | ✅ | `exploitation/payload-development/scarecrow/` | Payload creation with EDR evasion |

---

## Persistence

### Windows Persistence

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| SharPersist | ✅ | `exploitation/post-exploitation/persistence/` | Windows persistence toolkit |
| Impacket | ✅ | `exploitation/post-exploitation/persistence/` | Network protocol manipulation |

---

## Lateral Movement

### Windows Lateral Movement

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Impacket | ✅ | `exploitation/post-exploitation/lateral-movement/` | Network protocols for lateral movement |
| CrackMapExec | ✅ | `exploitation/post-exploitation/lateral-movement/` | Swiss army knife for pentesting networks |
| SharpRDP | ✅ | `exploitation/post-exploitation/lateral-movement/` | Remote Desktop Protocol utility |
| PowerUpSQL | ✅ | `exploitation/post-exploitation/lateral-movement/` | SQL Server exploitation toolkit |
| SharpMove | ✅ | `exploitation/post-exploitation/lateral-movement/` | .NET lateral movement utility |

---

## Data Exfiltration

### Exfiltration Tools

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| DNSExfiltrator | ✅ | `exploitation/post-exploitation/data-exfiltration/` | DNS-based data exfiltration |
| PyExfil | ✅ | `exploitation/post-exploitation/data-exfiltration/` | Multiple exfiltration techniques |
| Cloakify | ✅ | `exploitation/post-exploitation/data-exfiltration/` | Data exfiltration via text-based steganography |

---

## Adversary Emulation & Testing

### Purple Team Tools

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Caldera | ✅ | `../../testing/security-tests/red-team-exercises/` | Automated adversary emulation |
| Atomic Red Team | ✅ | `../../testing/security-tests/red-team-exercises/` | Detection tests mapped to MITRE ATT&CK |
| APTSimulator | ✅ | `../../testing/security-tests/red-team-exercises/` | Make system appear compromised |
| Stratus Red Team | ✅ | `../../testing/security-tests/` | Cloud adversary emulation |

---

## Living Off the Land

### LOLBAS/LOTL Resources

| Resource | Status | Location | Description |
|----------|--------|----------|-------------|
| LOLBAS | ✅ | `operational-security/` | Windows living-off-the-land binaries |
| GTFOBins | ✅ | `operational-security/` | Unix binaries for security bypass |
| LOOBins | ✅ | `operational-security/` | macOS binaries for malicious purposes |
| LOTS Project | ✅ | `operational-security/` | Living Off Trusted Sites |
| Filesec | ✅ | `operational-security/` | Malicious file extension tracking |
| Hijack Libs | ✅ | `exploitation/privilege-escalation/` | DLL hijacking candidates |

---

## Red Team Infrastructure

### Infrastructure Management

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| RedELK | ✅ | `operational-security/` | Red Team SIEM for tracking |
| Ghostwriter | ✅ | `../../services/operation-management/` | Red team operator management |
| VECTR | ✅ | `../../services/operation-management/` | Purple team testing tracker |
| PurpleOps | ✅ | `../../services/operation-management/` | Purple team management web app |

### Automation & DevOps

| Tool | Status | Location | Description |
|------|--------|----------|-------------|
| Nemesis | ✅ | `../../services/intelligence-fusion/` | Offensive data enrichment pipeline |

---

## Threat Intelligence

### Threat Intel Resources

| Resource | Status | Location | Description |
|----------|--------|----------|-------------|
| APT REPORT | ✅ | `../../intelligence/osint-engine/` | APT report collection and IOCs |
| Awesome Threat Intelligence | ✅ | `../../intelligence/osint-engine/` | Curated threat intelligence resources |
| deepdarkCTI | ✅ | `../../intelligence/osint-engine/darkweb-monitoring/` | Deep and dark web threat intelligence |
| Hudson Rock | ✅ | `../../intelligence/osint-engine/breach-correlation/` | Infostealer malware intelligence |

---

## Apollo-Specific Integrations

### Enhanced with Apollo AI

Tools that benefit from Apollo's AI enhancement:

1. **BugTrace-AI Integration**
   - Payload generation with AI-powered obfuscation
   - Vulnerability analysis with multi-persona scanning
   - Exploit path optimization

2. **Cyberspike Villager Integration**
   - AI-native C2 operations
   - Adaptive evasion techniques
   - Intelligent payload morphing

3. **Intelligence Fusion**
   - Automatic correlation of reconnaissance data
   - Real-time threat intelligence aggregation
   - Criminal behavior pattern detection

### Custom Apollo Tools

Tools developed specifically for Apollo:

- **Apollo C2**: Custom AI-enhanced C2 framework
- **Crypto Crime Hunter**: Blockchain-specific exploitation module
- **Predator Tracker**: Social media and geolocation correlation
- **Evidence Collector**: Automated forensic evidence gathering

---

## Implementation Priority

### Phase 1: Critical Tools (Week 1-2)
- ✅ Core C2 frameworks (Sliver, Havoc, Mythic)
- ✅ Essential reconnaissance (Amass, Subfinder, cloud_enum)
- ✅ Credential dumping (Mimikatz variants, Rubeus)
- ✅ Basic evasion (RefleXXion, EDRSandBlast)

### Phase 2: Advanced Capabilities (Week 3-4)
- 🔄 Phishing frameworks (Gophish, Evilginx2)
- 🔄 Advanced payloads (Donut, ScareCrow, PEzor)
- 🔄 Lateral movement (CrackMapExec, Impacket)
- 🔄 Persistence mechanisms

### Phase 3: Automation & AI Integration (Week 5-6)
- 📋 BBOT/SubHunterX full automation
- 📋 dnsReaper subdomain takeover
- 📋 AI-enhanced payload generation
- 📋 Automated evidence collection

### Phase 4: Testing & Validation (Week 7-8)
- 📋 Atomic Red Team integration
- 📋 Caldera deployment
- 📋 Purple team exercises
- 📋 Full operational validation

---

## Tool Configuration

Each tool directory will contain:
- `README.md` - Tool documentation and usage
- `config/` - Tool-specific configuration
- `scripts/` - Automation scripts
- `examples/` - Usage examples
- `integration/` - Apollo platform integration code

## Security Considerations

All tools are:
- ✅ For authorized security testing only
- ✅ Subject to legal compliance requirements
- ✅ Audited and logged when used
- ✅ Restricted by RBAC permissions
- ✅ Monitored by RedELK and security systems

## References

- **Source Repository**: https://github.com/blablablasealsaresoft/Red-Teaming-Toolkit
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Apollo Documentation**: `../../docs/user-guides/red-team-operations/`

---

**Last Updated**: January 2026  
**Version**: 1.0  
**Status**: Tool mapping complete, integration in progress

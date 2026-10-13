// ============================================================
// Clean TinyTask Cybersecurity & Compliance Knowledge Graph
// ============================================================

// 1. Company Context
MERGE (cc:CompanyContext {id: 'TINYTASK-01'})
SET cc.name = 'TinyTask SaaS',
    cc.industry = 'Productivity & Task Management',
    cc.dataTypes = ['Task text', 'User emails', 'API tokens'],
    cc.cloud = 'AWS EU-Central-1';

// 2. Threats
MERGE (t1:Threat {id: 'T-EXFILTRATION'})
SET t1.name = 'Customer Data Exfiltration',
    t1.description = 'Unauthorized exfiltration of sensitive task data and customer emails via exposed API',
    t1.severity = 'HIGH';

MERGE (t2:Threat {id: 'T-SUPPLY-CHAIN'})
SET t2.name = 'Malicious Dependency Injection',
    t2.description = 'Compromised npm package in frontend/backend build pipeline executing malicious payload',
    t2.severity = 'CRITICAL';

MERGE (t3:Threat {id: 'T-SESSION-HIJACK'})
SET t3.name = 'Session Token Hijacking',
    t3.description = 'Interception of long-lived JWT session tokens allowing impersonation of admin accounts',
    t3.severity = 'MEDIUM';

MERGE (t4:Threat {id: 'T-RANSOMWARE'})
SET t4.name = 'Database Encryption Extortion',
    t4.description = 'Ransomware deployment encrypting database volumes causing total downtime',
    t4.severity = 'HIGH';

// 3. Mitigations / Technical Controls
MERGE (m1:Mitigation {id: 'M-ENCRYPTION'})
SET m1.name = 'AES-GCM at-rest and TLS 1.3 in-transit Encryption',
    m1.description = 'Enforce end-to-end payload encryption and KMS managed rotation';

MERGE (m2:Mitigation {id: 'M-SBOM-SCAN'})
SET m2.name = 'Automated SBOM Generation and SCA Dependency Scanning',
    m2.description = 'Daily vulnerability scanning with Dependabot and block pipeline on CVSS >= 7.0';

MERGE (m3:Mitigation {id: 'M-INCIDENT-SOP'})
SET m3.name = 'CSIRT Incident Response Protocol and Automated Authority Notification',
    m3.description = 'Standard operating procedure for 24h/72h data breach notification to supervisory authorities';

MERGE (m4:Mitigation {id: 'M-MFA-ROTATION'})
SET m4.name = 'Mandatory MFA and Ephemeral Token Rotation',
    m4.description = 'Enforce FIDO2 WebAuthn MFA and short-lived JWT access tokens with strict refresh validation';

// 4. Domains
MERGE (d1:Domain {id: 'D-DATA-PROT'})
SET d1.name = 'Data Protection & Cryptography',
    d1.description = 'Encryption, data integrity, confidentiality and pseudonymisation';

MERGE (d2:Domain {id: 'D-SUPPLY-CHAIN'})
SET d2.name = 'Supply Chain & Third-Party Security',
    d2.description = 'Vendor assessment, SBOM and third-party software library governance';

MERGE (d3:Domain {id: 'D-INCIDENT-RESP'})
SET d3.name = 'Incident Handling & Breach Notification',
    d3.description = 'Detection, reporting and containment of security incidents';

MERGE (d4:Domain {id: 'D-ACCESS-CTRL'})
SET d4.name = 'Identity & Access Management',
    d4.description = 'Authentication, least-privilege authorization and session control';

// 5. Regulations
MERGE (r1:Regulation {id: 'REG-GDPR'})
SET r1.name = 'GDPR',
    r1.fullName = 'EU General Data Protection Regulation (2016/679)',
    r1.focus = 'Privacy and Personal Data Protection';

MERGE (r2:Regulation {id: 'REG-CRA'})
SET r2.name = 'CRA',
    r2.fullName = 'EU Cyber Resilience Act (2024)',
    r2.focus = 'Security of Hardware and Software Products with Digital Elements';

MERGE (r3:Regulation {id: 'REG-NIS2'})
SET r3.name = 'NIS2',
    r3.fullName = 'EU Network and Information Systems Directive 2',
    r3.focus = 'Critical Service Resilience and Incident Reporting';

// 6. Articles
MERGE (a1:Article {id: 'ART-GDPR-32'})
SET a1.number = '32',
    a1.title = 'Security of Processing',
    a1.regulation = 'GDPR';

MERGE (a2:Article {id: 'ART-GDPR-33'})
SET a2.number = '33',
    a2.title = 'Notification of a Personal Data Breach to the Supervisory Authority',
    a2.regulation = 'GDPR';

MERGE (a3:Article {id: 'ART-CRA-ANNEX1'})
SET a3.number = 'Annex I',
    a3.title = 'Essential Cybersecurity Requirements for Products',
    a3.regulation = 'CRA';

MERGE (a4:Article {id: 'ART-NIS2-21'})
SET a4.number = '21',
    a4.title = 'Cybersecurity Risk-Management Measures',
    a4.regulation = 'NIS2';

// 7. Clauses
MERGE (c1:Clause {id: 'CLS-GDPR-32.1a'})
SET c1.text = 'Pseudonymisation and encryption of personal data to protect against unauthorized access.',
    c1.normativeIntensity = 'MANDATORY';

MERGE (c2:Clause {id: 'CLS-GDPR-33.1'})
SET c2.text = 'In case of personal data breach, notify supervisory authority within 72 hours of becoming aware.',
    c2.normativeIntensity = 'MANDATORY';

MERGE (c3:Clause {id: 'CLS-CRA-ANNEX1.2'})
SET c3.text = 'Identify and document vulnerabilities and components, including drawing up a software bill of materials (SBOM).',
    c3.normativeIntensity = 'MANDATORY';

MERGE (c4:Clause {id: 'CLS-NIS2-21.2d'})
SET c4.text = 'Ensure supply chain security, taking into account vulnerabilities specific to direct suppliers and service providers.',
    c4.normativeIntensity = 'MANDATORY';

MERGE (c5:Clause {id: 'CLS-GDPR-32.1b'})
SET c5.text = 'Ensure the ability to restore availability and access to personal data in a timely manner in the event of an incident.',
    c5.normativeIntensity = 'MANDATORY';

// ============================================================
// RELATIONSHIPS WITH EXPLICIT MATCH
// ============================================================

MATCH (t:Threat {id: 'T-EXFILTRATION'}), (cc:CompanyContext {id: 'TINYTASK-01'}) MERGE (t)-[:TARGETS]->(cc);
MATCH (t:Threat {id: 'T-SUPPLY-CHAIN'}), (cc:CompanyContext {id: 'TINYTASK-01'}) MERGE (t)-[:TARGETS]->(cc);
MATCH (t:Threat {id: 'T-SESSION-HIJACK'}), (cc:CompanyContext {id: 'TINYTASK-01'}) MERGE (t)-[:TARGETS]->(cc);
MATCH (t:Threat {id: 'T-RANSOMWARE'}), (cc:CompanyContext {id: 'TINYTASK-01'}) MERGE (t)-[:TARGETS]->(cc);

MATCH (t:Threat {id: 'T-EXFILTRATION'}), (d:Domain {id: 'D-DATA-PROT'}) MERGE (t)-[:CONCERNS_DOMAIN]->(d);
MATCH (t:Threat {id: 'T-SUPPLY-CHAIN'}), (d:Domain {id: 'D-SUPPLY-CHAIN'}) MERGE (t)-[:CONCERNS_DOMAIN]->(d);
MATCH (t:Threat {id: 'T-SESSION-HIJACK'}), (d:Domain {id: 'D-ACCESS-CTRL'}) MERGE (t)-[:CONCERNS_DOMAIN]->(d);
MATCH (t:Threat {id: 'T-RANSOMWARE'}), (d:Domain {id: 'D-INCIDENT-RESP'}) MERGE (t)-[:CONCERNS_DOMAIN]->(d);

MATCH (t:Threat {id: 'T-EXFILTRATION'}), (m:Mitigation {id: 'M-ENCRYPTION'}) MERGE (t)-[:MITIGATED_BY]->(m);
MATCH (t:Threat {id: 'T-SUPPLY-CHAIN'}), (m:Mitigation {id: 'M-SBOM-SCAN'}) MERGE (t)-[:MITIGATED_BY]->(m);
MATCH (t:Threat {id: 'T-SESSION-HIJACK'}), (m:Mitigation {id: 'M-MFA-ROTATION'}) MERGE (t)-[:MITIGATED_BY]->(m);
MATCH (t:Threat {id: 'T-RANSOMWARE'}), (m:Mitigation {id: 'M-INCIDENT-SOP'}) MERGE (t)-[:MITIGATED_BY]->(m);

MATCH (m:Mitigation {id: 'M-ENCRYPTION'}), (d:Domain {id: 'D-DATA-PROT'}) MERGE (m)-[:RELATES_TO_DOMAIN]->(d);
MATCH (m:Mitigation {id: 'M-SBOM-SCAN'}), (d:Domain {id: 'D-SUPPLY-CHAIN'}) MERGE (m)-[:RELATES_TO_DOMAIN]->(d);
MATCH (m:Mitigation {id: 'M-INCIDENT-SOP'}), (d:Domain {id: 'D-INCIDENT-RESP'}) MERGE (m)-[:RELATES_TO_DOMAIN]->(d);
MATCH (m:Mitigation {id: 'M-MFA-ROTATION'}), (d:Domain {id: 'D-ACCESS-CTRL'}) MERGE (m)-[:RELATES_TO_DOMAIN]->(d);

MATCH (m:Mitigation {id: 'M-ENCRYPTION'}), (c:Clause {id: 'CLS-GDPR-32.1a'}) MERGE (m)-[:IMPLEMENTS_CLAUSE]->(c);
MATCH (m:Mitigation {id: 'M-SBOM-SCAN'}), (c:Clause {id: 'CLS-CRA-ANNEX1.2'}) MERGE (m)-[:IMPLEMENTS_CLAUSE]->(c);
MATCH (m:Mitigation {id: 'M-SBOM-SCAN'}), (c:Clause {id: 'CLS-NIS2-21.2d'}) MERGE (m)-[:IMPLEMENTS_CLAUSE]->(c);
MATCH (m:Mitigation {id: 'M-INCIDENT-SOP'}), (c:Clause {id: 'CLS-GDPR-33.1'}) MERGE (m)-[:IMPLEMENTS_CLAUSE]->(c);
MATCH (m:Mitigation {id: 'M-INCIDENT-SOP'}), (c:Clause {id: 'CLS-GDPR-32.1b'}) MERGE (m)-[:IMPLEMENTS_CLAUSE]->(c);

MATCH (c:Clause {id: 'CLS-GDPR-32.1a'}), (a:Article {id: 'ART-GDPR-32'}) MERGE (c)-[:BELONGS_TO_ARTICLE]->(a);
MATCH (c:Clause {id: 'CLS-GDPR-33.1'}), (a:Article {id: 'ART-GDPR-33'}) MERGE (c)-[:BELONGS_TO_ARTICLE]->(a);
MATCH (c:Clause {id: 'CLS-CRA-ANNEX1.2'}), (a:Article {id: 'ART-CRA-ANNEX1'}) MERGE (c)-[:BELONGS_TO_ARTICLE]->(a);
MATCH (c:Clause {id: 'CLS-NIS2-21.2d'}), (a:Article {id: 'ART-NIS2-21'}) MERGE (c)-[:BELONGS_TO_ARTICLE]->(a);
MATCH (c:Clause {id: 'CLS-GDPR-32.1b'}), (a:Article {id: 'ART-GDPR-32'}) MERGE (c)-[:BELONGS_TO_ARTICLE]->(a);

MATCH (a:Article {id: 'ART-GDPR-32'}), (r:Regulation {id: 'REG-GDPR'}) MERGE (a)-[:PART_OF_REGULATION]->(r);
MATCH (a:Article {id: 'ART-GDPR-33'}), (r:Regulation {id: 'REG-GDPR'}) MERGE (a)-[:PART_OF_REGULATION]->(r);
MATCH (a:Article {id: 'ART-CRA-ANNEX1'}), (r:Regulation {id: 'REG-CRA'}) MERGE (a)-[:PART_OF_REGULATION]->(r);
MATCH (a:Article {id: 'ART-NIS2-21'}), (r:Regulation {id: 'REG-NIS2'}) MERGE (a)-[:PART_OF_REGULATION]->(r);

MATCH (c:Clause {id: 'CLS-GDPR-32.1a'}), (d:Domain {id: 'D-DATA-PROT'}) MERGE (c)-[:MAPS_TO_DOMAIN]->(d);
MATCH (c:Clause {id: 'CLS-GDPR-33.1'}), (d:Domain {id: 'D-INCIDENT-RESP'}) MERGE (c)-[:MAPS_TO_DOMAIN]->(d);
MATCH (c:Clause {id: 'CLS-CRA-ANNEX1.2'}), (d:Domain {id: 'D-SUPPLY-CHAIN'}) MERGE (c)-[:MAPS_TO_DOMAIN]->(d);
MATCH (c:Clause {id: 'CLS-NIS2-21.2d'}), (d:Domain {id: 'D-SUPPLY-CHAIN'}) MERGE (c)-[:MAPS_TO_DOMAIN]->(d);
MATCH (c:Clause {id: 'CLS-GDPR-32.1b'}), (d:Domain {id: 'D-DATA-PROT'}) MERGE (c)-[:MAPS_TO_DOMAIN]->(d);

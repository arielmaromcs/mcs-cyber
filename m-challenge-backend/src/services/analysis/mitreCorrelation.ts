/**
 * MitreCorrelationService - MITRE ATT&CK mapping via LLM.
 * 
 * Supports: OpenAI-compatible API, Anthropic, or local stub.
 * Uses structured JSON schema output to prevent hallucination drift.
 */

import { config } from '../../config/env';

const MITRE_RESPONSE_SCHEMA = {
  type: 'object',
  properties: {
    mitre_available: { type: 'boolean' },
    attack_surface_summary: {
      type: 'object',
      properties: {
        external_posture: { type: 'string' },
        primary_exposure_vector: { type: 'string' },
        confidence: { type: 'string' },
      },
    },
    attack_score: {
      type: 'object',
      properties: {
        score: { type: 'number' },
        rating: { type: 'string' },
        reasoning: { type: 'array', items: { type: 'string' } },
      },
    },
    potential_attack_paths: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          entry_point: { type: 'string' },
          description: { type: 'string' },
          attacker_goal: { type: 'string' },
          likelihood: { type: 'string' },
          confidence: { type: 'string' },
        },
      },
    },
    mitre_mapping: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          tactic: { type: 'string' },
          technique: { type: 'string' },
          technique_id: { type: 'string' },
          why_relevant: { type: 'string' },
          confidence: { type: 'string' },
        },
      },
    },
    priority_findings: { type: 'array' },
    defensive_recommendations: { type: 'array' },
    remediation_roadmap: {
      type: 'object',
      properties: {
        immediate_30_days: { type: 'array', items: { type: 'string' } },
        short_term_60_days: { type: 'array', items: { type: 'string' } },
        long_term_90_days: { type: 'array', items: { type: 'string' } },
      },
    },
    attacker_view: {
      type: 'object',
      properties: {
        summary: { type: 'string' },
        difficulty_to_exploit: { type: 'string' },
        first_steps: { type: 'array', items: { type: 'string' } },
        likely_focus: { type: 'string' },
        detailed_scenario: { type: 'string' },
        attack_narrative: { type: 'array', items: { type: 'object', properties: { step: { type: 'number' }, action: { type: 'string' }, technique: { type: 'string' }, detail: { type: 'string' } } } },
        risk_summary: { type: 'string' },
        what_attacker_sees: { type: 'array', items: { type: 'string' } },
      },
    },
    executive_summary: {
      type: 'object',
      properties: {
        overview: { type: 'string' },
        key_risks: { type: 'array', items: { type: 'string' } },
        immediate_actions: { type: 'array', items: { type: 'string' } },
      },
    },
    disclaimer: { type: 'string' },
  },
};

export class MitreCorrelationService {
  async correlate(target: string, emailScan: any, webScan: any, threatIntel: any): Promise<any> {
    const prompt = this.buildPrompt(target, emailScan, webScan, threatIntel);

    if (config.llm.provider === 'local' || !config.llm.apiKey) {
      return this.generateLocalAnalysis(target, emailScan, webScan, threatIntel);
    }

    try {
      return await this.callLLM(prompt);
    } catch (err) {
      console.error('LLM call failed, using local analysis:', err);
      return this.generateLocalAnalysis(target, emailScan, webScan, threatIntel);
    }
  }

  private buildPrompt(target: string, emailScan: any, webScan: any, threatIntel: any): string {
    return `You are an expert cybersecurity analyst. Analyze the following external attack surface data and map findings to MITRE ATT&CK techniques.

TARGET: ${target}

${emailScan ? `EMAIL SCAN DATA:
- SPF: ${JSON.stringify(emailScan.spfRecord || emailScan.spf_record)}
- DKIM: ${JSON.stringify(emailScan.dkimRecord || emailScan.dkim_record)}
- DMARC: ${JSON.stringify(emailScan.dmarcRecord || emailScan.dmarc_record)}
- Score: ${emailScan.emailSecurityScore || emailScan.email_security_score}/100` : 'No email scan data'}

${webScan ? `WEB SCAN DATA:
- Findings: ${JSON.stringify((webScan.findings || []).slice(0, 10))}
- Exposures: ${JSON.stringify((webScan.exposureFindings || webScan.exposure_findings || []).slice(0, 5))}
- Score: ${webScan.webSecurityScore || webScan.web_security_score}/100` : 'No web scan data'}

${threatIntel ? `THREAT INTELLIGENCE:
${JSON.stringify(threatIntel).slice(0, 2000)}` : 'No threat intel data'}

Provide a comprehensive MITRE ATT&CK analysis. 
IMPORTANT for attacker_view: Write a detailed attack scenario as if you are a penetration tester explaining step-by-step how you would approach this target. Include:
- detailed_scenario: A 3-5 paragraph narrative of how an attacker would realistically exploit these vulnerabilities
- attack_narrative: Array of numbered steps an attacker would take, each with action, MITRE technique used, and technical details
- what_attacker_sees: List of specific things visible to an attacker doing reconnaissance
- risk_summary: One paragraph executive summary of the overall risk

Respond ONLY with valid JSON matching this schema (no markdown, no backticks):
${JSON.stringify(MITRE_RESPONSE_SCHEMA, null, 2)}`;
  }

  private async callLLM(prompt: string): Promise<any> {
    const body: any = {
      model: config.llm.model,
      messages: [
        { role: 'system', content: 'You are a cybersecurity analyst. Respond only with valid JSON.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 4000,
    };

    // OpenAI-compatible endpoint
    const res = await fetch(`${config.llm.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.llm.apiKey}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(60000),
    });

    if (!res.ok) throw new Error(`LLM API error: ${res.status}`);
    const data: any = await res.json();
    const text = data.choices?.[0]?.message?.content || '';

    // Parse JSON from response
    const clean = text.replace(/```json\n?|\n?```/g, '').trim();
    return JSON.parse(clean);
  }

  /**
   * Local analysis fallback — deterministic MITRE mapping based on scan data.
   * No LLM required. Generates realistic analysis from actual findings.
   */
  private generateLocalAnalysis(target: string, emailScan: any, webScan: any, threatIntel: any): any {
    const mappings: any[] = [];
    const paths: any[] = [];
    const findings: any[] = [];
    const recs: any[] = [];
    const immediate: string[] = [];
    const shortTerm: string[] = [];
    const longTerm: string[] = [];
    let scoreTotal = 0;
    const reasoning: string[] = [];

    // Analyze email scan
    if (emailScan) {
      const emailScore = emailScan.emailSecurityScore || emailScan.email_security_score || 0;
      if (emailScore < 60) {
        scoreTotal += 15;
        reasoning.push(`Email security score ${emailScore}/100 indicates weak email authentication`);
      }

      const dmarc = emailScan.dmarcRecord || emailScan.dmarc_record;
      if (!dmarc?.exists || dmarc?.policy === 'none') {
        mappings.push({ tactic: 'Initial Access', technique: 'Phishing', technique_id: 'T1566', why_relevant: 'Weak DMARC enables email spoofing for credential phishing', confidence: 'High' });
        paths.push({ entry_point: 'Email Spoofing', description: 'DMARC policy allows email spoofing for phishing campaigns', attacker_goal: 'Initial access via credential phishing', likelihood: 'High', confidence: 'High' });
        findings.push({ issue: 'Weak DMARC Policy', risk_level: 'Critical', evidence_source: 'Email Scan', technical_description: 'DMARC not enforced', business_impact: 'Email spoofing enables phishing', attack_scenario: 'Attacker spoofs domain emails', remediation_steps: ['Upgrade DMARC to reject policy', 'Configure rua reporting'] });
        immediate.push('Upgrade DMARC policy to quarantine/reject');
        scoreTotal += 10;
      }
    }

    // Analyze web scan
    if (webScan) {
      const webFindings = webScan.findings || [];
      const webScore = webScan.webSecurityScore || webScan.web_security_score || 0;
      if (webScore < 50) {
        scoreTotal += 20;
        reasoning.push(`Web security score ${webScore}/100 reveals significant vulnerabilities`);
      }

      const cspMissing = webFindings.find((f: any) => f.id?.includes('csp'));
      if (cspMissing) {
        mappings.push({ tactic: 'Execution', technique: 'User Execution', technique_id: 'T1204', why_relevant: 'Missing CSP allows XSS execution', confidence: 'Medium' });
        immediate.push('Implement strict Content-Security-Policy header');
        scoreTotal += 8;
      }

      const hstsMissing = webFindings.find((f: any) => f.id?.includes('hsts'));
      if (hstsMissing) {
        mappings.push({ tactic: 'Credential Access', technique: 'Man-in-the-Middle', technique_id: 'T1557', why_relevant: 'Missing HSTS allows MITM downgrade attacks', confidence: 'Medium' });
        immediate.push('Add HSTS header with long max-age');
      }

      const adminExposed = webFindings.find((f: any) => f.id?.includes('admin'));
      if (adminExposed) {
        mappings.push({ tactic: 'Credential Access', technique: 'Brute Force', technique_id: 'T1110', why_relevant: 'Internet-facing admin panel vulnerable to brute force', confidence: 'Medium' });
        paths.push({ entry_point: 'Admin Panel', description: 'Exposed admin panel at risk of credential attacks', attacker_goal: 'Administrative access', likelihood: 'Medium', confidence: 'Medium' });
        immediate.push('Restrict admin panel via IP whitelist or VPN');
        scoreTotal += 8;
      }
    }

    // Analyze threat intel
    if (threatIntel) {
      mappings.push({ tactic: 'Discovery', technique: 'Network Service Discovery', technique_id: 'T1046', why_relevant: 'Open ports and services discovered via scanning', confidence: 'High' });
      shortTerm.push('Review and close unnecessary open ports');
    }

    // Default entries
    if (mappings.length === 0) {
      mappings.push({ tactic: 'Reconnaissance', technique: 'Active Scanning', technique_id: 'T1595', why_relevant: 'External attack surface is discoverable', confidence: 'Low' });
    }

    shortTerm.push('Enable DNSSEC', 'Add SRI to external scripts', 'Review cookie security flags');
    longTerm.push('Deploy WAF with custom rules', 'Implement security.txt', 'Conduct full penetration test', 'Establish continuous monitoring');

    recs.push(
      { priority: 1, action: 'Enforce email authentication', impact: 'Eliminates spoofing', effort: 'Low', business_justification: 'Prevents phishing attacks' },
      { priority: 2, action: 'Add security headers', impact: 'Reduces browser-side attacks', effort: 'Low', business_justification: 'Quick wins with major impact' },
      { priority: 3, action: 'Restrict admin interfaces', impact: 'Reduces attack surface', effort: 'Medium', business_justification: 'Prevents brute force attacks' },
    );

    const finalScore = Math.min(100, Math.max(0, scoreTotal));
    const rating = finalScore >= 70 ? 'Critical' : finalScore >= 40 ? 'Moderate' : finalScore >= 15 ? 'Low' : 'Minimal';

    return {
      mitre_available: true,
      attack_surface_summary: {
        external_posture: finalScore >= 40 ? 'Exposed' : 'Moderate',
        primary_exposure_vector: emailScan && !emailScan?.dmarcRecord?.exists ? 'Email Spoofing' : 'Web Application',
        confidence: 'High',
      },
      attack_score: { score: finalScore, rating, reasoning },
      potential_attack_paths: paths,
      mitre_mapping: mappings,
      priority_findings: findings,
      defensive_recommendations: recs,
      remediation_roadmap: { immediate_30_days: immediate, short_term_60_days: shortTerm, long_term_90_days: longTerm },
      attacker_view: {
        summary: rating + ' difficulty target with ' + mappings.length + ' identified attack vectors',
        difficulty_to_exploit: rating === 'Critical' ? 'Low' : 'Medium',
        first_steps: ['Enumerate email authentication records (SPF/DKIM/DMARC)', 'Probe web application headers and TLS configuration', 'Check for exposed admin interfaces and sensitive paths', 'Fingerprint technologies and look for known CVEs'],
        likely_focus: emailScan ? 'Email-based phishing and domain spoofing' : 'Web application vulnerabilities and misconfigurations',
        detailed_scenario: 'An attacker targeting ' + target + ' would begin with passive reconnaissance, gathering DNS records, WHOIS data, and technology fingerprints visible in HTTP response headers. '
          + (emailScan ? 'Email security analysis shows a score of ' + (emailScan.emailSecurityScore || emailScan.email_security_score || 0) + '/100. ' + (!emailScan?.dmarcRecord?.exists && !emailScan?.dmarc_record?.exists ? 'The absence of a proper DMARC policy means an attacker could easily spoof emails from this domain, enabling highly convincing phishing campaigns against employees, partners, or customers. ' : 'DMARC is configured but additional email hardening may be needed. ') + (!emailScan?.spfRecord?.exists && !emailScan?.spf_record?.exists ? 'Without SPF, any mail server can send emails pretending to be from this domain. ' : '') + (!emailScan?.dkimRecord?.exists && !emailScan?.dkim_record?.exists ? 'Missing DKIM means email integrity cannot be verified, allowing message tampering in transit. ' : '') : 'No email scan was performed, so email attack vectors remain unknown. ')
          + (webScan ? 'Web application analysis reveals a score of ' + (webScan.webSecurityScore || webScan.web_security_score || 0) + '/100 with ' + ((webScan.findings || []).filter((f: any) => f.severity === 'critical' || f.severity === 'high').length) + ' high/critical findings. These provide direct entry points that an attacker could exploit for unauthorized access. ' : '')
          + 'The most likely attack chain would involve initial access through ' + (emailScan && (!emailScan?.dmarcRecord?.exists && !emailScan?.dmarc_record?.exists) ? 'crafted spear-phishing emails exploiting weak email authentication, followed by credential harvesting and lateral movement within the organization.' : 'exploiting web application vulnerabilities to gain a foothold, then pivoting to internal systems.'),
        attack_narrative: [
          { step: 1, action: 'Reconnaissance & OSINT', technique: 'T1595', detail: 'Scan target infrastructure using Shodan/Censys, enumerate subdomains via DNS brute-forcing, collect email addresses from LinkedIn/OSINT sources, and fingerprint the technology stack from HTTP headers.' },
          { step: 2, action: 'Resource Development', technique: 'T1583', detail: 'Register look-alike domains for phishing, prepare credential harvesting pages mimicking the target login portal, and set up C2 infrastructure for post-exploitation.' },
          { step: 3, action: 'Initial Access', technique: emailScan ? 'T1566.001' : 'T1190', detail: emailScan ? 'Send targeted spear-phishing emails with malicious attachments or links. Weak DMARC/SPF policies allow spoofing the target domain, increasing email deliverability and victim trust.' : 'Exploit identified web vulnerabilities (missing security headers, exposed endpoints) to gain initial foothold on the web server.' },
          { step: 4, action: 'Credential Harvesting', technique: 'T1110', detail: 'Use harvested credentials from phishing or attempt brute-force attacks against discovered login endpoints. Test for password reuse across services and check for default credentials on exposed admin panels.' },
          { step: 5, action: 'Privilege Escalation & Lateral Movement', technique: 'T1078', detail: 'Use compromised accounts to access internal systems, escalate privileges through misconfigured permissions, and move laterally across the network to reach high-value targets.' },
          { step: 6, action: 'Data Exfiltration', technique: 'T1048', detail: 'Identify and collect sensitive data (customer records, financial data, intellectual property), then exfiltrate through encrypted channels to avoid detection by network monitoring.' },
        ],
        what_attacker_sees: [
          ...(emailScan ? ['Email Auth: ' + (emailScan?.spfRecord?.exists || emailScan?.spf_record?.exists ? 'SPF configured' : 'NO SPF - domain spoofing possible')] : []),
          ...(emailScan ? ['DMARC: ' + (emailScan?.dmarcRecord?.exists || emailScan?.dmarc_record?.exists ? 'Policy: ' + (emailScan?.dmarcRecord?.policy || emailScan?.dmarc_record?.policy || 'none') : 'NOT CONFIGURED - emails can be forged')] : []),
          ...(emailScan ? ['DKIM: ' + (emailScan?.dkimRecord?.exists || emailScan?.dkim_record?.exists ? 'Configured' : 'NOT FOUND - message integrity unverified')] : []),
          ...(webScan ? ['Web Security: ' + (webScan.webSecurityScore || webScan.web_security_score || '?') + '/100'] : []),
          ...(webScan ? [((webScan.findings || []).filter((f: any) => f.severity === 'critical').length) + ' critical + ' + ((webScan.findings || []).filter((f: any) => f.severity === 'high').length) + ' high severity findings'] : []),
          'DNS records expose infrastructure layout and hosting provider',
          'HTTP headers reveal server technology and framework versions',
          ...(webScan && (webScan.findings || []).some((f: any) => f.category === 'exposure') ? ['Sensitive paths/files accessible without authentication'] : []),
        ],
        risk_summary: 'Target ' + target + ' presents a ' + rating.toLowerCase() + ' risk profile with an attack score of ' + finalScore + '/100. '
          + mappings.length + ' MITRE ATT&CK techniques were mapped across the external attack surface. '
          + (finalScore >= 60 ? 'Immediate remediation is strongly recommended - the current exposure level makes successful attacks highly likely without intervention.' : finalScore >= 30 ? 'Several security improvements should be prioritized. The attack surface has exploitable gaps that a motivated attacker would likely discover.' : 'The security posture is reasonable, but continuous monitoring and periodic assessments are advised to maintain resilience against evolving threats.'),
      },
      executive_summary: {
        overview: `Analysis of ${target} reveals a ${rating.toLowerCase()} risk posture with ${mappings.length} MITRE ATT&CK techniques identified across the external attack surface.`,
        key_risks: reasoning,
        immediate_actions: immediate.slice(0, 3),
      },
      disclaimer: 'This analysis is based on external reconnaissance only. No exploitation was performed. Findings should be validated by a qualified security professional.',
    };
  }
}

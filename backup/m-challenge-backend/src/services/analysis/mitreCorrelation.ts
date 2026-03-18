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

Provide a comprehensive MITRE ATT&CK analysis. Respond ONLY with valid JSON matching this schema (no markdown, no backticks):
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
        summary: `${rating} difficulty target with ${mappings.length} identified attack vectors`,
        difficulty_to_exploit: rating === 'Critical' ? 'Low' : 'Medium',
        first_steps: ['Enumerate email authentication', 'Probe web application headers', 'Check for exposed admin interfaces'],
        likely_focus: emailScan ? 'Email-based phishing' : 'Web application vulnerabilities',
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

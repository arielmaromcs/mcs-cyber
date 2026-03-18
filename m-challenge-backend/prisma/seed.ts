/**
 * Database seed script.
 * Creates: admin user, demo user, sample scans.
 * 
 * Usage: npx tsx prisma/seed.ts
 */

import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding database...');

  // ---- Admin user ----
  const adminPassword = await bcrypt.hash('admin123', 12);
  const admin = await prisma.user.upsert({
    where: { email: 'admin@mchallenge.io' },
    update: {},
    create: {
      email: 'admin@mchallenge.io',
      passwordHash: adminPassword,
      fullName: 'Admin User',
      role: 'ADMIN',
      plan: 'ENTERPRISE',
      scansRemaining: 9999,
    },
  });
  console.log(`Admin user: ${admin.email} (password: admin123)`);

  // ---- Demo analyst user ----
  const analystPassword = await bcrypt.hash('analyst123', 12);
  const analyst = await prisma.user.upsert({
    where: { email: 'analyst@mchallenge.io' },
    update: {},
    create: {
      email: 'analyst@mchallenge.io',
      passwordHash: analystPassword,
      fullName: 'Security Analyst',
      role: 'FULL_SCANS',
      plan: 'PRO',
      scansRemaining: 100,
    },
  });
  console.log(`Analyst user: ${analyst.email} (password: analyst123)`);

  // ---- Demo basic user ----
  const basicPassword = await bcrypt.hash('user123', 12);
  const basic = await prisma.user.upsert({
    where: { email: 'user@mchallenge.io' },
    update: {},
    create: {
      email: 'user@mchallenge.io',
      passwordHash: basicPassword,
      fullName: 'Basic User',
      role: 'BASIC_SCANS',
      plan: 'FREE',
      scansRemaining: 20,
    },
  });
  console.log(`Basic user: ${basic.email} (password: user123)`);

  // ---- Sample completed web scan ----
  await prisma.webScan.create({
    data: {
      userId: analyst.id,
      url: 'https://example.com',
      domain: 'example.com',
      status: 'COMPLETED',
      progress: 100,
      stage: 'COMPLETE',
      scanProfile: 'standard',
      webSecurityScore: 52,
      dnsSecurityScore: 68,
      riskScore: 36,
      pagesScanned: 18,
      requestsMade: 243,
      scanDurationSeconds: 48,
      findingsCount: { critical: 0, high: 2, medium: 3, low: 2, info: 1 },
      findings: [
        { id: 'hsts-missing', title: 'HSTS Header Missing', category: 'headers', severity: 'high',
          description: 'HTTP Strict Transport Security not configured.', impact: 'Downgrade attacks possible',
          recommendation: 'Add Strict-Transport-Security header', owasp_category: 'A05:2021' },
        { id: 'csp-missing', title: 'Content Security Policy Missing', category: 'headers', severity: 'high',
          description: 'No CSP header present.', impact: 'XSS not mitigated at browser level',
          recommendation: 'Implement Content-Security-Policy', owasp_category: 'A05:2021' },
        { id: 'xfo-missing', title: 'X-Frame-Options Missing', category: 'headers', severity: 'medium',
          description: 'Page can be iframed.', impact: 'Clickjacking possible',
          recommendation: 'Set X-Frame-Options: DENY' },
        { id: 'dns-no-dnssec', title: 'DNSSEC Not Enabled', category: 'dns', severity: 'medium',
          description: 'Domain lacks DNSSEC.' },
        { id: 'cookie-no-samesite', title: 'Cookies Without SameSite', category: 'cookies', severity: 'medium' },
        { id: 'server-disclosure', title: 'Server Version Disclosed', category: 'disclosure', severity: 'low' },
        { id: 'xcto-missing', title: 'X-Content-Type-Options Missing', category: 'headers', severity: 'low' },
        { id: 'exposure-robots', title: 'Robots.txt Discloses Paths', category: 'disclosure', severity: 'info' },
      ],
      technologies: { server: 'nginx/1.18.0', framework: null, cdn: 'Cloudflare', waf: 'Cloudflare WAF', libraries: ['jQuery'] },
      attackSurface: { total_pages: 18, total_forms: 3, total_inputs: 14, total_cookies: 5 },
      scoreBreakdown: {
        main_domain_score: 52, raw_score_before_cap: 52, score_cap: 55, score_cap_reason: '2+ high findings',
        critical_findings: 0, high_findings: 2,
        penalty_breakdown: { critical: 0, high: 16, medium: 12, low: 4 },
      },
      dnsAnalysis: {
        dns_score: 68, config_score: 80, email_dns_score: 60, takeover_risk_score: 100, hygiene_score: 100,
        records: { a: ['93.184.216.34'], mx: ['mail.example.com'], ns: ['ns1.example.com', 'ns2.example.com'],
          txt: ['v=spf1 include:_spf.google.com ~all'] },
        dnssec: { enabled: false },
      },
      exposureFindings: [
        { path: '/robots.txt', status_code: 200, severity: 'info', source: 'crawl', accessible: true },
        { path: '/admin', status_code: 403, severity: 'medium', source: 'safe-active', accessible: false },
      ],
    },
  });
  console.log('Created sample web scan for example.com');

  // ---- Sample completed email scan ----
  await prisma.emailScan.create({
    data: {
      userId: analyst.id,
      domain: 'example.com',
      status: 'COMPLETED',
      progress: 100,
      currentStage: 'Complete',
      emailSecurityScore: 74,
      scoreBreakdown: { spf: 14, dkim: 12, dmarc: 8, relay: 18, misc: 10, ports: 12 },
      scoreRating: 'Fair',
      dnsRecords: { a_records: ['93.184.216.34'], mx_records: ['10 mail.example.com'],
        ns_records: ['ns1.example.com', 'ns2.example.com'],
        txt_records: ['v=spf1 include:_spf.google.com ~all'] },
      spfRecord: { exists: true, record: 'v=spf1 include:_spf.google.com ~all', valid: true,
        policy: 'softfail', lookups: 1, score: 14, issues: ['Uses softfail (~all)'] },
      dkimRecord: { exists: true, selectors_found: ['google'], key_length: 1024, valid: true, score: 12,
        issues: ['Key length 1024 — recommend 2048'] },
      dmarcRecord: { exists: true, record: 'v=DMARC1; p=none; rua=mailto:dmarc@example.com', valid: true,
        policy: 'none', score: 8, issues: ['Policy is none — not enforcing'] },
      findings: [
        { severity: 'medium', title: 'SPF Softfail', description: 'SPF uses ~all instead of -all' },
        { severity: 'critical', title: 'DMARC Not Enforcing', description: 'DMARC policy is none' },
        { severity: 'medium', title: 'DKIM Key Too Short', description: '1024-bit key — recommend 2048' },
      ],
      recommendations: [
        'Upgrade DMARC policy from none to quarantine/reject',
        'Change SPF from softfail (~all) to hardfail (-all)',
        'Upgrade DKIM key to 2048-bit',
      ],
      mxtoolboxLinks: {
        blacklist: 'https://mxtoolbox.com/blacklists.aspx?q=example.com',
        email_health: 'https://mxtoolbox.com/emailhealth/example.com',
      },
    },
  });
  console.log('Created sample email scan for example.com');

  // ---- Sample scan history ----
  await prisma.scanHistory.create({
    data: {
      userId: analyst.id,
      target: 'example.com',
      userEmail: analyst.email,
      attackScore: 42,
      riskLevel: 'moderate',
      emailRisk: 26,
      webRisk: 48,
      networkRisk: 0,
    },
  });
  console.log('Created sample scan history');

  console.log('\nSeed complete! Accounts:');
  console.log('  Admin:   admin@mchallenge.io / admin123');
  console.log('  Analyst: analyst@mchallenge.io / analyst123');
  console.log('  User:    user@mchallenge.io / user123');
}

main()
  .catch(e => { console.error(e); process.exit(1); })
  .finally(async () => { await prisma.$disconnect(); });

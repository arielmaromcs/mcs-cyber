/**
 * EmailService - Send emails via SMTP or Microsoft Graph.
 * Supports admin-configured gateway with header injection protection.
 */

import nodemailer from 'nodemailer';
import { config } from '../../config/env';
import { prisma } from '../../config/database';

export class EmailService {
  async send(to: string | string[], subject: string, html: string, text?: string): Promise<boolean> {
    if ([to, subject].flat().some(v => typeof v === 'string' && /[\r\n]/.test(v))) {
      throw new Error('Invalid characters in email fields');
    }
    const adminSettings = await prisma.adminEmailSettings.findFirst();
    const provider = adminSettings?.provider || config.email.provider;
    if (provider === 'microsoft_graph') {
      return await this.sendViaMicrosoftGraph(to, subject, html, adminSettings);
    }
    return await this.sendViaSmtp(to, subject, html, text, adminSettings);
  }

  async sendTest(to: string, provider?: string, settings?: any): Promise<boolean> {
    const subject = 'M-Challenge Email Test';
    const html = '<div style="font-family: sans-serif; padding: 20px;">'
      + '<h2 style="color: #2b8aff;">M-Challenge Email Test</h2>'
      + '<p>This is a test email from M-Challenge Security Scanner.</p>'
      + '<p>Provider: ' + (provider || config.email.provider) + '</p>'
      + '<p>Time: ' + new Date().toISOString() + '</p>'
      + '<p style="color: #10b981; font-weight: bold;">Email configuration is working correctly.</p>'
      + '</div>';
    if (provider === 'microsoft_graph' && settings) {
      return await this.sendViaMicrosoftGraph(to, subject, html, settings);
    }
    return await this.sendViaSmtp(to, subject, html, undefined, settings);
  }

  async sendScanNotification(
    to: string[],
    target: string,
    scanType: string,
    score: number,
    pdfUrl?: string,
    extras?: { findings?: any[]; recommendations?: string[]; scoreBreakdown?: any; rating?: string }
  ): Promise<void> {
    const scoreColor = score >= 80 ? '#10b981' : score >= 50 ? '#3b82f6' : score >= 20 ? '#f59e0b' : '#ef4444';
    const rating = (extras && extras.rating) || (score >= 90 ? 'Excellent' : score >= 70 ? 'Good' : score >= 50 ? 'Fair' : 'Needs Improvement');
    const subject = '[M-Challenge] ' + scanType + ' Scan Complete: ' + target + ' (Score: ' + score + '/100)';

    let breakdownHtml = '';
    if (extras && extras.scoreBreakdown) {
      const bd = extras.scoreBreakdown;
      const items = [
        { key: 'spf', max: 18, label: 'SPF' },
        { key: 'dkim', max: 18, label: 'DKIM' },
        { key: 'dmarc', max: 22, label: 'DMARC' },
        { key: 'relay', max: 18, label: 'Relay Protection' },
        { key: 'misc', max: 12, label: 'Infrastructure' },
        { key: 'ports', max: 12, label: 'Port Security' },
      ];
      breakdownHtml = '<table style="width:100%; border-collapse:collapse; margin: 15px 0;">';
      for (const item of items) {
        const val = bd[item.key] || 0;
        const pct = Math.round((val / item.max) * 100);
        const barColor = pct >= 80 ? '#10b981' : pct >= 50 ? '#3b82f6' : '#f59e0b';
        breakdownHtml += '<tr>'
          + '<td style="padding:6px 0; color:#8899b4; font-size:13px;">' + item.label + '</td>'
          + '<td style="padding:6px 0; text-align:right; font-weight:bold; color:#fff; font-size:13px;">' + val + '/' + item.max + '</td>'
          + '<td style="padding:6px 0; width:120px;"><div style="background:#1a2640; border-radius:4px; height:8px; overflow:hidden;"><div style="background:' + barColor + '; height:100%; width:' + pct + '%; border-radius:4px;"></div></div></td>'
          + '</tr>';
      }
      breakdownHtml += '</table>';
    }

    let findingsHtml = '';
    if (extras && extras.findings && extras.findings.length > 0) {
      const sevColors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#64748b' };
      findingsHtml = '<h3 style="color:#fb7185; margin: 20px 0 10px;">Findings</h3>';
      for (const f of extras.findings) {
        const sc = sevColors[f.severity] || '#64748b';
        findingsHtml += '<div style="background:#111827; border-left:3px solid ' + sc + '; padding:10px 12px; margin:6px 0; border-radius:0 6px 6px 0;">'
          + '<div><span style="background:' + sc + '; color:#fff; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:bold; text-transform:uppercase;">' + f.severity + '</span> '
          + '<span style="color:#fff; font-size:13px; font-weight:600;">' + f.title + '</span></div>'
          + '<p style="color:#94a3b8; font-size:12px; margin:6px 0 0;">' + f.description + '</p>'
          + '</div>';
      }
    }

    let recsHtml = '';
    if (extras && extras.recommendations && extras.recommendations.length > 0) {
      recsHtml = '<h3 style="color:#10b981; margin: 20px 0 10px;">Recommendations</h3>';
      for (const r of extras.recommendations) {
        recsHtml += '<div style="padding:6px 0; font-size:12px; color:#94a3b8;">&#10003; ' + r + '</div>';
      }
    }

    const pdfBlock = pdfUrl
      ? '<div style="text-align:center; margin: 20px 0;"><a href="' + pdfUrl + '" style="background:#2d7aff; color:#fff; padding:10px 24px; border-radius:8px; text-decoration:none; font-size:13px;">Download Report</a></div>'
      : '';

    const html = '<div style="font-family: -apple-system, sans-serif; max-width: 600px; margin: 0 auto;">'
      + '<div style="background: linear-gradient(135deg, #0c1220 0%, #1a1f3a 100%); padding: 30px; border-radius: 12px; color: #fff;">'
      + '<div style="text-align: center; margin-bottom: 20px;"><span style="color:#2d7aff; font-size:14px; font-weight:600;">M-Challenge Security Scanner</span></div>'
      + '<h2 style="color: #fff; margin: 0 0 5px; font-size: 20px;">Scan Complete</h2>'
      + '<p style="color: #8899b4; margin: 0 0 20px; font-size: 13px;">' + target + ' &bull; ' + scanType + '</p>'
      + '<div style="background: #111827; border-radius: 10px; padding: 20px; text-align: center; margin-bottom: 20px;">'
      + '<div style="color: ' + scoreColor + '; font-size: 48px; font-weight: bold;">' + score + '</div>'
      + '<div style="color: #8899b4; font-size: 13px;">out of 100 &bull; <span style="color: ' + scoreColor + ';">' + rating + '</span></div></div>'
      + breakdownHtml + findingsHtml + recsHtml + pdfBlock
      + '<hr style="border-color: #1a2640; margin: 25px 0 15px;" />'
      + '<p style="color: #4a5568; font-size: 11px; text-align: center;">M-Challenge Security Scanner</p>'
      + '</div></div>';

    try {
      await this.send(to, subject, html);
    } catch (err) {
      console.error('Failed to send scan notification:', err);
    }
  }

  // ---- Private transport methods ----

  private async sendViaSmtp(to: string | string[], subject: string, html: string, text?: string, overrides?: any): Promise<boolean> {
    const smtpConfig = {
      host: overrides?.smtpHost || overrides?.smtp_host || config.email.smtp.host,
      port: overrides?.smtpPort || overrides?.smtp_port || config.email.smtp.port,
      secure: (overrides?.smtpPort || overrides?.smtp_port || config.email.smtp.port) === 465,
      auth: {
        user: overrides?.smtpUser || overrides?.smtp_user || config.email.smtp.user,
        pass: overrides?.smtpPassword || overrides?.smtp_password || config.email.smtp.password,
      },
    };

    if (!smtpConfig.host || !smtpConfig.auth.user) {
      console.warn('SMTP not configured, skipping email');
      return false;
    }

    const transporter = nodemailer.createTransport(smtpConfig);
    const fromName = overrides?.fromName || overrides?.from_name || config.email.smtp.fromName;
    const fromEmail = overrides?.fromEmail || overrides?.from_email || config.email.smtp.fromEmail;
    await transporter.sendMail({
      from: '"' + fromName + '" <' + fromEmail + '>',
      to: Array.isArray(to) ? to.join(', ') : to,
      subject,
      html,
      text: text || html.replace(/<[^>]*>/g, ''),
    });

    return true;
  }

  private async sendViaMicrosoftGraph(to: string | string[], subject: string, html: string, settings?: any): Promise<boolean> {
    const tenantId = settings?.msTenantId || settings?.ms_tenant_id || config.email.microsoftGraph.tenantId;
    const clientId = settings?.msClientId || settings?.ms_client_id || config.email.microsoftGraph.clientId;
    const clientSecret = settings?.msClientSecret || settings?.ms_client_secret || config.email.microsoftGraph.clientSecret;
    const fromEmail = settings?.fromEmail || settings?.from_email || settings?.msFromEmail || config.email.microsoftGraph.fromEmail;

    if (!tenantId || !clientId || !clientSecret) {
      throw new Error('Microsoft Graph credentials not configured');
    }

    const tokenUrl = 'https://login.microsoftonline.com/' + tenantId + '/oauth2/v2.0/token';
    const tokenRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        scope: 'https://graph.microsoft.com/.default',
        grant_type: 'client_credentials',
      }),
    });

    if (!tokenRes.ok) throw new Error('Failed to get Microsoft Graph token');
    const tokenData: any = await tokenRes.json();

    const recipients = (Array.isArray(to) ? to : [to]).map(email => ({
      emailAddress: { address: email },
    }));

    const graphUrl = 'https://graph.microsoft.com/v1.0/users/' + fromEmail + '/sendMail';
    const mailRes = await fetch(graphUrl, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + tokenData.access_token,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        message: {
          subject,
          body: { contentType: 'HTML', content: html },
          toRecipients: recipients,
        },
        saveToSentItems: true,
      }),
    });

    if (!mailRes.ok) throw new Error('Microsoft Graph sendMail failed: ' + mailRes.status);
    return true;
  }
} 

/**
 * EmailService - Send emails via SMTP or Microsoft Graph.
 * Supports admin-configured gateway with header injection protection.
 */

import nodemailer from 'nodemailer';
import { config } from '../../config/env';
import { prisma } from '../../config/database';

export class EmailService {
  /**
   * Send an email using the configured provider.
   */
  async send(to: string | string[], subject: string, html: string, text?: string): Promise<boolean> {
    // Injection protection
    if ([to, subject].flat().some(v => typeof v === 'string' && /[\r\n]/.test(v))) {
      throw new Error('Invalid characters in email fields');
    }

    // Load admin settings (override env if available)
    const adminSettings = await prisma.adminEmailSettings.findFirst();
    const provider = adminSettings?.provider || config.email.provider;

    if (provider === 'microsoft_graph') {
      return await this.sendViaMicrosoftGraph(to, subject, html, adminSettings);
    }

    return await this.sendViaSmtp(to, subject, html, text, adminSettings);
  }

  /**
   * Send a test email.
   */
  async sendTest(to: string, provider?: string, settings?: any): Promise<boolean> {
    const subject = 'M-Challenge Email Test';
    const html = `
      <div style="font-family: sans-serif; padding: 20px;">
        <h2 style="color: #2b8aff;">M-Challenge Email Test</h2>
        <p>This is a test email from M-Challenge Security Scanner.</p>
        <p>Provider: ${provider || config.email.provider}</p>
        <p>Time: ${new Date().toISOString()}</p>
        <p style="color: #10b981; font-weight: bold;">Email configuration is working correctly.</p>
      </div>
    `;

    if (provider === 'microsoft_graph' && settings) {
      return await this.sendViaMicrosoftGraph(to, subject, html, settings);
    }

    return await this.sendViaSmtp(to, subject, html, undefined, settings);
  }

  /**
   * Send scan completion notification.
   */
  async sendScanNotification(to: string[], target: string, scanType: string, score: number, pdfUrl?: string): Promise<void> {
    const scoreColor = score >= 80 ? '#10b981' : score >= 50 ? '#3b82f6' : score >= 20 ? '#f59e0b' : '#ef4444';
    const subject = `[M-Challenge] ${scanType} Scan Complete: ${target} (Score: ${score})`;
    const html = `
      <div style="font-family: sans-serif; padding: 20px; max-width: 600px;">
        <div style="background: #0c1220; padding: 20px; border-radius: 10px; color: #fff;">
          <h2 style="color: #2b8aff; margin-top: 0;">Scan Complete</h2>
          <p><strong>Target:</strong> ${target}</p>
          <p><strong>Type:</strong> ${scanType}</p>
          <p><strong>Score:</strong> <span style="color: ${scoreColor}; font-size: 24px; font-weight: bold;">${score}/100</span></p>
          ${pdfUrl ? `<p><a href="${pdfUrl}" style="color: #2b8aff;">Download Executive Report (PDF)</a></p>` : ''}
          <hr style="border-color: #1a2640; margin: 20px 0;" />
          <p style="color: #8899b4; font-size: 12px;">M-Challenge Security Scanner</p>
        </div>
      </div>
    `;

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
    await transporter.sendMail({
      from: `"${overrides?.fromName || overrides?.from_name || config.email.smtp.fromName}" <${overrides?.fromEmail || overrides?.from_email || config.email.smtp.fromEmail}>`,
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

    // Get OAuth token
    const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
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

    // Send email
    const recipients = (Array.isArray(to) ? to : [to]).map(email => ({
      emailAddress: { address: email },
    }));

    const mailRes = await fetch(`https://graph.microsoft.com/v1.0/users/${fromEmail}/sendMail`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
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

    if (!mailRes.ok) throw new Error(`Microsoft Graph sendMail failed: ${mailRes.status}`);
    return true;
  }
}

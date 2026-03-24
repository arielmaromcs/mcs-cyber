import { FastifyInstance } from 'fastify';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

function parseSslscan(output: string, host: string): any {
  const versions: any[] = [];
  const allVersions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

  // Parse protocol support
  for (const v of allVersions) {
    const key = v.replace('v', 'v').replace('.', '\\.');
    const match = output.match(new RegExp(v.replace('.', '\\.') + '\\s+(enabled|disabled)'));
    const supported = match ? match[1] === 'enabled' : false;
    const isWeak = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'].includes(v);
    versions.push({
      version: v,
      supported,
      ciphers: [],
      warnings: [],
      risk: supported && isWeak ? 'high' : supported ? 'good' : 'none',
      note: supported && isWeak ? 'Deprecated — should be disabled' : !supported && isWeak ? 'Good — disabled' : supported ? 'Secure' : 'Not supported',
    });
  }

  // Parse ciphers
  const cipherLines = output.match(/(Preferred|Accepted)\s+(TLS\S+|SSL\S+)\s+(\d+)\s+bits\s+(\S+)(.*)/g) || [];
  for (const line of cipherLines) {
    const m = line.match(/(Preferred|Accepted)\s+(TLS\S+|SSL\S+)\s+(\d+)\s+bits\s+(\S+)(.*)/);
    if (!m) continue;
    const ver = m[2];
    const bits = parseInt(m[3]);
    const cipher = m[4];
    const extra = m[5].trim();
    const isWeak = /RC4|DES|MD5|NULL|EXPORT|anon|3DES/i.test(cipher);
    const isPFS = /ECDHE|DHE/i.test(cipher);
    const grade = isWeak ? 'F' : bits >= 256 ? 'A' : bits >= 128 ? 'B' : 'C';

    const vObj = versions.find(v => v.version === ver);
    if (vObj) {
      vObj.ciphers.push({ name: cipher, bits, extra: extra || null, grade, isPFS, isWeak });
    }
  }

  // Parse heartbleed
  const heartbleed: any = {};
  const hbLines = output.match(/TLS\S+\s+(not vulnerable|vulnerable) to heartbleed/g) || [];
  for (const l of hbLines) {
    const m = l.match(/(TLS\S+)\s+(not vulnerable|vulnerable)/);
    if (m) heartbleed[m[1]] = m[2] === 'vulnerable';
  }

  // Parse cert
  const cert: any = {};
  const subjectMatch = output.match(/Subject:\s+(.+)/);
  const issuerMatch = output.match(/Issuer:\s+(.+)/);
  const notAfterMatch = output.match(/Not valid after:\s+(.+)/);
  const notBeforeMatch = output.match(/Not valid before:\s+(.+)/);
  const altMatch = output.match(/DNS:\s*(\S+)/g);

  if (subjectMatch) cert.subject = subjectMatch[1].trim();
  if (issuerMatch) cert.issuer = issuerMatch[1].trim();
  if (notAfterMatch) {
    cert.validTo = notAfterMatch[1].trim();
    cert.daysLeft = Math.floor((new Date(cert.validTo).getTime() - Date.now()) / 86400000);
  }
  if (notBeforeMatch) cert.validFrom = notBeforeMatch[1].trim();
  if (altMatch) cert.sans = altMatch.map(s => s.replace('DNS:', '').trim());

  // Parse renegotiation & compression
  const renegotiation = output.includes('Secure session renegotiation supported');
  const compression = !output.includes('Compression disabled');
  const fallbackScsv = output.includes('Server supports TLS Fallback SCSV');

  return { versions, heartbleed, cert, renegotiation, compression, fallbackScsv };
}

export async function tlsScanRoutes(app: FastifyInstance) {
  app.post('/scan', { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { target } = request.body as { target: string };
    if (!target) return reply.status(400).send({ error: 'Target required' });

    const host = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

    try {
      const { stdout } = await execAsync(
        `sslscan --no-colour ${host}:443`,
        { timeout: 60000, shell: '/bin/sh' }
      );

      const parsed = parseSslscan(stdout, host);
      return { host, port: 443, ...parsed, scannedAt: new Date().toISOString(), raw: stdout };
    } catch (err: any) {
      return reply.status(500).send({ error: 'Scan failed: ' + err.message });
    }
  });
}

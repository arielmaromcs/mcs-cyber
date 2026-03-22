import { FastifyInstance } from 'fastify';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as tls from 'tls';

const execAsync = promisify(exec);

async function checkTlsVersion(host: string, port: number, version: string): Promise<{ supported: boolean; ciphers: string[] }> {
  try {
    const flagMap: Record<string, string> = {
      'TLSv1.0': '-tls1',
      'TLSv1.1': '-tls1_1',
      'TLSv1.2': '-tls1_2',
      'TLSv1.3': '-tls1_3',
    };
    const flag = flagMap[version];
    const { stdout } = await execAsync(
      `echo | timeout 5 openssl s_client -connect ${host}:${port} ${flag} -cipher ALL 2>/dev/null | grep -E "Cipher|Protocol|SSL-Session"`,
      { timeout: 8000 }
    );
    const supported = stdout.includes('Cipher') && !stdout.includes('no peer certificate');
    const cipherMatch = stdout.match(/Cipher\s+:\s+(.+)/);
    const ciphers = cipherMatch ? [cipherMatch[1].trim()] : [];
    return { supported, ciphers };
  } catch {
    return { supported: false, ciphers: [] };
  }
}

async function getCiphersForVersion(host: string, port: number, version: string): Promise<string[]> {
  try {
    const flagMap: Record<string, string> = {
      'TLSv1.2': '-tls1_2',
      'TLSv1.3': '-tls1_3',
    };
    const flag = flagMap[version];
    if (!flag) return [];

    const { stdout: cipherList } = await execAsync(`openssl ciphers ${version === 'TLSv1.3' ? 'TLSv1.3' : 'ALL'} 2>/dev/null`);
    const ciphers = cipherList.trim().split(':').slice(0, 20);
    const supported: string[] = [];

    for (const cipher of ciphers.slice(0, 10)) {
      try {
        const { stdout } = await execAsync(
          `echo | timeout 3 openssl s_client -connect ${host}:${port} ${flag} -cipher "${cipher}" 2>/dev/null | grep "Cipher"`,
          { timeout: 5000 }
        );
        if (stdout.includes(cipher) || stdout.includes('Cipher') && !stdout.includes('0000')) {
          supported.push(cipher);
        }
      } catch {}
    }
    return supported;
  } catch {
    return [];
  }
}

async function getCertInfo(host: string, port: number): Promise<any> {
  try {
    const { stdout } = await execAsync(
      `echo | timeout 5 openssl s_client -connect ${host}:${port} -servername ${host} 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep -E "Subject:|Issuer:|Not Before|Not After|Subject Alternative"`,
      { timeout: 8000 }
    );
    const lines = stdout.split('\n').map(l => l.trim()).filter(Boolean);
    const notAfterLine = lines.find(l => l.includes('Not After'));
    const notBeforeLine = lines.find(l => l.includes('Not Before'));
    const subjectLine = lines.find(l => l.startsWith('Subject:'));
    const issuerLine = lines.find(l => l.startsWith('Issuer:'));
    const sanLine = lines.find(l => l.includes('DNS:'));

    const notAfter = notAfterLine ? notAfterLine.replace('Not After :', '').trim() : null;
    const notBefore = notBeforeLine ? notBeforeLine.replace('Not Before:', '').trim() : null;
    const daysLeft = notAfter ? Math.floor((new Date(notAfter).getTime() - Date.now()) / 86400000) : null;

    return {
      subject: subjectLine?.replace('Subject:', '').trim() || null,
      issuer: issuerLine?.replace('Issuer:', '').trim() || null,
      validFrom: notBefore,
      validTo: notAfter,
      daysLeft,
      sans: sanLine?.match(/DNS:[^,\s]+/g)?.map(s => s.replace('DNS:', '')) || [],
    };
  } catch {
    return null;
  }
}

export async function tlsScanRoutes(app: FastifyInstance) {
  app.post('/scan', { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { target } = request.body as { target: string };
    if (!target) return reply.status(400).send({ error: 'Target required' });

    const host = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    const port = 443;

    const versions = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
    const results: any[] = [];

    for (const version of versions) {
      const check = await checkTlsVersion(host, port, version);
      let ciphers: string[] = check.ciphers;

      if (check.supported && (version === 'TLSv1.2' || version === 'TLSv1.3')) {
        const detailed = await getCiphersForVersion(host, port, version);
        if (detailed.length > 0) ciphers = detailed;
      }

      const isWeak = version === 'TLSv1.0' || version === 'TLSv1.1';
      results.push({
        version,
        supported: check.supported,
        ciphers,
        risk: check.supported && isWeak ? 'high' : check.supported ? 'good' : 'none',
        note: isWeak && check.supported
          ? 'Deprecated — should be disabled'
          : !check.supported && isWeak
          ? 'Good — disabled'
          : check.supported
          ? 'Secure'
          : 'Not supported',
      });
    }

    const cert = await getCertInfo(host, port);

    return { host, port, results, cert, scannedAt: new Date().toISOString() };
  });
}

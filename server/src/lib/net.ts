/** Minimal IPv4 CIDR matching for the POC's optional source-IP restrictions. */
export function normalizeIp(ip: string | undefined): string {
  if (!ip) return '0.0.0.0';
  if (ip === '::1') return '127.0.0.1';
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  return ip;
}

function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!/^\d{1,3}$/.test(p) || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

export function isValidCidr(cidr: string): boolean {
  const [ip, bits] = cidr.split('/');
  return ipToInt(ip ?? '') !== null && (bits === undefined || (/^\d+$/.test(bits) && Number(bits) <= 32));
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.split('/');
  const bits = bitsStr === undefined ? 32 : Number(bitsStr);
  const a = ipToInt(ip);
  const b = ipToInt(base ?? '');
  if (a === null || b === null) return false;
  const block = 2 ** (32 - bits);
  return Math.floor(a / block) === Math.floor(b / block);
}

export function ipAllowed(ip: string, cidrs: string[]): boolean {
  return cidrs.length === 0 || cidrs.some((c) => ipInCidr(ip, c));
}

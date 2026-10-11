// Pure model of a meshmsg attachment share + explicit download.
// Order of checks mirrors src/attachment/transfer.rs (share_attachment, download_attachment).
export const KiB = 1024, MiB = 1024 * KiB, GiB = 1024 * MiB;
export const BLOCK = 16 * KiB;          // iroh-blobs IROH_BLOCK_SIZE: chunk log 4 = 16 KiB verified groups
export const PROGRESS_STEP = 8 * MiB;   // contracts.md: download progress step
export const DEFAULT_LIMIT = 4 * GiB;   // contracts.md: default maximum file/archive blob
export const FILES = [
  { id: 'notes', name: 'notes.pdf', size: Math.round(2.4 * MiB) },
  { id: 'results', name: 'results.tar', size: 240 * MiB },
  { id: 'capture', name: 'capture.mov', size: Math.round(1.6 * GiB) },
];
export const LIMITS = [
  { id: 'default', label: '4 GiB (default)', bytes: DEFAULT_LIMIT },
  { id: 'small', label: '64 MiB', bytes: 64 * MiB },
];
export const PHASES = ['pin', 'offer', 'wait', 'check', 'connect', 'stream', 'commit', 'install'];

export function defaults() {
  return { file: 'results', limit: 'default', providerOnline: true, destExists: false, tamper: false, dedup: false };
}
const fileOf = (o) => FILES.find((f) => f.id === o.file) ?? FILES[1];
const limitOf = (o) => (LIMITS.find((l) => l.id === o.limit) ?? LIMITS[0]).bytes;

// Returns the phases that will run and where (if anywhere) the download fails.
export function plan(options) {
  const file = fileOf(options), limit = limitOf(options);
  const steps = ['pin', 'offer', 'wait', 'check'];
  let fail = null;
  if (options.destExists) fail = { at: 'check', code: 'download_failed', why: 'The output path already exists. meshmsg never overwrites; it stops before any network work.' };
  else if (file.size > limit) fail = { at: 'check', code: 'download_failed', why: `The signed offer declares ${bytes(file.size)}, above this receiver's ${bytes(limit)} limit. Rejected before connecting.` };
  if (!fail) {
    if (options.dedup) steps.push('commit', 'install');
    else {
      steps.push('connect');
      if (!options.providerOnline) fail = { at: 'connect', code: 'download_failed', why: 'Bytes come only from the provider named in the offer. It is offline, so the connection times out and nothing is installed.' };
      else {
        steps.push('stream');
        if (options.tamper) fail = { at: 'stream', code: 'download_failed', why: 'A block did not match the BLAKE3 hash in the offer. Verified streaming rejects it; nothing is installed.' };
        else steps.push('commit', 'install');
      }
    }
  }
  return { file, limit, steps, fail, transfers: steps.includes('stream') };
}

// Where tampering is detected: the block at 45 % of the stream (deterministic for the demo).
export const TAMPER_AT = 0.45;

export function counters(size, received, complete) {
  const r = Math.max(0, Math.min(size, Math.floor(received)));
  const blocks = complete ? Math.ceil(size / BLOCK) : Math.floor(r / BLOCK);
  let events = Math.floor(r / PROGRESS_STEP);
  if (complete && size > 0 && size % PROGRESS_STEP !== 0) events += 1;
  return { received: r, blocks, events };
}

export function bytes(n) {
  if (n >= GiB) return `${(n / GiB).toFixed(n % GiB ? 1 : 0)} GiB`;
  if (n >= MiB) return `${(n / MiB).toFixed(n % MiB ? 1 : 0)} MiB`;
  if (n >= KiB) return `${(n / KiB).toFixed(0)} KiB`;
  return `${n} B`;
}

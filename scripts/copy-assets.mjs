import { copyFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const assets = [
  ['src/db/schema.sql', 'dist/db/schema.sql'],
  ['src/ui/dashboard.html', 'dist/ui/dashboard.html'],
];

for (const [srcRel, destRel] of assets) {
  const src = resolve(root, srcRel);
  const dest = resolve(root, destRel);
  await mkdir(dirname(dest), { recursive: true });
  await copyFile(src, dest);
  console.log(`Copied ${srcRel} -> ${destRel}`);
}

// Reproducible notices for the locked installed production dependency closure.
import { readFileSync, readdirSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
const packages = Object.entries(lock.packages).filter(([path, item]) => path.includes('node_modules/') && !item.dev && !item.link)
  .sort(([a], [b]) => a.localeCompare(b, 'en'));
const notices = [readFileSync(join(root, 'THIRD-PARTY-NOTICES.md'), 'utf8')];
const inventory = [];
for (const [path, item] of packages) {
  const directory = join(root, path);
  if (!existsSync(directory)) {
    if (item.optional) continue;
    throw new Error('Missing locked production package: ' + path);
  }
  const metadata = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
  if (metadata.version !== item.version) throw new Error('Installed/locked version mismatch: ' + path);
  const files = readdirSync(directory).filter(name => /^(licen[cs]e|copying|copyright|notice)([.-]|$)/i.test(name)).sort();
  if (!files.length) throw new Error('Missing license text: ' + path);
  inventory.push({ path, name: metadata.name, version: metadata.version, license: metadata.license ?? item.license ?? 'SEE LICENSE', files });
  notices.push('\n\n----- ' + metadata.name + '@' + metadata.version + ' (' + path + ') -----\n');
  for (const name of files) notices.push('\n' + name + '\n' + readFileSync(join(directory, name), 'utf8'));
}
const target = join(root, 'dist', 'licenses'); mkdirSync(target, { recursive: true });
writeFileSync(join(target, 'THIRD-PARTY-NOTICES.txt'), notices.join(''));
writeFileSync(join(target, 'dependencies.json'), JSON.stringify(inventory, null, 2) + '\n');
console.log('Generated full notices for ' + inventory.length + ' installed production packages.');

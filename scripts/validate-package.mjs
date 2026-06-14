import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const errors = [];

function relPath(rel) {
  return path.join(root, rel);
}

function exists(rel) {
  return fs.existsSync(relPath(rel));
}

function requireFile(rel) {
  if (!exists(rel) || !fs.statSync(relPath(rel)).isFile()) {
    errors.push(`missing required file: ${rel}`);
  }
}

function requireDir(rel) {
  if (!exists(rel) || !fs.statSync(relPath(rel)).isDirectory()) {
    errors.push(`missing required directory: ${rel}`);
  }
}

function requirePackageFile(pkg, rel) {
  const files = Array.isArray(pkg.files) ? pkg.files : [];
  const normalized = rel.endsWith('/') ? rel : rel.replaceAll('\\', '/');
  if (!files.includes(normalized)) {
    errors.push(`package.json files[] does not include ${normalized}`);
  }
}

function readJson(rel) {
  try {
    return JSON.parse(fs.readFileSync(relPath(rel), 'utf8'));
  } catch (error) {
    errors.push(`could not read ${rel}: ${error.message}`);
    return {};
  }
}

const pkg = readJson('package.json');

if (pkg.private === true) errors.push('package must not be private for public npm release');
if (pkg.name !== 'credential-airlock') errors.push('package name must be credential-airlock');
if (!pkg.version) errors.push('package version is required');
if (pkg.license !== 'Apache-2.0') errors.push('license must stay Apache-2.0');
if (pkg.author !== 'Classeve') errors.push('author must be Classeve');
if (!pkg.repository?.url?.includes('github.com/classeve-public/credential-airlock')) errors.push('repository.url must point at classeve-public/credential-airlock');
if (!pkg.homepage?.includes('github.com/classeve-public/credential-airlock')) errors.push('homepage must point at classeve-public/credential-airlock');
if (!pkg.bugs?.url?.includes('github.com/classeve-public/credential-airlock/issues')) errors.push('bugs.url must point at classeve-public/credential-airlock/issues');
if (pkg.publishConfig?.access !== 'public') errors.push('publishConfig.access must be public');
if (pkg.engines?.node !== '>=20.0.0') errors.push('engines.node must remain >=20.0.0');

if (pkg.main !== 'dist/index.js') errors.push('main must point at dist/index.js');
if (pkg.bin?.airlock !== 'dist/index.js') errors.push('bin.airlock must point at dist/index.js');

for (const field of ['prepare', 'prepack', 'prepublishOnly', 'package:check', 'smoke:install']) {
  if (!pkg.scripts?.[field]) errors.push(`missing npm script: ${field}`);
}

for (const item of ['dist/', 'deploy/', 'docs/', 'public/']) {
  requirePackageFile(pkg, item);
}

for (const item of ['README.md', 'NOTICE.md', 'LICENSE', 'CHANGELOG.md', 'SECURITY.md', 'CONTRIBUTING.md', 'policy.example.json', 'Dockerfile', 'docker-compose.yml']) {
  requirePackageFile(pkg, item);
}

requireFile('dist/index.js');
requireFile('public/index.html');
requireFile('public/app.js');
requireFile('NOTICE.md');
requireFile('policy.example.json');
requireFile('Dockerfile');
requireFile('docker-compose.yml');
requireDir('docs');
requireFile('docs/INSTALL.md');
requireFile('docs/QUICKSTART.md');
requireFile('docs/DEPLOY.md');
requireFile('docs/LAUNCH.md');
requireFile('docs/RELEASE.md');
requireDir('deploy');

if (exists('dist/index.js')) {
  const firstLine = fs.readFileSync(relPath('dist/index.js'), 'utf8').split(/\r?\n/, 1)[0];
  if (firstLine !== '#!/usr/bin/env node') {
    errors.push('dist/index.js must keep the node shebang for the airlock bin');
  }
}

if (exists('.gitignore')) {
  const gitignore = fs.readFileSync(relPath('.gitignore'), 'utf8');
  for (const pattern of ['.airlock/', 'airlock-data/', '*.vault', 'vdk.seal', '*.pem', '*.key', 'audit.jsonl']) {
    if (!gitignore.includes(pattern)) errors.push(`.gitignore must protect ${pattern}`);
  }
} else {
  errors.push('missing .gitignore');
}

if (errors.length) {
  console.error('package validation failed:');
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}

console.log(`package validation ok: ${pkg.name}@${pkg.version}`);

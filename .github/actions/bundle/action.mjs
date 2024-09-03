import fs from 'node:fs/promises';
import * as core from '@actions/core';
import * as exec from '@actions/exec';

let binary  = process.env.BINARY;
let name    = process.env.NAME;
let target  = process.env.TARGET;
let version = process.env.VERSION;

let [arch, _, os] = target.split('-');

switch (arch) {
    case 'aarch64':
        arch = 'arm64';
        break;
    case 'armv7':
        arch = 'arm';
        break;
    case 'x86_64':
        arch = 'amd64';
        break;
}

let bundle = `${name}_${version}_${os}_${arch}.tgz`;
let prefix = `${name}-${version}`;

let dir = `${prefix}/bin`;
let bin = `${prefix}/bin/${binary}`;

await fs.mkdir(dir, { recursive: true });
await fs.copyFile(binary, bin);
await fs.chmod(bin, '0755');

await exec.exec(`tar -czvf ${bundle} ${prefix}`);

core.setOutput('bundle', bundle);

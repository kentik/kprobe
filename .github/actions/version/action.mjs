import { env } from 'node:process';
import { Octokit } from '@octokit/rest';
import { notice, setOutput } from '@actions/core';
import { inc, parse, valid } from 'semver';

let octokit = new Octokit({ auth: env.GITHUB_TOKEN });
let github  = octokit.rest;

let [owner, repo] = env.GITHUB_REPOSITORY.split('/');
let ref = env.GITHUB_REF;
let build = env.GITHUB_RUN_NUMBER ?? 0;

let result = {
    'version':    'INVALID',
    'prerelease': false,
    'publish':    [],
    'release':    false,
}

if (ref.startsWith('refs/tags/')) {
    let [,, tag] = ref.split('/');
    let version  = parse(`v${tag}`);

    if (version) {
        result.version    = version.version;
        result.prerelease = version.prerelease.length > 0;
        result.publish    = ['bundle', 'package'];
        result.release    = true;
    }
} else {
    let branch = 'unknown';

    if (ref.startsWith('refs/heads/')) {
        branch = ref.split('/')[2];
    }

    let res = await github.repos.listTags({ owner, repo });
    let tag = res?.data?.[0]?.name ?? '0.0.0';
    let version = parse(`v${tag}`);

    if (version) {
        version = inc(version, 'prerelease', `${branch}.${build}`, false);
        result.version    = version;
        result.prerelease = true;
        result.publish    = ['bundle'];
        result.release    = false;
    }
}

notice(`version ${result.version}`);

console.log(result);

setOutput('version',    result.version);
setOutput('prerelease', result.prerelease);
setOutput('publish',    result.publish.join(','));
setOutput('release',    result.release);

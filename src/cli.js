#!/usr/bin/env node

const chalk = require('chalk');
const path = require('path');
const Scanner = require('./scanner');

const DEFAULT_DB_PATH = path.join(__dirname, '..', 'vulnerability-db.json');

async function main() {
    const args = process.argv.slice(2);
    const options = parseArgs(args);

    if (options.help) {
        showHelp();
        return;
    }

    const scanner = new Scanner({
        ignoreDevDependencies: options.ignoreDevDependencies,
        ignorePatches: options.ignorePatches
    });

    // Load vulnerability database
    console.log(chalk.blue('Loading vulnerability database...'));
    const dbLoaded = await scanner.loadVulnerabilityDB(options.dbPath || DEFAULT_DB_PATH);
    if (!dbLoaded) {
        console.error(chalk.red('Failed to load vulnerability database.'));
        process.exit(1);
    }

    // Scan package.json
    const packagePath = path.resolve(process.cwd(), options.package || 'package.json');
    console.log(chalk.blue(`Scanning ${packagePath}...`));
    
    const vulnerabilities = await scanner.scanPackageJson(packagePath);
    
    // Report findings
    reportVulnerabilities(vulnerabilities);
}

function parseArgs(args) {
    const options = {
        ignoreDevDependencies: false,
        ignorePatches: false
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--help':
            case '-h':
                options.help = true;
                break;
            case '--ignore-dev':
                options.ignoreDevDependencies = true;
                break;
            case '--ignore-patches':
                options.ignorePatches = true;
                break;
            case '--db':
                options.dbPath = args[++i];
                break;
            case '--package':
            case '-p':
                options.package = args[++i];
                break;
        }
    }

    return options;
}

function showHelp() {
    console.log(`
${chalk.bold('JSentinel - JavaScript Security Scanner')}

Usage: jsentinel [options]

Options:
    -h, --help          Show this help message
    --ignore-dev        Ignore devDependencies in package.json
    --ignore-patches    Ignore patch versions in vulnerability checks
    --db <path>        Path to custom vulnerability database
    -p, --package      Path to package.json (default: ./package.json)

Example:
    jsentinel --ignore-dev -p ./frontend/package.json
`);
}

function reportVulnerabilities(vulnerabilities) {
    if (vulnerabilities.length === 0) {
        console.log(chalk.green('\n✔ No vulnerabilities found!'));
        return;
    }

    console.log(chalk.red(`\n✖ Found ${vulnerabilities.length} vulnerabilities:\n`));

    vulnerabilities.forEach((vuln, index) => {
        console.log(chalk.yellow(`${index + 1}. ${vuln.package}@${vuln.version}`));
        console.log(chalk.grey(`   Severity: ${vuln.vulnerability.severity}`));
        console.log(chalk.grey(`   Summary: ${vuln.vulnerability.summary}`));
        if (vuln.vulnerability.cwe) {
            console.log(chalk.grey(`   CWE: ${vuln.vulnerability.cwe.join(', ')}`));
        }
        if (vuln.vulnerability.identifiers?.CVE) {
            console.log(chalk.grey(`   CVE: ${vuln.vulnerability.identifiers.CVE.join(', ')}`));
        }
        console.log('');
    });

    process.exit(vulnerabilities.length === 0 ? 0 : 1);
}

main().catch(error => {
    console.error(chalk.red('Error:', error.message));
    process.exit(1);
});

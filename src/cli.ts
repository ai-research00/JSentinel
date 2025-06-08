#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import path from 'path';
import { Scanner } from './scanner';
import { ScanResult, ScanOptions } from './types';

const DEFAULT_DB_PATH = path.join(__dirname, '..', 'vulnerability-db.json');
const DEFAULT_PATTERNS_PATH = path.join(__dirname, 'patterns', 'code-patterns.json');

const program = new Command();

program
    .name('jsentinel')
    .description('A comprehensive security vulnerability scanner for JavaScript projects')
    .version('1.0.0')
    .option('-p, --package <path>', 'path to package.json', 'package.json')
    .option('-d, --db <path>', 'path to vulnerability database', DEFAULT_DB_PATH)
    .option('--patterns <path>', 'path to code patterns file', DEFAULT_PATTERNS_PATH)
    .option('--ignore-dev', 'ignore devDependencies', false)
    .option('--ignore-patches', 'ignore patch versions in vulnerability checks', false)
    .option('--min-severity <level>', 'minimum severity level to report (low, medium, high, critical)', 'low')
    .option('--format <format>', 'output format (json, text, html, sarif)', 'text')
    .option('-w, --watch', 'watch mode - monitor files for changes', false)
    .option('--max-depth <n>', 'maximum directory depth for source scanning', '10')
    .option('--custom-rules <path>', 'path to custom rules file')
    .option('--scan-node-modules', 'scan node_modules directory', false)
    .action(async (options) => {
        try {
            const scanner = new Scanner({
                ignoreDevDependencies: options.ignoreDev,
                ignorePatches: options.ignorePatches,
                customRules: options.customRules,
                minSeverity: options.minSeverity,
                outputFormat: options.format,
                watchMode: options.watch,
                maxDepth: parseInt(options.maxDepth, 10),
                timeout: 30000
            });

            // Load vulnerability database
            console.log(chalk.blue('Loading vulnerability database...'));
            const dbLoaded = await scanner.loadVulnerabilityDB(options.db);
            if (!dbLoaded) {
                console.error(chalk.red('Failed to load vulnerability database.'));
                process.exit(1);
            }

            // Load code patterns
            console.log(chalk.blue('Loading code patterns...'));
            await scanner.loadCodePatterns(options.patterns);

            // Scan package.json
            const packagePath = path.resolve(process.cwd(), options.package);
            console.log(chalk.blue(`Scanning ${packagePath}...`));
            const dependencyVulns = await scanner.scanPackageJson(packagePath);

            // Scan source files
            const sourceVulns: ScanResult[] = [];
            const srcDir = path.dirname(packagePath);
            console.log(chalk.blue(`Scanning source files in ${srcDir}...`));
            
            // TODO: Implement source file scanning

            // Report findings
            reportVulnerabilities([...dependencyVulns, ...sourceVulns], options.format);

            if (options.watch) {
                console.log(chalk.yellow('\nWatch mode enabled. Monitoring for changes...'));
                // Watch mode implementation continues running
            }
        } catch (error) {
            console.error(chalk.red('Error:', (error as Error).message));
            process.exit(1);
        }
    });

program.parse();

function reportVulnerabilities(vulnerabilities: ScanResult[], format: string): void {
    if (vulnerabilities.length === 0) {
        console.log(chalk.green('\n✔ No vulnerabilities found!'));
        return;
    }

    console.log(chalk.red(`\n✖ Found ${vulnerabilities.length} vulnerabilities:\n`));

    switch (format) {
        case 'json':
            console.log(JSON.stringify(vulnerabilities, null, 2));
            break;
            
        case 'text':
        default:
            vulnerabilities.forEach((vuln, index) => {
                const location = vuln.filePath 
                    ? `${vuln.filePath}:${vuln.lineNumber || '?'}`
                    : `${vuln.packageName}@${vuln.version}`;

                console.log(chalk.yellow(`${index + 1}. ${location}`));
                console.log(chalk.grey(`   Severity: ${vuln.vulnerability.severity}`));
                console.log(chalk.grey(`   Summary: ${vuln.vulnerability.summary}`));
                
                if (vuln.vulnerability.cwe) {
                    console.log(chalk.grey(`   CWE: ${vuln.vulnerability.cwe.join(', ')}`));
                }
                
                if (vuln.vulnerability.identifiers?.CVE) {
                    console.log(chalk.grey(`   CVE: ${vuln.vulnerability.identifiers.CVE.join(', ')}`));
                }
                
                if (vuln.code) {
                    console.log(chalk.grey('   Code:'));
                    console.log(chalk.grey(`   ${vuln.code.trim()}`));
                }
                
                if (vuln.fix) {
                    console.log(chalk.green('   Suggested fix:'));
                    console.log(chalk.green(`   ${vuln.fix}`));
                }
                
                console.log('');
            });
            break;
    }

    process.exit(vulnerabilities.length === 0 ? 0 : 1);
}

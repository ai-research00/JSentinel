import { ScanResult } from '../types';
import * as fs from 'fs';
import * as path from 'path';

export interface Reporter {
    report(results: ScanResult[]): string | Promise<string>;
}

export class TextReporter implements Reporter {
    report(results: ScanResult[]): string {
        return results.map(result => {
            const location = result.filePath ? 
                `${result.filePath}:${result.lineNumber || 0}:${result.columnNumber || 0}` : 
                `${result.packageName}@${result.version}`;

            return [
                `[${result.vulnerability.severity.toUpperCase()}] ${location}`,
                `Summary: ${result.vulnerability.summary}`,
                result.vulnerability.cwe ? `CWE: ${result.vulnerability.cwe.join(', ')}` : '',
                result.code ? `Code: ${result.code}` : '',
                result.fix ? `Fix: ${result.fix}` : '',
                ''
            ].filter(Boolean).join('\n');
        }).join('\n');
    }
}

export class JSONReporter implements Reporter {
    report(results: ScanResult[]): string {
        return JSON.stringify(results, null, 2);
    }
}

export class SARIFReporter implements Reporter {
    report(results: ScanResult[]): string {
        const sarifReport = {
            $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: [
                {
                    tool: {
                        driver: {
                            name: "JSentinel",
                            version: "1.0.0",
                            rules: this.generateRules(results)
                        }
                    },
                    results: this.generateResults(results)
                }
            ]
        };

        return JSON.stringify(sarifReport, null, 2);
    }

    private generateRules(results: ScanResult[]) {
        const rules = new Map<string, any>();

        results.forEach(result => {
            if (!result.matchedPattern) return;

            const ruleId = result.matchedPattern.id;
            if (!rules.has(ruleId)) {
                rules.set(ruleId, {
                    id: ruleId,
                    name: result.matchedPattern.description,
                    shortDescription: {
                        text: result.matchedPattern.description
                    },
                    fullDescription: {
                        text: result.vulnerability.summary
                    },
                    defaultConfiguration: {
                        level: this.convertSeverity(result.vulnerability.severity)
                    },
                    help: {
                        text: result.fix || "No fix suggestion available"
                    }
                });
            }
        });

        return Array.from(rules.values());
    }

    private generateResults(results: ScanResult[]) {
        return results.map(result => ({
            ruleId: result.matchedPattern?.id || "vulnerability",
            level: this.convertSeverity(result.vulnerability.severity),
            message: {
                text: result.vulnerability.summary
            },
            locations: result.filePath ? [{
                physicalLocation: {
                    artifactLocation: {
                        uri: result.filePath
                    },
                    region: {
                        startLine: result.lineNumber || 0,
                        startColumn: result.columnNumber || 0
                    }
                }
            }] : [],
            partialFingerprints: {
                primaryLocationHash: this.generateHash(result)
            }
        }));
    }

    private convertSeverity(severity: string): string {
        const mapping: Record<string, string> = {
            critical: 'error',
            high: 'error',
            medium: 'warning',
            low: 'note'
        };
        return mapping[severity] || 'warning';
    }

    private generateHash(result: ScanResult): string {
        const content = [
            result.filePath,
            result.lineNumber,
            result.columnNumber,
            result.vulnerability.summary
        ].join('|');
        
        // Simple hash function for demonstration
        let hash = 0;
        for (let i = 0; i < content.length; i++) {
            const char = content.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(16);
    }
}

export class HTMLReporter implements Reporter {
    report(results: ScanResult[]): string {
        const template = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>JSentinel Security Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .critical { color: #d63031; }
                    .high { color: #e17055; }
                    .medium { color: #fdcb6e; }
                    .low { color: #00b894; }
                    .vulnerability {
                        border: 1px solid #ddd;
                        padding: 10px;
                        margin: 10px 0;
                        border-radius: 4px;
                    }
                    .code {
                        background: #f8f9fa;
                        padding: 10px;
                        border-radius: 4px;
                        font-family: monospace;
                    }
                    .fix {
                        background: #d5f5e3;
                        padding: 10px;
                        border-radius: 4px;
                        margin-top: 5px;
                    }
                </style>
            </head>
            <body>
                <h1>JSentinel Security Report</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total vulnerabilities found: ${results.length}</p>
                    <p>
                        Critical: ${this.countBySeverity(results, 'critical')} |
                        High: ${this.countBySeverity(results, 'high')} |
                        Medium: ${this.countBySeverity(results, 'medium')} |
                        Low: ${this.countBySeverity(results, 'low')}
                    </p>
                </div>
                <div class="vulnerabilities">
                    ${results.map(this.renderVulnerability).join('\n')}
                </div>
            </body>
            </html>
        `;

        return template.trim();
    }

    private countBySeverity(results: ScanResult[], severity: string): number {
        return results.filter(r => r.vulnerability.severity === severity).length;
    }

    private renderVulnerability(result: ScanResult): string {
        const location = result.filePath ? 
            `${result.filePath}:${result.lineNumber || 0}:${result.columnNumber || 0}` : 
            `${result.packageName}@${result.version}`;

        return `
            <div class="vulnerability">
                <h3 class="${result.vulnerability.severity}">
                    [${result.vulnerability.severity.toUpperCase()}] ${location}
                </h3>
                <p><strong>Summary:</strong> ${result.vulnerability.summary}</p>
                ${result.vulnerability.cwe ? 
                    `<p><strong>CWE:</strong> ${result.vulnerability.cwe.join(', ')}</p>` : 
                    ''}
                ${result.code ? 
                    `<div class="code"><strong>Code:</strong><pre>${result.code}</pre></div>` : 
                    ''}
                ${result.fix ? 
                    `<div class="fix"><strong>Fix:</strong><pre>${result.fix}</pre></div>` : 
                    ''}
            </div>
        `;
    }
}

export function createReporter(format: string): Reporter {
    switch (format.toLowerCase()) {
        case 'json':
            return new JSONReporter();
        case 'sarif':
            return new SARIFReporter();
        case 'html':
            return new HTMLReporter();
        case 'text':
        default:
            return new TextReporter();
    }
}

const axios = require('axios');
const fs = require('fs');
const path = require('path');

class Scanner {
    constructor(options = {}) {
        this.vulnerabilityDB = new Map();
        this.options = {
            ignoreDevDependencies: false,
            ignorePatches: false,
            ...options
        };
    }

    async loadVulnerabilityDB(dbPath) {
        try {
            const rawData = await fs.promises.readFile(dbPath, 'utf8');
            const data = JSON.parse(rawData);
            
            // Process and store vulnerability data
            Object.entries(data).forEach(([library, info]) => {
                this.vulnerabilityDB.set(library, info);
            });
            
            return true;
        } catch (error) {
            console.error('Error loading vulnerability database:', error);
            return false;
        }
    }

    async scanPackageJson(packagePath) {
        try {
            const rawData = await fs.promises.readFile(packagePath, 'utf8');
            const packageJson = JSON.parse(rawData);
            
            const vulnerabilities = [];
            
            // Scan dependencies
            await this._scanDependencies(packageJson.dependencies, vulnerabilities);
            
            // Scan devDependencies if not ignored
            if (!this.options.ignoreDevDependencies && packageJson.devDependencies) {
                await this._scanDependencies(packageJson.devDependencies, vulnerabilities);
            }
            
            return vulnerabilities;
        } catch (error) {
            console.error('Error scanning package.json:', error);
            return [];
        }
    }

    async _scanDependencies(dependencies, vulnerabilities) {
        if (!dependencies) return;

        for (const [package, version] of Object.entries(dependencies)) {
            const cleanVersion = version.replace(/[^0-9.]/g, '');
            const vulnInfo = this.vulnerabilityDB.get(package);
            
            if (vulnInfo) {
                vulnInfo.vulnerabilities.forEach(vuln => {
                    if (this._isVersionVulnerable(cleanVersion, vuln.ranges)) {
                        vulnerabilities.push({
                            package,
                            version,
                            vulnerability: {
                                severity: vuln.severity,
                                summary: vuln.summary,
                                cwe: vuln.cwe,
                                identifiers: vuln.identifiers
                            }
                        });
                    }
                });
            }
        }
    }

    _isVersionVulnerable(version, ranges) {
        return ranges.some(range => {
            const versionNum = this._parseVersion(version);
            const atOrAbove = range.atOrAbove ? this._parseVersion(range.atOrAbove) : null;
            const below = range.below ? this._parseVersion(range.below) : null;
            
            if (atOrAbove && below) {
                return versionNum >= atOrAbove && versionNum < below;
            } else if (atOrAbove) {
                return versionNum >= atOrAbove;
            } else if (below) {
                return versionNum < below;
            }
            return false;
        });
    }

    _parseVersion(version) {
        const parts = version.split('.').map(Number);
        return parts[0] * 10000 + (parts[1] || 0) * 100 + (parts[2] || 0);
    }
}

module.exports = Scanner;

import { 
    ScanOptions, 
    DatabaseEntry, 
    ScanResult, 
    CodePattern, 
    DataFlow, 
    Range, 
    SeverityLevel,
    Vulnerability
} from './types';
import { ParallelScanner } from './parallel/scanner';
import { createReporter, Reporter } from './reporters';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import axios from 'axios';
import * as parser from '@typescript-eslint/parser';
import { AST_NODE_TYPES, TSESTree } from '@typescript-eslint/types';
import { traverse } from '@typescript-eslint/typescript-estree';

export class Scanner {
    private vulnerabilityDB: Map<string, any>;
    private codePatterns: CodePattern[];
    private options: Required<ScanOptions>;
    private watchedFiles: Set<string>;
    private dataFlowGraph: Map<string, DataFlow>;
    private reporter: Reporter;
    private vulnCache: VulnerabilityCache;
    private parallelScanner: ParallelScanner;

    constructor(options: ScanOptions = {}) {
        this.vulnerabilityDB = new Map();
        this.codePatterns = [];
        this.watchedFiles = new Set();
        this.dataFlowGraph = new Map();
        this.options = {
            ignoreDevDependencies: options.ignoreDevDependencies ?? false,
            ignorePatches: options.ignorePatches ?? false,
            customRules: options.customRules ?? '',
            minSeverity: options.minSeverity ?? 'low',
            outputFormat: options.outputFormat ?? 'text',
            watchMode: options.watchMode ?? false,
            maxDepth: options.maxDepth ?? 10,
            timeout: options.timeout ?? 30000,
            enableASTAnalysis: options.enableASTAnalysis ?? true,
            enableDataFlow: options.enableDataFlow ?? true,
            customPatterns: options.customPatterns ?? [],
            cacheTTL: options.cacheTTL ?? 24 * 60 * 60 * 1000, // 24 hours
            cacheDir: options.cacheDir ?? path.join(process.cwd(), '.cache'),
            maxWorkers: options.maxWorkers ?? os.cpus().length,
            chunkSize: options.chunkSize ?? 100
        };
        this.reporter = createReporter(options.outputFormat || 'text');
        this.vulnCache = new VulnerabilityCache({
            ttl: options.cacheTTL,
            cacheDir: options.cacheDir
        });
        this.parallelScanner = new ParallelScanner(options);
    }

    public async loadVulnerabilityDB(dbPath: string): Promise<boolean> {
        try {
            // Try to get from cache first
            const cached = await this.vulnCache.getVulnerabilities(dbPath);
            if (cached) {
                Object.entries(cached).forEach(([library, info]) => {
                    this.vulnerabilityDB.set(library, info);
                });
                return true;
            }

            // If not in cache, load from file
            const rawData = await fs.promises.readFile(dbPath, 'utf8');
            const data = JSON.parse(rawData) as DatabaseEntry;
            
            // Update both memory and cache
            Object.entries(data).forEach(([library, info]) => {
                this.vulnerabilityDB.set(library, info);
            });
            
            await this.vulnCache.setVulnerabilities(dbPath, data);
            return true;
        } catch (error) {
            console.error('Error loading vulnerability database:', error);
            return false;
        }
    }

    async loadCodePatterns(patternsPath: string): Promise<void> {
        try {
            const rawData = await fs.promises.readFile(patternsPath, 'utf8');
            this.codePatterns = JSON.parse(rawData);
            
            // Load custom patterns if specified
            if (this.options.customPatterns.length > 0) {
                this.codePatterns = [...this.codePatterns, ...this.options.customPatterns];
            }
        } catch (error) {
            console.error('Error loading code patterns:', error);
        }
    }

    async scanPackageJson(packagePath: string): Promise<ScanResult[]> {
        try {
            const rawData = await fs.promises.readFile(packagePath, 'utf8');
            const packageJson = JSON.parse(rawData);
            
            const vulnerabilities: ScanResult[] = [];
            
            await this.scanDependencies(packageJson.dependencies, vulnerabilities);
            
            if (!this.options.ignoreDevDependencies && packageJson.devDependencies) {
                await this.scanDependencies(packageJson.devDependencies, vulnerabilities);
            }
            
            return this.filterBySeverity(vulnerabilities);
        } catch (error) {
            console.error('Error scanning package.json:', error);
            return [];
        }
    }

    async scanSourceFile(filePath: string): Promise<ScanResult[]> {
        try {
            const content = await fs.promises.readFile(filePath, 'utf8');
            const ast = parser.parse(content, {
                sourceType: 'module',
                ecmaVersion: 'latest',
                loc: true
            });

            const vulnerabilities: ScanResult[] = [];
            
            // Reset dataflow graph for new file
            this.dataFlowGraph.clear();

            // First pass: Build dataflow graph
            if (this.options.enableDataFlow) {
                this.buildDataFlowGraph(ast);
            }

            // Second pass: Scan for vulnerabilities
            traverse(ast, {
                enter: (node: TSESTree.Node, parent: TSESTree.Node | undefined) => {
                    if (this.options.enableASTAnalysis) {
                        this.analyzeNode(node, parent, filePath, content, vulnerabilities);
                    }
                }
            });

            return this.filterBySeverity(vulnerabilities);
        } catch (error) {
            console.error('Error scanning source file:', error);
            return [];
        }
    }

    private buildDataFlowGraph(ast: TSESTree.Program): void {
        traverse(ast, {
            enter: (node: TSESTree.Node) => {
                switch (node.type) {
                    case AST_NODE_TYPES.AssignmentExpression:
                        this.trackAssignment(node);
                        break;
                    case AST_NODE_TYPES.VariableDeclarator:
                        this.trackVariableDeclaration(node);
                        break;
                    case AST_NODE_TYPES.CallExpression:
                        this.trackFunctionCall(node);
                        break;
                }
            }
        });
    }

    private trackAssignment(node: TSESTree.AssignmentExpression): void {
        const targetId = this.getNodeId(node.left);
        const sourceId = this.getNodeId(node.right);
        
        if (targetId && sourceId) {
            this.dataFlowGraph.set(targetId, {
                type: 'assignment',
                source: sourceId,
                node: node
            });
        }
    }

    private trackVariableDeclaration(node: TSESTree.VariableDeclarator): void {
        const targetId = this.getNodeId(node.id);
        const sourceId = node.init ? this.getNodeId(node.init) : undefined;
        
        if (targetId && sourceId) {
            this.dataFlowGraph.set(targetId, {
                type: 'declaration',
                source: sourceId,
                node: node
            });
        }
    }

    private trackFunctionCall(node: TSESTree.CallExpression): void {
        const callId = this.getNodeId(node);
        if (callId) {
            const args = node.arguments.map(arg => this.getNodeId(arg))
                .filter((arg): arg is string => arg !== undefined);
            this.dataFlowGraph.set(callId, {
                type: 'call',
                source: this.getNodeId(node.callee),
                arguments: args,
                node: node
            });
        }
    }

    private getNodeId(node: TSESTree.Node): string | undefined {
        switch (node.type) {
            case AST_NODE_TYPES.Identifier:
                return node.name;
            case AST_NODE_TYPES.MemberExpression:
                const obj = this.getNodeId(node.object);
                const prop = this.getNodeId(node.property);
                return obj && prop ? `${obj}.${prop}` : undefined;
            default:
                return undefined;
        }
    }

    private analyzeNode(
        node: TSESTree.Node,
        parent: TSESTree.Node | undefined,
        filePath: string,
        content: string,
        vulnerabilities: ScanResult[]
    ): void {
        this.codePatterns.forEach(pattern => {
            if (this.matchesPattern(node, pattern)) {
                const dataFlowInfo = this.options.enableDataFlow ? 
                    this.analyzeDataFlow(node) : undefined;

                vulnerabilities.push({
                    filePath,
                    lineNumber: node.loc?.start.line,
                    columnNumber: node.loc?.start.column,
                    vulnerability: {
                        severity: pattern.severity,
                        summary: pattern.description,
                        ranges: [],
                        cwe: pattern.cwe
                    },
                    matchedPattern: pattern,
                    code: content.slice(node.range?.[0], node.range?.[1]),
                    fix: pattern.fix,
                    dataFlow: dataFlowInfo
                });
            }
        });
    }

    private matchesPattern(node: TSESTree.Node, pattern: CodePattern): boolean {
        // First check if node type matches base pattern
        if (pattern.nodeType && node.type !== pattern.nodeType) {
            return false;
        }

        // Handle different pattern types
        switch (node.type) {
            case AST_NODE_TYPES.CallExpression:
                return this.matchCallExpression(node, pattern);
            case AST_NODE_TYPES.MemberExpression:
                return this.matchMemberExpression(node, pattern);
            case AST_NODE_TYPES.AssignmentExpression:
                return this.matchAssignmentExpression(node, pattern);
            default:
                return false;
        }
    }

    private matchCallExpression(node: TSESTree.CallExpression, pattern: CodePattern): boolean {
        if (pattern.type !== 'CallExpression') {
            return false;
        }

        // Match function name if pattern has a CallExpressionPattern
        if (pattern.pattern && pattern.pattern.type === 'CallExpression') {
            if (node.callee.type === AST_NODE_TYPES.Identifier) {
                if (pattern.pattern.name && node.callee.name !== pattern.pattern.name) {
                    return false;
                }
            }
        }

        // Match argument patterns if specified
        if (pattern.pattern && pattern.pattern.type === 'CallExpression' && pattern.pattern.arguments) {
            if (node.arguments.length !== pattern.pattern.arguments.length) {
                return false;
            }

            return pattern.pattern.arguments.every((argPattern, i) => 
                this.matchArgumentPattern(node.arguments[i], argPattern));
        }

        return true;
    }

    private matchMemberExpression(node: TSESTree.MemberExpression, pattern: CodePattern): boolean {
        if (pattern.type !== 'MemberExpression') {
            return false;
        }

        if (pattern.pattern && pattern.pattern.type === 'MemberExpression') {
            // Match object name if specified
            if (pattern.pattern.object) {
                if (node.object.type === AST_NODE_TYPES.Identifier) {
                    if (node.object.name !== pattern.pattern.object) {
                        return false;
                    }
                } else if (node.object.type === AST_NODE_TYPES.ThisExpression) {
                    if (pattern.pattern.object !== 'this') {
                        return false;
                    }
                }
            }

            // Match property name
            if (pattern.pattern.property) {
                if (node.property.type === AST_NODE_TYPES.Identifier) {
                    if (node.property.name !== pattern.pattern.property) {
                        return false;
                    }
                } else if (node.property.type === AST_NODE_TYPES.Literal) {
                    if (typeof node.property.value === 'string' && 
                        node.property.value !== pattern.pattern.property) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    private matchAssignmentExpression(node: TSESTree.AssignmentExpression, pattern: CodePattern): boolean {
        if (pattern.type !== 'AssignmentExpression') {
            return false;
        }

        // Match operator if specified
        if (pattern.operator && node.operator !== pattern.operator) {
            return false;
        }

        // Match left-hand side pattern
        if (pattern.left) {
            const leftMatches = this.matchExpressionPattern(node.left, pattern.left);
            if (!leftMatches) return false;
        }

        // Match right-hand side pattern
        if (pattern.right) {
            const rightMatches = this.matchExpressionPattern(node.right, pattern.right);
            if (!rightMatches) return false;
        }

        return true;
    }

    private matchArgumentPattern(arg: TSESTree.Node, pattern: any): boolean {
        switch (arg.type) {
            case AST_NODE_TYPES.Literal:
                return this.matchLiteralPattern(arg, pattern);
            case AST_NODE_TYPES.TemplateLiteral:
                return this.matchTemplateLiteralPattern(arg, pattern);
            case AST_NODE_TYPES.Identifier:
                return this.matchIdentifierPattern(arg, pattern);
            case AST_NODE_TYPES.ObjectExpression:
                return this.matchObjectPattern(arg, pattern);
            case AST_NODE_TYPES.ArrayExpression:
                return this.matchArrayPattern(arg, pattern);
            default:
                return false;
        }
    }

    private matchLiteralPattern(node: TSESTree.Literal, pattern: any): boolean {
        if (pattern.type === 'Literal') {
            if (pattern.value !== undefined) {
                return node.value === pattern.value;
            }
            if (pattern.regex) {
                return new RegExp(pattern.regex).test(String(node.value));
            }
            return true;
        }
        return false;
    }

    private matchTemplateLiteralPattern(node: TSESTree.TemplateLiteral, pattern: any): boolean {
        if (pattern.type !== 'TemplateLiteral') {
            return false;
        }

        if (pattern.regex) {
            const value = node.quasis.map(q => q.value.raw).join('');
            return new RegExp(pattern.regex).test(value);
        }

        return true;
    }

    private matchIdentifierPattern(node: TSESTree.Identifier, pattern: any): boolean {
        if (pattern.type === 'Identifier') {
            if (pattern.name) {
                return node.name === pattern.name;
            }
            if (pattern.regex) {
                return new RegExp(pattern.regex).test(node.name);
            }
            return true;
        }
        return false;
    }

    private matchObjectPattern(node: TSESTree.ObjectExpression, pattern: any): boolean {
        if (pattern.type !== 'ObjectExpression') {
            return false;
        }

        if (pattern.properties) {
            return node.properties.some(prop => {
                if (prop.type !== AST_NODE_TYPES.Property) return false;
                const key = prop.key.type === AST_NODE_TYPES.Identifier ? prop.key.name :
                           prop.key.type === AST_NODE_TYPES.Literal ? String(prop.key.value) : null;
                return pattern.properties.some((patternProp: any) => 
                    patternProp.key === key && this.matchExpressionPattern(prop.value, patternProp.value)
                );
            });
        }

        return true;
    }

    private matchArrayPattern(node: TSESTree.ArrayExpression, pattern: any): boolean {
        if (pattern.type !== 'ArrayExpression') {
            return false;
        }

        if (pattern.elements) {
            if (pattern.elements.length !== node.elements.length) {
                return false;
            }
            return pattern.elements.every((elementPattern: any, index: number) => 
                node.elements[index] && this.matchExpressionPattern(node.elements[index], elementPattern)
            );
        }

        return true;
    }

    private matchExpressionPattern(node: TSESTree.Node, pattern: any): boolean {
        switch (node.type) {
            case AST_NODE_TYPES.Literal:
                return this.matchLiteralPattern(node, pattern);
            case AST_NODE_TYPES.Identifier:
                return this.matchIdentifierPattern(node, pattern);
            case AST_NODE_TYPES.MemberExpression:
                return this.matchMemberExpression(node, pattern);
            case AST_NODE_TYPES.CallExpression:
                return this.matchCallExpression(node, pattern);
            case AST_NODE_TYPES.ObjectExpression:
                return this.matchObjectPattern(node, pattern);
            case AST_NODE_TYPES.ArrayExpression:
                return this.matchArrayPattern(node, pattern);
            default:
                return false;
        }
    }

    private analyzeDataFlow(node: TSESTree.Node): any {
        // Analyze data flow for the node using dataFlowGraph
        const nodeId = this.getNodeId(node);
        if (!nodeId || !this.dataFlowGraph.has(nodeId)) {
            return undefined;
        }

        const flow = this.dataFlowGraph.get(nodeId)!;
        const sources = this.getDataFlowSources(flow);

        return {
            type: flow.type,
            sources,
            sinks: this.findDataFlowSinks(nodeId)
        };
    }

    private getDataFlowSources(flow: DataFlow): string[] {
        const sources: string[] = [];
        if (flow.source) {
            sources.push(flow.source);
            const sourceFlow = this.dataFlowGraph.get(flow.source);
            if (sourceFlow) {
                sources.push(...this.getDataFlowSources(sourceFlow));
            }
        }
        return [...new Set(sources)];
    }

    private findDataFlowSinks(nodeId: string): string[] {
        const sinks: string[] = [];
        for (const [id, flow] of this.dataFlowGraph.entries()) {
            if (flow.source === nodeId || flow.arguments?.includes(nodeId)) {
                sinks.push(id);
                sinks.push(...this.findDataFlowSinks(id));
            }
        }
        return [...new Set(sinks)];
    }

    private async scanDependencies(
        dependencies: Record<string, string>,
        vulnerabilities: ScanResult[]
    ): Promise<void> {
        if (!dependencies) return;

        for (const [pkg, version] of Object.entries(dependencies)) {
            const cleanVersion = version.replace(/[^0-9.]/g, '');
            const vulnInfo = this.vulnerabilityDB.get(pkg);
            
            if (vulnInfo && vulnInfo.vulnerabilities) {
                vulnInfo.vulnerabilities.forEach((vuln: Vulnerability) => {
                    if (this.isVersionInRange(cleanVersion, vuln.ranges)) {
                        vulnerabilities.push({
                            packageName: pkg,
                            version,
                            vulnerability: vuln
                        });
                    }
                });
            }

            // Check for known vulnerable code patterns in node_modules
            const modulePath = path.join('node_modules', pkg);
            if (fs.existsSync(modulePath)) {
                await this.scanProjectFiles(modulePath, vulnerabilities);
            }
        }
    }

    private isVersionInRange(version: string, ranges?: Range[]): boolean {
        if (!ranges || ranges.length === 0) return false;

        const parts = version.split('.').map(Number);
        const normalizedVersion = parts.slice(0, 3).join('.');

        return ranges.some(range => {
            if (range.atOrAbove && this.compareVersions(normalizedVersion, range.atOrAbove) < 0) {
                return false;
            }
            if (range.below && this.compareVersions(normalizedVersion, range.below) >= 0) {
                return false;
            }
            return true;
        });
    }

    private compareVersions(a: string, b: string): number {
        const aParts = a.split('.').map(Number);
        const bParts = b.split('.').map(Number);

        for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
            const aVal = aParts[i] || 0;
            const bVal = bParts[i] || 0;
            if (aVal !== bVal) {
                return aVal - bVal;
            }
        }
        return 0;
    }

    private async scanProjectFiles(dirPath: string, vulnerabilities: ScanResult[]): Promise<void> {
        try {
            const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
            
            for (const entry of entries) {
                const fullPath = path.join(dirPath, entry.name);
                
                if (entry.isDirectory()) {
                    if (this.shouldScanDirectory(entry.name)) {
                        await this.scanProjectFiles(fullPath, vulnerabilities);
                    }
                } else {
                    if (this.isPackageJsonFile(entry.name)) {
                        const results = await this.scanPackageJson(fullPath);
                        vulnerabilities.push(...results);
                    } else if (this.isJavaScriptSourceFile(entry.name)) {
                        const results = await this.scanSourceFile(fullPath);
                        vulnerabilities.push(...results);
                    }
                }
            }
        } catch (error) {
            console.error('Error scanning directory:', error);
        }
    }

    private shouldScanDirectory(name: string): boolean {
        const skipDirs = [
            'node_modules',
            'test',
            'tests',
            'dist',
            'build',
            'coverage',
            '.git'
        ];
        return !skipDirs.includes(name);
    }

    private isJavaScriptSourceFile(name: string): boolean {
        return /\.(js|jsx|ts|tsx)$/i.test(name);
    }

    private isPackageJsonFile(name: string): boolean {
        return /^package\.json$/i.test(name);
    }

    private filterBySeverity(results: ScanResult[]): ScanResult[] {
        const severityLevels = ['low', 'medium', 'high', 'critical'];
        const minSeverityIndex = severityLevels.indexOf(this.options.minSeverity);
        
        return results.filter(result => {
            const resultSeverityIndex = severityLevels.indexOf(result.vulnerability.severity);
            return resultSeverityIndex >= minSeverityIndex;
        });
    }

    private async startWatchMode(): Promise<void> {
        if (!this.options.watchMode) return;

        const chokidar = await import('chokidar');
        const watcher = chokidar.watch(['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx', '**/package.json'], {
            ignored: ['**/node_modules/**', '**/dist/**', '**/build/**'],
            persistent: true,
            ignoreInitial: false
        });

        watcher
            .on('add', async (filePath: string) => {
                await this.handleFileChange('add', filePath);
            })
            .on('change', async (filePath: string) => {
                await this.handleFileChange('change', filePath);
            })
            .on('unlink', (filePath: string) => {
                this.watchedFiles.delete(filePath);
            });
    }

    private async handleFileChange(event: 'add' | 'change', filePath: string): Promise<void> {
        const absolutePath = path.resolve(filePath);
        
        if (this.isPackageJsonFile(filePath)) {
            const results = await this.scanPackageJson(absolutePath);
            if (results.length > 0) {
                this.reportRealTimeVulnerabilities(results);
            }
        } else if (this.isJavaScriptSourceFile(filePath)) {
            const results = await this.scanSourceFile(absolutePath);
            if (results.length > 0) {
                this.reportRealTimeVulnerabilities(results);
            }
        }

        this.watchedFiles.add(absolutePath);
    }

    public async loadCustomRules(rulesPath: string): Promise<void> {
        try {
            if (fs.existsSync(rulesPath)) {
                const rawData = await fs.promises.readFile(rulesPath, 'utf8');
                const customRules = JSON.parse(rawData);
                
                // Validate custom rules
                const validRules = customRules.filter((rule: any) => {
                    return rule.id && 
                           rule.description && 
                           rule.severity &&
                           ['low', 'medium', 'high', 'critical'].includes(rule.severity);
                });

                this.codePatterns.push(...validRules);
            }
        } catch (error) {
            console.error('Error loading custom rules:', error);
        }
    }

    public formatResults(results: ScanResult[]): Promise<string> | string {
        return this.reporter.report(results);
    }

    private reportRealTimeVulnerabilities(results: ScanResult[]): void {
        const formattedResults = this.reporter.report(results);
        console.log(formattedResults);

        // Emit results for potential UI integration
        if (typeof process !== 'undefined' && process.send) {
            process.send({
                type: 'vulnerability-detected',
                results: formattedResults
            });
        }
    }

    public async start(): Promise<void> {
        if (this.options.watchMode) {
            await this.startWatchMode();
        }
    }

    public async scanProject(projectPath: string): Promise<ScanResult[]> {
        const vulnerabilities: ScanResult[] = [];
        
        // Scan package.json first
        const packageJsonPath = path.join(projectPath, 'package.json');
        if (fs.existsSync(packageJsonPath)) {
            const packageVulns = await this.scanPackageJson(packageJsonPath);
            vulnerabilities.push(...packageVulns);
        }

        // Then scan all source files
        await this.scanProjectFiles(projectPath, vulnerabilities);

        return this.filterBySeverity(vulnerabilities);
    }

    public async scanProjectInParallel(
        projectPath: string,
        onProgress?: (progress: number) => void
    ): Promise<ScanResult[]> {
        const allFiles: string[] = [];
        const vulnerabilities: ScanResult[] = [];

        // First scan package.json
        const packageJsonPath = path.join(projectPath, 'package.json');
        if (fs.existsSync(packageJsonPath)) {
            const packageVulns = await this.scanPackageJson(packageJsonPath);
            vulnerabilities.push(...packageVulns);
        }

        // Collect all JavaScript/TypeScript files
        await this.collectSourceFiles(projectPath, allFiles);

        // Scan files in parallel
        if (allFiles.length > 0) {
            const results = await this.parallelScanner.scanInParallel(
                allFiles,
                onProgress
            );
            vulnerabilities.push(...results);
        }

        return this.filterBySeverity(vulnerabilities);
    }

    private async collectSourceFiles(dirPath: string, files: string[]): Promise<void> {
        try {
            const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
            
            for (const entry of entries) {
                const fullPath = path.join(dirPath, entry.name);
                
                if (entry.isDirectory()) {
                    if (this.shouldScanDirectory(entry.name)) {
                        await this.collectSourceFiles(fullPath, files);
                    }
                } else if (this.isJavaScriptSourceFile(entry.name)) {
                    files.push(fullPath);
                }
            }
        } catch (error) {
            console.error('Error collecting source files:', error);
        }
    }

    public async addCustomPattern(pattern: CodePattern): Promise<void> {
        this.codePatterns.push(pattern);
    }

    public setMinimumSeverity(severity: SeverityLevel): void {
        this.options.minSeverity = severity;
    }

    public enableDataFlowAnalysis(enable: boolean): void {
        this.options.enableDataFlow = enable;
    }

    public enableASTAnalysis(enable: boolean): void {
        this.options.enableASTAnalysis = enable;
    }

    public getWatchedFiles(): string[] {
        return Array.from(this.watchedFiles);
    }

    public async updateVulnerabilityDB(url: string): Promise<boolean> {
        try {
            // Check if we have a cached version
            const cached = await this.vulnCache.getVulnerabilities(url);
            const headers: Record<string, string> = {};
            
            const cachedEntry = await this.vulnCache.get<DatabaseEntry>(url);
            if (cachedEntry?.etag) {
                headers['If-None-Match'] = cachedEntry.etag;
            }

            const response = await axios.get(url, { headers });
            
            if (response.status === 304) {
                // Not modified, use cache
                if (cached) {
                    Object.entries(cached).forEach(([library, info]) => {
                        this.vulnerabilityDB.set(library, info);
                    });
                    return true;
                }
            } else if (response.data) {
                // Update both memory and cache
                const etag = response.headers.etag;
                const data = response.data as DatabaseEntry;
                
                Object.entries(data).forEach(([library, info]) => {
                    this.vulnerabilityDB.set(library, info);
                });
                
                await this.vulnCache.setVulnerabilities(url, data, etag);
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Error updating vulnerability database:', error);
            return false;
        }
    }
}

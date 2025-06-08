import { AST_NODE_TYPES, TSESTree } from '@typescript-eslint/types';

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export interface Range {
    atOrAbove?: string;
    below?: string;
}

export interface Vulnerability {
    severity: SeverityLevel;
    summary: string;
    ranges: Range[];
    cwe?: string[];
    identifiers?: {
        CVE?: string[];
        bug?: string[];
        issue?: string[];
        githubID?: string[];
    };
}

export interface DatabaseEntry {
    [key: string]: {
        vulnerabilities: Vulnerability[];
        // Other metadata
    };
}

export interface BasePattern {
    type: string;
    value?: any;
    regex?: string;
}

export interface IdentifierPattern extends BasePattern {
    type: 'Identifier';
    name?: string;
}

export interface LiteralPattern extends BasePattern {
    type: 'Literal';
    value?: string | number | boolean | null;
    regex?: string;
}

export interface TemplateLiteralPattern extends BasePattern {
    type: 'TemplateLiteral';
    regex?: string;
}

export interface ObjectPattern extends BasePattern {
    type: 'ObjectExpression';
    properties?: Array<{
        key: string;
        value: ExpressionPattern;
    }>;
}

export interface ArrayPattern extends BasePattern {
    type: 'ArrayExpression';
    elements?: ExpressionPattern[];
}

export interface MemberExpressionPattern extends BasePattern {
    type: 'MemberExpression';
    object?: string;
    property?: string;
}

export interface AssignmentExpressionPattern extends BasePattern {
    type: 'AssignmentExpression';
    operator?: string;
    left?: ExpressionPattern;
    right?: ExpressionPattern;
}

export interface CallExpressionPattern extends BasePattern {
    type: 'CallExpression';
    name?: string;
    arguments?: Array<ExpressionPattern>;
}

export type ExpressionPattern = 
    | IdentifierPattern 
    | LiteralPattern 
    | TemplateLiteralPattern 
    | ObjectPattern 
    | ArrayPattern 
    | MemberExpressionPattern 
    | AssignmentExpressionPattern 
    | CallExpressionPattern;

export interface CodePattern {
    id: string;
    description: string;
    severity: SeverityLevel;
    cwe?: string[];
    fix?: string;
    
    // AST matching
    type: 'CallExpression' | 'MemberExpression' | 'AssignmentExpression' | string;
    nodeType?: AST_NODE_TYPES;
    selector?: string; // ESLint-style selector

    // Pattern details
    pattern?: ExpressionPattern;
    object?: string;  // For MemberExpression
    property?: string;  // For MemberExpression
    operator?: string;  // For AssignmentExpression
    left?: ExpressionPattern;  // For AssignmentExpression
    right?: ExpressionPattern;  // For AssignmentExpression
    arguments?: ExpressionPattern[];  // For CallExpression
    
    // Source code matching
    textPattern?: string; // Regex or string pattern
    language: string[]; // Supported languages
    
    // Custom properties
    customProperties?: Record<string, unknown>;
}

export interface DataFlow {
    type: 'assignment' | 'declaration' | 'call';
    source?: string;
    node: TSESTree.Node;
    arguments?: string[];
}

export interface DataFlowInfo {
    type: string;
    sources: string[];
    sinks: string[];
}

export interface ScanResult {
    packageName?: string;
    version?: string;
    filePath?: string;
    lineNumber?: number;
    columnNumber?: number;
    vulnerability: Vulnerability;
    matchedPattern?: CodePattern;
    code?: string;
    fix?: string;
    dataFlow?: DataFlowInfo;
}

export interface ScanOptions {
    ignoreDevDependencies?: boolean;
    ignorePatches?: boolean;
    customRules?: string;
    minSeverity?: SeverityLevel;
    outputFormat?: string;
    watchMode?: boolean;
    maxDepth?: number;
    timeout?: number;
    enableASTAnalysis?: boolean;
    enableDataFlow?: boolean;
    customPatterns?: CodePattern[];
    
    // Cache options
    cacheTTL?: number;  // Time to live in milliseconds
    cacheDir?: string;  // Directory to store cache files
    
    // Parallel scanning options
    maxWorkers?: number;  // Maximum number of worker threads to use
    chunkSize?: number;   // Number of files to process per worker
}

export interface ASTParsedFile {
    ast: TSESTree.Program;
    content: string;
}

export interface Scanner {
    loadVulnerabilityDB(dbPath: string): Promise<boolean>;
    loadCodePatterns(patternsPath: string): Promise<void>;
    scanPackageJson(packagePath: string): Promise<ScanResult[]>;
    scanSourceFile(filePath: string): Promise<ScanResult[]>;
    watchFiles(paths: string[]): Promise<void>;
}

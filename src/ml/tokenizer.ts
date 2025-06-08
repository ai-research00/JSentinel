import { Parser } from 'acorn';
import * as walk from 'acorn-walk';
import { TokenizedCode, TokenizerConfig } from './types';
import { getMLConfig } from '../config/ml.config';

const DEFAULT_CONFIG: TokenizerConfig = {
    maxVocabSize: 50000,
    specialTokens: ['[PAD]', '[UNK]', '[START]', '[END]', '[SEP]'],
    normalization: true
};

export async function tokenizeCode(code: string, config: TokenizerConfig = DEFAULT_CONFIG): Promise<TokenizedCode> {
    try {
        const tokens: string[] = [];
        const positions: Array<{ line: number; column: number }> = [];

        // Parse the code into an AST
        const ast = Parser.parse(code, {
            ecmaVersion: 'latest',
            sourceType: 'module',
            locations: true
        });

        // Walk the AST and collect tokens with their positions
        walk.full(ast, (node: any) => {
            if (!node.loc) return;

            const addToken = (token: string) => {
                tokens.push(token);
                positions.push({
                    line: node.loc.start.line,
                    column: node.loc.start.column
                });
            };

            switch (node.type) {
                case 'Identifier':
                    addToken(node.name);
                    break;
                case 'Literal':
                    addToken(normalizeLiteral(node.value));
                    break;
                case 'CallExpression':
                    if (node.callee.type === 'Identifier') {
                        addToken(normalizeAPI(node.callee.name));
                    }
                    break;
                case 'MemberExpression':
                    if (node.object.type === 'Identifier' && node.property.type === 'Identifier') {
                        addToken(`${node.object.name}.${node.property.name}`);
                    }
                    break;
                case 'FunctionDeclaration':
                case 'FunctionExpression':
                    addToken('FUNCTION');
                    break;
                case 'VariableDeclaration':
                    addToken(node.kind.toUpperCase()); // const, let, var
                    break;
                case 'BinaryExpression':
                case 'LogicalExpression':
                    addToken(node.operator);
                    break;
                case 'AssignmentExpression':
                    addToken(`ASSIGN_${node.operator}`);
                    break;
                case 'ImportDeclaration':
                    addToken('IMPORT');
                    break;
                case 'ExportDeclaration':
                    addToken('EXPORT');
                    break;
                case 'NewExpression':
                    addToken('NEW');
                    break;
            }
        });

        // Add special tokens while maintaining position tracking
        tokens.unshift('[START]');
        positions.unshift({ line: 1, column: 0 });
        
        tokens.push('[END]');
        const lastLine = code.split('\n').length;
        positions.push({ line: lastLine, column: 0 });

        // Normalize tokens if configured
        const normalizedTokens = config.normalization ? 
            normalizeTokens(tokens, config) : tokens;

        return {
            tokens: normalizedTokens,
            positions,
            originalCode: code
        };
    } catch (error) {
        if (error instanceof Error) {
            throw new Error(`Tokenization failed: ${error.message}`);
        }
        throw error;
    }
}

function normalizeTokens(tokens: string[], config: TokenizerConfig): string[] {
    return tokens.map(token => {
        // Special tokens remain unchanged
        if (config.specialTokens?.includes(token)) {
            return token;
        }

        // Handle numbers
        if (/^-?\d*\.?\d+$/.test(token)) {
            return '[NUMBER]';
        }

        // Handle strings
        if (/^["'`].*["'`]$/.test(token)) {
            return '[STRING]';
        }

        // Handle common dangerous APIs
        if (isDangerousAPI(token)) {
            return `DANGEROUS_API_${token}`;
        }

        // Handle common web APIs
        if (isWebAPI(token)) {
            return `WEB_API_${token}`;
        }

        return token;
    });
}

function normalizeLiteral(value: any): string {
    if (typeof value === 'number') return '[NUMBER]';
    if (typeof value === 'string') return '[STRING]';
    if (typeof value === 'boolean') return '[BOOL]';
    if (value === null) return '[NULL]';
    if (value === undefined) return '[UNDEFINED]';
    if (value instanceof RegExp) return '[REGEX]';
    return String(value);
}

function normalizeAPI(name: string): string {
    if (isDangerousAPI(name)) return `DANGEROUS_API_${name}`;
    if (isWebAPI(name)) return `WEB_API_${name}`;
    return `CALL_${name}`;
}

function isDangerousAPI(name: string): boolean {
    return new Set([
        'eval',
        'exec',
        'Function',
        'setTimeout',
        'setInterval',
        'execScript',
        'document.write',
        'innerHTML',
        'outerHTML'
    ]).has(name);
}

function isWebAPI(name: string): boolean {
    return new Set([
        'fetch',
        'XMLHttpRequest',
        'querySelector',
        'getElementById',
        'getElementsByClassName',
        'addEventListener',
        'localStorage',
        'sessionStorage'
    ]).has(name);
}

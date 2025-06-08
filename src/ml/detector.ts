import { VulnerabilityModel } from './model';
import { tokenizeCode } from './tokenizer';
import { VulnerabilityResult, VulnerabilityType, TokenizedCode } from './types';
import { getMLConfig } from '../config/ml.config';

export class MLDetector {
    private static instance: MLDetector;
    private model: VulnerabilityModel;
    private isInitialized: boolean = false;

    private constructor() {
        this.model = new VulnerabilityModel();
    }

    static getInstance(): MLDetector {
        if (!MLDetector.instance) {
            MLDetector.instance = new MLDetector();
        }
        return MLDetector.instance;
    }

    async initialize(): Promise<void> {
        if (this.isInitialized) return;

        try {
            await this.model.initialize();
            this.isInitialized = true;
        } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to initialize ML detector: ${errorMessage}`);
        }
    }

    async detectVulnerabilities(code: string): Promise<VulnerabilityResult[]> {
        if (!this.isInitialized) {
            throw new Error('ML detector not initialized. Call initialize() first.');
        }

        try {
            // Tokenize the code
            const tokenized: TokenizedCode = await tokenizeCode(code);

            // Generate embeddings
            const embedding = await this.model.embed(tokenized.tokens);

            // Get predictions
            const predictions = await this.model.predict(embedding);

            // Process predictions into vulnerability results
            return this.processPredictions(predictions, tokenized);
        } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`ML detection failed: ${errorMessage}`);
        }
    }

    private processPredictions(
        predictions: Array<{
            vulnerabilityType: VulnerabilityType;
            confidence: number;
            startPos: number;
            endPos: number;
        }>,
        tokenized: TokenizedCode
    ): VulnerabilityResult[] {
        const config = getMLConfig();

        return predictions
            .filter(pred => pred.confidence >= config.confidenceThreshold)
            .map(pred => {
                const startToken = tokenized.positions[pred.startPos];
                const endToken = tokenized.positions[pred.endPos];
                
                const vulnerableCode = tokenized.originalCode.split('\n')
                    .slice(startToken.line - 1, endToken.line)
                    .join('\n');

                return {
                    type: pred.vulnerabilityType,
                    confidence: pred.confidence,
                    location: {
                        start: startToken,
                        end: endToken
                    },
                    code: vulnerableCode,
                    description: this.generateVulnerabilityDescription(
                        pred.vulnerabilityType,
                        vulnerableCode
                    )
                };
            });
    }

    private generateVulnerabilityDescription(type: VulnerabilityType, code: string): string {
        const descriptions: Record<VulnerabilityType, string> = {
            'cross-site-scripting': 'Potential XSS vulnerability: User input is being rendered without proper sanitization',
            'code-injection': 'Possible code injection: Dynamic code execution with potentially unsafe input',
            'unsafe-eval': 'Unsafe eval usage: Dynamic code evaluation can lead to code injection',
            'prototype-pollution': 'Potential prototype pollution: Object properties are being modified insecurely',
            'unsafe-regex': 'Unsafe regular expression: Could be vulnerable to ReDoS attacks',
            'path-traversal': 'Path traversal vulnerability: File paths are not properly sanitized'
        };

        return descriptions[type] || 'Unknown vulnerability detected';
    }
}

import * as tf from '@tensorflow/tfjs-node';

export interface MLConfig {
    modelCachePath: string;
    modelUrl: string;
    batchSize: number;
    confidenceThreshold: number;
    maxTokenLength: number;
    embedDimension: number;
}

export interface TokenizedCode {
    tokens: string[];
    positions: Array<{ line: number; column: number }>;
    originalCode: string;
}

export interface VulnerabilityResult {
    type: VulnerabilityType;
    confidence: number;
    location: {
        start: { line: number; column: number };
        end: { line: number; column: number };
    };
    code: string;
    description: string;
}

export type VulnerabilityType =
    | 'cross-site-scripting'
    | 'code-injection'
    | 'unsafe-eval'
    | 'prototype-pollution'
    | 'unsafe-regex'
    | 'path-traversal';

export interface Confidence {
    LOW: 0.5;
    MEDIUM: 0.75;
    HIGH: 0.9;
}

export const CONFIDENCE_LEVELS: Confidence = {
    LOW: 0.5,
    MEDIUM: 0.75,
    HIGH: 0.9
};

export interface ModelPrediction {
    vulnerabilityType: VulnerabilityType | null;
    confidence: number;
    startPos: number;
    endPos: number;
}

export interface TokenizerConfig {
    maxVocabSize?: number;
    specialTokens?: string[];
    normalization?: boolean;
}

export interface CodeEmbedding {
    embed(tokens: string[]): Promise<tf.Tensor>;
    predict(embedding: tf.Tensor): Promise<ModelPrediction[]>;
}

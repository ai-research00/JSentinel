import { MLConfig } from '../ml/types';

export const getMLConfig = (): MLConfig => ({
    modelUrl: 'https://storage.googleapis.com/jsentinel-models/vulnerability-detection-v1.json',
    modelCachePath: './cache/ml-model',
    batchSize: 32,
    confidenceThreshold: 0.85,
    maxTokenLength: 512,
    embedDimension: 768
});

export const VULNERABILITY_TYPES = {
    XSS: 'cross-site-scripting',
    INJECTION: 'code-injection',
    UNSAFE_EVAL: 'unsafe-eval',
    PROTOTYPE_POLLUTION: 'prototype-pollution',
    UNSAFE_REGEX: 'unsafe-regex',
    PATH_TRAVERSAL: 'path-traversal'
} as const;

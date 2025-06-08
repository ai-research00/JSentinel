import * as tf from '@tensorflow/tfjs-node';
import { CodeEmbedding, MLConfig, ModelPrediction, VulnerabilityType } from './types';
import path from 'path';
import { getMLConfig } from '../config/ml.config';
import fetch from 'node-fetch';
import fs from 'fs/promises';

export class VulnerabilityModel implements CodeEmbedding {
    private model: tf.LayersModel | null = null;
    private config: MLConfig;

    constructor() {
        this.config = getMLConfig();
    }

    async initialize(): Promise<void> {
        try {
            this.model = await this.loadFromCache();
        } catch (error) {
            console.log('Model not found in cache, downloading...');
            this.model = await this.downloadAndSaveModel();
        }
    }

    private async loadFromCache(): Promise<tf.LayersModel> {
        return await tf.loadLayersModel(`file://${this.config.modelCachePath}/model.json`);
    }

    private async downloadAndSaveModel(): Promise<tf.LayersModel> {
        const response = await fetch(this.config.modelUrl);
        if (!response.ok) {
            throw new Error(`Failed to download model: ${response.statusText}`);
        }

        const modelData = await response.json();
        const model = await tf.loadLayersModel(tf.io.fromMemory(modelData));

        // Save to cache
        await fs.mkdir(this.config.modelCachePath, { recursive: true });
        await model.save(`file://${this.config.modelCachePath}`);

        return model;
    }

    async embed(tokens: string[]): Promise<tf.Tensor> {
        if (!this.model) {
            throw new Error('Model not initialized. Call initialize() first.');
        }

        // Pad or truncate tokens to maxTokenLength
        const paddedTokens = tokens.slice(0, this.config.maxTokenLength);
        while (paddedTokens.length < this.config.maxTokenLength) {
            paddedTokens.push('[PAD]');
        }

        // Convert tokens to tensor
        const inputTensor = tf.tensor2d([paddedTokens.map(t => this.tokenToId(t))], 
            [1, this.config.maxTokenLength]);

        // Get embeddings from the first layer (embedding layer)
        const embeddings = this.model.layers[0].apply(inputTensor) as tf.Tensor;
        return embeddings;
    }

    async predict(embedding: tf.Tensor): Promise<ModelPrediction[]> {
        if (!this.model) {
            throw new Error('Model not initialized. Call initialize() first.');
        }

        const predictions = await this.model.predict(embedding) as tf.Tensor;
        const probabilities = await predictions.data();

        return this.decodePredictions(Array.from(probabilities));
    }

    private tokenToId(token: string): number {
        // This should be replaced with actual vocabulary lookup
        // For now, just return a hash of the token modulo vocabulary size
        return Math.abs(this.hashString(token) % 10000);
    }

    private hashString(str: string): number {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash;
        }
        return hash;
    }

    private decodePredictions(probabilities: number[]): ModelPrediction[] {
        const predictions: ModelPrediction[] = [];
        const vulnerabilityTypes: VulnerabilityType[] = [
            'cross-site-scripting',
            'code-injection',
            'unsafe-eval',
            'prototype-pollution',
            'unsafe-regex',
            'path-traversal'
        ];

        for (let i = 0; i < probabilities.length; i += vulnerabilityTypes.length) {
            const classProbs = probabilities.slice(i, i + vulnerabilityTypes.length);
            const maxProb = Math.max(...classProbs);
            const maxIndex = classProbs.indexOf(maxProb);

            if (maxProb >= this.config.confidenceThreshold) {
                predictions.push({
                    vulnerabilityType: vulnerabilityTypes[maxIndex],
                    confidence: maxProb,
                    startPos: i,
                    endPos: i + vulnerabilityTypes.length - 1
                });
            }
        }

        return predictions;
    }
}

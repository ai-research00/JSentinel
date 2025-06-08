import * as os from 'os';
import * as path from 'path';
import { Worker } from 'worker_threads';
import { ScanResult, ScanOptions } from '../types';

export interface WorkerMessage {
    type: 'result' | 'error' | 'progress';
    data: any;
    filePath?: string;
}

export class ParallelScanner {
    private numWorkers: number;
    private workers: Worker[];
    private options: ScanOptions;

    constructor(options: ScanOptions = {}) {
        this.numWorkers = options.maxWorkers || os.cpus().length;
        this.workers = [];
        this.options = options;
    }

    public async scanInParallel(
        files: string[],
        onProgress?: (progress: number) => void
    ): Promise<ScanResult[]> {
        const results: ScanResult[] = [];
        let completedFiles = 0;

        // Split files among workers
        const filesPerWorker = Math.ceil(files.length / this.numWorkers);
        const workerFiles = Array.from({ length: this.numWorkers }, (_, i) =>
            files.slice(i * filesPerWorker, (i + 1) * filesPerWorker)
        );

        const workerPromises = workerFiles.map((fileList, index) =>
            this.createWorker(fileList, index, (progress: number) => {
                completedFiles += progress;
                const totalProgress = (completedFiles / files.length) * 100;
                onProgress?.(totalProgress);
            })
        );

        try {
            const workerResults = await Promise.all(workerPromises);
            results.push(...workerResults.flat());
        } finally {
            await this.terminateWorkers();
        }

        return results;
    }

    private createWorker(
        files: string[],
        workerId: number,
        onProgress?: (progress: number) => void
    ): Promise<ScanResult[]> {
        return new Promise((resolve, reject) => {
            const worker = new Worker(
                path.join(__dirname, 'scanner.worker.js'),
                {
                    workerData: {
                        files,
                        options: this.options,
                        workerId
                    }
                }
            );

            this.workers.push(worker);

            const results: ScanResult[] = [];

            worker.on('message', (message: WorkerMessage) => {
                switch (message.type) {
                    case 'result':
                        results.push(...message.data);
                        break;
                    case 'progress':
                        onProgress?.(1); // One file completed
                        break;
                    case 'error':
                        console.error(
                            `Error in worker ${workerId}:`,
                            message.data
                        );
                        break;
                }
            });

            worker.on('error', reject);

            worker.on('exit', (code) => {
                if (code !== 0) {
                    reject(new Error(`Worker stopped with exit code ${code}`));
                } else {
                    resolve(results);
                }
            });
        });
    }

    private async terminateWorkers(): Promise<void> {
        await Promise.all(
            this.workers.map(worker => worker.terminate())
        );
        this.workers = [];
    }
}

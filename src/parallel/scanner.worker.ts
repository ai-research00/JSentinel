import { parentPort, workerData } from 'worker_threads';
import { Scanner } from '../scanner';
import { ScanOptions, ScanResult } from '../types';

interface WorkerData {
    files: string[];
    options: ScanOptions;
    workerId: number;
}

async function run() {
    const { files, options, workerId } = workerData as WorkerData;
    const scanner = new Scanner(options);
    const results: ScanResult[] = [];

    try {
        // Initialize scanner
        if (options.customRules) {
            await scanner.loadCustomRules(options.customRules);
        }

        // Process files
        for (const file of files) {
            try {
                const fileResults = await scanner.scanSourceFile(file);
                if (fileResults.length > 0) {
                    results.push(...fileResults);
                }
                
                // Report progress
                parentPort?.postMessage({
                    type: 'progress',
                    data: 1,
                    filePath: file
                });
            } catch (error) {
                parentPort?.postMessage({
                    type: 'error',
                    data: error instanceof Error ? error.message : String(error),
                    filePath: file
                });
            }
        }

        // Send results back to main thread
        parentPort?.postMessage({
            type: 'result',
            data: results
        });
    } catch (error) {
        parentPort?.postMessage({
            type: 'error',
            data: error instanceof Error ? error.message : String(error)
        });
    }
}

run().catch(error => {
    parentPort?.postMessage({
        type: 'error',
        data: error.message
    });
});

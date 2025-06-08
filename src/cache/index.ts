import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { DatabaseEntry, Vulnerability } from '../types';

export interface CacheEntry<T> {
    timestamp: number;
    etag?: string;
    data: T;
}

export interface CacheOptions {
    ttl: number; // Time to live in milliseconds
    cacheDir: string;
}

export class Cache {
    private cacheDir: string;
    private ttl: number;

    constructor(options: CacheOptions) {
        this.cacheDir = options.cacheDir;
        this.ttl = options.ttl;
        this.ensureCacheDir();
    }

    private ensureCacheDir(): void {
        if (!fs.existsSync(this.cacheDir)) {
            fs.mkdirSync(this.cacheDir, { recursive: true });
        }
    }

    private getCacheFilePath(key: string): string {
        const hash = crypto.createHash('sha256').update(key).digest('hex');
        return path.join(this.cacheDir, `${hash}.json`);
    }

    public async get<T>(key: string): Promise<CacheEntry<T> | null> {
        try {
            const filePath = this.getCacheFilePath(key);
            if (!fs.existsSync(filePath)) {
                return null;
            }

            const data = await fs.promises.readFile(filePath, 'utf8');
            const entry: CacheEntry<T> = JSON.parse(data);

            // Check if cache is expired
            if (Date.now() - entry.timestamp > this.ttl) {
                await fs.promises.unlink(filePath);
                return null;
            }

            return entry;
        } catch (error) {
            console.error('Error reading from cache:', error);
            return null;
        }
    }

    public async set<T>(key: string, data: T, etag?: string): Promise<void> {
        try {
            const entry: CacheEntry<T> = {
                timestamp: Date.now(),
                etag,
                data
            };

            const filePath = this.getCacheFilePath(key);
            await fs.promises.writeFile(
                filePath,
                JSON.stringify(entry, null, 2),
                'utf8'
            );
        } catch (error) {
            console.error('Error writing to cache:', error);
        }
    }

    public async has(key: string): Promise<boolean> {
        const filePath = this.getCacheFilePath(key);
        return fs.existsSync(filePath);
    }

    public async delete(key: string): Promise<void> {
        try {
            const filePath = this.getCacheFilePath(key);
            if (fs.existsSync(filePath)) {
                await fs.promises.unlink(filePath);
            }
        } catch (error) {
            console.error('Error deleting from cache:', error);
        }
    }

    public async clear(): Promise<void> {
        try {
            const files = await fs.promises.readdir(this.cacheDir);
            await Promise.all(
                files.map(file => 
                    fs.promises.unlink(path.join(this.cacheDir, file))
                )
            );
        } catch (error) {
            console.error('Error clearing cache:', error);
        }
    }
}

export class VulnerabilityCache extends Cache {
    constructor(options?: Partial<CacheOptions>) {
        super({
            ttl: options?.ttl || 24 * 60 * 60 * 1000, // 24 hours by default
            cacheDir: options?.cacheDir || path.join(process.cwd(), '.cache', 'vulnerabilities')
        });
    }

    public async getVulnerabilities(url: string): Promise<DatabaseEntry | null> {
        const cached = await this.get<DatabaseEntry>(url);
        return cached?.data || null;
    }

    public async setVulnerabilities(url: string, data: DatabaseEntry, etag?: string): Promise<void> {
        await this.set(url, data, etag);
    }

    public async updateVulnerability(
        url: string,
        packageName: string,
        vulnerability: Vulnerability
    ): Promise<void> {
        const cached = await this.get<DatabaseEntry>(url);
        if (cached) {
            const db = cached.data;
            if (!db[packageName]) {
                db[packageName] = { vulnerabilities: [] };
            }
            
            // Update or add vulnerability
            const index = db[packageName].vulnerabilities.findIndex(
                v => v.summary === vulnerability.summary
            );
            
            if (index >= 0) {
                db[packageName].vulnerabilities[index] = vulnerability;
            } else {
                db[packageName].vulnerabilities.push(vulnerability);
            }

            await this.set(url, db, cached.etag);
        }
    }
}

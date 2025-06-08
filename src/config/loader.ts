import fs from 'fs';
import path from 'path';
import { cosmiconfig } from 'cosmiconfig';
import { Config, configSchema, defaultConfig } from './schema';
import { mergeDeep } from '../utils/merge';

export class ConfigLoader {
  private static instance: ConfigLoader;
  private config: Config = defaultConfig;
  private configPath?: string;

  private constructor() {}

  static getInstance(): ConfigLoader {
    if (!ConfigLoader.instance) {
      ConfigLoader.instance = new ConfigLoader();
    }
    return ConfigLoader.instance;
  }

  async load(configPath?: string): Promise<Config> {
    try {
      let loadedConfig: Partial<Config> = {};

      if (configPath) {
        // Load from specified path
        this.configPath = configPath;
        if (!fs.existsSync(configPath)) {
          throw new Error(`Config file not found: ${configPath}`);
        }
        loadedConfig = await this.loadFile(configPath);
      } else {
        // Search for config file using cosmiconfig
        const explorer = cosmiconfig('jsentinel', {
          searchPlaces: [
            'package.json',
            '.jsentinelrc',
            '.jsentinelrc.json',
            '.jsentinelrc.yaml',
            '.jsentinelrc.yml',
            '.jsentinelrc.js',
            '.jsentinel.config.js',
            '.jsentinel.config.cjs',
          ],
        });

        const result = await explorer.search();
        if (result && !result.isEmpty) {
          loadedConfig = result.config;
          this.configPath = result.filepath;
        }
      }

      // Merge with defaults and validate
      this.config = this.validateConfig(mergeDeep(defaultConfig, loadedConfig));
      return this.config;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to load config: ${error.message}`);
      }
      throw error;
    }
  }

  private async loadFile(filePath: string): Promise<Partial<Config>> {
    const ext = path.extname(filePath);
    let config: Partial<Config>;

    switch (ext) {
      case '.js':
      case '.cjs':
        config = await import(filePath);
        break;
      case '.json':
        config = JSON.parse(await fs.promises.readFile(filePath, 'utf8'));
        break;
      case '.yaml':
      case '.yml':
        throw new Error('YAML config files are not yet supported');
      default:
        throw new Error(`Unsupported config file type: ${ext}`);
    }

    return config;
  }

  private validateConfig(config: Partial<Config>): Config {
    const result = configSchema.safeParse(config);
    if (!result.success) {
      const errors = result.error.errors.map(err => 
        `${err.path.join('.')}: ${err.message}`
      ).join('\n');
      throw new Error(`Invalid configuration:\n${errors}`);
    }
    return result.data;
  }

  getConfig(): Config {
    return this.config;
  }

  getConfigPath(): string | undefined {
    return this.configPath;
  }
}

export const getConfig = (): Config => ConfigLoader.getInstance().getConfig();

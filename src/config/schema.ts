import { z } from 'zod';

export const configSchema = z.object({
  // Scanning options
  scanOptions: z.object({
    patterns: z.boolean().default(true),
    dependencies: z.boolean().default(true),
    devDependencies: z.boolean().default(false),
    ignoreFiles: z.array(z.string()).default([]),
    minSeverity: z.enum(['low', 'medium', 'high', 'critical']).default('low'),
    parallel: z.boolean().default(true),
    maxWorkers: z.number().optional(),
  }).default({}),

  // Custom rules and patterns
  rules: z.object({
    customPatternsPath: z.string().optional(),
    customRulesPath: z.string().optional(),
    disabledRules: z.array(z.string()).default([]),
  }).default({}),

  // Cache configuration
  cache: z.object({
    enabled: z.boolean().default(true),
    dir: z.string().default('.jsentinel/cache'),
    ttl: z.number().default(86400), // 24 hours in seconds
  }).default({}),

  // Reporting options
  reporting: z.object({
    format: z.enum(['text', 'json', 'sarif', 'html']).default('text'),
    outputFile: z.string().optional(),
    quiet: z.boolean().default(false),
    verbose: z.boolean().default(false),
  }).default({}),

  // CI/CD integration
  ci: z.object({
    failOnIssues: z.boolean().default(true),
    maxIssues: z.number().optional(),
    githubActions: z.boolean().default(false),
    jenkinsPlugin: z.boolean().default(false),
  }).default({}),
});

export type Config = z.infer<typeof configSchema>;

export const defaultConfig: Config = {
  scanOptions: {
    patterns: true,
    dependencies: true,
    devDependencies: false,
    ignoreFiles: [],
    minSeverity: 'low',
    parallel: true,
  },
  rules: {
    disabledRules: [],
  },
  cache: {
    enabled: true,
    dir: '.jsentinel/cache',
    ttl: 86400,
  },
  reporting: {
    format: 'text',
    quiet: false,
    verbose: false,
  },
  ci: {
    failOnIssues: true,
  },
};

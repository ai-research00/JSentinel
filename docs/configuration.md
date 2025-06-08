# JSentinel Configuration

JSentinel can be configured using various methods. The configuration system is flexible and supports multiple formats and locations.

## Configuration File Formats

JSentinel supports the following configuration file formats:

- `.jsentinelrc` (JSON)
- `.jsentinelrc.json`
- `.jsentinelrc.yaml`
- `.jsentinelrc.yml`
- `.jsentinelrc.js`
- `.jsentinel.config.js`
- `.jsentinel.config.cjs`
- `package.json` (with "jsentinel" field)

## Configuration Options

### Scanning Options

```json
{
  "scanOptions": {
    "patterns": true,          // Enable pattern-based scanning
    "dependencies": true,      // Scan package dependencies
    "devDependencies": false,  // Scan development dependencies
    "ignoreFiles": [          // Files/patterns to ignore
      "node_modules/**",
      "dist/**"
    ],
    "minSeverity": "low",     // Minimum severity level (low|medium|high|critical)
    "parallel": true,         // Enable parallel scanning
    "maxWorkers": 4          // Maximum number of worker threads
  }
}
```

### Custom Rules and Patterns

```json
{
  "rules": {
    "customPatternsPath": "./custom-patterns",  // Path to custom patterns
    "customRulesPath": "./custom-rules",        // Path to custom rules
    "disabledRules": []                         // List of rule IDs to disable
  }
}
```

### Cache Configuration

```json
{
  "cache": {
    "enabled": true,              // Enable caching
    "dir": ".jsentinel/cache",    // Cache directory
    "ttl": 86400                 // Cache TTL in seconds (24 hours)
  }
}
```

### Reporting Options

```json
{
  "reporting": {
    "format": "sarif",                    // Output format (text|json|sarif|html)
    "outputFile": "./security-report.sarif", // Output file path
    "quiet": false,                       // Suppress non-essential output
    "verbose": false                      // Enable verbose logging
  }
}
```

### CI/CD Integration

```json
{
  "ci": {
    "failOnIssues": true,    // Exit with error if issues found
    "maxIssues": 0,          // Maximum allowed issues (0 = no issues)
    "githubActions": true    // Enable GitHub Actions integration
  }
}
```

## Usage in package.json

You can also include JSentinel configuration in your `package.json`:

```json
{
  "name": "your-project",
  "version": "1.0.0",
  "jsentinel": {
    // Your JSentinel configuration here
  }
}
```

## Configuration Precedence

Configuration options are merged in the following order (later values override earlier ones):

1. Default configuration
2. Configuration file (`.jsentinelrc`, etc.)
3. `package.json` ("jsentinel" field)
4. Command line arguments

## Environment Variables

JSentinel also supports configuration through environment variables:

- `JSENTINEL_CONFIG_PATH`: Path to a configuration file
- `JSENTINEL_CACHE_ENABLED`: Enable/disable caching
- `JSENTINEL_MIN_SEVERITY`: Minimum severity level
- `JSENTINEL_CI`: Enable CI mode
- `JSENTINEL_GITHUB_ACTIONS`: Enable GitHub Actions integration

## Example Configuration

See the `.jsentinelrc.json` file in the project root for a complete example configuration.

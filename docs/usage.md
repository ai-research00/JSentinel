# Usage

## Basic Usage

```bash
retire
```

## Advanced Options

- Generate CycloneDX SBOM:
  ```bash
  retire --outputformat cyclonedx
  ```

- Integrate with Grunt/Gulp:
  - See [Grunt](https://github.com/bekk/grunt-retire)
  - See [Gulp](#user-content-gulp-task)

## Output

JSentinel will report any detected vulnerable libraries and suggest remediation steps.

# JSentinel

## Research-driven JavaScript Security Analysis

JSentinel is a research-focused tool for automated detection of vulnerable JavaScript libraries in web and Node.js projects.

### Research Context

This project is part of ongoing research into automated software composition analysis (SCA) and the security of third-party JavaScript dependencies. Our goal is to advance the state of the art in detecting, reporting, and remediating vulnerable components in modern software stacks.

### Key Features

- Scans for known vulnerable JavaScript libraries in projects
- Supports command line, Grunt, Gulp, and browser extension integrations
- CycloneDX SBOM generation for compliance and research reproducibility
- Extensible detection rules for new vulnerabilities

### Usage

```bash
npm install -g retire
retire
```

To generate a CycloneDX SBOM:
```bash
retire --outputformat cyclonedx
```

### Documentation

- [Introduction & Research](docs/introduction.md)
- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Results & Evaluation](docs/results.md)
- [API Reference](docs/api.md)
- [How to Cite](docs/cite.md)

### Contribution

Contributions are welcome! See [CONTRIBUTING.md](docs/contributing.md).

### License

MIT License (see LICENSE)

### How to Cite

If you use JSentinel in academic work, please see [docs/cite.md](docs/cite.md) for citation information.

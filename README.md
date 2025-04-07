# Container Results Parser

A tool for analyzing Docker container images and their vulnerabilities, providing detailed layer-by-layer information and mapping vulnerabilities to specific layers.

## Features

- Analyzes Docker container images and their layers
- Maps vulnerabilities to specific layers
- Identifies base image and application layers
- Provides detailed layer information including:
  - Layer creation commands
  - Creation dates
  - Layer sizes
  - Vulnerability counts by severity
- Supports Dockerfile instruction matching
- Can use either local tar files or download images directly
- Generates detailed reports with CWE information

## Prerequisites

- Node.js (v14 or higher)
- ncc node module installed
- Docker installed and running
- Access to the Docker daemon

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd container-results-parser
```

2. Install dependencies:
```bash
npm install
```

3. Build the project:
```bash
ncc build src/index.ts
```

## Usage

### Basic Usage

```bash
node dist/index.js -s <scan-file> -i <image-name>
```

### Options

- `-s, --scan_file`: Path to the scan JSON file (required)
- `-i, --image_name`: Docker image name to analyze (required)
- `-d, --detailed_report`: Show detailed CWE information for each layer (optional)
- `-t, --local_tar`: Path to a local tar file of the image (optional)

### Examples

1. Analyze an image with a scan file:
```bash
node dist/index.js -s scan.json -i myimage:latest
```

2. Analyze an image with detailed CWE information:
```bash
node dist/index.js -s scan.json -i myimage:latest -d
```

3. Analyze an image using a local tar file:
```bash
node dist/index.js -s scan.json -i myimage:latest -t /path/to/image.tar
```

## Output Format

The tool provides several sections of information:

1. **Layer Mapping Information**
   - Shows the relationship between history entries and actual layers
   - Indicates which history entries have corresponding layers
   - Displays creation commands and dates

2. **Application Layers**
   - Lists layers from top to bottom
   - Shows layer IDs, creation commands, and dates
   - Displays vulnerability counts by severity
   - Matches layers with Dockerfile instructions when possible

3. **Base Image Layer**
   - Identifies the base image layer
   - Shows base image information and vulnerabilities

## Scan File Format

The scan file should be a JSON file containing vulnerability information in the following format:

```json
{
  "findings": {
    "vulnerabilities": {
      "matches": [
        {
          "artifact": {
            "locations": [
              {
                "layerID": "sha256:..."
              }
            ]
          },
          "vulnerability": {
            "id": "CVE-XXXX-XXXX",
            "severity": "HIGH"
          }
        }
      ]
    }
  }
}
```

## Development

### Building
```bash
ncc build src/index.ts
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
MIT
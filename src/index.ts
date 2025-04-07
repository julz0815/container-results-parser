import * as fs from 'fs';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { execSync } from 'child_process';
import * as path from 'path';
import * as os from 'os';

interface InspectData {
    type: string;
    raw_name: string;
    name: string;
    RootFS: {
        Type: string;
        Layers: string[];
    };
    docker?: {
        Id: string;
        RepoTags: string[];
        RepoDigests: string[];
        Parent: string;
        Comment: string;
        Created: string;
        Container: string;
        ContainerConfig: {
            Hostname: string;
            Domainname: string;
            User: string;
            AttachStdin: boolean;
            AttachStdout: boolean;
            AttachStderr: boolean;
            ExposedPorts: Record<string, any>;
            Tty: boolean;
            OpenStdin: boolean;
            StdinOnce: boolean;
            Env: string[];
            Cmd: string[];
            ArgsEscaped: boolean;
            Image: string;
            Volumes: any;
            WorkingDir: string;
            Entrypoint: any;
            OnBuild: any[];
            Labels: Record<string, string>;
        };
        DockerVersion: string;
        Author: string;
        Config: {
            Hostname: string;
            Domainname: string;
            User: string;
            AttachStdin: boolean;
            AttachStdout: boolean;
            AttachStderr: boolean;
            ExposedPorts: Record<string, any>;
            Tty: boolean;
            OpenStdin: boolean;
            StdinOnce: boolean;
            Env: string[];
            Cmd: string[];
            ArgsEscaped: boolean;
            Image: string;
            Volumes: any;
            WorkingDir: string;
            Entrypoint: any;
            OnBuild: any[];
            Labels: Record<string, string>;
        };
        Architecture: string;
        Os: string;
        Size: number;
        VirtualSize: number;
        GraphDriver: {
            Data: {
                LowerDir: string;
                MergedDir: string;
                UpperDir: string;
                WorkDir: string;
            };
            Name: string;
        };
        Metadata: {
            LastTagTime: string;
        };
    };
    id: string;
}

interface ScanData {
    findings: {
        vulnerabilities: {
            matches: Array<{
                artifact: {
                    locations: Array<{
                        layerID: string;
                    }>;
                };
                vulnerability: Vulnerability;
            }>;
        };
    };
}

interface VulnerabilityMatch {
    artifact: {
        locations: { layerID: string }[];
    };
    vulnerability: {
        id: string;
        severity: string;
    };
}

interface LayerVulnerabilities {
    vulnerabilities: Set<[string, string]>;
    layer_num: number;
}

interface LayerInfo {
    layer_num: number;
    vulnerabilities: Set<[string, string]>;
    created_by?: string;
    created_at?: string;
    size?: string;
    comment?: string;
}

interface DockerHistoryEntry {
    ID: string;
    Created: string;
    CreatedBy: string;
    Size: string;
    Comment: string;
}

interface DockerfileInstruction {
    instruction: string;
    arguments: string;
    lineNumber: number;
}

interface ImageManifest {
    schemaVersion: number;
    mediaType: string;
    config: {
        digest: string;
        size: number;
        mediaType: string;
    };
    layers: {
        digest: string;
        size: number;
        mediaType: string;
    }[];
}

interface ImageConfig {
    architecture: string;
    config: {
        Cmd: string[];
        Env: string[];
        WorkingDir: string;
    };
    container: string;
    container_config: {
        Cmd: string[];
        Env: string[];
        WorkingDir: string;
    };
    created: string;
    docker_version: string;
    history: {
        created: string;
        created_by: string;
        empty_layer?: boolean;
        comment?: string;
    }[];
    os: string;
    rootfs: {
        type: string;
        diff_ids: string[];
    };
}

interface Vulnerability {
    id: string;
    severity: string;
    description?: string;
    cwe?: string;
    fix?: {
        versions?: string[];
        state?: string;
        description?: string;
    };
}

function getDockerInspect(imageName: string): InspectData {
    try {
        const output = execSync(`docker inspect --format '{{json .}}' ${imageName}`, { encoding: 'utf8' });
        return JSON.parse(output);
    } catch (error) {
        console.error('Error getting Docker inspect data:', error);
        throw new Error('Failed to get Docker inspect data');
    }
}

function getDockerHistory(imageName: string): DockerHistoryEntry[] {
    try {
        // Use a simpler format that's less likely to break
        const output = execSync(`docker history --no-trunc --format '{{.ID}}|{{.CreatedAt}}|{{.CreatedBy}}|{{.Size}}|{{.Comment}}' ${imageName}`, { encoding: 'utf8' });
        
        const entries = output.split('\n')
            .filter(line => line.trim())
            .map(line => {
                try {
                    const [ID, Created, CreatedBy, Size, Comment] = line.split('|');
                    return {
                        ID: ID.trim(),
                        Created: Created.trim(),
                        CreatedBy: CreatedBy.trim(),
                        Size: Size.trim(),
                        Comment: Comment.trim()
                    };
                } catch (e) {
                    console.error('Error parsing history entry:', line);
                    return null;
                }
            })
            .filter(entry => entry !== null) as DockerHistoryEntry[];
        
        console.log('\nDocker History Entries:');
        console.log('---------------------');
        entries.forEach(entry => {
            console.log(`ID: ${entry.ID}`);
            console.log(`CreatedBy: ${entry.CreatedBy}`);
            console.log(`Size: ${entry.Size}`);
            console.log('---------------------');
        });
        
        return entries;
    } catch (error) {
        console.error('Error getting Docker history:', error);
        return [];
    }
}

function parseDockerfile(): DockerfileInstruction[] | null {
    try {
        if (!fs.existsSync('Dockerfile')) {
            return null;
        }

        const dockerfileContent = fs.readFileSync('Dockerfile', 'utf8');
        const instructions: DockerfileInstruction[] = [];
        let lineNumber = 1;

        dockerfileContent.split('\n').forEach(line => {
            const trimmedLine = line.trim();
            if (trimmedLine && !trimmedLine.startsWith('#')) {
                const match = trimmedLine.match(/^(\w+)\s+(.+)$/);
                if (match) {
                    instructions.push({
                        instruction: match[1],
                        arguments: match[2],
                        lineNumber: lineNumber
                    });
                }
            }
            lineNumber++;
        });

        return instructions;
    } catch (error) {
        console.error('Error parsing Dockerfile:', error);
        return null;
    }
}

function downloadAndExtractImage(imageName: string, localTar?: string): string {
    console.log('\nDownloading and extracting image...');
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'docker-image-'));
    console.log(`Temporary directory: ${tempDir}`);

    try {
        let tarPath: string;
        
        if (localTar) {
            console.log('Using local tar file...');
            if (!fs.existsSync(localTar)) {
                throw new Error(`Local tar file not found at: ${localTar}`);
            }
            tarPath = localTar;
        } else {
            // Save the image to a tar file
            console.log('Saving image...');
            tarPath = path.join(tempDir, 'image.tar');
            execSync(`docker save ${imageName} -o ${tarPath}`);
        }

        // Extract the tar file
        console.log('Extracting image...');
        execSync(`tar -xf ${tarPath} -C ${tempDir}`);

        // Read the manifest.json to get layer information
        const manifestPath = path.join(tempDir, 'manifest.json');
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))[0];
        
        return tempDir;
    } catch (error) {
        console.error('Error downloading/extracting image:', error);
        // Clean up on error
        fs.rmSync(tempDir, { recursive: true, force: true });
        throw error;
    }
}

function getImageConfig(imageDir: string): ImageConfig {
    // Read index.json to get the manifest digest
    const indexPath = path.join(imageDir, 'index.json');
    const index = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
    const manifestDigest = index.manifests[0].digest.replace('sha256:', '');

    // Read the manifest to get the config digest
    const manifestPath = path.join(imageDir, 'blobs', 'sha256', manifestDigest);
    const manifest: ImageManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const configDigest = manifest.config.digest.replace('sha256:', '');

    // Read the config file
    const configPath = path.join(imageDir, 'blobs', 'sha256', configDigest);
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

function getLayerHistory(layerId: string, imageDir: string, imageConfig: ImageConfig): string {
    try {
        // Find the matching history entry for this layer
        let layerIndex = 0;
        for (let i = 0; i < imageConfig.history.length; i++) {
            if (!imageConfig.history[i].empty_layer) {
                if (layerIndex === 0) {
                    // This is the matching history entry
                    return imageConfig.history[i].created_by;
                }
                layerIndex--;
            }
        }
        return 'No matching history entry found';
    } catch (error) {
        console.error(`Error getting layer history for ${layerId}:`, error);
        return 'Error getting layer history';
    }
}

function main() {
    const argv = yargs(hideBin(process.argv))
        .option('scan_file', {
            alias: 's',
            type: 'string',
            required: true,
            describe: 'please input the scan json file',
        })
        .option('image_name', {
            alias: 'i',
            type: 'string',
            required: true,
            describe: 'Docker image name to analyze',
        })
        .option('detailed_report', {
            alias: 'd',
            type: 'boolean',
            default: false,
            describe: 'see detailed CWEs for each layer',
        })
        .option('local_tar', {
            alias: 't',
            type: 'string',
            describe: 'path to local tar file of the image',
        })
        .parseSync();

    const scanFile = argv.scan_file;
    const imageName = argv.image_name;
    const detailedReport = argv.detailed_report;
    const localTar = argv.local_tar;

    // Read scan data
    const scanData: ScanData = JSON.parse(fs.readFileSync(scanFile, 'utf-8'));

    console.log(`\nFetching information for image: ${imageName}`);
    
    // Download and extract the image
    const imageDir = downloadAndExtractImage(imageName, localTar);

    try {
        // Get Docker inspect data
        const inspectData = getDockerInspect(imageName);

        // Get layers from the inspect data
        if (!inspectData.RootFS) {
            throw new Error('RootFS field not found in inspect data');
        }

        const layers = inspectData.RootFS.Layers;
        if (!layers || layers.length === 0) {
            throw new Error('cannot find layers in inspect json');
        }

        console.log(`Found ${layers.length} layers in the image`);

        // Get image configuration
        const imageConfig = getImageConfig(imageDir);

        // Parse Dockerfile if it exists
        const dockerfileInstructions = parseDockerfile();
        if (dockerfileInstructions) {
            console.log('\nDockerfile Instructions:');
            console.log('----------------------');
            dockerfileInstructions.forEach(instruction => {
                console.log(`Line ${instruction.lineNumber}: ${instruction.instruction} ${instruction.arguments}`);
            });
            console.log('----------------------\n');
        }

        // Print layer mapping information
        console.log('\nLayer Mapping Information:');
        console.log('------------------------');
        let layerIndex = 0;
        imageConfig.history.forEach((entry, historyIndex) => {
            console.log(`\nHistory Index: ${historyIndex}`);
            console.log(`Created By: ${entry.created_by}`);
            console.log(`Created: ${new Date(entry.created).toLocaleString()}`);
            console.log(`Has Layer: ${!entry.empty_layer ? 'Yes' : 'No'}`);
            if (!entry.empty_layer) {
                console.log(`Maps to Layer: ${layers[layerIndex]}`);
                layerIndex++;
            } else {
                console.log('Maps to Layer: —');
            }
            console.log('------------------------');
        });

        const layerInfoDict: Record<string, LayerInfo> = {};

        let layerNum = 1;
        for (const layer of layers) {
            const layerId = layer.replace('sha256:', '');
            const layerHistory = getLayerHistory(layerId, imageDir, imageConfig);
            
            // Find the matching history entry for this layer
            let historyIndex = 0;
            for (let i = 0; i < imageConfig.history.length; i++) {
                if (!imageConfig.history[i].empty_layer) {
                    if (historyIndex === 0) {
                        layerInfoDict[layer] = {
                            layer_num: layerNum,
                            vulnerabilities: new Set(),
                            created_by: layerHistory,
                            created_at: imageConfig.history[i].created,
                            size: 'Unknown',
                            comment: imageConfig.history[i].comment || ''
                        };
                        break;
                    }
                    historyIndex--;
                }
            }
            layerNum++;
        }

        // Process scan data and map vulnerabilities
        for (const finding of scanData.findings.vulnerabilities.matches) {
            if (!finding.artifact || !finding.artifact.locations) {
                throw new Error('cannot find vulnerability artifact in scan results');
            }
            if (!finding.vulnerability) {
                throw new Error('finding structure missing vulnerabilities');
            }
            const vulnerability = finding.vulnerability;
            for (const layer of finding.artifact.locations) {
                const layerID = layer.layerID;
                if (!layerInfoDict[layerID]) {
                    throw new Error('scan data and inspect data not matching');
                }

                layerInfoDict[layerID].vulnerabilities.add([
                    vulnerability.id,
                    vulnerability.severity,
                ]);
            }
        }

        // Enhanced layer reporting with Dockerfile context
        console.log('\nLayer Information:');
        console.log('==================');

        // Report on application layers in chronological order (top to bottom)
        console.log('\nApplication Layers (from top to bottom):');
        console.log('--------------------------------------');
        
        const applicationLayers = Object.entries(layerInfoDict)
            .filter(([layerID]) => layerID !== layers[0])
            .sort(([, a], [, b]) => a.layer_num - b.layer_num);
        
        for (const [layerID, layer] of applicationLayers) {
            const layerNum = layer.layer_num;
            const vulCount = layer.vulnerabilities.size;
            const outputDict: Record<string, number> = {};

            for (const [, severity] of layer.vulnerabilities) {
                outputDict[severity] = (outputDict[severity] || 0) + 1;
            }

            console.log(`\nLayer ${layerNum}`);
            console.log('-------------------');
            console.log(`ID: ${layerID}`);
            
            if (layer.created_by) {
                console.log(`\nCreated by: ${layer.created_by}`);
            }
            if (layer.created_at) {
                console.log(`Created: ${new Date(layer.created_at).toLocaleString()}`);
            }
            if (layer.comment) {
                console.log(`Comment: ${layer.comment}`);
            }

            // Try to match with Dockerfile instruction
            if (dockerfileInstructions) {
                const matchingInstruction = dockerfileInstructions.find(instruction => 
                    layer.created_by?.includes(instruction.arguments)
                );
                if (matchingInstruction) {
                    console.log(`Dockerfile Line ${matchingInstruction.lineNumber}: ${matchingInstruction.instruction} ${matchingInstruction.arguments}`);
                }
            }

            console.log(`\nVulnerabilities: ${vulCount}`);
            for (const [severity, count] of Object.entries(outputDict)) {
                console.log(` - ${severity}: ${count}`);
            }

            // Show detailed findings if detailed_report is enabled
            if (detailedReport) {
                console.log('\nDetailed Findings:');
                console.log('-----------------');
                const layerFindings = scanData.findings.vulnerabilities.matches.filter(match => 
                    match.artifact.locations.some(loc => loc.layerID === layerID)
                );
                
                for (const finding of layerFindings) {
                    console.log(`\nVulnerability: ${finding.vulnerability.id}`);
                    console.log(`Severity: ${finding.vulnerability.severity}`);
                    if (finding.vulnerability.description) {
                        console.log(`Description: ${finding.vulnerability.description}`);
                    }
                    if (finding.vulnerability.cwe) {
                        console.log(`CWE: ${finding.vulnerability.cwe}`);
                    }
                    if (finding.vulnerability.fix) {
                        console.log('Fix Information:');
                        if (finding.vulnerability.fix.versions) {
                            console.log(` - Fixed in versions: ${finding.vulnerability.fix.versions.join(', ')}`);
                        }
                        if (finding.vulnerability.fix.state) {
                            console.log(` - State: ${finding.vulnerability.fix.state}`);
                        }
                        if (finding.vulnerability.fix.description) {
                            console.log(` - Description: ${finding.vulnerability.fix.description}`);
                        }
                    }
                }
            }
            console.log('-------------------');
        }

        // Report on base image layer at the end
        const baseImageLayer = layers[0];
        const baseImageInfo = layerInfoDict[baseImageLayer];
        
        console.log('\nBase Image Layer:');
        console.log('----------------');
        console.log(`ID: ${baseImageLayer}`);
        if (baseImageInfo.created_by) {
            console.log(`Base Image: ${baseImageInfo.created_by}`);
        }
        if (baseImageInfo.created_at) {
            console.log(`Created: ${new Date(baseImageInfo.created_at).toLocaleString()}`);
        }
        if (baseImageInfo.comment) {
            console.log(`Comment: ${baseImageInfo.comment}`);
        }
        
        const baseImageVulCount = baseImageInfo.vulnerabilities.size;
        const baseImageOutputDict: Record<string, number> = {};

        for (const [, severity] of baseImageInfo.vulnerabilities) {
            baseImageOutputDict[severity] = (baseImageOutputDict[severity] || 0) + 1;
        }

        console.log(`\nVulnerabilities: ${baseImageVulCount}`);
        for (const [severity, count] of Object.entries(baseImageOutputDict)) {
            console.log(` - ${severity}: ${count}`);
        }

        // Show detailed findings for base image if detailed_report is enabled
        if (detailedReport) {
            console.log('\nDetailed Findings:');
            console.log('-----------------');
            const baseImageFindings = scanData.findings.vulnerabilities.matches.filter(match => 
                match.artifact.locations.some(loc => loc.layerID === baseImageLayer)
            );
            
            for (const finding of baseImageFindings) {
                console.log(`\nVulnerability: ${finding.vulnerability.id}`);
                console.log(`Severity: ${finding.vulnerability.severity}`);
                if (finding.vulnerability.description) {
                    console.log(`Description: ${finding.vulnerability.description}`);
                }
                if (finding.vulnerability.cwe) {
                    console.log(`CWE: ${finding.vulnerability.cwe}`);
                }
                if (finding.vulnerability.fix) {
                    console.log('Fix Information:');
                    if (finding.vulnerability.fix.versions) {
                        console.log(` - Fixed in versions: ${finding.vulnerability.fix.versions.join(', ')}`);
                    }
                    if (finding.vulnerability.fix.state) {
                        console.log(` - State: ${finding.vulnerability.fix.state}`);
                    }
                    if (finding.vulnerability.fix.description) {
                        console.log(` - Description: ${finding.vulnerability.fix.description}`);
                    }
                }
            }
        }

    } finally {
        // Clean up the temporary directory
        console.log('\nCleaning up temporary files...');
        fs.rmSync(imageDir, { recursive: true, force: true });
    }
}

main();
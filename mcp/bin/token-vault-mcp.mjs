#!/usr/bin/env node
// Launcher: runs the TypeScript source with tsx, resolved from this package (works from any cwd).
import { tsImport } from 'tsx/esm/api';

await tsImport('../src/index.ts', import.meta.url);

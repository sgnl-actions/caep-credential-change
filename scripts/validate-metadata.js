#!/usr/bin/env node

/**
 * Validates metadata.yaml against the SGNL action metadata JSON Schema,
 * then checks that src/script.mjs conforms to the declared inputs/outputs.
 *
 * Schema: https://github.com/sgnl-actions/schemas/blob/main/metadata.schema.json
 */

import fs from 'fs';
import yaml from 'js-yaml';
import Ajv from 'ajv/dist/2020.js';
import { parse } from 'acorn';
import * as walk from 'acorn-walk';

const METADATA_FILE = 'metadata.yaml';
const SCRIPT_FILE = 'src/script.mjs';
const SCHEMA_URL = 'https://raw.githubusercontent.com/sgnl-actions/schemas/main/metadata.schema.json';

// --- Schema validation ---

async function loadSchema() {
  const localPath = 'node_modules/.cache/metadata.schema.json';
  if (fs.existsSync(localPath)) {
    return JSON.parse(fs.readFileSync(localPath, 'utf8'));
  }

  const response = await fetch(SCHEMA_URL);
  if (!response.ok) {
    throw new Error(`Failed to fetch schema: ${response.status} ${response.statusText}`);
  }

  const schema = await response.json();

  fs.mkdirSync('node_modules/.cache', { recursive: true });
  fs.writeFileSync(localPath, JSON.stringify(schema, null, 2));

  return schema;
}

function validateSchema(metadata, schema) {
  const ajv = new Ajv({ allErrors: true });
  const validate = ajv.compile(schema);

  if (!validate(metadata)) {
    console.error('Schema validation failed:');
    for (const err of validate.errors) {
      console.error(`  ${err.instancePath || '(root)'}: ${err.message}`);
    }
    return false;
  }

  console.log('Schema validation passed');
  console.log(`  Name: ${metadata.name}`);
  console.log(`  Description: ${metadata.description}`);
  console.log(`  Inputs: ${Object.keys(metadata.inputs).length}`);
  console.log(`  Outputs: ${Object.keys(metadata.outputs).length}`);
  if (metadata.secrets) {
    const count = Array.isArray(metadata.secrets)
      ? metadata.secrets.length
      : Object.keys(metadata.secrets).length;
    console.log(`  Secrets: ${count}`);
  }

  return true;
}

// --- Conformance validation ---

function findInvokeHandler(ast) {
  const exportDefault = ast.body.find(n => n.type === 'ExportDefaultDeclaration');
  if (!exportDefault || exportDefault.declaration.type !== 'ObjectExpression') {
    return null;
  }

  const invokeProp = exportDefault.declaration.properties.find(
    p => (p.key.name || p.key.value) === 'invoke'
  );
  if (!invokeProp) {
    return null;
  }

  return invokeProp.value;
}

function extractInputs(invokeFn) {
  const paramsParam = invokeFn.params[0];
  if (!paramsParam) {
    return new Set();
  }

  // Handle direct destructuring: async ({ first_name, last_name }) => {}
  if (paramsParam.type === 'ObjectPattern') {
    return new Set(paramsParam.properties.map(p => p.key.name || p.key.value));
  }

  // Handle identifier: async (params) => { const { x, y } = params; }
  const paramsName = paramsParam.name;
  const inputs = new Set();

  walk.simple(invokeFn.body, {
    VariableDeclarator(node) {
      if (node.id.type === 'ObjectPattern' &&
          node.init?.type === 'Identifier' &&
          node.init.name === paramsName) {
        for (const prop of node.id.properties) {
          inputs.add(prop.key.name || prop.key.value);
        }
      }
    },
    MemberExpression(node) {
      if (node.object.type === 'Identifier' &&
          node.object.name === paramsName &&
          !node.computed) {
        inputs.add(node.property.name || node.property.value);
      }
    }
  });

  return inputs;
}

function extractOutputs(invokeFn) {
  const outputs = new Set();
  const errors = [];
  let hasDynamicReturn = false;

  walk.simple(invokeFn.body, {
    ReturnStatement(node) {
      if (!node.argument) return;
      if (node.argument.type === 'ObjectExpression') {
        for (const prop of node.argument.properties) {
          if (prop.type === 'SpreadElement') {
            errors.push('Return statements in invoke must use explicit keys, not spread');
          } else {
            outputs.add(prop.key.name || prop.key.value);
          }
        }
      } else {
        // Return is a function call, variable, or await expression — can't statically resolve
        hasDynamicReturn = true;
      }
    }
  });

  return { outputs, errors, hasDynamicReturn };
}

function validateConformance(metadata) {
  if (!fs.existsSync(SCRIPT_FILE)) {
    console.error(`Conformance check skipped: ${SCRIPT_FILE} not found`);
    return true;
  }

  const source = fs.readFileSync(SCRIPT_FILE, 'utf8');
  const ast = parse(source, { ecmaVersion: 2024, sourceType: 'module' });

  const invokeFn = findInvokeHandler(ast);
  if (!invokeFn) {
    console.error('Conformance check failed: no invoke handler found in default export');
    return false;
  }

  const metadataInputs = new Set(Object.keys(metadata.inputs));
  const metadataOutputs = new Set(Object.keys(metadata.outputs));
  const codeInputs = extractInputs(invokeFn);
  const { outputs: codeOutputs, errors: outputErrors, hasDynamicReturn } = extractOutputs(invokeFn);

  const errors = [...outputErrors];
  const warnings = [];

  // Inputs: code reads a param not declared in metadata
  for (const input of codeInputs) {
    if (!metadataInputs.has(input)) {
      errors.push(`Input "${input}" is used in code but not declared in metadata`);
    }
  }

  // Inputs: metadata declares an input the code never reads
  for (const input of metadataInputs) {
    if (!codeInputs.has(input)) {
      warnings.push(`Input "${input}" is declared in metadata but not read by invoke handler`);
    }
  }

  // Output checks — skip if invoke returns a function call (can't statically resolve)
  if (hasDynamicReturn && codeOutputs.size === 0) {
    warnings.push('Invoke handler returns a function call instead of an explicit object literal. ' +
      'Output conformance check skipped. Best practice: return an explicit object with named keys.');
  } else {
    // Outputs: metadata declares an output the code never returns
    for (const output of metadataOutputs) {
      if (!codeOutputs.has(output)) {
        errors.push(`Output "${output}" is declared in metadata but not returned by invoke handler`);
      }
    }

    // Outputs: code returns a key not declared in metadata
    for (const output of codeOutputs) {
      if (!metadataOutputs.has(output)) {
        errors.push(`Output "${output}" is returned by invoke handler but not declared in metadata`);
      }
    }
  }

  if (warnings.length > 0) {
    console.log('Conformance warnings:');
    for (const w of warnings) {
      console.log(`  ${w}`);
    }
  }

  if (errors.length > 0) {
    console.error('Conformance check failed:');
    for (const e of errors) {
      console.error(`  ${e}`);
    }
    return false;
  }

  console.log('Conformance check passed');
  return true;
}

// --- Main ---

async function main() {
  if (!fs.existsSync(METADATA_FILE)) {
    console.error(`${METADATA_FILE} not found`);
    process.exit(1);
  }

  const content = fs.readFileSync(METADATA_FILE, 'utf8');
  const metadata = yaml.load(content);
  const schema = await loadSchema();

  const schemaOk = validateSchema(metadata, schema);
  if (!schemaOk) {
    process.exit(1);
  }

  console.log('');

  const conformanceOk = validateConformance(metadata);
  if (!conformanceOk) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Error during validation:', err.message);
  process.exit(1);
});

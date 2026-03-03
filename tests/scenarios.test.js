import { runScenarios } from '@sgnl-actions/testing';

runScenarios({
  script: './src/script.mjs',
  scenarios: './tests/scenarios.yaml',
  includeCommon: false
});

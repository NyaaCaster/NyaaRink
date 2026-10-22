import babelParser from '@babel/eslint-parser';
export default [
  { ignores: ['dist/**', 'node_modules/**', 'node_modules-p1-old/**', 'private/**', '.docs/**', '**/generated.ts'] },
  { files: ['**/*.{ts,tsx}'], languageOptions: { parser: babelParser,
    parserOptions: { requireConfigFile: false, babelOptions: { parserOpts: { plugins: ['typescript', 'jsx'] } } } } },
  { files: ['**/*.{mjs,js,ts,tsx}'], rules: {
    'no-debugger': 'error', 'no-unreachable': 'error', 'no-constant-condition': ['error', { checkLoops: false }],
    'eqeqeq': ['error', 'always'], 'no-duplicate-case': 'error', 'no-unsafe-finally': 'error'
  } }
];

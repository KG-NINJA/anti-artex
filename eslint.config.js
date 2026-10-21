import tseslint from 'typescript-eslint';
export default tseslint.config(...tseslint.configs.recommended, {
  files: ['src/**/*.ts'],
  rules: {
    'no-restricted-globals': ['error', 'fetch', 'WebSocket'],
    'no-eval': 'error', 'no-new-func': 'error',
    'no-restricted-imports': ['error', { patterns: ['node:*', 'child_process', 'http', 'https', 'net', 'fs'] }]
  }
});

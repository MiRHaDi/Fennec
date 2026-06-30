/* ESLint 8 config for the Vite + React + TypeScript dashboard. */
module.exports = {
  root: true,
  env: { browser: true, es2020: true, node: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', 'node_modules', '.eslintrc.cjs', 'vite.config.ts'],
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
  plugins: ['@typescript-eslint', 'react-refresh'],
  rules: {
    // tsc (noUnusedLocals/Parameters) already enforces unused symbols; let it own that.
    '@typescript-eslint/no-unused-vars': 'off',
    // The dashboard intentionally uses `any` at a few API/SSE boundaries.
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-empty-function': 'off',
    '@typescript-eslint/ban-ts-comment': 'off',
    // Advisory only (HMR hint / hook-dep heuristics) — keep them out of the CI gate.
    'react-refresh/only-export-components': 'off',
    'react-hooks/exhaustive-deps': 'off',
    // The SSE reader uses an intentional `while (true)` drain loop.
    'no-constant-condition': ['error', { checkLoops: false }],
  },
}

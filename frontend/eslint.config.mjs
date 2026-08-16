import eslint from '@eslint/js';
import typescript from 'typescript-eslint';

export default typescript.config(
  {ignores: ['dist/**', 'node_modules/**', '*.config.js', '*.d.ts']},
  eslint.configs.recommended,
  ...typescript.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    rules: {
      'no-undef': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['error', {argsIgnorePattern: '^_'}],
    },
  },
);

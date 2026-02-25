import js from '@eslint/js'
import globals from 'globals'
import react from 'eslint-plugin-react' 
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist', 'node_modules', 'build']),
  {
    files: ['**/*.{js,jsx}'],
    plugins: {
      react, // Registrar el plugin
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    languageOptions: {
      ecmaVersion: 'latest',
      globals: {
        ...globals.browser,
        ...globals.es2021,
        
        process: 'readonly', 
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    settings: {
      react: { version: 'detect' }, //Detecta la versión de React automáticamente
    },
    rules: {
      ...js.configs.recommended.rules,
      ...react.configs.recommended.rules, 
      ...reactHooks.configs.recommended.rules,
      'react/react-in-jsx-scope': 'off', 
      'react/prop-types': 'off', 
      'no-unused-vars': ['warn', { varsIgnorePattern: '^[A-Z_]' }], 
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
  },
])
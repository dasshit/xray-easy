import eslint from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import vue from 'eslint-plugin-vue'
import vueAccessibility from 'eslint-plugin-vuejs-accessibility'
import vueParser from 'vue-eslint-parser'

const webFiles = ['src/**/*.{ts,vue}', 'test/**/*.ts']

function restrictLayerImports(forbiddenLayers, layerName, disallowVue = true) {
  const patterns = [
    {
      regex: `^(\\.\\./)+(${forbiddenLayers.join('|')})(/|$)`,
      message: `The ${layerName} layer cannot import ${forbiddenLayers.join(', ')}.`,
    },
  ]

  if (disallowVue) {
    patterns.push({
      group: ['vue', 'vue/*'],
      message: `The ${layerName} layer must stay independent from Vue.`,
    })
  }

  return ['error', { patterns }]
}

const vueAccessibilityConfigs = vueAccessibility.configs['flat/recommended'].map(config => ({
  ...config,
  ...(config.rules ? {
    rules: Object.fromEntries(Object.entries(config.rules).map(([rule, setting]) => [
      rule,
      Array.isArray(setting) ? ['error', ...setting.slice(1)] : 'error',
    ])),
  } : {}),
}))

const vueAccessibilityOverrides = {
  rules: {
    // Explicit `for` attributes and implicit wrapping labels are both valid HTML.
    'vuejs-accessibility/label-has-for': ['error', { required: { some: ['nesting', 'id'] } }],
  },
}

export default tseslint.config(
  {
    ignores: ['dist/**', 'coverage/**'],
  },
  {
    files: webFiles,
    extends: [
      eslint.configs.recommended,
      ...tseslint.configs.recommendedTypeChecked,
      ...vue.configs['flat/strongly-recommended'],
    ],
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        projectService: true,
      },
    },
    rules: {
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/strict-boolean-expressions': 'error',
      'no-console': 'error',
      'vue/html-self-closing': 'off',
      'vue/max-attributes-per-line': 'off',
      'vue/singleline-html-element-content-newline': 'off',
      'vue/no-v-html': 'error',
    },
  },
  {
    files: ['src/domain/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictLayerImports(['application', 'infrastructure', 'presentation'], 'domain'),
    },
  },
  {
    files: ['src/application/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictLayerImports(['infrastructure', 'presentation'], 'application'),
    },
  },
  {
    files: ['src/infrastructure/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictLayerImports(['presentation'], 'infrastructure'),
    },
  },
  {
    files: ['src/presentation/**/*.{ts,vue}'],
    rules: {
      'no-restricted-imports': restrictLayerImports(['infrastructure'], 'presentation', false),
    },
  },
  {
    files: ['src/**/*.{ts,vue}'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/no-unnecessary-condition': 'warn',
    },
  },
  {
    files: ['src/**/*.{ts,vue}'],
    ignores: ['src/**/*.test.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-type-assertion': 'error',
    },
  },
  {
    files: ['src/**/*.test.ts', 'test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/unbound-method': 'off',
    },
  },
  {
    // vue-tsc checks Vue SFC imports; the TypeScript parser used by ESLint cannot infer that import's component type.
    files: ['src/main.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-argument': 'off',
    },
  },
  {
    files: ['src/**/*.ts', 'test/**/*.ts'],
    languageOptions: {
      parser: tseslint.parser,
    },
  },
  {
    files: ['src/**/*.vue'],
    languageOptions: {
      parser: vueParser,
      parserOptions: {
        parser: tseslint.parser,
        extraFileExtensions: ['.vue'],
      },
    },
  },
  ...vueAccessibilityConfigs,
  vueAccessibilityOverrides,
)

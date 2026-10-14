import js from "@eslint/js"
import prettier from "eslint-config-prettier"
import react from "eslint-plugin-react"
import reactHooks from "eslint-plugin-react-hooks"
import reactRefresh from "eslint-plugin-react-refresh"
import query from "@tanstack/eslint-plugin-query"
import globals from "globals"
import tseslint from "typescript-eslint"

export default tseslint.config(
  { ignores: ["dist", "coverage"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.recommended,
      react.configs.flat.recommended,
      // Desliga `react-in-jsx-scope` e activa as regras da nova transformação
      // JSX — com `jsx: "react-jsx"` já não é preciso importar o React.
      react.configs.flat["jsx-runtime"],
      reactHooks.configs["recommended-latest"],
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
        sourceType: "module",
      },
    },
    settings: {
      react: {
        version: "detect",
      },
    },
    plugins: {
      react,
      "react-refresh": reactRefresh,
    },
    rules: {
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
    },
  },
  {
    // As regras do plugin do TanStack aplicam-se à camada de serviços: query
    // keys factories em vez de strings ad-hoc, e estado de servidor sempre
    // em `useQuery`/`useMutation` em vez de `useState`.
    files: ["src/services/**/*.{ts,tsx}"],
    plugins: { "@tanstack/query": query },
    rules: query.configs["flat/recommended"][0].rules,
  },
  // Fica no fim e desliga TODAS as regras de formatação — o Prettier
  // (`.prettierrc`) é a fonte da verdade do estilo.
  prettier,
)

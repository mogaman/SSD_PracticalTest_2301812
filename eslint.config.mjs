import js from "@eslint/js";
import globals from "globals";

export default [
  // Apply recommended rules to server.js
  {
    files: ["src/server.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.node
      }
    },
    rules: {
      ...js.configs.recommended.rules
    }
  }
];
import js from "@eslint/js";
import globals from "globals";
import { defineConfig } from "eslint/config";

export default defineConfig([
  // Only check the server.js file
  { 
    files: ["src/server.js"], 
    plugins: { js }, 
    extends: ["js/recommended"], 
    languageOptions: { 
      globals: globals.node  // Use Node.js globals for server file
    }
  }
]);
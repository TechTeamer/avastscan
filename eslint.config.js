const standard = require("eslint-config-standard");
const nPlugin = require("eslint-plugin-n");

module.exports = {
  plugins: { n: nPlugin },
  rules: {
    curly: ["error", "all"],
    "brace-style": ["error", "1tbs", { allowSingleLine: false }],
    "guard-for-in": "error",
    "no-console": "error",
    "no-debugger": "error",
    radix: "error",
    "n/no-deprecated-api": "warn",
    "n/no-process-exit": "off",
    "no-process-exit": "off",
    "n/shebang": "off",
    "no-empty-function": "error",
    "no-shadow": "warn",
  },
  languageOptions: {
    ecmaVersion: 2020,
    sourceType: "script",
  },
};

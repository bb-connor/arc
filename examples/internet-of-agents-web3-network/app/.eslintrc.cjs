/** ESLint config for chio evidence console.
 *
 * The custom `no-em-dash` rule enforces the repo-wide ban on U+2014 in any
 * source-owned text (strings, templates, comments). Replace with hyphen ("-"),
 * parentheses, or plain words.
 */
module.exports = {
  root: true,
  extends: ["next/core-web-vitals"],
  rules: {
    "no-restricted-syntax": [
      "error",
      {
        selector: "Literal[value=/\\u2014/]",
        message: "No em dashes (U+2014). Use a hyphen or parentheses.",
      },
      {
        selector: "TemplateElement[value.raw=/\\u2014/]",
        message: "No em dashes (U+2014). Use a hyphen or parentheses.",
      },
      {
        selector: "JSXText[value=/\\u2014/]",
        message: "No em dashes (U+2014). Use a hyphen or parentheses.",
      },
    ],
  },
};

import { refillRule } from "./rules/refill.mjs";

/**
 * ESLint plugin that reflows comment paragraphs to a configured column
 * width, wrapping overlong lines and refilling under-filled ones. See
 * `rules/refill.mjs` for the `refill` rule and its option.
 */
const plugin = {
  meta: {
    name: "eslint-plugin-comment-refill",
  },
  rules: {
    refill: refillRule,
  },
};

export default plugin;

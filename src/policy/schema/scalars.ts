/**
 * Shared arktype field kinds used across the schema constructs.
 *
 * Kept in one leaf so a construct declares `nonEmptyString` rather than restating the
 * present-and-non-blank contract - the shape most documentation fields (reasons, comments,
 * descriptions) require - at every field.
 */
import { type } from "arktype";

/**
 * A required, present, non-blank string. A missing key is a required fault; a non-string is a type
 * fault; a whitespace-only value is rejected, since a reason or description that is only spaces
 * documents nothing. The value flows through verbatim - never trimmed - so what the policy wrote is
 * what the rule carries.
 */
export const nonEmptyString = type("string").narrow((value, ctx) =>
  value.trim() !== "" ? true : ctx.reject({ message: "must be a non-empty string" }),
);

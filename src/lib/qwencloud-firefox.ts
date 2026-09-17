/**
 * Compatibility re-export.
 *
 * Firefox profile discovery and cookie reading are service-independent and live
 * in `browser-firefox.ts`; QwenCloud code and its tests keep importing this name.
 */
export * from "./browser-firefox.js";

import { parseContextualHelp } from './schema';

/**
 * Absolute URL of the contextual help mapping, set at build time with
 * VITE_CONTEXTUAL_HELP_URL. XGuard has no public content server, so it is unset by default:
 * nothing is fetched and the help sidebar stays empty.
 */
export const contextualHelpSource: string | undefined =
  import.meta.env.VITE_CONTEXTUAL_HELP_URL || undefined;

export { parseContextualHelp };

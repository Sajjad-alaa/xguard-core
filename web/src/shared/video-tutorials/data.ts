import { z } from 'zod';
import type { VideoTutorialsMappings } from './types';

// ---------------------------------------------------------------------------
// Source resolution
// ---------------------------------------------------------------------------

/**
 * Absolute URL of the video tutorials mapping, set at build time with
 * VITE_VIDEO_TUTORIALS_URL. XGuard has no public content server, so it is unset by default:
 * nothing is fetched and the tutorials button, modal and widgets stay hidden.
 */
export const videoTutorialsSource: string | undefined =
  import.meta.env.VITE_VIDEO_TUTORIALS_URL || undefined;

// ---------------------------------------------------------------------------
// Zod schema + parser
// ---------------------------------------------------------------------------

const videoTutorialSchema = z
  .object({
    youtubeVideoId: z
      .string()
      .regex(
        /^[A-Za-z0-9_-]{11}$/,
        'youtubeVideoId must be exactly 11 alphanumeric/-/_ chars',
      ),
    title: z.string().min(1, 'title must be non-empty'),
    description: z.string().min(1, 'description must be non-empty'),
    appRoute: z.string().regex(/^\//, 'appRoute must start with "/"'),
    contextAppRoutes: z
      .array(z.string().regex(/^\//, 'contextAppRoutes entries must start with "/"'))
      .min(1, 'contextAppRoutes must contain at least one item')
      .optional(),
    docsUrl: z.string().url('docsUrl must be a valid URL').optional(),
  })
  .strip();

const sectionSchema = z
  .object({
    name: z.string().min(1, 'section name must be non-empty'),
    videos: z.array(videoTutorialSchema),
  })
  .strip();

const placementSchema = z
  .object({
    video: z
      .object({
        youtubeVideoId: z
          .string()
          .regex(
            /^[A-Za-z0-9_-]{11}$/,
            'youtubeVideoId must be exactly 11 alphanumeric/-/_ chars',
          ),
        title: z.string().min(1, 'title must be non-empty'),
      })
      .strip()
      .optional(),
    docs: z
      .array(
        z
          .object({
            docsTitle: z.string().min(1, 'docsTitle must be non-empty'),
            docsUrl: z.string().url('docsUrl must be a valid URL'),
          })
          .strip(),
      )
      .min(1, 'docs must contain at least one item')
      .optional(),
  })
  .refine((value) => Boolean(value.video || value.docs), {
    message: 'placement must define at least one of video or docs',
  })
  .strip();

const placementGroupSchema = z
  .object({
    default: placementSchema.optional(),
    steps: z.record(z.string(), placementSchema).optional(),
  })
  .strip();

const placementsSchema = z.record(z.string(), placementGroupSchema);

const versionEntrySchema = z
  .object({
    sections: z.array(sectionSchema),
    placements: placementsSchema.optional(),
  })
  .strip();

const mappingsSchema = z.object({
  versions: z.record(
    z
      .string()
      .regex(
        /^\d+\.\d+(\.\d+)?$/,
        'version key must be major.minor or major.minor.patch',
      ),
    versionEntrySchema,
  ),
});

/**
 * Validates raw JSON against the video tutorials mapping contract and returns a
 * trusted VideoTutorialsMappings object.
 * Throws a ZodError if the contract is violated.
 */
export function parseVideoTutorials(raw: unknown): VideoTutorialsMappings {
  const parsed = mappingsSchema.parse(raw);
  return parsed.versions;
}

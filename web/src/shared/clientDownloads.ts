/**
 * Client download links (Settings -> Client downloads).
 *
 * Installers are `<base_url>/<asset name>`: the client release workflow uploads every installer
 * under the same version-less name to each GitHub release, so the default base URL
 * (`.../releases/latest/download`) always serves the newest client. Keep the names in sync with
 * `CLIENT_ASSET_NAMES` in Core and `release-installers.yaml` in xguard-client.
 */

export type ClientDownloadSettings = {
  base_url: string;
  releases_url: string;
  android_url: string | null;
  ios_url: string | null;
  /** A macOS installer is published; otherwise the macOS button opens the releases page. */
  macos_installer: boolean;
  allow_http: boolean;
};

export type ClientDownloadsResponse = ClientDownloadSettings & {
  asset_names: string[];
  defaults: {
    base_url: string;
    releases_url: string;
  };
};

export const clientAssetNames = {
  debAmd64: 'xguard-client_amd64.deb',
  debArm64: 'xguard-client_arm64.deb',
  rpmX86_64: 'xguard-client.x86_64.rpm',
  rpmAarch64: 'xguard-client.aarch64.rpm',
  windowsX64: 'xguard-client_x64.msi',
  macosUniversal: 'xguard-client_universal.dmg',
} as const;

export type ClientAsset = keyof typeof clientAssetNames;

export const defaultClientDownloadSettings: ClientDownloadSettings = {
  base_url: 'https://github.com/Sajjad-alaa/xguard-client/releases/latest/download',
  releases_url: 'https://github.com/Sajjad-alaa/xguard-client/releases/latest',
  android_url: null,
  ios_url: null,
  macos_installer: false,
  allow_http: false,
};

export type ClientDownloadLinks = Record<ClientAsset, string> & {
  releases: string;
  /** Absent when the admin did not set a link: the UI hides the button. */
  android?: string;
  ios?: string;
};

/** Only http(s) links are ever rendered, whatever the server sent. */
const safeUrl = (value: string | null | undefined): string | undefined => {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined;
    return trimmed;
  } catch {
    return undefined;
  }
};

export const assetUrl = (baseUrl: string, assetName: string): string =>
  `${baseUrl.replace(/\/+$/, '')}/${assetName}`;

/** Builds every download link from the settings, falling back to the defaults. */
export const buildClientDownloadLinks = (
  settings?: Partial<ClientDownloadSettings> | null,
): ClientDownloadLinks => {
  const base = safeUrl(settings?.base_url) ?? defaultClientDownloadSettings.base_url;
  const releases =
    safeUrl(settings?.releases_url) ?? defaultClientDownloadSettings.releases_url;
  const assets = Object.fromEntries(
    Object.entries(clientAssetNames).map(([key, name]) => [key, assetUrl(base, name)]),
  ) as Record<ClientAsset, string>;
  if (!settings?.macos_installer) {
    // No signed macOS build is published (it needs an Apple Developer account).
    assets.macosUniversal = releases;
  }
  const links: ClientDownloadLinks = { ...assets, releases };
  const android = safeUrl(settings?.android_url);
  const ios = safeUrl(settings?.ios_url);
  if (android) links.android = android;
  if (ios) links.ios = ios;
  return links;
};

export type ClientUrlCheck = { ok: true; insecure: boolean } | { ok: false };

/**
 * Mirrors Core's validation for the settings form: https, or http with the opt-in; a host;
 * no credentials; the base URL also without query or fragment.
 */
export const checkClientDownloadUrl = (
  value: string,
  { allowHttp, pathOnly }: { allowHttp: boolean; pathOnly: boolean },
): ClientUrlCheck => {
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    return { ok: false };
  }
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    return { ok: false };
  }
  if (!url.hostname || url.username || url.password) return { ok: false };
  if (pathOnly && (url.search || url.hash)) return { ok: false };
  return { ok: true, insecure: url.protocol === 'http:' };
};

export type ClientDownloadItem = {
  id: string;
  label: string;
  href: string;
};

/** Linux entries of the download menus, most common first. */
export const linuxDownloadItems = (links: ClientDownloadLinks): ClientDownloadItem[] => [
  {
    id: 'deb-amd64',
    label: 'Debian / Ubuntu 22.04+ (x86_64, .deb)',
    href: links.debAmd64,
  },
  {
    id: 'deb-arm64',
    label: 'Debian / Ubuntu 22.04+ (ARM64, .deb)',
    href: links.debArm64,
  },
  { id: 'rpm-x86_64', label: 'Fedora / RHEL (x86_64, .rpm)', href: links.rpmX86_64 },
  { id: 'rpm-aarch64', label: 'Fedora / RHEL (ARM64, .rpm)', href: links.rpmAarch64 },
];

/** Mobile app links that are set; empty when the admin configured none. */
export const mobileDownloadItems = (links: ClientDownloadLinks): ClientDownloadItem[] => {
  const items: ClientDownloadItem[] = [];
  if (links.android) items.push({ id: 'android', label: 'Android', href: links.android });
  if (links.ios) items.push({ id: 'ios', label: 'iOS', href: links.ios });
  return items;
};

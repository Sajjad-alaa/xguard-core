export const FirewallPageTab = {
  Rules: 'rules',
  Snat: 'snat',
  Enforcement: 'enforcement',
} as const;

export type FirewallPageTabValue = (typeof FirewallPageTab)[keyof typeof FirewallPageTab];

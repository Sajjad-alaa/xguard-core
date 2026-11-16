// Fixed instance behaviour in XGuard. These values used to be editable
// "enterprise settings"; XGuard ships the open defaults: users manage their own
// devices, manual WireGuard setup is allowed and the Edge shows its standard pages.
export const instanceBehavior = {
  admin_device_management: false,
  only_client_activation: false,
  display_download_step: true,
  display_password_reset: true,
  group_client_traffic_policies: {
    none: [] as number[],
    disable_all_traffic: [] as number[],
    force_all_traffic: [] as number[],
  },
} as const;

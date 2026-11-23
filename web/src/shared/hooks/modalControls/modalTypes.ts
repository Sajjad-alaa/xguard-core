import z from 'zod';
import type { ActivityLogStream, AddDeviceResponse, User } from '../../api/types';
import type {
  OpenAddApiTokenModal,
  OpenAddNetworkDeviceModal,
  OpenAppUpdateModal,
  OpenAssignUserDeviceIPModal,
  OpenAssignUserIPModal,
  OpenAssignUsersToGroupsModal,
  OpenAuthKeyRenameModal,
  OpenCEFirewallRuleModal,
  OpenCEGroupModal,
  OpenCEOpenIdClientModal,
  OpenCEPostureCheckModal,
  OpenCESnatBindingModal,
  OpenCEWebhookModal,
  OpenConfirmActionModal,
  OpenDeleteAliasDestinationBlockedModal,
  OpenDeleteAliasDestinationConfirmModal,
  OpenDevicePostureModal,
  OpenDisplayListModal,
  OpenEditDeviceModal,
  OpenEditNetworkDeviceModal,
  OpenEditUserModal,
  OpenEnrollmentTokenModal,
  OpenNetworkDeviceConfigModal,
  OpenNetworkDeviceTokenModal,
  OpenRenameApiTokenModal,
} from './types';

export const ModalName = {
  SendTestMail: 'sendTestMail',
  GatewaySetup: 'gatewaySetup',
  DisplayList: 'displayList',
  DeleteAliasDestinationConfirm: 'deleteAliasDestinationConfirm',
  DeleteAliasDestinationBlocked: 'deleteAliasDestinationBlocked',
  ChangePassword: 'changePassword',
  TotpSetup: 'totpSetup',
  RecoveryCodes: 'recoveryCodes',
  EmailMfaSetup: 'emailMfaSetup',
  WebauthnSetup: 'webauthnSetup',
  EditUserDevice: 'editUserDevice',
  UserDeviceConfig: 'userDeviceConfig',
  AddAuthKey: 'addAuthKey',
  RenameAuthKey: 'renameAuthKey',
  AddApiToken: 'addApiToken',
  RenameApiToken: 'renameApiToken',
  CreateEditGroup: 'createEditGroup',
  EditUserModal: 'editUserModal',
  CEOpenIdClient: 'createEditOpenIdClient',
  CEWebhook: 'createEditWebhook',
  CEFirewallRule: 'createEditFirewallRule',
  CEPostureCheck: 'createEditPostureCheck',
  DevicePosture: 'devicePosture',
  CESnatBinding: 'createEditSnatBinding',
  AssignGroupsToUsers: 'assignGroupsToUsers',
  AddNetworkDevice: 'addNetworkDevice',
  EditNetworkDevice: 'editNetworkDevice',
  NetworkDeviceConfig: 'networkDeviceConfig',
  NetworkDeviceToken: 'networkDeviceToken',
  AddLocation: 'addLocation',
  AddLogStreaming: 'addLogStreaming',
  EditLogStreaming: 'editLogStreaming',
  SelfEnrollmentToken: 'selfEnrollmentToken',
  AddNewDevice: 'addNewDevice',
  AssignUserIP: 'assignUserIP',
  AssignUserDeviceIP: 'assignUserDeviceIP',
  ConfirmAction: 'confirmAction',
  AppUpdate: 'appUpdate',
} as const;

export type ModalNameValue = (typeof ModalName)[keyof typeof ModalName];

const modalOpenArgsSchema = z.discriminatedUnion('name', [
  z.object({
    name: z.literal(ModalName.ChangePassword),
    data: z.object({
      user: z.custom<User>(),
      adminForm: z.boolean(),
    }),
  }),
  z.object({ name: z.literal(ModalName.TotpSetup) }),
  z.object({ name: z.literal(ModalName.RecoveryCodes), data: z.array(z.string()) }),
  z.object({ name: z.literal(ModalName.EmailMfaSetup) }),
  z.object({ name: z.literal(ModalName.WebauthnSetup) }),
  z.object({
    name: z.literal(ModalName.EditUserDevice),
    data: z.custom<OpenEditDeviceModal>(),
  }),
  z.object({
    name: z.literal(ModalName.UserDeviceConfig),
    data: z.custom<AddDeviceResponse>(),
  }),
  z.object({
    name: z.literal(ModalName.AddAuthKey),
    data: z.object({
      username: z.string(),
    }),
  }),
  z.object({
    name: z.literal(ModalName.RenameAuthKey),
    data: z.custom<OpenAuthKeyRenameModal>(),
  }),
  z.object({
    name: z.literal(ModalName.AddApiToken),
    data: z.custom<OpenAddApiTokenModal>(),
  }),
  z.object({
    name: z.literal(ModalName.RenameApiToken),
    data: z.custom<OpenRenameApiTokenModal>(),
  }),
  z.object({
    name: z.literal(ModalName.CreateEditGroup),
    data: z.custom<OpenCEGroupModal>(),
  }),
  z.object({
    name: z.literal(ModalName.EditUserModal),
    data: z.custom<OpenEditUserModal>(),
  }),
  z.object({
    name: z.literal(ModalName.SelfEnrollmentToken),
    data: z.custom<OpenEnrollmentTokenModal>(),
  }),
  z.object({
    name: z.literal(ModalName.EditUserModal),
    data: z.custom<OpenEditUserModal>(),
  }),
  z.object({
    name: z.literal(ModalName.CEOpenIdClient),
    data: z.custom<OpenCEOpenIdClientModal>(),
  }),
  z.object({
    name: z.literal(ModalName.CEWebhook),
    data: z.custom<OpenCEWebhookModal>(),
  }),
  z.object({
    name: z.literal(ModalName.CEFirewallRule),
    data: z.custom<OpenCEFirewallRuleModal>(),
  }),
  z.object({
    name: z.literal(ModalName.CEPostureCheck),
    data: z.custom<OpenCEPostureCheckModal>(),
  }),
  z.object({
    name: z.literal(ModalName.DevicePosture),
    data: z.custom<OpenDevicePostureModal>(),
  }),
  z.object({
    name: z.literal(ModalName.CESnatBinding),
    data: z.custom<OpenCESnatBindingModal>(),
  }),
  z.object({
    name: z.literal(ModalName.AssignGroupsToUsers),
    data: z.custom<OpenAssignUsersToGroupsModal>(),
  }),
  z.object({
    name: z.literal(ModalName.AddNetworkDevice),
    data: z.custom<OpenAddNetworkDeviceModal>(),
  }),
  z.object({
    name: z.literal(ModalName.EditNetworkDevice),
    data: z.custom<OpenEditNetworkDeviceModal>(),
  }),
  z.object({
    name: z.literal(ModalName.NetworkDeviceConfig),
    data: z.custom<OpenNetworkDeviceConfigModal>(),
  }),
  z.object({
    name: z.literal(ModalName.NetworkDeviceToken),
    data: z.custom<OpenNetworkDeviceTokenModal>(),
  }),
  z.object({
    name: z.literal(ModalName.DisplayList),
    data: z.custom<OpenDisplayListModal>(),
  }),
  z.object({
    name: z.literal(ModalName.DeleteAliasDestinationConfirm),
    data: z.custom<OpenDeleteAliasDestinationConfirmModal>(),
  }),
  z.object({
    name: z.literal(ModalName.DeleteAliasDestinationBlocked),
    data: z.custom<OpenDeleteAliasDestinationBlockedModal>(),
  }),
  z.object({
    name: z.literal(ModalName.AddLocation),
  }),
  z.object({
    name: z.literal(ModalName.AddLogStreaming),
  }),
  z.object({
    name: z.literal(ModalName.EditLogStreaming),
    data: z.custom<ActivityLogStream>(),
  }),
  z.object({
    name: z.literal(ModalName.SendTestMail),
  }),
  z.object({
    name: z.literal(ModalName.AddNewDevice),
    data: z.custom<User>(),
  }),
  z.object({
    name: z.literal(ModalName.AssignUserIP),
    data: z.custom<OpenAssignUserIPModal>(),
  }),
  z.object({
    name: z.literal(ModalName.AssignUserDeviceIP),
    data: z.custom<OpenAssignUserDeviceIPModal>(),
  }),
  z.object({
    name: z.literal(ModalName.ConfirmAction),
    data: z.custom<OpenConfirmActionModal>(),
  }),
  z.object({
    name: z.literal(ModalName.AppUpdate),
    data: z.custom<OpenAppUpdateModal>(),
  }),
]);

export type ModalOpenEvent = z.infer<typeof modalOpenArgsSchema>;

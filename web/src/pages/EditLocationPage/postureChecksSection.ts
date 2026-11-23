export type PostureChecksSectionState = {
  hasAnyPostureChecks: boolean;
  hasAssignedPostureChecks: boolean;
  showAssignButton: boolean;
  showAssignedPostureChecks: boolean;
  showEmptyState: boolean;
};

type Input = {
  assignedPostureChecksCount: number;
  postureChecksCount: number;
};

// Keep the edit-location posture-check section aligned with the Figma states.
export const getPostureChecksSectionState = ({
  assignedPostureChecksCount,
  postureChecksCount,
}: Input): PostureChecksSectionState => {
  const hasAnyPostureChecks = postureChecksCount > 0;
  const hasAssignedPostureChecks = assignedPostureChecksCount > 0;

  return {
    hasAnyPostureChecks,
    hasAssignedPostureChecks,
    showAssignButton: hasAnyPostureChecks && !hasAssignedPostureChecks,
    showAssignedPostureChecks: hasAssignedPostureChecks,
    showEmptyState: !hasAnyPostureChecks,
  };
};

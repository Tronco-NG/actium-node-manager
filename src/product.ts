export type DeploymentEnvironment = "stable" | "lab";

const configuredEnvironment = import.meta.env.VITE_ACTIUM_DEPLOYMENT_ENVIRONMENT
  ?? import.meta.env.VITE_ACTIUM_PRODUCT_CHANNEL;

export const buildDeploymentEnvironment: DeploymentEnvironment = configuredEnvironment === "lab" ? "lab" : "stable";

export function composeProjectName(deploymentCode: string): string {
  const normalized = deploymentCode.trim();
  const prefix = buildDeploymentEnvironment === "lab" ? "actium-lab-" : "actium-node-";
  return normalized.startsWith(prefix) ? normalized : `${prefix}${normalized}`;
}

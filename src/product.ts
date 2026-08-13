export type ProductChannel = "stable" | "lab";

const configuredChannel = import.meta.env.VITE_ACTIUM_PRODUCT_CHANNEL;

export const buildProductChannel: ProductChannel = configuredChannel === "lab" ? "lab" : "stable";

export function composeProjectName(deploymentCode: string): string {
  const normalized = deploymentCode.trim();
  const prefix = buildProductChannel === "lab" ? "actium-lab-" : "actium-node-";
  return normalized.startsWith(prefix) ? normalized : `${prefix}${normalized}`;
}

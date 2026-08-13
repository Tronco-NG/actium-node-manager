export type ProductChannel = "stable" | "lab";

const configuredChannel = import.meta.env.VITE_ACTIUM_PRODUCT_CHANNEL;

export const buildProductChannel: ProductChannel = configuredChannel === "lab" ? "lab" : "stable";

export function composeProjectName(deploymentCode: string): string {
  const normalized = deploymentCode.trim();
  if (buildProductChannel === "lab" && !normalized.startsWith("actium-lab-")) {
    return `actium-lab-${normalized}`;
  }
  return normalized;
}

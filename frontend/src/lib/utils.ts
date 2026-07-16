export function buildCpeString(vendor: string, product: string, version: string): string {
  return `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`
}

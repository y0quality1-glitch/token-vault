declare module 'swagger-ui-dist' {
  /** The folder holding swagger-ui's static files. */
  export function getAbsoluteFSPath(): string;
  const mod: { getAbsoluteFSPath(): string };
  export default mod;
}

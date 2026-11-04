import base from '../../client/tailwind.config.js';

/** Same design tokens as the Token Vault console; also scans the shared UI components. */
export default {
  ...base,
  content: ['./index.html', './src/**/*.{ts,tsx}', '../../client/src/components/ui/**/*.{ts,tsx}'],
};

// @ts-check
import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
  // Static output: all pages are pre-rendered at build time.
  // Dynamic routes (like /container/[name]) are handled via client-side JS
  // that reads window.location.pathname to extract the container name.
  output: 'static',
});

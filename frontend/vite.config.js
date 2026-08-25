import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The built assets are served by the FastAPI `/static/react/` mount. Using a
// stable base plus deterministic output filenames keeps the FastAPI HTML shell
// able to reference index.js / workbench.css without a manifest lookup.
export default defineConfig({
  base: '/static/react/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        entryFileNames: 'assets/index.js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name && assetInfo.name.endsWith('.css')) {
            return 'assets/workbench.css';
          }
          return 'assets/[name][extname]';
        },
      },
    },
  },
});

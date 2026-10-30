import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { app } from './app.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`[AI-SOC] Server running on http://0.0.0.0:${port}`);
  });
}

startServer().catch(err => {
  console.error('[AI-SOC] Fatal server error:', err);
  process.exit(1);
});

export { app };
export default app;

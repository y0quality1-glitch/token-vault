import { config } from './config';
import { createApp } from './app';
import { seedDatabase, DEMO_PASSWORD } from './store/seed';
import { startHeartbeat } from './modules/webhooks/webhook.service';

seedDatabase();
const app = createApp();

app.listen(config.port, () => {
  console.log(`[api] Token Vault control plane listening on http://localhost:${config.port}`);
  console.log(`[api] Customer webhook expected at ${config.defaultWebhookUrl}`);
  console.log(`[api] Demo sign-in: owner@demo.test / ${DEMO_PASSWORD} (mock account, development only)`);
  startHeartbeat();
});

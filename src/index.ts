import { registerPlugin } from '@capacitor/core';

import type { rootCheckerPlugin } from './definitions';

const rootChecker = registerPlugin<rootCheckerPlugin>('rootChecker', {
  web: () => import('./web').then(m => new m.rootCheckerWeb()),
});

export * from './definitions';
export { rootChecker };

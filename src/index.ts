import { registerPlugin } from '@capacitor/core';

import type { rootCheckerPlugin } from './definitions';

const rootChecker = registerPlugin<rootCheckerPlugin>('rootChecker', {});

export * from './definitions';
export { rootChecker };
//harshal

import { registerPlugin } from '@capacitor/core';

import type { RootCheckerPlugin } from './definitions';

const RootChecker = registerPlugin<RootCheckerPlugin>('RootChecker', {});

export * from './definitions';
export { RootChecker };

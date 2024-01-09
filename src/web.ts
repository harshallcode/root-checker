import { WebPlugin } from '@capacitor/core';

import type { rootCheckerPlugin } from './definitions';

export class rootCheckerWeb extends WebPlugin implements rootCheckerPlugin {
  async echo(options: { value: string }): Promise<{ value: string }> {
    console.log('ECHO', options);
    return options;
  }
  async checkRoot():Promise<void>{
    console.log("Check Root");
    
  }
}

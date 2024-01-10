export interface rootCheckerPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
  checkRoot(options: { isRooted: boolean }): Promise<void>;
}

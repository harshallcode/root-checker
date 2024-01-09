export interface rootCheckerPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
  checkRoot():Promise<void>
}
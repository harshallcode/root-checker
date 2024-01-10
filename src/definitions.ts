export interface rootCheckerPlugin {
  /**
   * Get information about device root status
   *
   * @since 1.0.0
   */
  checkRoot(): Promise<{ isRooted: string }>;
}

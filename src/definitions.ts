export interface rootCheckerPlugin {
  /**
   * Get information about device root status
   *
   * @since 1.0.0
   */
  checkRoot(): Promise<{ isRooted: boolean }>;
  isDeveloperModeEnable(): Promise<{ isEnabled: boolean }>;
}

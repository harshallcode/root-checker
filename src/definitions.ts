export interface rootCheckerPlugin {
  /**
   * Get information about device root status
   *
   * @since 1.0.0
   */
  checkRoot(): Promise<{ isRooted: boolean }>;
  /**
   * Get whether developer mode is enabled on user device or not
   *
   * @since 1.0.0
   */
  isDeveloperModeEnable(): Promise<{ isEnabled: boolean }>;
  /**
   * Get whether the app is being run on an emulator or not
   *
   * @since 1.0.0
   */
  isEmulatorPresent(): Promise<{ isEmulator: boolean }>;
  /**
   * Get information about CPU architecture
   *
   * @since 1.1.0
   */
  getCpuArchitecture(): Promise<{ cpuArch: string }>;
  /**
   * Redirect to user's device's developer setting, usually to turn off developer mode
   *
   * @since 1.2.0
   */
  openDeveloperSetting(): Promise<void>;

  /**
   * Returns whether ADB is enabled in user's device or not
   *
   * @since 1.2.2
   */
    isADBEnabled(): Promise<{ isADBEnabled: boolean }>;
}

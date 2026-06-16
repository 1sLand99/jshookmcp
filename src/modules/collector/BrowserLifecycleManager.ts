import type { Browser } from 'rebrowser-puppeteer-core';
import { logger } from '@utils/logger';
import { existsSync } from 'fs';
import { findBrowserExecutableAsync } from '@utils/browserExecutable';
import {
  resolveChromeLaunchOptions,
  sameChromeLaunchOptions,
  type ChromeLaunchOverrides,
  type ResolvedChromeLaunchOptions,
} from '@modules/collector/CodeCollectorLaunchOptions';
import type { PuppeteerConfig } from '@internal-types/index';

export interface CodeCollectorLaunchResult {
  action: 'launched' | 'relaunched' | 'reused';
  launchOptions: ResolvedChromeLaunchOptions;
  reason?: 'replacing-existing-browser-connection' | 'launch-options-changed';
}

/**
 * Manages browser lifecycle (launch, connect, close) for CodeCollector.
 * Extracted from CodeCollector to reduce class complexity.
 */
export class BrowserLifecycleManager {
  private browser: Browser | null = null;
  private chromePid: number | null = null;
  private currentLaunchOptions: ResolvedChromeLaunchOptions | null = null;
  private connectedToExistingBrowser: boolean = false;
  private currentHeadless: boolean | null = null;

  private static readonly BROWSER_CLOSE_TIMEOUT_MS = 5000;

  constructor(
    private readonly config: PuppeteerConfig,
    private readonly viewport: { width: number; height: number },
    private readonly onDisconnected: () => void,
  ) {}

  getBrowser(): Browser | null {
    return this.browser;
  }

  isExistingBrowserConnection(): boolean {
    return this.connectedToExistingBrowser;
  }

  getChromePid(): number | null {
    return this.chromePid;
  }

  getCurrentHeadless(): boolean | null {
    return this.currentHeadless;
  }

  getCurrentLaunchOptions(): ResolvedChromeLaunchOptions | null {
    return this.currentLaunchOptions;
  }

  async launch(
    overrides?: ChromeLaunchOverrides,
    initPromise?: Promise<void> | null,
  ): Promise<CodeCollectorLaunchResult> {
    if (initPromise) {
      await initPromise;
    }

    const executablePath = await this.resolveExecutablePath();
    const launchOptions = resolveChromeLaunchOptions(
      this.config,
      overrides,
      executablePath,
      this.viewport,
    );

    // Internal callers such as collector.init() only need "a browser".
    // If one already exists, do not silently relaunch it with default config.
    if (this.browser && overrides === undefined) {
      return {
        action: 'reused',
        launchOptions: this.currentLaunchOptions ?? launchOptions,
      };
    }

    if (
      this.browser &&
      !this.connectedToExistingBrowser &&
      sameChromeLaunchOptions(this.currentLaunchOptions, launchOptions)
    ) {
      return {
        action: 'reused',
        launchOptions,
      };
    }

    const action: CodeCollectorLaunchResult['action'] = this.browser ? 'relaunched' : 'launched';
    const reason = this.browser
      ? this.connectedToExistingBrowser
        ? 'replacing-existing-browser-connection'
        : 'launch-options-changed'
      : undefined;

    await this.launchInner(launchOptions);

    return {
      action,
      launchOptions,
      ...(reason ? { reason } : {}),
    };
  }

  private async launchInner(launchOptions: ResolvedChromeLaunchOptions): Promise<void> {
    if (this.browser) {
      await this.disposeCurrentBrowser(false, async () => {});
    }

    const browserLaunchOptions: Parameters<typeof import('rebrowser-puppeteer-core').launch>[0] = {
      headless: launchOptions.headless,
      args: launchOptions.args,
      defaultViewport: this.viewport,
      protocolTimeout: 60000,
    };
    if (launchOptions.executablePath) {
      browserLaunchOptions.executablePath = launchOptions.executablePath;
    }
    logger.info('Initializing browser with anti-detection...');
    const puppeteer = await import('rebrowser-puppeteer-core');
    const launchFn = puppeteer.default?.launch ?? puppeteer.launch;
    this.browser = await launchFn(browserLaunchOptions);
    this.connectedToExistingBrowser = false;
    this.chromePid = this.browser.process()?.pid ?? null;
    if (this.chromePid) {
      logger.debug(`Chrome child process PID: ${this.chromePid}`);
    }
    this.currentHeadless = launchOptions.headless;
    this.currentLaunchOptions = launchOptions;
    this.browser.on('disconnected', () => {
      this.handleBrowserDisconnected();
    });
    logger.success('Browser initialized with enhanced anti-detection');
  }

  private async resolveExecutablePath(): Promise<string | undefined> {
    const configuredPath = this.config.executablePath?.trim();
    if (configuredPath) {
      if (existsSync(configuredPath)) {
        return configuredPath;
      }
      throw new Error(
        `Configured browser executable was not found: ${configuredPath}. ` +
          'Set a valid executablePath or configure CHROME_PATH / PUPPETEER_EXECUTABLE_PATH / BROWSER_EXECUTABLE_PATH.',
      );
    }
    const detectedPath = await findBrowserExecutableAsync();
    if (detectedPath) {
      return detectedPath;
    }
    logger.info(
      'No explicit browser executable configured. Falling back to Puppeteer-managed browser resolution.',
    );
    return undefined;
  }

  private handleBrowserDisconnected(): void {
    logger.warn('Browser disconnected');
    this.browser = null;
    this.currentHeadless = null;
    this.currentLaunchOptions = null;
    this.connectedToExistingBrowser = false;
    this.chromePid = null;
    this.onDisconnected();
  }

  private async disposeCurrentBrowser(
    markExplicitlyClosed: boolean,
    clearAllData: () => Promise<void>,
  ): Promise<void> {
    await clearAllData();

    const browser = this.browser;
    const disconnectOnly = this.connectedToExistingBrowser;
    const pid = this.chromePid;
    this.browser = null;
    this.currentHeadless = null;
    this.currentLaunchOptions = null;
    this.connectedToExistingBrowser = false;
    this.chromePid = null;

    if (browser) {
      if (disconnectOnly) {
        await browser.disconnect();
      } else {
        await this.closeBrowserWithForceKill(browser, pid);
      }
    }
  }

  async close(clearAllData: () => Promise<void>): Promise<void> {
    await this.disposeCurrentBrowser(true, clearAllData);
    logger.info('Browser closed and all data cleared');
  }

  /**
   * Close browser with a timeout guard. If browser.close() hangs or fails,
   * force-kill the Chrome child process by PID to prevent zombie processes.
   */
  async closeBrowserWithForceKill(browser: Browser, pid: number | null): Promise<void> {
    try {
      await Promise.race([
        browser.close(),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error('browser.close() timed out')),
            BrowserLifecycleManager.BROWSER_CLOSE_TIMEOUT_MS,
          ),
        ),
      ]);
    } catch (error) {
      logger.warn('browser.close() failed or timed out, attempting force-kill:', error);
      BrowserLifecycleManager.forceKillPid(pid);
    }
  }

  /** Force-kill a process by PID. Safe to call with null/invalid PIDs. */
  static forceKillPid(pid: number | null): void {
    if (!pid) return;
    try {
      process.kill(pid, 'SIGKILL');
      logger.info(`Force-killed Chrome process PID ${pid}`);
    } catch (error) {
      // ESRCH = process already exited, which is fine
      if ((error as NodeJS.ErrnoException).code !== 'ESRCH') {
        logger.warn(`Failed to force-kill Chrome PID ${pid}:`, error);
      }
    }
  }

  async connect(
    connectOptions: { browserWSEndpoint?: string; browserURL?: string },
    connectWithTimeout: (
      connectOptions: { browserWSEndpoint?: string; browserURL?: string },
      target: string,
    ) => Promise<Browser>,
    target: string,
  ): Promise<void> {
    if (this.browser) {
      await this.disposeCurrentBrowser(false, async () => {});
    }
    logger.info(`Connecting to existing browser: ${target}`);
    this.browser = await connectWithTimeout(connectOptions, target);
    this.connectedToExistingBrowser = true;
    this.currentLaunchOptions = null;
    this.browser.on('disconnected', () => {
      this.handleBrowserDisconnected();
    });
    logger.success('Connected to existing browser successfully');
  }
}

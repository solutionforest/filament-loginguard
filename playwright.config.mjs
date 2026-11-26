import { defineConfig } from '@playwright/test'

export default defineConfig({
    testDir: './tests/Browser',
    outputDir: './build/playwright',
    workers: 1,
    timeout: 60000,
    forbidOnly: Boolean(process.env.CI),
    use: {
        browserName: 'chromium',
        headless: true,
        screenshot: 'only-on-failure',
        launchOptions: {
            executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
        },
    },
})

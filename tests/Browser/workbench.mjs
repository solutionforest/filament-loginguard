import { test as base, expect } from '@playwright/test'
import { execFileSync, spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'

const root = fileURLToPath(new URL('../../', import.meta.url))
const publicPath = join(root, 'vendor/orchestra/testbench-core/laravel/public')

export const test = base.extend({
    // Lockouts include an IP-wide key. Give each test its own server and SQLite
    // database so tests can run in either order, including individual retries.
    baseURL: async ({}, use, testInfo) => {
        const directory = mkdtempSync(join(tmpdir(), 'loginguard-browser-'))
        const database = join(directory, 'workbench.sqlite')
        const port = Number(process.env.LOGINGUARD_BROWSER_PORT ?? 8765)
        const url = `http://127.0.0.1:${port}`
        const env = {
            ...process.env,
            APP_ENV: 'local',
            APP_DEBUG: 'true',
            APP_URL: url,
            APP_KEY: `base64:${randomBytes(32).toString('base64')}`,
            DB_CONNECTION: 'sqlite',
            DB_DATABASE: database,
            DB_URL: '',
            SESSION_CONNECTION: 'sqlite',
            SESSION_DRIVER: 'database',
            LOG_CHANNEL: 'stderr',
            MAIL_MAILER: 'array',
            CACHE_STORE: 'array',
            QUEUE_CONNECTION: 'sync',
            TESTBENCH_WORKING_PATH: root,
        }

        let server
        let diagnostics = ''
        let loginResponse
        try {
            writeFileSync(database, '', { flag: 'wx' })
            execFileSync(
                'php',
                [
                    'vendor/bin/testbench',
                    'migrate',
                    '--database=sqlite',
                    '--force',
                    '--seed',
                    '--seeder=Workbench\\Database\\Seeders\\DatabaseSeeder',
                ],
                { cwd: root, env, stdio: 'inherit', timeout: 30000 },
            )

            const router = join(
                root,
                'vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php',
            )
            // Testbench reads the test configuration from PHP's environment.
            // Include $_ENV explicitly for hosts using the default GPCS order.
            server = spawn(
                'php',
                [
                    '-d',
                    'variables_order=EGPCS',
                    '-S',
                    `127.0.0.1:${port}`,
                    router,
                ],
                { cwd: publicPath, env },
            )
            let listening = false
            const collectOutput = (chunk) => {
                diagnostics = (diagnostics + chunk).slice(-32_768)
                listening ||= diagnostics.includes(
                    'Development Server (' + url + ') started',
                )
            }
            server.stderr.on('data', collectOutput)
            server.stdout.on('data', collectOutput)

            await expect
                .poll(
                    async () => {
                        if (server.exitCode !== null)
                            throw new Error(
                                `Workbench server exited. ${diagnostics}`,
                            )
                        if (!listening) return undefined
                        const response = await fetch(`${url}/login`, {
                            headers: { Accept: 'application/json' },
                            signal: AbortSignal.timeout(2000),
                        }).catch(() => null)

                        if (response && response.status >= 500) {
                            loginResponse = (await response.text()).slice(
                                0,
                                8192,
                            )
                            throw new Error(
                                `Workbench GET /login returned HTTP ${response.status}`,
                            )
                        }

                        await response?.body?.cancel()
                        return response?.status
                    },
                    {
                        timeout: 15000,
                        message: 'Waiting for the Workbench login form',
                    },
                )
                .toBe(200)

            await use(url)
        } catch (error) {
            const logPath = testInfo.outputPath('workbench.log')
            writeFileSync(logPath, diagnostics)
            await testInfo.attach('Workbench server output', {
                path: logPath,
                contentType: 'text/plain',
            })

            if (loginResponse !== undefined) {
                const responsePath = testInfo.outputPath('workbench-login.txt')
                writeFileSync(responsePath, loginResponse)
                await testInfo.attach('Workbench login response', {
                    path: responsePath,
                    contentType: 'text/plain',
                })
            }

            throw error
        } finally {
            if (
                server &&
                server.exitCode === null &&
                server.signalCode === null
            ) {
                const closed = once(server, 'exit')
                server.kill()
                await closed
            }
            rmSync(directory, { recursive: true, force: true })
        }
    },
})

export { expect }

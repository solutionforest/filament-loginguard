import { test, expect } from './workbench.mjs'

async function login(page, { password = 'password', remember = false } = {}) {
    await page.goto('/login')
    await page.getByLabel('Email', { exact: true }).fill('test@example.com')
    await page.getByLabel('Password', { exact: true }).fill(password)
    if (remember)
        await page.getByRole('checkbox', { name: 'Remember me' }).check()
    await page.getByRole('button', { name: 'Log in' }).click()
}

test('a locked login rejects the correct password', async ({ page }) => {
    // Workbench deliberately sets the package threshold to three failed logins.
    for (let attempt = 1; attempt <= 3; attempt++) {
        await login(page, { password: 'incorrect' })
        await expect(
            page.getByText(
                attempt === 3
                    ? /Access is blocked/
                    : /credentials do not match/i,
            ),
        ).toBeVisible()
    }
    await login(page)
    await expect(page.getByText(/Access is blocked/)).toBeVisible()
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/\/login$/)
})

test('the owner can review and revoke a second remembered browser', async ({
    page,
    browser,
    baseURL,
}) => {
    const second = await browser.newContext({ baseURL })
    try {
        const remembered = await second.newPage()
        await login(remembered, { remember: true })
        await expect(remembered).toHaveURL(/\/dashboard$/)
        expect(
            (await second.cookies()).some(
                ({ name, expires }) =>
                    name.startsWith('remember_web_') && expires > 0,
            ),
        ).toBe(true)

        await login(page)
        await expect(page).toHaveURL(/\/dashboard$/)
        await page.goto('/admin/my-devices')
        await expect(
            page.getByRole('heading', { name: 'This device' }),
        ).toBeVisible()
        await expect(page.getByText('2 signed-in devices.')).toBeVisible()
        await page.getByRole('button', { name: 'Device actions' }).click()
        await page.getByText("This isn't me", { exact: true }).click()
        const dialog = page.getByRole('alertdialog')
        await expect(
            dialog.getByRole('heading', { name: "This isn't me?" }),
        ).toBeVisible()
        await dialog.getByRole('button', { name: 'Confirm' }).click()

        await expect(
            page.getByText("Device revoked. It won't be recognized again."),
        ).toBeVisible()
        await expect(page.getByText('1 signed-in device.')).toBeVisible()
        await remembered.goto('/dashboard')
        await expect(remembered).toHaveURL(/\/login$/)
        await expect(
            remembered.getByRole('button', { name: 'Log in' }),
        ).toBeVisible()
        await page.reload()
        await expect(
            page.getByRole('heading', { name: 'My Devices', exact: true }),
        ).toBeVisible()
        await expect(page.getByText('1 signed-in device.')).toBeVisible()
    } finally {
        await second.close()
    }
})

import { chromium } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'

const baseURL = process.env.AEGIS_CONSOLE_URL ?? 'http://host.docker.internal:8000/console/'
const output = process.env.AEGIS_UI_ARTIFACTS ?? '/workspace/artifacts/phase-1.0-ui'
await mkdir(output, { recursive: true })

const browser = await chromium.launch({ headless: true })
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'dark' })
const page = await context.newPage()

const capture = async (name) => {
  await page.screenshot({ path: path.join(output, name), fullPage: true })
}

await page.goto(baseURL, { waitUntil: 'networkidle' })
await page.getByText('RESPONSIBILITY-AWARE WORKFLOW').waitFor()
await capture('mission-control.desktop.ui-regression.png')

await page.getByRole('button', { name: /Audit/ }).click()
await page.getByRole('heading', { name: 'Audit Explorer' }).waitFor()
await capture('audit-explorer.desktop.ui-regression.png')

await page.getByRole('button', { name: /Mission Control/ }).click()
await page.getByRole('button', { name: 'Open replay' }).click()
await page.getByRole('heading', { name: 'Chronological replay' }).waitFor()
await capture('run-replay.desktop.ui-regression.png')

await page.getByRole('button', { name: /Findings/ }).click()
await page.getByRole('heading', { name: 'Findings', level: 2 }).waitFor()
const findingRow = page.locator('tbody tr').first()
if (await findingRow.count()) {
  await findingRow.click()
  await page.getByRole('heading', { name: /Broken Object|authorization|metadata exposed|header missing/i }).waitFor()
  await capture('finding-detail.desktop.ui-regression.png')
}

await page.getByRole('button', { name: 'Presentation mode' }).click()
await page.getByText('Honest limitations').waitFor()
await capture('management-view.desktop.ui-regression.png')

await context.close()
const tablet = await browser.newContext({ viewport: { width: 900, height: 1100 }, colorScheme: 'dark' })
const tabletPage = await tablet.newPage()
await tabletPage.goto(baseURL, { waitUntil: 'networkidle' })
await tabletPage.getByText('RESPONSIBILITY-AWARE WORKFLOW').waitFor()
await tabletPage.screenshot({
  path: path.join(output, 'mission-control.tablet.ui-regression.png'),
  fullPage: true,
})
await tablet.close()
await browser.close()

console.log(`UI visual-regression captures written to ${output}`)

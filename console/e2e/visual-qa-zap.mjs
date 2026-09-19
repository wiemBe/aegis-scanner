import { chromium } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'

// Phase 1.3 ZAP visual-regression captures. UI regression artifacts only — NOT scan evidence.
const baseURL = process.env.AEGIS_CONSOLE_URL ?? 'http://host.docker.internal:8000/console/'
const output = process.env.AEGIS_UI_ARTIFACTS ?? '/workspace/artifacts/phase-1.3-ui'
const zapRun = process.env.AEGIS_ZAP_RUN ?? ''
await mkdir(output, { recursive: true })

const browser = await chromium.launch({ headless: true })
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'dark' })
const page = await context.newPage()
const capture = async (name) => page.screenshot({ path: path.join(output, name), fullPage: true })

await page.goto(baseURL, { waitUntil: 'networkidle' })
await page.getByText('RESPONSIBILITY-AWARE WORKFLOW').waitFor()

await page.getByRole('button', { name: /Integrations/ }).click()
await page.getByText('Engine adapters').waitFor()
await capture('integrations-zap.desktop.ui-regression.png')

await page.getByRole('button', { name: /Runs/ }).click()
await page.getByRole('heading', { name: 'Runs', level: 2 }).waitFor()
await page.getByText(zapRun.slice(0, 19)).first().click()
await page.getByRole('heading', { name: 'Chronological replay' }).waitFor()
await page.getByText('Passive analysis of approved read-only operations').waitFor()
await capture('run-replay-zap.desktop.ui-regression.png')

await page.getByRole('button', { name: 'Tool alert' }).click()
await capture('run-replay-zap-alert.desktop.ui-regression.png')

await page.getByRole('button', { name: 'Presentation mode' }).click()
await page.getByText('Honest limitations').waitFor()
await capture('management-view-zap.desktop.ui-regression.png')
await context.close()

const tablet = await browser.newContext({ viewport: { width: 900, height: 1100 }, colorScheme: 'dark' })
const tabletPage = await tablet.newPage()
await tabletPage.goto(baseURL, { waitUntil: 'networkidle' })
await tabletPage.getByText('RESPONSIBILITY-AWARE WORKFLOW').waitFor()
await tabletPage.getByRole('button', { name: /Integrations/ }).click()
await tabletPage.getByText('Engine adapters').waitFor()
await tabletPage.screenshot({ path: path.join(output, 'integrations-zap.tablet.ui-regression.png'), fullPage: true })
await tablet.close()
await browser.close()
console.log(`ZAP UI visual-regression captures written to ${output}`)

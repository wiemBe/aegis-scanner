import { chromium } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'

// Phase 1.5 ZAP Active visual QA. UI regression captures only — NOT scan evidence.
const baseURL = process.env.AEGIS_CONSOLE_URL ?? 'http://control-plane:8000/console/'
const output = process.env.AEGIS_UI_ARTIFACTS ?? '/workspace/artifacts/phase-1.5-ui'
await mkdir(output, { recursive: true })

const browser = await chromium.launch({ headless: true })
const desktop = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'dark' })
const page = await desktop.newPage()
const errors = []
page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`))
page.on('console', (message) => {
  if (message.type() === 'error') errors.push(`console: ${message.text()}`)
})

await page.goto(baseURL, { waitUntil: 'domcontentloaded' })
await page.getByRole('button', { name: 'ZAP Active' }).waitFor({ timeout: 30000 })
await page.getByRole('button', { name: 'ZAP Active' }).click()
await page.getByRole('heading', { name: 'ZAP Active — reflected XSS' }).waitFor({ timeout: 30000 })
await page.waitForTimeout(1500)  // let the 2s status poll settle once the view is mounted
await page.screenshot({ path: path.join(output, 'zap-active.desktop.ui-regression.png'), fullPage: true })

// The activation ceremony dialog at desktop width.
await page.getByRole('button', { name: 'ACTIVATE ACTIVE SCAN' }).click()
await page.getByRole('dialog', { name: 'ZAP Active activation ceremony' }).waitFor()
await page.screenshot({ path: path.join(output, 'zap-active-ceremony.desktop.ui-regression.png'), fullPage: true })
await page.getByRole('button', { name: 'Close activation ceremony' }).click()
await desktop.close()

const tablet = await browser.newContext({ viewport: { width: 900, height: 1100 }, colorScheme: 'dark' })
const tabletPage = await tablet.newPage()
tabletPage.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`))
await tabletPage.goto(baseURL, { waitUntil: 'domcontentloaded' })
await tabletPage.getByRole('button', { name: 'ZAP Active' }).waitFor({ timeout: 30000 })
await tabletPage.getByRole('button', { name: 'ZAP Active' }).click()
await tabletPage.getByRole('heading', { name: 'ZAP Active — reflected XSS' }).waitFor({ timeout: 30000 })
await tabletPage.screenshot({ path: path.join(output, 'zap-active.tablet.ui-regression.png'), fullPage: true })
await tablet.close()

await browser.close()
if (errors.length) {
  console.error('browser errors:', errors.join(' | '))
  process.exit(1)
}
console.log(`ZAP Active visual QA captures written to ${output}`)

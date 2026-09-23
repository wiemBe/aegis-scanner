// Phase 1.9.5 visual-verification capture. Navigates the real local console and saves PNGs.
// Usage: node e2e/capture-1.9.5.mjs <baseURL> <outDir> <runId>
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const [baseURL, outDir, runId] = process.argv.slice(2)
mkdirSync(outDir, { recursive: true })

const shot = async (page, name) => {
  await page.waitForTimeout(350)
  await page.screenshot({ path: `${outDir}/${name}.png` })
  console.log('saved', name)
}

const browser = await chromium.launch()

async function desktop(width, height, suffix) {
  const ctx = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 2 })
  const page = await ctx.newPage()

  await page.goto(`${baseURL}/console/index.html#/`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(500)
  await shot(page, `landing${suffix}`)

  // New Assessment — step 1 (target)
  await page.goto(`${baseURL}/console/index.html#/new`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(400)
  await shot(page, `new-target${suffix}`)

  // step 2 (profile)
  await page.getByText('Synthetic Bank API').first().click()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.waitForTimeout(300)
  await shot(page, `new-profile${suffix}`)

  // step 3 (controls)
  await page.getByText('Web & API Authorization').first().click()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.waitForTimeout(300)
  await shot(page, `new-controls${suffix}`)

  // step 4 (review)
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.waitForTimeout(300)
  await shot(page, `new-review${suffix}`)

  if (runId) {
    await page.goto(`${baseURL}/console/index.html#/runs/${runId}`, { waitUntil: 'networkidle' })
    await page.waitForTimeout(600)
    await shot(page, `run-overview${suffix}`)
    await page.getByRole('tab', { name: 'Findings' }).click()
    await page.waitForTimeout(300)
    await shot(page, `run-findings${suffix}`)
    await page.getByRole('tab', { name: 'Activity' }).click()
    await page.waitForTimeout(300)
    await shot(page, `run-activity${suffix}`)
    await page.getByRole('tab', { name: 'Cleanup' }).click()
    await page.waitForTimeout(300)
    await shot(page, `run-cleanup${suffix}`)
    await page.getByRole('tab', { name: 'Report' }).click()
    await page.waitForTimeout(300)
    await shot(page, `run-report${suffix}`)
  }

  await page.goto(`${baseURL}/console/index.html#/findings`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(400)
  await shot(page, `findings${suffix}`)

  await page.goto(`${baseURL}/console/index.html#/targets`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(400)
  await shot(page, `targets${suffix}`)

  await ctx.close()
}

await desktop(1440, 900, '')
await desktop(1280, 800, '-laptop')

await browser.close()
console.log('done')

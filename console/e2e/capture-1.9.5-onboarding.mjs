// Phase 1.9.5 correction — company target onboarding visual capture. Drives the real local console
// and its controller-owned inventory endpoints (persisting to the server's SQLite), saving PNGs.
// Usage: node e2e/capture-1.9.5-onboarding.mjs <baseURL> <outDir>
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const [baseURL, outDir] = process.argv.slice(2)
mkdirSync(outDir, { recursive: true })

const shot = async (page, name) => {
  await page.waitForTimeout(300)
  await page.screenshot({ path: `${outDir}/${name}.png` })
  console.log('saved', name)
}

const browser = await chromium.launch()
const ctx = await browser.newContext({ viewport: { width: 1440, height: 960 }, deviceScaleFactor: 2 })
const page = await ctx.newPage()

// 1) Target selection showing the "Add authorized target" action.
await page.goto(`${baseURL}/console/index.html#/new`, { waitUntil: 'networkidle' })
await page.waitForTimeout(400)
await shot(page, 'target-select-with-add')

// 2) Add Company Website form.
await page.getByRole('button', { name: '+ Add authorized target' }).click()
await page.getByRole('dialog', { name: 'Add authorized target' }).waitFor()
await page.getByPlaceholder('Company Marketing Site').fill('Company Marketing Site')
await page.getByPlaceholder('CHG-1029 / ticket ID').fill('CHG-1029')
await page.getByPlaceholder(/example\.company\.com\nhttps/).fill('example.company.com\nhttps://shop.company.com')
await page.getByPlaceholder('/admin, /internal').fill('/admin, /internal')
await page.getByLabel('I confirm that I am authorized to assess these targets').check()
await shot(page, 'add-company-website-form')

// 3) Normalized scope review (controller dry-run preview).
await page.getByRole('button', { name: 'Preview scope' }).click()
await page.getByText('Normalized authorized scope').waitFor()
await shot(page, 'normalized-scope-review')

// Save this company target and return to the flow with it selected.
await page.getByRole('button', { name: 'Add and continue' }).click()
await page.getByRole('dialog', { name: 'Add authorized target' }).waitFor({ state: 'detached' })
await page.getByText('Company Marketing Site').first().waitFor()
await shot(page, 'company-target-selected')

// 4) Add API form (base URLs + OpenAPI + credential reference, secrets warning).
await page.getByRole('button', { name: '+ Add authorized target' }).click()
await page.getByRole('dialog', { name: 'Add authorized target' }).waitFor()
await page.getByRole('tab', { name: 'API' }).click()
await page.getByPlaceholder('Company Marketing Site').fill('Payments API')
await page.getByPlaceholder('CHG-1029 / ticket ID').fill('JIRA-88')
await page.getByPlaceholder(/api\.company\.com:8443/).fill('https://api.company.com\nhttps://api.company.com:8443')
await page.getByPlaceholder('https://api.company.com/openapi.json').fill('https://api.company.com/openapi.json')
await page.getByPlaceholder('vault://payments-api/token').fill('vault://payments-api/token')
await page.getByLabel('I confirm that I am authorized to assess these targets').check()
await shot(page, 'add-api-form')
await page.getByRole('dialog', { name: 'Add authorized target' }).getByRole('button', { name: 'Cancel' }).click()

// 5) Review & Start showing authorized scope and exclusions. A synthetic-range target routes to the
//    always-available native profile, so the review step is reachable without enabling engines or
//    starting any real company scan; the excluded paths and normalized scope are shown.
await page.getByRole('button', { name: '+ Add authorized target' }).click()
await page.getByRole('dialog', { name: 'Add authorized target' }).waitFor()
await page.getByRole('tab', { name: 'Synthetic range target' }).click()
await page.getByPlaceholder('Company Marketing Site').fill('Synthetic Demo Range')
await page.getByPlaceholder('CHG-1029 / ticket ID').fill('SYNTH-REVIEW')
await page.getByPlaceholder(/example\.company\.com\nhttps/).fill('http://demo-range.local:8090')
await page.getByPlaceholder('/admin, /internal').fill('/private, /internal')
await page.getByLabel('I confirm that I am authorized to assess these targets').check()
await page.getByRole('button', { name: 'Add and continue' }).click()
await page.getByRole('dialog', { name: 'Add authorized target' }).waitFor({ state: 'detached' })
// Continue through the wizard to Review & Start.
await page.getByRole('button', { name: 'Continue' }).click() // to Assessment
await page.getByText('Web & API Authorization').first().click()
await page.getByRole('button', { name: 'Continue' }).click() // to Controls
await page.getByRole('button', { name: 'Continue' }).click() // to Review
await page.getByText('Review and start').waitFor()
await shot(page, 'review-and-start-scope')

// 6) Functional Targets page with company/synthetic distinction and actions.
await page.goto(`${baseURL}/console/index.html#/targets`, { waitUntil: 'networkidle' })
await page.waitForTimeout(400)
await shot(page, 'targets-page-functional')

await ctx.close()
await browser.close()
console.log('done')

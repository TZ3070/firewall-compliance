import { afterEach, describe, expect, it, vi } from 'vitest'

import { getComplianceReport } from './client'

describe('getComplianceReport', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('preserves report id path separators and encodes each segment', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ report_id: 'rpt:assessment/report-pack/1.0.0' }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const report = await getComplianceReport('rpt:assessment/report-pack/1.0.0')

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/compliance-reports/rpt%3Aassessment/report-pack/1.0.0',
    )
    expect(report.report_id).toBe('rpt:assessment/report-pack/1.0.0')
  })
})

import { describe, expect, it } from 'vitest'

import { isFindingResult } from './contracts'

describe('finding result contract', () => {
  it('accepts only the supported result values', () => {
    expect(isFindingResult('Passed')).toBe(true)
    expect(isFindingResult('Failed')).toBe(true)
    expect(isFindingResult('NeedsReview')).toBe(true)
    expect(isFindingResult('NotApplicable')).toBe(true)
    expect(isFindingResult('NeedsReview')).toBe(true)
    expect(isFindingResult('InsufficientEvidence')).toBe(false)
    expect(isFindingResult('Unknown')).toBe(false)
  })
})

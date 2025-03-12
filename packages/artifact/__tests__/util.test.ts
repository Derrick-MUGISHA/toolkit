import * as config from '../src/internal/shared/config'
import * as util from '../src/internal/shared/util'
import {maskSigUrl, maskSecretUrls} from '../src/internal/shared/util'
import {setSecret, debug} from '@actions/core'

export const testRuntimeToken =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2NwIjoiQWN0aW9ucy5FeGFtcGxlIEFjdGlvbnMuQW5vdGhlckV4YW1wbGU6dGVzdCBBY3Rpb25zLlJlc3VsdHM6Y2U3ZjU0YzctNjFjNy00YWFlLTg4N2YtMzBkYTQ3NWY1ZjFhOmNhMzk1MDg1LTA0MGEtNTI2Yi0yY2U4LWJkYzg1ZjY5Mjc3NCIsImlhdCI6MTUxNjIzOTAyMn0.XYnI_wHPBlUi1mqYveJnnkJhp4dlFjqxzRmISPsqfw8'

describe('get-backend-ids-from-token', () => {
  it('should return backend ids when the token is valid', () => {
    jest.spyOn(config, 'getRuntimeToken').mockReturnValue(testRuntimeToken)

    const backendIds = util.getBackendIdsFromToken()
    expect(backendIds.workflowRunBackendId).toBe(
      'ce7f54c7-61c7-4aae-887f-30da475f5f1a'
    )
    expect(backendIds.workflowJobRunBackendId).toBe(
      'ca395085-040a-526b-2ce8-bdc85f692774'
    )
  })

  it("should throw an error when the token doesn't have the right scope", () => {
    jest
      .spyOn(config, 'getRuntimeToken')
      .mockReturnValue(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2NwIjoiQWN0aW9ucy5FeGFtcGxlIEFjdGlvbnMuQW5vdGhlckV4YW1wbGU6dGVzdCIsImlhdCI6MTUxNjIzOTAyMn0.K0IEoULZteGevF38G94xiaA8zcZ5UlKWfGfqE6q3dhw'
      )

    expect(util.getBackendIdsFromToken).toThrowError(
      'Failed to get backend IDs: The provided JWT token is invalid'
    )
  })

  it('should throw an error when the token has a malformed scope', () => {
    jest
      .spyOn(config, 'getRuntimeToken')
      .mockReturnValue(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2NwIjoiQWN0aW9ucy5FeGFtcGxlIEFjdGlvbnMuQW5vdGhlckV4YW1wbGU6dGVzdCBBY3Rpb25zLlJlc3VsdHM6Y2U3ZjU0YzctNjFjNy00YWFlLTg4N2YtMzBkYTQ3NWY1ZjFhIiwiaWF0IjoxNTE2MjM5MDIyfQ.7D0_LRfRFRZFImHQ7GxH2S6ZyFjjZ5U0ujjGCfle1XE'
      )

    expect(util.getBackendIdsFromToken).toThrowError(
      'Failed to get backend IDs: The provided JWT token is invalid'
    )
  })

  it('should throw an error when the token is in an invalid format', () => {
    jest.spyOn(config, 'getRuntimeToken').mockReturnValue('token')

    expect(util.getBackendIdsFromToken).toThrowError('Invalid token specified')
  })

  it("should throw an error when the token doesn't have the right field", () => {
    jest
      .spyOn(config, 'getRuntimeToken')
      .mockReturnValue(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
      )

    expect(util.getBackendIdsFromToken).toThrowError(
      'Failed to get backend IDs: The provided JWT token is invalid'
    )
  })
})

jest.mock('@actions/core')

describe('maskSigUrl', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('masks the sig parameter in the URL and sets it as a secret', () => {
    const url = 'https://example.com?sig=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?sig=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('returns the original URL if no sig parameter is present', () => {
    const url = 'https://example.com'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe(url)
    expect(setSecret).not.toHaveBeenCalled()
  })

  it('masks the sig parameter in the middle of the URL and sets it as a secret', () => {
    const url = 'https://example.com?param1=value1&sig=12345&param2=value2'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe(
      'https://example.com/?param1=value1&sig=***&param2=value2'
    )
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('returns the original URL if it is empty', () => {
    const url = ''
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('')
    expect(setSecret).not.toHaveBeenCalled()
  })

  it('handles URLs with special characters in signature', () => {
    const url = 'https://example.com?sig=abc/+=%3D'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?sig=***')

    expect(setSecret).toHaveBeenCalledWith('abc/+')
    expect(setSecret).toHaveBeenCalledWith('abc/ ==')
    expect(setSecret).toHaveBeenCalledWith('abc%2F%20%3D%3D')
  })

  it('handles relative URLs', () => {
    const url = '/path?param=value&sig=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/path?param=value&sig=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('handles URLs with uppercase SIG parameter', () => {
    const url = 'https://example.com?SIG=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?SIG=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('handles malformed URLs using regex fallback', () => {
    const url = 'not:a:valid:url:but:has:sig=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('not:a:valid:url:but:has:sig=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
  })

  it('handles URLs with fragments', () => {
    const url = 'https://example.com?sig=12345#fragment'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?sig=***#fragment')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('handles URLs with Sig parameter (first letter uppercase)', () => {
    const url = 'https://example.com?Sig=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?Sig=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('handles URLs with sIg parameter (middle letter uppercase)', () => {
    const url = 'https://example.com?sIg=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?sIg=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('handles URLs with siG parameter (last letter uppercase)', () => {
    const url = 'https://example.com?siG=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?siG=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('handles URLs with mixed case sig parameters in the same URL', () => {
    const url = 'https://example.com?sig=123&SIG=456&Sig=789'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?sig=***&SIG=***&Sig=***')
    expect(setSecret).toHaveBeenCalledWith('123')
    expect(setSecret).toHaveBeenCalledWith('456')
    expect(setSecret).toHaveBeenCalledWith('789')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('123'))
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('456'))
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('789'))
  })

  it('handles malformed URLs with different sig case variations', () => {
    const url = 'not:a:valid:url:but:has:Sig=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('not:a:valid:url:but:has:Sig=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
  })

  it('handles malformed URLs with uppercase SIG in irregular formats', () => {
    const url = 'something&SIG=12345&other:stuff'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('something&SIG=***&other:stuff')
    expect(setSecret).toHaveBeenCalledWith('12345')
  })

  it('handles sig parameter at the start of the query string', () => {
    const url = 'https://example.com?sig=12345&param=value'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?sig=***&param=value')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })

  it('handles sig parameter at the end of the query string', () => {
    const url = 'https://example.com?param=value&sig=12345'
    const maskedUrl = maskSigUrl(url)
    expect(maskedUrl).toBe('https://example.com/?param=value&sig=***')
    expect(setSecret).toHaveBeenCalledWith('12345')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('12345'))
  })
})

describe('maskSecretUrls', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('masks sig parameters in signed_upload_url and signed_url', () => {
    const body = {
      signed_upload_url: 'https://upload.com?sig=upload123',
      signed_url: 'https://download.com?sig=download123'
    }
    maskSecretUrls(body)
    expect(setSecret).toHaveBeenCalledWith('upload123')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('upload123'))
    expect(setSecret).toHaveBeenCalledWith('download123')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('download123'))
  })

  it('handles case where only upload_url is present', () => {
    const body = {
      signed_upload_url: 'https://upload.com?sig=upload123'
    }
    maskSecretUrls(body)
    expect(setSecret).toHaveBeenCalledWith('upload123')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('upload123'))
  })

  it('handles case where only download_url is present', () => {
    const body = {
      signed_url: 'https://download.com?sig=download123'
    }
    maskSecretUrls(body)
    expect(setSecret).toHaveBeenCalledWith('download123')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('download123'))
  })

  it('handles case where URLs do not contain sig parameters', () => {
    const body = {
      signed_upload_url: 'https://upload.com?token=abc',
      signed_url: 'https://download.com?token=xyz'
    }
    maskSecretUrls(body)
    expect(setSecret).not.toHaveBeenCalled()
  })

  it('handles empty string URLs', () => {
    const body = {
      signed_upload_url: '',
      signed_url: ''
    }
    maskSecretUrls(body)
    expect(setSecret).not.toHaveBeenCalled()
  })

  it('handles malformed URLs in the body', () => {
    const body = {
      signed_upload_url: 'not:a:valid:url:but:has:sig=upload123',
      signed_url: 'also:not:valid:with:sig=download123'
    }
    maskSecretUrls(body)
    expect(setSecret).toHaveBeenCalledWith('upload123')
    expect(setSecret).toHaveBeenCalledWith('download123')
  })

  it('handles URLs with different case variations of sig parameter', () => {
    const body = {
      signed_upload_url: 'https://upload.com?SIG=upload123',
      signed_url: 'https://download.com?Sig=download123'
    }
    maskSecretUrls(body)
    expect(setSecret).toHaveBeenCalledWith('upload123')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('upload123'))
    expect(setSecret).toHaveBeenCalledWith('download123')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('download123'))
  })

  it('handles URLs with special characters in signature', () => {
    const specialSig = 'xyz!@#$'
    const encodedSpecialSig = encodeURIComponent(specialSig)

    const body = {
      signed_upload_url: 'https://upload.com?sig=abc/+=%3D',
      signed_url: `https://download.com?sig=${encodedSpecialSig}`
    }
    maskSecretUrls(body)

    const allCalls = (setSecret as jest.Mock).mock.calls.flat()

    expect(allCalls).toContain('abc/+')
    expect(allCalls).toContain('abc/ ==')
    expect(allCalls).toContain('abc%2F%20%3D%3D')

    expect(allCalls).toContain(specialSig)
  })

  it('handles deeply nested URLs in the body', () => {
    const body = {
      data: {
        urls: {
          signed_upload_url: 'https://upload.com?sig=nested123',
          signed_url: 'https://download.com?sig=nested456'
        }
      }
    }
    maskSecretUrls(body)
    expect(setSecret).toHaveBeenCalledWith('nested123')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('nested123'))
    expect(setSecret).toHaveBeenCalledWith('nested456')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('nested456'))
  })

  it('handles arrays of URLs in the body', () => {
    const body = {
      signed_urls: [
        'https://first.com?sig=first123',
        'https://second.com?sig=second456'
      ]
    }
    maskSecretUrls(body)
    expect(setSecret).toHaveBeenCalledWith('first123')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('first123'))
    expect(setSecret).toHaveBeenCalledWith('second456')
    expect(setSecret).toHaveBeenCalledWith(encodeURIComponent('second456'))
  })

  it('does nothing if body is not an object or is null', () => {
    maskSecretUrls(null)
    expect(debug).toHaveBeenCalledWith('body is not an object or is null')
    expect(setSecret).not.toHaveBeenCalled()
  })

  it('does nothing if signed_upload_url and signed_url are not strings', () => {
    const body = {
      signed_upload_url: 123,
      signed_url: 456
    }
    maskSecretUrls(body)
    expect(setSecret).not.toHaveBeenCalled()
  })
})

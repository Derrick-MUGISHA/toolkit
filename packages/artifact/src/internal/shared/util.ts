import * as core from '@actions/core'
import {getRuntimeToken} from './config'
import jwt_decode from 'jwt-decode'
import {debug, setSecret} from '@actions/core'

export interface BackendIds {
  workflowRunBackendId: string
  workflowJobRunBackendId: string
}

interface ActionsToken {
  scp: string
}

const InvalidJwtError = new Error(
  'Failed to get backend IDs: The provided JWT token is invalid and/or missing claims'
)

// uses the JWT token claims to get the
// workflow run and workflow job run backend ids
export function getBackendIdsFromToken(): BackendIds {
  const token = getRuntimeToken()
  const decoded = jwt_decode<ActionsToken>(token)
  if (!decoded.scp) {
    throw InvalidJwtError
  }

  /*
   * example decoded:
   * {
   *   scp: "Actions.ExampleScope Actions.Results:ce7f54c7-61c7-4aae-887f-30da475f5f1a:ca395085-040a-526b-2ce8-bdc85f692774"
   * }
   */

  const scpParts = decoded.scp.split(' ')
  if (scpParts.length === 0) {
    throw InvalidJwtError
  }
  /*
   * example scpParts:
   * ["Actions.ExampleScope", "Actions.Results:ce7f54c7-61c7-4aae-887f-30da475f5f1a:ca395085-040a-526b-2ce8-bdc85f692774"]
   */

  for (const scopes of scpParts) {
    const scopeParts = scopes.split(':')
    if (scopeParts?.[0] !== 'Actions.Results') {
      // not the Actions.Results scope
      continue
    }

    /*
     * example scopeParts:
     * ["Actions.Results", "ce7f54c7-61c7-4aae-887f-30da475f5f1a", "ca395085-040a-526b-2ce8-bdc85f692774"]
     */
    if (scopeParts.length !== 3) {
      // missing expected number of claims
      throw InvalidJwtError
    }

    const ids = {
      workflowRunBackendId: scopeParts[1],
      workflowJobRunBackendId: scopeParts[2]
    }

    core.debug(`Workflow Run Backend ID: ${ids.workflowRunBackendId}`)
    core.debug(`Workflow Job Run Backend ID: ${ids.workflowJobRunBackendId}`)

    return ids
  }

  throw InvalidJwtError
}

/**
 * Masks the `sig` parameter in a URL and sets it as a secret.
 * @param url The URL containing the `sig` parameter.
 * @returns A masked URL where the sig parameter value is replaced with '***' if found,
 *          or the original URL if no sig parameter is present.
 */
export function maskSigUrl(url: string): string {
  if (!url) return url

  try {
    const rawSigRegex = /[?&](sig)=([^&=#]+)/gi
    let match

    while ((match = rawSigRegex.exec(url)) !== null) {
      const rawSignature = match[2]
      if (rawSignature) {
        setSecret(rawSignature)
      }
    }

    let parsedUrl: URL
    try {
      parsedUrl = new URL(url)
    } catch {
      try {
        parsedUrl = new URL(url, 'https://example.com')
      } catch (error) {
        debug(`Failed to parse URL: ${url}`)
        return maskSigWithRegex(url)
      }
    }

    let masked = false
    const paramNames = Array.from(parsedUrl.searchParams.keys())

    for (const paramName of paramNames) {
      if (paramName.toLowerCase() === 'sig') {
        const signature = parsedUrl.searchParams.get(paramName)
        if (signature) {
          setSecret(signature)
          setSecret(encodeURIComponent(signature))
          parsedUrl.searchParams.set(paramName, '***')
          masked = true
        }
      }
    }
    if (masked) {
      return parsedUrl.toString()
    }

    if (/([:?&]|^)(sig)=([^&=#]+)/i.test(url)) {
      return maskSigWithRegex(url)
    }
  } catch (error) {
    debug(
      `Error masking URL: ${
        error instanceof Error ? error.message : String(error)
      }`
    )
    return maskSigWithRegex(url)
  }

  return url
}

/**
 * Fallback method to mask signatures using regex when URL parsing fails
 */
function maskSigWithRegex(url: string): string {
  try {
    const regex = /([:?&]|^)(sig)=([^&=#]+)/gi

    return url.replace(regex, (fullMatch, prefix, paramName, value) => {
      if (value) {
        setSecret(value)
        try {
          setSecret(decodeURIComponent(value))
        } catch {
          // Ignore decoding errors
        }
        return `${prefix}${paramName}=***`
      }
      return fullMatch
    })
  } catch (error) {
    debug(
      `Error in maskSigWithRegex: ${
        error instanceof Error ? error.message : String(error)
      }`
    )
    return url
  }
}

/**
 * Masks any URLs containing signature parameters in the provided object
 * Recursively searches through nested objects and arrays
 */
export function maskSecretUrls(
  body: Record<string, unknown> | unknown[] | null
): void {
  if (typeof body !== 'object' || body === null) {
    debug('body is not an object or is null')
    return
  }

  type NestedValue =
    | string
    | number
    | boolean
    | null
    | undefined
    | NestedObject
    | NestedArray
  interface NestedObject {
    [key: string]: NestedValue
    signed_upload_url?: string
    signed_url?: string
  }
  type NestedArray = NestedValue[]

  const processUrl = (url: string): void => {
    maskSigUrl(url)
  }

  const processObject = (
    obj: Record<string, NestedValue> | NestedValue[]
  ): void => {
    if (typeof obj !== 'object' || obj === null) {
      return
    }

    if (Array.isArray(obj)) {
      for (const item of obj) {
        if (typeof item === 'string') {
          processUrl(item)
        } else if (typeof item === 'object' && item !== null) {
          processObject(item as Record<string, NestedValue> | NestedValue[])
        }
      }
      return
    }

    if (
      'signed_upload_url' in obj &&
      typeof obj.signed_upload_url === 'string'
    ) {
      maskSigUrl(obj.signed_upload_url)
    }
    if ('signed_url' in obj && typeof obj.signed_url === 'string') {
      maskSigUrl(obj.signed_url)
    }

    for (const key in obj) {
      const value = obj[key]
      if (typeof value === 'string') {
        if (/([:?&]|^)(sig)=/i.test(value)) {
          maskSigUrl(value)
        }
      } else if (typeof value === 'object' && value !== null) {
        processObject(value as Record<string, NestedValue> | NestedValue[])
      }
    }
  }
  processObject(body as Record<string, NestedValue> | NestedValue[])
}

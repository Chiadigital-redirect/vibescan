// ─── Scan History (localStorage) ─────────────────────────────────────────────
// Stores up to MAX_ENTRIES scan results so the user can see their recent scans
// without needing an account or backend.

export interface ScanHistoryEntry {
  url: string
  domain: string
  score: number
  critical: number
  warnings: number
  passed: number
  scannedAt: string
}

const STORAGE_KEY = 'vibescan-history'
const MAX_ENTRIES = 10

function getDomain(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return url
  }
}

/**
 * Save a completed scan to localStorage history.
 * De-duplicates by domain (most recent scan for each domain wins).
 */
export function saveScanToHistory(entry: Omit<ScanHistoryEntry, 'domain'>): void {
  if (typeof window === 'undefined') return
  try {
    const existing = getScanHistory()
    const domain = getDomain(entry.url)
    // Remove any previous scan for this exact domain
    const filtered = existing.filter(e => e.domain !== domain)
    const updated: ScanHistoryEntry[] = [{ ...entry, domain }, ...filtered].slice(0, MAX_ENTRIES)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
  } catch {
    // localStorage may be unavailable in some environments — fail silently
  }
}

/**
 * Read the scan history from localStorage, newest first.
 */
export function getScanHistory(): ScanHistoryEntry[] {
  if (typeof window === 'undefined') return []
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as ScanHistoryEntry[]) : []
  } catch {
    return []
  }
}

/**
 * Remove a single entry by domain.
 */
export function removeScanFromHistory(domain: string): void {
  if (typeof window === 'undefined') return
  try {
    const updated = getScanHistory().filter(e => e.domain !== domain)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
  } catch {}
}

/**
 * Clear all scan history.
 */
export function clearScanHistory(): void {
  if (typeof window === 'undefined') return
  try {
    localStorage.removeItem(STORAGE_KEY)
  } catch {}
}

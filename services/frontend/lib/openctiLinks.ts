/**
 * Build OpenCTI global knowledge search URL for an IOC string.
 * Paths differ slightly by OpenCTI version; override with NEXT_PUBLIC_OPENCTI_SEARCH_PATH / QUERY_PARAM.
 */
export function openctiKnowledgeSearchUrl(searchTerm: string): string {
  const baseRaw = (process.env.NEXT_PUBLIC_OPENCTI_URL || '').trim();
  if (!baseRaw) return '';

  const base = baseRaw.replace(/\/?$/, '/');
  const relPath = (process.env.NEXT_PUBLIC_OPENCTI_SEARCH_PATH || 'dashboard/search/knowledge/global')
    .trim()
    .replace(/^\/+/, '');
  const param = (process.env.NEXT_PUBLIC_OPENCTI_SEARCH_QUERY_PARAM || 'keyword').trim() || 'keyword';

  const url = new URL(relPath, base);
  url.searchParams.set(param, searchTerm.trim());
  return url.toString();
}

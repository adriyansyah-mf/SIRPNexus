import { redirect } from 'next/navigation';

/** Legacy path; threat intel UI is OpenCTI (nav link + NEXT_PUBLIC_OPENCTI_URL). */
export default function AnalyzersRedirectPage() {
  const url = (process.env.NEXT_PUBLIC_OPENCTI_URL || '').trim();
  redirect(url || '/');
}

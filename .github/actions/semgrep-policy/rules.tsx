export function Unsafe({ html }: { html: string }) {
  // ruleid: poc-react-untrusted-html
  return <section dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Safe({ html }: { html: string }) {
  // ok: poc-react-untrusted-html
  return <section>{html}</section>;
}

export function writeUnsafe(element: HTMLElement, html: string) {
  // ruleid: poc-browser-innerhtml-assignment
  element.innerHTML = html;
}

export function writeSafe(element: HTMLElement, html: string) {
  // ok: poc-browser-innerhtml-assignment
  element.textContent = html;
}

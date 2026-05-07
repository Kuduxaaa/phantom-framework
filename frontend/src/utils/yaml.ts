/**
 * Minimal YAML tokenizer used by the signature source view.
 *
 * Returns a flat list of `{ text, kind }` tokens that the renderer maps to
 * theme colors. Not a real parser — only good enough for highlighting.
 */

export type TokenKind =
  | 'plain'
  | 'indent'
  | 'dash'
  | 'key'
  | 'colon'
  | 'string'
  | 'template'
  | 'literal'
  | 'number'
  | 'comment'

export interface Token {
  text: string
  kind: TokenKind
}

const VALUE_REGEX = /"([^"]*)"|'([^']*)'|\{\{([^}]+)\}\}|\b(true|false|null)\b|\b(\d+(?:\.\d+)?)\b/g

function tokenizeValue(value: string): Token[] {
  if (!value) return [{ text: value, kind: 'plain' }]
  const tokens: Token[] = []
  let i = 0
  let match: RegExpExecArray | null
  VALUE_REGEX.lastIndex = 0
  while ((match = VALUE_REGEX.exec(value))) {
    if (match.index > i) tokens.push({ text: value.slice(i, match.index), kind: 'plain' })
    if (match[1] !== undefined) tokens.push({ text: `"${match[1]}"`, kind: 'string' })
    else if (match[2] !== undefined) tokens.push({ text: `'${match[2]}'`, kind: 'string' })
    else if (match[3] !== undefined) tokens.push({ text: `{{${match[3]}}}`, kind: 'template' })
    else if (match[4]) tokens.push({ text: match[4], kind: 'literal' })
    else if (match[5]) tokens.push({ text: match[5], kind: 'number' })
    i = match.index + match[0].length
  }
  if (i < value.length) tokens.push({ text: value.slice(i), kind: 'plain' })
  return tokens
}

/**
 * Tokenize a single YAML line into highlighted spans.
 */
export function tokenizeYamlLine(line: string): Token[] {
  const out: Token[] = []
  const commentIdx = line.indexOf('#')
  let work = line
  let comment = ''
  if (commentIdx >= 0 && (commentIdx === 0 || /\s/.test(line[commentIdx - 1] ?? ''))) {
    work = line.slice(0, commentIdx)
    comment = line.slice(commentIdx)
  }
  const kvMatch = work.match(/^(\s*)([-]?\s*)([\w-]+)(:)(.*)$/)
  if (kvMatch) {
    const [, indent = '', dash = '', key = '', colon = '', rest = ''] = kvMatch
    if (indent) out.push({ text: indent, kind: 'indent' })
    if (dash.trim()) out.push({ text: dash, kind: 'dash' })
    out.push({ text: key, kind: 'key' })
    out.push({ text: colon, kind: 'colon' })
    out.push(...tokenizeValue(rest))
  } else {
    out.push(...tokenizeValue(work))
  }
  if (comment) out.push({ text: comment, kind: 'comment' })
  return out
}

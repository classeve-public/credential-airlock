/*
 * Credential Airlock — secret PRESETS (REFERENCE COPY).
 *
 * IMPORTANT: the admin server's static route map only serves '/', '/index.html',
 * '/app.js' and '/style.css'. It does NOT serve '/presets.js' (it will 404).
 * Therefore the UI does NOT load this file — the authoritative copy of PRESETS
 * lives inlined at the top of app.js. This file is kept only as human-readable
 * documentation / a single place to copy the canonical list from. Keep the two
 * copies in sync if you edit either.
 *
 * Each preset shape:
 *   { id, label, hosts:[string], placeholder:"__NAME__", injection:InjectionSpec, docs?, note? }
 *
 * InjectionSpec:
 *   { mode:'header'|'placeholder'|'query', header?, valueTemplate?, queryParam?,
 *     placeholder?, injectInBody? }
 */
const PRESETS = [
  {
    id: 'openai',
    label: 'OpenAI',
    hosts: ['api.openai.com'],
    placeholder: '__OPENAI_KEY__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://platform.openai.com/docs/api-reference/authentication',
    note: 'Standard Bearer token in the Authorization header.',
  },
  {
    id: 'anthropic',
    label: 'Anthropic',
    hosts: ['api.anthropic.com'],
    placeholder: '__ANTHROPIC_KEY__',
    injection: { mode: 'header', header: 'x-api-key', valueTemplate: '{{secret}}' },
    docs: 'https://docs.anthropic.com/en/api/getting-started',
    note: 'Anthropic uses the raw key in the x-api-key header (no "Bearer " prefix).',
  },
  {
    id: 'stripe',
    label: 'Stripe',
    hosts: ['api.stripe.com'],
    placeholder: '__STRIPE_KEY__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://stripe.com/docs/api/authentication',
    note: 'Money mover. Add an amountLimit rule on field "amount" in Policy to cap charges.',
    suggestAmountField: 'amount',
  },
  {
    id: 'github',
    label: 'GitHub',
    hosts: ['api.github.com'],
    placeholder: '__GITHUB_TOKEN__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://docs.github.com/en/rest/authentication',
    note: 'Fine-grained PAT or classic token as a Bearer credential.',
  },
  {
    id: 'cloudflare',
    label: 'Cloudflare',
    hosts: ['api.cloudflare.com'],
    placeholder: '__CLOUDFLARE_TOKEN__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/',
    note: 'Use an API Token (not the legacy Global API Key) as a Bearer credential.',
  },
  {
    id: 'sendgrid',
    label: 'SendGrid',
    hosts: ['api.sendgrid.com'],
    placeholder: '__SENDGRID_KEY__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://docs.sendgrid.com/api-reference/how-to-use-the-sendgrid-v3-api/authentication',
    note: 'Bearer token in the Authorization header.',
  },
  {
    id: 'slack',
    label: 'Slack',
    hosts: ['slack.com', 'api.slack.com'],
    placeholder: '__SLACK_TOKEN__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://api.slack.com/authentication/token-types',
    note: 'Bot/user token (xoxb-/xoxp-) as a Bearer credential.',
  },
  {
    id: 'gemini',
    label: 'Google Gemini',
    hosts: ['generativelanguage.googleapis.com'],
    placeholder: '__GEMINI_KEY__',
    injection: { mode: 'query', queryParam: 'key' },
    docs: 'https://ai.google.dev/gemini-api/docs/api-key',
    note: 'Gemini takes the API key as a ?key= query parameter, not a header.',
  },
  {
    id: 'notion',
    label: 'Notion',
    hosts: ['api.notion.com'],
    placeholder: '__NOTION_TOKEN__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://developers.notion.com/reference/authentication',
    note: 'Integration token as a Bearer credential. (Also set a Notion-Version header in your client.)',
  },
  {
    id: 'twilio',
    label: 'Twilio',
    hosts: ['api.twilio.com'],
    placeholder: '__TWILIO_AUTH__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Basic {{secret}}' },
    docs: 'https://www.twilio.com/docs/usage/api',
    note: 'HTTP Basic auth: store the base64 of "AccountSID:AuthToken" as the secret value.',
  },
];

// Exported only for tooling/tests that may import this file in Node.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PRESETS };
}
